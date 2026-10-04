"""One WebSocket subscriber: its lifecycle, its bounded queue, its counters (M14.4/M14.15).

A connection is the unit the manager fans out to, and everything about
back-pressure lives here rather than in the manager: the queue, its fixed cap, the
drop-oldest rule, and the counters that make a dropped event visible instead of
silent.

Three design decisions worth stating:

* **The queue holds encoded text, not events.** Encoding happens once, on the
  dispatch path, and every subscriber of a broadcast receives the same string.
  Encoding per subscriber would cost one serialization per client per event and
  could fail *after* a subscriber was picked.
* **The sender task is the only writer.** A ping/pong reply or a refusal is
  offered to the same queue rather than written directly by the receive loop, so
  two tasks never interleave frames on one socket (M14.23/M14.24).
* **Nothing here knows what an event means.** The connection sees text to send,
  and the manager owns the policy that decided to send it. That is what keeps the
  channel table in :mod:`app.websockets.policy` the single place rate and depth
  are configured.
"""

from __future__ import annotations

import asyncio
import itertools
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum

from app.websockets.channels import Channel

#: Prefix on every connection id, so a log line is obviously a socket rather than
#: an alert or an incident.
CLIENT_ID_PREFIX = "wsc-"

_client_ids = itertools.count(1)


def new_client_id() -> str:
    """Return a unique connection identifier.

    A short increasing number with a random suffix: the number makes a connection
    easy to refer to in a log, and the suffix keeps two processes — or two test
    runs in one process — from colliding.
    """
    return f"{CLIENT_ID_PREFIX}{next(_client_ids)}-{uuid.uuid4().hex[:6]}"


class ConnectionState(str, Enum):
    """The lifecycle of one connection (M14.4).

    ``CLOSED`` is terminal and reachable from every other state, which is what
    makes cleanup-on-any-path safe: whatever happened, the connection ends there.
    """

    CONNECTING = "connecting"
    CONNECTED = "connected"
    CLOSING = "closing"
    CLOSED = "closed"


@dataclass
class ConnectionCounters:
    """What happened to one connection's traffic (M14.15).

    Counted per connection so a dashboard can name the one client that is not
    keeping up, and summed by the manager so the process total is available too.
    ``dropped_queue_full`` and ``dropped_oversized`` are the two numbers that make
    a lossy live view honest rather than invisible.
    """

    offered: int = 0
    sent: int = 0
    dropped_queue_full: int = 0
    dropped_oversized: int = 0
    send_errors: int = 0
    received: int = 0
    refused: int = 0
    pings_sent: int = 0
    pongs_received: int = 0


@dataclass
class ClientConnection:
    """One connected client, its bounded queue and its counters.

    Attributes:
        client_id: Stable identifier for the life of this socket.
        channel: The channel this socket dialled; fixed for its lifetime (M14.6).
        queue: The bounded outbound queue of encoded messages.
        max_queue: The queue's cap, kept separately so diagnostics can report the
            configured depth even after the queue has drained.
        state: Lifecycle state (M14.4).
        connected_at: Wall-clock connect time, epoch seconds, for display.
        connected_monotonic: Monotonic connect time, for a duration that a clock
            adjustment cannot make negative.
        counters: Per-connection counters.
        awaiting_pong: True while a server ping is unanswered (M14.24).
        sender_task: The task draining the queue, assigned by the manager.
    """

    client_id: str
    channel: Channel
    queue: asyncio.Queue[str]
    max_queue: int
    state: ConnectionState = ConnectionState.CONNECTING
    connected_at: float = field(default_factory=time.time)
    connected_monotonic: float = field(default_factory=time.monotonic)
    counters: ConnectionCounters = field(default_factory=ConnectionCounters)
    awaiting_pong: bool = False
    sender_task: asyncio.Task[None] | None = None

    # -- lifecycle --------------------------------------------------------

    def mark_connected(self) -> None:
        """Move to ``CONNECTED`` (M14.4)."""
        if self.state is not ConnectionState.CLOSED:
            self.state = ConnectionState.CONNECTED

    def mark_closing(self) -> None:
        """Move to ``CLOSING``; a no-op once the connection is closed."""
        if self.state is not ConnectionState.CLOSED:
            self.state = ConnectionState.CLOSING

    def mark_closed(self) -> None:
        """Move to the terminal ``CLOSED`` state (M14.4)."""
        self.state = ConnectionState.CLOSED

    @property
    def is_closed(self) -> bool:
        """Return True once no further message can be delivered."""
        return self.state is ConnectionState.CLOSED

    # -- queueing (M14.15) ------------------------------------------------

    def offer(self, message: str) -> bool:
        """Queue one encoded message, dropping the oldest when full.

        Returns:
            True when the message was queued, False when it was dropped as
            oversized. A full queue is *not* a failure: the oldest entry is
            discarded (it is stale telemetry by definition) and the newest message
            is queued, which is the drop policy documented in
            ``docs/18_M14_WebSocket_Design.md`` §8.2.

        This method is only ever called on the event loop, so
        ``asyncio.Queue.put_nowait`` is safe here — the queue is deliberately not
        touched from a publisher's thread (M14.21).
        """
        self.counters.offered += 1
        while True:
            try:
                self.queue.put_nowait(message)
                return True
            except asyncio.QueueFull:
                try:
                    self.queue.get_nowait()
                except asyncio.QueueEmpty:  # pragma: no cover - racing drain
                    # Another task drained the queue between the put and the get:
                    # nothing was dropped and the retry will succeed.
                    continue
                self.counters.dropped_queue_full += 1

    def note_sent(self) -> None:
        """Record one successful socket write."""
        self.counters.sent += 1

    def note_send_error(self) -> None:
        """Record one failed socket write."""
        self.counters.send_errors += 1

    def note_received(self) -> None:
        """Record one client message that parsed and was accepted."""
        self.counters.received += 1

    def note_refused(self) -> None:
        """Record one client message that was refused (M14.23)."""
        self.counters.refused += 1

    def note_oversized(self) -> None:
        """Record one event dropped for exceeding the event-size cap (M14.22)."""
        self.counters.dropped_oversized += 1

    def note_ping(self) -> None:
        """Record one server ping; marks the connection as awaiting a pong."""
        self.counters.pings_sent += 1
        self.awaiting_pong = True

    def note_pong(self) -> None:
        """Record a pong (or a client ping), clearing the outstanding-ping mark."""
        self.counters.pongs_received += 1
        self.awaiting_pong = False

    @property
    def queued(self) -> int:
        """Return how many messages are waiting to be written."""
        return self.queue.qsize()

    @property
    def age_seconds(self) -> float:
        """Return how long this connection has been open, in seconds."""
        return max(0.0, time.monotonic() - self.connected_monotonic)

    def snapshot(self) -> dict[str, object]:
        """Return a JSON-friendly view of this connection for diagnostics."""
        return {
            "client_id": self.client_id,
            "channel": self.channel.value,
            "state": self.state.value,
            "connected_at": self.connected_at,
            "age_seconds": round(self.age_seconds, 3),
            "queued": self.queued,
            "max_queue": int(self.max_queue),
            "awaiting_pong": bool(self.awaiting_pong),
            "offered": self.counters.offered,
            "sent": self.counters.sent,
            "dropped_queue_full": self.counters.dropped_queue_full,
            "dropped_oversized": self.counters.dropped_oversized,
            "send_errors": self.counters.send_errors,
            "received": self.counters.received,
            "refused": self.counters.refused,
        }


def build_connection(
    channel: Channel, *, queue_size: int
) -> ClientConnection:
    """Create a connection with its bounded queue already sized (M14.15).

    A tiny factory rather than a constructor call at the call site, so the queue
    cap and the recorded ``max_queue`` cannot disagree — the recorded value is
    what diagnostics report and what the tests assert against.
    """
    depth = max(int(queue_size), 1)
    return ClientConnection(
        client_id=new_client_id(),
        channel=channel,
        queue=asyncio.Queue(maxsize=depth),
        max_queue=depth,
    )


__all__ = [
    "CLIENT_ID_PREFIX",
    "ClientConnection",
    "ConnectionCounters",
    "ConnectionState",
    "build_connection",
    "new_client_id",
]
