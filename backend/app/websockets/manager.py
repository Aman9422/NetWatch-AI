"""The WebSocket manager: connection lifecycle, registry, fan-out, back-pressure (M14.2).

``WebSocketManager`` is the only object that knows about sockets, queues and the
event loop at once. It is the layer M14.2 asks for, with the methods the milestone
names — ``connect``/``disconnect``/``subscribe``/``unsubscribe``/``broadcast``/
``send``/``get_connection_count`` — plus the two entry points the rest of the
application actually uses:

* :meth:`publish` — **callable from any thread**, which is what makes it the seam
  the capture pipeline and the API can both use (M14.21). It never touches a queue
  or a socket: it hands the event to the loop with
  ``loop.call_soon_threadsafe`` and returns.
* :meth:`broadcast` — the loop-side fan-out ``publish`` schedules, split out so a
  caller already on the loop (a route, a tick, a test) can call it directly.

Three invariants hold the design together:

1. **A socket is written by exactly one task.** Each connection owns a sender task
   that drains its queue; nothing else calls ``send_text``. A heartbeat or a
   refusal is queued like any other message, so frames cannot interleave.
2. **A publish never waits and never raises.** The publisher checks the loop, hands
   over, and returns; every failure is counted rather than propagated, because
   M14.14 forbids a WebSocket fault reaching the capture thread.
3. **A broken client is removed, the others are not touched.** A send failure ends
   that connection and skips it in later fan-outs; the remaining subscribers keep
   receiving (M14.14).
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Iterable
from typing import Protocol

from app.websockets.channels import CHANNELS, Channel
from app.websockets.connection import ClientConnection, build_connection
from app.websockets.event import WebSocketEvent, encoded
from app.websockets.policy import PolicySet, default_policies

logger = logging.getLogger(__name__)

#: Close code sent when the server shuts down (M14.20): 1001 is "going away",
#: which tells a client to reconnect rather than treat the close as an error.
CLOSE_GOING_AWAY = 1001

#: Close code for a connection the server refuses: 1008 is "policy violation",
#: used for the connection caps and an unknown channel (M14.22).
CLOSE_POLICY_VIOLATION = 1008

#: Close code for a client that keeps sending messages the server will not accept
#: (M14.23).
CLOSE_INVALID_MESSAGE = 1003


class WebSocketLike(Protocol):
    """The part of a Starlette ``WebSocket`` this manager uses.

    Declared as a protocol so the manager can be tested against a fake socket
    without an ASGI stack, while the real route passes the genuine object and is
    type-compatible without a cast.
    """

    async def send_text(self, data: str) -> None:  # pragma: no cover - protocol
        """Send one text frame."""
        ...

    async def close(  # pragma: no cover - protocol
        self, code: int = 1000, reason: str | None = None
    ) -> None:
        """Close the socket."""
        ...


class WebSocketManager:
    """Owns every WebSocket connection in the process (M14.2).

    Args:
        policies: Per-channel queue depth, rate ceiling and enabled state. Defaults
            to the documented table (M14.15/M14.16).
        max_connections: Hard cap on simultaneous connections, process-wide.
        max_connections_per_channel: Hard cap per channel.
        max_event_bytes: Largest encoded event that may be queued (M14.22).
        send_timeout_seconds: How long one socket write may take before the client
            is treated as dead (M14.14).
        enabled: When False the manager accepts no connection and publishes
            nothing, which is the master switch (``websockets_enabled``).
        clock: Time source for diagnostics, injectable for tests.
    """

    def __init__(
        self,
        *,
        policies: PolicySet | None = None,
        max_connections: int = 32,
        max_connections_per_channel: int = 16,
        max_event_bytes: int = 16384,
        send_timeout_seconds: float = 5.0,
        enabled: bool = True,
        clock: object = time.time,
    ) -> None:
        self._policies = policies if policies is not None else default_policies()
        self._max_connections = max(int(max_connections), 1)
        self._max_per_channel = max(int(max_connections_per_channel), 1)
        self._max_event_bytes = max(int(max_event_bytes), 1)
        self._send_timeout = max(float(send_timeout_seconds), 0.001)
        self._enabled = bool(enabled)
        self._clock = clock

        # Registry state. Mutated on the event loop, read from any thread, so it is
        # guarded by a plain lock rather than assumed single-threaded (M14.21).
        self._lock = threading.RLock()
        self._sockets: dict[str, WebSocketLike] = {}
        self._connections: dict[str, ClientConnection] = {}
        self._order: list[str] = []

        # Cross-thread handoff. ``_loop`` is bound at startup and unbound at
        # shutdown; ``_closed`` stops a publish that races the shutdown.
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closed = False

        # Counters, incremented from the loop and from publisher threads.
        self._counters: dict[str, int] = {
            "published": 0,
            "broadcast": 0,
            "delivered": 0,
            "dropped_no_loop": 0,
            "dropped_disabled": 0,
            "dropped_rate_limited": 0,
            "rejected_oversized": 0,
            "publish_errors": 0,
            "send_errors": 0,
            "connections_accepted": 0,
            "connections_refused": 0,
            "connections_closed": 0,
            "heartbeat_pings": 0,
            "heartbeat_timeouts": 0,
        }

    # -- configuration ----------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Return whether the layer is switched on at all."""
        return self._enabled

    @property
    def policies(self) -> PolicySet:
        """Return the per-channel policy table (M14.15)."""
        return self._policies

    @property
    def max_event_bytes(self) -> int:
        """Return the encoded event-size cap (M14.22)."""
        return self._max_event_bytes

    @property
    def is_running(self) -> bool:
        """Return True while the manager has a bound loop and is not closed."""
        return self._loop is not None and not self._closed

    # -- lifecycle (M14.20) -----------------------------------------------

    def bind_loop(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Bind the event loop that publishes are handed to.

        Called at startup, and callable directly by a test that wants to drive the
        manager from outside an application. Passing ``None`` binds the running
        loop, which is the normal case; passing one explicitly is what the tests
        use.
        """
        if loop is None:
            loop = asyncio.get_running_loop()
        with self._lock:
            self._loop = loop
            self._closed = False

    async def start(self) -> None:
        """Prepare the manager to accept connections (M14.20)."""
        if not self._enabled:
            logger.info("WebSocket layer disabled by configuration")
            return
        self.bind_loop()
        logger.info("WebSocket manager started")

    async def shutdown(self) -> None:
        """Close every client and release every resource (M14.18/M14.20).

        Idempotent, and safe to call when startup never ran: a test that builds the
        application without its lifespan still gets a clean, quiet shutdown.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
            connections = list(self._connections.values())
        for connection in connections:
            await self._close_connection(connection, code=CLOSE_GOING_AWAY)
        with self._lock:
            self._sockets.clear()
            self._connections.clear()
            self._order.clear()
            self._loop = None
        logger.info("WebSocket manager stopped")

    # -- registry and lifecycle of a connection (M14.2/M14.4/M14.5) --------

    def subscribe(self, connection: ClientConnection) -> None:
        """Add ``connection`` to the registry (M14.2/M14.5).

        The registry operation on its own, without a socket: it is what
        :meth:`connect` is built from, and it is the seam a test drives when it
        wants to exercise fan-out without an ASGI stack.
        """
        with self._lock:
            self._connections[connection.client_id] = connection
            if connection.client_id not in self._order:
                self._order.append(connection.client_id)

    def unsubscribe(self, client_id: str) -> bool:
        """Remove ``client_id`` from the registry, returning whether it was there.

        ``False`` for an unknown id rather than an error, because cleanup runs from
        more than one path and a repeat must be harmless (M14.18).
        """
        with self._lock:
            removed = self._connections.pop(client_id, None) is not None
            self._sockets.pop(client_id, None)
            if client_id in self._order:
                self._order.remove(client_id)
        return removed

    @property
    def connection_count(self) -> int:
        """Return how many connections are registered (M14.2)."""
        return self.get_connection_count()

    def get_connection_count(self, channel: Channel | None = None) -> int:
        """Return the number of live connections, optionally for one channel.

        Read from any thread: the registry lock makes the count a consistent
        snapshot rather than a number assembled from a dict being mutated.
        """
        with self._lock:
            if channel is None:
                return len(self._connections)
            return sum(
                1
                for connection in self._connections.values()
                if connection.channel is channel
            )

    def get_connections(
        self, channel: Channel | None = None
    ) -> list[ClientConnection]:
        """Return a snapshot of the registered connections, in connect order."""
        with self._lock:
            ids = list(self._order)
            connections = [
                self._connections[client_id]
                for client_id in ids
                if client_id in self._connections
            ]
        if channel is None:
            return connections
        return [item for item in connections if item.channel is channel]

    def get_connection(self, client_id: str) -> ClientConnection | None:
        """Return one connection by id, or ``None``."""
        with self._lock:
            return self._connections.get(client_id)

    def check_admission(self, channel: Channel) -> str | None:
        """Return a refusal reason for a new connection, or ``None`` to admit it.

        Two caps and one switch are checked before any socket state is created, so
        a refused client is closed with a code rather than registered and then
        dropped (M14.22).
        """
        if not self._enabled:
            return "The WebSocket layer is disabled"
        if self._closed:
            # M14.20 says shutdown stops accepting new connections, and this is
            # where that is enforced: ``connect`` may still be reached from a test
            # or a route racing the lifespan, and without this check the socket
            # would be registered against an unbound loop and then sit connected
            # and silent forever — strictly worse for the client than a refusal
            # that carries a reason. ``bind_loop`` clears the flag at startup, so a
            # manager that never started is unaffected.
            return "The WebSocket layer is shutting down"
        if channel not in CHANNELS:
            return "Unknown channel"
        with self._lock:
            total = len(self._connections)
            on_channel = sum(
                1
                for connection in self._connections.values()
                if connection.channel is channel
            )
        if total >= self._max_connections:
            return "Too many WebSocket connections"
        if on_channel >= self._max_per_channel:
            return "Too many connections on this channel"
        return None

    async def connect(
        self, websocket: WebSocketLike, channel: Channel
    ) -> ClientConnection:
        """Accept a socket, register it and start its sender task (M14.2/M14.4).

        The connection's queue is sized from the channel policy, so the bound on a
        client's buffering is decided before it can receive anything.
        """
        connection = build_connection(
            channel, queue_size=self._policies.queue_size(channel)
        )
        with self._lock:
            self._sockets[connection.client_id] = websocket
        self.subscribe(connection)
        connection.mark_connected()
        connection.sender_task = asyncio.create_task(
            self._sender(websocket, connection),
            name=f"ws-sender-{connection.client_id}",
        )
        self._bump("connections_accepted")
        logger.info(
            "WebSocket client %s connected on %s", connection.client_id, channel.value
        )
        return connection

    async def disconnect(self, client_id: str) -> bool:
        """Detach one connection and release its resources (M14.18).

        Safe to call twice and safe to call for an unknown id: the second call is a
        no-op returning ``False``, which is what makes cleanup from both the route
        and a send failure harmless.
        """
        with self._lock:
            connection = self._connections.get(client_id)
        if connection is None:
            return False
        await self._close_connection(connection, code=CLOSE_GOING_AWAY)
        return True

    async def refuse(self, websocket: WebSocketLike, reason: str) -> None:
        """Close a socket the manager will not register (M14.22).

        Counted, and the close is guarded: a client that vanished between the
        admission check and the close must not turn a refusal into an exception.
        """
        self._bump("connections_refused")
        logger.warning("Refused a WebSocket connection: %s", reason)
        try:
            await websocket.close(
                code=CLOSE_POLICY_VIOLATION, reason=reason[:120]
            )
        except Exception:  # noqa: BLE001 - a refusal may not raise
            logger.debug("Failed to close a refused WebSocket cleanly")

    async def _close_connection(
        self, connection: ClientConnection, *, code: int
    ) -> None:
        """Unregister one connection, cancel its task and close its socket.

        Order matters: the connection leaves the registry *first*, so a broadcast
        that is already in flight cannot reach a socket that is about to close, and
        only then is the sender task cancelled and the socket closed.
        """
        # The socket is taken out of ``self._sockets`` *before* ``unsubscribe``
        # runs, because ``unsubscribe`` removes it too: looking it up afterwards
        # would find ``None`` and this method would return having cancelled a task
        # but never sent the close frame — no 1001 at shutdown, no close code on a
        # heartbeat retirement, and a socket left open for Starlette to reap.
        connection.mark_closing()
        with self._lock:
            websocket = self._sockets.pop(connection.client_id, None)
        self.unsubscribe(connection.client_id)
        task = connection.sender_task
        connection.sender_task = None
        if task is not None and not task.done():
            task.cancel()
        if websocket is not None:
            try:
                await websocket.close(code=code)
            except Exception:  # noqa: BLE001 - closing a dead socket may fail
                logger.debug(
                    "Failed to close WebSocket %s cleanly", connection.client_id
                )
        connection.mark_closed()
        self._bump("connections_closed")

    # -- publishing (M14.13/M14.21) ----------------------------------------

    def publish(self, event: WebSocketEvent) -> bool:
        """Hand one event to the loop, from any thread (M14.13/M14.21).

        This is the call the capture pipeline, the alert service and the capture
        manager make. It reads the loop, schedules the fan-out with
        ``call_soon_threadsafe`` and returns immediately, so a publisher never
        waits on a socket, never touches an ``asyncio.Queue`` and never raises.

        Returns:
            True when the event was accepted for dispatch, False when it was
            dropped — because the layer is disabled, has no bound loop, or is
            shutting down. A drop is counted, never logged per event: a disabled
            layer would otherwise write a log line for every packet captured.
        """
        self._bump("published")
        try:
            if not self._enabled:
                self._bump("dropped_disabled")
                return False
            loop = self._loop
            if loop is None or self._closed or loop.is_closed():
                # No loop means no subscriber can be reached: before startup,
                # after shutdown, or in a unit test with no event loop at all.
                self._bump("dropped_no_loop")
                return False
            loop.call_soon_threadsafe(self._dispatch, event)
            return True
        except Exception:  # noqa: BLE001 - publishing must never raise (M14.14)
            self._bump("publish_errors")
            logger.debug(
                "Could not publish a WebSocket event; the caller continues",
                exc_info=True,
            )
            return False

    def publish_many(self, events: Iterable[WebSocketEvent]) -> int:
        """Publish several events, returning how many were accepted."""
        return sum(1 for event in events if self.publish(event))

    def _dispatch(self, event: WebSocketEvent) -> None:
        """Run on the loop and broadcast one event, containing any failure.

        Exceptions raised inside a ``call_soon_threadsafe`` callback would
        otherwise reach the loop's exception handler with nobody to report to, so
        the containment lives here as well as in :meth:`publish` (M14.14).
        """
        try:
            self.broadcast(event)
        except Exception:  # noqa: BLE001 - the loop must survive a bad event
            self._bump("publish_errors")
            logger.warning("WebSocket broadcast failed for %s", event.type, exc_info=True)

    def broadcast(self, event: WebSocketEvent) -> int:
        """Fan one event out to its channel's subscribers (M14.2).

        Must be called on the event loop: it offers to ``asyncio.Queue`` objects,
        which are not thread-safe (M14.21). A caller on another thread uses
        :meth:`publish`.

        Returns:
            How many connections the event was queued for. A full queue still
            counts as a delivery, because the connection did receive the event —
            it dropped an older one to make room (M14.15).
        """
        channel = event.channel
        if not self._policies.is_enabled(channel):
            self._bump("dropped_disabled")
            return 0
        if not self._policies.allow(channel):
            self._bump("dropped_rate_limited")
            return 0
        encoded_text = encoded(event)
        if len(encoded_text.encode("utf-8")) > self._max_event_bytes:
            self._bump("rejected_oversized")
            logger.warning(
                "Refused an oversized %s event (> %d bytes)",
                event.type,
                self._max_event_bytes,
            )
            return 0

        delivered = 0
        for connection in self.get_connections(channel):
            if connection.is_closed:
                continue
            if connection.offer(encoded_text):
                delivered += 1
        self._bump("broadcast")
        if delivered:
            self._bump("delivered", delivered)
        return delivered

    def send(self, client_id: str, event: WebSocketEvent) -> bool:
        """Queue one event for one connection (M14.2).

        The directed counterpart of :meth:`broadcast`: a ping, a pong or a refusal
        goes to the client that earned it rather than to the channel. Loop-side for
        the same reason as :meth:`broadcast`.
        """
        connection = self.get_connection(client_id)
        if connection is None or connection.is_closed:
            return False
        encoded_text = encoded(event)
        if len(encoded_text.encode("utf-8")) > self._max_event_bytes:
            self._bump("rejected_oversized")
            return False
        return connection.offer(encoded_text)

    # -- the sender task (M14.14/M14.15) -----------------------------------

    async def _sender(
        self, websocket: WebSocketLike, connection: ClientConnection
    ) -> None:
        """Drain one connection's queue onto its socket.

        The only task that writes to this socket. A write that fails or exceeds
        the send timeout ends *this* connection and nothing else: the remaining
        subscribers continue to be served, which is M14.14's requirement that a
        broken client must not propagate into the rest of the application.
        """
        while True:
            message = await connection.queue.get()
            try:
                await asyncio.wait_for(
                    websocket.send_text(message), timeout=self._send_timeout
                )
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - a dead socket is a normal outcome
                connection.note_send_error()
                self._bump("send_errors")
                logger.info(
                    "WebSocket %s failed to send; removing it and continuing",
                    connection.client_id,
                )
                await self._close_connection(connection, code=CLOSE_GOING_AWAY)
                return
            connection.note_sent()

    async def drop(self, client_id: str, *, code: int = CLOSE_GOING_AWAY) -> bool:
        """Close and unregister one connection by id (M14.18).

        The public form of the cleanup path, so the heartbeat can retire a client
        that stopped answering without reaching into the manager's internals.
        """
        return await self.disconnect(client_id)

    # -- keepalive support (M14.24) ----------------------------------------

    async def heartbeat_tick(self) -> int:
        """Ping every live connection, retiring any that never answered.

        One outstanding ping per connection: a provider that answered the last tick
        is pinged again, and one that left the previous ping unanswered has had a
        full interval to reply and is treated as gone. That bounds a half-open
        socket's lifetime to roughly two intervals (M14.24).

        Returns:
            How many pings were queued.
        """
        from app.websockets import builders

        sent = 0
        for connection in self.get_connections():
            if connection.is_closed:
                continue
            if connection.awaiting_pong:
                self._bump("heartbeat_timeouts")
                logger.info(
                    "WebSocket %s did not answer a keepalive; removing it",
                    connection.client_id,
                )
                await self._close_connection(connection, code=CLOSE_GOING_AWAY)
                continue
            if self.send(connection.client_id, builders.ping_event(connection.channel)):
                connection.note_ping()
                sent += 1
        if sent:
            self._bump("heartbeat_pings", sent)
        return sent

    # -- diagnostics (M14.33) ----------------------------------------------

    def _bump(self, name: str, amount: int = 1) -> None:
        """Add ``amount`` to one counter under the registry lock."""
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + int(amount)

    def get_counters(self) -> dict[str, int]:
        """Return a copy of the manager counters."""
        with self._lock:
            return dict(self._counters)

    def channel_stats(self) -> dict[str, dict[str, object]]:
        """Return per-channel configuration and live depth.

        The view the benchmark and the verification script read: it states what the
        effective policy is (queue depth, rate ceiling, priority, enabled) next to
        what is happening (connections, queued messages), so a measurement can be
        interpreted without also reading the settings object.
        """
        stats: dict[str, dict[str, object]] = {}
        with self._lock:
            connections = list(self._connections.values())
        for channel in CHANNELS:
            policy = self._policies.policy(channel)
            on_channel = [
                connection
                for connection in connections
                if connection.channel is channel
            ]
            stats[channel.value] = {
                "connections": len(on_channel),
                "queued": sum(connection.queued for connection in on_channel),
                "queue_size": policy.queue_size,
                "max_events_per_second": policy.max_events_per_second,
                "priority": policy.priority,
                "enabled": policy.enabled,
            }
        return stats

    def get_stats(self) -> dict[str, object]:
        """Return counters, connections and per-channel configuration (M14.33)."""
        with self._lock:
            connections = [item.snapshot() for item in self._connections.values()]
        return {
            "enabled": self._enabled,
            "running": self.is_running,
            "connection_count": self.get_connection_count(),
            "max_connections": self._max_connections,
            "max_connections_per_channel": self._max_per_channel,
            "max_event_bytes": self._max_event_bytes,
            "counters": self.get_counters(),
            "channels": self.channel_stats(),
            "connections": connections,
        }


__all__ = [
    "CLOSE_GOING_AWAY",
    "CLOSE_INVALID_MESSAGE",
    "CLOSE_POLICY_VIOLATION",
    "WebSocketLike",
    "WebSocketManager",
]
