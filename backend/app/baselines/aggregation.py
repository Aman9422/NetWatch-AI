"""In-memory behavioural window aggregation (M21.5).

Packets never go to the database. They update a small counter per device per
window in memory, and a closed window is written in one batched transaction. This
module is that in-memory state and nothing else — no database, no thread, no
clock of its own. The engine drives it.

## Bounded by construction

Three caps keep the footprint bounded, and each one records that it was hit
rather than silently under-reporting:

* ``max_devices`` — how many windows may be open at once. A device normally holds
  exactly one, so this reads as a device bound; the guarantee is on windows,
  because windows are what consume memory. Over capacity the stalest window is
  evicted, so a flood of spoofed addresses costs one eviction instead of
  unbounded memory. The same rule bounds a single device whose windows cannot be
  flushed: its oldest windows are evicted before a stalled database can grow the
  buffer without limit.
* ``max_peers`` / ``max_ports`` — how many distinct peers and destination ports
  one window may remember. A peer flood fills the set and sets
  ``peers_truncated``; the count then reads as "at least this many" rather than
  as an exact number that was never measured.
* ``max_connection_keys`` — how many conversation keys one device remembers
  across windows to answer "is this new?". A device that exceeds it stops
  reporting new connections rather than growing without bound, and the fact is
  counted.

## Why the window is keyed on a floored time

``window_start`` is the packet timestamp floored to a multiple of the window
length, in UTC. That makes the boundaries deterministic and independent of when
aggregation happened to start, so two runs over the same traffic produce the same
windows — which is what a test and a benchmark both need.

## Why a device may hold more than one pending window

The map is keyed on ``(device_key, window_start)`` rather than on the device. A
device that keeps transmitting while the flush thread is behind must not have its
earlier window replaced by the later one: that would silently drop observations
that really happened, and the number of samples a device accumulates would depend
on how quickly the disk happened to drain a backlog. Keying on both keeps every
unflushed window, and ``close_expired`` removes them by exactly that key.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.baselines.features import (
    PacketObservation,
    is_dns,
    is_icmp,
    is_tcp,
    is_udp,
)

#: Defaults, mirroring ``app.config.settings`` so the class is usable alone.
DEFAULT_WINDOW_SECONDS = 60.0
DEFAULT_MAX_DEVICES = 4096
DEFAULT_MAX_PEERS = 1024
DEFAULT_MAX_PORTS = 1024
DEFAULT_MAX_CONNECTION_KEYS = 4096

#: A key identifying one device's window: the device and the floored window start.
WindowKey = tuple[str, float]


def floor_window(timestamp: float, window_seconds: float) -> float:
    """Return the start of the window ``timestamp`` falls in.

    Args:
        timestamp: Epoch seconds, as carried by a normalized packet.
        window_seconds: Length of one aggregation window; must be positive.

    Returns:
        The largest multiple of ``window_seconds`` that is ``<= timestamp``.

    Raises:
        ValueError: If ``window_seconds`` is not positive. A window length of
            zero would put every packet in one window or in an infinite number
            of them depending on the arithmetic chosen, and neither is a
            behaviour worth having.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    return math.floor(timestamp / window_seconds) * window_seconds


def window_start_datetime(window_start: float) -> datetime:
    """Return a window start as a naive UTC ``datetime``.

    The project stores UTC timestamps in SQLite as naive datetimes (see
    ``app.models.mixins.utcnow``, whose result is stored the same way). This
    function is that conversion, written once, so a window row, a profile row and
    an API response can never disagree about what a timestamp means.
    """
    return datetime.fromtimestamp(window_start, tz=timezone.utc).replace(tzinfo=None)


@dataclass
class WindowCounters:
    """The counters accumulated for one device inside one window (M21.4).

    A plain mutable dataclass, touched only while the aggregator's lock is held.
    """

    device_key: str
    identity_kind: str
    window_start: float
    window_seconds: float
    packet_count: int = 0
    byte_count: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    dns_packets: int = 0
    new_connections: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    mac_address: str | None = None
    ip_address: str | None = None
    peers: set[str] = field(default_factory=set)
    ports: set[int] = field(default_factory=set)
    peers_truncated: bool = False
    ports_truncated: bool = False
    #: Every distinct conversation key seen in this window, so a flush can hand
    #: them to the device's remembered-key set without a second pass.
    conversation_keys: set[str] = field(default_factory=set)

    @property
    def observed(self) -> bool:
        """Return True when the window actually saw traffic.

        This is the guard that stops a zero-valued row being written. A window
        that observed nothing is not a sample of a silent device; it is a window
        in which nothing was recorded, and those are different facts (M21.5).
        """
        return self.packet_count > 0

    def record(
        self,
        observation: PacketObservation,
        *,
        at: float,
        max_peers: int,
        max_ports: int,
        is_new_conversation: bool,
    ) -> None:
        """Fold one packet observation into these counters."""
        if self.first_seen is None:
            self.first_seen = at
        self.last_seen = at
        self.packet_count += 1
        self.byte_count += observation.length
        if is_tcp(observation):
            self.tcp_packets += 1
        elif is_udp(observation):
            self.udp_packets += 1
        elif is_icmp(observation):
            self.icmp_packets += 1
        if is_dns(observation):
            self.dns_packets += 1

        if observation.mac_address is not None:
            self.mac_address = observation.mac_address
        if observation.ip_address is not None:
            self.ip_address = observation.ip_address

        if observation.peer_ip is not None:
            if len(self.peers) < max_peers:
                self.peers.add(observation.peer_ip)
            elif observation.peer_ip not in self.peers:
                # The set is full *and* this is a peer it does not hold, so the
                # cardinality below is a floor. Recorded rather than hidden.
                self.peers_truncated = True

        if observation.destination_port is not None:
            if len(self.ports) < max_ports:
                self.ports.add(observation.destination_port)
            elif observation.destination_port not in self.ports:
                self.ports_truncated = True

        key = observation.conversation_key
        if key is not None:
            self.conversation_keys.add(key)
        if is_new_conversation:
            self.new_connections += 1

    @property
    def unique_peers(self) -> int:
        """Return the number of distinct peers observed in this window."""
        return len(self.peers)

    @property
    def unique_destination_ports(self) -> int:
        """Return the number of distinct destination ports observed."""
        return len(self.ports)


class WindowAggregator:
    """Holds the open windows of every device and closes them on demand (M21.5).

    Thread-safe: the capture thread calls :meth:`observe_packet` while the flush
    thread calls :meth:`close_expired`, so every mutation happens under one
    re-entrant lock. The lock is held only for the in-memory update — never
    across a database write — so a slow disk cannot stall capture.
    """

    def __init__(
        self,
        *,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        max_devices: int = DEFAULT_MAX_DEVICES,
        max_peers: int = DEFAULT_MAX_PEERS,
        max_ports: int = DEFAULT_MAX_PORTS,
        max_connection_keys: int = DEFAULT_MAX_CONNECTION_KEYS,
    ) -> None:
        """Create an aggregator.

        Args:
            window_seconds: Length of one window.
            max_devices: Cap on windows held open at once, which is one per
                active device in normal operation.
            max_peers: Cap on distinct peers remembered per window.
            max_ports: Cap on distinct destination ports remembered per window.
            max_connection_keys: Cap on conversation keys remembered per device.

        Raises:
            ValueError: If any cap or the window length is not positive.
        """
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if max_devices < 1:
            raise ValueError("max_devices must be at least 1")
        if max_peers < 1:
            raise ValueError("max_peers must be at least 1")
        if max_ports < 1:
            raise ValueError("max_ports must be at least 1")
        if max_connection_keys < 1:
            raise ValueError("max_connection_keys must be at least 1")

        self._window_seconds = float(window_seconds)
        self._max_devices = max_devices
        self._max_peers = max_peers
        self._max_ports = max_ports
        self._max_connection_keys = max_connection_keys

        self._lock = threading.RLock()
        #: One entry per open window, so a device with a backlog holds several.
        #: The tuple key is what stops a newer window replacing an older one.
        self._windows: dict[WindowKey, WindowCounters] = {}
        #: Conversation keys each device has ever seen, for the "new connection"
        #: feature. Bounded per device; a device that exceeds the cap stops
        #: reporting new connections rather than growing without bound.
        self._known_conversations: dict[str, set[str]] = {}
        self._eviction_count = 0
        self._skipped_count = 0
        self._conversation_cap_count = 0

    # -- properties -------------------------------------------------------

    @property
    def window_seconds(self) -> float:
        """Return the configured window length in seconds."""
        return self._window_seconds

    @property
    def tracked_devices(self) -> int:
        """Return how many distinct devices currently hold a live window."""
        with self._lock:
            return len({device_key for device_key, _ in self._windows})

    @property
    def pending_windows(self) -> int:
        """Return how many windows are awaiting a flush.

        Never larger than the device cap, and equal to the device count whenever
        every device holds only its current window — which is the steady state.
        """
        with self._lock:
            return len(self._windows)

    # -- ingestion --------------------------------------------------------

    def observe_packet(self, observation: PacketObservation, *, at: float) -> bool:
        """Fold one packet into its device's window for ``at``.

        Args:
            observation: The features extracted from the packet.
            at: Observation time in epoch seconds.

        Returns:
            True when the packet was aggregated, False when it was skipped. A
            skip is counted rather than raised: one unattributable packet must
            not interrupt capture (M21.5).
        """
        try:
            return self._observe(observation, at)
        except Exception:  # noqa: BLE001 - aggregation must never stop capture
            with self._lock:
                self._skipped_count += 1
            return False

    def _observe(self, observation: PacketObservation, at: float) -> bool:
        """Implementation of :meth:`observe_packet`."""
        with self._lock:
            start = floor_window(at, self._window_seconds)
            device_key = observation.device_key
            window_key: WindowKey = (device_key, start)
            counters = self._windows.get(window_key)
            if counters is None:
                # A window that is not open yet. Any other window of this device
                # stays in the map: it has not been flushed, and dropping it here
                # would lose observations that really happened (M21.5).
                counters = WindowCounters(
                    device_key=device_key,
                    identity_kind=observation.identity_kind,
                    window_start=start,
                    window_seconds=self._window_seconds,
                )
                self._windows[window_key] = counters
                self._enforce_capacity(protected_key=window_key)

            is_new = self._note_conversation(device_key, observation)
            counters.record(
                observation,
                at=at,
                max_peers=self._max_peers,
                max_ports=self._max_ports,
                is_new_conversation=is_new,
            )
            return True

    def _note_conversation(
        self, device_key: str, observation: PacketObservation
    ) -> bool:
        """Record a conversation key for a device; return True if it is new.

        Called with the lock held. Returns False when the packet carries no
        conversation key, because "this packet has no peer" is not evidence that
        a conversation started.
        """
        conversation = observation.conversation_key
        if conversation is None:
            return False
        known = self._known_conversations.get(device_key)
        if known is None:
            known = set()
            self._known_conversations[device_key] = known
        if conversation in known:
            return False
        if len(known) >= self._max_connection_keys:
            # The cap is reached. The device keeps reporting on the keys it
            # knows, but a genuinely new conversation can no longer be told apart
            # from a forgotten one, so nothing is claimed and the event is
            # counted.
            self._conversation_cap_count += 1
            return False
        known.add(conversation)
        return True

    # -- closing windows --------------------------------------------------

    def close_expired(self, *, now: float) -> list[WindowCounters]:
        """Close every window that has ended as of ``now`` and return them.

        A window is expired once ``now`` has reached the start of the *next*
        window, so the window a packet at ``now`` would fall in is never closed
        while it is still current. Closed counters are removed from the map, so a
        second call returns nothing for them.

        Args:
            now: The current time in epoch seconds.

        Returns:
            The closed windows, in no particular order.
        """
        with self._lock:
            current = floor_window(now, self._window_seconds)
            expired = [
                window_key
                for window_key, counters in self._windows.items()
                if counters.window_start < current
            ]
            closed = [self._windows.pop(window_key) for window_key in expired]
            return closed

    def drain(self) -> list[WindowCounters]:
        """Close every window, current ones included, and return them.

        Used on graceful shutdown, where a partial window is still worth keeping:
        those counters are real observations, and dropping them would mean a
        session that ended mid-window contributed nothing to the baseline. The
        caller still discards a drained window that observed nothing, so this
        never invents a sample.
        """
        with self._lock:
            closed = list(self._windows.values())
            self._windows.clear()
            return closed

    def forget_device(self, device_key: str) -> None:
        """Drop a device's windows and remembered conversations (M21.10 reset).

        Every open window of the device goes, not just its current one, or a
        reset could be undone by an older window that was still waiting to be
        flushed. The "new connection" memory is cleared too: without that, every
        conversation the device had already had would still count as old.
        """
        with self._lock:
            stale = [
                window_key
                for window_key, counters in self._windows.items()
                if counters.device_key == device_key
            ]
            for window_key in stale:
                del self._windows[window_key]
            self._known_conversations.pop(device_key, None)

    def reset(self) -> None:
        """Drop every window, every remembered conversation and every counter."""
        with self._lock:
            self._windows.clear()
            self._known_conversations.clear()
            self._eviction_count = 0
            self._skipped_count = 0
            self._conversation_cap_count = 0

    # -- diagnostics ------------------------------------------------------

    def get_skipped_count(self) -> int:
        """Return how many packets could not be aggregated."""
        with self._lock:
            return self._skipped_count

    def get_eviction_count(self) -> int:
        """Return how many windows were evicted by the window cap."""
        with self._lock:
            return self._eviction_count

    def get_conversation_cap_count(self) -> int:
        """Return how many new conversations could not be recorded (cap hit)."""
        with self._lock:
            return self._conversation_cap_count

    # -- internals --------------------------------------------------------

    def _enforce_capacity(self, *, protected_key: WindowKey) -> None:
        """Evict the stalest window(s) until the window cap holds.

        ``protected_key`` is the window just opened and is never evicted: it is
        by definition the most recently active, and evicting it would make the
        observation that triggered this call lose its own window.
        """
        while len(self._windows) > self._max_devices:
            candidates = [
                window_key
                for window_key in self._windows
                if window_key != protected_key
            ]
            if not candidates:
                return
            victim = min(candidates, key=self._staleness)
            del self._windows[victim]
            self._eviction_count += 1

    def _staleness(self, window_key: WindowKey) -> tuple[float, float, str]:
        """Return a sort key that orders windows oldest-activity first.

        A window that has never recorded a packet falls back to its start time,
        so it competes on the same scale as one that has. The window start is the
        tie-breaker, which keeps eviction deterministic when two windows were
        last touched at the same instant.
        """
        counters = self._windows[window_key]
        last_seen = counters.last_seen if counters.last_seen is not None else 0.0
        return (last_seen, counters.window_start, counters.device_key)


__all__ = [
    "DEFAULT_MAX_CONNECTION_KEYS",
    "DEFAULT_MAX_DEVICES",
    "DEFAULT_MAX_PEERS",
    "DEFAULT_MAX_PORTS",
    "DEFAULT_WINDOW_SECONDS",
    "WindowAggregator",
    "WindowCounters",
    "WindowKey",
    "floor_window",
    "window_start_datetime",
]
