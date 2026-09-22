"""Thread-safe connection registry: the bounded store of conversations (M9.16/M9.18).

The registry is the one component that owns mutable connection state and the
only concurrency boundary of M9 — exactly as ``DeviceRegistry`` is for M8. It
keeps three structures, all guarded by a single re-entrant lock:

    _active      connection_id -> Connection   conversations still being observed
    _historical  connection_id -> Connection   retired conversations, kept for
                                               reporting and persistence
    _by_id       connection_id -> Connection   O(1) lookup across both

A record lives in exactly one of ``_active`` / ``_historical`` and always in
``_by_id``, so a lookup by id never scans. Placement is decided by one rule,
applied after every observation::

    a record that is still active   -> _active
    a record that has ended or idled out -> _historical

Memory is bounded on both sides:

* the active cap evicts the stalest records in **amortized batches**, so a flood
  of new flows costs ``O(n log k)`` per batch instead of a full scan per packet;
* the historical cap drops the oldest retired records outright.

The registry holds no policy: timeouts, capacities and persistence all arrive
from the caller, so every rule here is testable without a clock or a database.
"""

from __future__ import annotations

import heapq
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from app.connections.connection import Connection
from app.connections.identity import ConnectionKey, Flow
from app.connections.state import TcpFlags

# Defaults; the tracker supplies configured values.
DEFAULT_MAX_TRACKED = 8192
DEFAULT_MAX_HISTORICAL = 1024

# Fraction of the active cap evicted per capacity breach (1/16). Chosen so the
# eviction scan is amortized over many insertions rather than paid per packet.
_EVICTION_BATCH_DIVISOR = 16


@dataclass(frozen=True)
class ObservationResult:
    """Outcome of one :meth:`ConnectionRegistry.observe` call."""

    connection: Connection
    #: True only when this observation produced a brand-new record.
    created: bool
    #: True when this observation moved the record into the historical store.
    retired: bool


# Resolves the idle timeout for a protocol. Injected so the registry stays
# configuration-free.
TimeoutProvider = Callable[[str], float]


class ConnectionRegistry:
    """Lock-protected, bounded store of active and historical connections."""

    def __init__(
        self,
        *,
        max_tracked: int = DEFAULT_MAX_TRACKED,
        max_historical: int = DEFAULT_MAX_HISTORICAL,
    ) -> None:
        if max_tracked < 1:
            raise ValueError("max_tracked must be at least 1")
        if max_historical < 0:
            raise ValueError("max_historical must not be negative")
        self._max_tracked = max_tracked
        self._max_historical = max_historical
        self._lock = threading.RLock()
        self._active: dict[ConnectionKey, Connection] = {}
        self._historical: dict[ConnectionKey, Connection] = {}
        self._by_id: dict[str, Connection] = {}
        # Diagnostics (M9.18 / M9.27).
        self._expiration_count = 0
        self._eviction_count = 0
        self._dropped_count = 0

    # -- locking ----------------------------------------------------------

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Hold the registry lock for a compound read or write."""
        with self._lock:
            yield

    # -- ingestion --------------------------------------------------------

    def observe(
        self,
        *,
        flow: Flow,
        length: int,
        at: float,
        ip_version: int | None = None,
        tcp_flags: TcpFlags | None = None,
        source_device_id: str | None = None,
        destination_device_id: str | None = None,
    ) -> ObservationResult:
        """Attribute one packet to its conversation, creating it when new.

        Returns:
            An :class:`ObservationResult` describing what changed.
        """
        key = flow.key()
        with self._lock:
            connection = self._active.get(key) or self._historical.get(key)
            created = connection is None
            if connection is None:
                connection = Connection.create(flow=flow, ip_version=ip_version)
                self._active[key] = connection
                self._by_id[connection.connection_id] = connection
            before_active = key in self._active

            connection.observe(
                direction=connection.direction_for(flow),
                length=length,
                at=at,
                tcp_flags=tcp_flags,
                source_device_id=source_device_id,
                destination_device_id=destination_device_id,
            )

            retired = self._place(connection) if before_active else False
            if retired:
                self._expiration_count += 1
            self._enforce_active_capacity(now=at, protected_id=connection.connection_id)
            return ObservationResult(
                connection=connection, created=created, retired=retired
            )

    def expire(self, *, now: float, timeout_for: TimeoutProvider) -> list[Connection]:
        """Retire every active conversation idle beyond its protocol timeout.

        Args:
            now: Current time in epoch seconds.
            timeout_for: Resolves the idle timeout for a protocol name.

        Returns:
            The connections retired by this sweep, in no particular order. They
            remain queryable in the historical store; the caller decides whether
            to persist them.
        """
        with self._lock:
            victims = [
                connection
                for connection in self._active.values()
                if connection.has_idled_out(now=now, timeout=timeout_for(connection.protocol))
            ]
            for connection in victims:
                self._retire_locked(connection, at=now)
                self._expiration_count += 1
            self._enforce_historical_capacity()
            return victims

    def collect_dirty(self) -> list[Connection]:
        """Return records with unwritten observations and clear their dirty flag.

        Clearing happens under the lock, so an observation that lands while the
        caller is writing is simply flagged again and picked up next sweep.
        """
        with self._lock:
            dirty = [connection for connection in self._all() if connection.dirty]
            for connection in dirty:
                connection.dirty = False
            return dirty

    # -- lookups ----------------------------------------------------------

    def get(self, connection_id: str) -> Connection | None:
        """Return the tracked connection with ``connection_id``, or ``None``."""
        with self._lock:
            return self._by_id.get(connection_id)

    def get_by_key(self, key: ConnectionKey) -> Connection | None:
        """Return the tracked connection for a canonical key, or ``None``."""
        with self._lock:
            return self._active.get(key) or self._historical.get(key)

    def all_active(self) -> list[Connection]:
        """Return a snapshot list of the still-active conversations."""
        with self._lock:
            return list(self._active.values())

    def all_historical(self) -> list[Connection]:
        """Return a snapshot list of the retired conversations."""
        with self._lock:
            return list(self._historical.values())

    def all_tracked(self) -> list[Connection]:
        """Return a snapshot list of every tracked conversation."""
        with self._lock:
            return self._all()

    def count_active(self) -> int:
        """Return how many conversations are currently active."""
        with self._lock:
            return len(self._active)

    def count_historical(self) -> int:
        """Return how many retired conversations are retained."""
        with self._lock:
            return len(self._historical)

    # -- mutation ---------------------------------------------------------

    def reset(self) -> None:
        """Drop every tracked connection and diagnostic counter."""
        with self._lock:
            self._active.clear()
            self._historical.clear()
            self._by_id.clear()
            self._expiration_count = 0
            self._eviction_count = 0
            self._dropped_count = 0

    # -- diagnostics ------------------------------------------------------

    def expiration_count(self) -> int:
        """Return how many times a record ended (close or idle timeout)."""
        with self._lock:
            return self._expiration_count

    def eviction_count(self) -> int:
        """Return how many records the active cap pushed into history."""
        with self._lock:
            return self._eviction_count

    def dropped_count(self) -> int:
        """Return how many retired records the historical cap discarded."""
        with self._lock:
            return self._dropped_count

    # -- internals (caller holds the lock) --------------------------------

    def _all(self) -> list[Connection]:
        """Return every tracked record (active plus historical)."""
        return list(self._active.values()) + list(self._historical.values())

    def _place(self, connection: Connection) -> bool:
        """Move ``connection`` to the store its current state belongs in.

        Returns True when the move was a retirement into history.
        """
        key = connection.key
        if connection.is_active:
            if key not in self._active:
                self._historical.pop(key, None)
                self._active[key] = connection
            return False
        if key in self._active:
            self._retire_locked(connection, at=connection.last_seen)
            return True
        self._historical[key] = connection
        return False

    def _retire_locked(self, connection: Connection, *, at: float) -> None:
        """Move a record from active to historical (caller holds the lock)."""
        self._active.pop(connection.key, None)
        self._historical[connection.key] = connection
        connection.retire(at=at)

    def _enforce_active_capacity(self, *, now: float, protected_id: str) -> None:
        """Evict the stalest active records in a batch when over capacity."""
        overflow = len(self._active) - self._max_tracked
        if overflow <= 0:
            return
        batch = max(1, self._max_tracked // _EVICTION_BATCH_DIVISOR)
        candidates = (
            connection
            for connection in self._active.values()
            if connection.connection_id != protected_id
        )
        victims = heapq.nsmallest(
            batch, candidates, key=lambda item: (item.last_seen, item.connection_id)
        )
        for connection in victims:
            self._retire_locked(connection, at=now)
            self._eviction_count += 1
        self._enforce_historical_capacity()

    def _enforce_historical_capacity(self) -> None:
        """Drop the oldest retired records once the historical cap is exceeded.

        A discarded record may still have carried unwritten observations. The
        cap is a memory guarantee (M9.18) and wins over completeness; the loss
        is counted rather than hidden.
        """
        overflow = len(self._historical) - self._max_historical
        if overflow <= 0:
            return
        victims = heapq.nsmallest(
            overflow,
            list(self._historical.values()),
            key=lambda item: (item.last_seen, item.connection_id),
        )
        for connection in victims:
            self._drop_locked(connection)
            self._dropped_count += 1

    def _drop_locked(self, connection: Connection) -> None:
        """Remove a record from the registry entirely (caller holds the lock)."""
        self._active.pop(connection.key, None)
        self._historical.pop(connection.key, None)
        self._by_id.pop(connection.connection_id, None)
