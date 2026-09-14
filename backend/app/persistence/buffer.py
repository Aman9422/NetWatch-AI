"""Bounded, thread-safe buffer of pending packet rows (M7.9).

The capture thread must never block on the database. It hands each mapped
packet to this buffer and returns immediately; a background worker drains the
buffer in batches.

The buffer is **bounded**: when it is full the *oldest* pending row is evicted
and counted. Dropping the oldest — rather than the newest — keeps the most
recent window of traffic, which is what a live-traffic view shows, and keeps the
buffer's memory independent of how long the database stays slow. Every eviction
is counted so the chosen policy is observable rather than silent (M7.9).
"""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Iterable

# Default number of rows that may wait for the database.
DEFAULT_QUEUE_MAX = 10000

# A packet row is a flat mapping of ``packets`` column name to value.
PacketRow = dict[str, object]


class BoundedPacketBuffer:
    """A bounded FIFO of pending packet rows, safe for many producers/consumers."""

    def __init__(self, max_size: int = DEFAULT_QUEUE_MAX) -> None:
        if max_size < 1:
            raise ValueError("max_size must be at least 1")
        self._max_size = max_size
        self._condition = threading.Condition()
        self._items: deque[PacketRow] = deque()
        self._dropped = 0

    @property
    def max_size(self) -> int:
        """Return the hard capacity of the buffer."""
        return self._max_size

    def put(self, row: PacketRow) -> bool:
        """Append one row.

        Returns:
            True when the row was stored; False when an older row had to be
            evicted to make room.
        """
        with self._condition:
            evicted = False
            if len(self._items) >= self._max_size:
                self._items.popleft()
                self._dropped += 1
                evicted = True
            self._items.append(row)
            self._condition.notify()
            return not evicted

    def put_many(self, rows: Iterable[PacketRow]) -> int:
        """Append many rows, returning how many were evicted to make room."""
        evicted = 0
        for row in rows:
            if not self.put(row):
                evicted += 1
        return evicted

    def get_batch(self, max_items: int) -> list[PacketRow]:
        """Remove and return up to ``max_items`` rows, oldest first."""
        if max_items < 1:
            return []
        with self._condition:
            count = min(max_items, len(self._items))
            return [self._items.popleft() for _ in range(count)]

    def drain(self) -> list[PacketRow]:
        """Remove and return every pending row, oldest first."""
        with self._condition:
            rows = list(self._items)
            self._items.clear()
            return rows

    def wait_for_item(self, timeout: float) -> bool:
        """Block until a row is available or ``timeout`` seconds pass.

        Returns:
            True if at least one row is buffered when this returns.
        """
        with self._condition:
            if not self._items:
                self._condition.wait(timeout)
            return bool(self._items)

    def wake(self) -> None:
        """Wake a thread blocked in :meth:`wait_for_item` (used on shutdown)."""
        with self._condition:
            self._condition.notify_all()

    def size(self) -> int:
        """Return how many rows are currently buffered (queue depth)."""
        with self._condition:
            return len(self._items)

    def is_empty(self) -> bool:
        """Return True when nothing is buffered."""
        with self._condition:
            return not self._items

    def dropped_count(self) -> int:
        """Return how many rows were evicted because the buffer was full."""
        with self._condition:
            return self._dropped

    def clear(self) -> None:
        """Discard every buffered row and reset the eviction counter."""
        with self._condition:
            self._items.clear()
            self._dropped = 0
