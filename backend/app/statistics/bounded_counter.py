"""Bounded packet/byte counters keyed by a string (M6.14).

High-cardinality data (source IPs, destination IPs, ports) must not grow
without limit. :class:`BoundedCounter` keeps at most ``max_keys`` entries and,
when full, evicts the entry with the smallest packet count. This keeps memory
bounded while preserving the "top talkers" signal that matters most.

Eviction uses a lazily-invalidated min-heap rather than a linear ``min()`` scan,
so admitting a new key costs O(log n) instead of O(n). Without the heap, a flood
of fresh keys (port scans, spoofed sources) would pay a full scan of every
tracked key on each insertion.
"""

import heapq
import threading


class BoundedCounter:
    """A thread-safe, size-limited counter of ``(packets, bytes)`` per key."""

    def __init__(self, max_keys: int = 1024) -> None:
        if max_keys < 1:
            raise ValueError("max_keys must be at least 1")
        self._max_keys = max_keys
        self._lock = threading.Lock()
        self._counters: dict[str, list[int]] = {}
        # Min-heap of ``(packet_count_at_push, key)``. Entries become stale as a
        # key's count grows; they are discarded lazily when popped. Rebuilt when
        # it outgrows the live data so memory stays proportional to ``max_keys``.
        self._heap: list[tuple[int, str]] = []
        self._heap_rebuild_threshold = max_keys * 4 + 16

    def add(self, key: str, packets: int = 1, num_bytes: int = 0) -> None:
        """Add packet/byte counts for ``key``, evicting the smallest if full."""
        with self._lock:
            entry = self._counters.get(key)
            if entry is None:
                if len(self._counters) >= self._max_keys:
                    self._evict_smallest()
                self._counters[key] = [packets, num_bytes]
                heapq.heappush(self._heap, (packets, key))
                return
            entry[0] += packets
            entry[1] += num_bytes
            heapq.heappush(self._heap, (entry[0], key))
            if len(self._heap) > self._heap_rebuild_threshold:
                self._rebuild_heap()

    def items(self) -> dict[str, tuple[int, int]]:
        """Return a snapshot copy of all ``{key: (packets, bytes)}`` entries."""
        with self._lock:
            return {key: (value[0], value[1]) for key, value in self._counters.items()}

    def top(self, limit: int = 10, by: str = "packets") -> list[tuple[str, int, int]]:
        """Return the ``limit`` busiest keys, ranked by ``packets`` or ``bytes``.

        Args:
            limit: Maximum number of entries to return.
            by: Ranking metric, ``"packets"`` or ``"bytes"``.

        Returns:
            A list of ``(key, packets, bytes)`` tuples, highest first. Ties are
            broken by key so ordering is deterministic.
        """
        with self._lock:
            rows = [
                (key, value[0], value[1]) for key, value in self._counters.items()
            ]
        if by == "bytes":
            rows.sort(key=lambda row: (-row[2], row[0]))
        else:
            rows.sort(key=lambda row: (-row[1], row[0]))
        return rows[:limit]

    def reset(self) -> None:
        """Clear all counters."""
        with self._lock:
            self._counters.clear()
            self._heap.clear()

    def __len__(self) -> int:
        """Return the number of distinct keys currently tracked."""
        with self._lock:
            return len(self._counters)

    def _evict_smallest(self) -> None:
        """Remove the key with the fewest packets (caller holds the lock).

        Discards stale heap entries (whose recorded count no longer matches the
        live value, or whose key is gone) until the smallest *valid* key is on
        top, then evicts it.
        """
        while self._heap:
            count, key = self._heap[0]
            entry = self._counters.get(key)
            if entry is None or entry[0] != count:
                heapq.heappop(self._heap)
                continue
            heapq.heappop(self._heap)
            del self._counters[key]
            return
        # Heap exhausted without a valid entry (defensive fallback).
        if self._counters:
            smallest_key = min(self._counters, key=lambda key: self._counters[key][0])
            del self._counters[smallest_key]

    def _rebuild_heap(self) -> None:
        """Rebuild the heap from live data (caller holds the lock)."""
        self._heap = [(value[0], key) for key, value in self._counters.items()]
        heapq.heapify(self._heap)
