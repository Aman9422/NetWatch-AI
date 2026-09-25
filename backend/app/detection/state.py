"""Bounded runtime state for detection rules (M10.19, M10.20).

Detectors that reason over a time window must remember what they have seen
recently. Keeping that memory inside a rule is what lets a detector answer
questions such as *"how many distinct destination ports has this source touched
in the last ten seconds?"* without ever holding on to packet history.

Two structures cover every detector in M10:

* :class:`WindowedCounter` — per-subject event counts inside a window;
* :class:`WindowedDistinct` — per-subject distinct values inside a window.

Both are bounded in two directions (M10.19). The number of subjects is capped,
and once a structure is full the subjects holding the oldest window are evicted
*in a batch* rather than one at a time, so a flood of fresh subjects cannot turn
each insertion into a full scan. :class:`WindowedDistinct` additionally caps how
many distinct values one subject may accumulate, so a scan across every port
cannot grow a set without limit.

Both use a *tumbling* window rather than a sliding one: a subject owns a window
that starts at its first event in that window, and an event arriving after the
window has elapsed restarts it. A tumbling window is O(1) per event, stores no
per-event history, and has an explicit start and end — exactly what M10.13 asks
a window to expose. The trade-off is honest and documented: a burst that
straddles two windows can be split between them, so a threshold is measured
against the window it falls in rather than against a continuously sliding
window.

Each structure guards its own data with its own lock (M10.20), so detectors
never corrupt one another's state and no global lock is needed.
"""

from __future__ import annotations

import threading
from collections.abc import Hashable
from dataclasses import dataclass, field
from typing import Generic, TypeVar

# Value type tracked by :class:`WindowedDistinct`: a port number or an address.
ValueT = TypeVar("ValueT", bound=Hashable)

# Fraction of the capacity evicted at once when a structure is full. Batch
# eviction keeps the amortised cost of a flood of fresh subjects constant
# instead of paying a full sort on every insertion.
_EVICTION_FRACTION = 16


@dataclass
class _CountingWindow:
    """The current window of one subject in a :class:`WindowedCounter`."""

    start: float
    count: int = 0

    def has_elapsed(self, now: float, window_seconds: float) -> bool:
        """Return True when ``now`` is at or beyond this window's end."""
        return now >= self.start + window_seconds


@dataclass
class _DistinctWindow(Generic[ValueT]):
    """The current window of one subject in a :class:`WindowedDistinct`."""

    start: float
    values: set[ValueT] = field(default_factory=set)

    def has_elapsed(self, now: float, window_seconds: float) -> bool:
        """Return True when ``now`` is at or beyond this window's end."""
        return now >= self.start + window_seconds


class WindowedCounter:
    """Thread-safe per-subject event counts inside a tumbling window."""

    def __init__(self, window_seconds: float, max_keys: int = 1024) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if max_keys < 1:
            raise ValueError("max_keys must be at least 1")
        self._window_seconds = window_seconds
        self._max_keys = max_keys
        self._lock = threading.Lock()
        self._windows: dict[str, _CountingWindow] = {}

    @property
    def window_seconds(self) -> float:
        """Return the length of the window each subject is measured over."""
        return self._window_seconds

    def record(self, key: str, at: float, weight: int = 1) -> int:
        """Add ``weight`` events for ``key`` at ``at``, return the window total.

        The returned total is the count inside the subject's *current* window.
        When ``at`` falls outside the window the subject is already in, that
        window has elapsed and a fresh one starts, so the total restarts rather
        than accumulating across windows.
        """
        with self._lock:
            window = self._windows.get(key)
            if window is None or window.has_elapsed(at, self._window_seconds):
                if window is None and len(self._windows) >= self._max_keys:
                    self._evict_oldest()
                window = _CountingWindow(start=at)
                self._windows[key] = window
            window.count += weight
            return window.count

    def count(self, key: str, at: float) -> int:
        """Return the windowed count for ``key``, or 0 once it has elapsed."""
        with self._lock:
            window = self._windows.get(key)
            if window is None or window.has_elapsed(at, self._window_seconds):
                return 0
            return window.count

    def window_start(self, key: str, at: float) -> float | None:
        """Return the start of ``key``'s current window, or ``None``."""
        with self._lock:
            window = self._windows.get(key)
            if window is None or window.has_elapsed(at, self._window_seconds):
                return None
            return window.start

    def clear(self, key: str) -> None:
        """Forget ``key`` entirely (used for minimal suppression, M10.18)."""
        with self._lock:
            self._windows.pop(key, None)

    def reset(self) -> None:
        """Forget every subject."""
        with self._lock:
            self._windows.clear()

    def __len__(self) -> int:
        """Return the number of subjects currently tracked."""
        with self._lock:
            return len(self._windows)

    def _evict_oldest(self) -> None:
        """Evict the subjects holding the oldest windows (caller holds lock)."""
        batch = max(1, self._max_keys // _EVICTION_FRACTION)
        oldest = sorted(self._windows.items(), key=lambda row: row[1].start)[:batch]
        for key, _ in oldest:
            del self._windows[key]


class WindowedDistinct(Generic[ValueT]):
    """Thread-safe distinct-value tracking per subject inside a tumbling window."""

    def __init__(
        self,
        window_seconds: float,
        max_keys: int = 1024,
        max_values_per_key: int = 4096,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if max_keys < 1:
            raise ValueError("max_keys must be at least 1")
        if max_values_per_key < 1:
            raise ValueError("max_values_per_key must be at least 1")
        self._window_seconds = window_seconds
        self._max_keys = max_keys
        self._max_values_per_key = max_values_per_key
        self._lock = threading.Lock()
        self._windows: dict[str, _DistinctWindow[ValueT]] = {}

    @property
    def window_seconds(self) -> float:
        """Return the length of the window each subject is measured over."""
        return self._window_seconds

    def record(self, key: str, value: ValueT, at: float) -> int:
        """Record ``value`` for ``key`` at ``at``, return the distinct count.

        The count restarts with the subject's next window, exactly as
        :meth:`WindowedCounter.record` does. Once a subject holds
        ``max_values_per_key`` distinct values further values are not stored, so
        the count saturates instead of growing without bound (M10.19).
        """
        with self._lock:
            window = self._windows.get(key)
            if window is None or window.has_elapsed(at, self._window_seconds):
                if window is None and len(self._windows) >= self._max_keys:
                    self._evict_oldest()
                window = _DistinctWindow(start=at)
                self._windows[key] = window
            if len(window.values) < self._max_values_per_key:
                window.values.add(value)
            return len(window.values)

    def values(self, key: str, at: float) -> frozenset[ValueT]:
        """Return the distinct values for ``key``, or empty once elapsed."""
        with self._lock:
            window = self._windows.get(key)
            if window is None or window.has_elapsed(at, self._window_seconds):
                return frozenset()
            return frozenset(window.values)

    def count(self, key: str, at: float) -> int:
        """Return the number of distinct values recorded for ``key``."""
        return len(self.values(key, at))

    def window_start(self, key: str, at: float) -> float | None:
        """Return the start of ``key``'s current window, or ``None``."""
        with self._lock:
            window = self._windows.get(key)
            if window is None or window.has_elapsed(at, self._window_seconds):
                return None
            return window.start

    def clear(self, key: str) -> None:
        """Forget ``key`` entirely (used for minimal suppression, M10.18)."""
        with self._lock:
            self._windows.pop(key, None)

    def reset(self) -> None:
        """Forget every subject."""
        with self._lock:
            self._windows.clear()

    def __len__(self) -> int:
        """Return the number of subjects currently tracked."""
        with self._lock:
            return len(self._windows)

    def _evict_oldest(self) -> None:
        """Evict the subjects holding the oldest windows (caller holds lock)."""
        batch = max(1, self._max_keys // _EVICTION_FRACTION)
        oldest = sorted(self._windows.items(), key=lambda row: row[1].start)[:batch]
        for key, _ in oldest:
            del self._windows[key]
