"""Sliding-window rate tracking for packets/sec and bytes/sec (M6.8/M6.9).

Events are aggregated into fixed-size time buckets instead of being stored
individually. That keeps the memory footprint proportional to the window length
(``window_seconds / bucket_seconds`` buckets, a small constant) rather than to
the number of packets observed, so the engine's memory stays controlled even at
high packet rates (M6.14).
"""

import threading
import time

# Default bucket resolution. 100 ms is fine-grained enough for 1s/10s/60s rate
# meters while keeping every window to a few hundred buckets at most.
DEFAULT_BUCKET_SECONDS = 0.1

# Microseconds per second, used to turn time into an exact integer bucket index.
_MICROSECONDS = 1_000_000


class RateWindow:
    """Tracks counts over a sliding time window and reports rates.

    Events fall into fixed sub-second buckets. Buckets older than
    ``window_seconds`` are dropped both when a new bucket is created and when the
    current rate is requested, so the buffer stays bounded even if the rate is
    never read.
    """

    def __init__(
        self,
        window_seconds: float = 1.0,
        bucket_seconds: float = DEFAULT_BUCKET_SECONDS,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if bucket_seconds <= 0:
            raise ValueError("bucket_seconds must be positive")
        self._window_seconds = window_seconds
        self._bucket_micros = max(1, int(bucket_seconds * _MICROSECONDS))
        self._lock = threading.Lock()
        # bucket index -> [packets, bytes]
        self._buckets: dict[int, list[int]] = {}

    def record(self, packets: int = 1, num_bytes: int = 0, at: float | None = None) -> None:
        """Record an event occurring at ``at`` (epoch seconds, default now).

        The event is merged into its time bucket; when a new bucket is opened,
        anything older than the window is dropped so the buffer cannot grow
        without bound.
        """
        timestamp = at if at is not None else time.time()
        index = self._bucket_index(timestamp)
        with self._lock:
            bucket = self._buckets.get(index)
            if bucket is None:
                self._buckets[index] = [packets, num_bytes]
                self._prune(timestamp - self._window_seconds)
            else:
                bucket[0] += packets
                bucket[1] += num_bytes

    def rates(self, now: float | None = None) -> tuple[float, float]:
        """Return ``(packets_per_second, bytes_per_second)`` for the window."""
        reference = now if now is not None else time.time()
        with self._lock:
            self._prune(reference - self._window_seconds)
            total_packets = sum(bucket[0] for bucket in self._buckets.values())
            total_bytes = sum(bucket[1] for bucket in self._buckets.values())
        return total_packets / self._window_seconds, total_bytes / self._window_seconds

    def reset(self) -> None:
        """Clear all recorded events."""
        with self._lock:
            self._buckets.clear()

    def _bucket_index(self, timestamp: float) -> int:
        """Return the bucket index that ``timestamp`` falls into.

        Uses integer microseconds so the index is stable and free of the
        rounding drift that ``timestamp / bucket_seconds`` would introduce.
        """
        return int(timestamp * _MICROSECONDS) // self._bucket_micros

    def _prune(self, cutoff: float) -> None:
        """Drop buckets starting before ``cutoff`` (caller holds the lock)."""
        cutoff_index = int(cutoff * _MICROSECONDS) // self._bucket_micros
        stale = [index for index in self._buckets if index < cutoff_index]
        for index in stale:
            del self._buckets[index]
