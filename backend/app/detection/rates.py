"""Traffic-rate acquisition for the detection engine (M10.12).

The high bandwidth detector consumes a rate rather than counting bytes itself
(M10.12), so the engine needs a small, cheap, failure-isolated way to read the
rate M6 already maintains. That is all this module does.

Two properties matter:

* **It is throttled.** The rate is recomputed at most once per ``ttl_seconds``.
  M6 recomputes from its sliding window on every call, and calling it for every
  captured packet would add that work to the hot path for no benefit — a
  one-second window barely moves inside half a second.
* **It never raises.** A source that fails is reported as "no rate available",
  the failure is counted for diagnostics, and detection continues on every rule
  that does not need a rate (M10.17).
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Protocol

logger = logging.getLogger(__name__)

# M6's supported rate windows: label -> seconds. Mirrored here so the engine can
# state the window a rate was measured over without reaching into M6.
_RATE_WINDOWS: dict[str, float] = {"1s": 1.0, "10s": 10.0, "60s": 60.0}

# The most responsive rate M6 offers, and therefore the default.
DEFAULT_RATES_WINDOW = "1s"

# How long a computed rate is reused. Half a second keeps the per-packet cost
# negligible while staying well inside the one-second measurement window.
DEFAULT_RATES_TTL_SECONDS = 0.5


class TrafficRatesSource(Protocol):
    """Anything that can report ``(packets_per_second, bytes_per_second)``."""

    def get_rates(self, window: str = "1s") -> tuple[float, float]:
        """Return the observed rates for ``window``."""
        ...


def window_seconds(window: str) -> float:
    """Return the length in seconds of an M6 rate window label.

    Raises:
        ValueError: If the label is not one M6 supports.
    """
    try:
        return _RATE_WINDOWS[window]
    except KeyError:
        raise ValueError(f"Unknown rate window: {window}") from None


class RatesFeed:
    """Reads M6 traffic rates, throttled and failure-isolated (M10.12)."""

    def __init__(
        self,
        source: TrafficRatesSource,
        window: str = DEFAULT_RATES_WINDOW,
        ttl_seconds: float = DEFAULT_RATES_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._source = source
        self._window = window
        self._window_seconds = window_seconds(window)
        self._ttl_seconds = max(0.0, float(ttl_seconds))
        self._clock = clock
        self._lock = threading.Lock()
        self._cached: tuple[float, float] | None = None
        self._cached_at = 0.0
        self._error_count = 0

    @property
    def window(self) -> str:
        """Return the M6 window label this feed reads."""
        return self._window

    @property
    def window_seconds(self) -> float:
        """Return the length of that window, for reporting on a finding."""
        return self._window_seconds

    @property
    def error_count(self) -> int:
        """Return how many rate reads have failed."""
        with self._lock:
            return self._error_count

    def current(self) -> tuple[float | None, float | None]:
        """Return the cached rates, refreshing them when the TTL has expired.

        Returns:
            ``(packets_per_second, bytes_per_second)``, or ``(None, None)`` when
            the source failed. ``None`` means "the rate is unknown" — a detector
            must never substitute a guess for it.
        """
        now = self._clock()
        with self._lock:
            cached = self._cached
            if cached is not None and now - self._cached_at < self._ttl_seconds:
                return cached

        try:
            packets_per_second, bytes_per_second = self._source.get_rates(self._window)
        except Exception:  # noqa: BLE001 - detection continues without a rate
            with self._lock:
                self._error_count += 1
            logger.warning(
                "Traffic rate unavailable; detection continues without it"
            )
            return None, None

        rates = (float(packets_per_second), float(bytes_per_second))
        with self._lock:
            self._cached = rates
            self._cached_at = self._clock()
        return rates

    def reset(self) -> None:
        """Discard the cached rate and the failure count."""
        with self._lock:
            self._cached = None
            self._cached_at = 0.0
            self._error_count = 0
