"""High bandwidth / traffic spike detector (M10.12).

A traffic spike is unusually high observed volume. This detector consumes the
rate M6 already measures — it does **not** re-aggregate packets, and it keeps no
byte history of its own — and compares that rate with a configurable
bytes-per-second threshold.

Two details are worth being precise about, because it is easy to overclaim here:

* The measurement is M6's **one-second** rate window, and the context reports
  which window that was (``rate_window_seconds``). M6's most responsive window
  is used deliberately, so a spike is seen while it is happening rather than
  only in retrospect.
* The detector's own configured window
  (``HIGH_BANDWIDTH_TIME_WINDOW_SECONDS``) is the **minimum interval between
  findings**. A spike that lasts a minute is one condition, not sixty thousand
  findings: a further finding is raised only once that interval has passed and
  the rate is still above the threshold.

This is a traffic-volume observation, not a security verdict. Saturating a link
is often a backup, a large download or a video call, so the finding reports that
volume was high and leaves interpretation to the alert and correlation layers
(M10.16).

Nothing here blocks, shapes or rate-limits traffic, and nothing here scores risk.
"""

from __future__ import annotations

import threading

from app.detection.base import DetectionRule
from app.detection.context import DetectionContext
from app.detection.finding import DetectionFinding, threshold_confidence

# Defaults kept in step with the settings defaults (M10.7).
DEFAULT_WINDOW_SECONDS = 5.0
DEFAULT_BYTES_PER_SECOND_THRESHOLD = 1_000_000.0

# Divisor used to render the observed rate in megabytes per second.
_BYTES_PER_MEGABYTE = 1_000_000.0


class HighBandwidthRule(DetectionRule):
    """Report traffic volume above the configured rate threshold (M10.12)."""

    rule_id = "high_bandwidth"
    rule_name = "High Bandwidth"
    description = "Observed traffic volume above the configured bytes-per-second rate"

    def __init__(
        self,
        *,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        bytes_per_second_threshold: float = DEFAULT_BYTES_PER_SECOND_THRESHOLD,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled, window_seconds=window_seconds)
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if bytes_per_second_threshold <= 0:
            raise ValueError("bytes_per_second_threshold must be positive")

        self._bytes_per_second_threshold = float(bytes_per_second_threshold)
        self._suppression_seconds = float(window_seconds)
        self._lock = threading.Lock()
        self._last_fired_at: float | None = None

    def evaluate(self, context: DetectionContext) -> DetectionFinding | None:
        """Return a finding when the observed rate crosses the threshold (M10.12).

        A context that carries no traffic rate — a context built from a packet
        alone, or a statistics outage — yields ``None``. The detector never
        estimates a rate it was not given, and it reports a sustained spike at
        most once per configured window (M10.18).
        """
        bytes_per_second = context.bytes_per_second
        if bytes_per_second is None:
            return None
        if bytes_per_second < self._bytes_per_second_threshold:
            return None

        at = context.timestamp
        with self._lock:
            last_fired_at = self._last_fired_at
            if (
                last_fired_at is not None
                and at - last_fired_at < self._suppression_seconds
            ):
                return None
            self._last_fired_at = at

        megabytes = bytes_per_second / _BYTES_PER_MEGABYTE
        evidence: dict[str, int | float | str | bool] = {
            "bytes_per_second": round(bytes_per_second, 3),
            "bytes_per_second_threshold": self._bytes_per_second_threshold,
            "observation_window_seconds": self._suppression_seconds,
        }
        if context.rate_window_seconds is not None:
            evidence["measurement_window_seconds"] = context.rate_window_seconds
        if context.packets_per_second is not None:
            evidence["packets_per_second"] = round(context.packets_per_second, 3)
        if context.total_bytes is not None:
            evidence["total_bytes"] = context.total_bytes
        if context.total_packets is not None:
            evidence["total_packets"] = context.total_packets

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            timestamp=at,
            # The volume is a whole-capture observation: no single endpoint is
            # claimed, because none was observed to be its cause (M10.14).
            source_ip=None,
            destination_ip=None,
            protocol=None,
            description=(
                f"Possible traffic spike detected ({megabytes:.2f} MB/s observed)"
            ),
            evidence=evidence,
            confidence=threshold_confidence(
                bytes_per_second, self._bytes_per_second_threshold
            ),
            metadata={
                "bytes_per_second_threshold": self._bytes_per_second_threshold,
                "minimum_interval_seconds": self._suppression_seconds,
            },
        )

    def state_size(self) -> int:
        """Return 1 while a previous finding is still remembered (M10.19)."""
        with self._lock:
            return 1 if self._last_fired_at is not None else 0

    def reset(self) -> None:
        """Forget the last finding time, so the next spike reports immediately."""
        with self._lock:
            self._last_fired_at = None
