"""SYN flood detector (M10.9).

A SYN flood is a destination receiving an unusually high rate of TCP SYNs. This
detector keys on the **destination** — the party being flooded — and measures
SYN packets per second against a configurable rate threshold over a configurable
window.

Only pure SYNs count (``SYN`` without ``ACK``). A ``SYN+ACK`` is a *reply* to a
SYN, so counting it would let ordinary server traffic inflate the rate; the
signal for a flood is unanswered connection openings aimed at one host.

A single SYN is never reported as a flood, whatever the configured rate: the
detector requires at least two observed SYNs in the window before it will fire.
That keeps a low threshold from turning one ordinary packet into a dramatic
finding (M10.9).

The finding names the destination. It names the source only when exactly one
source was actually observed — reporting one arbitrary source out of a spoofed
flood would be misleading (M10.14). The distinct source count is reported as
evidence instead, and correlating those sources belongs to M12, not here.

Nothing here blocks, drops or rate-limits traffic, and nothing here scores risk.
"""

from __future__ import annotations

import threading

from app.detection.base import DetectionRule
from app.detection.context import DetectionContext
from app.detection.finding import DetectionFinding, threshold_confidence
from app.detection.rules.signals import is_handshake_open
from app.detection.state import WindowedCounter, WindowedDistinct

# Defaults kept in step with the settings defaults (M10.7).
DEFAULT_WINDOW_SECONDS = 5.0
DEFAULT_RATE_THRESHOLD = 200.0
DEFAULT_MAX_KEYS = 4096

# Fewest SYNs that can ever constitute a flood, regardless of configuration.
MINIMUM_SYN_PACKETS = 2

# One distinct source value is stored per destination, so nothing to cap beyond
# the source cap; a small number keeps a spoofed flood's memory bounded (M10.19).
MAX_SOURCES_PER_DESTINATION = 1024


class SynFloodRule(DetectionRule):
    """Report a destination receiving an excessive rate of TCP SYNs (M10.9)."""

    rule_id = "syn_flood"
    rule_name = "SYN Flood"
    description = "One destination receiving an excessive rate of TCP SYN packets"

    def __init__(
        self,
        *,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        rate_threshold: float = DEFAULT_RATE_THRESHOLD,
        max_keys: int = DEFAULT_MAX_KEYS,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled, window_seconds=window_seconds)
        if rate_threshold <= 0:
            raise ValueError("rate_threshold must be positive")

        self._rate_threshold = float(rate_threshold)
        self._syn_packets = WindowedCounter(window_seconds, max_keys)
        self._sources: WindowedDistinct[str] = WindowedDistinct(
            window_seconds, max_keys, MAX_SOURCES_PER_DESTINATION
        )
        # Guards the read-then-clear decision for one destination (M10.18).
        self._lock = threading.Lock()

    def evaluate(self, context: DetectionContext) -> DetectionFinding | None:
        """Return a finding when a destination's SYN rate crosses the threshold."""
        packet = context.packet
        if packet is None or packet.destination_ip is None:
            return None
        if not is_handshake_open(packet):
            return None

        destination_ip = packet.destination_ip
        at = context.timestamp
        window_seconds = self._window_seconds or DEFAULT_WINDOW_SECONDS

        with self._lock:
            syn_packets = self._syn_packets.record(destination_ip, at)
            if packet.source_ip is not None:
                self._sources.record(destination_ip, packet.source_ip, at)

            if syn_packets < MINIMUM_SYN_PACKETS:
                return None
            rate = syn_packets / window_seconds
            if rate < self._rate_threshold:
                return None

            sources = self._sources.values(destination_ip, at)
            window_start = self._syn_packets.window_start(destination_ip, at)
            # Minimal rule-level suppression (M10.18).
            self._syn_packets.clear(destination_ip)
            self._sources.clear(destination_ip)

        observed_source = next(iter(sources)) if len(sources) == 1 else None
        evidence: dict[str, int | float | str | bool] = {
            "syn_packets": syn_packets,
            "syn_packets_per_second": round(rate, 3),
            "syn_rate_threshold": self._rate_threshold,
            "observation_window_seconds": window_seconds,
            "distinct_sources": len(sources),
        }
        if window_start is not None:
            evidence["window_start"] = window_start

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            timestamp=at,
            # Only claimed when the flood actually came from one observed source.
            source_ip=observed_source,
            destination_ip=destination_ip,
            protocol="TCP",
            description=f"Possible SYN flood detected against {destination_ip}",
            evidence=evidence,
            confidence=threshold_confidence(rate, self._rate_threshold),
            metadata={
                "syn_packets": syn_packets,
                "distinct_sources": len(sources),
            },
        )

    def state_size(self) -> int:
        """Return how many destinations the rule currently tracks (M10.19)."""
        return len(self._syn_packets)

    def reset(self) -> None:
        """Discard every accumulated observation."""
        self._syn_packets.reset()
        self._sources.reset()
