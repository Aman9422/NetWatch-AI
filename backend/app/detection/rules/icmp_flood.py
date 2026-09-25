"""ICMP flood detector (M10.10).

An ICMP flood is a destination receiving an unusually high rate of ICMP
packets. This detector keys on the **destination** — the party being flooded —
and measures ICMP packets per second against a configurable rate threshold over
a configurable window.

It deliberately does not treat ping activity as malicious. Any single `ping` is
one or two ICMP packets, far below any sane rate threshold, and the detector
refuses to fire on fewer than two observed ICMP packets whatever the threshold
says. The finding states what was observed ("an excessive rate of ICMP traffic")
rather than asserting an attack (M10.16).

The finding names the destination. It names the source only when exactly one
source was actually observed, and otherwise reports the distinct source count as
evidence, so a distributed flood is not misrepresented as a single culprit
(M10.14).

Nothing here blocks, drops or rate-limits traffic, and nothing here scores risk.
"""

from __future__ import annotations

import threading

from app.detection.base import DetectionRule
from app.detection.context import DetectionContext
from app.detection.finding import DetectionFinding, threshold_confidence
from app.detection.rules.signals import is_icmp
from app.detection.state import WindowedCounter, WindowedDistinct

# Defaults kept in step with the settings defaults (M10.7).
DEFAULT_WINDOW_SECONDS = 5.0
DEFAULT_RATE_THRESHOLD = 100.0
DEFAULT_MAX_KEYS = 4096

# Fewest ICMP packets that can ever constitute a flood, regardless of config.
MINIMUM_ICMP_PACKETS = 2

# Bound on the distinct sources recorded per destination (M10.19).
MAX_SOURCES_PER_DESTINATION = 1024

# Transport label reported on the finding.
PROTOCOL_LABEL = "ICMP"


class IcmpFloodRule(DetectionRule):
    """Report a destination receiving an excessive rate of ICMP (M10.10)."""

    rule_id = "icmp_flood"
    rule_name = "ICMP Flood"
    description = "One destination receiving an excessive rate of ICMP packets"

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
        self._icmp_packets = WindowedCounter(window_seconds, max_keys)
        self._sources: WindowedDistinct[str] = WindowedDistinct(
            window_seconds, max_keys, MAX_SOURCES_PER_DESTINATION
        )
        # Guards the read-then-clear decision for one destination (M10.18).
        self._lock = threading.Lock()

    def evaluate(self, context: DetectionContext) -> DetectionFinding | None:
        """Return a finding when a destination's ICMP rate crosses the threshold."""
        packet = context.packet
        if packet is None or packet.destination_ip is None:
            return None
        if not is_icmp(packet):
            return None

        destination_ip = packet.destination_ip
        at = context.timestamp
        window_seconds = self._window_seconds or DEFAULT_WINDOW_SECONDS

        with self._lock:
            icmp_packets = self._icmp_packets.record(destination_ip, at)
            if packet.source_ip is not None:
                self._sources.record(destination_ip, packet.source_ip, at)

            if icmp_packets < MINIMUM_ICMP_PACKETS:
                return None
            rate = icmp_packets / window_seconds
            if rate < self._rate_threshold:
                return None

            sources = self._sources.values(destination_ip, at)
            window_start = self._icmp_packets.window_start(destination_ip, at)
            # Minimal rule-level suppression (M10.18).
            self._icmp_packets.clear(destination_ip)
            self._sources.clear(destination_ip)

        observed_source = next(iter(sources)) if len(sources) == 1 else None
        evidence: dict[str, int | float | str | bool] = {
            "icmp_packets": icmp_packets,
            "icmp_packets_per_second": round(rate, 3),
            "icmp_rate_threshold": self._rate_threshold,
            "observation_window_seconds": window_seconds,
            "distinct_sources": len(sources),
        }
        if window_start is not None:
            evidence["window_start"] = window_start

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            timestamp=at,
            source_ip=observed_source,
            destination_ip=destination_ip,
            protocol=PROTOCOL_LABEL,
            description=f"Possible ICMP flood detected against {destination_ip}",
            evidence=evidence,
            confidence=threshold_confidence(rate, self._rate_threshold),
            metadata={
                "icmp_packets": icmp_packets,
                "distinct_sources": len(sources),
            },
        )

    def state_size(self) -> int:
        """Return how many destinations the rule currently tracks (M10.19)."""
        return len(self._icmp_packets)

    def reset(self) -> None:
        """Discard every accumulated observation."""
        self._icmp_packets.reset()
        self._sources.reset()
