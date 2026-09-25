"""Internal network scan detector (M10.11).

A host that reaches out to an unusually large number of **internal
destinations** inside a short window is sweeping the local network. This
detector keys on the source and counts the distinct *internal* addresses it
contacted within a configurable window, against a configurable threshold.

What counts as internal is decided in :mod:`app.detection.networks`, not here:
addresses that are not globally routable, plus the host's own addresses. An
external destination is never counted, so a client talking to many public
services cannot be mistaken for a network sweep — the detector is silent on
external traffic by construction.

The source is *not* required to be internal. A host sweeping the local network
from outside it is exactly the behaviour worth observing, so any source that
reaches many internal destinations is a candidate.

Only genuine connection attempts count (see
:mod:`app.detection.rules.signals`), which stops a server answering many
internal clients from looking like a scanner.

The finding names only the source: a sweep spans many destinations, so
``destination_ip`` is left empty rather than naming whichever destination
happened to complete the window (M10.14). On firing, the source's state is
discarded so one sweep cannot emit a stream of identical findings (M10.18).
"""

from __future__ import annotations

import threading

from app.detection.base import DetectionRule
from app.detection.context import DetectionContext
from app.detection.finding import DetectionFinding, threshold_confidence
from app.detection.networks import InternalNetworkClassifier
from app.detection.rules.signals import is_connection_attempt
from app.detection.state import WindowedCounter, WindowedDistinct

# Defaults kept in step with the settings defaults (M10.7).
DEFAULT_WINDOW_SECONDS = 10.0
DEFAULT_UNIQUE_DESTINATION_THRESHOLD = 15
DEFAULT_MAX_KEYS = 4096
DEFAULT_MAX_DESTINATIONS_PER_SOURCE = 4096


class InternalScanRule(DetectionRule):
    """Report a source contacting many distinct internal destinations (M10.11)."""

    rule_id = "internal_scan"
    rule_name = "Internal Network Scan"
    description = "One source contacting many distinct internal destinations in a window"

    def __init__(
        self,
        *,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        unique_destination_threshold: int = DEFAULT_UNIQUE_DESTINATION_THRESHOLD,
        classifier: InternalNetworkClassifier | None = None,
        max_keys: int = DEFAULT_MAX_KEYS,
        max_values_per_key: int = DEFAULT_MAX_DESTINATIONS_PER_SOURCE,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled, window_seconds=window_seconds)
        if unique_destination_threshold < 1:
            raise ValueError("unique_destination_threshold must be at least 1")

        self._unique_destination_threshold = int(unique_destination_threshold)
        self._classifier = classifier or InternalNetworkClassifier()
        self._destinations: WindowedDistinct[str] = WindowedDistinct(
            window_seconds, max_keys, max_values_per_key
        )
        self._attempts = WindowedCounter(window_seconds, max_keys)
        # Guards the read-then-clear decision for one source (M10.18).
        self._lock = threading.Lock()

    def evaluate(self, context: DetectionContext) -> DetectionFinding | None:
        """Return a finding when one source contacts too many internal hosts."""
        packet = context.packet
        if packet is None or packet.source_ip is None:
            return None
        if not is_connection_attempt(packet):
            return None
        destination_ip = packet.destination_ip
        if destination_ip is None:
            return None
        # A source talking to itself is not a sweep.
        if destination_ip == packet.source_ip:
            return None
        if not self._classifier.is_internal(destination_ip):
            return None

        source_ip = packet.source_ip
        at = context.timestamp

        with self._lock:
            unique_destinations = self._destinations.record(
                source_ip, destination_ip, at
            )
            attempts = self._attempts.record(source_ip, at)
            if unique_destinations < self._unique_destination_threshold:
                return None

            window_start = self._destinations.window_start(source_ip, at)
            # Minimal rule-level suppression (M10.18).
            self._destinations.clear(source_ip)
            self._attempts.clear(source_ip)

        window_seconds = self._window_seconds or 0.0
        evidence: dict[str, int | float | str | bool] = {
            "unique_internal_destinations": unique_destinations,
            "unique_destination_threshold": self._unique_destination_threshold,
            "connection_attempts": attempts,
            "observation_window_seconds": window_seconds,
        }
        if window_start is not None:
            evidence["window_start"] = window_start

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            timestamp=at,
            source_ip=source_ip,
            # A sweep spans destinations, so no single destination is claimed.
            destination_ip=None,
            protocol=packet.protocol,
            description=(
                f"Possible internal network scan detected from {source_ip}"
            ),
            evidence=evidence,
            confidence=threshold_confidence(
                float(unique_destinations),
                float(self._unique_destination_threshold),
            ),
            metadata={
                "unique_internal_destinations": unique_destinations,
                "connection_attempts": attempts,
            },
        )

    def state_size(self) -> int:
        """Return how many sources the rule currently tracks (M10.19)."""
        return len(self._destinations)

    def reset(self) -> None:
        """Discard every accumulated observation."""
        self._destinations.reset()
        self._attempts.reset()
