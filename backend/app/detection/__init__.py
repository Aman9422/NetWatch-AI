"""Rule-based detection layer for NetWatch AI (M10).

This package turns the normalized traffic already produced by M5 and aggregated
by M6/M8/M9 into **detection findings**. Its shape is deliberate:

    DetectionContext  ->  DetectionRule.evaluate()  ->  DetectionFinding | None
            ^                                                 |
            |                                                 v
      DetectionEngine  ---------------------------->  bounded finding history

A finding is an *observation*, not an alert. There is no severity, no risk
score, no deduplication key and no lifecycle anywhere in this package: those
belong to the M11 alert engine and the M12 correlation and scoring layers. What
lives here is measurement — the distinct destination ports a source touched, the
SYN rate aimed at a destination, the ICMP rate, the distinct internal hosts a
source contacted, and the observed traffic volume.

Detectors never touch a database, a socket, the API or global application state.
They receive a narrow :class:`~app.detection.context.DetectionContext`, return a
:class:`~app.detection.finding.DetectionFinding` or ``None``, keep their own
bounded and lock-protected state, and take their thresholds as arguments rather
than reading the environment themselves.

Design: ``docs/14_M10_Detection_Engine_Design.md``.
"""

from app.detection.base import DetectionRule
from app.detection.context import DetectionContext, DetectionWindow
from app.detection.engine import DetectionEngine, RuleCounters
from app.detection.finding import (
    DetectionFinding,
    new_finding_id,
    threshold_confidence,
)
from app.detection.history import FindingHistory
from app.detection.networks import InternalNetworkClassifier, is_private_address
from app.detection.rates import RatesFeed, TrafficRatesSource
from app.detection.rules import build_default_rules
from app.detection.rules.high_bandwidth import HighBandwidthRule
from app.detection.rules.icmp_flood import IcmpFloodRule
from app.detection.rules.internal_scan import InternalScanRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.syn_flood import SynFloodRule
from app.detection.state import WindowedCounter, WindowedDistinct

__all__ = [
    "DetectionContext",
    "DetectionEngine",
    "DetectionFinding",
    "DetectionRule",
    "DetectionWindow",
    "FindingHistory",
    "HighBandwidthRule",
    "IcmpFloodRule",
    "InternalNetworkClassifier",
    "InternalScanRule",
    "PortScanRule",
    "RatesFeed",
    "RuleCounters",
    "SynFloodRule",
    "TrafficRatesSource",
    "WindowedCounter",
    "WindowedDistinct",
    "build_default_rules",
    "get_detection_engine",
    "is_private_address",
    "new_finding_id",
    "reset_detection_engine",
    "threshold_confidence",
]

# Shared singleton used by the application at runtime.
_detection_engine: DetectionEngine | None = None


def _build_default_engine() -> DetectionEngine:
    """Construct the process-wide engine from application settings (M10.7).

    Imports are local so importing this package never triggers interface
    enumeration, device discovery or statistics construction as a side effect.
    """
    from app.config.settings import settings
    from app.devices.manager import get_device_manager
    from app.services.interface_manager import get_interface_manager
    from app.statistics.manager import get_statistics_manager

    interface_manager = get_interface_manager()
    classifier = InternalNetworkClassifier(
        local_addresses_provider=interface_manager.get_local_addresses
    )
    device_registry = get_device_manager().registry

    def resolve_device(ip_address: str) -> str | None:
        """Return the M8 device id owning ``ip_address``, or ``None`` (M10.4)."""
        device = device_registry.get_by_ip(ip_address)
        return device.device_id if device is not None else None

    return DetectionEngine(
        build_default_rules(settings, classifier=classifier),
        rates_source=get_statistics_manager(),
        device_resolver=resolve_device,
        max_findings=settings.detection_max_findings,
    )


def get_detection_engine() -> DetectionEngine:
    """FastAPI dependency returning the shared detection engine instance."""
    global _detection_engine
    if _detection_engine is None:
        _detection_engine = _build_default_engine()
    return _detection_engine


def reset_detection_engine() -> None:
    """Drop the shared engine so the next call rebuilds it (used by tests)."""
    global _detection_engine
    _detection_engine = None
