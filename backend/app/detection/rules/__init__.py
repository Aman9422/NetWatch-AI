"""Detection rules and the default rule set (M10.2, M10.7).

This package holds the five M10 detectors and the single place that turns
configured thresholds into rule instances. The engine itself stays free of
configuration — it is handed rules, whatever their origin — so a test can
register one rule while a deployment registers the whole default set.

:func:`build_default_rules` reads an explicit ``Settings`` object and constructs
the detectors with its windows and thresholds. It deliberately does not call
``get_settings()`` behind the caller's back, so a test that passes its own
settings gets exactly that configuration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.detection.base import DetectionRule
from app.detection.networks import InternalNetworkClassifier
from app.detection.rules.high_bandwidth import HighBandwidthRule
from app.detection.rules.icmp_flood import IcmpFloodRule
from app.detection.rules.internal_scan import InternalScanRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.syn_flood import SynFloodRule

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance for typing only
    from app.config.settings import Settings

__all__ = [
    "HighBandwidthRule",
    "IcmpFloodRule",
    "InternalScanRule",
    "PortScanRule",
    "SynFloodRule",
    "build_default_rules",
]


def build_default_rules(
    settings: "Settings",
    *,
    classifier: InternalNetworkClassifier | None = None,
) -> list[DetectionRule]:
    """Return the five M10 detectors configured from ``settings`` (M10.7).

    Args:
        settings: The application settings providing every detection threshold.
        classifier: The internal-address classifier the internal scan detector
            should use. When omitted, that detector falls back to classifying
            addresses by their own routing semantics alone.

    Returns:
        One instance of each M10 detector, in the order the milestone lists them.
    """
    max_keys = settings.detection_max_state_keys
    max_values_per_key = settings.detection_max_values_per_key

    return [
        PortScanRule(
            window_seconds=settings.port_scan_time_window_seconds,
            unique_port_threshold=settings.port_scan_unique_port_threshold,
            syn_ratio_threshold=settings.port_scan_syn_ratio_threshold,
            max_keys=max_keys,
            max_values_per_key=max_values_per_key,
        ),
        SynFloodRule(
            window_seconds=settings.syn_flood_time_window_seconds,
            rate_threshold=settings.syn_flood_rate_threshold,
            max_keys=max_keys,
        ),
        IcmpFloodRule(
            window_seconds=settings.icmp_flood_time_window_seconds,
            rate_threshold=settings.icmp_flood_rate_threshold,
            max_keys=max_keys,
        ),
        InternalScanRule(
            window_seconds=settings.internal_scan_time_window_seconds,
            unique_destination_threshold=(
                settings.internal_scan_unique_destination_threshold
            ),
            classifier=classifier,
            max_keys=max_keys,
            max_values_per_key=max_values_per_key,
        ),
        HighBandwidthRule(
            window_seconds=settings.high_bandwidth_time_window_seconds,
            bytes_per_second_threshold=(
                settings.high_bandwidth_bytes_per_second_threshold
            ),
        ),
    ]
