"""Presentation of the live, in-process halves of the analytics responses (M16.1).

Each analytics response mixes two kinds of material: figures read from a runtime
service (the M6 statistics manager, the M8 registry, the M9 tracker, the M10
engine, the M12 registry) and figures read from SQLite. This module owns the
first kind only — the live halves — so :mod:`app.analytics.service` can stay an
orchestrator and the persisted halves stay in their own builders.

Nothing here re-derives a figure a service already states. A ranking is the
service's own views sorted; a status count is the same; the incident breakdown is
one pass over the registry's snapshot so the status total and the band total
cannot describe two different instants. Ordering is always descending on the
metric with the entry's own identity as tie-break, so equal traffic orders the
same way on every request (M13.24).

Risk appears in exactly two places — the incident bands and the highest score —
and both read M12's value. No live block computes a score, bands a score with its
own thresholds, or invents a severity (M16.6).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.alerts.queries import AlertSummary
from app.alerts.status import ACTIVE_STATUSES as ACTIVE_ALERT_STATUSES
from app.analytics.alert_view import RISK_BAND_KEYS, SEVERITY_KEYS
from app.analytics.metrics import RankMetric
from app.correlation.incident import CorrelatedIncident
from app.correlation.status import ACTIVE_STATUSES as ACTIVE_INCIDENT_STATUSES
from app.correlation.status import STATUS_VALUES as INCIDENT_STATUS_VALUES
from app.detection.engine import DetectionEngine
from app.risk.bands import band_for
from app.schemas.analytics import RankedConnection, RankedDevice, ThreatRuleStat
from app.schemas.device import DeviceStatus, DeviceView


@dataclass(frozen=True)
class IncidentBreakdown:
    """Counts taken from one snapshot of the M12 incident registry (M16.6).

    Attributes:
        total: How many incidents are currently held.
        active: How many are in a state that still needs attention.
        by_status: Incidents per lifecycle state, every state named.
        by_risk_band: Incidents per M12 risk band, every band named.
        highest_risk_score: The worst score currently held, or ``0`` when the
            registry is empty. ``0`` is the model's own minimum (M12.14), so an
            empty registry reporting it is not an invented measurement.
    """

    total: int = 0
    active: int = 0
    by_status: dict[str, int] = field(default_factory=dict)
    by_risk_band: dict[str, int] = field(default_factory=dict)
    highest_risk_score: int = 0


def topped(
    entries: list[Any],
    *,
    limit: int,
    metric: Callable[[Any], float],
    key: Callable[[Any], str],
) -> list[Any]:
    """Return the ``limit`` highest entries by ``metric``, deterministically.

    The tie-break is the entry's own identity, so two entries with equal traffic
    always come back in the same order and a page boundary cannot shuffle them
    (M13.24).
    """
    ordered = sorted(entries, key=lambda item: (-metric(item), key(item)))
    return ordered[:limit]


def device_status_counts(views: list[DeviceView]) -> dict[str, int]:
    """Return how many devices stand in each M8 activity state.

    Every state is named, so an empty registry still renders fixed rows rather
    than leaving a client to guess the vocabulary.
    """
    counts = {status.value: 0 for status in DeviceStatus}
    for view in views:
        counts[view.status.value] = counts.get(view.status.value, 0) + 1
    return counts


def ranked_devices(
    views: list[DeviceView], *, limit: int, by: RankMetric
) -> list[DeviceView]:
    """Return the busiest M8 device views, most traffic first."""
    return topped(
        views,
        limit=limit,
        metric=_device_metric(by),
        key=lambda view: view.device_id,
    )


def _device_metric(by: RankMetric) -> Callable[[DeviceView], float]:
    """Return the metric a device ranking orders by, as M8 reports it."""
    if by == "bytes":
        return lambda view: float(view.byte_count)
    return lambda view: float(view.packet_count)


def ranked_connections(
    views: list[Any], *, limit: int, by: RankMetric
) -> list[Any]:
    """Return the busiest M9 connection views, most traffic first."""
    return topped(
        views,
        limit=limit,
        metric=_connection_metric(by),
        key=lambda view: view.connection_id,
    )


def _connection_metric(by: RankMetric) -> Callable[[Any], float]:
    """Return the metric a connection ranking orders by, as M9 reports it.

    Both directions count: an endpoint's traffic is not a one-way property, so
    ``byte_count`` and ``packet_count`` are the tracker's sent-plus-received
    totals rather than one side of the conversation (M16.5).
    """
    if by == "bytes":
        return lambda view: float(view.byte_count)
    return lambda view: float(view.packet_count)


def connection_entry(view: Any) -> RankedConnection:
    """Project one M9 connection view onto the analytics ranking entry.

    The identity fields are copied as M9 reported them, including the ports it
    left unobserved, so a client can render a ranking row without resolving the
    conversation again.
    """
    return RankedConnection(
        connection_id=view.connection_id,
        protocol=view.protocol,
        source_ip=view.source_ip,
        source_port=view.source_port,
        destination_ip=view.destination_ip,
        destination_port=view.destination_port,
        state=view.state.value,
        packets=view.packet_count,
        bytes=view.byte_count,
    )


def severity_counts(summary: AlertSummary) -> dict[str, int]:
    """Return M11's severity counts, every severity named (M16.6).

    The live block reports the four severities even at zero, so a client renders
    a fixed histogram rather than discovering a missing key.
    """
    by_severity = summary["by_severity"]
    return {severity: int(by_severity.get(severity, 0)) for severity in SEVERITY_KEYS}


def open_alert_count(summary: AlertSummary) -> int:
    """Return how many stored alerts still need attention (M11.6)."""
    by_status = summary["by_status"]
    return sum(
        int(count)
        for status, count in by_status.items()
        if status in ACTIVE_ALERT_STATUSES
    )


def rule_stats(engine: DetectionEngine) -> list[ThreatRuleStat]:
    """Join each registered detector with its own execution counters (M13.18).

    The counters and the rule table are read separately, so a rule registered
    between the two calls is reported with zeroes rather than dropped. Reporting a
    detector with no counts is correct; omitting it would make the list disagree
    with ``GET /api/v1/detections/rules``.
    """
    counters = engine.get_rule_counters()
    stats: list[ThreatRuleStat] = []
    for rule in engine.get_rules():
        counted = counters.get(rule.rule_id)
        stats.append(
            ThreatRuleStat(
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                enabled=rule.enabled,
                evaluations=counted.evaluations if counted else 0,
                findings=counted.findings if counted else 0,
                errors=counted.errors if counted else 0,
            )
        )
    return stats


def incident_breakdown(
    incidents: list[CorrelatedIncident],
) -> IncidentBreakdown:
    """Return the incident counts, taken from one snapshot of the registry.

    Both breakdowns and the highest score come from the same list, so the status
    total and the band total cannot describe different instants. Bands are read
    from :func:`app.risk.bands.band_for` — the same function the incident detail
    view uses (M12.27) — rather than a second set of thresholds written here, and
    the score itself is M12's, never recomputed (M16.6).
    """
    by_status = {status: 0 for status in INCIDENT_STATUS_VALUES}
    by_band = {band: 0 for band in RISK_BAND_KEYS}
    highest = 0
    for incident in incidents:
        lifecycle = incident.normalized_status.value
        by_status[lifecycle] = by_status.get(lifecycle, 0) + 1
        band = band_for(incident.risk_score).value
        by_band[band] = by_band.get(band, 0) + 1
        highest = max(highest, int(incident.risk_score))
    return IncidentBreakdown(
        total=len(incidents),
        active=sum(
            count
            for status, count in by_status.items()
            if status in ACTIVE_INCIDENT_STATUSES
        ),
        by_status=by_status,
        by_risk_band=by_band,
        highest_risk_score=highest,
    )
__all__ = [
    "IncidentBreakdown",
    "connection_entry",
    "device_status_counts",
    "incident_breakdown",
    "open_alert_count",
    "ranked_connections",
    "ranked_devices",
    "rule_stats",
    "severity_counts",
    "topped",
]
