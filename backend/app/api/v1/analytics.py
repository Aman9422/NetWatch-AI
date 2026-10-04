"""Analytics API endpoints for NetWatch AI (M13.18).

Analytics is a *derived view* over the services M6, M7, M8, M9, M10, M11 and M12
already provide. It is not a second statistics engine and it is not a place where
numbers are extrapolated: every figure below is read from the object that owns it,
and the only arithmetic is presentation — an average, a share, a sort.

Why this is not ``/statistics`` again. ``/statistics`` reports the *current
runtime snapshot* of the M6 manager and nothing else. These endpoints answer
different questions over the same underlying services:

* ``traffic`` adds the **persisted** packet count from the packet table, so the
  live view and what has been stored are both visible (M13.18);
* ``devices`` and ``connections`` rank the M8 and M9 registries by traffic, which
  no statistics endpoint does;
* ``threats`` reads across M10, M11 and M12 — finding counters, alert severity and
  incident risk bands — which the statistics layer has no knowledge of.

Nothing here is simulated. Where a service holds nothing, the answer is zero and
an empty list, not an invented series. ``traffic`` deliberately exposes no
historical series, because no milestone writes ``traffic_statistics`` and
inventing one from the packet table would be a different (and far more expensive)
query than this milestone asks for (M13.18).

Rankings are bounded by ``limit`` and ordered by a documented metric with a
deterministic tie-break, so the same request returns the same rows in the same
order (M13.24).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.alerts.queries import AlertQueries
from app.alerts.status import ACTIVE_STATUSES
from app.api.common import success_payload
from app.api.v1.deps import get_alert_queries
from app.connections.manager import ConnectionTracker, get_connection_tracker
from app.correlation import get_correlation_engine
from app.correlation.engine import CorrelationEngine
from app.correlation.status import (
    ACTIVE_STATUSES as ACTIVE_INCIDENT_STATUSES,
    STATUS_VALUES,
)
from app.database.session import get_db
from app.detection import DetectionEngine, get_detection_engine
from app.devices.manager import DeviceDiscoveryManager, get_device_manager
from app.risk.bands import BAND_RANGES, band_for
from app.schemas.analytics import (
    AnalyticsConnections,
    AnalyticsDevices,
    AnalyticsProtocols,
    AnalyticsThreats,
    AnalyticsTraffic,
    RankedConnection,
    RankedDevice,
    ThreatRuleStat,
)
from app.schemas.device import DeviceStatus
from app.schemas.statistics import ProtocolStat
from app.services.packet_query import PacketQueryService
from app.statistics.manager import TrafficStatisticsManager, get_statistics_manager

logger = logging.getLogger(__name__)

router = APIRouter()

#: Ranking metric accepted by every ranked endpoint.
RankMetric = Literal["packets", "bytes"]

#: Rate window accepted by ``analytics/traffic``, mirroring M6's own labels.
RateWindowLabel = Literal["1s", "10s", "60s"]

#: How many ranked entries a request gets when it does not ask for a number.
DEFAULT_TOP_LIMIT = 10
#: Largest ranking one request may ask for, so a ranking stays a ranking.
MAX_TOP_LIMIT = 100

#: Severities the threat block always names, so a client renders fixed rows.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")


def _topped(
    entries: list,
    *,
    limit: int,
    metric: Callable[[Any], float],
    key: Callable[[Any], str],
) -> list:
    """Return the ``limit`` highest entries by ``metric``, deterministically.

    The tie-break is the entry's own identity, so two entries with equal traffic
    always come back in the same order and a page boundary cannot shuffle them
    (M13.24).
    """
    ordered = sorted(entries, key=lambda item: (-metric(item), key(item)))
    return ordered[:limit]


@router.get("/traffic", response_model=None)
def get_traffic_analytics(
    window: RateWindowLabel = Query(
        default="1s", description="Rate window used for the per-second figures"
    ),
    limit: int = Query(
        default=DEFAULT_TOP_LIMIT,
        ge=1,
        le=MAX_TOP_LIMIT,
        description="How many entries each ranking carries",
    ),
    by: RankMetric = Query(
        default="packets", description="Metric the rankings are ordered by"
    ),
    statistics: TrafficStatisticsManager = Depends(get_statistics_manager),
    db: Session = Depends(get_db),
) -> dict:
    """Return traffic analytics: totals, derived ratios and leading talkers (M13.18).

    The snapshot is read once, so the totals, the rates and the protocol list all
    describe the same instant. The rate window only changes which per-second figure
    is reported; when the window is the default the snapshot's own rate is used,
    which is exactly what ``/statistics/traffic`` reports.
    """
    snapshot = statistics.get_statistics()
    packets_per_second = snapshot.packets_per_second
    bytes_per_second = snapshot.bytes_per_second
    bits_per_second = snapshot.bits_per_second
    if window != "1s":
        packets_per_second, bytes_per_second = statistics.get_rates(window)
        bits_per_second = bytes_per_second * 8.0

    talkers = statistics.get_top_talkers(limit=limit, by=by)
    payload = AnalyticsTraffic(
        total_packets=snapshot.total_packets,
        total_bytes=snapshot.total_bytes,
        packets_per_second=packets_per_second,
        bytes_per_second=bytes_per_second,
        bits_per_second=bits_per_second,
        average_packet_bytes=(
            snapshot.total_bytes / snapshot.total_packets
            if snapshot.total_packets
            else 0.0
        ),
        stored_packet_count=PacketQueryService(db).count(),
        protocol_count=len(snapshot.protocol_statistics),
        directions=list(snapshot.direction_statistics),
        protocols=list(snapshot.protocol_statistics),
        top_sources=list(talkers["sources"]),
        top_destinations=list(talkers["destinations"]),
        top_ports=statistics.get_top_ports(limit=limit, by=by, direction="destination"),
    )
    logger.info(
        "Traffic analytics served (%d packet(s) live, %d stored)",
        payload.total_packets,
        payload.stored_packet_count,
    )
    return success_payload("Traffic analytics retrieved", payload.model_dump(mode="json"))


@router.get("/protocols", response_model=None)
def get_protocol_analytics(
    by: RankMetric = Query(
        default="packets", description="Metric the protocol list is ordered by"
    ),
    statistics: TrafficStatisticsManager = Depends(get_statistics_manager),
) -> dict:
    """Return the protocol breakdown, ordered by the requested metric (M13.18).

    The entries and their shares come from M6 as they are; ordering is the only
    thing this endpoint decides. Ordering here rather than trusting the service's
    own order keeps the response stable whatever the manager returns, and the name
    tie-break makes it total (M13.24).
    """
    protocols: list[ProtocolStat] = statistics.get_protocol_statistics()
    ordered = _topped(
        protocols,
        limit=len(protocols),
        metric=(lambda entry: entry.bytes) if by == "bytes" else (lambda entry: entry.packets),
        key=lambda entry: entry.protocol,
    )
    payload = AnalyticsProtocols(
        count=len(ordered),
        total_packets=sum(entry.packets for entry in ordered),
        total_bytes=sum(entry.bytes for entry in ordered),
        rank_by=by,
        protocols=ordered,
    )
    logger.info("Protocol analytics served (%d protocol(s))", payload.count)
    return success_payload(
        "Protocol analytics retrieved", payload.model_dump(mode="json")
    )


@router.get("/devices", response_model=None)
def get_device_analytics(
    by: RankMetric = Query(
        default="packets", description="Metric the ranking is ordered by"
    ),
    limit: int = Query(
        default=DEFAULT_TOP_LIMIT,
        ge=1,
        le=MAX_TOP_LIMIT,
        description="How many devices the ranking carries",
    ),
    manager: DeviceDiscoveryManager = Depends(get_device_manager),
) -> dict:
    """Return device analytics: totals by state and a traffic ranking (M13.18).

    Both halves come from the M8 manager's own views, so the activity state is the
    one M8 computed rather than one guessed here. The ranking is over traffic
    totals, never a risk figure — M8 does not score risk, so there is none to rank
    by (M13.10).
    """
    views = manager.list_device_views()
    counts = {status.value: 0 for status in DeviceStatus}
    for view in views:
        counts[view.status.value] = counts.get(view.status.value, 0) + 1

    ranked = _topped(
        views,
        limit=limit,
        metric=(
            (lambda view: view.byte_count)
            if by == "bytes"
            else (lambda view: view.packet_count)
        ),
        key=lambda view: view.device_id,
    )
    payload = AnalyticsDevices(
        total=len(views),
        by_status=counts,
        rank_by=by,
        top=[
            RankedDevice(
                device_id=view.device_id,
                mac_address=view.mac_address,
                ip_addresses=list(view.ip_addresses),
                hostname=view.hostname,
                status=view.status.value,
                packets=view.packet_count,
                bytes=view.byte_count,
            )
            for view in ranked
        ],
    )
    logger.info(
        "Device analytics served (%d device(s), %d ranked)", payload.total, len(payload.top)
    )
    return success_payload("Device analytics retrieved", payload.model_dump(mode="json"))


@router.get("/connections", response_model=None)
def get_connection_analytics(
    by: RankMetric = Query(
        default="bytes", description="Metric the ranking is ordered by"
    ),
    limit: int = Query(
        default=DEFAULT_TOP_LIMIT,
        ge=1,
        le=MAX_TOP_LIMIT,
        description="How many conversations the ranking carries",
    ),
    tracker: ConnectionTracker = Depends(get_connection_tracker),
) -> dict:
    """Return connection analytics: tracker counters and a traffic ranking (M13.18).

    The counters are the tracker's own, so they agree with ``/connections``. The
    ranking deliberately includes retired conversations (``active_only=False``):
    the busiest conversation of a session is frequently one that has already
    closed, and omitting it would make the ranking answer a narrower question than
    "which conversations carried the most traffic".
    """
    views = tracker.list_connection_views(active_only=False)
    ranked = _topped(
        views,
        limit=limit,
        metric=(
            (lambda view: view.byte_count)
            if by == "bytes"
            else (lambda view: view.packet_count)
        ),
        key=lambda view: view.connection_id,
    )
    payload = AnalyticsConnections(
        active=tracker.get_active_count(),
        historical=tracker.get_historical_count(),
        tracked=tracker.get_tracked_count(),
        rank_by=by,
        top=[
            RankedConnection(
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
            for view in ranked
        ],
    )
    logger.info(
        "Connection analytics served (%d tracked, %d ranked)",
        payload.tracked,
        len(payload.top),
    )
    return success_payload(
        "Connection analytics retrieved", payload.model_dump(mode="json")
    )


def _rule_stats(engine: DetectionEngine) -> list[ThreatRuleStat]:
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


@router.get("/threats", response_model=None)
def get_threat_analytics(
    queries: AlertQueries = Depends(get_alert_queries),
    detections: DetectionEngine = Depends(get_detection_engine),
    correlations: CorrelationEngine = Depends(get_correlation_engine),
) -> dict:
    """Return threat analytics across M10, M11 and M12 (M13.18).

    Three layers are reported side by side and kept distinct, because collapsing
    them would invent a single "threat" number that no milestone produces:

    * M10's finding counters — what the detectors *observed*, with no judgement;
    * M11's alert counts by severity and status — the evidence-based judgement;
    * M12's incident counts by lifecycle state and by risk band — the bounded
      prioritisation metric.

    The incident pass reads the registry once and takes both breakdowns from that
    one snapshot, so the status total and the band total cannot describe different
    instants. Bands come from :func:`app.risk.bands.band_for`, the same function
    the incident detail view uses (M12.27), rather than a second set of thresholds
    written here.
    """
    alert_summary = queries.summary()
    by_status = alert_summary["by_status"]
    diagnostics = detections.get_diagnostics()

    incidents = correlations.registry.incidents()
    status_counts = {status: 0 for status in STATUS_VALUES}
    band_counts = {band.value: 0 for band, _low, _high in BAND_RANGES}
    highest_risk_score = 0
    for incident in incidents:
        lifecycle = incident.normalized_status.value
        status_counts[lifecycle] = status_counts.get(lifecycle, 0) + 1
        band = band_for(incident.risk_score).value
        band_counts[band] = band_counts.get(band, 0) + 1
        highest_risk_score = max(highest_risk_score, int(incident.risk_score))

    payload = AnalyticsThreats(
        alerts_total=alert_summary["total"],
        alerts_open=sum(
            count for status, count in by_status.items() if status in ACTIVE_STATUSES
        ),
        alerts_by_severity={
            severity: alert_summary["by_severity"].get(severity, 0)
            for severity in SEVERITIES
        },
        alerts_by_status=dict(by_status),
        findings_retained=diagnostics.retained_findings,
        detections_evaluated=diagnostics.evaluations,
        detections_findings=diagnostics.findings,
        detections_errors=diagnostics.errors,
        rules=_rule_stats(detections),
        incidents_total=len(incidents),
        incidents_active=sum(
            count
            for status, count in status_counts.items()
            if status in ACTIVE_INCIDENT_STATUSES
        ),
        incidents_by_status=status_counts,
        incidents_by_risk_band=band_counts,
        highest_risk_score=highest_risk_score,
    )
    logger.info(
        "Threat analytics served (%d alert(s), %d incident(s))",
        payload.alerts_total,
        payload.incidents_total,
    )
    return success_payload("Threat analytics retrieved", payload.model_dump(mode="json"))


__all__ = [
    "DEFAULT_TOP_LIMIT",
    "MAX_TOP_LIMIT",
    "SEVERITIES",
    "router",
]
