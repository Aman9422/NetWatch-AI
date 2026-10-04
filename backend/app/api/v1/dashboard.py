"""Consolidated dashboard endpoint for NetWatch AI (M13.19).

One request that answers "what is happening right now?" by reading the services
that already hold each answer. It is an *aggregator*, not a new layer: every
number here comes from the service that owns it, and nothing is derived from
anything a dedicated endpoint would not report.

That constraint is what the module is built around. A dashboard that recomputed
"open alerts" from the alert table, or re-aggregated traffic from statistics the
M6 manager already maintains, would be a second implementation of a rule that
already has one — and the two would eventually disagree (M13.19: "It must not
duplicate business logic"). So:

* capture state comes from :class:`~app.services.capture_manager.CaptureManager`;
* traffic comes from the M6 ``TrafficSnapshot``;
* device counts come from the M8 registry's own views;
* connection counts come from the M9 tracker's own counters;
* alert counts come from the M11 query service's aggregation;
* incident counts come from the M12 engine, and "open" uses
  :data:`app.correlation.status.ACTIVE_STATUSES` rather than a local list;
* recent findings come from the M10 engine's retained history.

Every block is emitted even when its service holds nothing, with zeroed values,
so a client renders a fixed layout instead of distinguishing "nothing observed"
from "field absent".

The endpoint is read-only and changes nothing. It is also the most expensive
route in the surface by construction, since it touches seven services; M13.37
measures it for exactly that reason.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query

from app.alerts.queries import AlertQueries
from app.alerts.status import ACTIVE_STATUSES
from app.api.common import success_payload
from app.api.v1.deps import get_alert_queries
from app.connections.manager import ConnectionTracker, get_connection_tracker
from app.correlation import get_correlation_engine
from app.correlation.engine import CorrelationEngine
from app.correlation.registry import IncidentOrder, IncidentQuery
from app.correlation.status import STATUS_VALUES
from app.detection import DetectionEngine, get_detection_engine
from app.devices.manager import DeviceDiscoveryManager, get_device_manager
from app.schemas.alert import to_iso_timestamp
from app.schemas.dashboard import (
    DashboardAlerts,
    DashboardCapture,
    DashboardConnections,
    DashboardDetections,
    DashboardDevices,
    DashboardIncidents,
    DashboardSection,
    DashboardSummaryData,
    DashboardTraffic,
    DataT,
)
from app.schemas.device import DeviceStatus
from app.services.capture_manager import CaptureManager, get_capture_manager
from app.statistics.manager import TrafficStatisticsManager, get_statistics_manager

logger = logging.getLogger(__name__)

router = APIRouter()

#: How many recent findings the summary carries unless the caller asks for more.
DEFAULT_RECENT_FINDINGS = 5
#: Largest number of recent findings one dashboard request may carry, so the
#: summary stays a summary (M13.24).
MAX_RECENT_FINDINGS = 50

#: Severities the alert block always names, so a client renders fixed rows.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")


def _capture_block(manager: CaptureManager) -> DashboardCapture:
    """Build the capture block from the live manager (M13.19)."""
    status = manager.get_status()
    return DashboardCapture(
        running=manager.is_running(),
        status=status.status,
        interface=status.interface,
        packet_count=status.packet_count,
    )


def _traffic_block(manager: TrafficStatisticsManager) -> DashboardTraffic:
    """Build the traffic block from the M6 snapshot (M13.19).

    The snapshot is asked for once and read three times, so the totals and the
    rates describe the same instant. Asking separately would let them disagree by
    whatever arrived in between.
    """
    snapshot = manager.get_statistics()
    return DashboardTraffic(
        total_packets=snapshot.total_packets,
        total_bytes=snapshot.total_bytes,
        packets_per_second=snapshot.packets_per_second,
        bytes_per_second=snapshot.bytes_per_second,
        bits_per_second=snapshot.bits_per_second,
        protocol_count=len(snapshot.protocol_statistics),
    )


def _devices_block(manager: DeviceDiscoveryManager) -> DashboardDevices:
    """Count the M8 registry by activity state (M13.19).

    The status is read from the manager's own views rather than recomputed here,
    because "active vs inactive" is an M8 rule with an inactivity threshold
    behind it. Counting the views costs one pass over a bounded registry, which is
    the price of not restating the rule (M13.19).
    """
    views = manager.list_device_views()
    counts = {status.value: 0 for status in DeviceStatus}
    for view in views:
        counts[view.status.value] = counts.get(view.status.value, 0) + 1
    return DashboardDevices(total=len(views), by_status=counts)


def _connections_block(tracker: ConnectionTracker) -> DashboardConnections:
    """Read the M9 tracker's own counters (M13.19)."""
    return DashboardConnections(
        active=tracker.get_active_count(),
        historical=tracker.get_historical_count(),
        tracked=tracker.get_tracked_count(),
    )


def _alerts_block(queries: AlertQueries) -> DashboardAlerts:
    """Build the alert block from the M11 aggregation (M13.19).

    The aggregation is read *inside* this section rather than before it, so a
    database problem becomes "the alerts section is unavailable" instead of
    failing the whole summary.

    ``open`` is the sum of the states M11 marks as still needing attention. A
    stored status that is neither active nor recognised contributes to
    ``by_status`` but never to ``open``, which is the honest reading: the
    application cannot call a status it does not know "open" (M11.18).
    """
    summary = queries.summary()
    by_status = summary["by_status"]
    return DashboardAlerts(
        total=summary["total"],
        open=sum(count for status, count in by_status.items() if status in ACTIVE_STATUSES),
        by_severity={
            severity: summary["by_severity"].get(severity, 0)
            for severity in SEVERITIES
        },
        by_status=dict(by_status),
    )


def _incidents_block(engine: CorrelationEngine) -> DashboardIncidents:
    """Count the M12 registry and read its worst score (M13.19).

    "Active" uses the engine's own ``active_only`` filter rather than a local list
    of states, and the highest score is read from the riskiest incident the store
    returns rather than recomputed, so neither can drift from the dedicated
    incident endpoints (M12.13).
    """
    counts = {
        status: engine.count_incidents(IncidentQuery(statuses=(status,)))
        for status in STATUS_VALUES
    }
    riskiest = engine.get_incidents(
        IncidentQuery(order=IncidentOrder.RISK, limit=1)
    )
    return DashboardIncidents(
        total=engine.count_incidents(),
        active=engine.count_incidents(IncidentQuery(active_only=True)),
        highest_risk_score=riskiest[0].risk_score if riskiest else 0,
        by_status=counts,
    )


def _detections_block(
    engine: DetectionEngine, recent_limit: int
) -> DashboardDetections:
    """Read the M10 retained history (M13.19).

    ``recent`` is projected through the same wire view the detection endpoints
    use, so the summary never invents a shape a client has not already seen.
    Findings that have aged out of the bounded history are simply absent, which is
    the same answer ``GET /api/v1/detections/{id}`` would give (M13.12).
    """
    findings = engine.get_findings(limit=recent_limit)
    return DashboardDetections(
        retained=engine.get_retained_finding_count(),
        recent=[finding.to_view() for finding in findings],
    )


def _section_error(name: str) -> str:
    """Return a safe reason for an unavailable section (M13.5/M13.30).

    The exception's own text is deliberately not used. A driver message can name
    a filesystem path or a host, and M13.30 forbids returning either; naming the
    section is enough for a caller to know what it cannot read.
    """
    return f"The {name} section is unavailable"


def _section(name: str, builder: Callable[[], DataT]) -> DashboardSection[DataT]:
    """Run one section builder, containing its failure (M13.19/M13.29).

    A section is exactly one service read, so a section is where a failure
    belongs. A device-registry problem must not hide the alert counts, and a
    dashboard that answers ``500`` because one of its seven dependencies is
    unhappy is far less useful than one that answers with six sections and says
    which is missing (M13.29).

    Args:
        name: The section name, used in the reason and the log line.
        builder: Zero-argument callable producing the section payload.

    Returns:
        An available section holding the payload, or an unavailable section
        holding a safe reason. Never raises, so the caller cannot lose the rest
        of the summary to one bad section.
    """
    try:
        return DashboardSection[DataT](data=builder())
    except Exception:  # noqa: BLE001 - one section failing is a verdict
        logger.warning("Dashboard section %r is unavailable", name, exc_info=True)
        return DashboardSection[DataT](available=False, error=_section_error(name))


@router.get("/summary", response_model=None)
def get_dashboard_summary(
    recent_limit: int = Query(
        default=DEFAULT_RECENT_FINDINGS,
        ge=0,
        le=MAX_RECENT_FINDINGS,
        description="How many recent detection findings to include",
    ),
    capture_manager: CaptureManager = Depends(get_capture_manager),
    statistics: TrafficStatisticsManager = Depends(get_statistics_manager),
    devices: DeviceDiscoveryManager = Depends(get_device_manager),
    connections: ConnectionTracker = Depends(get_connection_tracker),
    detections: DetectionEngine = Depends(get_detection_engine),
    correlations: CorrelationEngine = Depends(get_correlation_engine),
    queries: AlertQueries = Depends(get_alert_queries),
) -> dict:
    """Return the consolidated dashboard summary (M13.19).

    Each section is read through :func:`_section`, so one unavailable service
    leaves the rest of the summary intact and names itself in
    ``unavailable_sections``. A section that reads successfully and holds nothing
    is reported as available with zeroes; the two cases are different facts and
    are reported as such.

    ``recent_limit`` bounds the findings the summary carries. Everything else is
    a count, which is bounded by definition.
    """
    capture_section = _section("capture", lambda: _capture_block(capture_manager))
    traffic_section = _section("traffic", lambda: _traffic_block(statistics))
    devices_section = _section("devices", lambda: _devices_block(devices))
    connections_section = _section(
        "connections", lambda: _connections_block(connections)
    )
    alerts_section = _section("alerts", lambda: _alerts_block(queries))
    incidents_section = _section("incidents", lambda: _incidents_block(correlations))
    detections_section = _section(
        "detections", lambda: _detections_block(detections, recent_limit)
    )

    sections: tuple[tuple[str, DashboardSection], ...] = (
        ("capture", capture_section),
        ("traffic", traffic_section),
        ("devices", devices_section),
        ("connections", connections_section),
        ("alerts", alerts_section),
        ("incidents", incidents_section),
        ("detections", detections_section),
    )
    unavailable = [name for name, section in sections if not section.available]
    payload = DashboardSummaryData(
        generated_at=to_iso_timestamp(datetime.now(timezone.utc)) or "",
        unavailable_sections=unavailable,
        capture=capture_section,
        traffic=traffic_section,
        devices=devices_section,
        connections=connections_section,
        alerts=alerts_section,
        incidents=incidents_section,
        detections=detections_section,
    )
    if unavailable:
        logger.warning("Dashboard summary served without: %s", ", ".join(unavailable))
    else:
        logger.info("Dashboard summary served with every section available")
    return success_payload(
        "Dashboard summary retrieved", payload.model_dump(mode="json")
    )


__all__ = [
    "DEFAULT_RECENT_FINDINGS",
    "MAX_RECENT_FINDINGS",
    "SEVERITIES",
    "router",
]
