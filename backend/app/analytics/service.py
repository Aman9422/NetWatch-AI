"""The analytics service: the five views, assembled from the services that own the data.

This is the layer M16 exists to add. Before it, the analytics routes read the
live services directly and the persisted half of every response was declared but
never filled. Here the two halves are put together once, per view, so a route is
a thin adapter over one call (M16.1).

**What each view is.** ``traffic``, ``protocols``, ``devices``, ``connections``
and ``threats`` each return the M13 response model, extended with the M16 blocks.
Nothing about the M13 fields changes — same names, same types, same sources —
which is what keeps the M15 frontend compatible (M16.11).

**Two kinds of material, two failure models.** A live figure comes from a runtime
service that either answers or takes the request down with it; it is read
directly. A persisted figure comes from SQLite and *can* fail on its own — a
locked file, a full disk — so every database-derived block is read through
:func:`~app.analytics.sections.read_section` and reported as an availability
section. An unavailable section says so; it is never silently zeroed, because
"the store holds nothing" and "the store could not be read" are different answers
and both are representable (M16.8).

**The period is reported, not implied.** Every view carries the resolved window
its persisted block was read over, including whether the caller named it, so a
client never has to guess which window a number describes (M16.7).

**No view computes a score, a severity or a rule.** Traffic totals come from M6
and the packet table; devices from M8; conversations from M9; findings from M10;
severities and alert states from M11; risk bands from M12. The only arithmetic
here is presentation — a rate, a share, an average, a sort (M16.1).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.alerts.queries import AlertQueries
from app.analytics.alert_view import DEFAULT_RULE_LIMIT, build_stored_alerts
from app.analytics.connection_view import build_stored_connections
from app.analytics.device_view import build_device_window, ranked_device
from app.analytics.live_view import (
    connection_entry,
    device_status_counts,
    incident_breakdown,
    open_alert_count,
    ranked_connections,
    ranked_devices,
    rule_stats,
    severity_counts,
    topped,
)
from app.analytics.metrics import RankMetric
from app.analytics.sections import read_section
from app.analytics.threat_view import build_findings_summary, build_incident_linkage
from app.analytics.traffic_view import (
    build_stored_protocols,
    build_stored_traffic,
)
from app.analytics.window import MAX_BUCKETS, AnalyticsWindow
from app.connections.manager import ConnectionTracker
from app.correlation.engine import CorrelationEngine
from app.detection.engine import DetectionEngine
from app.devices.manager import DeviceDiscoveryManager
from app.schemas.analytics import (
    AlertsSection,
    AnalyticsConnections,
    AnalyticsDevices,
    AnalyticsPeriod,
    AnalyticsProtocols,
    AnalyticsThreats,
    AnalyticsTraffic,
    ConnectionsSection,
    DeviceWindowSection,
    ProtocolsSection,
    TrafficSection,
)
from app.schemas.statistics import ProtocolStat
from app.statistics.manager import TrafficStatisticsManager

#: The rate window label that means "use the snapshot's own figure". Any other
#: value asks M6 for that window's rate, mirroring ``/statistics/traffic``.
DEFAULT_RATE_WINDOW = "1s"


def period_from_window(window: AnalyticsWindow) -> AnalyticsPeriod:
    """Project a resolved window onto the period a response reports (M16.7).

    The bounds are rendered as ISO-8601 UTC, matching M13.26, and the bucket
    choice is reported beside its ceiling so the relationship between a window's
    length and its resolution is visible rather than mysterious.
    """
    return AnalyticsPeriod(
        since=window.iso_since(),
        until=window.iso_until(),
        seconds=window.seconds,
        bucket_seconds=window.bucket_seconds,
        buckets=window.buckets,
        max_buckets=MAX_BUCKETS,
        defaulted=window.defaulted,
    )


class AnalyticsService:
    """Assembles the five analytics views from the services that own the data.

    Every collaborator is injected, so a test can substitute any one of them and
    the service never reaches for a global (M13.28). The session is the
    request-scoped one, used only for the database-derived blocks; this service
    holds it for the duration of one call and closes nothing it did not open.
    """

    def __init__(
        self,
        *,
        db: Session,
        statistics: TrafficStatisticsManager,
        devices: DeviceDiscoveryManager,
        tracker: ConnectionTracker,
        alerts: AlertQueries,
        detections: DetectionEngine,
        correlations: CorrelationEngine,
    ) -> None:
        """Bind the service to its collaborators."""
        self._db = db
        self._statistics = statistics
        self._devices = devices
        self._tracker = tracker
        self._alerts = alerts
        self._detections = detections
        self._correlations = correlations

    # -- traffic (M16.2) ---------------------------------------------------

    def traffic(
        self,
        *,
        window: AnalyticsWindow,
        rate_window: str = DEFAULT_RATE_WINDOW,
        limit: int,
        by: RankMetric,
    ) -> AnalyticsTraffic:
        """Return the traffic view: M13's live snapshot plus the stored window.

        The snapshot is read once, so the totals, the rates and the protocol list
        all describe the same instant. ``stored_packet_count`` stays the M13
        figure it has always been — the unwindowed row count — because the M15
        client types it as a plain integer, but it is read *through* the stored
        section rather than beside it: it counts the same packet table, so a table
        that cannot be read must report itself unavailable instead of raising out
        of the guard and failing the whole request (M16.8).
        """
        snapshot = self._statistics.get_statistics()
        packets_per_second = snapshot.packets_per_second
        bytes_per_second = snapshot.bytes_per_second
        bits_per_second = snapshot.bits_per_second
        if rate_window != DEFAULT_RATE_WINDOW:
            packets_per_second, bytes_per_second = self._statistics.get_rates(
                rate_window
            )
            bits_per_second = bytes_per_second * 8.0

        talkers = self._statistics.get_top_talkers(limit=limit, by=by)
        stored = read_section(
            lambda: build_stored_traffic(self._db, window, limit=limit, by=by),
            name="traffic",
            session=self._db,
        )
        return AnalyticsTraffic(
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
            stored_packet_count=(
                stored.data.stored_packet_count if stored.data is not None else 0
            ),
            protocol_count=len(snapshot.protocol_statistics),
            directions=list(snapshot.direction_statistics),
            protocols=list(snapshot.protocol_statistics),
            top_sources=list(talkers["sources"]),
            top_destinations=list(talkers["destinations"]),
            top_ports=self._statistics.get_top_ports(
                limit=limit, by=by, direction="destination"
            ),
            period=period_from_window(window),
            stored=TrafficSection(
                available=stored.available, error=stored.error, data=stored.data
            ),
        )

    # -- protocols (M16.3) -------------------------------------------------

    def protocols(
        self, *, window: AnalyticsWindow, by: RankMetric
    ) -> AnalyticsProtocols:
        """Return the protocol view: M13's live distribution plus the stored one.

        The live entries and their shares come from M6 as they are; ordering is
        the only thing decided here, and the name tie-break makes it total
        (M13.24). The stored breakdown is a separate selection, so its
        percentages are taken against that window's own packet count rather than
        being reconciled with the live list (M16.3).
        """
        live: list[ProtocolStat] = self._statistics.get_protocol_statistics()
        ordered = topped(
            list(live),
            limit=len(live),
            metric=(
                (lambda entry: float(entry.bytes))
                if by == "bytes"
                else (lambda entry: float(entry.packets))
            ),
            key=lambda entry: entry.protocol,
        )
        stored = read_section(
            lambda: build_stored_protocols(self._db, window, by=by),
            name="protocols",
            session=self._db,
        )
        return AnalyticsProtocols(
            count=len(ordered),
            total_packets=sum(entry.packets for entry in ordered),
            total_bytes=sum(entry.bytes for entry in ordered),
            rank_by=by,
            protocols=ordered,
            period=period_from_window(window),
            stored=ProtocolsSection(
                available=stored.available, error=stored.error, data=stored.data
            ),
        )

    # -- devices (M16.4) ---------------------------------------------------

    def devices(
        self, *, window: AnalyticsWindow, limit: int, by: RankMetric
    ) -> AnalyticsDevices:
        """Return the device view: M13's registry totals plus the windowed one.

        Both halves read the same M8 views, so the totals and the ranking cannot
        disagree about what the registry holds. ``windowed`` re-filters those
        views by ``last_seen`` — the only time bound M8 records — and is a
        section because it is a block a client renders on its own, so a future
        registry failure must be reportable rather than fatal.
        """
        views = self._devices.list_device_views()
        ranked = ranked_devices(views, limit=limit, by=by)
        windowed = read_section(
            lambda: build_device_window(views, window, limit=limit, by=by),
            name="devices",
        )
        return AnalyticsDevices(
            total=len(views),
            by_status=device_status_counts(views),
            rank_by=by,
            top=[ranked_device(view) for view in ranked],
            period=period_from_window(window),
            windowed=DeviceWindowSection(
                available=windowed.available,
                error=windowed.error,
                data=windowed.data,
            ),
        )

    # -- connections (M16.5) -----------------------------------------------

    def connections(
        self, *, window: AnalyticsWindow, limit: int, by: RankMetric
    ) -> AnalyticsConnections:
        """Return the connection view: M9's tracker counters plus the stored rows.

        The counters are the tracker's own, so they agree with ``/connections``.
        The ranking deliberately spans retired conversations as well as live
        ones: the busiest conversation of a session is frequently one that has
        already closed, and omitting it would answer a narrower question than
        "which conversations carried the most traffic".
        """
        views = self._tracker.list_connection_views(active_only=False)
        ranked = ranked_connections(views, limit=limit, by=by)
        stored = read_section(
            lambda: build_stored_connections(self._db, window, limit=limit, by=by),
            name="connections",
            session=self._db,
        )
        return AnalyticsConnections(
            active=self._tracker.get_active_count(),
            historical=self._tracker.get_historical_count(),
            tracked=self._tracker.get_tracked_count(),
            rank_by=by,
            top=[connection_entry(view) for view in ranked],
            period=period_from_window(window),
            stored=ConnectionsSection(
                available=stored.available, error=stored.error, data=stored.data
            ),
        )

    # -- threats (M16.6) ---------------------------------------------------

    def threats(
        self,
        *,
        window: AnalyticsWindow,
        rule_limit: int = DEFAULT_RULE_LIMIT,
    ) -> AnalyticsThreats:
        """Return the threat view: M10, M11 and M12 side by side, plus the window.

        Three judgements are reported and never collapsed into one "threat"
        number, because no milestone produces such a number: M10's findings are
        observations with no verdict, M11's severities are the evidence-based
        judgement, and M12's bands are the bounded prioritisation metric. The
        stored block adds a fourth, orthogonal view — the alert table read over
        an explicit period — rather than a fourth judgement.

        The incident registry is read once and both breakdowns come from that one
        snapshot, so the status total and the band total cannot describe different
        instants (M16.6).
        """
        summary = self._alerts.summary()
        diagnostics = self._detections.get_diagnostics()
        incidents = self._correlations.registry.incidents()
        breakdown = incident_breakdown(incidents)
        stored = read_section(
            lambda: build_stored_alerts(self._db, window, rule_limit=rule_limit),
            name="alerts",
            session=self._db,
        )
        return AnalyticsThreats(
            alerts_total=summary["total"],
            alerts_open=open_alert_count(summary),
            alerts_by_severity=severity_counts(summary),
            alerts_by_status=dict(summary["by_status"]),
            findings_retained=diagnostics.retained_findings,
            detections_evaluated=diagnostics.evaluations,
            detections_findings=diagnostics.findings,
            detections_errors=diagnostics.errors,
            rules=rule_stats(self._detections),
            incidents_total=breakdown.total,
            incidents_active=breakdown.active,
            incidents_by_status=breakdown.by_status,
            incidents_by_risk_band=breakdown.by_risk_band,
            highest_risk_score=breakdown.highest_risk_score,
            period=period_from_window(window),
            stored=AlertsSection(
                available=stored.available, error=stored.error, data=stored.data
            ),
            findings=build_findings_summary(self._detections, window),
            incident_links=build_incident_linkage(incidents),
        )


__all__ = [
    "DEFAULT_RATE_WINDOW",
    "AnalyticsService",
    "period_from_window",
]
