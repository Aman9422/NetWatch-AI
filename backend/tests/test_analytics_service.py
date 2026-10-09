"""Tests for the analytics service that assembles the five views (M16.1).

The query and view tests cover the pieces; this file covers the assembly. Two
things are only observable here:

* **the two halves stay separate.** A live figure comes from a runtime service, a
  stored one from SQLite, and the tests check they are read from where they claim
  rather than one standing in for the other;
* **a stored block can fail on its own.** A database that cannot be read must
  produce an unavailable section beside intact live figures — never a zero, and
  never a failed request (M16.8).

The collaborators are the real classes the application wires, driven by
deterministic clocks, so the assembly under test is the production one.
"""

from __future__ import annotations

from collections.abc import Callable, Generator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.alerts.queries import AlertQueries
from app.analytics.sections import UNAVAILABLE_MESSAGE
from app.analytics.service import DEFAULT_RATE_WINDOW, AnalyticsService, period_from_window
from app.analytics.window import MAX_BUCKETS, AnalyticsWindow
from app.connections.manager import ConnectionTracker
from app.correlation.engine import CorrelationEngine
from app.detection.engine import DetectionEngine
from app.devices.manager import DeviceDiscoveryManager
from app.schemas.packet import PacketType
from app.statistics.manager import TrafficStatisticsManager
from tests.analytics_fakes import make_window, seed_alert, seed_connection, seed_packet
from tests.correlation_fakes import make_alert, make_engine
from tests.detection_fakes import FixedRule, make_context
from tests.fakes import PACKET_BASE_TIME, FakeClock, make_normalized_packet

MAC_A = "AA:BB:CC:DD:EE:FF"
IP_A = "192.168.1.10"


@pytest.fixture
def statistics() -> TrafficStatisticsManager:
    """A statistics manager owned by one test."""
    return TrafficStatisticsManager()


@pytest.fixture
def devices() -> DeviceDiscoveryManager:
    """A device registry over a deterministic clock."""
    return DeviceDiscoveryManager(
        inactivity_threshold=60.0,
        retention_seconds=600.0,
        clock=FakeClock(PACKET_BASE_TIME),
    )


@pytest.fixture
def tracker() -> ConnectionTracker:
    """A thread-free connection tracker over a deterministic clock."""
    return ConnectionTracker(
        autostart_cleanup=False, clock=FakeClock(PACKET_BASE_TIME)
    )


@pytest.fixture
def detections() -> DetectionEngine:
    """An engine with one detector that fires on demand."""
    return DetectionEngine([FixedRule()])


@pytest.fixture
def correlations() -> CorrelationEngine:
    """A correlation engine over deterministic collaborators."""
    return make_engine()


@pytest.fixture
def service(
    db_session: Session,
    statistics: TrafficStatisticsManager,
    devices: DeviceDiscoveryManager,
    tracker: ConnectionTracker,
    session_factory: Callable[[], Session],
    detections: DetectionEngine,
    correlations: CorrelationEngine,
) -> AnalyticsService:
    """The service under test, over the isolated database."""
    return AnalyticsService(
        db=db_session,
        statistics=statistics,
        devices=devices,
        tracker=tracker,
        alerts=AlertQueries(session_factory=session_factory),
        detections=detections,
        correlations=correlations,
    )


@pytest.fixture
def bare_engine():
    """A fresh SQLite engine whose tables were never created.

    Deliberately *not* the shared ``db_engine``: the fixtures that create the M2
    schema act on that one, so a "bare" session over it would find the tables and
    read them successfully. This engine is touched by nothing else, which is what
    makes every analytic SELECT against it fail the way an unreadable store does.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def bare_db_session(bare_engine) -> Generator[Session, None, None]:
    """A session over a database where the analytics tables do not exist (M16.8)."""
    session = Session(bind=bare_engine)
    try:
        yield session
    finally:
        session.close()


def seed_packet_statistics(
    statistics: TrafficStatisticsManager, *, length: int = 100
) -> None:
    """Record one packet with the M6 manager."""
    statistics.record_packet(make_normalized_packet(length=length))


def seed_device(devices: DeviceDiscoveryManager) -> None:
    """Track one device through the real M8 path."""
    devices.process_packet(
        make_normalized_packet(
            source_mac=MAC_A,
            source_ip=IP_A,
            destination_ip=None,
            length=100,
            timestamp=PACKET_BASE_TIME,
        )
    )


# --------------------------------------------------------------------------
# the period every view reports (M16.7)
# --------------------------------------------------------------------------


def test_period_projects_the_resolved_window() -> None:
    window = make_window(since=PACKET_BASE_TIME, until=PACKET_BASE_TIME + 600.0)

    period = period_from_window(window)

    assert period.since == window.iso_since()
    assert period.until == window.iso_until()
    assert period.seconds == 600.0
    assert period.bucket_seconds == window.bucket_seconds
    assert period.buckets == window.buckets
    assert period.max_buckets == MAX_BUCKETS
    assert period.defaulted is False


def test_period_says_when_the_caller_named_no_bounds() -> None:
    window = AnalyticsWindow(
        since=PACKET_BASE_TIME,
        until=PACKET_BASE_TIME + 60.0,
        bucket_seconds=10,
        defaulted=True,
    )

    assert period_from_window(window).defaulted is True


@pytest.mark.parametrize(
    "method",
    ["traffic", "protocols", "devices", "connections", "threats"],
)
def test_every_view_reports_the_same_period(service: AnalyticsService, method: str) -> None:
    """A client never has to guess which window a number describes (M16.7)."""

    window = make_window()
    payload = getattr(service, method)(window=window, **_view_arguments(method))

    assert payload.period.since == window.iso_since()
    assert payload.period.until == window.iso_until()
    assert payload.period.bucket_seconds == window.bucket_seconds


def _view_arguments(method: str) -> dict:
    """Return the extra keyword arguments one view method requires."""
    if method in {"traffic", "devices", "connections"}:
        return {"limit": 10, "by": "packets"}
    if method == "protocols":
        return {"by": "packets"}
    return {}


# --------------------------------------------------------------------------
# traffic (M16.2)
# --------------------------------------------------------------------------


def test_traffic_is_empty_on_both_halves_before_anything_happens(
    service: AnalyticsService,
) -> None:
    payload = service.traffic(window=make_window(), limit=10, by="packets")

    assert payload.total_packets == 0
    assert payload.total_bytes == 0
    assert payload.average_packet_bytes == 0.0
    assert payload.stored_packet_count == 0
    assert payload.protocols == []
    assert payload.stored.available is True
    assert payload.stored.data is not None
    assert payload.stored.data.total_packets == 0


def test_traffic_live_half_is_the_m6_snapshot(
    service: AnalyticsService, statistics: TrafficStatisticsManager
) -> None:
    seed_packet_statistics(statistics, length=100)
    seed_packet_statistics(statistics, length=60)

    payload = service.traffic(window=make_window(), limit=10, by="packets")
    snapshot = statistics.get_statistics()

    assert payload.total_packets == snapshot.total_packets == 2
    assert payload.total_bytes == snapshot.total_bytes == 160
    assert payload.average_packet_bytes == 80.0
    assert payload.protocol_count == len(snapshot.protocol_statistics)


def test_traffic_live_and_stored_are_two_different_figures(
    service: AnalyticsService, statistics: TrafficStatisticsManager
) -> None:
    """Live counters reset with the process; stored rows do not (M16.2)."""

    seed_packet_statistics(statistics)

    payload = service.traffic(window=make_window(), limit=10, by="packets")

    assert payload.total_packets == 1  # observed live
    assert payload.stored.data is not None
    assert payload.stored.data.total_packets == 0  # nothing persisted
    assert payload.stored_packet_count == 0


def test_traffic_stored_half_answers_for_the_window(
    service: AnalyticsService, db_session: Session
) -> None:
    seed_packet(db_session, offset=10.0, length=200)
    seed_packet(db_session, offset=20.0, length=200)
    # Outside the window, so it must not be counted.
    seed_packet(db_session, offset=10_000.0, length=200)

    payload = service.traffic(window=make_window(), limit=10, by="packets")

    assert payload.stored.data is not None
    assert payload.stored.data.total_packets == 2
    assert payload.stored.data.total_bytes == 400
    assert payload.stored_packet_count == 3  # unwindowed, as M13 reported it


def test_traffic_uses_the_snapshot_rates_by_default(
    service: AnalyticsService, statistics: TrafficStatisticsManager
) -> None:
    seed_packet_statistics(statistics)

    payload = service.traffic(
        window=make_window(), rate_window=DEFAULT_RATE_WINDOW, limit=10, by="packets"
    )
    snapshot = statistics.get_statistics()

    assert payload.packets_per_second == snapshot.packets_per_second
    assert payload.bytes_per_second == snapshot.bytes_per_second
    assert payload.bits_per_second == snapshot.bits_per_second


def test_traffic_asks_the_manager_for_a_named_rate_window(
    service: AnalyticsService, statistics: TrafficStatisticsManager
) -> None:
    seed_packet_statistics(statistics, length=100)

    payload = service.traffic(
        window=make_window(), rate_window="10s", limit=10, by="packets"
    )
    expected_packets, expected_bytes = statistics.get_rates("10s")

    assert payload.packets_per_second == expected_packets
    assert payload.bytes_per_second == expected_bytes
    assert payload.bits_per_second == expected_bytes * 8.0


def test_traffic_rankings_come_from_the_manager_and_the_table(
    service: AnalyticsService, statistics: TrafficStatisticsManager, db_session: Session
) -> None:
    seed_packet_statistics(statistics)
    seed_packet(db_session, offset=0.0, source_ip="10.0.0.1", length=10)
    seed_packet(db_session, offset=1.0, source_ip="10.0.0.2", length=900)

    payload = service.traffic(window=make_window(), limit=10, by="bytes")

    assert [entry.key for entry in payload.top_sources] == ["192.168.1.10"]
    assert payload.stored.data is not None
    assert [entry.key for entry in payload.stored.data.top_sources] == [
        "10.0.0.2",
        "10.0.0.1",
    ]


# --------------------------------------------------------------------------
# protocols (M16.3)
# --------------------------------------------------------------------------


def test_protocols_is_empty_on_both_halves(
    service: AnalyticsService,
) -> None:
    payload = service.protocols(window=make_window(), by="packets")

    assert payload.count == 0
    assert payload.total_packets == 0
    assert payload.protocols == []
    assert payload.stored.available is True
    assert payload.stored.data is not None
    assert payload.stored.data.count == 0


def test_protocols_live_entries_are_ordered_by_the_requested_metric(
    service: AnalyticsService, statistics: TrafficStatisticsManager
) -> None:
    statistics.record_packet(
        make_normalized_packet(
            protocol=PacketType.TCP.value, packet_type=PacketType.TCP, length=1000
        )
    )
    for _ in range(3):
        statistics.record_packet(
            make_normalized_packet(
                protocol=PacketType.UDP.value, packet_type=PacketType.UDP, length=10
            )
        )

    by_packets = service.protocols(window=make_window(), by="packets")
    by_bytes = service.protocols(window=make_window(), by="bytes")

    assert [entry.protocol for entry in by_packets.protocols][0] == "UDP"
    assert [entry.protocol for entry in by_bytes.protocols][0] == "TCP"
    assert by_bytes.rank_by == "bytes"


def test_protocols_stored_breakdown_is_separate_from_the_live_one(
    service: AnalyticsService, statistics: TrafficStatisticsManager, db_session: Session
) -> None:
    statistics.record_packet(
        make_normalized_packet(
            protocol=PacketType.DNS.value, packet_type=PacketType.DNS
        )
    )
    seed_packet(db_session, offset=0.0, packet_type=PacketType.UDP)

    payload = service.protocols(window=make_window(), by="packets")

    assert [entry.protocol for entry in payload.protocols] == ["DNS"]
    assert payload.stored.data is not None
    assert [entry.protocol for entry in payload.stored.data.protocols] == ["UDP"]


# --------------------------------------------------------------------------
# devices (M16.4)
# --------------------------------------------------------------------------


def test_devices_is_empty_but_names_every_state(service: AnalyticsService) -> None:
    payload = service.devices(window=make_window(), limit=10, by="packets")

    assert payload.total == 0
    assert payload.top == []
    assert set(payload.by_status) == {"active", "inactive", "unknown"}
    assert payload.windowed.available is True
    assert payload.windowed.data is not None
    assert payload.windowed.data.total == 0


def test_devices_reports_the_registry_and_what_fell_in_the_period(
    service: AnalyticsService, devices: DeviceDiscoveryManager
) -> None:
    seed_device(devices)

    payload = service.devices(window=make_window(), limit=10, by="packets")

    assert payload.total == len(devices.list_device_views()) == 1
    assert payload.by_status["active"] == 1
    assert payload.top[0].device_id == f"mac:{MAC_A}"
    assert payload.windowed.data is not None
    assert payload.windowed.data.total == 1


def test_devices_windowed_block_excludes_a_device_last_seen_earlier(
    service: AnalyticsService, devices: DeviceDiscoveryManager
) -> None:
    seed_device(devices)

    later = AnalyticsWindow(
        since=PACKET_BASE_TIME + 3600.0,
        until=PACKET_BASE_TIME + 7200.0,
        bucket_seconds=60,
    )
    payload = service.devices(window=later, limit=10, by="packets")

    assert payload.total == 1  # the registry still holds it
    assert payload.windowed.data is not None
    assert payload.windowed.data.total == 0  # but M8 did not see it then


def test_devices_ranking_carries_no_risk(service: AnalyticsService, devices: DeviceDiscoveryManager) -> None:
    """M8 scores no risk, so neither half of the view invents one (M16.4)."""

    seed_device(devices)

    payload = service.devices(window=make_window(), limit=10, by="packets")

    assert "risk_score" not in payload.top[0].model_dump()
    assert payload.windowed.data is not None
    assert "risk_score" not in payload.windowed.data.top[0].model_dump()


def test_devices_honour_the_limit_on_both_rankings(
    service: AnalyticsService, devices: DeviceDiscoveryManager
) -> None:
    for index in range(4):
        devices.process_packet(
            make_normalized_packet(
                source_mac=f"AA:BB:CC:DD:EE:{index:02X}",
                source_ip=f"192.168.1.{10 + index}",
                destination_ip=None,
                timestamp=PACKET_BASE_TIME,
            )
        )

    payload = service.devices(window=make_window(), limit=2, by="packets")

    assert payload.total == 4
    assert len(payload.top) == 2
    assert payload.windowed.data is not None
    assert len(payload.windowed.data.top) == 2


# --------------------------------------------------------------------------
# connections (M16.5)
# --------------------------------------------------------------------------


def test_connections_is_empty_but_names_the_counters(
    service: AnalyticsService,
) -> None:
    payload = service.connections(window=make_window(), limit=10, by="bytes")

    assert payload.active == 0
    assert payload.historical == 0
    assert payload.tracked == 0
    assert payload.top == []
    assert payload.stored.available is True
    assert payload.stored.data is not None
    assert set(payload.stored.data.by_status) == {"active", "completed", "timeout"}


def test_connections_counters_are_the_tracker_s_own(
    service: AnalyticsService, tracker: ConnectionTracker
) -> None:
    tracker.process_packet(make_normalized_packet())

    payload = service.connections(window=make_window(), limit=10, by="bytes")

    assert payload.active == tracker.get_active_count() == 1
    assert payload.tracked == tracker.get_tracked_count() == 1
    assert payload.top[0].protocol == "TCP"


def test_connections_ranking_spans_retired_conversations(
    service: AnalyticsService, tracker: ConnectionTracker
) -> None:
    tracker.process_packet(make_normalized_packet())
    tracker.expire_connections(now=PACKET_BASE_TIME + 100_000)

    payload = service.connections(window=make_window(), limit=10, by="bytes")

    assert payload.active == 0
    assert payload.tracked == 1
    assert len(payload.top) == 1


def test_connections_stored_block_reads_the_table(
    service: AnalyticsService, db_session: Session
) -> None:
    seed_connection(db_session, offset=0.0, protocol="TCP", status="completed")
    seed_connection(db_session, offset=10.0, protocol="UDP", status="active")

    payload = service.connections(window=make_window(), limit=10, by="bytes")

    assert payload.stored.data is not None
    assert payload.stored.data.total == 2
    assert payload.stored.data.active == 1
    assert payload.stored.data.by_protocol == {"TCP": 1, "UDP": 1}


# --------------------------------------------------------------------------
# threats (M16.6)
# --------------------------------------------------------------------------


def test_threats_is_empty_but_keeps_every_vocabulary(
    service: AnalyticsService,
) -> None:
    payload = service.threats(window=make_window())

    assert payload.alerts_total == 0
    assert payload.incidents_total == 0
    assert payload.findings_retained == 0
    assert set(payload.alerts_by_severity) == {"critical", "high", "medium", "low"}
    assert set(payload.incidents_by_risk_band) == {
        "minimal",
        "low",
        "moderate",
        "high",
    }
    assert payload.stored.available is True
    assert payload.stored.data is not None
    assert payload.stored.data.total == 0


def test_threats_reports_the_detector_counters(
    service: AnalyticsService, detections: DetectionEngine
) -> None:
    detections.evaluate(make_context())

    payload = service.threats(window=make_window())
    diagnostics = detections.get_diagnostics()

    assert payload.findings_retained == diagnostics.retained_findings == 1
    assert payload.detections_findings == diagnostics.findings == 1
    assert [rule.rule_id for rule in payload.rules] == ["fixed"]


def test_threats_keeps_findings_alerts_and_incidents_apart(
    service: AnalyticsService, detections: DetectionEngine, correlations: CorrelationEngine
) -> None:
    """Three layers, three answers — no single collapsed "threat" number (M16.6)."""

    detections.evaluate(make_context())
    correlations.correlate_alerts([make_alert(), make_alert(alert_id=2)])

    payload = service.threats(window=make_window())

    assert payload.detections_findings == 1
    assert payload.alerts_total == 0
    assert payload.incidents_total == correlations.count_incidents()
    assert sum(payload.incidents_by_risk_band.values()) == payload.incidents_total
    assert payload.findings.in_window == 1
    assert payload.incident_links.alerts_in_incidents == 2


def test_threats_stored_block_reads_the_alert_table(
    service: AnalyticsService, db_session: Session
) -> None:
    seed_alert(db_session, offset=0.0, severity="critical", risk_score=80)
    seed_alert(db_session, offset=10.0, severity="low", risk_score=10)

    payload = service.threats(window=make_window())

    assert payload.stored.data is not None
    assert payload.stored.data.total == 2
    assert payload.stored.data.by_severity["critical"] == 1
    assert payload.stored.data.by_risk_band["high"] == 1
    assert payload.stored.data.by_risk_band["minimal"] == 1


def test_threats_scores_no_risk_of_its_own(
    service: AnalyticsService, correlations: CorrelationEngine, db_session: Session
) -> None:
    """Both band breakdowns read M12's score, banded by M12's own table."""

    correlations.correlate_alerts([make_alert(), make_alert(alert_id=2)])
    seed_alert(db_session, offset=0.0, risk_score=90)

    payload = service.threats(window=make_window())

    assert payload.highest_risk_score == max(
        incident.risk_score for incident in correlations.registry.incidents()
    )
    assert payload.stored.data is not None
    assert payload.stored.data.by_risk_band["high"] == 1


# --------------------------------------------------------------------------
# failure isolation (M16.8)
# --------------------------------------------------------------------------


@pytest.fixture
def broken_service(
    bare_db_session: Session,
    statistics: TrafficStatisticsManager,
    devices: DeviceDiscoveryManager,
    tracker: ConnectionTracker,
    session_factory: Callable[[], Session],
    detections: DetectionEngine,
    correlations: CorrelationEngine,
) -> AnalyticsService:
    """The service whose request-scoped session cannot read its tables (M16.8).

    ``db`` is the one thing here that is broken: it is the session the route
    hands the service, and every analytic SELECT through it fails. The other
    collaborators open their own connections and still answer, which is what
    makes the isolation assertions mean something — the failure under test is a
    single unreadable block, not a dead process.

    It also marks the boundary of what M16 can report. The M13 top-level figures
    are plain integers a client already renders, so a collaborator that fails
    there must still take the request down with it; only the blocks M16 added are
    representable as unavailable, which is exactly what these tests exercise.
    """
    return AnalyticsService(
        db=bare_db_session,
        statistics=statistics,
        devices=devices,
        tracker=tracker,
        alerts=AlertQueries(session_factory=session_factory),
        detections=detections,
        correlations=correlations,
    )


def test_traffic_reports_an_unreadable_store_but_keeps_the_live_figures(
    broken_service: AnalyticsService, statistics: TrafficStatisticsManager
) -> None:
    """A block that cannot be read says so; it is never reported as zero (M16.8)."""

    seed_packet_statistics(statistics, length=100)

    payload = broken_service.traffic(window=make_window(), limit=10, by="packets")

    assert payload.total_packets == 1  # the live half is intact
    assert payload.stored.available is False
    assert payload.stored.error == UNAVAILABLE_MESSAGE
    assert payload.stored.data is None


def test_protocols_reports_an_unreadable_store(
    broken_service: AnalyticsService,
) -> None:
    payload = broken_service.protocols(window=make_window(), by="packets")

    assert payload.stored.available is False
    assert payload.stored.error == UNAVAILABLE_MESSAGE


def test_connections_reports_an_unreadable_store(
    broken_service: AnalyticsService, tracker: ConnectionTracker
) -> None:
    tracker.process_packet(make_normalized_packet())

    payload = broken_service.connections(window=make_window(), limit=10, by="bytes")

    assert payload.tracked == 1
    assert payload.stored.available is False
    assert payload.stored.error == UNAVAILABLE_MESSAGE


def test_threats_reports_an_unreadable_store(
    broken_service: AnalyticsService,
) -> None:
    payload = broken_service.threats(window=make_window())

    assert payload.stored.available is False
    assert payload.stored.error == UNAVAILABLE_MESSAGE
    # The vocabularies are still named, so a client still renders fixed rows.
    assert set(payload.alerts_by_severity) == {"critical", "high", "medium", "low"}
    assert payload.incident_links.incidents_total == 0


def test_an_unreadable_store_never_leaks_its_cause(
    broken_service: AnalyticsService,
) -> None:
    """The message names no table, query or exception text (M13.30/M16.8)."""

    payload = broken_service.traffic(window=make_window(), limit=10, by="packets")

    message = payload.stored.error or ""
    assert message == UNAVAILABLE_MESSAGE
    assert "no such table" not in message
    assert "packets" not in message
    assert "SELECT" not in message


def test_one_unreadable_block_does_not_take_the_next_one_with_it(
    broken_service: AnalyticsService,
) -> None:
    """A reported section leaves the session usable for the following read."""

    first = broken_service.traffic(window=make_window(), limit=10, by="packets")
    second = broken_service.protocols(window=make_window(), by="packets")

    assert first.stored.available is False
    # The second view's *live* half still resolves, which it could not if the
    # first failure had left the request unusable.
    assert second.count == 0
    assert second.stored.available is False
