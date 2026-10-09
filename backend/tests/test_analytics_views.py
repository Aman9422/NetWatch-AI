"""Tests for the M16 view builders and the availability sections (M16.2-M16.6).

The query layer was tested against rows it wrote; these builders are tested on
what they *decide* — which figures they report, which vocabularies they
zero-fill, and what they say when a read fails. The distinction matters because
it is where M16's rules live: a series is zero-filled over the window's own
buckets, a closed vocabulary is named in full, and an unreadable block is
reported as unreadable rather than as zero.
"""

from __future__ import annotations

from sqlalchemy import select, text

from app.alerts.queries import AlertQueries, AlertSummary
from app.analytics.alert_view import (
    DEFAULT_RULE_LIMIT,
    RISK_BAND_KEYS,
    SEVERITY_KEYS,
    build_stored_alerts,
)
from app.analytics.connection_view import build_stored_connections
from app.analytics.device_view import build_device_window, iso_to_epoch, ranked_device
from app.analytics.distributions import (
    CONFIDENCE_RANGES,
    CONFIDENCE_RANGE_LABELS,
    confidence_range_label,
)
from app.analytics.live_view import (
    connection_entry,
    device_status_counts,
    incident_breakdown,
    open_alert_count,
    ranked_devices,
    severity_counts,
    topped,
)
from app.analytics.sections import UNAVAILABLE_MESSAGE, read_section
from app.analytics.threat_view import build_findings_summary, build_incident_linkage
from app.analytics.traffic_view import build_stored_protocols, build_stored_traffic
from app.analytics.window import iso_from_epoch
from app.connections.manager import ConnectionTracker
from app.detection.engine import DetectionEngine
from app.risk.bands import BAND_RANGES
from app.schemas.device import DeviceStatus, DeviceView
from app.schemas.packet import PacketType
from tests.analytics_fakes import (
    WINDOW_BUCKET_SECONDS,
    make_window,
    seed_alert,
    seed_connection,
    seed_packet,
    utc,
)
from tests.correlation_fakes import make_alert, make_engine
from tests.detection_fakes import FixedRule, make_context
from tests.fakes import FakeClock, PACKET_BASE_TIME, make_normalized_packet


def _naive(epoch: float):
    """Return the naive UTC datetime a stored column holds for ``epoch``."""
    return utc(epoch)


def _make_connection_view():
    """Return a real M9 connection view for one tracked conversation.

    Built through the tracker rather than by constructing the view directly, so
    the projection under test reads the fields M9 actually produces.
    """
    tracker = ConnectionTracker(
        autostart_cleanup=False, clock=FakeClock(PACKET_BASE_TIME)
    )
    tracker.process_packet(make_normalized_packet())
    return tracker.list_connection_views(active_only=False)[0]

MAC_A = "AA:BB:CC:DD:EE:FF"
MAC_B = "AA:BB:CC:DD:EE:01"
IP_A = "192.168.1.10"
IP_B = "192.168.1.11"


def make_device_view(**overrides) -> DeviceView:
    """Build one M8 device view, dated inside the test window by default."""
    values: dict = {
        "device_id": f"mac:{MAC_A}",
        "mac_address": MAC_A,
        "ip_addresses": [IP_A],
        "first_seen": iso_from_epoch(PACKET_BASE_TIME),
        "last_seen": iso_from_epoch(PACKET_BASE_TIME + 30.0),
        "packet_count": 10,
        "byte_count": 1000,
        "hostname": None,
        "status": DeviceStatus.ACTIVE,
    }
    values.update(overrides)
    return DeviceView(**values)


# --------------------------------------------------------------------------
# availability sections (M16.8)
# --------------------------------------------------------------------------


def test_a_successful_read_is_available_and_carries_its_value(db_session) -> None:
    outcome = read_section(lambda: 42, name="probe")

    assert outcome.available is True
    assert outcome.error is None
    assert outcome.data == 42


def test_a_failing_read_is_unavailable_with_a_safe_message(db_session) -> None:
    def failing():
        raise RuntimeError("the disk is on fire at /var/lib/netwatch.db")

    outcome = read_section(failing, name="broken")

    assert outcome.available is False
    assert outcome.error == UNAVAILABLE_MESSAGE
    assert outcome.data is None
    # The message names nothing about the failure itself.
    assert "disk" not in (outcome.error or "")
    assert "/var/lib" not in (outcome.error or "")


def test_read_section_never_propagates_its_loader_s_failure() -> None:
    """The function is total: a raise inside becomes a reported section."""

    def failing():
        raise ValueError("boom")

    outcome = read_section(failing, name="always-broken")

    assert outcome.available is False
    assert outcome.data is None


def test_a_failed_read_rolls_the_session_back_so_later_reads_work(db_session) -> None:
    """One bad statement must not make every later block unavailable (M16.8)."""

    def failing():
        return db_session.execute(text("SELECT * FROM no_such_table")).all()

    outcome = read_section(failing, name="broken", session=db_session)

    assert outcome.available is False
    # The session is usable again, so the block after this one still reads.
    assert db_session.scalar(select(1)) == 1
    assert read_section(lambda: "later", name="later").available is True


# --------------------------------------------------------------------------
# confidence ranges (M16.6)
# --------------------------------------------------------------------------


def test_confidence_ranges_are_derived_from_the_risk_tiling() -> None:
    """One documented 0-100 tiling, not a second set of thresholds (M12.27)."""

    assert CONFIDENCE_RANGES == tuple(
        (f"{low}-{high}", low, high) for _band, low, high in BAND_RANGES
    )
    assert CONFIDENCE_RANGE_LABELS == ("0-24", "25-49", "50-74", "75-100")


def test_confidence_range_labels_are_numeric_not_band_names() -> None:
    """A confidence range must not be named after a risk band."""

    band_names = {band.value for band, _low, _high in BAND_RANGES}
    assert band_names.isdisjoint(set(CONFIDENCE_RANGE_LABELS))


def test_every_confidence_is_placed_in_its_range() -> None:
    assert confidence_range_label(0) == "0-24"
    assert confidence_range_label(24) == "0-24"
    assert confidence_range_label(25) == "25-49"
    assert confidence_range_label(49) == "25-49"
    assert confidence_range_label(50) == "50-74"
    assert confidence_range_label(74) == "50-74"
    assert confidence_range_label(75) == "75-100"
    assert confidence_range_label(100) == "75-100"


def test_an_out_of_range_confidence_is_clamped_not_dropped() -> None:
    """A histogram that silently omits observations is worse than a clamped edge."""

    assert confidence_range_label(-5) == CONFIDENCE_RANGE_LABELS[0]
    assert confidence_range_label(150) == CONFIDENCE_RANGE_LABELS[-1]


# --------------------------------------------------------------------------
# stored traffic (M16.2)
# --------------------------------------------------------------------------


def test_stored_traffic_reports_zeroes_and_nulls_for_an_empty_window(db_session) -> None:
    window = make_window()
    data = build_stored_traffic(db_session, window, limit=10, by="packets")

    assert data.total_packets == 0
    assert data.total_bytes == 0
    assert data.packets_per_second == 0.0
    assert data.bytes_per_second == 0.0
    # No packet was stored, so no size was observed: null, not 0.0.
    assert data.average_packet_bytes is None
    assert data.first_timestamp is None
    assert data.last_timestamp is None
    assert data.distinct_protocols == 0
    assert data.top_sources == []
    assert data.protocols == []


def test_stored_traffic_series_is_zero_filled_over_the_window_s_buckets(db_session) -> None:
    """A bucket with nothing stored plots as a gap, and the listing is bounded."""

    window = make_window()
    seed_packet(db_session, offset=0.0)

    data = build_stored_traffic(db_session, window, limit=10, by="packets")

    assert len(data.series) == window.buckets
    assert len(data.series) <= 240
    filled = [point for point in data.series if point.packets == 0]
    assert filled  # every bucket but the one holding the packet is empty
    assert sum(point.packets for point in data.series) == 1


def test_stored_traffic_totals_and_rates_describe_the_window(db_session) -> None:
    window = make_window()
    seed_packet(db_session, offset=10.0, length=100)
    seed_packet(db_session, offset=20.0, length=300)

    data = build_stored_traffic(db_session, window, limit=10, by="packets")

    assert data.total_packets == 2
    assert data.total_bytes == 400
    assert data.average_packet_bytes == 200.0
    assert data.packets_per_second == 2 / window.seconds
    assert data.bytes_per_second == 400 / window.seconds
    assert data.first_timestamp == iso_from_epoch(PACKET_BASE_TIME + 10.0)
    assert data.last_timestamp == iso_from_epoch(PACKET_BASE_TIME + 20.0)


def test_stored_traffic_rankings_use_the_requested_metric(db_session) -> None:
    """The two metrics genuinely disagree, so neither can stand in for the other."""

    # ``chatty`` sends more packets; ``bulky`` sends fewer but far bigger ones.
    seed_packet(db_session, offset=0.0, source_ip="10.0.0.1", length=10)
    seed_packet(db_session, offset=1.0, source_ip="10.0.0.1", length=10)
    seed_packet(db_session, offset=2.0, source_ip="10.0.0.2", length=900)

    by_packets = build_stored_traffic(
        db_session, make_window(), limit=10, by="packets"
    )
    by_bytes = build_stored_traffic(db_session, make_window(), limit=10, by="bytes")

    assert by_packets.top_sources[0].key == "10.0.0.1"
    assert by_packets.top_sources[0].packets == 2
    assert by_bytes.top_sources[0].key == "10.0.0.2"
    assert by_bytes.top_sources[0].bytes == 900


def test_equal_traffic_ranks_on_the_key_so_a_ranking_is_stable(db_session) -> None:
    seed_packet(db_session, offset=0.0, source_ip="10.0.0.2")
    seed_packet(db_session, offset=1.0, source_ip="10.0.0.1")

    data = build_stored_traffic(db_session, make_window(), limit=10, by="packets")

    assert [entry.key for entry in data.top_sources] == ["10.0.0.1", "10.0.0.2"]


def test_stored_traffic_states_how_much_of_the_window_the_port_ranking_omitted(
    db_session,
) -> None:
    seed_packet(db_session, offset=0.0, source_port=None, destination_port=None)

    data = build_stored_traffic(db_session, make_window(), limit=10, by="packets")

    assert data.packets_without_source_port == 1
    assert data.packets_without_destination_port == 1
    assert data.top_ports == []


# --------------------------------------------------------------------------
# stored protocols (M16.3)
# --------------------------------------------------------------------------


def test_stored_protocols_is_empty_when_nothing_is_stored(db_session) -> None:
    data = build_stored_protocols(db_session, make_window(), by="packets")

    assert data.count == 0
    assert data.distinct_protocols == 0
    assert data.truncated is False
    assert data.total_packets == 0
    assert data.total_bytes == 0
    assert data.protocols == []


def test_stored_protocol_percentages_are_shares_of_the_window(db_session) -> None:
    """The denominator is the window, so the shares always sum to 100."""

    seed_packet(db_session, offset=0.0, packet_type=PacketType.TCP, length=100)
    seed_packet(db_session, offset=1.0, packet_type=PacketType.TCP, length=100)
    seed_packet(db_session, offset=2.0, packet_type=PacketType.TCP, length=100)
    seed_packet(db_session, offset=3.0, packet_type=PacketType.UDP, length=10)

    data = build_stored_protocols(db_session, make_window(), by="packets")
    by_name = {entry.protocol: entry for entry in data.protocols}

    assert data.count == 2
    assert data.total_packets == 4
    assert by_name["TCP"].packets == 3
    assert by_name["TCP"].percentage == 75.0
    assert by_name["UDP"].percentage == 25.0
    assert sum(entry.percentage for entry in data.protocols) == 100.0


def test_stored_protocols_are_ranked_by_the_requested_metric(db_session) -> None:
    seed_packet(db_session, offset=0.0, packet_type=PacketType.TCP, length=1000)
    for index in range(3):
        seed_packet(
            db_session,
            offset=float(index + 1),
            packet_type=PacketType.UDP,
            length=10,
        )

    by_packets = build_stored_protocols(db_session, make_window(), by="packets")
    by_bytes = build_stored_protocols(db_session, make_window(), by="bytes")

    assert [entry.protocol for entry in by_packets.protocols] == ["UDP", "TCP"]
    assert [entry.protocol for entry in by_bytes.protocols] == ["TCP", "UDP"]
    assert by_bytes.rank_by == "bytes"


def test_an_empty_breakdown_reports_no_truncation(db_session) -> None:
    data = build_stored_protocols(db_session, make_window(), by="bytes")

    assert data.truncated is False
    assert data.rank_by == "bytes"


# --------------------------------------------------------------------------
# device window (M16.4)
# --------------------------------------------------------------------------


def test_no_devices_names_every_state_at_zero() -> None:
    data = build_device_window([], make_window(), limit=10, by="packets")

    assert data.total == 0
    assert data.top == []
    assert set(data.by_status) == {status.value for status in DeviceStatus}
    assert all(count == 0 for count in data.by_status.values())


def test_the_device_window_selects_on_last_seen() -> None:
    inside = make_device_view()
    before = make_device_view(
        device_id=f"mac:{MAC_B}",
        last_seen=iso_from_epoch(PACKET_BASE_TIME - 1.0),
    )
    after = make_device_view(
        device_id="mac:AA:BB:CC:DD:EE:02",
        last_seen=iso_from_epoch(PACKET_BASE_TIME + 600.0),  # exactly `until`
    )

    data = build_device_window(
        [inside, before, after], make_window(), limit=10, by="packets"
    )

    assert data.total == 1
    assert data.top[0].device_id == inside.device_id


def test_an_undated_device_is_in_no_window() -> None:
    """The registry cannot say when it saw it, so it is not placed in a window."""

    undated = make_device_view(first_seen=None, last_seen=None)

    data = build_device_window([undated], make_window(), limit=10, by="packets")

    assert data.total == 0


def test_the_device_window_ranks_by_traffic_with_a_total_tie_break() -> None:
    heavy = make_device_view(device_id=f"mac:{MAC_B}", packet_count=50, byte_count=5)
    light = make_device_view(device_id=f"mac:{MAC_A}", packet_count=1, byte_count=900)
    equal_a = make_device_view(
        device_id="mac:01:00:00:00:00:00", packet_count=7, byte_count=7
    )
    equal_b = make_device_view(
        device_id="mac:02:00:00:00:00:00", packet_count=7, byte_count=7
    )

    by_packets = build_device_window(
        [heavy, light, equal_a, equal_b], make_window(), limit=10, by="packets"
    )
    by_bytes = build_device_window(
        [heavy, light, equal_a, equal_b], make_window(), limit=10, by="bytes"
    )

    assert [entry.device_id for entry in by_packets.top][0] == heavy.device_id
    assert [entry.device_id for entry in by_bytes.top][0] == light.device_id
    # Equal traffic orders on the device id, so the ranking is stable (M13.24).
    equal_ids = [
        entry.device_id
        for entry in by_packets.top
        if entry.device_id in {equal_a.device_id, equal_b.device_id}
    ]
    assert equal_ids == [equal_a.device_id, equal_b.device_id]


def test_the_device_window_honours_its_limit() -> None:
    views = [
        make_device_view(device_id=f"mac:AA:BB:CC:DD:EE:{index:02X}")
        for index in range(5)
    ]

    data = build_device_window(views, make_window(), limit=2, by="packets")

    assert data.total == 5
    assert len(data.top) == 2


def test_a_ranked_device_carries_m8_identity_and_dates() -> None:
    view = make_device_view(
        hostname="laptop",
        ip_addresses=[IP_A, IP_B],
        packet_count=12,
        byte_count=345,
    )

    entry = ranked_device(view)

    assert entry.device_id == view.device_id
    assert entry.mac_address == MAC_A
    assert entry.ip_addresses == [IP_A, IP_B]
    assert entry.hostname == "laptop"
    assert entry.status == "active"
    assert entry.first_seen == view.first_seen
    assert entry.last_seen == view.last_seen
    assert entry.packets == 12
    assert entry.bytes == 345


def test_a_ranked_device_carries_no_risk_figure() -> None:
    """M8 scores no risk, so M16 invents none (M13.10/M16.4)."""

    assert "risk_score" not in ranked_device(make_device_view()).model_dump()


def test_grouped_device_views_keep_every_address_of_a_shared_next_hop() -> None:
    """The M8 limitation is reported, not quietly resolved (M16.4).

    On a routed path the next hop's MAC can stand for several remote addresses;
    M8 records one device with many IPs and M16 passes all of them through.
    """

    view = make_device_view(ip_addresses=[IP_A, IP_B, "8.8.8.8"])

    assert ranked_device(view).ip_addresses == [IP_A, IP_B, "8.8.8.8"]


def test_iso_to_epoch_parses_zulu_and_offset_forms_and_tolerates_junk() -> None:
    assert iso_to_epoch("1970-01-01T00:00:00Z") == 0.0
    assert iso_to_epoch("1970-01-01T00:00:00+00:00") == 0.0
    assert iso_to_epoch("1970-01-01T00:00:00+05:00") == -18_000.0
    assert iso_to_epoch(None) is None
    assert iso_to_epoch("") is None
    assert iso_to_epoch("not a date") is None
# --------------------------------------------------------------------------
# stored connections (M16.5)
# --------------------------------------------------------------------------


def test_stored_connections_is_empty_but_names_every_status(db_session) -> None:
    data = build_stored_connections(db_session, make_window(), limit=10, by="bytes")

    assert data.total == 0
    assert data.active == 0
    assert data.first_timestamp is None
    assert data.last_timestamp is None
    assert data.series == [] or all(point.connections == 0 for point in data.series)
    # A closed vocabulary is named in full, so a client renders fixed rows.
    assert set(data.by_status) == {"active", "completed", "timeout"}
    assert all(count == 0 for count in data.by_status.values())
    # A protocol list cannot be enumerated, so it is reported as it stands.
    assert data.by_protocol == {}


def test_stored_connections_zero_fills_statuses_but_not_protocols(db_session) -> None:
    seed_connection(db_session, offset=0.0, protocol="TCP", status="completed")
    seed_connection(db_session, offset=1.0, protocol="TCP", status="completed")
    seed_connection(db_session, offset=2.0, protocol="QUIC", status="active")

    data = build_stored_connections(db_session, make_window(), limit=10, by="bytes")

    assert data.total == 3
    assert data.active == 1
    assert data.by_status == {"active": 1, "completed": 2, "timeout": 0}
    assert data.by_protocol == {"TCP": 2, "QUIC": 1}


def test_stored_connection_series_is_zero_filled_over_the_window(db_session) -> None:
    window = make_window()
    seed_connection(db_session, offset=5.0)

    data = build_stored_connections(db_session, window, limit=10, by="bytes")

    assert len(data.series) == window.buckets
    assert sum(point.connections for point in data.series) == 1
    assert any(point.connections == 0 for point in data.series)


def test_stored_connection_duration_reports_its_own_sample_size(db_session) -> None:
    start = PACKET_BASE_TIME
    seed_connection(
        db_session,
        offset=10.0,
        start_time=_naive(start + 10),
        end_time=_naive(start + 40),
    )
    # Still running: no `end_time`, so it contributes no duration.
    seed_connection(db_session, offset=20.0, end_time=None)

    data = build_stored_connections(db_session, make_window(), limit=10, by="bytes")

    assert data.total == 2
    assert data.duration.samples == 1
    assert data.duration.min_seconds == 30.0


def test_stored_connection_duration_is_absent_when_nothing_ended(db_session) -> None:
    seed_connection(db_session, offset=0.0, end_time=None)

    data = build_stored_connections(db_session, make_window(), limit=10, by="bytes")

    assert data.duration.samples == 0
    assert data.duration.mean_seconds is None


# --------------------------------------------------------------------------
# stored alerts (M16.6)
# --------------------------------------------------------------------------


def test_stored_alerts_of_an_empty_window_names_every_vocabulary(db_session) -> None:
    data = build_stored_alerts(db_session, make_window())

    assert data.total == 0
    assert data.without_rule_key == 0
    assert data.first_timestamp is None
    assert data.last_timestamp is None
    assert set(data.by_severity) == set(SEVERITY_KEYS)
    assert set(data.by_risk_band) == set(RISK_BAND_KEYS)
    assert set(data.by_confidence_range) == set(CONFIDENCE_RANGE_LABELS)
    # Every status M11 can store, so a lifecycle histogram has fixed rows.
    assert "open" in data.by_status
    assert "resolved" in data.by_status
    assert all(count == 0 for count in data.by_severity.values())


def test_stored_alerts_keeps_severity_confidence_and_risk_in_three_fields(
    db_session,
) -> None:
    """Three different questions, three different answers (M16.6)."""

    seed_alert(db_session, offset=0.0, severity="critical", confidence=90, risk_score=80)

    data = build_stored_alerts(db_session, make_window())

    assert data.by_severity["critical"] == 1
    assert data.by_confidence_range["75-100"] == 1
    assert data.by_risk_band["high"] == 1
    # ...and the three blocks are not the same dict.
    assert data.by_severity != data.by_confidence_range


def test_stored_alerts_counts_a_never_scored_alert_in_the_minimal_band(
    db_session,
) -> None:
    """M11 leaves ``risk_score`` at 0, which bands ``minimal``, not a verdict."""

    seed_alert(db_session, offset=0.0, risk_score=0, severity="high")

    data = build_stored_alerts(db_session, make_window())

    assert data.by_risk_band["minimal"] == 1
    assert data.by_severity["high"] == 1


def test_stored_alerts_rank_detectors_and_state_the_unrankable_count(
    db_session,
) -> None:
    seed_alert(db_session, offset=0.0, correlation_key="port_scan|x|y")
    seed_alert(db_session, offset=1.0, correlation_key="port_scan|a|b")
    seed_alert(db_session, offset=2.0, correlation_key=None)

    data = build_stored_alerts(db_session, make_window())

    assert [(entry.rule_key, entry.alerts) for entry in data.rules] == [
        ("port_scan", 2)
    ]
    assert data.without_rule_key == 1


def test_stored_alert_series_is_zero_filled_over_the_window(db_session) -> None:
    window = make_window()
    seed_alert(db_session, offset=5.0)
    seed_alert(db_session, offset=15.0)

    data = build_stored_alerts(db_session, window)

    assert len(data.series) == window.buckets
    assert sum(point.alerts for point in data.series) == 2


def test_stored_alert_rule_limit_is_capped_by_the_query_layer(db_session) -> None:
    for index in range(60):
        seed_alert(
            db_session,
            offset=float(index % 60),
            correlation_key=f"rule_{index:03d}|x",
        )

    data = build_stored_alerts(db_session, make_window(), rule_limit=10_000)

    assert len(data.rules) <= 50
    assert DEFAULT_RULE_LIMIT == 20


# --------------------------------------------------------------------------
# retained findings and incident links (M16.6)
# --------------------------------------------------------------------------


def test_findings_summary_is_empty_before_anything_is_evaluated() -> None:
    detections = DetectionEngine([FixedRule()])

    summary = build_findings_summary(detections, make_window())

    assert summary.retained == 0
    assert summary.in_window == 0
    assert summary.mean_confidence is None
    assert summary.by_rule == []
    assert set(summary.by_confidence_range) == set(CONFIDENCE_RANGE_LABELS)


def test_findings_summary_counts_what_is_retained_inside_the_window() -> None:
    detections = DetectionEngine([FixedRule()])
    detections.evaluate(make_context())
    detections.evaluate(make_context())

    summary = build_findings_summary(detections, make_window())

    assert summary.retained == 2
    assert summary.in_window == 2
    assert summary.mean_confidence is not None
    assert sum(summary.by_confidence_range.values()) == 2
    assert [(entry.rule_id, entry.findings) for entry in summary.by_rule] == [
        ("fixed", 2)
    ]
    assert summary.by_rule[0].rule_name == "Fixed Rule"


def test_findings_summary_excludes_what_falls_outside_the_period() -> None:
    detections = DetectionEngine([FixedRule()])
    detections.evaluate(make_context())
    # A finding one whole window later is retained but not in this period.
    detections.evaluate(make_context(timestamp=PACKET_BASE_TIME + 86_400.0))

    summary = build_findings_summary(detections, make_window())

    assert summary.retained == 2
    assert summary.in_window == 1


def test_incident_linkage_counts_distinct_alerts_not_links() -> None:
    """An alert two incidents reference is one alert (M16.6)."""

    engine = make_engine()
    engine.correlate_alerts([make_alert(), make_alert(alert_id=2)])
    incidents = engine.registry.incidents()

    linkage = build_incident_linkage(incidents)

    assert linkage.incidents_total == len(incidents) == 1
    assert linkage.incidents_with_alerts == 1
    assert linkage.alerts_in_incidents == 2


def test_incident_linkage_of_an_empty_registry_is_all_zero() -> None:
    linkage = build_incident_linkage([])

    assert linkage.incidents_total == 0
    assert linkage.incidents_with_alerts == 0
    assert linkage.alerts_in_incidents == 0


# --------------------------------------------------------------------------
# the live halves (M16.1/M16.6)
# --------------------------------------------------------------------------


def test_topped_orders_descending_and_breaks_ties_on_identity() -> None:
    entries = [
        {"key": "b", "value": 5},
        {"key": "a", "value": 5},
        {"key": "c", "value": 9},
    ]

    ordered = topped(
        entries,
        limit=10,
        metric=lambda entry: float(entry["value"]),
        key=lambda entry: entry["key"],
    )

    assert [entry["key"] for entry in ordered] == ["c", "a", "b"]


def test_topped_honours_its_limit() -> None:
    entries = [{"key": str(index), "value": index} for index in range(10)]

    ordered = topped(
        entries,
        limit=3,
        metric=lambda entry: float(entry["value"]),
        key=lambda entry: entry["key"],
    )

    assert [entry["key"] for entry in ordered] == ["9", "8", "7"]


def test_device_status_counts_names_every_state_even_when_empty() -> None:
    counts = device_status_counts([])

    assert set(counts) == {status.value for status in DeviceStatus}
    assert all(count == 0 for count in counts.values())


def test_device_status_counts_classify_the_registry() -> None:
    counts = device_status_counts(
        [
            make_device_view(),
            make_device_view(
                device_id=f"mac:{MAC_B}", status=DeviceStatus.INACTIVE
            ),
        ]
    )

    assert counts["active"] == 1
    assert counts["inactive"] == 1
    assert counts["unknown"] == 0


def test_ranked_devices_read_the_metric_the_caller_asks_for() -> None:
    chatty = make_device_view(device_id=f"mac:{MAC_A}", packet_count=50, byte_count=10)
    bulky = make_device_view(device_id=f"mac:{MAC_B}", packet_count=1, byte_count=900)

    by_packets = ranked_devices([chatty, bulky], limit=10, by="packets")
    by_bytes = ranked_devices([chatty, bulky], limit=10, by="bytes")

    assert [view.device_id for view in by_packets] == [chatty.device_id, bulky.device_id]
    assert [view.device_id for view in by_bytes] == [bulky.device_id, chatty.device_id]


def test_connection_entry_copies_the_tracker_s_own_view() -> None:
    view = _make_connection_view()

    entry = connection_entry(view)

    assert entry.connection_id == view.connection_id
    assert entry.protocol == view.protocol
    assert entry.source_ip == view.source_ip
    assert entry.state == view.state.value
    assert entry.packets == view.packet_count
    assert entry.bytes == view.byte_count


def test_severity_counts_names_every_severity_from_the_summary(
    session_factory,
) -> None:
    summary = AlertQueries(session_factory=session_factory).summary()

    counts = severity_counts(summary)

    assert set(counts) == set(SEVERITY_KEYS)
    assert all(count == 0 for count in counts.values())


def test_open_alert_count_sums_only_the_states_that_need_attention() -> None:
    summary = AlertSummary(
        total=5,
        by_severity={"high": 5},
        by_status={"open": 2, "acknowledged": 1, "resolved": 2},
    )

    assert open_alert_count(summary) == 3


def test_incident_breakdown_of_an_empty_registry_names_every_vocabulary() -> None:
    breakdown = incident_breakdown([])

    assert breakdown.total == 0
    assert breakdown.active == 0
    assert breakdown.highest_risk_score == 0
    assert set(breakdown.by_risk_band) == set(RISK_BAND_KEYS)
    assert all(count == 0 for count in breakdown.by_status.values())


def test_incident_breakdown_describes_one_snapshot_of_the_registry() -> None:
    engine = make_engine()
    engine.correlate_alerts([make_alert(), make_alert(alert_id=2)])

    breakdown = incident_breakdown(engine.registry.incidents())

    assert breakdown.total == 1
    assert sum(breakdown.by_status.values()) == breakdown.total
    assert sum(breakdown.by_risk_band.values()) == breakdown.total
    # The score is M12's own, read rather than recomputed.
    assert breakdown.highest_risk_score == max(
        incident.risk_score for incident in engine.registry.incidents()
    )
