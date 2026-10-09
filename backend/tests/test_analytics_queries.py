"""Tests for the M16 aggregate queries over the persisted tables (M16.2/M16.3/M16.5/M16.6).

Each query class is exercised against a real in-memory SQLite database holding
known rows, because what is under test is the SQL: which rows the window selects,
what SQLite groups them into, and what it reports for an empty selection. Faking a
session here would test the fake rather than the aggregation.

Three properties are checked repeatedly, because they are the ones a reviewer
cannot confirm by reading a ``GROUP BY``:

* the window bounds are ``[since, until)`` — a row exactly on ``until`` is *out*;
* a value that genuinely does not exist is ``None``, never ``0``;
* every statement's row count is capped, whatever the table holds.
"""

from __future__ import annotations

from app.alerts.dedup import KEY_SEPARATOR
from app.analytics.alert_queries import AlertAnalytics
from app.analytics.connection_queries import ConnectionAnalytics
from app.analytics.metrics import MAX_GROUPS
from app.analytics.packet_queries import MAX_PROTOCOLS, PacketAnalytics
from app.analytics.window import bucket_start
from app.schemas.packet import PacketType
from tests.analytics_fakes import (
    WINDOW_BUCKET_SECONDS,
    WINDOW_END,
    WINDOW_START,
    make_window,
    seed_alert,
    seed_connection,
    seed_packet,
    utc,
)
from tests.fakes import PACKET_BASE_TIME


def _naive(epoch: float):
    """Return the naive UTC datetime a stored column holds for ``epoch``."""
    return utc(epoch)


def _key(rule_id: str, discriminator: str) -> str:
    """Build a deduplication key the way M11 does (M11.9)."""
    return f"{rule_id}{KEY_SEPARATOR}{discriminator}"


# --------------------------------------------------------------------------
# traffic and protocol aggregates (M16.2/M16.3)
# --------------------------------------------------------------------------


def test_empty_window_reports_zero_counts_and_no_instants(db_session) -> None:
    window = make_window()
    totals = PacketAnalytics(db_session).totals(window)

    assert totals.packets == 0
    assert totals.bytes == 0
    assert totals.first_epoch is None
    assert totals.last_epoch is None
    assert totals.packets_without_source_port == 0
    assert totals.packets_without_destination_port == 0


def test_stored_count_is_unwindowed_and_counts_every_row(db_session) -> None:
    seed_packet(db_session, offset=0.0)
    seed_packet(db_session, offset=30.0)
    # Outside the window the test uses, but still stored.
    seed_packet(db_session, offset=10 * 86_400.0)

    analytics = PacketAnalytics(db_session)

    assert analytics.stored_count() == 3
    assert analytics.totals(make_window()).packets == 2


def test_totals_sum_the_window_and_report_its_instants(db_session) -> None:
    seed_packet(db_session, offset=10.0, length=100)
    seed_packet(db_session, offset=20.0, length=250)
    seed_packet(db_session, offset=30.0, length=50)

    totals = PacketAnalytics(db_session).totals(make_window())

    assert totals.packets == 3
    assert totals.bytes == 400
    assert totals.first_epoch == PACKET_BASE_TIME + 10.0
    assert totals.last_epoch == PACKET_BASE_TIME + 30.0


def test_window_is_inclusive_of_since_and_exclusive_of_until(db_session) -> None:
    seed_packet(db_session, offset=0.0)  # exactly `since` — in
    seed_packet(db_session, offset=WINDOW_END - WINDOW_START)  # exactly `until` — out
    seed_packet(db_session, offset=30.0)  # inside

    totals = PacketAnalytics(db_session).totals(make_window())

    assert totals.packets == 2


def test_a_row_before_the_window_is_excluded(db_session) -> None:
    seed_packet(db_session, offset=-1.0)

    assert PacketAnalytics(db_session).totals(make_window()).packets == 0


def test_portless_packets_are_counted_separately_per_side(db_session) -> None:
    seed_packet(db_session, source_port=None, destination_port=None)
    seed_packet(db_session, source_port=None)

    totals = PacketAnalytics(db_session).totals(make_window())

    assert totals.packets == 2
    assert totals.packets_without_source_port == 2
    assert totals.packets_without_destination_port == 1


def test_series_buckets_rows_and_agrees_with_the_python_bucket_rule(
    db_session,
) -> None:
    """The SQL bucketing and ``bucket_start`` must name the same bucket.

    They are the same rule written twice — once in Python to decide which buckets
    a response lists, once in SQLite to decide which rows fall in them — so this
    is the test that keeps them from drifting apart (M16.7).
    """

    window = make_window()
    seed_packet(db_session, offset=120.0, length=100)
    seed_packet(db_session, offset=150.0, length=200)
    seed_packet(db_session, offset=400.0, length=50)

    rows = PacketAnalytics(db_session).series(window)

    assert [row.bucket_start for row in rows] == sorted(
        row.bucket_start for row in rows
    )
    for row, offset in zip(rows, (120.0, 400.0)):
        assert row.bucket_start == bucket_start(PACKET_BASE_TIME + offset, 60)
    assert rows[0].packets == 2
    assert rows[0].bytes == 300
    assert rows[1].packets == 1
    assert rows[1].bytes == 50


def test_series_omits_buckets_the_store_has_nothing_for(db_session) -> None:
    seed_packet(db_session, offset=0.0)
    seed_packet(db_session, offset=300.0)

    rows = PacketAnalytics(db_session).series(make_window())

    assert len(rows) == 2


def test_series_cannot_return_more_points_than_the_ceiling(db_session) -> None:
    window = make_window()
    for index in range(40):
        seed_packet(db_session, offset=float(index * 10))

    rows = PacketAnalytics(db_session).series(window)

    assert len(rows) <= 240
    assert all(row.bucket_start % window.bucket_seconds == 0 for row in rows)


def test_protocols_group_by_classification(db_session) -> None:
    seed_packet(db_session, packet_type=PacketType.TCP, length=100)
    seed_packet(db_session, packet_type=PacketType.TCP, length=100)
    seed_packet(db_session, packet_type=PacketType.UDP, length=300)

    rows = PacketAnalytics(db_session).protocols(make_window())

    assert [(row.protocol, row.packets, row.bytes) for row in rows] == [
        ("TCP", 2, 200),
        ("UDP", 1, 300),
    ]


def test_protocols_breakdown_is_capped_but_the_distinct_count_is_exact(
    db_session,
) -> None:
    # More distinct classifications than the breakdown may return. The protocol
    # column is wide enough for these labels.
    for index in range(MAX_PROTOCOLS + 5):
        seed_packet(db_session, protocol=f"P{index:03d}", packet_type=PacketType.OTHER)

    analytics = PacketAnalytics(db_session)

    assert len(analytics.protocols(make_window())) == MAX_PROTOCOLS + 1
    assert analytics.distinct_protocols(make_window()) == MAX_PROTOCOLS + 5


def test_protocols_reports_an_empty_list_and_zero_distinct_when_nothing_stored(
    db_session,
) -> None:
    analytics = PacketAnalytics(db_session)

    assert analytics.protocols(make_window()) == []
    assert analytics.distinct_protocols(make_window()) == 0


def test_top_sources_rank_by_packets_by_default(db_session) -> None:
    seed_packet(db_session, source_ip="10.0.0.1", length=100)
    seed_packet(db_session, source_ip="10.0.0.1", length=100)
    seed_packet(db_session, source_ip="10.0.0.2", length=900)

    rows = PacketAnalytics(db_session).top_sources(
        make_window(), limit=10, by="packets"
    )

    assert [row.key for row in rows] == ["10.0.0.1", "10.0.0.2"]
    assert rows[0].packets == 2


def test_top_sources_rank_by_bytes_when_asked(db_session) -> None:
    seed_packet(db_session, source_ip="10.0.0.1", length=100)
    seed_packet(db_session, source_ip="10.0.0.1", length=100)
    seed_packet(db_session, source_ip="10.0.0.2", length=900)

    rows = PacketAnalytics(db_session).top_sources(
        make_window(), limit=10, by="bytes"
    )

    assert [row.key for row in rows] == ["10.0.0.2", "10.0.0.1"]


def test_equal_traffic_breaks_the_tie_on_the_key(db_session) -> None:
    seed_packet(db_session, source_ip="10.0.0.9")
    seed_packet(db_session, source_ip="10.0.0.3")

    rows = PacketAnalytics(db_session).top_sources(
        make_window(), limit=10, by="packets"
    )

    assert [row.key for row in rows] == ["10.0.0.3", "10.0.0.9"]


def test_rankings_are_capped_at_the_group_ceiling(db_session) -> None:
    for index in range(MAX_GROUPS + 20):
        seed_packet(db_session, source_ip=f"10.0.{index // 256}.{index % 256}")

    rows = PacketAnalytics(db_session).top_sources(
        make_window(), limit=10_000, by="packets"
    )

    assert len(rows) == MAX_GROUPS


def test_a_ranking_honours_a_smaller_limit(db_session) -> None:
    for index in range(5):
        seed_packet(db_session, source_ip=f"10.0.0.{index}")

    rows = PacketAnalytics(db_session).top_sources(
        make_window(), limit=2, by="packets"
    )

    assert len(rows) == 2


def test_destination_port_ranking_omits_packets_that_carry_no_port(db_session) -> None:
    seed_packet(db_session, destination_port=443)
    seed_packet(db_session, destination_port=443)
    seed_packet(db_session, source_port=None, destination_port=None)

    rows = PacketAnalytics(db_session).top_destination_ports(
        make_window(), limit=10, by="packets"
    )

    assert [(row.key, row.packets) for row in rows] == [("443", 2)]
    # ...and the omission is stated by the window totals.
    assert PacketAnalytics(db_session).totals(make_window()).packets_without_destination_port == 1


def test_top_destinations_group_by_destination(db_session) -> None:
    seed_packet(db_session, destination_ip="8.8.8.8")
    seed_packet(db_session, destination_ip="8.8.8.8")
    seed_packet(db_session, destination_ip="1.1.1.1")

    rows = PacketAnalytics(db_session).top_destinations(
        make_window(), limit=10, by="packets"
    )

    assert [row.key for row in rows] == ["8.8.8.8", "1.1.1.1"]


# --------------------------------------------------------------------------
# conversation aggregates (M16.5)
# --------------------------------------------------------------------------


def test_no_connections_reports_zeroes_and_no_instants(db_session) -> None:
    totals = ConnectionAnalytics(db_session).totals(make_window())

    assert totals.connections == 0
    assert totals.active == 0
    assert totals.first_epoch is None
    assert totals.last_epoch is None


def test_connection_totals_count_the_window_and_its_active_share(db_session) -> None:
    seed_connection(db_session, offset=0.0, status="active")
    seed_connection(db_session, offset=60.0, status="completed")
    seed_connection(db_session, offset=120.0, status="active")

    totals = ConnectionAnalytics(db_session).totals(make_window())

    assert totals.connections == 3
    assert totals.active == 2
    assert totals.first_epoch == PACKET_BASE_TIME
    assert totals.last_epoch == PACKET_BASE_TIME + 120.0


def test_connection_window_selects_on_start_time_and_excludes_until(db_session) -> None:
    seed_connection(db_session, offset=0.0)
    seed_connection(db_session, offset=WINDOW_END - WINDOW_START)  # exactly `until`
    seed_connection(db_session, offset=-30.0)

    assert ConnectionAnalytics(db_session).totals(make_window()).connections == 1


def test_status_and_protocol_breakdowns_group_the_window(db_session) -> None:
    seed_connection(db_session, offset=0.0, protocol="TCP", status="active")
    seed_connection(db_session, offset=10.0, protocol="TCP", status="completed")
    seed_connection(db_session, offset=20.0, protocol="UDP", status="timeout")

    analytics = ConnectionAnalytics(db_session)

    assert analytics.count_by_protocol(make_window()) == {"TCP": 2, "UDP": 1}
    assert analytics.count_by_status(make_window()) == {
        "active": 1,
        "completed": 1,
        "timeout": 1,
    }


def test_empty_breakdowns_are_empty_mappings_not_zero_filled(db_session) -> None:
    analytics = ConnectionAnalytics(db_session)

    assert analytics.count_by_protocol(make_window()) == {}
    assert analytics.count_by_status(make_window()) == {}


def test_connection_series_buckets_by_start_time(db_session) -> None:
    window = make_window()
    seed_connection(db_session, offset=5.0)
    seed_connection(db_session, offset=15.0)
    seed_connection(db_session, offset=125.0)

    rows = ConnectionAnalytics(db_session).series(window)

    assert len(rows) == 2
    assert rows[0].bucket_start == bucket_start(PACKET_BASE_TIME + 5.0, WINDOW_BUCKET_SECONDS)
    assert rows[0].connections == 2
    assert rows[1].connections == 1


def test_duration_statistics_cover_only_conversations_that_ended(db_session) -> None:
    start = PACKET_BASE_TIME
    seed_connection(
        db_session,
        offset=10.0,
        start_time=_naive(start + 10),
        end_time=_naive(start + 40),
    )
    seed_connection(
        db_session,
        offset=20.0,
        start_time=_naive(start + 20),
        end_time=_naive(start + 80),
    )
    # Still running: excluded from the statistics, not counted as a zero.
    seed_connection(
        db_session,
        offset=30.0,
        start_time=_naive(start + 30),
        end_time=None,
    )

    stats = ConnectionAnalytics(db_session).duration_stats(make_window())

    assert stats.samples == 2
    assert stats.min_seconds == 30.0
    assert stats.max_seconds == 60.0
    assert stats.mean_seconds == 45.0


def test_duration_statistics_are_absent_when_no_conversation_ended(db_session) -> None:
    seed_connection(db_session, offset=0.0, end_time=None)

    stats = ConnectionAnalytics(db_session).duration_stats(make_window())

    assert stats.samples == 0
    assert stats.min_seconds is None
    assert stats.mean_seconds is None
    assert stats.max_seconds is None


def test_connection_endpoint_rankings_sum_both_directions(db_session) -> None:
    seed_connection(
        db_session,
        offset=0.0,
        source_ip="10.0.0.1",
        packets_sent=5,
        packets_received=5,
        bytes_sent=500,
        bytes_received=500,
    )
    seed_connection(
        db_session,
        offset=10.0,
        source_ip="10.0.0.2",
        packets_sent=1,
        packets_received=1,
        bytes_sent=10,
        bytes_received=10,
    )

    by_packets = ConnectionAnalytics(db_session).top_sources(
        make_window(), limit=10, by="packets"
    )
    by_bytes = ConnectionAnalytics(db_session).top_sources(
        make_window(), limit=10, by="bytes"
    )

    assert [(row.key, row.packets, row.bytes) for row in by_packets] == [
        ("10.0.0.1", 10, 1000),
        ("10.0.0.2", 2, 20),
    ]
    assert [row.key for row in by_bytes] == ["10.0.0.1", "10.0.0.2"]


def test_connection_rankings_are_capped_and_tied_on_the_address(db_session) -> None:
    seed_connection(db_session, offset=0.0, destination_ip="8.8.8.8")
    seed_connection(db_session, offset=1.0, destination_ip="1.1.1.1")

    rows = ConnectionAnalytics(db_session).top_destinations(
        make_window(), limit=1, by="packets"
    )

    assert len(rows) == 1
    assert rows[0].key == "1.1.1.1"


# --------------------------------------------------------------------------
# stored-alert aggregates (M16.6)
# --------------------------------------------------------------------------


def test_no_alerts_reports_zeroes_and_no_instants(db_session) -> None:
    totals = AlertAnalytics(db_session).totals(make_window())

    assert totals.alerts == 0
    assert totals.without_rule_key == 0
    assert totals.first_epoch is None
    assert totals.last_epoch is None


def test_alert_totals_count_the_window_and_the_keyless_ones(db_session) -> None:
    seed_alert(db_session, offset=0.0)
    seed_alert(db_session, offset=60.0, correlation_key=None)

    totals = AlertAnalytics(db_session).totals(make_window())

    assert totals.alerts == 2
    assert totals.without_rule_key == 1
    assert totals.first_epoch == PACKET_BASE_TIME
    assert totals.last_epoch == PACKET_BASE_TIME + 60.0


def test_alert_window_filters_on_created_at_not_insert_time(db_session) -> None:
    seed_alert(db_session, offset=0.0)
    seed_alert(db_session, offset=WINDOW_END - WINDOW_START)  # exactly `until`
    seed_alert(db_session, offset=-1.0)

    assert AlertAnalytics(db_session).totals(make_window()).alerts == 1


def test_severity_and_status_breakdowns_group_the_window(db_session) -> None:
    seed_alert(db_session, offset=0.0, severity="high", status="open")
    seed_alert(db_session, offset=1.0, severity="high", status="resolved")
    seed_alert(db_session, offset=2.0, severity="low", status="open")

    analytics = AlertAnalytics(db_session)

    assert analytics.count_by_severity(make_window()) == {"high": 2, "low": 1}
    assert analytics.count_by_status(make_window()) == {"open": 2, "resolved": 1}


def test_risk_bands_read_the_score_m12_wrote(db_session) -> None:
    for score, band in ((10, "minimal"), (30, "low"), (60, "moderate"), (95, "high")):
        seed_alert(db_session, offset=float(score), risk_score=score)

    counted = AlertAnalytics(db_session).count_by_risk_band(make_window())

    assert counted == {"minimal": 1, "low": 1, "moderate": 1, "high": 1}


def test_confidence_ranges_use_the_documented_tiling_without_risk_names(db_session) -> None:
    for confidence in (5, 30, 60, 90):
        seed_alert(db_session, offset=float(confidence), confidence=confidence)

    counted = AlertAnalytics(db_session).count_by_confidence_range(make_window())

    assert counted == {"0-24": 1, "25-49": 1, "50-74": 1, "75-100": 1}


def test_rule_ranking_uses_the_leading_key_component(db_session) -> None:
    seed_alert(db_session, offset=0.0, correlation_key=_key("port_scan", "1"))
    seed_alert(db_session, offset=1.0, correlation_key=_key("port_scan", "2"))
    seed_alert(db_session, offset=2.0, correlation_key=_key("syn_flood", "3"))

    rows = AlertAnalytics(db_session).top_rules(make_window(), limit=10)

    assert [(row.rule_key, row.alerts) for row in rows] == [
        ("port_scan", 2),
        ("syn_flood", 1),
    ]


def test_rule_ranking_handles_a_key_with_no_separator(db_session) -> None:
    seed_alert(db_session, offset=0.0, correlation_key="bare_rule")

    rows = AlertAnalytics(db_session).top_rules(make_window(), limit=10)

    assert [(row.rule_key, row.alerts) for row in rows] == [("bare_rule", 1)]


def test_rule_ranking_omits_keyless_alerts_but_names_them_elsewhere(db_session) -> None:
    seed_alert(db_session, offset=0.0, correlation_key=None)

    analytics = AlertAnalytics(db_session)

    assert analytics.top_rules(make_window(), limit=10) == []
    assert analytics.totals(make_window()).without_rule_key == 1


def test_rule_ranking_is_capped(db_session) -> None:
    for index in range(60):
        seed_alert(
            db_session,
            offset=float(index % 60),
            correlation_key=_key(f"rule_{index:03d}", "x"),
        )

    rows = AlertAnalytics(db_session).top_rules(make_window(), limit=10_000)

    assert len(rows) == 50


def test_alert_series_buckets_by_created_at(db_session) -> None:
    window = make_window()
    seed_alert(db_session, offset=5.0)
    seed_alert(db_session, offset=15.0)
    seed_alert(db_session, offset=130.0)

    rows = AlertAnalytics(db_session).series(window)

    assert len(rows) == 2
    assert rows[0].bucket_start == bucket_start(PACKET_BASE_TIME + 5.0, WINDOW_BUCKET_SECONDS)
    assert rows[0].alerts == 2
    assert rows[1].alerts == 1


def test_empty_alert_series_is_an_empty_list(db_session) -> None:
    assert AlertAnalytics(db_session).series(make_window()) == []
