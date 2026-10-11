"""Tests for the report assembler (M17.3).

The assembler is the one place where a report stops being a document and becomes
a set of answers read out of the analytics layer, so the tests here are in two
parts and the split is the point.

**The presentation arithmetic** -- a count, a scaled byte total, a rate, a share,
a breakdown's ordering -- is tested directly on the small functions that perform
it. That arithmetic is the only computation the reporting layer does, and stating
its rules exactly (a share of nothing is ``n/a`` and not ``0.00%``; an absent
value is the documented not-reported text and not an empty cell) is cheaper and
clearer than inferring it from a rendered file.

**The sections** are built from the real M16 collaborators over a seeded database,
using the same seeders the analytics tests use. A report is only worth testing if
the figures in it came from the code the dashboard reads, so nothing here replaces
a service with a double -- except in the availability tests, where a double is the
only way to make a whole view fail and prove the assembler turns that into an
unavailable section rather than a report of zeroes (M16.8).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

import pytest
from sqlalchemy.orm import Session

from app.analytics.service import AnalyticsService
from app.reports.assembler import (
    CONNECTION_COLUMNS,
    DEVICE_COLUMNS,
    HEADLINE_METRICS,
    NO_ROWS_NOTICE,
    REPORT_ROW_LIMIT,
    THREAT_SEVERITIES,
    THREAT_STATUSES,
    UNAVAILABLE_NOTICE,
    _breakdown_rows,
    _bytes,
    _count,
    _rate,
    _share,
    _text,
    analytics_window_for,
    build_report_content,
    default_title,
)
from app.reports.content import NOT_REPORTED, ReportContent, ReportSection, ReportTable
from app.reports.period import ReportPeriod, resolve_daily, resolve_weekly
from app.schemas.packet import PacketType
from tests.analytics_fakes import (
    WINDOW_END,
    WINDOW_START,
    seed_alert,
    seed_connection,
    seed_packet,
)
from tests.correlation_fakes import make_alert
from tests.detection_fakes import make_context
from tests.fakes import PACKET_BASE_TIME, make_normalized_packet
from tests.reports_fakes import GENERATED_AT, make_analytics, make_environment

MAC_A = "AA:BB:CC:DD:EE:FF"
IP_A = "192.168.1.10"

#: The period every data test reports over: the same ten-minute span the M16
#: analytics tests read, so the assembler and the service in front of it are
#: asked about the same instants.
PERIOD = ReportPeriod(
    since=float(WINDOW_START), until=float(WINDOW_END), report_type="custom"
)


# ---------------------------------------------------------------------------
# reading a built report
# ---------------------------------------------------------------------------


def metric_value(section: ReportSection, label: str) -> str:
    """Return one metric's rendered value, failing loudly when it is absent."""
    for metric in section.metrics:
        if metric.label == label:
            return metric.value
    raise AssertionError(f"section {section.key!r} carries no metric {label!r}")


def table(content: ReportContent, section_key: str, table_key: str) -> ReportTable:
    """Return one table by its section and its own key."""
    section = content.section(section_key)
    assert section is not None, f"no section {section_key!r}"
    for candidate in section.tables:
        if candidate.key == table_key:
            return candidate
    raise AssertionError(f"section {section_key!r} carries no table {table_key!r}")


# ---------------------------------------------------------------------------
# the presentation arithmetic (M17.3)
# ---------------------------------------------------------------------------


def test_a_count_is_grouped_for_reading() -> None:
    """A reader compares four- and five-figure totals at a glance."""
    assert _count(0) == "0"
    assert _count(1234) == "1,234"
    assert _count(1_000_000) == "1,000,000"


def test_a_byte_total_is_scaled_but_a_small_one_is_not() -> None:
    """The scaled figure is a convenience; the raw total is always printed beside it."""
    assert _bytes(0) == "0 B"
    assert _bytes(512) == "512 B"
    assert _bytes(1024) == "1.00 KiB"
    assert _bytes(2048) == "2.00 KiB"
    assert _bytes(1024 * 1024 * 3) == "3.00 MiB"


def test_a_rate_carries_its_unit_and_a_fixed_precision() -> None:
    """A rate without its unit is a number a reader cannot use."""
    assert _rate(1.5, "pkt/s") == "1.50 pkt/s"
    assert _rate(0.0, "B/s") == "0.00 B/s"


def test_a_share_is_a_percentage_of_the_dataset_it_came_from() -> None:
    """Shares are taken against the selected period, not a global total."""
    assert _share(50, 100) == "50.00%"
    assert _share(1, 3) == "33.33%"


def test_a_share_of_nothing_is_not_zero_percent() -> None:
    """A share of an empty denominator is undefined, so it says so (M17.3).

    Printing ``0.00%`` would claim the value was measured and found to be nothing,
    which is a different and false statement.
    """
    assert _share(0, 0) == "n/a"
    assert _share(5, 0) == "n/a"


def test_an_absent_value_is_the_not_reported_text_not_an_empty_cell() -> None:
    """A reader can tell 'the backend has no value' from 'the value is empty' (M17.3)."""
    assert _text(None) == NOT_REPORTED
    assert _text("") == NOT_REPORTED
    assert _text("   ") == NOT_REPORTED
    assert _text("  host  ") == "host"


def test_a_measured_zero_stays_a_zero() -> None:
    """The distinction the whole layer turns on: zero is a measurement (M16.8)."""
    assert _text(0) == "0"


def test_a_breakdown_puts_named_keys_first_in_their_given_order() -> None:
    """Two reports of the same type line up for comparison."""
    counts = {"inactive": 0, "active": 3}

    assert _breakdown_rows(counts, order=("active", "inactive", "unknown")) == [
        ("active", "3"),
        ("inactive", "0"),
    ]


def test_a_breakdown_includes_a_key_the_caller_did_not_name() -> None:
    """A vocabulary extension is included rather than silently dropped.

    The alternative -- rendering only the keys a milestone named -- would let a new
    state vanish from every future report without anything failing.
    """
    counts = {"active": 3, "quarantined": 1}

    rows = _breakdown_rows(counts, order=("active", "inactive"))

    assert rows == [("active", "3"), ("quarantined", "1")]


# ---------------------------------------------------------------------------
# the analytics window a report reads over (M17.6)
# ---------------------------------------------------------------------------


def test_the_analytics_window_covers_the_report_period_exactly() -> None:
    """A report selects the same rows an analytics request for it would (M17.3).

    The bounds are passed through unchanged, so the two cannot disagree about
    which instant a figure describes.
    """
    window = analytics_window_for(PERIOD)

    assert window.since == PERIOD.since
    assert window.until == PERIOD.until
    assert window.iso_since() == PERIOD.iso_since()
    assert window.iso_until() == PERIOD.iso_until()


# ---------------------------------------------------------------------------
# the title (M17.6)
# ---------------------------------------------------------------------------


def test_a_derived_title_names_the_period_not_the_moment_of_generation() -> None:
    """Five daily reports generated in one hour must have five different names."""
    daily = resolve_daily(now=PACKET_BASE_TIME + 86_400.0)

    title = default_title(daily, "PDF")

    assert daily.label() in title
    assert title == f"Daily network report {daily.label()} (PDF)"


def test_a_derived_title_carries_the_format_it_was_asked_for() -> None:
    """The name says which file the reader is holding."""
    weekly = resolve_weekly(now=PACKET_BASE_TIME)

    assert default_title(weekly, "csv").endswith("(CSV)")


# ---------------------------------------------------------------------------
# the assembled report, over real seeded data (M17.3/M17.16)
# ---------------------------------------------------------------------------


@pytest.fixture
def seeded(db_session: Session, session_factory: Callable[[], Session]):
    """Return an analytics service over the isolated database and its environment.

    The environment is returned too, because several tests drive a runtime service
    (the device registry, the tracker, the detector) directly -- which is how a
    report's live half is placed under test without going through a capture.
    """
    environment = make_environment(session_factory)
    return make_analytics(db_session, environment), environment


def build(analytics, *, output_format: str = "PDF", title: str | None = None) -> ReportContent:
    """Assemble a report over the test period."""
    return build_report_content(
        analytics=analytics,
        period=PERIOD,
        output_format=output_format,
        generated_at=GENERATED_AT,
        report_id=7,
        title=title,
    )


def test_a_report_carries_the_five_sections_in_reading_order(seeded) -> None:
    """Traffic, protocols, devices, connections, threats -- the M16 subjects."""
    analytics, _ = seeded

    content = build(analytics)

    assert [section.key for section in content.sections] == [
        "traffic",
        "protocols",
        "devices",
        "connections",
        "threats",
    ]


def test_the_identity_is_recorded_on_the_content(seeded) -> None:
    """Which report, which format, over which period (M17.3)."""
    analytics, _ = seeded

    content = build(analytics, output_format="CSV", title="Weekly review")

    assert content.report_id == 7
    assert content.title == "Weekly review"
    assert content.report_type == "custom"
    assert content.output_format == "CSV"
    assert content.period_start == PERIOD.iso_since()
    assert content.period_end == PERIOD.iso_until()
    assert content.period_seconds == PERIOD.seconds


def test_the_summary_leads_with_the_identity(seeded) -> None:
    """A reader who picks up one file must be able to tell which day it covers."""
    analytics, _ = seeded

    summary = {metric.label: metric.value for metric in build(analytics).summary}

    assert summary["Report title"]
    assert summary["Report type"] == "custom"
    assert summary["Output format"] == "PDF"
    assert summary["Period start (inclusive, UTC)"] == PERIOD.iso_since()
    assert summary["Period end (exclusive, UTC)"] == PERIOD.iso_until()


def test_every_headline_metric_resolves_in_the_body_it_summarises(seeded) -> None:
    """The summary is lifted from the sections by name, so it cannot disagree.

    This asserts each named pair exists, so renaming a section's metric without
    updating the summary fails the suite rather than silently dropping a headline
    figure from every future report.
    """
    analytics, _ = seeded

    content = build(analytics)

    for section_key, label in HEADLINE_METRICS:
        section = content.section(section_key)
        assert section is not None, f"headline names a missing section {section_key!r}"
        # Resolving the label is the assertion: the helper raises when it is absent.
        assert isinstance(metric_value(section, label), str)


def test_the_summary_value_is_the_sections_own_value(
    seeded, db_session: Session
) -> None:
    """A summary figure is read from the body, never recomputed."""
    analytics, _ = seeded
    seed_packet(db_session, offset=0.0)
    seed_packet(db_session, offset=1.0)

    content = build(analytics)
    summary = {metric.label: metric.value for metric in content.summary}
    traffic = content.section("traffic")
    assert traffic is not None

    assert summary["Packets stored in period"] == metric_value(
        traffic, "Packets stored in period"
    )
    assert summary["Packets stored in period"] == "2"


def test_a_requested_title_overrides_the_derived_one(seeded) -> None:
    """A caller who names the report gets that name, and the summary repeats it."""
    analytics, _ = seeded

    content = build(analytics, title="Nightly digest")
    summary = {metric.label: metric.value for metric in content.summary}

    assert content.title == "Nightly digest"
    assert summary["Report title"] == "Nightly digest"


# ---------------------------------------------------------------------------
# traffic (M16.2 → M17.3)
# ---------------------------------------------------------------------------


def test_traffic_reports_the_packets_stored_in_the_period(
    seeded, db_session: Session
) -> None:
    """Only rows inside the period are counted; an outside row is not (M17.6)."""
    analytics, _ = seeded
    seed_packet(db_session, offset=0.0, length=100)
    seed_packet(db_session, offset=10.0, length=100)
    seed_packet(db_session, offset=10_000.0, length=100)  # outside the period

    section = build(analytics).section("traffic")
    assert section is not None

    assert metric_value(section, "Packets stored in period") == "2"
    assert metric_value(section, "Bytes stored in period") == "200"


def test_traffic_bounds_its_busiest_sources_table(
    seeded, db_session: Session
) -> None:
    """A report listing is bounded by the analytics group cap (M17.13)."""
    analytics, _ = seeded
    seed_packet(db_session, offset=0.0, source_ip="10.0.0.2", length=900)
    seed_packet(db_session, offset=1.0, source_ip="10.0.0.1", length=10)

    content = build(analytics)
    sources = table(content, "traffic", "top_sources")

    assert sources.columns == ("Source", "Packets", "Bytes")
    assert len(sources.rows) <= REPORT_ROW_LIMIT
    # Ranked by bytes, so the heavier source comes first.
    assert sources.rows[0][0] == "10.0.0.2"


def test_traffic_series_is_bucketed_and_labelled(
    seeded, db_session: Session
) -> None:
    """A time series names its bucket start and carries counts, not raw rows."""
    analytics, _ = seeded
    seed_packet(db_session, offset=0.0)
    seed_packet(db_session, offset=60.0)

    content = build(analytics)
    series = table(content, "traffic", "traffic_series")

    assert series.columns == ("Bucket start (UTC)", "Packets", "Bytes")
    assert len(series.rows) >= 1


# ---------------------------------------------------------------------------
# protocols (M16.3 → M17.3)
# ---------------------------------------------------------------------------


def test_protocols_reports_the_stored_distribution_with_shares(
    seeded, db_session: Session
) -> None:
    """Shares are taken against the period's own packet count (M16.3)."""
    analytics, _ = seeded
    seed_packet(db_session, offset=0.0, packet_type=PacketType.UDP)
    seed_packet(db_session, offset=1.0, packet_type=PacketType.UDP)
    seed_packet(db_session, offset=2.0, packet_type=PacketType.TCP)

    content = build(analytics)
    distribution = table(content, "protocols", "stored_protocols")

    assert distribution.columns == (
        "Protocol",
        "Packets",
        "Bytes",
        "Share of period packets",
    )
    rows = {row[0]: row for row in distribution.rows}
    assert rows["UDP"][3] == "66.67%"
    assert rows["TCP"][3] == "33.33%"


def test_protocols_states_that_it_was_read_even_when_empty(seeded) -> None:
    """An available section holding nothing is not an unavailable one (M16.8)."""
    analytics, _ = seeded

    section = build(analytics).section("protocols")
    assert section is not None

    assert section.available is True
    assert metric_value(section, "Protocols recorded in period") == "0"


# ---------------------------------------------------------------------------
# devices (M16.4 → M17.3)
# ---------------------------------------------------------------------------


def test_devices_reports_the_registry_and_the_period(seeded) -> None:
    """Both the whole registry and what it saw in the period are reported."""
    analytics, environment = seeded
    environment.devices.process_packet(
        make_normalized_packet(
            source_mac=MAC_A,
            source_ip=IP_A,
            destination_ip=None,
            timestamp=PACKET_BASE_TIME,
        )
    )

    section = build(analytics).section("devices")
    assert section is not None

    assert metric_value(section, "Devices known to the registry") == "1"
    assert metric_value(section, "Devices observed in period") == "1"
    assert metric_value(section, "Devices active") == "1"


def test_devices_ranked_table_uses_the_documented_columns(seeded) -> None:
    """The device table's shape is declared once, so CSV and PDF agree (M17.3)."""
    analytics, environment = seeded
    environment.devices.process_packet(
        make_normalized_packet(
            source_mac=MAC_A,
            source_ip=IP_A,
            destination_ip=None,
            timestamp=PACKET_BASE_TIME,
        )
    )

    content = build(analytics)
    devices = table(content, "devices", "top_devices")

    assert devices.columns == DEVICE_COLUMNS
    assert devices.rows[0][0] == f"mac:{MAC_A}"


def test_a_device_with_no_registry_entry_is_still_counted_as_zero(seeded) -> None:
    """An empty registry is a measured zero, not an unavailable section."""
    analytics, _ = seeded

    section = build(analytics).section("devices")
    assert section is not None

    assert metric_value(section, "Devices known to the registry") == "0"
    assert section.available is True


# ---------------------------------------------------------------------------
# connections (M16.5 → M17.3)
# ---------------------------------------------------------------------------


def test_connections_reports_the_tracker_counters(seeded) -> None:
    """The live counters are the tracker's own, so they agree with /connections."""
    analytics, environment = seeded
    environment.tracker.process_packet(make_normalized_packet())

    section = build(analytics).section("connections")
    assert section is not None

    assert metric_value(section, "Conversations tracked now") == "1"
    assert metric_value(section, "Conversations active now") == "1"


def test_connections_reports_the_conversations_recorded_in_the_period(
    seeded, db_session: Session
) -> None:
    """The stored block is the record a report reads historically (M16.5)."""
    analytics, _ = seeded
    seed_connection(db_session, offset=0.0, protocol="TCP", status="completed")
    seed_connection(db_session, offset=10.0, protocol="UDP", status="active")

    content = build(analytics)
    section = content.section("connections")
    assert section is not None

    assert metric_value(section, "Conversations recorded in period") == "2"
    assert metric_value(section, "Conversations active in period") == "1"

    by_protocol = table(content, "connections", "stored_connections_by_protocol")
    assert {row[0]: row[1] for row in by_protocol.rows} == {"TCP": "1", "UDP": "1"}


def test_connections_duration_is_reported_over_the_ended_ones_only(
    seeded, db_session: Session
) -> None:
    """A conversation still running has no duration, so it is excluded, not zeroed."""
    analytics, _ = seeded
    seed_connection(db_session, offset=0.0, end_time=None)

    section = build(analytics).section("connections")
    assert section is not None

    assert metric_value(section, "Ended conversations sampled") == "0"
    assert metric_value(section, "Mean conversation") == NOT_REPORTED


def test_the_conversation_table_shape_is_declared_once(seeded) -> None:
    """The conversation columns are the same names both renderers print (M17.3)."""
    analytics, environment = seeded
    environment.tracker.process_packet(make_normalized_packet())

    content = build(analytics)
    conversations = table(content, "connections", "top_conversations")

    assert conversations.columns == CONNECTION_COLUMNS


# ---------------------------------------------------------------------------
# threats (M16.6 → M17.3)
# ---------------------------------------------------------------------------


def test_threats_reports_the_stored_alerts_in_the_period(
    seeded, db_session: Session
) -> None:
    """The stored block reads the alert table historically (M16.6)."""
    analytics, _ = seeded
    seed_alert(db_session, offset=0.0, severity="critical", risk_score=80)
    seed_alert(db_session, offset=10.0, severity="low", risk_score=10)

    content = build(analytics)
    section = content.section("threats")
    assert section is not None

    assert metric_value(section, "Alerts recorded in period") == "2"

    by_severity = table(content, "threats", "stored_alerts_by_severity")
    counts = {row[0]: row[1] for row in by_severity.rows}
    assert counts["critical"] == "1"
    assert counts["low"] == "1"


def test_threats_keeps_the_three_vocabularies_separate(seeded) -> None:
    """Severity, status, confidence and risk are four different questions (M17.9)."""
    analytics, _ = seeded

    content = build(analytics)

    severity = table(content, "threats", "stored_alerts_by_severity").columns
    status = table(content, "threats", "stored_alerts_by_status").columns
    confidence = table(content, "threats", "stored_alerts_by_confidence").columns
    risk = table(content, "threats", "stored_alerts_by_risk_band").columns

    assert severity == ("Severity", "Alerts")
    assert status == ("Status", "Alerts")
    assert confidence == ("Confidence range", "Alerts")
    assert risk == ("Risk band", "Alerts")


def test_every_threat_vocabulary_is_named_even_when_nothing_was_seen(seeded) -> None:
    """A client renders fixed rows, so a vocabulary is named rather than omitted."""
    analytics, _ = seeded

    content = build(analytics)
    severity = table(content, "threats", "stored_alerts_by_severity")

    assert {row[0] for row in severity.rows} == set(THREAT_SEVERITIES)
    assert table(content, "threats", "stored_alerts_by_status").rows


def test_the_status_breakdown_lists_every_lifecycle_status(seeded) -> None:
    """M11's own status vocabulary, in a fixed order."""
    analytics, _ = seeded

    status = table(build(analytics), "threats", "stored_alerts_by_status")

    assert {row[0] for row in status.rows} == set(THREAT_STATUSES)


def test_threats_reports_the_detector_counters(seeded) -> None:
    """A finding is M10's observation, reported with no verdict attached (M16.6)."""
    analytics, environment = seeded
    environment.detections.evaluate(make_context())

    section = build(analytics).section("threats")
    assert section is not None

    assert metric_value(section, "Findings raised this session") == "1"
    assert metric_value(section, "Findings inside the period") == "1"


def test_threats_reports_the_incident_linkage(seeded) -> None:
    """Alerts and incidents stay linked but are never collapsed into one number."""
    analytics, environment = seeded
    environment.correlations.correlate_alerts([make_alert(), make_alert(alert_id=2)])

    section = build(analytics).section("threats")
    assert section is not None

    assert metric_value(section, "Incidents referencing alerts") == "1"
    assert metric_value(section, "Distinct alerts referenced by incidents") == "2"


# ---------------------------------------------------------------------------
# an empty period (M17.3/M17.7)
# ---------------------------------------------------------------------------


def test_a_period_with_nothing_stored_reports_zeroes_not_failure(seeded) -> None:
    """A period with no rows is a measured nothing, not an unreadable section (M16.8).

    The analytics layer zero-fills the buckets and the vocabularies it owns, so the
    tables exist and carry a measured zero. What matters is that the section is
    available and its count is that zero -- never that the section is absent.
    """
    analytics, _ = seeded
    content = build(analytics)
    traffic = content.section("traffic")
    assert traffic is not None

    assert traffic.available is True
    assert metric_value(traffic, "Packets stored in period") == "0"
    assert table(content, "traffic", "top_sources").is_empty is True


def test_an_empty_ranking_says_why_it_is_empty(seeded) -> None:
    """A table with no rows carries the standard sentence, not a bare header."""
    analytics, _ = seeded

    sources = table(build(analytics), "traffic", "top_sources")

    assert sources.is_empty is True
    assert sources.notice == NO_ROWS_NOTICE


# ---------------------------------------------------------------------------
# a view that could not be read at all (M16.8 → M17.3)
# ---------------------------------------------------------------------------


class ExplodingAnalytics:
    """An analytics service whose every view fails, with no internal detail exposed.

    Used only to exercise the assembler's guard: the failure that matters here is a
    whole view being unreadable, and a real service is not made to fail that way
    without breaking a collaborator the rest of the suite shares.
    """

    def __getattr__(self, name: str) -> Callable[..., object]:
        def _raise(**_kwargs: object) -> object:
            raise RuntimeError("simulated unreadable view")

        return _raise


def unreadable_analytics() -> AnalyticsService:
    """Return the always-failing analytics service, typed for the assembler boundary.

    The cast records the intent precisely: this object is a stand-in that satisfies
    the *shape* the assembler calls, and every call it receives raises. It is not a
    subclass, because the methods it stands in for are the real class's and would
    otherwise be inherited and answer.
    """
    return cast(AnalyticsService, ExplodingAnalytics())


def test_an_unreadable_view_becomes_an_unavailable_section() -> None:
    """A view that cannot be read is declared, never rendered as zeroes (M16.8).

    This is the reports layer's half of the availability contract: an exception
    out of the analytics layer is caught, and the section says it could not be read
    rather than presenting a table of zeroes nobody measured.
    """
    content = build_report_content(
        analytics=unreadable_analytics(),
        period=PERIOD,
        output_format="PDF",
        generated_at=GENERATED_AT,
    )

    for section in content.sections:
        assert section.available is False
        assert section.notice == UNAVAILABLE_NOTICE
        assert section.metrics == ()
        assert section.tables == ()


def test_a_headline_drawn_from_an_unreadable_section_is_not_reported() -> None:
    """The summary does not invent a figure for a section that could not be read."""
    content = build_report_content(
        analytics=unreadable_analytics(),
        period=PERIOD,
        output_format="PDF",
        generated_at=GENERATED_AT,
    )
    summary = {metric.label: metric.value for metric in content.summary}

    for _section_key, label in HEADLINE_METRICS:
        assert summary[label] == NOT_REPORTED


def test_an_unavailable_section_names_no_internal() -> None:
    """The sentence names the situation, not a table, a query or a traceback (M13.30)."""
    content = build_report_content(
        analytics=unreadable_analytics(),
        period=PERIOD,
        output_format="PDF",
        generated_at=GENERATED_AT,
    )

    for section in content.sections:
        message = section.notice or ""
        for internal in ("Traceback", "File \"", "app.", "SELECT", "simulated"):
            assert internal not in message
