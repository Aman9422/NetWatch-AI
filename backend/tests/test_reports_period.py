"""Tests for the reporting period model (M17.4–M17.6).

The period is the one fact a reader must be able to trust about a report — which
day it describes — so the tests pin the *calendar* rather than the arithmetic.
The reference instant is 2026-10-07T12:00:00Z, a Wednesday, and the expected
bounds are written out as literal instants: a daily report is the previous
completed UTC day, and a weekly report is the previous completed Monday-to-Sunday
week.

The half-open convention gets its own tests, because it is the property that
keeps two adjacent reports from both claiming a record observed exactly on their
shared boundary.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from app.analytics.window import MAX_WINDOW_SECONDS
from app.reports.period import (
    CUSTOM,
    DAILY,
    MAX_REPORT_PERIOD_SECONDS,
    REPORT_TYPES,
    SECONDS_PER_DAY,
    SECONDS_PER_WEEK,
    WEEKLY,
    ReportPeriod,
    day_bounds,
    parse_report_date,
    resolve_custom,
    resolve_daily,
    resolve_weekly,
    utc_day_start,
    utc_week_start,
)

#: A Wednesday, midday. Chosen because a Wednesday's *previous completed week* is
#: the whole of the previous Monday-to-Sunday, which is the interesting case: a
#: weekly report generated on a Monday would have almost nothing to describe.
NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc).timestamp()

MONDAY = 2026, 10, 5
TUESDAY = 2026, 10, 6
WEDNESDAY = 2026, 10, 7
PREVIOUS_MONDAY = 2026, 9, 28


def at(*parts: int) -> float:
    """Return epoch seconds for a UTC calendar instant ``(y, m, d[, h, m])``."""
    year, month, day = parts[0], parts[1], parts[2]
    hour = parts[3] if len(parts) > 3 else 0
    minute = parts[4] if len(parts) > 4 else 0
    return datetime(year, month, day, hour, minute, tzinfo=timezone.utc).timestamp()


# ---------------------------------------------------------------------------
# the shared constants
# ---------------------------------------------------------------------------


def test_the_ceiling_is_the_analytics_layers_own() -> None:
    """The reports layer cannot ask a question M16 would refuse (M17.6).

    Reusing the number rather than inventing a second one is what makes a report
    period and an analytics window the same kind of bound: a report that could
    span longer than a window would have no way to be built.
    """
    assert MAX_REPORT_PERIOD_SECONDS == MAX_WINDOW_SECONDS


def test_the_supported_types_are_the_three_documented() -> None:
    """``daily``, ``weekly`` and ``custom``, in that order."""
    assert REPORT_TYPES == (DAILY, WEEKLY, CUSTOM)


# ---------------------------------------------------------------------------
# calendar arithmetic
# ---------------------------------------------------------------------------


def test_utc_day_start_floors_to_the_calendar_day() -> None:
    """A midnight-to-midnight UTC day, not twenty-four hours before an instant."""
    assert utc_day_start(at(*WEDNESDAY, 12, 30)) == at(*WEDNESDAY)
    assert utc_day_start(at(*WEDNESDAY)) == at(*WEDNESDAY)


def test_utc_week_start_floors_to_the_preceding_monday() -> None:
    """A week begins on Monday 00:00 UTC, so Wednesday floors to Monday."""
    assert utc_week_start(at(*WEDNESDAY, 23, 59)) == at(*MONDAY)
    assert utc_week_start(at(*MONDAY)) == at(*MONDAY)


def test_a_week_is_seven_utc_days() -> None:
    """The week length is a definition, not a calculation, so it is asserted."""
    assert SECONDS_PER_WEEK == 7 * SECONDS_PER_DAY


# ---------------------------------------------------------------------------
# daily
# ---------------------------------------------------------------------------


def test_daily_covers_the_previous_completed_utc_day() -> None:
    """A report generated on Wednesday describes Tuesday, whole."""
    period = resolve_daily(now=NOW)

    assert period.report_type == DAILY
    assert period.since == at(*TUESDAY)
    assert period.until == at(*WEDNESDAY)
    assert period.seconds == float(SECONDS_PER_DAY)


def test_daily_bounds_are_rendered_as_iso_utc() -> None:
    """The bounds are the API's convention: ISO-8601 with an explicit offset."""
    period = resolve_daily(now=NOW)

    assert period.iso_since() == "2026-10-06T00:00:00+00:00"
    assert period.iso_until() == "2026-10-07T00:00:00+00:00"


def test_daily_is_named_by_the_day_it_covers() -> None:
    """The label names the calendar day, which is what tells two reports apart."""
    assert resolve_daily(now=NOW).label() == "2026-10-06"


def test_daily_periods_are_half_open_and_adjacent() -> None:
    """Two days meet at an instant and neither claims it (M17.5).

    This is the property the half-open interval exists for: a record observed at
    midnight belongs to exactly one of the two days it could be argued into.
    """
    tuesday = resolve_daily(now=NOW)
    monday = resolve_daily(now=tuesday.since)

    # The two days meet exactly: Monday ends where Tuesday begins, so the record
    # observed at that midnight falls in Tuesday's report and in no other.
    assert monday.until == tuesday.since
    # No overlap and no gap: the union of the two is exactly forty-eight hours.
    assert tuesday.until - monday.since == 2 * SECONDS_PER_DAY


def test_daily_is_the_calendar_day_not_a_rolling_window() -> None:
    """An instant early in the day still floors to the whole day (M17.4).

    A rolling "twenty-four hours before now" would cover part of yesterday and
    part of today, which is not a day and could not be compared with another
    daily report.
    """
    midnight_report = resolve_daily(now=at(*WEDNESDAY, 0, 1))

    assert midnight_report.since == at(*TUESDAY)
    assert midnight_report.until == at(*WEDNESDAY)


# ---------------------------------------------------------------------------
# weekly
# ---------------------------------------------------------------------------


def test_weekly_covers_the_previous_completed_utc_week() -> None:
    """A report generated on Wednesday describes the previous Monday-to-Sunday."""
    period = resolve_weekly(now=NOW)

    assert period.report_type == WEEKLY
    assert period.since == at(*PREVIOUS_MONDAY)
    assert period.until == at(*MONDAY)
    assert period.seconds == float(SECONDS_PER_WEEK)


def test_weekly_label_names_the_last_day_it_covers() -> None:
    """``until`` is exclusive, so the label must not name the following Monday.

    A week labelled "2026-09-28 to 2026-10-05" would name a day the report does
    not describe, which is why the label reads the last *covered* day instead.
    """
    assert resolve_weekly(now=NOW).label() == "2026-09-28 to 2026-10-04"


def test_weekly_periods_are_half_open_and_adjacent() -> None:
    """Consecutive weeks meet at a Monday midnight and neither claims it."""
    this_week_report = resolve_weekly(now=NOW)
    previous = resolve_weekly(now=this_week_report.since)

    assert previous.until == this_week_report.since
    assert this_week_report.since - previous.since == SECONDS_PER_WEEK


def test_weekly_generated_on_a_monday_covers_the_week_just_ended() -> None:
    """Monday is the first instant of a new week, so the last week is complete.

    A report generated at one second past Monday midnight still covers the seven
    days that ended at that midnight, rather than an almost-empty new week.
    """
    period = resolve_weekly(now=at(*MONDAY, 0, 1))

    assert period.since == at(*PREVIOUS_MONDAY)
    assert period.until == at(*MONDAY)


# ---------------------------------------------------------------------------
# custom
# ---------------------------------------------------------------------------


def test_custom_is_taken_as_given() -> None:
    """A caller-supplied range is echoed, not adjusted."""
    period = resolve_custom(since=at(*MONDAY), until=at(*WEDNESDAY))

    assert period.report_type == CUSTOM
    assert period.since == at(*MONDAY)
    assert period.until == at(*WEDNESDAY)


def test_custom_is_named_by_both_of_its_instants() -> None:
    """Neither bound is a round calendar boundary, so both are named (M17.6)."""
    label = resolve_custom(since=at(*MONDAY, 6), until=at(*MONDAY, 9)).label()

    assert label == "2026-10-05T06:00:00+00:00 to 2026-10-05T09:00:00+00:00"


def test_custom_accepts_a_period_exactly_at_the_ceiling() -> None:
    """The ceiling is inclusive, so a thirty-day report is answerable (M17.6)."""
    period = resolve_custom(since=0.0, until=MAX_REPORT_PERIOD_SECONDS)

    assert period.seconds == MAX_REPORT_PERIOD_SECONDS


def test_custom_refuses_a_period_past_the_ceiling() -> None:
    """One second past the ceiling is refused, not clamped."""
    with pytest.raises(ValueError, match="must not exceed"):
        resolve_custom(since=0.0, until=MAX_REPORT_PERIOD_SECONDS + 1.0)


def test_custom_refuses_an_inverted_range() -> None:
    """A start after its end can never match, so it is refused rather than empty."""
    with pytest.raises(ValueError, match="since must not be later"):
        resolve_custom(since=at(*WEDNESDAY), until=at(*MONDAY))


def test_custom_refuses_an_empty_range() -> None:
    """A zero-length period is a different mistake with its own message."""
    with pytest.raises(ValueError, match="must not be empty"):
        resolve_custom(since=at(*MONDAY), until=at(*MONDAY))


# ---------------------------------------------------------------------------
# the period object
# ---------------------------------------------------------------------------


def test_a_period_converts_its_bounds_to_the_naive_utc_a_table_stores() -> None:
    """The conversion the stores filter against drops the offset but keeps UTC."""
    period = resolve_daily(now=NOW)

    assert period.utc_since() == datetime(2026, 10, 6, 0, 0, 0)
    assert period.utc_until() == datetime(2026, 10, 7, 0, 0, 0)
    assert period.utc_since().tzinfo is None


def test_a_period_reports_its_own_length() -> None:
    """``seconds`` is ``until - since``, which every rate in a report divides by."""
    period = ReportPeriod(since=100.0, until=400.0, report_type=CUSTOM)

    assert period.seconds == 300.0


# ---------------------------------------------------------------------------
# date parsing and day bounds
# ---------------------------------------------------------------------------


def test_a_plain_date_parses() -> None:
    """``2026-10-09`` is a date."""
    assert parse_report_date("2026-10-09") == date(2026, 10, 9)


def test_a_full_timestamp_is_accepted_as_its_date() -> None:
    """A timestamp names the same calendar day, so refusing it would be pedantry."""
    assert parse_report_date("2026-10-09T23:59:59+00:00") == date(2026, 10, 9)


def test_a_bad_date_is_refused_and_names_its_field() -> None:
    """A typo must fail loudly rather than silently shifting the day."""
    with pytest.raises(ValueError, match="since"):
        parse_report_date("not-a-date", "since")


def test_a_blank_date_is_refused() -> None:
    """An empty value is a mistake, not the default."""
    with pytest.raises(ValueError, match="must not be empty"):
        parse_report_date("   ")


def test_day_bounds_are_half_open() -> None:
    """One calendar day: midnight inclusive to the next midnight exclusive."""
    start, end = day_bounds(date(2026, 10, 9))

    assert start == at(2026, 10, 9)
    assert end == at(2026, 10, 10)
    assert end - start == SECONDS_PER_DAY
