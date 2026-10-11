"""Resolving a *reporting period* into one bounded, half-open interval (M17.4-M17.6).

Every report is read over an explicit period, and this module is the only place
that decides what one *is*. Four rules, all documented rather than implied:

**Bounds follow M13.26.** A period is ``[since, until)``: ``since`` is inclusive
and ``until`` is exclusive. That is the convention M10's finding query, M11's
alert query, M16's analytics window and M13's HTTP filters already use, so a
report and the analytics view for the same instants select the same records.

**The interval is half-open on purpose.** Consecutive daily reports share a
boundary instant -- one ends at ``T`` and the next begins at ``T`` -- and a
half-open interval is what stops the record observed exactly at ``T`` from being
counted in both. A closed interval would double-count it in two adjacent
reports, which is exactly the failure M17.5 asks to be verified absent.

**A period is always bounded.** The daily and weekly presets derive their bounds
from the UTC calendar, and a caller-supplied period is refused when it is empty,
inverted, or longer than :data:`MAX_REPORT_PERIOD_SECONDS`. There is no path that
reports over "all of history", because such a report would scan the packet table
without limit.

**Daily and weekly mean *the previous completed* UTC day and week.** A daily
report generated on Tuesday covers Monday; a weekly report generated on a
Wednesday covers the Monday-to-Sunday week that ended most recently. This is
stated in the report itself, so a reader never has to infer which day a "daily"
report describes.

The ceiling is M16's own (:data:`~app.analytics.window.MAX_WINDOW_SECONDS`,
thirty days) rather than a second number invented here: M17.6 asks the reports
contract to reuse the analytics policy unless an existing reports contract
requires otherwise, and none does.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from app.analytics.window import (
    MAX_WINDOW_SECONDS,
    iso_from_epoch,
    to_utc_datetime,
)

#: Longest reporting period one report may cover, in seconds. Reused from M16 so
#: the reports layer cannot ask a question the analytics layer would refuse.
MAX_REPORT_PERIOD_SECONDS = MAX_WINDOW_SECONDS

#: Seconds in one UTC calendar day.
SECONDS_PER_DAY = 86_400

#: Seconds in one UTC calendar week. Monday is day 0 (``datetime.weekday``), so a
#: week is seven days and its first day is Monday.
SECONDS_PER_WEEK = 7 * SECONDS_PER_DAY

#: A report covering the previous completed UTC calendar day.
DAILY = "daily"

#: A report covering the previous completed UTC calendar week.
WEEKLY = "weekly"

#: A report covering a caller-supplied period.
CUSTOM = "custom"

#: Every supported kind, in the order a help string should list them.
REPORT_TYPES: tuple[str, ...] = (DAILY, WEEKLY, CUSTOM)


@dataclass(frozen=True)
class ReportPeriod:
    """A resolved, bounded, half-open reporting period (M17.4).

    Attributes:
        since: Inclusive lower bound, epoch seconds.
        until: Exclusive upper bound, epoch seconds.
        report_type: ``daily``, ``weekly`` or ``custom`` -- recorded on the
            report so a stored row says which preset produced it.
    """

    since: float
    until: float
    report_type: str

    @property
    def seconds(self) -> float:
        """Return the period length in seconds."""
        return self.until - self.since

    def iso_since(self) -> str:
        """Return the inclusive bound as an ISO-8601 UTC string."""
        return iso_from_epoch(self.since)

    def iso_until(self) -> str:
        """Return the exclusive bound as an ISO-8601 UTC string."""
        return iso_from_epoch(self.until)

    def utc_since(self) -> datetime:
        """Return the inclusive bound as the naive UTC datetime a table stores."""
        return to_utc_datetime(self.since)

    def utc_until(self) -> datetime:
        """Return the exclusive bound as the naive UTC datetime a table stores."""
        return to_utc_datetime(self.until)

    def label(self) -> str:
        """Return a short human label for the period, used in the report name.

        A daily report is named by its calendar day and a weekly one by its date
        range, because those are the two facts a reader needs to tell two reports
        apart. A custom period is named by both of its instants, since neither is
        a round calendar boundary.
        """
        if self.report_type == DAILY:
            return iso_from_epoch(self.since)[:10]
        if self.report_type == WEEKLY:
            return f"{iso_from_epoch(self.since)[:10]} to {_inclusive_end_date(self)}"
        return f"{self.iso_since()} to {self.iso_until()}"


def _inclusive_end_date(period: ReportPeriod) -> str:
    """Return the last calendar day the period touches, as a date string.

    ``until`` is exclusive, so the last day a report *covers* is the day holding
    the instant one second before it. Naming that day rather than the exclusive
    bound is what makes a weekly label read "2026-09-28 to 2026-10-04" instead of
    ending on a Monday nobody considers part of the week.
    """
    return iso_from_epoch(period.until - 1)[:10]


def utc_day_start(epoch_seconds: float) -> int:
    """Return the epoch second the UTC calendar day containing an instant begins.

    Flooring to a whole day in UTC is what makes a daily period a *calendar* day
    rather than "twenty-four hours before the request". The conversion goes
    through ``datetime`` rather than integer division so a DST rule or a change
    of the UTC offset in some future tz database cannot make the arithmetic
    disagree with the calendar.
    """
    moment = datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc)
    start = datetime(moment.year, moment.month, moment.day, tzinfo=timezone.utc)
    return int(start.timestamp())


def utc_week_start(epoch_seconds: float) -> int:
    """Return the epoch second of the Monday 00:00 UTC that starts an instant's week."""
    day_start = utc_day_start(epoch_seconds)
    moment = datetime.fromtimestamp(day_start, tz=timezone.utc)
    return day_start - moment.weekday() * SECONDS_PER_DAY


def resolve_daily(*, now: float) -> ReportPeriod:
    """Return the previous completed UTC calendar day (M17.4).

    Args:
        now: The instant the report is being requested at. Passed in rather than
            read from the clock so a test, and the report's own log line, can pin
            it.

    Returns:
        ``[previous day 00:00 UTC, today 00:00 UTC)``. Half-open, so the record
        observed exactly at today's midnight belongs to *today's* report and not
        to this one.
    """
    today_start = utc_day_start(now)
    return ReportPeriod(
        since=float(today_start - SECONDS_PER_DAY),
        until=float(today_start),
        report_type=DAILY,
    )


def resolve_weekly(*, now: float) -> ReportPeriod:
    """Return the previous completed UTC calendar week (M17.5).

    A week begins on Monday 00:00 UTC and ends at the following Monday 00:00 UTC,
    which is the ISO-8601 week and the same rule :func:`utc_week_start` applies.

    Args:
        now: The instant the report is being requested at.

    Returns:
        ``[previous Monday 00:00 UTC, this Monday 00:00 UTC)``. The interval is
        half-open for the same reason the daily one is: adjacent weekly reports
        meet at an instant and neither may claim the record observed exactly
        there.
    """
    this_monday = utc_week_start(now)
    return ReportPeriod(
        since=float(this_monday - SECONDS_PER_WEEK),
        until=float(this_monday),
        report_type=WEEKLY,
    )


def resolve_custom(*, since: float, until: float) -> ReportPeriod:
    """Return a caller-supplied reporting period, validated (M17.6).

    Args:
        since: Inclusive lower bound, epoch seconds.
        until: Exclusive upper bound, epoch seconds.

    Returns:
        The period as given.

    Raises:
        ValueError: If the range is inverted, empty, or longer than
            :data:`MAX_REPORT_PERIOD_SECONDS`. Each of those is a request that
            cannot be honoured, so it is refused with the reason rather than
            adjusted into a report of a different question -- and, crucially,
            rather than being allowed to produce a misleading report.
    """
    lower = float(since)
    upper = float(until)
    if lower > upper:
        raise ValueError("since must not be later than until")
    if lower == upper:
        raise ValueError("the reporting period must not be empty")
    span = upper - lower
    if span > MAX_REPORT_PERIOD_SECONDS:
        raise ValueError(
            "the reporting period must not exceed "
            f"{int(MAX_REPORT_PERIOD_SECONDS)} seconds"
        )
    return ReportPeriod(since=lower, until=upper, report_type=CUSTOM)


def parse_report_date(value: str, field: str = "since") -> date:
    """Parse an ISO-8601 date, refusing anything that is not one.

    A full timestamp is accepted and truncated to its date, because ``2026-10-09``
    and ``2026-10-09T00:00:00+00:00`` name the same calendar day, and refusing the
    second would be pedantry rather than validation.

    Raises:
        ValueError: If the value is blank or is not an ISO-8601 date or
            timestamp. A typo must fail loudly rather than silently shifting the
            period to another day.
    """
    text = str(value).strip()
    if not text:
        raise ValueError(f"{field} must not be empty")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(
                f"'{value}' is not a valid ISO-8601 date for {field}"
            ) from exc


def day_bounds(day: date) -> tuple[float, float]:
    """Return the half-open UTC bounds of one calendar day.

    Returns:
        ``(start, end)``: midnight UTC of ``day`` inclusive, and midnight UTC of
        the following day exclusive.
    """
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    return (
        float(start.timestamp()),
        float((start + timedelta(days=1)).timestamp()),
    )


__all__ = [
    "CUSTOM",
    "DAILY",
    "MAX_REPORT_PERIOD_SECONDS",
    "REPORT_TYPES",
    "SECONDS_PER_DAY",
    "SECONDS_PER_WEEK",
    "WEEKLY",
    "ReportPeriod",
    "day_bounds",
    "parse_report_date",
    "resolve_custom",
    "resolve_daily",
    "resolve_weekly",
    "utc_day_start",
    "utc_week_start",
]
