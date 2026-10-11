"""Tests for report request validation (M17.4).

A report request is the boundary between a loose HTTP body and a pipeline that
assumes its inputs are already answerable. These tests hold that boundary to two
properties:

* **Defaults are the layer's own, and they are stated.** No body at all means the
  previous completed UTC day as a PDF — the documented reading of "generate a
  report" — and a test asserts each default rather than leaving it implicit.
* **A value that cannot be honoured is refused, never adjusted.** An unknown
  format, an unknown preset, an unparsable instant, a preset given bounds and a
  custom period given only one of them are five different mistakes, and each is
  reported with the field that made it.

The last group compares this module's instant parsing with
:mod:`app.api.common.validation`, because the two are deliberately separate
restatements of the same rule (the reports layer must not depend on the API
layer) and two restatements that disagreed would place a report in a different
window than the dashboard it summarises.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.api.common.validation import parse_epoch_filter
from app.reports.errors import ReportRequestError
from app.reports.period import CUSTOM, DAILY, WEEKLY, resolve_daily, resolve_weekly
from app.reports.requests import (
    DEFAULT_FORMAT,
    DEFAULT_REPORT_TYPE,
    SUPPORTED_FORMATS,
    build_request,
    normalize_format,
    normalize_report_type,
    parse_instant,
    resolve_period,
)

#: A literal instant, used wherever a test needs one. The value is arbitrary; what
#: matters is that it is unambiguous and carries an explicit offset.
INSTANT = "2026-10-06T13:45:30+00:00"
INSTANT_EPOCH = datetime(2026, 10, 6, 13, 45, 30, tzinfo=timezone.utc).timestamp()
LATER = "2026-10-06T14:45:30+00:00"


# ---------------------------------------------------------------------------
# format
# ---------------------------------------------------------------------------


def test_both_formats_are_supported() -> None:
    """The layer produces exactly CSV and PDF (M17.7/M17.8)."""
    assert SUPPORTED_FORMATS == ("CSV", "PDF")


def test_the_default_format_is_a_pdf() -> None:
    """A report's default reader is a person, so the default is the readable one."""
    assert DEFAULT_FORMAT == "PDF"
    assert normalize_format(None) == "PDF"


def test_format_case_is_folded() -> None:
    """``pdf`` and ``PDF`` are the same format to every person."""
    assert normalize_format("pdf") == "PDF"
    assert normalize_format("  csv  ") == "CSV"


def test_an_unsupported_format_is_refused() -> None:
    """Asking for a format the layer cannot produce is refused, not defaulted."""
    with pytest.raises(ReportRequestError, match="not a supported format") as caught:
        normalize_format("DOCX")

    assert caught.value.field == "format"


def test_a_blank_format_is_refused() -> None:
    """A present-but-empty value is a typo, not "no preference"."""
    with pytest.raises(ReportRequestError, match="must not be empty"):
        normalize_format("   ")


# ---------------------------------------------------------------------------
# report type
# ---------------------------------------------------------------------------


def test_the_default_type_is_daily() -> None:
    """The shortest period is the safest thing to answer by accident (M17.4)."""
    assert DEFAULT_REPORT_TYPE == DAILY
    assert normalize_report_type(None) == DAILY


def test_report_type_case_is_folded() -> None:
    """``WEEKLY`` and ``weekly`` are the same preset."""
    assert normalize_report_type("WEEKLY") == WEEKLY
    assert normalize_report_type("Custom") == CUSTOM


def test_an_unsupported_type_is_refused() -> None:
    """A preset the layer does not implement is not silently treated as daily."""
    with pytest.raises(ReportRequestError, match="not a supported report type") as err:
        normalize_report_type("hourly")

    assert err.value.field == "report_type"


def test_a_blank_type_is_refused() -> None:
    """A blank preset is refused rather than defaulted."""
    with pytest.raises(ReportRequestError, match="must not be empty"):
        normalize_report_type("  ")


# ---------------------------------------------------------------------------
# instants
# ---------------------------------------------------------------------------


def test_an_absent_instant_is_absent() -> None:
    """Not sent is not the same as sent empty."""
    assert parse_instant(None, "since") is None


def test_an_offset_instant_parses() -> None:
    """An explicit offset is converted to the same instant in UTC."""
    assert parse_instant(INSTANT, "since") == INSTANT_EPOCH


def test_a_zulu_instant_parses() -> None:
    """``Z`` is accepted as the UTC designator, which ISO-8601 permits."""
    assert parse_instant("2026-10-06T13:45:30Z", "since") == INSTANT_EPOCH


def test_a_non_utc_offset_is_converted_not_truncated() -> None:
    """A ``+05:30`` value names the same instant, not the same wall clock."""
    with_offset = parse_instant("2026-10-06T19:15:30+05:30", "since")

    assert with_offset == INSTANT_EPOCH


def test_a_naive_instant_is_read_as_utc() -> None:
    """A naive value is UTC, which is the only reading that is machine-independent.

    Reading it as the server's local time would make the same request name a
    different window on two machines (M13.26).
    """
    assert parse_instant("2026-10-06T13:45:30", "since") == INSTANT_EPOCH


def test_an_unparsable_instant_is_refused_and_names_its_field() -> None:
    """A typo must fail loudly rather than shift the period to another day."""
    with pytest.raises(ReportRequestError, match="not a valid ISO-8601") as err:
        parse_instant("yesterday", "until")

    assert err.value.field == "until"


def test_a_blank_instant_is_refused() -> None:
    """A present-but-empty bound is a mistake, not an absent one."""
    with pytest.raises(ReportRequestError, match="must not be empty") as err:
        parse_instant("  ", "since")

    assert err.value.field == "since"


def test_this_layers_instant_parsing_agrees_with_the_api_layers() -> None:
    """Two restatements of one rule must place a report where the API would (M16.7).

    The reports layer parses its own instants so it does not depend on the API
    layer; the analytics routes parse theirs through the shared validator. If the
    two ever disagreed, a report would cover a different window than the dashboard
    summary for what looked like the same request.
    """
    for value in (INSTANT, "2026-10-06T13:45:30Z", "2026-10-06T13:45:30", "2026-10-06T19:15:30+05:30"):
        assert parse_instant(value, "since") == parse_epoch_filter(value, "since")


def test_both_restatements_refuse_the_same_inputs() -> None:
    """And they refuse the same things, so neither is the more permissive one.

    The two raise different *types* on purpose: the shared validator raises a
    ``ValueError`` for its caller to map, and this layer raises the reporting
    layer's own ``ReportRequestError`` so the route can answer ``400`` with the
    failure's field. What must agree is that the same input is refused at all --
    a permissive restatement would let a report be built from a value the
    analytics routes would have rejected.
    """
    for value in ("yesterday", "2026-13-45T00:00:00+00:00", "  "):
        with pytest.raises(ReportRequestError):
            parse_instant(value, "since")
        with pytest.raises(ValueError):
            parse_epoch_filter(value, "since")


# ---------------------------------------------------------------------------
# build_request
# ---------------------------------------------------------------------------


def test_an_empty_request_takes_every_default() -> None:
    """No body means the previous completed day as a PDF: the documented default."""
    request = build_request(now=INSTANT_EPOCH)

    assert request.report_type == DAILY
    assert request.output_format == "PDF"
    assert request.title is None
    assert request.generated_by is None
    assert request.since is None
    assert request.until is None
    assert request.now == INSTANT_EPOCH


def test_now_is_pinned_rather_than_read_from_the_clock() -> None:
    """A caller-supplied instant is honoured, so a test and a log line agree."""
    assert build_request(now=1234.5).now == 1234.5


def test_a_blank_title_is_treated_as_absent() -> None:
    """An empty title would be an unnamed report, so it becomes the derived name."""
    assert build_request(title="   ", now=0.0).title is None


def test_a_title_is_trimmed() -> None:
    """Surrounding whitespace is not part of a name."""
    assert build_request(title="  Weekly review  ", now=0.0).title == "Weekly review"


def test_generated_by_is_recorded_as_an_integer() -> None:
    """The stored column is an integer, so the value is coerced here."""
    assert build_request(generated_by=7, now=0.0).generated_by == 7


def test_both_bounds_are_parsed_into_epoch_seconds() -> None:
    """The period model downstream reasons in epoch seconds only (M13.26)."""
    request = build_request(
        report_type=CUSTOM, since=INSTANT, until=LATER, now=0.0
    )

    assert request.since == INSTANT_EPOCH
    assert request.until == INSTANT_EPOCH + 3600.0


def test_a_bad_instant_in_a_request_names_its_own_field() -> None:
    """Validation happens once, in the builder, with the field it concerns."""
    with pytest.raises(ReportRequestError) as caught:
        build_request(since="not-a-date", now=0.0)

    assert caught.value.field == "since"


# ---------------------------------------------------------------------------
# resolve_period
# ---------------------------------------------------------------------------


def test_a_daily_request_resolves_the_previous_day() -> None:
    """A preset derives its bounds from the UTC calendar."""
    request = build_request(report_type=DAILY, now=INSTANT_EPOCH)
    period = resolve_period(request)

    assert period.since == resolve_daily(now=INSTANT_EPOCH).since
    assert period.report_type == DAILY


def test_a_weekly_request_resolves_the_previous_week() -> None:
    """And the weekly preset resolves the previous completed week."""
    request = build_request(report_type=WEEKLY, now=INSTANT_EPOCH)
    period = resolve_period(request)

    assert period.since == resolve_weekly(now=INSTANT_EPOCH).since
    assert period.report_type == WEEKLY


def test_a_custom_request_resolves_the_bounds_it_was_given() -> None:
    """A custom report's own instants are passed through unchanged (M17.6)."""
    request = build_request(
        report_type=CUSTOM, since=INSTANT, until=LATER, now=INSTANT_EPOCH
    )

    assert resolve_period(request).since == INSTANT_EPOCH


@pytest.mark.parametrize("preset", [DAILY, WEEKLY])
def test_a_preset_given_bounds_is_refused(preset: str) -> None:
    """A preset derives its period, so naming one as well contradicts itself.

    The alternative — preferring the bounds, or preferring the preset — would
    silently answer a question the caller only half asked (M17.6).
    """
    request = build_request(
        report_type=preset, since=INSTANT, until=LATER, now=0.0
    )

    with pytest.raises(ReportRequestError, match="cannot be supplied") as caught:
        resolve_period(request)

    assert caught.value.field == "period"


def test_a_preset_given_only_one_bound_is_also_refused() -> None:
    """Half a range is still a contradiction, so it is still refused."""
    request = build_request(report_type=DAILY, since=INSTANT, now=0.0)

    with pytest.raises(ReportRequestError, match="cannot be supplied"):
        resolve_period(request)


def test_a_custom_request_without_bounds_is_refused() -> None:
    """Neither bound can be defaulted: an open-ended report is unbounded."""
    request = build_request(report_type=CUSTOM, now=0.0)

    with pytest.raises(ReportRequestError, match="needs both since and until") as err:
        resolve_period(request)

    assert err.value.field == "period"


def test_a_custom_request_with_one_bound_is_refused() -> None:
    """Defaulting the missing half would answer a question nobody asked."""
    request = build_request(report_type=CUSTOM, since=INSTANT, now=0.0)

    with pytest.raises(ReportRequestError, match="needs both since and until"):
        resolve_period(request)


def test_an_unusable_custom_range_is_refused_not_adjusted() -> None:
    """An inverted range is a refusal naming the period, never an empty report."""
    request = build_request(
        report_type=CUSTOM, since=LATER, until=INSTANT, now=0.0
    )

    with pytest.raises(ReportRequestError, match="since must not be later") as err:
        resolve_period(request)

    assert err.value.field == "period"


def test_a_period_past_the_ceiling_is_refused_through_the_request_layer() -> None:
    """The ceiling is enforced on the way in, not left to the analytics window."""
    request = build_request(
        report_type=CUSTOM,
        since="2023-01-01T00:00:00+00:00",
        until="2024-01-01T00:00:00+00:00",
        now=0.0,
    )

    with pytest.raises(ReportRequestError, match="must not exceed"):
        resolve_period(request)


def test_a_refusal_never_names_an_internal() -> None:
    """A refusal is a sentence, with no path, table or traceback (M13.30)."""
    with pytest.raises(ReportRequestError) as caught:
        normalize_format("docx")

    message = caught.value.message
    for internal in ("Traceback", 'File "', "app.", "site-packages", "sqlalchemy"):
        assert internal not in message
