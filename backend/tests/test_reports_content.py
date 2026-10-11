"""Tests for the report content model (M17.3).

The content model is the contract between the assembler and the two renderers, so
these tests hold it to the properties that contract depends on: a table states its
own columns, a section states its own availability, and "no rows" is distinguishable
from "no data at all".

The ``is_empty`` property gets the most attention, because both renderers use it to
decide whether a report needs the explicit "this period holds nothing" statement —
and it must ignore an *unavailable* section, since a section that could not be read
has no rows to be empty of (M16.8).
"""

from __future__ import annotations

import dataclasses

import pytest

from app.reports.content import (
    NOT_REPORTED,
    SUMMARY_SECTION,
    Metric,
    ReportContent,
    ReportSection,
    ReportTable,
)


def content(**overrides: object) -> ReportContent:
    """Return a minimal content model, with any field replaced."""
    values: dict[str, object] = {
        "report_id": 1,
        "title": "Report",
        "report_type": "daily",
        "output_format": "CSV",
        "generated_at": "2026-10-10T00:00:00+00:00",
        "period_start": "2026-10-09T00:00:00+00:00",
        "period_end": "2026-10-10T00:00:00+00:00",
        "period_seconds": 86_400.0,
    }
    values.update(overrides)
    return ReportContent(**values)  # type: ignore[arg-type]


def table(*, rows: tuple[tuple[str, ...], ...] = (("a", "1"),)) -> ReportTable:
    """Return a two-column table with the given rows."""
    return ReportTable(
        key="top_sources",
        title="Busiest sources",
        columns=("Source", "Packets"),
        rows=rows,
    )


# ---------------------------------------------------------------------------
# the not-reported constant
# ---------------------------------------------------------------------------


def test_the_not_reported_text_is_a_phrase_not_a_zero() -> None:
    """A value the backend has none of is not zero, and the text says so (M17.3).

    The constant exists once so the CSV and the PDF cannot spell "no data" two
    different ways.
    """
    assert NOT_REPORTED == "not reported"
    assert NOT_REPORTED != "0"
    assert NOT_REPORTED != ""


def test_the_summary_section_key_is_named_once() -> None:
    """The key every report's identity block carries."""
    assert SUMMARY_SECTION == "summary"


# ---------------------------------------------------------------------------
# the three shapes
# ---------------------------------------------------------------------------


def test_a_metric_carries_a_label_and_an_already_rendered_value() -> None:
    """The value is text: its format is decided once, beside its meaning."""
    metric = Metric(label="Total packets", value="1,234")

    assert metric.label == "Total packets"
    assert metric.value == "1,234"


@pytest.mark.parametrize(
    "shape",
    [
        Metric(label="a", value="b"),
        ReportTable(key="k", title="t", columns=("c",)),
        ReportSection(key="k", title="t"),
    ],
)
def test_every_shape_is_frozen(shape: object) -> None:
    """A report is a record: nothing may mutate it after it is assembled.

    Frozen dataclasses are what make a content model safe to hand to two renderers
    in sequence — a renderer cannot damage what the next one reads.
    """
    with pytest.raises(dataclasses.FrozenInstanceError):
        shape.__setattr__("key", "changed")  # type: ignore[attr-defined]


def test_a_table_states_its_own_columns() -> None:
    """The column names are stored, not implied, so both renderers read one list."""
    assert table().columns == ("Source", "Packets")


def test_a_table_is_empty_exactly_when_it_has_no_rows() -> None:
    """``is_empty`` is what a renderer branches on to print a notice instead."""
    assert table(rows=()).is_empty is True
    assert table(rows=(("a", "1"),)).is_empty is False


def test_a_table_carries_an_optional_notice() -> None:
    """The sentence shown *instead of* rows, when there are none."""
    empty_one = ReportTable(
        key="k", title="t", columns=("c",), rows=(), notice="nothing here"
    )

    assert empty_one.notice == "nothing here"
    assert table().notice is None


def test_a_section_is_available_unless_it_says_otherwise() -> None:
    """The default is the common case: a section that was read."""
    section = ReportSection(key="traffic", title="Traffic")

    assert section.available is True
    assert section.notice is None
    assert section.metrics == ()
    assert section.tables == ()


def test_an_unavailable_section_carries_a_safe_sentence() -> None:
    """A section that could not be read says so rather than reporting zeroes."""
    section = ReportSection(
        key="threats",
        title="Threats",
        available=False,
        notice="This section could not be read and is not included.",
    )

    assert section.available is False
    assert section.notice is not None
    assert section.metrics == ()
    assert section.tables == ()


# ---------------------------------------------------------------------------
# looking a section up
# ---------------------------------------------------------------------------


def test_a_section_is_found_by_key() -> None:
    """The summariser lifts headline figures by section key, so the lookup is real."""
    traffic = ReportSection(key="traffic", title="Traffic")
    content_model = content(sections=(traffic,))

    assert content_model.section("traffic") is traffic


def test_an_unknown_key_yields_nothing_rather_than_raising() -> None:
    """A summary asks for a key that may not be there; the caller decides."""
    assert content(sections=(ReportSection(key="traffic", title="Traffic"),)).section(
        "devices"
    ) is None


def test_a_content_model_with_no_sections_has_no_section() -> None:
    """An empty report is still a well-formed content model."""
    assert content(sections=()).section("traffic") is None


# ---------------------------------------------------------------------------
# is_empty
# ---------------------------------------------------------------------------


def test_a_report_whose_sections_all_hold_rows_is_not_empty() -> None:
    """Any row anywhere means the report has something to say."""
    content_model = content(
        sections=(
            ReportSection(key="traffic", title="Traffic", tables=(table(),)),
        )
    )

    assert content_model.is_empty is False


def test_a_report_whose_sections_hold_no_rows_is_empty() -> None:
    """Every table empty means the period held nothing to record."""
    content_model = content(
        sections=(
            ReportSection(key="traffic", title="Traffic", tables=(table(rows=()),)),
            ReportSection(key="devices", title="Devices", tables=(table(rows=()),)),
        )
    )

    assert content_model.is_empty is True


def test_a_section_with_no_tables_at_all_contributes_no_rows() -> None:
    """A section that only carries metrics has no rows to be empty of."""
    content_model = content(
        sections=(
            ReportSection(
                key="traffic",
                title="Traffic",
                metrics=(Metric(label="a", value="1"),),
                tables=(),
            ),
        )
    )

    assert content_model.is_empty is True


def test_an_unavailable_section_neither_makes_a_report_empty_nor_populated() -> None:
    """A section that could not be read is excluded from the question (M16.8).

    It has no rows to be empty of, so counting it would claim an absence nobody
    measured — the exact conflation M16.8 forbids.
    """
    populated = content(
        sections=(
            ReportSection(key="traffic", title="Traffic", tables=(table(),)),
            ReportSection(key="threats", title="Threats", available=False),
        )
    )
    only_unavailable = content(
        sections=(ReportSection(key="threats", title="Threats", available=False),)
    )

    assert populated.is_empty is False
    assert only_unavailable.is_empty is True


def test_a_report_with_no_sections_is_empty() -> None:
    """Nothing was assembled, so nothing was recorded."""
    assert content(sections=()).is_empty is True


# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------


def test_a_report_records_the_format_it_was_asked_for() -> None:
    """The format is *in* the content, so a reader of the file can see it (M17.3).

    It is also what :func:`app.reports.renderers.render_report` dispatches on, so
    the file a caller receives cannot be in a different format than the one the
    same content says it is.
    """
    assert content(output_format="PDF").output_format == "PDF"
    assert content(output_format="CSV").output_format == "CSV"


def test_a_report_may_have_no_stored_id_yet() -> None:
    """A report is assembled before its row is written, so ``None`` is valid."""
    assert content(report_id=None).report_id is None
