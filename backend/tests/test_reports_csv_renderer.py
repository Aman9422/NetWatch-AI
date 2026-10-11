"""Tests for the CSV renderer (M17.7).

A report is many tables and a CSV file is one, so the tests care about the
reconciliation: every block is self-describing, no column is ever reused with a
different meaning, and the block order is the content model's own order so two
reports of the same content render byte-identically.

The file is parsed with the standard library's ``csv`` reader rather than matched
against a literal string. That is deliberate: a test asserting the exact bytes
would pass while the file became unparseable, and what matters about a CSV file is
that a reader can read it.
"""

from __future__ import annotations

import csv
import io

import pytest

from app.reports.content import Metric, ReportTable
from app.reports.csv_renderer import (
    BLOCK_MARKER,
    EMPTY_NOTICE,
    LINE_TERMINATOR,
    NOTICE_BLOCK,
    REPORT_BLOCK,
    render_csv,
)
from tests.reports_fakes import (
    TITLE,
    empty_content,
    make_content,
    make_section,
    make_table,
)


def rows(content) -> list[list[str]]:
    """Parse rendered CSV bytes into rows of cells."""
    text = render_csv(content).decode("utf-8")
    return [row for row in csv.reader(io.StringIO(text, newline=""))]


def is_marker(row: list[str]) -> bool:
    """Return True when a row is a block boundary.

    A boundary is exactly two cells: the marker token and the block's name. That
    is what lets the parser here agree with the format's own guarantee, because a
    *data* row of a one-column table could otherwise begin with the marker token
    and be mistaken for a boundary.
    """
    return len(row) == 2 and row[0] == BLOCK_MARKER


def block_bounds(parsed: list[list[str]], name: str) -> tuple[int, int]:
    """Return the index range of the block named ``name``: marker to next marker."""
    start = next(
        index for index, row in enumerate(parsed) if is_marker(row) and row[1] == name
    )
    end = next(
        (
            index
            for index in range(start + 1, len(parsed))
            if is_marker(parsed[index])
        ),
        len(parsed),
    )
    return start, end


def block(parsed: list[list[str]], name: str) -> list[list[str]]:
    """Return one named block, including its marker row."""
    start, end = block_bounds(parsed, name)
    return parsed[start:end]


# ---------------------------------------------------------------------------
# the file itself
# ---------------------------------------------------------------------------


def test_the_file_is_utf8() -> None:
    """The declared encoding is UTF-8, and a non-ASCII value survives it."""
    rendered = render_csv(
        make_content(
            output_format="CSV",
            summary=(Metric(label="Résumé", value="café — naïve"),),
        )
    )

    assert isinstance(rendered, bytes)
    assert "café" in rendered.decode("utf-8")


def test_the_line_terminator_is_crlf() -> None:
    """RFC 4180 specifies CRLF, and Excel expects it (M17.7)."""
    rendered = render_csv(make_content(output_format="CSV")).decode("utf-8")

    assert LINE_TERMINATOR == "\r\n"
    assert rendered.endswith("\r\n")
    assert "\r\n" in rendered


def test_every_marker_row_is_a_two_cell_record() -> None:
    """A marker is distinguishable from any data row, whatever its columns.

    That is what makes the block structure safe: no table's own row can be
    mistaken for a block boundary, because a boundary always carries the marker
    *and* a name.
    """
    parsed = rows(make_content(output_format="CSV"))

    for row in parsed:
        if row and row[0] == BLOCK_MARKER:
            assert len(row) == 2
            assert row[1] != ""


# ---------------------------------------------------------------------------
# the report block
# ---------------------------------------------------------------------------


def test_the_report_block_comes_first() -> None:
    """The identity block is the first thing a reader meets (M17.7)."""
    parsed = rows(make_content(output_format="CSV"))

    assert parsed[0] == [BLOCK_MARKER, REPORT_BLOCK]


def test_the_report_block_has_its_own_header() -> None:
    """A block that exists is always self-describing."""
    report = block(rows(make_content(output_format="CSV")), REPORT_BLOCK)

    assert report[1] == ["key", "value"]


def test_the_report_block_carries_the_identity_and_the_period() -> None:
    """Which report, in which format, over which period — before any table.

    The format recorded here is the one the content was asked for, not the one it
    happens to be rendered in yet: this file is a CSV, and says so.
    """
    report = dict(
        row for row in block(rows(make_content(output_format="CSV")), REPORT_BLOCK)[2:]
    )

    assert report["report_id"] == "7"
    assert report["title"] == TITLE
    assert report["report_type"] == "daily"
    assert report["output_format"] == "CSV"
    assert report["period_start"] == "2026-10-09T00:00:00+00:00"
    assert report["period_end"] == "2026-10-10T00:00:00+00:00"
    assert report["period_seconds"] == "86400"


def test_the_report_block_carries_the_summary_metrics() -> None:
    """The headline figures ride in the same block as the identity."""
    report = dict(
        row for row in block(rows(make_content(output_format="CSV")), REPORT_BLOCK)[2:]
    )

    assert report["Total packets stored"] == "1,234"


def test_a_report_with_no_stored_id_leaves_the_cell_empty() -> None:
    """The field is present and empty, which is not the same as absent."""
    report = dict(
        row
        for row in block(
            rows(make_content(output_format="CSV", report_id=None)), REPORT_BLOCK
        )[2:]
    )

    assert report["report_id"] == ""


# ---------------------------------------------------------------------------
# section blocks
# ---------------------------------------------------------------------------


def test_each_section_gets_its_own_named_block() -> None:
    """One block per subject, keyed by the section's stable machine name."""
    parsed = rows(make_content(output_format="CSV"))

    assert block(parsed, "section:traffic")


def test_a_section_block_states_its_own_availability() -> None:
    """A reader can tell a section that was read from one that was not (M16.8)."""
    available = dict(
        row
        for row in block(rows(make_content(output_format="CSV")), "section:traffic")[2:]
    )

    assert available["available"] == "true"


def test_an_unavailable_section_states_that_and_its_sentence() -> None:
    """An unreadable section is never reported as a set of zeroes."""
    content = make_content(
        output_format="CSV",
        sections=(
            make_section(
                key="threats",
                title="Threats",
                metrics=(),
                tables=(),
                available=False,
                notice="This section could not be read and is not included.",
            ),
        ),
    )
    section = dict(
        row for row in block(rows(content), "section:threats")[2:]
    )

    assert section["available"] == "false"
    assert section["notice"] == "This section could not be read and is not included."


def test_a_section_block_carries_its_metrics() -> None:
    """The section's own labelled scalars follow its availability."""
    section = dict(
        row
        for row in block(rows(make_content(output_format="CSV")), "section:traffic")[2:]
    )

    assert section["Total packets stored"] == "1,234"


# ---------------------------------------------------------------------------
# table blocks
# ---------------------------------------------------------------------------


def test_a_table_block_header_is_the_tables_own_columns() -> None:
    """Not a generic header: the columns the renderer was given, in order.

    This is what keeps a ``packets`` column from meaning the packets of a source
    address on one row and of a conversation on the next (M17.7).
    """
    parsed = rows(make_content(output_format="CSV"))
    table = block(parsed, "table:traffic.top_sources")

    assert table[1] == ["Source", "Packets", "Bytes"]


def test_a_table_block_carries_its_rows_verbatim() -> None:
    """Rows are already-rendered strings, so the writer does not reformat them."""
    table = block(rows(make_content(output_format="CSV")), "table:traffic.top_sources")

    assert table[2] == ["10.0.0.5", "900", "120,000"]


def test_an_empty_table_states_why_it_is_empty() -> None:
    """A header with nothing under it would be an unlabelled blank."""
    content = make_content(
        output_format="CSV",
        sections=(
            make_section(
                tables=(
                    make_table(rows=(), notice="No data was recorded in this period."),
                )
            ),
        ),
    )
    table = block(rows(content), "table:traffic.top_sources")

    assert table[1] == ["Source", "Packets", "Bytes"]
    assert table[2] == ["notice", "No data was recorded in this period."]


def test_an_empty_table_falls_back_to_the_standard_sentence() -> None:
    """A table with no notice still says something rather than nothing."""
    content = make_content(
        output_format="CSV",
        sections=(
            make_section(
                tables=(
                    ReportTable(
                        key="top_sources",
                        title="Busiest sources",
                        columns=("Source",),
                        rows=(),
                    ),
                )
            ),
        ),
    )
    table = block(rows(content), "table:traffic.top_sources")

    assert table[2] == ["notice", EMPTY_NOTICE]


# ---------------------------------------------------------------------------
# the empty report
# ---------------------------------------------------------------------------


def test_an_empty_report_opens_with_a_statement_of_that() -> None:
    """A reader is told why there are no records, not left with bare headers."""
    parsed = rows(empty_content(output_format="CSV"))
    notice = block(parsed, NOTICE_BLOCK)

    assert notice[1] == ["message"]
    assert notice[2] == [EMPTY_NOTICE]


def test_a_report_with_records_carries_no_notice_block() -> None:
    """The notice is for an empty period and appears nowhere else."""
    parsed = rows(make_content(output_format="CSV"))

    assert all(row[:2] != [BLOCK_MARKER, NOTICE_BLOCK] for row in parsed)


# ---------------------------------------------------------------------------
# determinism and order
# ---------------------------------------------------------------------------


def test_the_same_content_renders_byte_identically() -> None:
    """A non-deterministic export would be undiffable (M17.8)."""
    content = make_content(output_format="CSV")

    assert render_csv(content) == render_csv(content)


def test_blocks_follow_the_content_models_own_order() -> None:
    """Sections in reading order, then each section's tables in their order."""
    content = make_content(
        output_format="CSV",
        sections=(
            make_section(
                key="traffic",
                title="Traffic",
                tables=(
                    make_table(key="first", title="First"),
                    make_table(key="second", title="Second"),
                ),
            ),
            make_section(key="devices", title="Devices", tables=(make_table(),)),
        ),
    )

    markers = [
        row[1] for row in rows(content) if row and row[0] == BLOCK_MARKER
    ]

    assert markers == [
        REPORT_BLOCK,
        "section:traffic",
        "table:traffic.first",
        "table:traffic.second",
        "section:devices",
        "table:devices.top_sources",
    ]


# ---------------------------------------------------------------------------
# quoting
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.5, secondary",
        'a "quoted" name',
        "line one\nline two",
        " leading space",
        "trailing space ",
        "",
    ],
)
def test_an_awkward_value_round_trips(value: str) -> None:
    """Python's writer does the quoting, so a value cannot break the row structure.

    Nothing here hand-rolls quoting, because hand-rolled quoting is where CSV
    writers go wrong — and a device hostname or a rule name is exactly the sort of
    value that contains a comma or a quote.
    """
    content = make_content(
        output_format="CSV",
        summary=(Metric(label="Value", value=value),),
    )
    report = dict(
        row for row in block(rows(content), REPORT_BLOCK)[2:]
    )

    assert report["Value"] == value


def test_a_value_containing_the_line_terminator_is_quoted() -> None:
    """A newline inside a cell must not become a new record."""
    content = make_content(
        output_format="CSV",
        summary=(Metric(label="Value", value="one\r\ntwo"),),
    )

    assert dict(row for row in block(rows(content), REPORT_BLOCK)[2:])["Value"] == (
        "one\r\ntwo"
    )


def test_a_table_row_is_not_mistaken_for_a_block_marker() -> None:
    """A cell equal to the marker token is still just a cell."""
    content = make_content(
        output_format="CSV",
        sections=(
            make_section(
                tables=(
                    make_table(
                        columns=("Column",),
                        rows=((BLOCK_MARKER,),),
                    ),
                )
            ),
        ),
    )
    table = block(rows(content), "table:traffic.top_sources")

    assert table[2] == [BLOCK_MARKER]


def test_a_section_with_no_tables_still_gets_its_block() -> None:
    """A section that was read is reported even when it has nothing to list.

    The report is *empty* by the content model's own definition — no section holds
    a row — so it also carries the notice block. Both are asserted, because the
    two statements are independent: "this section was read" and "this period holds
    no rows" are different facts.
    """
    content = make_content(
        output_format="CSV",
        sections=(make_section(key="traffic", title="Traffic", tables=()),),
    )
    markers = [row[1] for row in rows(content) if is_marker(row)]

    assert "section:traffic" in markers
    assert markers == [REPORT_BLOCK, NOTICE_BLOCK, "section:traffic"]
