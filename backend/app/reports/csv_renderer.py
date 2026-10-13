"""Rendering a report as CSV (M17.7).

A CSV file is one table, and a report is many. The two facts have to be reconciled
rather than ignored, and this module's whole design is that reconciliation.

**Why not one wide table.** The alternative -- one row per record with the union of
every column any block needs -- produces a file whose ``packets`` column means
"packets of a source address" on one row and "packets of a conversation" on the
next. That is precisely the "ambiguous columns" outcome M17.7 forbids, and it
happens silently: the file is valid CSV and wrong.

**What this writes instead.** A sequence of named blocks, each with its own header
row and its own records::

    ### report
    key,value
    Report title,Daily network report 2026-10-09 (CSV)
    ...

    ### section:traffic
    metric,value
    Packets stored in period,1,234

    ### table:traffic.top_sources
    Source,Packets,Bytes
    10.0.0.5,900,120,000

A ``###`` marker line is a C0-free, comment-like record that spreadsheet software
displays as its own row and that a parser can key on. Every block is
self-describing: its columns are named in the header that follows the marker, and
they are the *same* column names the PDF renders, because both renderers read
:mod:`app.reports.content`. No column is ever reused with a different meaning.

**Determinism.** The block order is the content model's own order -- summary,
then each section in reading order, then each section's tables in their order --
so two reports of the same period produce byte-identical files apart from the
values. A test asserts exactly that, because a non-deterministic export is
undiffable and M17.8 asks for reproducibility.

**Encodings and quoting.** The file is written as UTF-8. Python's ``csv`` writer
does the quoting: a field containing a comma, a quote, a newline or a leading or
trailing space is quoted and its inner quotes doubled, so a device hostname or a
rule name cannot break the row structure. Nothing here hand-rolls quoting, because
hand-rolled quoting is where CSV writers go wrong.

**An empty period is stated, not blank.** When no section carries a row, the file
opens with the summary block and then a single ``### notice`` block carrying the
sentence from the content model. A reader gets a file that says why it has no
records, rather than a file with headers and nothing under them.

**A cell cannot be read as a formula.** A CSV file is opened in a spreadsheet, and
a spreadsheet evaluates a cell whose first character is ``=``, ``+``, ``-`` or
``@`` (M18.11). One value in a report is caller-supplied -- the report's title --
and a device hostname or a rule name could begin with one of those characters, so
the file is a *formula-injection* surface: a value nobody reviewed could execute
on the machine of the operator who opens the report.

Every cell therefore passes through :func:`guard_cell` at a single choke point,
:class:`_GuardedWriter`, which prefixes a formula-triggering value with a single
quote -- the conventional spreadsheet text marker. A cell that is genuinely a
number (``-12``, ``+3``) is left alone: a spreadsheet reads those as numbers
rather than formulas, and guarding them would turn a figure into a string that
would not sum. This is the only place in the reporting layer that alters a value
on its way out, and it is documented here rather than applied silently, because a
reviewer has to be able to see why a report can differ from what the store held.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable
from typing import Protocol

from app.reports.content import ReportContent, ReportSection, ReportTable


class _RowWriter(Protocol):
    """The one method this module uses from a ``csv`` writer.

    The writer is described structurally rather than annotated as
    ``csv.writer``, because that name is typed as a *constructor* in some
    type-checker distributions and as a class in others. A protocol says what is
    actually required -- a ``writerow`` -- and is right under both.
    """

    def writerow(self, row: Iterable[object], /) -> object:
        """Write one record. Positional-only, matching ``csv.writer``."""
        ...  # pragma: no cover - protocol declaration only

#: The marker token that introduces a named block. Three characters a field would
#: never legitimately begin with, so a marker line cannot be confused with data.
BLOCK_MARKER = "###"

#: The block name carrying the report's identity and headline figures.
REPORT_BLOCK = "report"

#: The block name a report with no records carries.
NOTICE_BLOCK = "notice"

#: The sentence the notice block carries for a period that holds no records. One
#: constant, so CSV and PDF word an empty report identically.
EMPTY_NOTICE = "No data was recorded in this period."

#: The line terminator. CRLF is what RFC 4180 specifies and what Excel expects;
#: a Unix-only consumer reads it unchanged.
LINE_TERMINATOR = "\r\n"

#: The characters a spreadsheet may read as the start of a formula or a command
#: (M18.11). ``=``, ``+``, ``-`` and ``@`` begin a formula; a leading tab or
#: carriage return is trimmed by some importers, which then exposes whatever
#: follows it. The set is named once here rather than inlined at the guard, so
#: the rule has exactly one definition and exactly one test.
FORMULA_TRIGGER_CHARS: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")

#: What is written in front of a value that would otherwise be read as a formula.
#: A single quote is a spreadsheet's own text marker, so the cell is displayed as
#: the text it was meant to be instead of being evaluated.
FORMULA_GUARD = "'"


def _looks_numeric(value: str) -> bool:
    """Return True when ``value`` is a number a spreadsheet would read as one.

    Used to keep the guard away from ordinary figures: ``-12`` and ``+3`` are
    numbers rather than formulas, and prefixing them would turn a value a reader
    might sum into a string instead.
    """
    try:
        float(value)
    except ValueError:
        return False
    return True


def guard_cell(value: object) -> str:
    """Return ``value`` as a cell a spreadsheet cannot evaluate (M18.11).

    Args:
        value: The already-rendered cell text.

    Returns:
        The text unchanged, unless its first character could begin a formula -- in
        which case it is prefixed with :data:`FORMULA_GUARD`. A value that is a
        plain number is returned unchanged whatever its sign.

    The guard is applied on the way *out* of the renderer and nowhere else, so a
    reviewer can read one function to know whether a report can differ from the
    content it was built from. It never raises: a value it cannot inspect is
    written as it stands rather than dropped.
    """
    text = str(value)
    if not text:
        return text
    if text[0] not in FORMULA_TRIGGER_CHARS:
        return text
    if _looks_numeric(text):
        return text
    return FORMULA_GUARD + text


class _GuardedWriter:
    """A ``csv`` writer that passes every cell through :func:`guard_cell`.

    One choke point rather than a call at each write site: a block added later
    cannot forget the guard, because nothing in this module writes to the ``csv``
    writer directly. It satisfies :class:`_RowWriter`, so every block helper above
    is unchanged.
    """

    def __init__(self, writer: _RowWriter) -> None:
        self._writer = writer

    def writerow(self, row: Iterable[object], /) -> None:
        """Write one record with every cell guarded."""
        self._writer.writerow([guard_cell(cell) for cell in row])


def _write_marker(writer: _RowWriter, name: str) -> None:
    """Write one block marker row."""
    writer.writerow([BLOCK_MARKER, name])


def _write_block(
    writer: _RowWriter, name: str, header: tuple[str, ...], rows: list[tuple[str, ...]]
) -> None:
    """Write one named block: its marker, its header row, then its records.

    The header is written even when there are no records, so a block that exists
    is always self-describing. That is what lets a consumer tell "this table is
    empty" from "this table was not exported".
    """
    _write_marker(writer, name)
    writer.writerow(list(header))
    for row in rows:
        writer.writerow(list(row))


def _summary_rows(content: ReportContent) -> list[tuple[str, str]]:
    """Return the report block's ``(key, value)`` records."""
    rows: list[tuple[str, str]] = [
        ("report_id", "" if content.report_id is None else str(content.report_id)),
        ("title", content.title),
        ("report_type", content.report_type),
        ("output_format", content.output_format),
        ("generated_at", content.generated_at),
        ("period_start", content.period_start),
        ("period_end", content.period_end),
        ("period_seconds", f"{content.period_seconds:.0f}"),
    ]
    rows.extend(
        (metric.label, metric.value) for metric in content.summary
    )
    return rows


def _section_metric_rows(section: ReportSection) -> list[tuple[str, str]]:
    """Return a section block's records: its availability, then its metrics."""
    rows: list[tuple[str, str]] = [
        ("available", "true" if section.available else "false"),
    ]
    if section.notice:
        rows.append(("notice", section.notice))
    rows.extend((metric.label, metric.value) for metric in section.metrics)
    return rows


def _table_rows(table: ReportTable) -> list[tuple[str, ...]]:
    """Return a table block's records, or one notice record when it holds none."""
    if table.is_empty:
        return [("notice", table.notice or EMPTY_NOTICE)]
    return list(table.rows)


def render_csv(content: ReportContent) -> bytes:
    """Render a report as CSV bytes (M17.7).

    Args:
        content: The assembled report. Nothing is read from anywhere else: a
            renderer that queried a database could disagree with the PDF rendered
            from the same request.

    Returns:
        The encoded file, ready to write to disk. Encoding is UTF-8, and the
        newline convention is CRLF so the file opens correctly in a spreadsheet
        on every platform.
    """
    buffer = io.StringIO(newline="")
    # Wrapped, not used directly: every cell is guarded on its way out, so a
    # block added below cannot write an unguarded value (M18.11).
    writer = _GuardedWriter(
        csv.writer(
            buffer,
            delimiter=",",
            quotechar='"',
            quoting=csv.QUOTE_MINIMAL,
            lineterminator=LINE_TERMINATOR,
        )
    )

    _write_block(
        writer, REPORT_BLOCK, ("key", "value"), _summary_rows(content)
    )

    if content.is_empty:
        _write_marker(writer, NOTICE_BLOCK)
        writer.writerow(["message"])
        writer.writerow([EMPTY_NOTICE])

    for section in content.sections:
        _write_block(
            writer,
            f"section:{section.key}",
            ("metric", "value"),
            _section_metric_rows(section),
        )
        for table in section.tables:
            _write_block(
                writer,
                f"table:{section.key}.{table.key}",
                table.columns,
                _table_rows(table),
            )

    return buffer.getvalue().encode("utf-8")


__all__ = [
    "BLOCK_MARKER",
    "EMPTY_NOTICE",
    "FORMULA_GUARD",
    "FORMULA_TRIGGER_CHARS",
    "LINE_TERMINATOR",
    "NOTICE_BLOCK",
    "REPORT_BLOCK",
    "guard_cell",
    "render_csv",
]
