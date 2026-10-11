"""The one report content model both renderers consume (M17.3).

A report is *data* before it is a file. This module is that data, and it is
deliberately renderer-agnostic: nothing here knows about CSV, PDF, reportlab or
the ``csv`` module. The CSV renderer and the PDF renderer both walk the same
structure, so the two formats cannot disagree about what a report says -- which
is the whole reason M17.7 asks for a "common report content structure".

Three shapes, each with one job:

:class:`Metric`
    A labelled scalar. Rendered as a labelled line in a PDF and as a row in a
    CSV metric block.
:class:`ReportTable`
    A titled table with declared column names and string rows. The column names
    are *stored* rather than implied, because a CSV header and a PDF table header
    must come from the same source; and the cells are already-rendered strings,
    so a number's formatting is decided once, beside the value's meaning, rather
    than twice by two renderers.
:class:`ReportSection`
    One subject -- traffic, devices, alerts -- with its own metrics and tables,
    and an explicit *availability*. An unavailable section is a section that
    could not be read at all (M16.8), and it says so in a sentence rather than
    reporting zeroes nobody measured (M17.3).

**Nothing in this module computes a figure.** Every value arrives from the
assembler, which reads it from the service that owns it. The only arithmetic in
the package is presentation -- a label, a rounding, a ``/s`` suffix.

**Nulls stay distinguishable from zeroes.** A field that is genuinely absent is
rendered as the documented :data:`NOT_REPORTED` text, never as ``0``: the two are
different answers and a report that collapsed them would misstate what was
measured.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: What a value renders as when the backend genuinely has none. One constant, so
#: the CSV and PDF renderers cannot spell "no data" two different ways.
NOT_REPORTED = "not reported"

#: The section key every report carries: the report's own identity and the
#: headline figures an executive summary is built from.
SUMMARY_SECTION = "summary"


@dataclass(frozen=True)
class Metric:
    """One labelled scalar in a report (M17.3).

    Attributes:
        label: The human-readable name, e.g. ``Total packets stored``.
        value: The value, already rendered as text. Keeping it a string means a
            caller decides a number's format once, at the point where its unit is
            known, rather than each renderer guessing.
    """

    label: str
    value: str


@dataclass(frozen=True)
class ReportTable:
    """One titled table of uniformly-shaped rows (M17.3).

    Attributes:
        key: A stable machine name, used in the CSV block marker and in a test's
            assertion. Never shown to a reader.
        title: The human title, e.g. ``Busiest sources``.
        columns: The column names, in order. Documented and stable, because this
            is where both a CSV header row and a PDF table header come from.
        rows: The rows, each already rendered to strings and holding exactly
            ``len(columns)`` cells.
        notice: A sentence to show *instead of* rows when the table has none --
            either because the store held nothing in the period or because the
            data it needed could not be read. ``None`` when rows are present.
    """

    key: str
    title: str
    columns: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...] = ()
    notice: str | None = None

    @property
    def is_empty(self) -> bool:
        """Return True when the table has no rows to render."""
        return len(self.rows) == 0


@dataclass(frozen=True)
class ReportSection:
    """One subject of a report: its metrics, its tables and its availability (M17.3).

    Attributes:
        key: A stable machine name, e.g. ``traffic``.
        title: The human title, e.g. ``Traffic``.
        metrics: The section's scalars, in the order they should be read.
        tables: The section's tables, in the order they should be read.
        available: False when the section could not be read at all. An available
            section holding zeroes means the store held nothing in the period; an
            unavailable one means the question could not be asked (M16.8). The
            two are never conflated.
        notice: A safe sentence explaining an unavailable section. Names no
            table, column, query or exception (M13.30).
    """

    key: str
    title: str
    metrics: tuple[Metric, ...] = ()
    tables: tuple[ReportTable, ...] = ()
    available: bool = True
    notice: str | None = None


@dataclass(frozen=True)
class ReportContent:
    """Everything one report says, before it is a file (M17.3).

    Attributes:
        report_id: The stored metadata identifier, or ``None`` while a report is
            still being assembled.
        title: The report's title, shown as the PDF heading and the CSV's first
            metric.
        report_type: ``daily``, ``weekly`` or ``custom``.
        output_format: ``CSV`` or ``PDF``. Recorded *in* the content so a reader
            of the file can see which format it was asked for, and so a test can
            assert the two are consistent.
        generated_at: When the report was produced, ISO-8601 UTC.
        period_start: The reporting period's inclusive bound, ISO-8601 UTC.
        period_end: The reporting period's exclusive bound, ISO-8601 UTC.
        period_seconds: The period's length, so a rate in the report is checkable.
        summary: The executive-summary metrics: the report's identity plus the
            headline figures drawn from every section.
        sections: The body sections, in reading order.
    """

    report_id: int | None
    title: str
    report_type: str
    output_format: str
    generated_at: str
    period_start: str
    period_end: str
    period_seconds: float
    summary: tuple[Metric, ...] = ()
    sections: tuple[ReportSection, ...] = field(default_factory=tuple)

    def section(self, key: str) -> ReportSection | None:
        """Return one section by key, or ``None`` when the report has none."""
        for section in self.sections:
            if section.key == key:
                return section
        return None

    @property
    def is_empty(self) -> bool:
        """Return True when no section carries a single row.

        Used by the renderers to decide whether a report needs the explicit
        "the period holds no stored data" statement, so an empty report says so
        rather than presenting an unlabelled set of empty tables (M17.7/M17.8).
        """
        return all(
            len(section.tables) == 0
            or all(table.is_empty for table in section.tables)
            for section in self.sections
            if section.available
        )


__all__ = [
    "NOT_REPORTED",
    "SUMMARY_SECTION",
    "Metric",
    "ReportContent",
    "ReportSection",
    "ReportTable",
]
