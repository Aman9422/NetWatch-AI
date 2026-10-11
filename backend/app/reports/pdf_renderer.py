"""Rendering a report as a PDF document (M17.8).

The PDF is the *readable* form of a report: a title block, an executive summary,
then one section per subject with its labelled metrics and its tables. It is built
with ReportLab's platypus layer, so text wraps, tables break across pages with
their header row repeated, and every page carries a header and a page number.

**One source, two renderers.** Every string in the document comes from
:mod:`app.reports.content`, exactly as the CSV renderer's do. The two formats
therefore cannot disagree about a figure or a column name, which is the "common
report content structure" the milestone asks for made real rather than
aspirational.

**Layout decisions, and why.**

* **A4 portrait, 18 mm margins.** A table of four columns and a table of nine both
  fit a portrait A4 frame, and portrait is what a report is read in. The margin is
  wide enough that a printer cannot clip the page number.
* **Columns are sized from their content, then normalised to the frame.** A
  proportional width computed from each column's longest cell gives a nine-column
  table sensible proportions without any per-table tuning, and normalising to the
  frame width is what guarantees no table can overflow the page -- ReportLab's own
  auto-sizing is measured against the data, not against the frame.
* **Cell text is a wrapped paragraph, never a bare string.** A bare string in a
  ReportLab table is drawn on one line however long it is, which is how a device
  hostname ends up running off the page. A paragraph wraps, so a long value makes
  its row taller instead of making the table wider.
* **A table repeats its header row on every page it spans.** A table broken across
  two pages without a header is a table whose second half is unlabelled.
* **Nothing is truncated.** A report is a record; silently dropping rows would
  misstate what was observed. The *assembly* step bounds every table, so rendering
  preserves whatever it was given.

**Text and characters.** A font is registered from the Bitstream Vera faces
ReportLab ships, which cover Latin, Greek and Cyrillic -- so a hostname with a
non-ASCII character renders rather than raising. If those files are absent the
renderer falls back to the built-in Helvetica, which covers Latin-1, and says so
in the log rather than failing a generation over a font.

**A failed render is a failure, not a blank document.** If ReportLab raises, the
exception is translated into :class:`~app.reports.errors.ReportGenerationError`
with a safe sentence; the caller marks the row failed and writes no artifact.
"""

from __future__ import annotations

import io
import logging
import os
from xml.sax.saxutils import escape as escape_markup

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as pdf_canvas
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.reports.content import Metric, ReportContent, ReportSection, ReportTable
from app.reports.csv_renderer import EMPTY_NOTICE
from app.reports.errors import ReportGenerationError

logger = logging.getLogger(__name__)

#: Page geometry. Portrait A4 with an 18 mm margin on every side.
PAGE_SIZE = A4
PAGE_MARGIN = 18 * mm

#: The width a table may occupy: the page minus both margins.
FRAME_WIDTH = PAGE_SIZE[0] - 2 * PAGE_MARGIN

#: The registered font family, or the built-in fallback. Resolved once, by
#: :func:`_register_fonts`.
FONT_REGULAR = "Helvetica"
FONT_BOLD = "Helvetica-Bold"
FONT_ITALIC = "Helvetica-Oblique"

#: Smallest share of the frame one table column may claim, as a weight. A weight
#: of 3 against a long column's 40 keeps a two-character column -- a port, a
#: status -- wide enough for its header text to be readable rather than split.
MIN_COLUMN_WEIGHT = 3

#: Longest column weight, so one wide column cannot starve the rest. A cell longer
#: than this wraps rather than widening its column, which is what keeps a table
#: with one very long hostname from squashing every other column.
MAX_COLUMN_WEIGHT = 40

#: The colours the document uses. Deliberately few: a report is read, not admired,
#: and every one of them is a neutral that prints legibly in greyscale.
INK = colors.HexColor("#111827")
MUTED = colors.HexColor("#6b7280")
RULE = colors.HexColor("#d1d5db")
HEADER_BG = colors.HexColor("#f3f4f6")
ZEBRA_BG = colors.HexColor("#fafafa")


def _register_fonts() -> None:
    """Register the bundled Unicode faces, keeping the fallback if unavailable.

    Registration is process-wide, so it is attempted once here: a missing font
    file costs one failed lookup rather than one per render. The fallback is not an
    error -- Helvetica renders every character this application's own data
    contains, and refusing to generate a report because a font is absent would be a
    worse outcome than a report in a slightly narrower character set.
    """
    global FONT_REGULAR, FONT_BOLD, FONT_ITALIC
    if FONT_REGULAR != "Helvetica":
        return

    try:
        import reportlab  # noqa: PLC0415 - located lazily, only when rendering

        base = os.path.join(os.path.dirname(reportlab.__file__), "fonts")
        faces = (
            ("Regular", "Vera.ttf"),
            ("Bold", "VeraBd.ttf"),
            ("Italic", "VeraIt.ttf"),
            ("BoldItalic", "VeraBI.ttf"),
        )
        for suffix, filename in faces:
            path = os.path.join(base, filename)
            if not os.path.exists(path):
                raise FileNotFoundError(filename)
            pdfmetrics.registerFont(TTFont(f"ReportSans-{suffix}", path))
        pdfmetrics.registerFontFamily(
            "ReportSans",
            normal="ReportSans-Regular",
            bold="ReportSans-Bold",
            italic="ReportSans-Italic",
            boldItalic="ReportSans-BoldItalic",
        )
    except Exception:  # noqa: BLE001 - a missing font must not fail a report
        logger.warning(
            "Unicode report font unavailable; falling back to the built-in faces"
        )
        return
    FONT_REGULAR = "ReportSans-Regular"
    FONT_BOLD = "ReportSans-Bold"
    FONT_ITALIC = "ReportSans-Italic"


def _styles() -> dict[str, ParagraphStyle]:
    """Return the paragraph styles the document uses, keyed by purpose."""
    return {
        "title": ParagraphStyle(
            "ReportTitle",
            fontName=FONT_BOLD,
            fontSize=19,
            leading=23,
            textColor=INK,
            spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            fontName=FONT_REGULAR,
            fontSize=9.5,
            leading=13,
            textColor=MUTED,
            spaceAfter=10,
        ),
        "section": ParagraphStyle(
            "ReportSection",
            fontName=FONT_BOLD,
            fontSize=13.5,
            leading=17,
            textColor=INK,
            spaceBefore=6,
            spaceAfter=4,
        ),
        "table": ParagraphStyle(
            "ReportTableHead",
            fontName=FONT_BOLD,
            fontSize=10.5,
            leading=13,
            textColor=INK,
            spaceBefore=8,
            spaceAfter=3,
        ),
        "cell": ParagraphStyle(
            "ReportCell",
            fontName=FONT_REGULAR,
            fontSize=7.8,
            leading=10,
            textColor=INK,
        ),
        "cell_head": ParagraphStyle(
            "ReportCellHead",
            fontName=FONT_BOLD,
            fontSize=7.8,
            leading=10,
            textColor=INK,
        ),
        "notice": ParagraphStyle(
            "ReportNotice",
            fontName=FONT_ITALIC,
            fontSize=9,
            leading=12,
            textColor=MUTED,
            spaceBefore=2,
            spaceAfter=6,
        ),
    }


def _paragraph(text: str, style: ParagraphStyle) -> Paragraph:
    """Return ``text`` as a wrapped paragraph.

    The value is passed through the standard library's XML escaper first, because
    ReportLab's paragraph markup is XML-like: a value containing ``&`` or ``<`` --
    a hostname, a rule name -- would otherwise be parsed as markup and either
    vanish or raise. Escaping is applied at the single point where text enters the
    markup parser rather than at every call site.
    """
    return Paragraph(escape_markup(str(text)), style)


def _metrics_table(metrics: tuple[Metric, ...], styles) -> Table | None:
    """Return a two-column label/value table, or ``None`` when there are none."""
    if not metrics:
        return None
    rows = [
        [
            _paragraph(metric.label, styles["cell"]),
            _paragraph(metric.value, styles["cell"]),
        ]
        for metric in metrics
    ]
    table = Table(rows, colWidths=[FRAME_WIDTH * 0.62, FRAME_WIDTH * 0.38])
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW", (0, 0), (-1, -2), 0.25, RULE),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _column_widths(table: ReportTable) -> list[float]:
    """Return frame-fitting column widths, proportional to the content.

    The weight of a column is the length of its longest cell, bounded by
    :data:`MIN_COLUMN_WEIGHT` and :data:`MAX_COLUMN_WEIGHT`, so a column of
    addresses gets more room than a column of states without any per-table
    configuration. Normalising the weights to :data:`FRAME_WIDTH` is what
    guarantees the result fits the frame.
    """
    weights: list[float] = []
    for index, column in enumerate(table.columns):
        longest = len(str(column))
        for row in table.rows:
            if index < len(row):
                longest = max(longest, len(str(row[index])))
        weights.append(float(min(MAX_COLUMN_WEIGHT, max(MIN_COLUMN_WEIGHT, longest))))
    total = sum(weights) or 1.0
    return [FRAME_WIDTH * weight / total for weight in weights]


def _data_table(table: ReportTable, styles) -> Table:
    """Return one report table as a styled, header-repeating ReportLab table."""
    rows: list[list[Paragraph]] = [
        [_paragraph(name, styles["cell_head"]) for name in table.columns]
    ]
    for row in table.rows:
        rows.append([_paragraph(cell, styles["cell"]) for cell in row])

    rendered = Table(rows, colWidths=_column_widths(table), repeatRows=1, hAlign="LEFT")
    style: list[tuple] = [
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, RULE),
        ("LINEBELOW", (0, 1), (-1, -1), 0.2, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    for index in range(2, len(rows), 2):
        style.append(("BACKGROUND", (0, index), (-1, index), ZEBRA_BG))
    rendered.setStyle(TableStyle(style))
    return rendered


# ---------------------------------------------------------------------------
# Page furniture: header and "Page X of Y"
# ---------------------------------------------------------------------------


def _canvas_maker(title: str):
    """Return a canvas class that draws this report's header and page numbers.

    A page number is only knowable once every page has been laid out, so the class
    defers drawing: :meth:`showPage` captures each page's state instead of ending
    the page, and :meth:`save` replays them once the total is known. That is
    ReportLab's own documented recipe for "Page X of Y", restated here rather than
    imported from a helper, because this is the only place in the project that
    needs it.
    """

    class _ReportCanvas(pdf_canvas.Canvas):
        """A canvas that stamps a footer on every page."""

        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            self._page_states: list[dict] = []

        def showPage(self) -> None:  # noqa: N802 - ReportLab's own method name
            self._page_states.append(dict(self.__dict__))
            # ``_startPage`` is ReportLab's own internal page reset. It is not in
            # the type stubs, and calling it is the documented recipe for a
            # numbered canvas, so the attribute error is suppressed rather than
            # worked around.
            self._startPage()  # type: ignore[attr-defined]

        def save(self) -> None:
            total = len(self._page_states)
            for number, state in enumerate(self._page_states, start=1):
                self.__dict__.update(state)
                self._draw_footer(number, total)
                super().showPage()
            super().save()

        def _draw_footer(self, number: int, total: int) -> None:
            """Draw the rule and the header/footer line on the current page."""
            width, _height = PAGE_SIZE
            self.saveState()
            self.setStrokeColor(RULE)
            self.setLineWidth(0.4)
            self.setFont(FONT_REGULAR, 7.5)
            self.setFillColor(MUTED)

            baseline = PAGE_MARGIN - 6 * mm
            self.line(PAGE_MARGIN, PAGE_MARGIN - 3.5 * mm, width - PAGE_MARGIN, PAGE_MARGIN - 3.5 * mm)
            self.drawString(PAGE_MARGIN, baseline, _clip(title, 110))
            self.drawRightString(
                width - PAGE_MARGIN, baseline, f"Page {number} of {total}"
            )

            self.setFont(FONT_REGULAR, 7.5)
            self.drawString(
                PAGE_MARGIN,
                PAGE_SIZE[1] - PAGE_MARGIN + 3.5 * mm,
                "NetWatch AI \u2014 generated report",
            )
            self.restoreState()

    return _ReportCanvas


def _clip(text: str, limit: int) -> str:
    """Return ``text`` shortened to ``limit`` characters, with an ellipsis.

    Used only for the running header, where the alternative -- a title wider than
    the page -- would overlap the header's own right-hand text. Table and body text
    is never clipped: a report's *data* is never shortened.
    """
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "\u2026"


# ---------------------------------------------------------------------------
# The document's story
# ---------------------------------------------------------------------------


def _subtitle(content: ReportContent) -> str:
    """Return the one-line context block under the title."""
    return (
        f"Period {content.period_start} to {content.period_end} (exclusive)  |  "
        f"Type {content.report_type}  |  Format {content.output_format}  |  "
        f"Generated {content.generated_at}"
    )


def _section_story(section: ReportSection, styles) -> list:
    """Return the flowables for one report section."""
    flowables: list = [
        KeepTogether([_paragraph(section.title, styles["section"])])
    ]

    if not section.available:
        flowables.append(
            _paragraph(section.notice or "This section is not available.", styles["notice"])
        )
        return flowables

    metrics = _metrics_table(section.metrics, styles)
    if metrics is not None:
        flowables.append(metrics)

    for table in section.tables:
        flowables.append(_paragraph(table.title, styles["table"]))
        if table.is_empty:
            flowables.append(
                _paragraph(table.notice or EMPTY_NOTICE, styles["notice"])
            )
        else:
            flowables.append(_data_table(table, styles))

    return flowables


def _build_story(content: ReportContent, styles) -> list:
    """Return the whole document as a list of flowables."""
    story: list = [
        _paragraph(content.title, styles["title"]),
        _paragraph(_subtitle(content), styles["subtitle"]),
        _paragraph("Summary", styles["section"]),
    ]

    summary = _metrics_table(content.summary, styles)
    if summary is not None:
        story.append(summary)

    if content.is_empty:
        story.append(_paragraph(EMPTY_NOTICE, styles["notice"]))

    for index, section in enumerate(content.sections):
        if index > 0:
            story.append(Spacer(1, 6))
        story.extend(_section_story(section, styles))

    return story


def render_pdf(content: ReportContent) -> bytes:
    """Render a report as PDF bytes (M17.8).

    Args:
        content: The assembled report. Nothing is read from anywhere else, so this
            document and the CSV rendered from the same content cannot disagree.

    Returns:
        The encoded document, ready to write to disk.

    Raises:
        ReportGenerationError: If ReportLab could not produce the document. The
            message names the situation and carries no traceback or path; the real
            exception is logged (M17.14).
    """
    _register_fonts()
    styles = _styles()
    buffer = io.BytesIO()
    try:
        document = SimpleDocTemplate(
            buffer,
            pagesize=PAGE_SIZE,
            leftMargin=PAGE_MARGIN,
            rightMargin=PAGE_MARGIN,
            topMargin=PAGE_MARGIN + 8 * mm,
            bottomMargin=PAGE_MARGIN + 4 * mm,
            title=content.title,
            author="NetWatch AI",
            subject=f"{content.report_type} network report",
        )
        document.build(_build_story(content, styles), canvasmaker=_canvas_maker(content.title))
    except ReportGenerationError:
        raise
    except Exception as exc:  # noqa: BLE001 - translated below, logged here
        logger.exception("Report PDF could not be rendered")
        raise ReportGenerationError(
            "The report PDF could not be generated"
        ) from exc

    payload = buffer.getvalue()
    if not payload.startswith(b"%PDF"):
        # A PDF that does not begin with its own signature is not a PDF. Checking
        # here means the service never stores a file a reader cannot open, which is
        # the difference between a failed generation and a corrupt artifact.
        raise ReportGenerationError("The generated report PDF was not a valid document")
    logger.info("Rendered report PDF (%d byte(s))", len(payload))
    return payload


__all__ = [
    "FRAME_WIDTH",
    "PAGE_MARGIN",
    "PAGE_SIZE",
    "render_pdf",
]
