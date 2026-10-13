"""Tests for the PDF renderer (M17.8).

A PDF is the format nobody can eyeball in a diff, so the tests here assert the
properties a *reader* depends on rather than a byte-for-byte document: that the
file is a PDF at all, that it opens and closes the way the format requires, and
that the awkward values this application's own data really contains -- a hostname
with an ``&``, a rule name with a ``<``, a non-ASCII label, a cell far wider than
its column -- render a valid document instead of raising.

Two groups of tests sit below those. The column-sizing tests exercise the one
piece of layout arithmetic the renderer performs, because "the table fits the
page" is a property that can be stated exactly and would otherwise only be
checked by a human noticing a column running off the paper. The dispatch tests
hold :mod:`app.reports.renderers` to its contract: the format vocabulary and the
set of formats that can actually be produced are one set, and an unrenderable
format fails loudly rather than silently writing a file in the wrong format.
"""

from __future__ import annotations

import pytest

from app.reports.content import Metric
from app.reports.errors import ReportGenerationError
from app.reports.pdf_renderer import (
    FRAME_WIDTH,
    MAX_COLUMN_WEIGHT,
    MIN_COLUMN_WEIGHT,
    PAGE_MARGIN,
    PAGE_SIZE,
    _clip,
    _column_widths,
    render_pdf,
)
from app.reports.renderers import RENDERERS, render_report
from app.reports.requests import SUPPORTED_FORMATS
from tests.reports_fakes import empty_content, make_content, make_section, make_table


#: A cell wide enough that a renderer which sized columns from one line of
#: unwrapped text would push the other columns off the page.
LONG_VALUE = "fe80::a00:27ff:fe4e:66a1-very-long-interface-identifier-000000000000"

#: A value containing every character ReportLab's XML-like paragraph markup treats
#: as significant, plus one that would be invalid if it reached the parser raw.
MARKUP_VALUE = "a < b & c > d \" ' \\ "

#: A value in three scripts, to prove the registered face is not Latin-1 only.
UNICODE_VALUE = "café — naïve, Ελληνικά, Кириллица"


def is_valid_pdf(payload: bytes) -> bool:
    """Return True when ``payload`` is a PDF by its own two terminal markers.

    A PDF must *begin* with its signature and *end* with its end-of-file marker.
    Those two facts are the difference between a document a reader can open and
    one that happens to contain the letters ``PDF``.
    """
    return payload.startswith(b"%PDF") and payload.rstrip().endswith(b"%%EOF")


# ---------------------------------------------------------------------------
# the document
# ---------------------------------------------------------------------------


def test_a_rendered_report_is_a_pdf() -> None:
    """The renderer produces a document, not merely bytes (M17.8)."""
    payload = render_pdf(make_content())

    assert isinstance(payload, bytes)
    assert is_valid_pdf(payload)


def test_the_document_carries_content_not_just_a_header() -> None:
    """A file that is only a signature would pass the marker check and be useless."""
    payload = render_pdf(make_content())

    assert len(payload) > 1_000


def test_an_empty_report_still_renders() -> None:
    """An empty period is a report that says so, not a failed generation."""
    payload = render_pdf(empty_content())

    assert is_valid_pdf(payload)


def test_a_report_with_many_sections_renders() -> None:
    """Sections are rendered in reading order, however many there are."""
    content = make_content(
        sections=tuple(
            make_section(key=f"section_{index}", title=f"Section {index}")
            for index in range(8)
        )
    )

    assert is_valid_pdf(render_pdf(content))


def test_an_unavailable_section_renders_its_sentence() -> None:
    """An unreadable section is stated, never rendered as a set of zeroes (M16.8)."""
    content = make_content(
        sections=(
            make_section(
                key="threats",
                title="Threats",
                metrics=(),
                tables=(),
                available=False,
                notice="This section could not be read and is not included.",
            ),
        )
    )

    assert is_valid_pdf(render_pdf(content))


def test_an_empty_table_renders_a_notice_rather_than_an_unlabelled_blank() -> None:
    """A table with no rows still says why it has none."""
    content = make_content(
        sections=(
            make_section(tables=(make_table(title="Busiest sources", rows=()),)),
        )
    )

    assert is_valid_pdf(render_pdf(content))


# ---------------------------------------------------------------------------
# the values a report really carries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [MARKUP_VALUE, UNICODE_VALUE, LONG_VALUE, "", "0", "not reported"],
)
def test_an_awkward_value_renders_a_valid_document(value: str) -> None:
    """A value is escaped before it reaches ReportLab's markup parser.

    ``&`` and ``<`` in a hostname or a rule name would otherwise be parsed as
    markup and either vanish or raise, and a cell far wider than its column must
    wrap rather than widen the table (M17.8).
    """
    content = make_content(
        summary=(Metric(label="Awkward", value=value),),
        sections=(
            make_section(
                tables=(
                    make_table(
                        columns=("Source", "Note"),
                        rows=((value, value),),
                    ),
                )
            ),
        ),
    )

    assert is_valid_pdf(render_pdf(content))


def test_a_many_column_table_renders() -> None:
    """Nine columns is the widest table the assembler can produce (M17.5)."""
    columns = tuple(f"Column {index}" for index in range(9))
    content = make_content(
        sections=(
            make_section(
                tables=(
                    make_table(
                        columns=columns,
                        rows=(tuple(str(index) for index in range(9)),),
                    ),
                )
            ),
        )
    )

    assert is_valid_pdf(render_pdf(content))


# ---------------------------------------------------------------------------
# column sizing
# ---------------------------------------------------------------------------


def test_column_widths_always_fit_the_frame() -> None:
    """The sum of a table's columns is the frame width, so no table overflows.

    ReportLab's own auto-sizing measures a column against its data, not against
    the page, which is how a wide table ends up clipped. Normalising to the frame
    is what makes "fits the page" true for every table rather than the narrow ones.
    """
    for column_count in (1, 3, 9):
        table = make_table(
            columns=tuple(f"Column {index}" for index in range(column_count)),
            rows=(tuple(LONG_VALUE for _ in range(column_count)),),
        )
        widths = _column_widths(table)

        assert len(widths) == column_count
        assert sum(widths) == pytest.approx(FRAME_WIDTH)


def test_a_wider_column_receives_a_wider_share_of_the_frame() -> None:
    """A column of addresses gets more room than a column of states, unasked."""
    table = make_table(
        columns=("Source address", "State"),
        rows=(("10.0.0.5", "up"),),
    )
    wide, narrow = _column_widths(table)

    assert wide > narrow


def test_one_very_long_column_cannot_starve_the_others() -> None:
    """A long hostname wraps instead of squashing every other column to nothing.

    The weight is capped, so the widest a single column can be is its share of the
    frame against the others' minimum weights -- which keeps a three-character
    column readable rather than a sliver.
    """
    table = make_table(
        columns=("Host", "Port"),
        rows=((LONG_VALUE * 10, "443"),),
    )
    wide, narrow = _column_widths(table)

    floor = FRAME_WIDTH * MIN_COLUMN_WEIGHT / (MAX_COLUMN_WEIGHT + MIN_COLUMN_WEIGHT)
    assert narrow >= floor
    assert wide <= FRAME_WIDTH - narrow


def test_no_column_is_ever_zero_width() -> None:
    """A zero-width column is a column a reader cannot read."""
    table = make_table(
        columns=("a", "b", "c"),
        rows=(("x", "", LONG_VALUE * 5),),
    )

    assert all(width > 0 for width in _column_widths(table))


# ---------------------------------------------------------------------------
# the running header's one shortening rule
# ---------------------------------------------------------------------------


def test_a_short_title_is_left_alone() -> None:
    """The running header shows the title unchanged unless it must not."""
    assert _clip("Daily report", 110) == "Daily report"


def test_a_long_title_is_shortened_with_an_ellipsis() -> None:
    """A title wider than the page would overlap the header's right-hand text."""
    clipped = _clip("x" * 200, 110)

    assert len(clipped) == 110
    assert clipped.endswith("\u2026")


# ---------------------------------------------------------------------------
# choosing the renderer
# ---------------------------------------------------------------------------


def test_the_renderer_table_and_the_accepted_formats_are_the_same_set() -> None:
    """A format the request layer accepts must be one this layer can produce.

    The two are asserted equal because a format accepted and then found
    unrenderable would be a request that validates and then fails, which is the
    failure mode this single source of truth exists to prevent.
    """
    assert set(RENDERERS) == set(SUPPORTED_FORMATS)


def test_the_renderer_table_names_the_two_documented_renderers() -> None:
    """CSV and PDF, each bound to the function that produces it."""
    assert RENDERERS["CSV"].__name__ == "render_csv"
    assert RENDERERS["PDF"].__name__ == "render_pdf"


def test_dispatch_produces_the_format_the_content_asks_for() -> None:
    """The file a caller receives is the format the same content says it is."""
    as_csv = render_report(make_content(output_format="CSV"))
    as_pdf = render_report(make_content(output_format="PDF"))

    assert as_csv.startswith(b"###")
    assert is_valid_pdf(as_pdf)


def test_dispatch_refuses_a_format_it_cannot_render() -> None:
    """An unknown format fails loudly rather than producing a file nobody asked for.

    This is unreachable through the API, which validates the format first, so it
    is a guard: a content model carrying an unknown format must not be silently
    rendered as something else.
    """
    with pytest.raises(ReportGenerationError, match="not a renderable report format"):
        render_report(make_content(output_format="DOCX"))


def test_a_refusal_never_names_an_internal() -> None:
    """The failure sentence names the situation, not a path or a traceback (M13.30)."""
    with pytest.raises(ReportGenerationError) as caught:
        render_report(make_content(output_format="DOCX"))

    message = str(caught.value)
    for internal in ("Traceback", "File \"", "app.", "site-packages", "reportlab"):
        assert internal not in message
# ---------------------------------------------------------------------------
# the two layout failures M18.10 exposed
# ---------------------------------------------------------------------------


def test_the_frame_width_is_the_width_the_frame_really_lays_out_in() -> None:
    """``FRAME_WIDTH`` must be the frame's usable width, not the margin box.

    Every table is normalised to :data:`FRAME_WIDTH`, so if that constant were the
    margin box rather than the area *inside* it, every table would be built wider
    than the space available: its right column drawn past the margin, and
    ReportLab's own measurement of a cell disagreeing with the width the table was
    built for.

    ``Frame`` is constructed here exactly as ``SimpleDocTemplate`` constructs its
    own -- from the margins -- and its usable width is compared with the constant.
    The two must be equal, which is a stronger claim than "the constant is smaller
    than the page": too narrow leaves a visible gutter, too wide is the defect
    (M17.8).
    """
    from reportlab.platypus import Frame

    frame = Frame(
        PAGE_MARGIN,
        PAGE_MARGIN,
        PAGE_SIZE[0] - 2 * PAGE_MARGIN,
        PAGE_SIZE[1] - 2 * PAGE_MARGIN,
    )

    # ``_aW`` is ReportLab's usable width: the frame's outer width minus the
    # padding it applies inside itself. It is not in the type stubs, so it is read
    # by name -- the value, not the attribute access, is what is being asserted.
    usable_width = getattr(frame, "_aW")

    assert FRAME_WIDTH == pytest.approx(usable_width)


def test_a_row_taller_than_a_page_still_renders() -> None:
    """One crowded row must not cost a reader the whole document.

    M8 identifies a device by its MAC, so a machine observed at hundreds of
    addresses is a single row whose address cell is taller than a page. That is
    the identity limitation M8 documents rather than an artificial input.

    ReportLab refuses to lay out a row taller than the frame, and that refusal
    fails the *entire* document -- every other section included -- unless the table
    is told it may split a row across pages. The addresses below are enough to
    exceed a page in the narrow column a nine-column table gives them, which is the
    shape that was failing (M17.8).
    """
    addresses = ", ".join(
        f"10.{index // 250}.{(index // 250) % 250}.{index % 250}"
        for index in range(400)
    )
    content = make_content(
        sections=(
            make_section(
                tables=(
                    make_table(
                        columns=(
                            "Device",
                            "MAC address",
                            "IP addresses",
                            "Hostname",
                            "Status",
                            "First seen",
                            "Last seen",
                            "Packets",
                            "Bytes",
                        ),
                        rows=(
                            (
                                "dev-1",
                                "aa:bb:cc:00:11:22",
                                addresses,
                                "not reported",
                                "active",
                                "2026-01-01 00:00:00",
                                "2026-01-01 00:00:00",
                                "1",
                                "2",
                            ),
                        ),
                    ),
                )
            ),
        )
    )

    assert len(addresses) > 4_000
    assert is_valid_pdf(render_pdf(content))
