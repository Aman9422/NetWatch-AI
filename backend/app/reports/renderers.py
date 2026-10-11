"""Choosing the renderer for a report's format (M17.7/M17.8).

One table, one function. The table is what makes the supported-format vocabulary
and the things this layer can actually produce the same set: a format that has no
renderer is a format the layer cannot generate, and the two lists cannot drift
apart because there is only one of them.

The renderers themselves know nothing about each other and nothing about this
module. They take the same :class:`~app.reports.content.ReportContent` and return
bytes, which is the contract that lets this be a lookup rather than a branch.
"""

from __future__ import annotations

from collections.abc import Callable

from app.reports.content import ReportContent
from app.reports.csv_renderer import render_csv
from app.reports.errors import ReportGenerationError
from app.reports.pdf_renderer import render_pdf

#: The formats this layer can produce, mapped to the renderer that produces one.
#: The keys are the same canonical strings
#: :data:`~app.reports.requests.SUPPORTED_FORMATS` validates against; a test
#: asserts the two agree, so a format cannot be accepted by the request layer and
#: then be unrenderable here.
RENDERERS: dict[str, Callable[[ReportContent], bytes]] = {
    "CSV": render_csv,
    "PDF": render_pdf,
}


def render_report(content: ReportContent) -> bytes:
    """Render a report's content in the format it was asked for (M17.7/M17.8).

    Args:
        content: The assembled report. Its ``output_format`` decides the renderer,
            so the file a caller receives is always the format the same content
            says it is -- the two cannot disagree, because there is one field.

    Returns:
        The encoded document.

    Raises:
        ReportGenerationError: If the content's format has no renderer. This is
            unreachable through the API, which validates the format first, and is
            a guard rather than a supported path: a content model that somehow
            carried an unknown format must fail loudly instead of silently
            producing a file in a format nobody asked for.
    """
    format_name = str(content.output_format).upper()
    renderer = RENDERERS.get(format_name)
    if renderer is None:
        allowed = ", ".join(sorted(RENDERERS))
        raise ReportGenerationError(
            f"'{content.output_format}' is not a renderable report format "
            f"(expected one of: {allowed})"
        )
    return renderer(content)


__all__ = ["RENDERERS", "render_report"]
