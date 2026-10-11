"""The M17 reporting layer.

One package, because a report is one pipeline and its stages must be readable in
one place (M17.2). The stages are separate modules, each with one job:

* :mod:`app.reports.period` — resolves a *reporting period*: the daily preset,
  the weekly preset, or a caller-supplied range (M17.4–M17.6).
* :mod:`app.reports.requests` — validates the loose values a route received into
  one canonical :class:`~app.reports.requests.ReportRequest`, refusing a
  contradiction rather than adjusting it (M17.4).
* :mod:`app.reports.content` — the *report content model*, the one structure both
  renderers consume, so CSV and PDF cannot disagree about what a report says
  (M17.3).
* :mod:`app.reports.assembler` — fills that model from the analytics views and
  services that already exist (M16), computing nothing of its own.
* :mod:`app.reports.csv_renderer` and :mod:`app.reports.pdf_renderer` — turn the
  model into bytes (M17.7/M17.8); :mod:`app.reports.renderers` picks between them
  from the content's own format field.
* :mod:`app.reports.storage` — writes and resolves artifacts inside one
  configurable directory, and refuses to touch anything outside it (M17.9).
* :mod:`app.reports.status` — the generation-status vocabulary a stored row
  carries.
* :mod:`app.reports.errors` — the failures this layer raises, with sentences that
  name no table, path or traceback (M17.14).
* :mod:`app.reports.service` — coordinates the pipeline and persists the
  metadata, so a route stays a thin adapter (M17.12).

Nothing in this package captures packets, detects anything, or scores risk. It
reads what M6–M12 already produced and writes it down.
"""

from app.reports.content import (
    NOT_REPORTED,
    SUMMARY_SECTION,
    Metric,
    ReportContent,
    ReportSection,
    ReportTable,
)
from app.reports.errors import (
    ReportArtifactMissing,
    ReportError,
    ReportGenerationError,
    ReportRequestError,
)
from app.reports.period import (
    CUSTOM,
    DAILY,
    MAX_REPORT_PERIOD_SECONDS,
    REPORT_TYPES,
    WEEKLY,
    ReportPeriod,
    resolve_custom,
    resolve_daily,
    resolve_weekly,
)
from app.reports.renderers import RENDERERS, render_report
from app.reports.requests import (
    DEFAULT_FORMAT,
    DEFAULT_REPORT_TYPE,
    SUPPORTED_FORMATS,
    ReportRequest,
    build_request,
    resolve_period,
)
from app.reports.service import GeneratedReport, ReportService
from app.reports.status import DEFAULT_STATUS, ReportStatus

__all__ = [
    "CUSTOM",
    "DAILY",
    "DEFAULT_FORMAT",
    "DEFAULT_REPORT_TYPE",
    "DEFAULT_STATUS",
    "MAX_REPORT_PERIOD_SECONDS",
    "NOT_REPORTED",
    "RENDERERS",
    "REPORT_TYPES",
    "SUPPORTED_FORMATS",
    "SUMMARY_SECTION",
    "WEEKLY",
    "GeneratedReport",
    "Metric",
    "ReportArtifactMissing",
    "ReportContent",
    "ReportError",
    "ReportGenerationError",
    "ReportPeriod",
    "ReportRequest",
    "ReportRequestError",
    "ReportSection",
    "ReportService",
    "ReportStatus",
    "ReportTable",
    "build_request",
    "render_report",
    "resolve_custom",
    "resolve_daily",
    "resolve_period",
    "resolve_weekly",
]
