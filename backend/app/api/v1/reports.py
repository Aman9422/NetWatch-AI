"""Report API endpoints for NetWatch AI (M13.20).

Read-only over the ``reports`` table, which stores report **metadata**. Report
*generation* is M17 and is not implemented, so ``POST /reports/generate`` answers
``501 FEATURE_NOT_IMPLEMENTED`` rather than fabricating a file or a row. That is
the honest answer: this application has no report writer, and a route that
appeared to produce one would be claiming a subsystem that does not exist.

The metadata that *is* stored is exposed, because it is real: a name, a type, a
format, who asked for it and when it was produced. ``file_path`` is deliberately
not part of any response — it is an internal filesystem location, and M13.30
forbids exposing one. The omission lives in the schema rather than in a filter
here, so no code path can forget it.

Filtering is by exact stored value. The route folds case, because "PDF" and "pdf"
are the same format to every human, but it does not translate an unknown value
into a known one: an unrecognised filter selects nothing, which is the truthful
answer for a value the store does not hold (M13.25).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query

from app.api.common import (
    ErrorCode,
    FeatureNotImplementedError,
    NotFoundError,
    PageWindow,
    page_meta,
    pagination_params,
    success_payload,
)
from app.api.v1.deps import get_report_repository
from app.repositories.report import ReportRepository
from app.schemas.report import ReportListData, ReportView

logger = logging.getLogger(__name__)

router = APIRouter()

GENERATION_MESSAGE = (
    "Report generation is not implemented. M13 exposes stored report metadata; "
    "producing reports is owned by a later milestone."
)


@router.get("", response_model=None)
def list_reports(
    report_type: str | None = Query(
        default=None, description="Keep only reports of this stored type"
    ),
    format: str | None = Query(
        default=None, description="Keep only reports in this stored format"
    ),
    window: PageWindow = Depends(pagination_params),
    repository: ReportRepository = Depends(get_report_repository),
) -> dict:
    """Return stored report metadata, newest first (M13.20).

    Ordering is ``generated_at DESC, id DESC`` — the natural order with the
    primary key as a tie-break, so the order is total and two identical requests
    return the same page (M13.24). ``total`` comes from a count over the same
    filters, so a page and its total cannot disagree.
    """
    type_value = report_type.strip() if report_type else None
    format_value = format.strip().upper() if format else None

    rows = repository.list_reports(
        report_type=type_value or None,
        report_format=format_value,
        limit=window.limit,
        offset=window.offset,
    )
    total = repository.count_reports(
        report_type=type_value or None, report_format=format_value
    )
    payload = ReportListData(
        **page_meta(len(rows), window, total=total),
        reports=[ReportView.from_record(row) for row in rows],
    )
    logger.info("Returning %d of %d report(s) via API", payload.count, payload.total)
    return success_payload("Reports retrieved", payload.model_dump(mode="json"))


@router.post("/generate", response_model=None)
def generate_report() -> dict:
    """Refuse to generate a report (M13.20).

    Raises:
        FeatureNotImplementedError: Always. M17 owns report generation; this
            milestone exposes stored metadata and nothing more.
    """
    logger.info("Report generation requested; the feature is not implemented")
    raise FeatureNotImplementedError(GENERATION_MESSAGE, field="report_generation")


@router.get("/{report_id}", response_model=None)
def get_report(
    report_id: int,
    repository: ReportRepository = Depends(get_report_repository),
) -> dict:
    """Return one stored report's metadata, or ``404`` when unknown (M13.20)."""
    row = repository.get_by_id(report_id)
    if row is None:
        logger.info("Report lookup failed for id %d", report_id)
        raise NotFoundError(
            "Report not found", code=ErrorCode.REPORT_NOT_FOUND, field="report_id"
        )
    return success_payload(
        "Report retrieved", ReportView.from_record(row).model_dump(mode="json")
    )


__all__ = ["GENERATION_MESSAGE", "router"]
