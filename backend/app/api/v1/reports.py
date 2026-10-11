"""Report API endpoints for NetWatch AI (M13.20, generation added by M17).

Four surfaces over one subsystem:

* ``GET /reports`` — stored report metadata, newest first, each row stating
  whether its artifact can actually be downloaded.
* ``GET /reports/{id}`` — one report's metadata.
* ``POST /reports/generate`` — produce a report and record it (M17.4–M17.12).
* ``GET /reports/{id}/download`` — serve the artifact itself (M17.11).

**Generation is a write, and answers like one.** A successful generation creates a
row and a file, so the route answers ``201`` with the standard envelope — the
stored metadata plus the summary figures the report opens with, so a client can
show what was produced without fetching the file it just asked for.

**One request body covers daily, weekly and custom.** A preset derives its period
from the UTC calendar and a custom report names its own bounds; the two are
mutually exclusive and the service refuses a request that tries to be both rather
than quietly preferring one. Splitting them into three endpoints would have meant
three copies of the same validation and three chances to disagree about defaults.

**The download is the one route that does not answer in the envelope.** A file is
not a JSON payload, so it is served as an attachment with its own media type. The
*filename* is the artifact's own name — already reduced to ``[A-Za-z0-9-]`` by the
storage layer, so it cannot inject a header — and the client never learns the
directory it lives in, which M13.30 forbids exposing.

**Every failure is a sentence.** A refusal is a ``400`` naming the field, a
generation that could not finish is a ``500`` whose message is the safe sentence
the layer already wrote, and a missing artifact is a ``404``. None of them carries
a path, a table name, a query or a traceback (M13.5/M13.30/M17.14).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import FileResponse

from app.api.common import (
    ApiError,
    BadRequestError,
    ErrorCode,
    NotFoundError,
    PageWindow,
    page_meta,
    pagination_params,
    success_payload,
)
from app.api.v1.deps import get_report_service
from app.models.report import Report
from app.reports.errors import (
    ReportArtifactMissing,
    ReportError,
    ReportRequestError,
)
from app.reports.requests import build_request
from app.reports.service import ReportService
from app.schemas.report import (
    GeneratedReportData,
    ReportGenerationRequest,
    ReportListData,
    ReportMetricView,
    ReportView,
)

logger = logging.getLogger(__name__)

router = APIRouter()

#: The media type each stored format is served as. CSV is declared UTF-8 because
#: that is what the renderer writes, so a browser picks the right decoder; PDF is
#: binary and says so. The mapping is the HTTP layer's own -- a ``Content-Type``
#: is a transport fact, not something the renderer or the store should know.
MEDIA_TYPES: dict[str, str] = {
    "CSV": "text/csv; charset=utf-8",
    "PDF": "application/pdf",
}

#: What an unrecognised stored format is served as. A report row written by hand
#: before M17 could name anything; serving it as an opaque download is honest and
#: still lets the reader open it with whatever tool knows the format.
DEFAULT_MEDIA_TYPE = "application/octet-stream"

#: The sentence a download answers with when the row exists but its file does not.
#: Deliberately the same answer whether the file was never written, was removed,
#: or is stored outside the directory -- all three are "the artifact is not
#: available", and none of them may name a path (M13.30).
ARTIFACT_MISSING_MESSAGE = "The report file is not available for download"


def media_type_for(output_format: str) -> str:
    """Return the media type a stored format is served as."""
    return MEDIA_TYPES.get(str(output_format).upper(), DEFAULT_MEDIA_TYPE)


def _as_api_error(exc: ReportError) -> ApiError:
    """Translate a reporting failure into the API's controlled error (M17.14).

    The message is the failure's own sentence, which the reporting layer already
    guarantees is free of internals. Only the status and the machine-readable code
    are decided here, because those are the HTTP layer's vocabulary.

    Args:
        exc: The failure raised by the reporting layer.

    Returns:
        The API error to raise in its place.
    """
    if isinstance(exc, ReportRequestError):
        return BadRequestError(
            exc.message, code=ErrorCode.INVALID_REQUEST, field=exc.field
        )
    if isinstance(exc, ReportArtifactMissing):
        return NotFoundError(
            ARTIFACT_MISSING_MESSAGE,
            code=ErrorCode.REPORT_NOT_FOUND,
            field=exc.field,
        )
    # Anything else is a generation that was attempted and did not finish. The
    # real cause is already logged beside the report's id; the client gets the
    # safe sentence and no detail.
    return ApiError(exc.message, code=ErrorCode.INTERNAL_ERROR, field=exc.field)


def _view(record: Report, service: ReportService) -> ReportView:
    """Project one stored row, stating whether its artifact can be downloaded.

    The availability check is asked of the storage layer rather than inferred from
    the row's status, because the two can genuinely disagree: a file removed by
    hand leaves a ``completed`` row with nothing to serve, and reporting it as
    downloadable would be a promise the next request breaks.
    """
    return ReportView.from_record(
        record, downloadable=service.artifact_is_available(record)
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
    service: ReportService = Depends(get_report_service),
) -> dict:
    """Return stored report metadata, newest first (M13.20).

    Ordering is ``generated_at DESC, id DESC`` — the natural order with the
    primary key as a tie-break, so the order is total and two identical requests
    return the same page (M13.24). ``total`` comes from a count over the same
    filters, so a page and its total cannot disagree.
    """
    type_value = report_type.strip() if report_type else None
    format_value = format.strip().upper() if format else None

    rows = service.repository.list_reports(
        report_type=type_value or None,
        report_format=format_value,
        limit=window.limit,
        offset=window.offset,
    )
    total = service.repository.count_reports(
        report_type=type_value or None, report_format=format_value
    )
    payload = ReportListData(
        **page_meta(len(rows), window, total=total),
        reports=[_view(row, service) for row in rows],
    )
    logger.info("Returning %d of %d report(s) via API", payload.count, payload.total)
    return success_payload("Reports retrieved", payload.model_dump(mode="json"))


@router.post("/generate", response_model=None, status_code=201)
def generate_report(
    body: ReportGenerationRequest | None = Body(default=None),
    service: ReportService = Depends(get_report_service),
) -> dict:
    """Generate a report and record it (M17.4–M17.12).

    A request with no body produces the previous completed UTC day as a PDF,
    because those are the layer's own documented defaults and "generate a report"
    with no further qualification means the day that just ended.

    Args:
        body: The optional request body: the preset, the format, an optional
            title and the bounds a custom period needs.
        service: The reporting service bound to this request's session.

    Returns:
        The stored metadata plus the summary block the artifact opens with.

    Raises:
        BadRequestError: If the request names an unsupported type or format, or
            supplies bounds a preset cannot honour. Raised before any row or file
            is written, so an unanswerable request changes nothing.
        ApiError: If generation was attempted and did not finish. The row is left
            marked ``failed`` with a safe sentence and no artifact.
    """
    payload = body if body is not None else ReportGenerationRequest()
    try:
        request = build_request(
            report_type=payload.report_type,
            output_format=payload.format,
            title=payload.title,
            generated_by=payload.generated_by,
            since=payload.since,
            until=payload.until,
        )
        generated = service.generate(request)
    except ReportError as exc:
        logger.info("Report generation refused or failed: %s", exc.message)
        raise _as_api_error(exc) from exc

    data = GeneratedReportData(
        report=ReportView.from_record(generated.record, downloadable=True),
        summary=[
            ReportMetricView(label=metric.label, value=metric.value)
            for metric in generated.content.summary
        ],
    )
    logger.info(
        "Generated report %d via API (%s, %d byte(s))",
        generated.report_id,
        request.output_format,
        generated.size_bytes,
    )
    return success_payload("Report generated", data.model_dump(mode="json"))


@router.get("/{report_id}", response_model=None)
def get_report(
    report_id: int,
    service: ReportService = Depends(get_report_service),
) -> dict:
    """Return one stored report's metadata, or ``404`` when unknown (M13.20)."""
    row = service.get_record(report_id)
    if row is None:
        logger.info("Report lookup failed for id %d", report_id)
        raise NotFoundError(
            "Report not found", code=ErrorCode.REPORT_NOT_FOUND, field="report_id"
        )
    return success_payload(
        "Report retrieved", _view(row, service).model_dump(mode="json")
    )


@router.get("/{report_id}/download", response_model=None)
def download_report(
    report_id: int,
    service: ReportService = Depends(get_report_service),
) -> FileResponse:
    """Serve a stored report's artifact (M17.11).

    The response is the file itself rather than the standard envelope: a document
    is not a data payload, and wrapping bytes in JSON would make the download
    useless to the browser that asked for it. The status codes still follow the
    API's conventions — the artifact is either there (``200``) or it is not
    (``404``) — and the message on failure is the same regardless of *why* the
    file is unavailable.

    Raises:
        NotFoundError: If no such report exists, or its artifact is not available
            in the storage directory. Both are ``404``, and neither names a path
            (M13.30).
    """
    row = service.get_record(report_id)
    if row is None:
        logger.info("Report download failed for unknown id %d", report_id)
        raise NotFoundError(
            "Report not found", code=ErrorCode.REPORT_NOT_FOUND, field="report_id"
        )
    try:
        path = service.artifact_path(row)
    except ReportError as exc:
        logger.info("Report %d has no downloadable artifact", report_id)
        raise _as_api_error(exc) from exc

    logger.info("Serving report artifact for id %d", report_id)
    return FileResponse(
        path=path,
        media_type=media_type_for(str(row.format)),
        # The artifact's own name is already reduced to [A-Za-z0-9-] and carries
        # the report's id, so it is safe in a header and unique in a downloads
        # folder -- and it is not the path.
        filename=path.name,
    )


__all__ = ["DEFAULT_MEDIA_TYPE", "MEDIA_TYPES", "media_type_for", "router"]
