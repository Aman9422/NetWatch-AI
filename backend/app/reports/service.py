"""Generating one report end to end (M17.12).

This module is the pipeline's conductor and nothing else. It resolves a period,
writes the metadata row, asks the assembler for the content, asks the renderer for
bytes, asks the storage layer to put them somewhere, and records the outcome. It
computes no figure, formats no value and touches no table other than the one
``reports`` row it owns -- each of those belongs to a module that already does it.

**The row is written before the file, and says so.** A generation is a small state
machine over one row: ``generating`` while the artifact is being produced,
``completed`` once it is on disk with its size recorded, ``failed`` with a safe
sentence when it is not. Writing the row first is what makes the middle state
observable rather than theoretical: a request interrupted mid-render leaves a row
that truthfully says the file does not exist yet, instead of leaving no trace of
the work that was attempted.

**A failure leaves nothing behind that claims otherwise.** If assembly, rendering
or the write fails, the row is marked ``failed``, any partial artifact is removed,
and the failure is re-raised as a
:class:`~app.reports.errors.ReportGenerationError` carrying a sentence an operator
can act on. The real exception is logged here, beside the report's id, and never
returned (M13.30/M17.14).

**Where the file name comes from.** The name carries the row's own id, so it can
only be built once the insert has assigned one. That is why the row is created
with an empty location and the name filled in immediately afterwards: the empty
value is not a location, and the storage layer refuses to resolve it, so a row
interrupted between the two steps can never be served as though it had a file.

**The storage directory is a collaborator, not a global.** The service takes a
:class:`~app.reports.storage.ReportStorage` rather than reaching for one, so a test
can generate a real report into a temporary directory without touching the
configured one, and so the one place that decides where files live stays the one
place that decides where files live.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app.analytics.service import AnalyticsService
from app.analytics.window import iso_from_epoch, to_utc_datetime
from app.config.settings import settings
from app.models.report import Report
from app.repositories.report import ReportRepository
from app.reports.assembler import REPORT_ROW_LIMIT, build_report_content, default_title
from app.reports.content import ReportContent
from app.reports.errors import ReportError, ReportGenerationError
from app.reports.period import ReportPeriod
from app.reports.renderers import render_report
from app.reports.requests import ReportRequest, resolve_period
from app.reports.status import ReportStatus
from app.reports.storage import ReportStorage

logger = logging.getLogger(__name__)

#: The sentence a row carries when generation failed for a reason the layer did
#: not classify. Constant, and free of any internal detail: an operator reads it,
#: the log carries the real cause (M17.14).
GENERIC_FAILURE = "The report could not be generated"


@dataclass(frozen=True)
class GeneratedReport:
    """The result of one successful generation (M17.12).

    Attributes:
        record: The persisted metadata row, already in the ``completed`` state.
        content: The assembled content the artifact was rendered from. Returned
            so a caller can report what the report *says* -- its period and its
            headline figures -- without re-reading the file it just wrote.
        path: Where the artifact was written.
        size_bytes: The artifact's size, the same figure recorded on the row.
    """

    record: Report
    content: ReportContent
    path: Path
    size_bytes: int

    @property
    def report_id(self) -> int:
        """Return the stored report's id."""
        return int(self.record.id)


def _row_limit() -> int:
    """Return how many rows a report table may carry (M17.13).

    The configured ceiling is applied, but never raised above the analytics
    layer's own group cap: a report cannot show more groups than the service it
    reads is willing to produce, and listing a larger number would only mislead.
    Lowering the setting lowers the report; raising it past the analytics ceiling
    changes nothing, which is the honest behaviour.
    """
    return max(1, min(int(settings.report_max_table_rows), REPORT_ROW_LIMIT))


class ReportService:
    """Generates reports and serves their artifacts (M17.12).

    The service holds a request-scoped database session and the analytics service
    bound to the same session, so a generation reads and writes through one
    connection. It is built per request rather than cached, for the same reason
    the analytics service is: a cached session is the exact bug that would follow
    (M13.28).
    """

    def __init__(
        self,
        *,
        db: Session,
        analytics: AnalyticsService,
        storage: ReportStorage | None = None,
    ) -> None:
        """Bind the service to this request's session, analytics and storage.

        Args:
            db: The request-scoped session, used for the report metadata row.
            analytics: The M16 analytics service, already bound to ``db``.
            storage: Where artifacts are written. Defaults to the configured
                directory; a test supplies its own.
        """
        self.db = db
        self.analytics = analytics
        self.storage = storage if storage is not None else ReportStorage()
        self.repository = ReportRepository(db)

    # -- generation -----------------------------------------------------

    def generate(self, request: ReportRequest) -> GeneratedReport:
        """Generate one report and record it (M17.12).

        Args:
            request: The already-validated request.

        Returns:
            The stored row, the content it was rendered from and where the
            artifact landed.

        Raises:
            ReportRequestError: If the request's period cannot be resolved. Raised
                before any row is written, so an unanswerable request leaves the
                store untouched.
            ReportGenerationError: If assembly, rendering or the write failed. The
                report's row is marked ``failed`` first, so the store never claims
                a file that is not there.
        """
        period = resolve_period(request)
        generated_at = iso_from_epoch(request.now)
        row = self._open_row(request=request, period=period)
        filename = self.storage.filename_for(
            report_id=int(row.id),
            label=period.label(),
            output_format=request.output_format,
        )
        self.repository.update(row, file_path=filename)

        try:
            content = build_report_content(
                analytics=self.analytics,
                period=period,
                output_format=request.output_format,
                generated_at=generated_at,
                report_id=int(row.id),
                title=row.name,
                row_limit=_row_limit(),
            )
            payload = render_report(content)
            artifact = self.storage.write(filename=filename, payload=payload)
        except ReportError as exc:
            self._mark_failed(row, filename, exc.message)
            raise
        except Exception as exc:  # noqa: BLE001 - classified and re-raised below
            logger.exception("Report %d could not be generated", int(row.id))
            self._mark_failed(row, filename, GENERIC_FAILURE)
            raise ReportGenerationError(GENERIC_FAILURE) from exc

        self.repository.update(
            row,
            status=ReportStatus.COMPLETED,
            file_path=filename,
            file_size=int(artifact.size_bytes),
            error=None,
        )
        logger.info(
            "Generated report %d (%s, %s, %d byte(s)) for %s",
            int(row.id),
            request.output_format,
            period.report_type,
            artifact.size_bytes,
            period.label(),
        )
        return GeneratedReport(
            record=row,
            content=content,
            path=artifact.path,
            size_bytes=int(artifact.size_bytes),
        )

    def _open_row(self, *, request: ReportRequest, period: ReportPeriod) -> Report:
        """Write the ``generating`` metadata row and return it (M17.9).

        The title comes from the caller when one was supplied and from the period
        otherwise, so two daily reports generated in the same hour cannot share a
        name (M17.6).
        """
        title = request.title or default_title(period, request.output_format)
        return self.repository.create_report(
            name=title,
            report_type=period.report_type,
            report_format=request.output_format,
            # The real name needs the id this insert assigns, so it is filled in
            # immediately afterwards. An empty value is not a location.
            file_path="",
            generated_at=to_utc_datetime(request.now),
            status=ReportStatus.GENERATING,
            period_start=period.utc_since(),
            period_end=period.utc_until(),
            generated_by=request.generated_by,
        )

    def _mark_failed(self, row: Report, filename: str, message: str) -> None:
        """Record a failed generation and drop any partial artifact (M17.9).

        This runs on the way out of a failure, so it must not raise: a second
        exception raised while cleaning up would replace the one worth reporting.
        Both steps are attempted and any trouble is logged rather than propagated.
        """
        try:
            self.storage.delete(filename)
        except Exception:  # noqa: BLE001 - cleanup must not mask the real failure
            logger.exception(
                "Partial artifact for report %d could not be removed", int(row.id)
            )
        try:
            self.repository.update(
                row, status=ReportStatus.FAILED, error=str(message), file_size=None
            )
        except Exception:  # noqa: BLE001 - see above
            logger.exception("Report %d could not be marked failed", int(row.id))

    # -- artifacts ------------------------------------------------------

    def get_record(self, report_id: int) -> Report | None:
        """Return one stored report's metadata, or ``None`` when unknown."""
        return self.repository.get_by_id(report_id)

    def artifact_path(self, record: Report) -> Path:
        """Return the path of a stored report's artifact (M17.9).

        Delegates to the storage layer's containment check rather than resolving
        anything here, so the download path and the resolve path enforce exactly
        the same rule.

        Raises:
            ReportArtifactMissing: If the artifact is outside the storage
                directory, absent, or not a file. None of those names a path.
        """
        return self.storage.artifact_path(str(record.file_path))

    def read_artifact(self, record: Report) -> bytes:
        """Return a stored report's bytes, or raise when it is unavailable.

        Raises:
            ReportArtifactMissing: If the artifact is not available.
        """
        return self.storage.read(str(record.file_path))

    def artifact_is_available(self, record: Report) -> bool:
        """Return True when a stored report's artifact can actually be served.

        Used by the listing to say, per row, whether a download would succeed --
        without a download being attempted. A row whose status is ``completed``
        but whose file has since been removed by hand reports False, which is the
        truthful answer.
        """
        if str(record.status) != ReportStatus.COMPLETED:
            return False
        return self.storage.exists(str(record.file_path))


__all__ = [
    "GENERIC_FAILURE",
    "GeneratedReport",
    "ReportService",
]
