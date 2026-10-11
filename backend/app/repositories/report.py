"""Report repository: stored report *metadata* (M13.20, written by M17.9).

The ``reports`` table holds a description of a report — its name, type, format,
where its file lives and when it was produced — not the report itself. M13.20
exposes that metadata read-only; M17 adds the one write this layer needs, so a
generated report's row is persisted through the repository that already owns the
table rather than through a second, parallel data path.

**One insert, and the base class's own update.** Generation is a small state
machine over a single row — ``generating`` → ``completed`` or ``failed`` — and
every transition after the insert is a field assignment. :meth:`create_report`
is the only new method here, because ``BaseRepository.update`` already commits an
arbitrary field set for a row and a second wrapper around it would be a second
place for the same behaviour to drift.

**The status vocabulary is not imported here.** The values ``generating``,
``completed`` and ``failed`` belong to :mod:`app.reports.status`, and passing them
in as plain strings is what keeps this module free of a dependency on the reports
package — which matters, because the reports package imports the analytics layer,
which imports this repository. The caller that owns the vocabulary names the
state; this module stores it.

``file_path`` is stored but never exposed through the API, because it is an
internal filesystem location (M13.30).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.report import Report
from app.repositories.base import BaseRepository


class ReportRepository(BaseRepository[Report]):
    """Reads and writes stored report metadata (M13.20/M17.9)."""

    def __init__(self, db: Session) -> None:
        super().__init__(db, Report)

    def get_by_id(self, report_id: int) -> Report | None:
        """Return one report row by id, or ``None`` when unknown."""
        return self.db.get(Report, int(report_id))

    def create_report(
        self,
        *,
        name: str,
        report_type: str,
        report_format: str,
        file_path: str,
        generated_at: datetime,
        status: str,
        period_start: datetime | None = None,
        period_end: datetime | None = None,
        generated_by: int | None = None,
        file_size: int | None = None,
        error: str | None = None,
    ) -> Report:
        """Insert one report metadata row and return it with its id assigned (M17.9).

        The row is committed immediately, which is what makes the ``generating``
        status meaningful: between this call and the artifact landing on disk, a
        row exists that describes an intention rather than a file. If the process
        is interrupted in that window the row is still there and still says
        ``generating`` -- the honest description -- rather than the report
        vanishing without trace.

        ``file_path`` is supplied empty and filled in by the caller once the
        insert has assigned the id the file name is built from. An empty value is
        not a location, and :meth:`~app.reports.storage.ReportStorage.artifact_path`
        refuses to resolve it, so a row interrupted at this point can never be
        served as though it had a file.

        Args:
            name: The report's name, derived from its period (M17.6).
            report_type: ``daily``, ``weekly`` or ``custom``.
            report_format: ``CSV`` or ``PDF``, already validated by the caller.
            file_path: Where the artifact lives, or ``""`` before it is named.
            generated_at: The generation instant, naive UTC, as the column stores.
            status: The starting state, named by the caller that owns the
                vocabulary (M17.9).
            period_start: Inclusive lower bound of the covered period.
            period_end: Exclusive upper bound of the covered period.
            generated_by: Optional user id. ``None`` when no user is recorded,
                which is the honest value for a local deployment with no accounts.
            file_size: The artifact's size, unknown at insert time.
            error: A failure sentence, unknown at insert time.

        Returns:
            The persisted row, with ``id`` populated.
        """
        row = Report(
            name=str(name),
            report_type=str(report_type),
            format=str(report_format),
            generated_by=generated_by,
            file_path=str(file_path),
            generated_at=generated_at,
            period_start=period_start,
            period_end=period_end,
            status=str(status),
            file_size=file_size,
            error=error,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row

    def list_reports(
        self,
        *,
        report_type: str | None = None,
        report_format: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Report]:
        """Return report metadata, newest first.

        Ordering is ``generated_at DESC, id DESC``: the timestamp is the natural
        order and the primary key makes it total, so two identical requests
        return the same page (M13.24).
        """
        statement = self._filtered(
            select(Report), report_type=report_type, report_format=report_format
        )
        statement = (
            statement.order_by(Report.generated_at.desc(), Report.id.desc())
            .limit(int(limit))
            .offset(int(offset))
        )
        return list(self.db.scalars(statement).all())

    def count_reports(
        self, *, report_type: str | None = None, report_format: str | None = None
    ) -> int:
        """Count stored reports matching the same filters as :meth:`list_reports`."""
        statement = self._filtered(
            select(func.count()).select_from(Report),
            report_type=report_type,
            report_format=report_format,
        )
        return int(self.db.scalar(statement) or 0)

    @staticmethod
    def _filtered(statement, *, report_type: str | None, report_format: str | None):
        """Apply the shared report filters to a select statement."""
        if report_type is not None:
            statement = statement.where(Report.report_type == report_type)
        if report_format is not None:
            statement = statement.where(Report.format == report_format)
        return statement


__all__ = ["ReportRepository"]
