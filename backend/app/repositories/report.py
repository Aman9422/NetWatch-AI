"""Report repository: stored report *metadata* (M13.20).

The ``reports`` table holds a description of a report — its name, type, format,
where its file lives and when it was produced — not the report itself. M13.20
exposes that metadata and nothing more: report *generation* is M17, so nothing
in this repository writes a row or produces a file.

``file_path`` is stored but never exposed through the API, because it is an
internal filesystem location (M13.30).
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.report import Report
from app.repositories.base import BaseRepository


class ReportRepository(BaseRepository[Report]):
    """Reads stored report metadata (M13.20)."""

    def __init__(self, db: Session) -> None:
        super().__init__(db, Report)

    def get_by_id(self, report_id: int) -> Report | None:
        """Return one report row by id, or ``None`` when unknown."""
        return self.db.get(Report, int(report_id))

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
