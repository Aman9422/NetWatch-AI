"""Evidence repository: the ``alert_evidence`` table, and nothing else (M11.16).

Evidence rows belong to an alert and are written with it, so this repository
follows the same *stage then commit* split as the M7 packet repository: the
service stages every evidence row for an alert, then commits them in one
transaction, so an alert is never persisted with only part of its evidence.

Deletion exists for one reason — removing evidence for an alert that is being
deleted — and for no other. Evidence is otherwise append-only: rewriting it would
mean editing the record of what justified an alert, which defeats the point of
keeping evidence at all.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models.alert_evidence import AlertEvidence
from app.repositories.base import BaseRepository


class AlertEvidenceRepository(BaseRepository[AlertEvidence]):
    """Repository for persisting and querying alert evidence (M11.16)."""

    def __init__(self, db: Session) -> None:
        super().__init__(db, AlertEvidence)

    # -- writes -----------------------------------------------------------

    def stage(self, rows: Sequence[Mapping[str, object]]) -> int:
        """Stage evidence rows for insertion without committing them.

        Args:
            rows: ``alert_evidence`` column values, as produced by
                :meth:`app.alerts.evidence.AlertEvidenceRecord.to_row_values`.

        Returns:
            How many rows were staged.
        """
        records = [AlertEvidence(**dict(row)) for row in rows]
        if records:
            self.db.add_all(records)
        return len(records)

    def write_many(self, rows: Sequence[Mapping[str, object]]) -> int:
        """Insert a batch of evidence rows in one transaction.

        Returns:
            The number of rows written.

        Raises:
            Exception: Whatever the database raised, after the transaction has
                been rolled back — a failed batch never leaves an alert with
                partial evidence. The caller isolates and counts the failure.
        """
        if not rows:
            return 0
        records = [AlertEvidence(**dict(row)) for row in rows]
        try:
            self.db.add_all(records)
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return len(records)

    def commit(self) -> None:
        """Commit the staged evidence rows."""
        self.db.commit()

    def rollback(self) -> None:
        """Discard the staged evidence rows."""
        self.db.rollback()

    def delete_for_alert(self, alert_id: int) -> int:
        """Delete every evidence row of one alert; return how many were deleted.

        The ``alert_evidence.alert_id`` foreign key already cascades on delete,
        so this exists for the explicit case rather than the incidental one —
        and so a caller can report what it removed.
        """
        result = self.db.execute(
            delete(AlertEvidence).where(AlertEvidence.alert_id == alert_id)
        )
        self.db.commit()
        return int(getattr(result, "rowcount", 0) or 0)

    # -- reads ------------------------------------------------------------

    def list_for_alert(
        self,
        alert_id: int,
        *,
        evidence_type: str | None = None,
        limit: int | None = None,
    ) -> list[AlertEvidence]:
        """Return an alert's evidence, oldest first (M11.18).

        Oldest first is deliberate: evidence accumulates in the order it was
        attached, so a reader follows the same trail the service built —
        the finding, then what supported it.

        Raises:
            ValueError: If ``limit`` is not positive.
        """
        if limit is not None and limit < 1:
            raise ValueError("limit must be at least 1")
        statement = select(AlertEvidence).where(AlertEvidence.alert_id == alert_id)
        if evidence_type is not None:
            statement = statement.where(AlertEvidence.evidence_type == evidence_type)
        statement = statement.order_by(AlertEvidence.id)
        if limit is not None:
            statement = statement.limit(limit)
        return list(self.db.scalars(statement).all())

    def list_packet_evidence(
        self, alert_id: int, *, limit: int | None = None
    ) -> list[AlertEvidence]:
        """Return only the packet evidence of an alert (M11.13)."""
        return self.list_for_alert(alert_id, evidence_type="packet", limit=limit)

    def count_for_alert(self, alert_id: int) -> int:
        """Return how many evidence rows an alert has (M11.3/M11.12)."""
        return int(
            self.db.scalar(
                select(func.count())
                .select_from(AlertEvidence)
                .where(AlertEvidence.alert_id == alert_id)
            )
            or 0
        )

    def count_by_type(self, alert_id: int) -> dict[str, int]:
        """Return the evidence count per ``evidence_type`` for one alert.

        This is what makes an alert's evidence *explainable* rather than just
        numerous: the response can say "2 packets, 1 connection, 1 rule" instead
        of only "4".
        """
        statement = (
            select(AlertEvidence.evidence_type, func.count())
            .where(AlertEvidence.alert_id == alert_id)
            .group_by(AlertEvidence.evidence_type)
        )
        return {
            str(evidence_type): int(count)
            for evidence_type, count in self.db.execute(statement).all()
        }

    def count_for_alerts(self, alert_ids: Iterable[int]) -> dict[int, int]:
        """Return an evidence count per alert id, in one query (M11.18).

        A listing must not query once per row, so the counts for a whole page
        are fetched together. Ids with no evidence are absent from the result,
        which the caller reads as zero.
        """
        ids = sorted({int(alert_id) for alert_id in alert_ids})
        if not ids:
            return {}
        statement = (
            select(AlertEvidence.alert_id, func.count())
            .where(AlertEvidence.alert_id.in_(ids))
            .group_by(AlertEvidence.alert_id)
        )
        return {
            int(alert_id): int(count)
            for alert_id, count in self.db.execute(statement).all()
        }
