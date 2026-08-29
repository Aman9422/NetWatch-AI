"""Behavioral baseline repository for NetWatch AI."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.baseline import BehavioralBaseline
from app.repositories.base import BaseRepository


class BaselineRepository(BaseRepository[BehavioralBaseline]):
    """Repository for behavioral baseline queries."""

    def __init__(self, db: Session) -> None:
        super().__init__(db, BehavioralBaseline)

    def get_by_device(self, device_id: int) -> BehavioralBaseline | None:
        """Return the baseline for a specific device.

        ``device_id`` is unique on the model, so at most one row is returned.
        """
        stmt = select(BehavioralBaseline).where(BehavioralBaseline.device_id == device_id)
        return self.db.scalar(stmt)

    def get_active(self) -> list[BehavioralBaseline]:
        """Return baselines in the ``active`` state."""
        stmt = (
            select(BehavioralBaseline)
            .where(BehavioralBaseline.status == "active")
            .order_by(BehavioralBaseline.id)
        )
        return list(self.db.scalars(stmt).all())

    def get_learning(self) -> list[BehavioralBaseline]:
        """Return baselines still in the ``learning`` state."""
        stmt = (
            select(BehavioralBaseline)
            .where(BehavioralBaseline.status == "learning")
            .order_by(BehavioralBaseline.id)
        )
        return list(self.db.scalars(stmt).all())

    def get_disabled(self) -> list[BehavioralBaseline]:
        """Return baselines that are ``disabled``."""
        stmt = (
            select(BehavioralBaseline)
            .where(BehavioralBaseline.status == "disabled")
            .order_by(BehavioralBaseline.id)
        )
        return list(self.db.scalars(stmt).all())
