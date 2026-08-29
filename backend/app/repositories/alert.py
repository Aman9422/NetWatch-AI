"""Alert repository for NetWatch AI."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.repositories.base import BaseRepository


class AlertRepository(BaseRepository[Alert]):
    """Repository for alert queries."""

    def __init__(self, db: Session) -> None:
        super().__init__(db, Alert)

    def get_by_severity(self, severity: str, *, limit: int = 100) -> list[Alert]:
        """Return alerts matching a severity level."""
        stmt = (
            select(Alert)
            .where(Alert.severity == severity)
            .order_by(Alert.created_at.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_by_status(self, status: str, *, limit: int = 100) -> list[Alert]:
        """Return alerts matching a status."""
        stmt = (
            select(Alert)
            .where(Alert.status == status)
            .order_by(Alert.created_at.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_by_device(self, device_id: int, *, limit: int = 100) -> list[Alert]:
        """Return alerts linked to a device."""
        stmt = (
            select(Alert)
            .where(Alert.device_id == device_id)
            .order_by(Alert.created_at.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_by_rule(self, rule_id: int, *, limit: int = 100) -> list[Alert]:
        """Return alerts triggered by a detection rule."""
        stmt = (
            select(Alert)
            .where(Alert.rule_id == rule_id)
            .order_by(Alert.created_at.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_unresolved(self, *, limit: int = 100) -> list[Alert]:
        """Return alerts that are not yet resolved or false positives."""
        stmt = (
            select(Alert)
            .where(Alert.status.notin_(("resolved", "false_positive")))
            .order_by(Alert.created_at.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_high_priority(self, min_severity: str = "high", *, limit: int = 100) -> list[Alert]:
        """Return alerts at or above a severity threshold.

        Severity ordering is ``critical`` > ``high`` > ``medium`` > ``low``.
        This method treats ``min_severity`` as a minimum and returns alerts
        whose severity is in the set at or above that level.
        """
        priority = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = priority[min_severity]
        stmt = (
            select(Alert)
            .where(Alert.severity.in_([s for s, p in priority.items() if p >= threshold]))
            .order_by(Alert.severity, Alert.created_at.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())
