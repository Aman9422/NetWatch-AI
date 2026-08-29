"""Detection rule repository for NetWatch AI."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.detection_rule import DetectionRule
from app.repositories.base import BaseRepository


class DetectionRuleRepository(BaseRepository[DetectionRule]):
    """Repository for detection rule queries."""

    def __init__(self, db: Session) -> None:
        super().__init__(db, DetectionRule)

    def get_by_rule_key(self, rule_key: str) -> DetectionRule | None:
        """Return the rule with a matching stable rule key."""
        stmt = select(DetectionRule).where(DetectionRule.rule_key == rule_key)
        return self.db.scalar(stmt)

    def get_enabled(self) -> list[DetectionRule]:
        """Return all enabled rules."""
        stmt = (
            select(DetectionRule)
            .where(DetectionRule.enabled == 1)
            .order_by(DetectionRule.id)
        )
        return list(self.db.scalars(stmt).all())

    def get_by_detection_type(self, detection_type: str) -> list[DetectionRule]:
        """Return rules belonging to a detection category."""
        stmt = (
            select(DetectionRule)
            .where(DetectionRule.detection_type == detection_type)
            .order_by(DetectionRule.id)
        )
        return list(self.db.scalars(stmt).all())

    def get_by_severity(self, severity: str) -> list[DetectionRule]:
        """Return rules with a default severity."""
        stmt = (
            select(DetectionRule)
            .where(DetectionRule.severity == severity)
            .order_by(DetectionRule.id)
        )
        return list(self.db.scalars(stmt).all())
