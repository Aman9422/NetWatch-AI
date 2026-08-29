"""Detection rule model for NetWatch AI."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.mixins import TimestampMixin

if TYPE_CHECKING:
    from app.models.alert import Alert


class DetectionRule(TimestampMixin, Base):
    """A configurable detection rule.

    Detection logic should not live entirely in hard-coded thresholds — it
    should be data-driven so analysts can tune rules without changing code.

    Attributes:
        rule_key: Stable, unique identifier (e.g. ``port_scan``).
        rule_name: Display name.
        description: Human-readable explanation.
        detection_type: Rule category (e.g. ``port_scan``, ``syn_flood``).
        severity: Default severity for alerts this rule generates.
        enabled: Whether the rule is active (1) or disabled (0).
        threshold_config: Optional JSON string of tunable thresholds.
        time_window_seconds: Detection time window.
        version: Rule version number.
    """

    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    rule_key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    detection_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    enabled: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    threshold_config: Mapped[str | None] = mapped_column(Text, nullable=True)
    time_window_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    alerts: Mapped[list["Alert"]] = relationship(back_populates="rule")

    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low')",
            name="ck_detection_rules_severity",
        ),
    )
