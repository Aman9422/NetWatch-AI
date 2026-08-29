"""AI insight model for NetWatch AI."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.mixins import utcnow

if TYPE_CHECKING:
    from app.models.alert import Alert


class AiInsight(Base):
    """AI-generated analysis associated with a network event or alert.

    Attributes:
        alert_id: Related alert (optional).
        device_id: Related device (optional).
        insight_type: ``alert_summary``, ``device_analysis``,
            ``traffic_summary``, or ``investigation_guidance``.
        summary: Short AI summary.
        explanation: Detailed explanation.
        recommendation: Recommended next action.
        confidence: 0-100 AI confidence.
        model_name: Model used to generate the insight.
    """

    __tablename__ = "ai_insights"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[int | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL"),
        nullable=True,
    )
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
    )
    insight_type: Mapped[str] = mapped_column(String(50), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    model_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)

    alert: Mapped["Alert"] = relationship(back_populates="ai_insights")
