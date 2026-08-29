"""Alert evidence model for NetWatch AI."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.mixins import utcnow

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.packet import Packet


class AlertEvidence(Base):
    """A piece of supporting evidence associated with an alert.

    An alert can reference many evidence records. Each record may optionally
    point to the specific packet that triggered it.

    Attributes:
        alert_id: The alert this evidence belongs to.
        packet_id: Optional related packet.
        evidence_type: ``packet``, ``connection``, ``behavioral``, ``rule``,
            ``ml``, or ``device``.
        evidence_data: Structured evidence (often JSON).
    """

    __tablename__ = "alert_evidence"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
    )
    packet_id: Mapped[int | None] = mapped_column(
        ForeignKey("packets.id", ondelete="SET NULL"),
        nullable=True,
    )
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)
    evidence_data: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)

    alert: Mapped["Alert"] = relationship(back_populates="evidence_records")
    packet: Mapped["Packet"] = relationship(back_populates="evidence_records")
