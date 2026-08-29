"""Report model for NetWatch AI."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.mixins import utcnow

if TYPE_CHECKING:
    from app.models.user import User


class Report(Base):
    """Metadata for a generated report.

    The actual report file may live on the local filesystem; only a reference
    is stored here.

    Attributes:
        name: Report name.
        report_type: ``daily``, ``weekly``, or ``custom``.
        format: ``PDF`` or ``CSV``.
        generated_by: Foreign key to the user who created it (optional).
        file_path: Where the report file is stored.
        generated_at: When the report was generated.
    """

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[str] = mapped_column(String(50), nullable=False)
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    generated_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)

    generator: Mapped["User"] = relationship(back_populates="reports")
