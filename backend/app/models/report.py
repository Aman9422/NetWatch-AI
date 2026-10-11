"""Report model for NetWatch AI (M2, extended by M17.9).

The ``reports`` table stores report **metadata**: which report, over which period,
in which format, where its file is, how large it is, and whether generation
finished. M13.20 read this table for its listing; M17.9 writes it.

Five columns beyond the M2 shape were added by M17 to describe a *generated*
report rather than merely a referenced one:

``period_start`` / ``period_end``
    The half-open reporting window the report covers. M2 recorded only when a
    report was *generated*, which cannot answer "which day does this cover" -- and
    for a daily report generated after midnight those are different days. Both
    columns are nullable, because a row written before M17 genuinely has no
    recorded period and a fabricated one would be a lie.
``status``
    ``generating``, ``completed`` or ``failed`` (M17.9). NOT NULL with a server
    default, so the additive migration can add it to an existing table and every
    pre-M17 row is correctly described as ``completed``: those rows were written by
    hand and always described a file that existed.
``file_size``
    The artifact's size in bytes, recorded at write time so a client can report it
    without a filesystem call. Nullable, because it is unknown for a row that
    predates the column -- and unknown is not zero.
``error``
    A safe sentence explaining a failed generation (M17.14). Nullable, and null for
    every row that succeeded and for every row that predates the column.

**No column here is a new source of truth.** ``file_path`` still holds where the
artifact is; M13.30 still forbids exposing it; the period columns describe the
same instants the analytics window does, so a report and a dashboard query for the
same day select the same rows.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.mixins import utcnow

if TYPE_CHECKING:
    from app.models.user import User


class Report(Base):
    """Metadata for a generated report.

    The report file itself lives on the local filesystem; only a reference to it,
    and the facts needed to describe it, are stored here.

    Attributes:
        name: Report name, derived from the period so two daily reports cannot
            share one (M17.6).
        report_type: ``daily``, ``weekly`` or ``custom``.
        format: ``PDF`` or ``CSV``.
        generated_by: Foreign key to the user who created it (optional).
        file_path: Where the report file is stored. Internal; never exposed
            through the API (M13.30).
        generated_at: When the report was generated.
        period_start: Inclusive lower bound of the period the report covers.
        period_end: Exclusive upper bound of the period the report covers.
        status: ``generating``, ``completed`` or ``failed``.
        file_size: The artifact's size in bytes, once written.
        error: A safe sentence explaining a failed generation, when it failed.
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

    period_start: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    period_end: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # ``server_default`` rather than only ``default``: the additive migration adds
    # this column to an existing table, and SQLite requires a default to add a NOT
    # NULL column at all. With the default in place, every pre-M17 row is described
    # as completed, which is what it was.
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="completed", server_default="completed"
    )
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    generator: Mapped["User"] = relationship(back_populates="reports")
