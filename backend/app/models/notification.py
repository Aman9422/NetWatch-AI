"""Notification model for NetWatch AI."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.mixins import utcnow

if TYPE_CHECKING:
    from app.models.user import User


class Notification(Base):
    """A user-visible notification.

    Attributes:
        user_id: Target user (optional).
        title: Notification title.
        message: Notification content.
        notification_type: Category (``new_alert``, ``capture_started``,
            ``capture_stopped``, ``report_generated``, ``system_warning``).
        is_read: Whether the notification has been read.
        created_at: Creation time.
    """

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    notification_type: Mapped[str] = mapped_column(String(50), nullable=False)
    is_read: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)

    user: Mapped["User"] = relationship(back_populates="notifications")
