"""User model for NetWatch AI."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.mixins import TimestampMixin

if TYPE_CHECKING:
    from app.models.notification import Notification
    from app.models.report import Report


class User(TimestampMixin, Base):
    """Application user account.

    The initial local version may run without authentication, but this table
    provides the foundation for future login and role-based access control.

    Attributes:
        id: Primary key.
        username: Unique login name.
        email: Unique email address (optional).
        password_hash: Secure one-way hash, never a plaintext password.
        role: User permission level: ``admin``, ``analyst``, or ``viewer``.
        last_login: Most recent successful login time (optional).
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(Text, unique=True, nullable=True)
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="viewer")
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # One user can generate many reports and receive many notifications.
    reports: Mapped[list["Report"]] = relationship(back_populates="generator")
    notifications: Mapped[list["Notification"]] = relationship(back_populates="user")
