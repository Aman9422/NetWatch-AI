"""Shared model mixins and helpers for NetWatch AI."""

from datetime import datetime, timezone

from sqlalchemy import DateTime, func
from sqlalchemy.orm import Mapped, mapped_column


def utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime.

    ``datetime.utcnow()`` is deprecated since Python 3.12 in favour of
    timezone-aware objects. This helper is the standard replacement and is
    used as the ``default`` for columns that should default to "now".
    """
    return datetime.now(timezone.utc)


class TimestampMixin:
    """Adds ``created_at`` and ``updated_at`` columns to a model.

    A *mixin* is a small class you can "mix into" other classes. Any model
    that inherits from this gets the two timestamp columns automatically,
    so you don't have to type them out in every model.

    ``server_default=func.now()`` tells the database itself to fill in the
    current time when a row is inserted — no Python code needed.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
