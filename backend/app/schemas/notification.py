"""Read-only wire schemas for stored notifications (M13.23).

A notification is a record the application wrote for a human to read: a title, a
body, a category and whether it has been read. These models expose exactly that.

There is deliberately **no delivery state** here — no "sent", no "channel", no
"delivered_at". The base application has no external notification integration, so
nothing is ever dispatched, and a field implying otherwise would claim a subsystem
that does not exist (M13.23).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from app.schemas.alert import to_iso_timestamp

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.models.notification import Notification


class NotificationView(BaseModel):
    """Serializable snapshot of one stored notification (M13.23)."""

    notification_id: int
    user_id: int | None = Field(
        default=None, description="Target user, when the record names one"
    )
    title: str
    message: str = ""
    notification_type: str = Field(
        default="", description="Category, e.g. new_alert or system_warning"
    )
    is_read: bool = Field(default=False, description="Whether it has been read")
    created_at: str | None = Field(default=None, description="ISO-8601 UTC")
    created_at_epoch: float | None = Field(
        default=None, description="The same instant in epoch seconds (M13.26)"
    )

    @classmethod
    def from_record(cls, record: "Notification") -> "NotificationView":
        """Project a stored notification row onto this model.

        ``is_read`` is stored as an integer because that is the M2 column type;
        it is reported as a boolean because that is what it means. The conversion
        is explicit here rather than left to a client to interpret ``0``/``1``.
        """
        created = record.created_at
        epoch: float | None = None
        if isinstance(created, datetime):
            aware = (
                created
                if created.tzinfo is not None
                else created.replace(tzinfo=timezone.utc)
            )
            epoch = aware.timestamp()
        return cls(
            notification_id=int(record.id),
            user_id=record.user_id,
            title=str(record.title),
            message=str(record.message or ""),
            notification_type=str(record.notification_type),
            is_read=bool(record.is_read),
            created_at=to_iso_timestamp(created),
            created_at_epoch=epoch,
        )


class NotificationListData(BaseModel):
    """Payload of the notification-collection endpoint (M13.23/M13.24)."""

    count: int = 0
    total: int = 0
    limit: int = 100
    offset: int = 0
    has_more: bool = False
    notifications: list[NotificationView] = Field(default_factory=list)


__all__ = ["NotificationListData", "NotificationView"]
