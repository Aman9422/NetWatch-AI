"""Notification repository: stored user-visible notifications (M13.23).

Read-only by design. No external delivery integration exists in the base
application, so nothing here sends anything: the endpoints built on this
repository report the records that are stored and claim nothing more (M13.23).

The table is written by the application's own event handlers, not by this API.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.notification import Notification
from app.repositories.base import BaseRepository


class NotificationRepository(BaseRepository[Notification]):
    """Reads stored notifications (M13.23)."""

    def __init__(self, db: Session) -> None:
        super().__init__(db, Notification)

    def get_by_id(self, notification_id: int) -> Notification | None:
        """Return one notification row by id, or ``None`` when unknown."""
        return self.db.get(Notification, int(notification_id))

    def list_notifications(
        self,
        *,
        unread_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Notification]:
        """Return stored notifications, newest first.

        Ordering is ``created_at DESC, id DESC``. The primary key tie-break makes
        the order total, so two identical requests return the same page even when
        several notifications share a timestamp (M13.24).
        """
        statement = self._filtered(select(Notification), unread_only=unread_only)
        statement = (
            statement.order_by(Notification.created_at.desc(), Notification.id.desc())
            .limit(int(limit))
            .offset(int(offset))
        )
        return list(self.db.scalars(statement).all())

    def count_notifications(self, *, unread_only: bool = False) -> int:
        """Count notifications matching the same filter as :meth:`list_notifications`."""
        statement = self._filtered(
            select(func.count()).select_from(Notification), unread_only=unread_only
        )
        return int(self.db.scalar(statement) or 0)

    @staticmethod
    def _filtered(statement, *, unread_only: bool):
        """Apply the shared notification filters to a select statement."""
        if unread_only:
            statement = statement.where(Notification.is_read == 0)
        return statement


__all__ = ["NotificationRepository"]
