"""Notification API endpoints for NetWatch AI (M13.23).

Read-only over the ``notifications`` table. The base application has **no external
delivery integration**: nothing is emailed, pushed or posted anywhere, and these
routes claim nothing of the sort. They report the records that are stored, which
is what M13.23 allows when no delivery subsystem exists.

There is therefore no "mark as read" verb either. Changing ``is_read`` would be a
write the milestone does not ask for, and adding one would imply a read/unread
workflow the rest of the application does not participate in.

Ordering is ``created_at DESC, id DESC``: the natural order with the primary key
as a tie-break, so two notifications sharing a timestamp still come back in a
stable order and a page cannot repeat or skip a row (M13.24).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query

from app.api.common import (
    ErrorCode,
    NotFoundError,
    PageWindow,
    page_meta,
    pagination_params,
    success_payload,
)
from app.api.v1.deps import get_notification_repository
from app.repositories.notification import NotificationRepository
from app.schemas.notification import NotificationListData, NotificationView

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("", response_model=None)
def list_notifications(
    unread_only: bool = Query(
        default=False, description="Keep only notifications that have not been read"
    ),
    window: PageWindow = Depends(pagination_params),
    repository: NotificationRepository = Depends(get_notification_repository),
) -> dict:
    """Return stored notifications, newest first (M13.23).

    ``count`` is this page's size and ``total`` the size of the whole match set,
    both computed over the same filter so the two cannot disagree.
    """
    rows = repository.list_notifications(
        unread_only=unread_only, limit=window.limit, offset=window.offset
    )
    total = repository.count_notifications(unread_only=unread_only)
    payload = NotificationListData(
        **page_meta(len(rows), window, total=total),
        notifications=[NotificationView.from_record(row) for row in rows],
    )
    logger.info(
        "Returning %d of %d notification(s) via API", payload.count, payload.total
    )
    return success_payload(
        "Notifications retrieved", payload.model_dump(mode="json")
    )


@router.get("/{notification_id}", response_model=None)
def get_notification(
    notification_id: int,
    repository: NotificationRepository = Depends(get_notification_repository),
) -> dict:
    """Return one stored notification, or ``404`` when unknown (M13.23)."""
    row = repository.get_by_id(notification_id)
    if row is None:
        logger.info("Notification lookup failed for id %d", notification_id)
        raise NotFoundError(
            "Notification not found",
            code=ErrorCode.NOTIFICATION_NOT_FOUND,
            field="notification_id",
        )
    return success_payload(
        "Notification retrieved", NotificationView.from_record(row).model_dump(mode="json")
    )


__all__ = ["router"]
