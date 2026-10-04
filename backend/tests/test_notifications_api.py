"""API tests for the notifications endpoints (M13.23).

The base application has **no external delivery integration** — nothing is
emailed, pushed or posted anywhere. These tests hold the surface to exactly
that: it reports the records that are stored, and it never grows a field
implying a delivery subsystem that does not exist (``sent``, ``channel``,
``delivered_at``).

There is likewise no "mark as read" verb. Changing ``is_read`` would be a write
M13.23 does not ask for, so the absence is asserted rather than assumed.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.notification import Notification
from tests.m13_fakes import api_client, make_db_override

NOTIFICATIONS_URL = "/api/v1/notifications"

OLDER = datetime(2024, 1, 1, 8, 0, 0)
NEWER = datetime(2024, 6, 1, 8, 0, 0)

#: Fields that would claim a delivery subsystem the application does not have.
FORBIDDEN_FIELDS = ("sent", "sent_at", "channel", "delivered_at", "delivery_status")


@pytest.fixture
def client(db_engine) -> Generator[TestClient, None, None]:
    """A client reading the isolated in-memory database, not the real one."""
    with api_client({get_db: make_db_override(db_engine)}) as test_client:
        yield test_client


def store(
    session: Session,
    *,
    title: str,
    message: str = "something happened",
    notification_type: str = "new_alert",
    is_read: int = 0,
    created_at: datetime = OLDER,
) -> Notification:
    """Write one notification row as the application stores it."""
    row = Notification(
        user_id=None,
        title=title,
        message=message,
        notification_type=notification_type,
        is_read=is_read,
        created_at=created_at,
    )
    session.add(row)
    session.commit()
    return row


def iso(value: datetime) -> str:
    """Render a naive UTC datetime the way the API documents it (M13.26)."""
    return value.replace(tzinfo=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# GET /notifications
# ---------------------------------------------------------------------------


def test_empty_listing_is_well_formed(client: TestClient) -> None:
    """An empty table returns a well-formed, empty collection with a total."""
    body = client.get(NOTIFICATIONS_URL).json()

    assert body["success"] is True
    data = body["data"]
    assert data["count"] == 0
    assert data["total"] == 0
    assert data["notifications"] == []
    assert data["has_more"] is False


def test_listing_returns_stored_records(
    client: TestClient, db_session: Session
) -> None:
    """A stored notification comes back with the fields that were written."""
    store(db_session, title="Port scan detected")

    record = client.get(NOTIFICATIONS_URL).json()["data"]["notifications"][0]

    assert record["title"] == "Port scan detected"
    assert record["message"] == "something happened"
    assert record["notification_type"] == "new_alert"
    assert record["created_at"] == iso(OLDER)
    assert record["created_at_epoch"] == OLDER.replace(tzinfo=timezone.utc).timestamp()
    assert record["notification_id"] > 0


def test_is_read_is_reported_as_a_boolean(
    client: TestClient, db_session: Session
) -> None:
    """The column is an integer; the value means a boolean, and is sent as one.

    Leaving a client to interpret ``0``/``1`` would make the storage detail part
    of the contract (M13.23).
    """
    store(db_session, title="unread one", is_read=0)
    store(db_session, title="read one", is_read=1)

    by_title = {
        record["title"]: record
        for record in client.get(NOTIFICATIONS_URL).json()["data"]["notifications"]
    }

    assert by_title["unread one"]["is_read"] is False
    assert by_title["read one"]["is_read"] is True


def test_no_field_claims_a_delivery_subsystem(
    client: TestClient, db_session: Session
) -> None:
    """Nothing here implies delivery, because nothing is ever delivered."""
    store(db_session, title="Port scan detected")

    record = client.get(NOTIFICATIONS_URL).json()["data"]["notifications"][0]

    assert set(record).isdisjoint(FORBIDDEN_FIELDS)
    assert set(record) == {
        "notification_id",
        "user_id",
        "title",
        "message",
        "notification_type",
        "is_read",
        "created_at",
        "created_at_epoch",
    }


def test_filter_by_unread(client: TestClient, db_session: Session) -> None:
    """``unread_only`` keeps only the records that have not been read."""
    store(db_session, title="unread one", is_read=0)
    store(db_session, title="read one", is_read=1)

    data = client.get(
        NOTIFICATIONS_URL, params={"unread_only": True}
    ).json()["data"]

    assert data["count"] == 1
    assert data["notifications"][0]["title"] == "unread one"


def test_total_reflects_the_filter(client: TestClient, db_session: Session) -> None:
    """``total`` counts the filtered matches, so a page and its total agree."""
    store(db_session, title="unread one", is_read=0)
    store(db_session, title="read one", is_read=1)

    data = client.get(
        NOTIFICATIONS_URL, params={"unread_only": True}
    ).json()["data"]

    assert data["count"] == 1
    assert data["total"] == 1


def test_listing_is_newest_first(client: TestClient, db_session: Session) -> None:
    """Ordering is ``created_at DESC``, so the newest notification leads."""
    store(db_session, title="older", created_at=OLDER)
    store(db_session, title="newer", created_at=NEWER)

    titles = [
        record["title"]
        for record in client.get(NOTIFICATIONS_URL).json()["data"]["notifications"]
    ]

    assert titles == ["newer", "older"]


def test_listing_order_is_total_across_equal_timestamps(
    client: TestClient, db_session: Session
) -> None:
    """Records sharing a timestamp still have one stable order (M13.24)."""
    store(db_session, title="first", created_at=NEWER)
    store(db_session, title="second", created_at=NEWER)

    first_pass = [
        r["notification_id"]
        for r in client.get(NOTIFICATIONS_URL).json()["data"]["notifications"]
    ]
    second_pass = [
        r["notification_id"]
        for r in client.get(NOTIFICATIONS_URL).json()["data"]["notifications"]
    ]

    assert first_pass == second_pass
    assert first_pass == sorted(first_pass, reverse=True)


def test_pagination_bounds_the_page(
    client: TestClient, db_session: Session
) -> None:
    """``limit``/``offset`` bound the page and never overlap each other."""
    for index in range(5):
        store(db_session, title=f"notification {index}", created_at=NEWER)

    first = client.get(NOTIFICATIONS_URL, params={"limit": 2}).json()["data"]
    second = client.get(
        NOTIFICATIONS_URL, params={"limit": 2, "offset": 2}
    ).json()["data"]

    assert first["count"] == 2
    assert first["total"] == 5
    assert first["has_more"] is True
    assert {r["notification_id"] for r in first["notifications"]}.isdisjoint(
        {r["notification_id"] for r in second["notifications"]}
    )


def test_limit_bounds_are_validated(client: TestClient) -> None:
    """An out-of-range limit fails request validation (M13.24)."""
    assert client.get(NOTIFICATIONS_URL, params={"limit": 0}).status_code == 422
    assert client.get(NOTIFICATIONS_URL, params={"limit": 100_000}).status_code == 422
    assert client.get(NOTIFICATIONS_URL, params={"offset": -1}).status_code == 422


# ---------------------------------------------------------------------------
# GET /notifications/{notification_id}
# ---------------------------------------------------------------------------


def test_single_read_returns_the_record(
    client: TestClient, db_session: Session
) -> None:
    """A known id resolves to that notification."""
    row = store(db_session, title="Port scan detected")

    body = client.get(f"{NOTIFICATIONS_URL}/{row.id}").json()

    assert body["success"] is True
    assert body["data"]["notification_id"] == row.id
    assert body["data"]["title"] == "Port scan detected"


def test_unknown_notification_is_404(client: TestClient) -> None:
    """An unknown id returns the standard not-found envelope (M13.23)."""
    response = client.get(f"{NOTIFICATIONS_URL}/424242")

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [
        {"field": "notification_id", "code": "NOTIFICATION_NOT_FOUND"}
    ]


def test_non_numeric_id_is_rejected(client: TestClient) -> None:
    """A non-numeric id fails request validation rather than the lookup."""
    assert client.get(f"{NOTIFICATIONS_URL}/not-a-number").status_code == 422


# ---------------------------------------------------------------------------
# Verbs
# ---------------------------------------------------------------------------


def test_collection_is_read_only(client: TestClient) -> None:
    """No verb creates, replaces or deletes a notification through this API."""
    assert client.post(NOTIFICATIONS_URL).status_code == 405
    assert client.put(NOTIFICATIONS_URL).status_code == 405
    assert client.delete(NOTIFICATIONS_URL).status_code == 405


def test_reading_a_notification_cannot_be_marked(
    client: TestClient, db_session: Session
) -> None:
    """There is no "mark as read" verb, so the stored flag is unchanged.

    Adding one would imply a read/unread workflow the rest of the application
    does not participate in (M13.23).
    """
    row = store(db_session, title="unread one", is_read=0)

    assert client.post(f"{NOTIFICATIONS_URL}/{row.id}/read").status_code in (404, 405)
    db_session.refresh(row)
    assert row.is_read == 0
