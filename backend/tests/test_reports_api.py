"""API tests for the reports endpoints (M13.20).

Two things are under test, and they pull in opposite directions. The surface
reports stored report *metadata*, which is real and must come back accurately —
and it must never report a report's **file path**, because that is an internal
filesystem location (M13.30). Report *generation* is M17 and does not exist, so
``POST /reports/generate`` has to say so rather than fabricate a file.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.report import Report
from tests.m13_fakes import api_client, make_db_override

REPORTS_URL = "/api/v1/reports"
GENERATE_URL = f"{REPORTS_URL}/generate"

#: A filesystem location that must never appear in a response (M13.30).
INTERNAL_PATH = "/var/lib/netwatch/reports/daily.pdf"

OLDER = datetime(2024, 1, 1, 8, 0, 0)
NEWER = datetime(2024, 6, 1, 8, 0, 0)


@pytest.fixture
def client(db_engine) -> Generator[TestClient, None, None]:
    """A client reading the isolated in-memory database, not the real one."""
    with api_client({get_db: make_db_override(db_engine)}) as test_client:
        yield test_client


def store(
    session: Session,
    *,
    name: str,
    report_type: str = "daily",
    report_format: str = "PDF",
    generated_at: datetime = OLDER,
    file_path: str = INTERNAL_PATH,
) -> Report:
    """Write one report metadata row as the application stores it."""
    row = Report(
        name=name,
        report_type=report_type,
        format=report_format,
        file_path=file_path,
        generated_at=generated_at,
        generated_by=None,
    )
    session.add(row)
    session.commit()
    return row


def iso(value: datetime) -> str:
    """Render a naive UTC datetime the way the API documents it (M13.26)."""
    return value.replace(tzinfo=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# GET /reports
# ---------------------------------------------------------------------------


def test_empty_listing_is_well_formed(client: TestClient) -> None:
    """An empty table returns a well-formed, empty collection with a total."""
    body = client.get(REPORTS_URL).json()

    assert body["success"] is True
    data = body["data"]
    assert data["count"] == 0
    assert data["total"] == 0
    assert data["reports"] == []
    assert data["has_more"] is False


def test_listing_returns_stored_metadata(
    client: TestClient, db_session: Session
) -> None:
    """A stored report comes back with its name, type, format and timestamps."""
    store(db_session, name="Daily summary")

    report = client.get(REPORTS_URL).json()["data"]["reports"][0]

    assert report["name"] == "Daily summary"
    assert report["report_type"] == "daily"
    assert report["format"] == "PDF"
    assert report["generated_at"] == iso(OLDER)
    assert report["generated_at_epoch"] == OLDER.replace(
        tzinfo=timezone.utc
    ).timestamp()
    assert report["report_id"] > 0


def test_listing_never_exposes_the_file_path(
    client: TestClient, db_session: Session
) -> None:
    """The stored location is internal and is not part of any response.

    The omission is structural — ``file_path`` is absent from the wire model —
    so no code path can forget it (M13.30).
    """
    store(db_session, name="Daily summary")

    report = client.get(REPORTS_URL).json()["data"]["reports"][0]

    assert "file_path" not in report
    assert INTERNAL_PATH not in client.get(REPORTS_URL).text


def test_listing_is_newest_first(
    client: TestClient, db_session: Session
) -> None:
    """Ordering is ``generated_at DESC``, so the newest report leads."""
    store(db_session, name="older", generated_at=OLDER)
    store(db_session, name="newer", generated_at=NEWER)

    names = [
        report["name"]
        for report in client.get(REPORTS_URL).json()["data"]["reports"]
    ]

    assert names == ["newer", "older"]


def test_listing_order_is_total_across_equal_timestamps(
    client: TestClient, db_session: Session
) -> None:
    """Rows sharing a timestamp still have one stable order (M13.24).

    The primary key is the tie-break, so two identical requests cannot return
    the same two rows in different orders.
    """
    store(db_session, name="first", generated_at=NEWER)
    store(db_session, name="second", generated_at=NEWER)

    first_pass = [r["report_id"] for r in client.get(REPORTS_URL).json()["data"]["reports"]]
    second_pass = [r["report_id"] for r in client.get(REPORTS_URL).json()["data"]["reports"]]

    assert first_pass == second_pass
    assert first_pass == sorted(first_pass, reverse=True)


def test_filter_by_format_folds_case(
    client: TestClient, db_session: Session
) -> None:
    """``format=pdf`` matches the stored ``PDF``, because that is the same thing.

    Folding case is a convenience; translating an *unknown* value into a known
    one would not be (M13.25).
    """
    store(db_session, name="pdf one", report_format="PDF")
    store(db_session, name="csv one", report_format="CSV")

    data = client.get(REPORTS_URL, params={"format": "pdf"}).json()["data"]

    assert data["count"] == 1
    assert data["reports"][0]["name"] == "pdf one"


def test_filter_by_type(client: TestClient, db_session: Session) -> None:
    """``report_type`` selects only reports of that category."""
    store(db_session, name="daily one", report_type="daily")
    store(db_session, name="weekly one", report_type="weekly")

    data = client.get(REPORTS_URL, params={"report_type": "weekly"}).json()["data"]

    assert data["count"] == 1
    assert data["reports"][0]["name"] == "weekly one"


def test_filter_by_unknown_format_returns_nothing(
    client: TestClient, db_session: Session
) -> None:
    """A value the store does not hold selects nothing, rather than everything."""
    store(db_session, name="pdf one", report_format="PDF")

    data = client.get(REPORTS_URL, params={"format": "xlsx"}).json()["data"]

    assert data["count"] == 0
    assert data["total"] == 0
    assert data["reports"] == []


def test_pagination_bounds_the_page_and_reports_the_total(
    client: TestClient, db_session: Session
) -> None:
    """``limit``/``offset`` bound the page while ``total`` describes the match set."""
    for index in range(5):
        store(db_session, name=f"report {index}", generated_at=NEWER)

    first = client.get(REPORTS_URL, params={"limit": 2}).json()["data"]
    second = client.get(REPORTS_URL, params={"limit": 2, "offset": 2}).json()["data"]

    assert first["count"] == 2
    assert first["total"] == 5
    assert first["limit"] == 2
    assert first["offset"] == 0
    assert first["has_more"] is True
    assert second["offset"] == 2
    # Pages do not overlap: the second page continues where the first stopped.
    assert {r["report_id"] for r in first["reports"]}.isdisjoint(
        {r["report_id"] for r in second["reports"]}
    )


def test_total_reflects_the_filter_not_the_table(
    client: TestClient, db_session: Session
) -> None:
    """``total`` counts the filtered matches, so a page and its total agree."""
    store(db_session, name="pdf one", report_format="PDF")
    store(db_session, name="csv one", report_format="CSV")

    data = client.get(REPORTS_URL, params={"format": "PDF"}).json()["data"]

    assert data["count"] == 1
    assert data["total"] == 1


def test_limit_bounds_are_validated(client: TestClient) -> None:
    """An out-of-range limit fails request validation, never the store (M13.24)."""
    assert client.get(REPORTS_URL, params={"limit": 0}).status_code == 422
    assert client.get(REPORTS_URL, params={"limit": 100_000}).status_code == 422
    assert client.get(REPORTS_URL, params={"offset": -1}).status_code == 422


# ---------------------------------------------------------------------------
# GET /reports/{report_id}
# ---------------------------------------------------------------------------


def test_single_read_returns_the_report(
    client: TestClient, db_session: Session
) -> None:
    """A known id resolves to that report's metadata."""
    row = store(db_session, name="Daily summary")

    body = client.get(f"{REPORTS_URL}/{row.id}").json()

    assert body["success"] is True
    assert body["data"]["report_id"] == row.id
    assert body["data"]["name"] == "Daily summary"
    assert "file_path" not in body["data"]


def test_unknown_report_is_404(client: TestClient) -> None:
    """An unknown id returns the standard not-found envelope (M13.20)."""
    response = client.get(f"{REPORTS_URL}/424242")

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [{"field": "report_id", "code": "REPORT_NOT_FOUND"}]


def test_non_numeric_id_is_rejected(client: TestClient) -> None:
    """A non-numeric id fails request validation rather than the lookup."""
    assert client.get(f"{REPORTS_URL}/not-a-number").status_code == 422


# ---------------------------------------------------------------------------
# POST /reports/generate
# ---------------------------------------------------------------------------


def test_generation_reports_not_implemented(client: TestClient) -> None:
    """Generation is M17, so the route says so instead of fabricating a file."""
    response = client.post(GENERATE_URL)

    assert response.status_code == 501
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [
        {"field": "report_generation", "code": "FEATURE_NOT_IMPLEMENTED"}
    ]


def test_generation_creates_no_row(client: TestClient) -> None:
    """Refusing is not a silent success: the table is untouched (M13.20)."""
    client.post(GENERATE_URL)

    assert client.get(REPORTS_URL).json()["data"]["total"] == 0


def test_generation_message_names_no_internals(client: TestClient) -> None:
    """The refusal is a sentence, not a path or a traceback (M13.5)."""
    message = client.post(GENERATE_URL).json()["message"]

    assert "M17" in message or "later milestone" in message
    assert "Traceback" not in message
    assert "app/" not in message


# ---------------------------------------------------------------------------
# Verbs
# ---------------------------------------------------------------------------


def test_collection_rejects_unsupported_verbs(client: TestClient) -> None:
    """Only ``/generate`` accepts a POST; the collection stays read-only."""
    assert client.post(REPORTS_URL).status_code == 405
    assert client.put(REPORTS_URL).status_code == 405
    assert client.delete(REPORTS_URL).status_code == 405
