"""API tests for the reports endpoints (M13.20, generation and download added by M17).

The surface is wide and its two halves pull in opposite directions. The *read*
half reports stored report metadata, which is real and must come back accurately --
and it must never report a report's **file path**, because that is an internal
filesystem location (M13.30). The *write* half is M17: ``POST /reports/generate``
now produces a report and records it, and ``GET /reports/{id}/download`` serves the
artifact.

What these tests hold to:

* **Metadata is accurate and bounded.** A page and its total agree, the order is
  total, and the M17 facts a generated report carries -- its status, its size, its
  period, and whether it can be downloaded -- are reported. A pre-M17 row reports
  those as absent rather than as plausible defaults, because an unknown period is
  not the epoch and an unknown size is not zero.
* **Generation answers like the write it is.** ``201`` with the stored metadata and
  the summary block the report opens with, so a client can show what was produced
  without fetching the file it just asked for. The persisted row is visible in the
  listing immediately afterwards.
* **A refusal is a sentence naming a field.** An unsupported format, a preset given
  bounds, a custom period missing a bound -- each is a ``400`` in the standard
  envelope, raised before anything is written.
* **A download is a file, and never a path.** The bytes are the artifact, the
  filename is the artifact's own name, and no response body ever contains the
  storage directory.

Generation writes a real artifact, so the generating client is pointed at a
temporary storage directory. Nothing here touches the developer's configured
``reports/`` directory.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.analytics.service import AnalyticsService
from app.api.common import ErrorCode
from app.api.v1.deps import get_analytics_service, get_report_service
from app.database.session import get_db
from app.models.report import Report
from app.reports.service import ReportService
from app.reports.storage import ReportStorage
from tests.m13_fakes import api_client, make_db_override

REPORTS_URL = "/api/v1/reports"
GENERATE_URL = f"{REPORTS_URL}/generate"

#: A filesystem location that must never appear in a response (M13.30).
INTERNAL_PATH = "/var/lib/netwatch/reports/daily.pdf"

OLDER = datetime(2024, 1, 1, 8, 0, 0)
NEWER = datetime(2024, 6, 1, 8, 0, 0)

#: A bounded custom period, well inside the analytics layer's thirty-day ceiling.
CUSTOM_SINCE = "2026-10-01T00:00:00+00:00"
CUSTOM_UNTIL = "2026-10-02T00:00:00+00:00"


@pytest.fixture
def client(db_engine) -> Generator[TestClient, None, None]:
    """A client reading the isolated in-memory database, not the real one."""
    with api_client({get_db: make_db_override(db_engine)}) as test_client:
        yield test_client


def report_service_override(directory: str) -> Callable[..., ReportService]:
    """Return a ``get_report_service`` override writing into ``directory``.

    The service is built from the *request's* own session and the analytics service
    over it, exactly as the application builds it -- only the storage directory
    differs, so a test generates a real artifact into a temporary path instead of
    the configured one.
    """

    def override(
        db: Session = Depends(get_db),
        analytics: AnalyticsService = Depends(get_analytics_service),
    ) -> ReportService:
        return ReportService(
            db=db, analytics=analytics, storage=ReportStorage(directory)
        )

    return override


@pytest.fixture
def generating(tmp_path: Path, db_engine) -> Generator[TestClient, None, None]:
    """A client whose report generation writes into a temporary directory."""
    overrides = {
        get_db: make_db_override(db_engine),
        get_report_service: report_service_override(str(tmp_path / "artifacts")),
    }
    with api_client(overrides) as test_client:
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


def test_a_pre_m17_row_reports_its_new_fields_as_absent(
    client: TestClient, db_session: Session
) -> None:
    """An unknown period is not the epoch and an unknown size is not zero (M17.9).

    A row written by hand before M17 genuinely has no recorded period or size, so
    the model says so rather than inventing a value a reader would believe.
    """
    store(db_session, name="Daily summary")

    report = client.get(REPORTS_URL).json()["data"]["reports"][0]

    assert report["status"] == "completed"
    assert report["file_size"] is None
    assert report["error"] is None
    assert report["period_start"] is None
    assert report["period_end"] is None
    assert report["downloadable"] is False


def test_downloadable_is_false_when_the_artifact_is_not_in_the_store(
    client: TestClient, db_session: Session
) -> None:
    """A hand-written row names a location outside the storage directory.

    Reporting it as downloadable would be a promise the next request breaks, so
    the field is computed from the store rather than inferred from the status.
    """
    store(db_session, name="Daily summary", file_path=INTERNAL_PATH)

    report = client.get(REPORTS_URL).json()["data"]["reports"][0]

    assert report["downloadable"] is False


def test_listing_never_exposes_the_file_path(
    client: TestClient, db_session: Session
) -> None:
    """The stored location is internal and is not part of any response.

    The omission is structural -- ``file_path`` is absent from the wire model --
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
    """Rows sharing a timestamp still have one stable order (M13.24)."""
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


def test_generation_returns_created_with_the_stored_metadata(
    generating: TestClient,
) -> None:
    """A generation is a write, so it answers ``201`` with the row it wrote."""
    response = generating.post(
        GENERATE_URL,
        json={
            "report_type": "custom",
            "format": "CSV",
            "since": CUSTOM_SINCE,
            "until": CUSTOM_UNTIL,
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["success"] is True
    report = body["data"]["report"]
    assert report["report_id"] > 0
    assert report["report_type"] == "custom"
    assert report["format"] == "CSV"
    assert report["status"] == "completed"
    assert report["error"] is None
    assert report["file_size"] > 0
    assert report["downloadable"] is True
    assert report["period_start"] == CUSTOM_SINCE
    assert report["period_end"] == CUSTOM_UNTIL
    assert "file_path" not in report


def test_generation_returns_the_summary_the_report_opens_with(
    generating: TestClient,
) -> None:
    """The summary a client shows and the one in the file come from one assembly."""
    body = generating.post(
        GENERATE_URL, json={"format": "CSV"}
    ).json()["data"]

    summary = {metric["label"]: metric["value"] for metric in body["summary"]}

    assert summary["Report title"] == body["report"]["name"]
    assert summary["Output format"] == "CSV"
    assert "Period start (inclusive, UTC)" in summary


def test_the_default_request_is_the_previous_day_as_a_pdf(
    generating: TestClient,
) -> None:
    """An empty body means the layer's own documented defaults (M17.4)."""
    response = generating.post(GENERATE_URL)

    assert response.status_code == 201
    report = response.json()["data"]["report"]
    assert report["report_type"] == "daily"
    assert report["format"] == "PDF"


def test_a_generation_is_visible_in_the_listing(
    generating: TestClient,
) -> None:
    """The row is persisted, so a client that missed the response can find it."""
    generated = generating.post(GENERATE_URL, json={"format": "CSV"}).json()
    report_id = generated["data"]["report"]["report_id"]

    listing = generating.get(REPORTS_URL).json()["data"]

    assert listing["total"] == 1
    listed = listing["reports"][0]
    assert listed["report_id"] == report_id
    assert listed["downloadable"] is True
    assert listed["file_size"] == generated["data"]["report"]["file_size"]


def test_an_unsupported_format_is_a_400_naming_the_field(
    generating: TestClient,
) -> None:
    """A format the layer cannot produce is refused, not defaulted."""
    response = generating.post(GENERATE_URL, json={"format": "DOCX"})

    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [{"field": "format", "code": ErrorCode.INVALID_REQUEST}]


def test_a_preset_given_bounds_is_a_400_naming_the_period(
    generating: TestClient,
) -> None:
    """A daily report derives its period, so naming one too contradicts itself."""
    response = generating.post(
        GENERATE_URL,
        json={"report_type": "daily", "since": CUSTOM_SINCE, "until": CUSTOM_UNTIL},
    )

    assert response.status_code == 400
    assert response.json()["errors"] == [
        {"field": "period", "code": ErrorCode.INVALID_REQUEST}
    ]


def test_a_custom_report_without_bounds_is_a_400_naming_the_period(
    generating: TestClient,
) -> None:
    """Neither bound can be defaulted: an open-ended report is unbounded."""
    response = generating.post(GENERATE_URL, json={"report_type": "custom"})

    assert response.status_code == 400
    assert response.json()["errors"] == [
        {"field": "period", "code": ErrorCode.INVALID_REQUEST}
    ]


def test_a_bad_timestamp_is_a_400_naming_its_own_field(
    generating: TestClient,
) -> None:
    """A typo fails loudly rather than shifting the period to another day."""
    response = generating.post(
        GENERATE_URL,
        json={"report_type": "custom", "since": "yesterday", "until": CUSTOM_UNTIL},
    )

    assert response.status_code == 400
    assert response.json()["errors"] == [
        {"field": "since", "code": ErrorCode.INVALID_REQUEST}
    ]


def test_a_refused_generation_writes_no_row(generating: TestClient) -> None:
    """Refusing is not a silent success: the table is untouched."""
    generating.post(GENERATE_URL, json={"format": "DOCX"})

    assert generating.get(REPORTS_URL).json()["data"]["total"] == 0


def test_a_generation_failure_is_a_500_with_a_safe_sentence(
    db_engine, tmp_path: Path
) -> None:
    """A generation that cannot finish fails loudly, and names no internal."""
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"i am a file")
    overrides = {
        get_db: make_db_override(db_engine),
        get_report_service: report_service_override(str(blocker)),
    }
    with api_client(overrides) as failing:
        response = failing.post(GENERATE_URL, json={"format": "CSV"})
        listing = failing.get(REPORTS_URL).json()["data"]

    assert response.status_code == 500
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == ErrorCode.INTERNAL_ERROR
    for internal in ("Traceback", "File \"", "app.", str(blocker)):
        assert internal not in body["message"]
    # The row is recorded as failed rather than vanishing.
    assert listing["reports"][0]["status"] == "failed"
    assert listing["reports"][0]["file_size"] is None


# ---------------------------------------------------------------------------
# GET /reports/{report_id}/download
# ---------------------------------------------------------------------------


def test_a_generated_csv_downloads_as_a_csv(
    generating: TestClient, tmp_path: Path
) -> None:
    """The response is the artifact itself, served as its own media type."""
    report_id = generating.post(GENERATE_URL, json={"format": "CSV"}).json()["data"][
        "report"
    ]["report_id"]

    response = generating.get(f"{REPORTS_URL}/{report_id}/download")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert response.content.startswith(b"###")
    assert report_id is not None


def test_a_generated_pdf_downloads_as_a_pdf(generating: TestClient) -> None:
    """The binary format is served with its own media type."""
    report_id = generating.post(GENERATE_URL, json={"format": "PDF"}).json()["data"][
        "report"
    ]["report_id"]

    response = generating.get(f"{REPORTS_URL}/{report_id}/download")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.content.startswith(b"%PDF")


def test_a_download_never_names_the_storage_directory(
    generating: TestClient, tmp_path: Path
) -> None:
    """The filename is the artifact's own name, and the directory is internal."""
    report_id = generating.post(GENERATE_URL, json={"format": "CSV"}).json()["data"][
        "report"
    ]["report_id"]

    response = generating.get(f"{REPORTS_URL}/{report_id}/download")

    assert str(tmp_path) not in response.headers.get("content-disposition", "")
    assert "netwatch-report-" in response.headers["content-disposition"]


def test_download_of_an_unknown_report_is_404(generating: TestClient) -> None:
    """An unknown id is not found, whatever the file system holds."""
    response = generating.get(f"{REPORTS_URL}/424242/download")

    assert response.status_code == 404
    assert response.json()["errors"] == [
        {"field": "report_id", "code": "REPORT_NOT_FOUND"}
    ]


def test_a_missing_artifact_downloads_as_404(
    generating: TestClient, tmp_path: Path
) -> None:
    """A row whose file was removed is not found, not a server error."""
    report_id = generating.post(GENERATE_URL, json={"format": "CSV"}).json()["data"][
        "report"
    ]["report_id"]
    for artifact in (tmp_path / "artifacts").iterdir():
        artifact.unlink()

    response = generating.get(f"{REPORTS_URL}/{report_id}/download")

    assert response.status_code == 404
    assert response.json()["errors"][0]["code"] == "REPORT_NOT_FOUND"


# ---------------------------------------------------------------------------
# Verbs
# ---------------------------------------------------------------------------


def test_collection_rejects_unsupported_verbs(client: TestClient) -> None:
    """Only ``/generate`` accepts a POST; the collection stays read-only."""
    assert client.post(REPORTS_URL).status_code == 405
    assert client.put(REPORTS_URL).status_code == 405
    assert client.delete(REPORTS_URL).status_code == 405
