"""Filter, pagination and time-handling tests (M13.25/M13.26).

The per-endpoint test files each check their own filters. This one covers the
pieces those files share, and it does so from two directions on purpose:

* the **helpers** in :mod:`app.api.common.validation` are tested directly, because
  a bug there is a bug in every router at once;
* the **boundary** is tested too, because a helper can be correct while a route
  forgets to call it — which is exactly the failure that made an unparseable
  timestamp answer 500 in the incidents router.

The time tests are the ones worth stating plainly. M13.26 asks for *one* timestamp
convention, so two things are asserted: an offset in a filter must actually shift
the instant rather than be ignored, and no response may carry a datetime without
one. The second is a sweep, because a single router that renders a naive datetime
is enough to give a client an ambiguous value.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Generator
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.alerts.queries import AlertQueries
from app.api.common.pagination import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.api.common.validation import (
    MAX_PORT,
    MAX_RISK_SCORE,
    MIN_PORT,
    MIN_RISK_SCORE,
    normalize_filter_ip,
    normalize_filter_mac,
    parse_datetime_filter,
    parse_epoch_filter,
    validate_choice,
    validate_port,
    validate_risk_range,
    validate_time_range,
)
from app.api.v1.deps import get_alert_queries
from app.api.v1.incidents import MAX_INCIDENT_PAGE_SIZE
from app.database.session import get_db
from app.models.notification import Notification
from app.models.report import Report
from tests.m13_fakes import api_client, make_db_override

#: Matches the start of an ISO-8601 datetime, so a response can be searched for
#: timestamps without knowing which field holds one.
ISO_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

#: The offset every API timestamp must carry (M13.26).
UTC_OFFSET = "+00:00"

#: Every paginated collection and the largest page *it* will serve (M13.24).
#:
#: The maximum is a property of the endpoint, not one number for the whole API.
#: Most collections serve the shared :data:`MAX_PAGE_SIZE`; incidents narrows to
#: the correlation store's own cap, because ``IncidentQuery`` refuses a larger
#: page than that. Asserting a single number everywhere would have failed against
#: a router behaving correctly, and would have hidden the real defect — that the
#: narrower cap was declared and never enforced.
PAGINATED_COLLECTIONS = {
    "/api/v1/packets": MAX_PAGE_SIZE,
    "/api/v1/devices": MAX_PAGE_SIZE,
    "/api/v1/connections": MAX_PAGE_SIZE,
    "/api/v1/detections": MAX_PAGE_SIZE,
    "/api/v1/incidents": MAX_INCIDENT_PAGE_SIZE,
    "/api/v1/reports": MAX_PAGE_SIZE,
    "/api/v1/notifications": MAX_PAGE_SIZE,
}

#: The collection URLs alone, for the tests that do not bound a page.
PAGINATED_URLS = tuple(PAGINATED_COLLECTIONS)

#: Endpoints swept for timestamp formatting, chosen so the sweep runs without
#: seeding data into every store.
SWEPT_URLS = (
    "/api/v1/dashboard/summary",
    "/api/v1/system/status",
    "/api/v1/system/info",
)

#: Endpoints that accept a time filter, so each one's translation is checked.
TIME_FILTER_URLS = (
    "/api/v1/incidents",
    "/api/v1/packets",
    "/api/v1/detections",
)


@pytest.fixture
def client(
    db_engine, session_factory: Callable[[], Session]
) -> Generator[TestClient, None, None]:
    """A client whose database-backed collaborators are all in-memory."""
    with api_client(
        {
            get_db: make_db_override(db_engine),
            get_alert_queries: lambda: AlertQueries(session_factory=session_factory),
        }
    ) as test_client:
        yield test_client


def find_datetimes(value: object, path: str = "$") -> list[tuple[str, str]]:
    """Return every ``(path, value)`` whose string looks like an ISO datetime.

    Recursive because a timestamp may sit anywhere — at the top of a payload, in a
    nested object, or inside a list — and the rule is the same wherever it is.
    """
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            found.extend(find_datetimes(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(find_datetimes(item, f"{path}[{index}]"))
    elif isinstance(value, str) and ISO_DATETIME.match(value):
        found.append((path, value))
    return found


# ---------------------------------------------------------------------------
# Timestamp parsing (M13.26)
# ---------------------------------------------------------------------------


def test_an_absent_filter_is_not_a_parse() -> None:
    """``None`` passes through, so an omitted filter never narrows a result."""
    assert parse_epoch_filter(None, "since") is None
    assert parse_datetime_filter(None, "since") is None


def test_a_zone_offset_shifts_the_instant() -> None:
    """The offset is applied, not discarded.

    ``+05:30`` is a different instant from ``Z``, and treating them as equal would
    silently move a query window by hours — which is the whole reason the
    conversion happens at one boundary (M13.26).
    """
    zulu = parse_epoch_filter("2024-01-01T00:00:00+00:00", "since")
    shifted = parse_epoch_filter("2024-01-01T05:30:00+05:30", "since")
    naive = parse_epoch_filter("2024-01-01T00:00:00", "since")

    assert zulu == shifted
    # A naive value is read as UTC rather than as the server's local zone, so the
    # same request means the same thing on every machine.
    assert naive == zulu


def test_a_z_suffix_is_accepted() -> None:
    """``Z`` is the other spelling of UTC, and is read as such."""
    assert parse_epoch_filter("2024-01-01T00:00:00Z", "since") == parse_epoch_filter(
        "2024-01-01T00:00:00+00:00", "since"
    )


@pytest.mark.parametrize("value", ["", "   ", "yesterday", "2024-13-45T00:00:00"])
def test_an_unusable_timestamp_raises(value: str) -> None:
    """A value that cannot be read raises, naming the field that failed."""
    with pytest.raises(ValueError) as excinfo:
        parse_epoch_filter(value, "since")

    assert "since" in str(excinfo.value)


def test_the_stored_form_is_naive_utc() -> None:
    """The packet filter's form is naive UTC, matching what SQLite returns.

    A tz-aware datetime here would be compared against naive column values and
    could shift by the offset, so the conversion drops the tzinfo deliberately.
    """
    parsed = parse_datetime_filter("2024-01-01T05:30:00+05:30", "since")

    assert parsed is not None
    assert parsed.tzinfo is None
    assert parsed == datetime(2024, 1, 1, 0, 0, 0)


# ---------------------------------------------------------------------------
# Value validation (M13.25)
# ---------------------------------------------------------------------------


def test_a_closed_vocabulary_returns_the_canonical_member() -> None:
    """Case is folded for comparison, and the canonical spelling is returned."""
    assert validate_choice("HIGH", ("low", "high"), "severity") == "high"
    assert validate_choice("high", ("low", "high"), "severity") == "high"


@pytest.mark.parametrize("value", ["", "   ", "critical!"])
def test_an_unusable_choice_raises(value: str) -> None:
    """A blank value is a failure, not "no filter" — it is the typo being caught."""
    with pytest.raises(ValueError):
        validate_choice(value, ("low", "high"), "severity")


def test_an_absent_choice_is_not_validated() -> None:
    """``None`` means "not asked for", which is different from a bad value."""
    assert validate_choice(None, ("low", "high"), "severity") is None


def test_port_bounds() -> None:
    """A port inside the range passes; outside it raises."""
    assert validate_port(MIN_PORT, "source_port") == MIN_PORT
    assert validate_port(MAX_PORT, "source_port") == MAX_PORT

    for value in (MIN_PORT - 1, MAX_PORT + 1):
        with pytest.raises(ValueError):
            validate_port(value, "source_port")


def test_risk_bounds_and_ordering() -> None:
    """Both ends are bounded, and an inverted range is rejected (M13.25)."""
    assert validate_risk_range(MIN_RISK_SCORE, MAX_RISK_SCORE) == (
        MIN_RISK_SCORE,
        MAX_RISK_SCORE,
    )

    with pytest.raises(ValueError):
        validate_risk_range(MAX_RISK_SCORE + 1, None)
    with pytest.raises(ValueError):
        validate_risk_range(None, MIN_RISK_SCORE - 1)
    with pytest.raises(ValueError):
        validate_risk_range(80, 20)


def test_time_range_ordering() -> None:
    """An inverted window raises rather than returning an empty result."""
    validate_time_range(1.0, 2.0)
    validate_time_range(None, 2.0)
    validate_time_range(1.0, None)

    with pytest.raises(ValueError):
        validate_time_range(2.0, 1.0)


def test_address_filters_return_none_for_an_unusable_value() -> None:
    """An unparseable address returns ``None`` so the caller names the field.

    The predicate form is deliberate: the device router wants to report ``ip`` and
    the connection router wants the tracker to decide, so the naming rule cannot
    live here.
    """
    assert normalize_filter_ip(None) is None
    assert normalize_filter_ip("not-an-ip") is None
    assert normalize_filter_mac("not-a-mac") is None
# ---------------------------------------------------------------------------
# Pagination (M13.24)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", PAGINATED_URLS)
def test_a_collection_defaults_to_the_shared_page_size(
    client: TestClient, url: str
) -> None:
    """Every collection answers the same default window (M13.24)."""
    data = client.get(url).json()["data"]

    assert data["limit"] == DEFAULT_PAGE_SIZE
    assert data["offset"] == 0


@pytest.mark.parametrize("url, maximum", PAGINATED_COLLECTIONS.items())
def test_the_maximum_page_is_accepted(
    client: TestClient, url: str, maximum: int
) -> None:
    """Each collection serves the largest page it documents (M13.24)."""
    assert client.get(url, params={"limit": maximum}).status_code == 200


@pytest.mark.parametrize("url, maximum", PAGINATED_COLLECTIONS.items())
def test_a_page_beyond_the_maximum_is_a_422(
    client: TestClient, url: str, maximum: int
) -> None:
    """An over-large page fails request validation, never a live query (M13.24).

    The failure must be request validation rather than an exception from the
    store, because only one of those tells the client which parameter to fix and
    only one of them keeps a client mistake from looking like a server fault.
    """
    response = client.get(url, params={"limit": maximum + 1})

    assert response.status_code == 422
    assert "detail" in response.json()


def test_the_incident_cap_is_enforced_by_request_validation(
    client: TestClient,
) -> None:
    """The narrower incident maximum is a 422, not a 500 (M13.24/M13.6).

    ``IncidentQuery`` enforces the correlation store's own page maximum by
    raising. When the API's declared bound was the wider shared one, a page this
    router accepted was refused by the store, and the raise escaped as an opaque
    500 for what is a client mistake. This asserts the bound is applied at the
    boundary, where the error can name ``limit``.
    """
    response = client.get(
        "/api/v1/incidents", params={"limit": MAX_INCIDENT_PAGE_SIZE + 1}
    )

    assert response.status_code == 422
    assert any(
        error["loc"][-1] == "limit" for error in response.json()["detail"]
    )


def test_baselines_reports_unavailable_rather_than_fake_data(
    client: TestClient,
) -> None:
    """The reserved baseline API answers 501 until a baseline engine exists.

    Excluded from the paginated set on purpose (M13.17). It serves no page at
    all, and returning an empty one would assert that no behavioural baseline was
    breached when none has ever been computed — the "fake data" the milestone
    explicitly forbids.
    """
    assert client.get("/api/v1/baselines").status_code == 501


@pytest.mark.parametrize("url", PAGINATED_URLS)
@pytest.mark.parametrize("params", [{"limit": 0}, {"offset": -1}])
def test_a_page_below_the_minimum_is_a_422(
    client: TestClient, url: str, params: dict[str, int]
) -> None:
    """A zero page or a negative offset is rejected before a handler runs."""
    assert client.get(url, params=params).status_code == 422


@pytest.mark.parametrize("url", PAGINATED_URLS)
def test_an_empty_collection_reports_a_total_it_can_stand_behind(
    client: TestClient, url: str
) -> None:
    """``count`` and ``total`` agree, and an empty page says it has no more."""
    data = client.get(url).json()["data"]

    assert data["count"] == 0
    assert data["total"] == 0
    assert data["has_more"] is False


# ---------------------------------------------------------------------------
# One timestamp convention (M13.26)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", SWEPT_URLS)
def test_no_response_carries_a_timestamp_without_an_offset(
    client: TestClient, url: str
) -> None:
    """Every datetime in a response names its zone (M13.26).

    A naive ``2026-01-01T12:00:00`` is ambiguous — two clients in two zones read
    it differently — so a sweep is the only way to check the *whole* surface
    rather than whichever endpoint a test happened to look at.
    """
    body = client.get(url).json()

    for path, value in find_datetimes(body):
        assert value.endswith(UTC_OFFSET), f"{path} = {value}"


def test_a_stored_timestamp_round_trips_with_its_offset(
    client: TestClient, db_session: Session
) -> None:
    """A stored record's time comes back as the same instant, in UTC.

    Seeded explicitly so the assertion is about a real row rather than an empty
    collection, which would pass the sweep trivially.
    """
    attached = datetime(2024, 1, 1, 8, 0, 0)
    db_session.add(
        Notification(
            user_id=None,
            title="Port scan detected",
            message="something happened",
            notification_type="new_alert",
            is_read=0,
            created_at=attached,
        )
    )
    db_session.commit()

    record = client.get("/api/v1/notifications").json()["data"]["notifications"][0]
    as_utc = attached.replace(tzinfo=timezone.utc)

    assert record["created_at"] == as_utc.isoformat()
    assert record["created_at_epoch"] == as_utc.timestamp()


def test_the_epoch_beside_an_iso_string_is_the_same_instant(
    client: TestClient, db_session: Session
) -> None:
    """A payload carrying both forms must not describe two different times.

    That is the whole risk of exposing two representations (M13.26), so it is
    checked rather than assumed.
    """
    generated = datetime(2024, 6, 1, 12, 0, 0)
    db_session.add(
        Report(
            name="Daily summary",
            report_type="daily",
            format="PDF",
            file_path="/tmp/report.pdf",
            generated_at=generated,
            generated_by=None,
        )
    )
    db_session.commit()

    report = client.get("/api/v1/reports").json()["data"]["reports"][0]
    as_utc = generated.replace(tzinfo=timezone.utc)

    assert report["generated_at"] == as_utc.isoformat()
    assert report["generated_at_epoch"] == as_utc.timestamp()


@pytest.mark.parametrize("url", TIME_FILTER_URLS)
def test_a_well_formed_time_filter_is_accepted(client: TestClient, url: str) -> None:
    """A usable timestamp is a filter, not a validation failure."""
    response = client.get(url, params={"since": "2024-01-01T00:00:00+00:00"})

    assert response.status_code == 200


@pytest.mark.parametrize("url", TIME_FILTER_URLS)
def test_an_unusable_time_filter_is_a_400_not_a_500(
    client: TestClient, url: str
) -> None:
    """A typo in a timestamp is the client's error, reported as such (M13.25).

    ``ValueError`` from the parser is exactly the kind of failure that becomes a
    500 if a route forgets to translate it, so every endpoint that accepts a time
    filter is checked rather than only the one where the problem was found.
    """
    response = client.get(url, params={"since": "yesterday"})

    assert response.status_code == 400
    assert response.json()["success"] is False


@pytest.mark.parametrize("url", TIME_FILTER_URLS)
def test_an_inverted_time_filter_is_rejected(client: TestClient, url: str) -> None:
    """A window that cannot match is a controlled 400, not an empty page."""
    response = client.get(
        url,
        params={
            "since": "2024-06-01T00:00:00+00:00",
            "until": "2024-01-01T00:00:00+00:00",
        },
    )

    assert response.status_code == 400
    assert response.json()["success"] is False
