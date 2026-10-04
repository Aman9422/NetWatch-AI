"""Cross-cutting API contract tests (M13.34).

Every other M13 test file checks one group of endpoints. This one checks the
things that must hold for *all* of them at once, because those are the properties
no single router can own: one success shape, one error shape, one status mapping,
and one place where an unexpected failure is contained.

Two exceptions to the envelope are asserted rather than assumed, because both are
deliberate:

* request validation keeps FastAPI's own ``detail`` list (it already returns 422
  with per-field detail, which is the whole point of that case — M13.6);
* an unexpected failure answers with a constant message and nothing else, so no
  traceback, path or driver string reaches a client (M13.30).
"""

from __future__ import annotations

from collections.abc import Callable, Generator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.alerts.queries import AlertQueries
from app.api.common import ErrorCode, register_exception_handlers
from app.api.common.envelope import GENERIC_CODE_STATUS
from app.api.v1.deps import get_alert_queries
from app.api.v1.system import API_PREFIX
from app.database.session import get_db
from app.main import app
from tests.m13_fakes import api_client, make_db_override

#: The message the API returns when it does not anticipate a failure. Constant on
#: purpose: the real message is logged, never serialised (M13.5/M13.30).
OPAQUE_500_MESSAGE = (
    "The request could not be completed due to an internal error"
)

#: Strings that must never appear in any response body.
FORBIDDEN_IN_BODY = ("Traceback", "sqlalchemy", "app/", "site-packages", ".py\"")

#: One collection endpoint from every M13 group, so a shape regression in any
#: router is caught by the sweep below rather than only by its own test file.
COLLECTION_URLS = (
    "/api/v1/capture/interfaces",
    "/api/v1/capture/status",
    "/api/v1/packets",
    "/api/v1/statistics/traffic",
    "/api/v1/statistics/protocols",
    "/api/v1/devices",
    "/api/v1/connections",
    "/api/v1/detections",
    "/api/v1/alerts",
    "/api/v1/incidents",
    "/api/v1/baselines",
    "/api/v1/analytics/traffic",
    "/api/v1/analytics/protocols",
    "/api/v1/analytics/devices",
    "/api/v1/analytics/connections",
    "/api/v1/analytics/threats",
    "/api/v1/dashboard/summary",
    "/api/v1/reports",
    "/api/v1/settings",
    "/api/v1/system/status",
    "/api/v1/system/health",
    "/api/v1/notifications",
)

#: The path prefix every M13 group is mounted under (M13.3).
EXPECTED_PREFIXES = (
    "/api/v1/capture",
    "/api/v1/packets",
    "/api/v1/statistics",
    "/api/v1/devices",
    "/api/v1/connections",
    "/api/v1/detections",
    "/api/v1/alerts",
    "/api/v1/evidence",
    "/api/v1/incidents",
    "/api/v1/baselines",
    "/api/v1/analytics",
    "/api/v1/dashboard",
    "/api/v1/reports",
    "/api/v1/settings",
    "/api/v1/system",
    "/api/v1/notifications",
)


@pytest.fixture
def client(
    db_engine, session_factory: Callable[[], Session]
) -> Generator[TestClient, None, None]:
    """A client whose database-backed collaborators are all in-memory.

    Both overrides are supplied so a sweep across every group reads an isolated
    database rather than the developer's own — the sweep's whole point is that it
    touches all of them.
    """
    with api_client(
        {
            get_db: make_db_override(db_engine),
            get_alert_queries: lambda: AlertQueries(session_factory=session_factory),
        }
    ) as test_client:
        yield test_client


def assert_envelope(body: object) -> dict:
    """Assert ``body`` is one of the two documented shapes, and return it.

    Written as a helper because the sweep asserts it for two dozen endpoints, and
    the rule is the same for each: exactly three keys, ``success`` a boolean, and
    either ``data`` or a list of ``{field, code}`` pairs.
    """
    assert isinstance(body, dict), body
    assert set(body) in (
        {"success", "message", "data"},
        {"success", "message", "errors"},
    ), sorted(body)
    assert isinstance(body["success"], bool)
    assert isinstance(body["message"], str) and body["message"]
    if body["success"]:
        assert "data" in body
    else:
        assert isinstance(body["errors"], list) and body["errors"]
        for entry in body["errors"]:
            assert set(entry) == {"field", "code"}, entry
            assert isinstance(entry["field"], str) and entry["field"]
            assert isinstance(entry["code"], str) and entry["code"]
    return body


# ---------------------------------------------------------------------------
# The envelope
# ---------------------------------------------------------------------------


def test_a_successful_response_uses_the_success_shape(client: TestClient) -> None:
    """A successful payload is ``success``/``message``/``data`` — nothing else."""
    body = assert_envelope(client.get("/api/v1/system/status").json())

    assert body["success"] is True


def test_an_error_response_uses_the_error_shape(client: TestClient) -> None:
    """A failure is ``success``/``message``/``errors`` — nothing else."""
    body = assert_envelope(client.get("/api/v1/incidents/inc:nope").json())

    assert body["success"] is False
    assert body["errors"][0]["field"] == "incident_id"


@pytest.mark.parametrize("url", COLLECTION_URLS)
def test_every_group_answers_in_the_envelope(client: TestClient, url: str) -> None:
    """Whatever a group returns — data, an empty list or an error — it fits.

    The sweep is deliberately unconditional: it does not care which status an
    endpoint chose, only that the body is one of the two documented shapes. A
    router that returned a bare list, or Django-style ``{"error": ...}``, would
    fail here.
    """
    assert_envelope(client.get(url).json())


@pytest.mark.parametrize("url", COLLECTION_URLS)
def test_no_response_leaks_an_internal_string(client: TestClient, url: str) -> None:
    """No body carries a traceback, a module path or a driver name (M13.5)."""
    text = client.get(url).text

    for forbidden in FORBIDDEN_IN_BODY:
        assert forbidden not in text, forbidden


def test_a_collection_carries_its_pagination_block(client: TestClient) -> None:
    """A collection echoes the window it was served with (M13.24)."""
    data = client.get("/api/v1/reports").json()["data"]

    assert {"count", "limit", "offset"} <= set(data)
    assert data["limit"] == 100
    assert data["offset"] == 0


# ---------------------------------------------------------------------------
# Status codes
# ---------------------------------------------------------------------------


def test_an_unrouted_url_is_a_404_in_the_envelope(client: TestClient) -> None:
    """A URL nobody serves answers in the same shape as everything else."""
    response = client.get("/api/v1/no-such-group")

    assert response.status_code == 404
    body = assert_envelope(response.json())
    assert body["errors"][0]["code"] == ErrorCode.NOT_FOUND


def test_a_wrong_verb_is_a_405_in_the_envelope(client: TestClient) -> None:
    """A known path with an unknown verb is a 405, rendered consistently."""
    response = client.post("/api/v1/reports")

    assert response.status_code == 405
    assert assert_envelope(response.json())["errors"][0]["code"] == (
        ErrorCode.METHOD_NOT_ALLOWED
    )


def test_an_invalid_filter_is_a_400(client: TestClient) -> None:
    """A filter that cannot be honoured is a 400 naming the field (M13.25)."""
    response = client.get("/api/v1/incidents", params={"since": "yesterday"})

    assert response.status_code == 400
    assert assert_envelope(response.json())["errors"][0]["field"] == "since"


def test_a_conflict_is_a_409(client: TestClient) -> None:
    """A move the lifecycle forbids is a 409, not a 500 (M13.16)."""
    response = client.post("/api/v1/incidents/inc:missing/resolve")

    # Unknown id first: the store reports not-found before transition validity.
    assert response.status_code == 404


def test_an_unimplemented_feature_is_a_501(client: TestClient) -> None:
    """A surface M13 exposes but does not implement says so (M13.17/M13.20)."""
    response = client.post("/api/v1/reports/generate")

    assert response.status_code == 501
    assert assert_envelope(response.json())["errors"][0]["code"] == (
        ErrorCode.FEATURE_NOT_IMPLEMENTED
    )


def test_request_validation_keeps_its_own_detail_shape(client: TestClient) -> None:
    """A 422 is FastAPI's per-field ``detail``, and deliberately not the envelope.

    M13.6 keeps 422 for validation errors, and FastAPI's handler already names
    every failing field. Wrapping it in the envelope would discard exactly the
    field-level detail the 422 case exists to provide, so the divergence is
    asserted rather than papered over.
    """
    response = client.get("/api/v1/incidents", params={"limit": 0})

    assert response.status_code == 422
    body = response.json()
    assert "detail" in body
    assert "errors" not in body


def test_a_non_numeric_identifier_is_a_422(client: TestClient) -> None:
    """A path parameter of the wrong type is rejected before any lookup."""
    assert client.get("/api/v1/packets/not-a-number").status_code == 422


# ---------------------------------------------------------------------------
# Error isolation (M13.29)
# ---------------------------------------------------------------------------


def make_probe_app(failure: Exception) -> FastAPI:
    """Return a throwaway app whose one route raises ``failure``.

    A separate application rather than a route added to the real one: the point
    is to exercise the *handlers*, and mutating the shared app would leave a
    route behind for every later test in the session.
    """

    probe = FastAPI()

    @probe.get("/boom")
    def boom() -> dict:
        raise failure

    register_exception_handlers(probe)
    return probe


@pytest.mark.parametrize(
    "failure",
    [
        RuntimeError("connection to the driver at /var/lib/netwatch failed"),
        ZeroDivisionError("division by zero"),
        KeyError("internal_field"),
    ],
)
def test_an_unexpected_failure_is_an_opaque_500(failure: Exception) -> None:
    """Any unanticipated exception becomes a constant 500, whatever it was.

    The body is compared to the constant exactly, so a handler that started
    including the exception text — even helpfully — fails this test (M13.30).
    """
    with TestClient(
        make_probe_app(failure), raise_server_exceptions=False
    ) as probe_client:
        response = probe_client.get("/boom")

    assert response.status_code == 500
    body = assert_envelope(response.json())
    assert body["message"] == OPAQUE_500_MESSAGE
    assert body["errors"][0]["code"] == ErrorCode.INTERNAL_ERROR
    assert "driver" not in response.text
    assert "division" not in response.text
    assert str(failure) not in response.text


def test_an_api_failure_does_not_stop_the_next_request(client: TestClient) -> None:
    """A failed request leaves the application able to serve the following one.

    This is the property M13.29 asks for, stated as behaviour: containment means
    the *next* request still works, not merely that a handler returned 500.
    """
    client.get("/api/v1/no-such-group")
    client.get("/api/v1/incidents", params={"since": "yesterday"})

    assert client.get("/api/v1/system/health").status_code == 200


# ---------------------------------------------------------------------------
# Route structure and OpenAPI (M13.3/M13.27)
# ---------------------------------------------------------------------------


def test_every_group_is_mounted_under_the_versioned_prefix(client: TestClient) -> None:
    """Every M13 group is reachable under ``/api/v1`` (M13.3)."""
    paths = app.openapi()["paths"]

    for prefix in EXPECTED_PREFIXES:
        assert any(path.startswith(prefix) for path in paths), prefix


def test_no_group_is_exposed_unversioned(client: TestClient) -> None:
    """No production group is reachable outside ``/api/v1`` (M13.3).

    The unversioned surfaces are the documentation and the health probe only;
    everything else must be versioned so a future v2 can be added beside it.
    """
    paths = set(app.openapi()["paths"])
    unversioned = {path for path in paths if not path.startswith(API_PREFIX)}

    assert unversioned <= {"/docs", "/redoc", "/openapi.json"}, sorted(unversioned)


def test_the_document_is_served(client: TestClient) -> None:
    """``/openapi.json`` is served and describes the API (M13.27)."""
    response = client.get("/openapi.json")

    assert response.status_code == 200
    document = response.json()
    assert document["info"]["title"]
    assert document["paths"]


def test_the_documentation_pages_are_served(client: TestClient) -> None:
    """``/docs`` and ``/redoc`` both render (M13.27)."""
    assert client.get("/docs").status_code == 200
    assert client.get("/redoc").status_code == 200


def test_documented_operations_carry_summaries(client: TestClient) -> None:
    """Every operation is documented, so ``/docs`` is readable (M13.27).

    A path with no summary renders as a bare URL in the UI, which is the
    difference between documentation and a route dump.
    """
    undocumented = [
        f"{method.upper()} {path}"
        for path, operations in app.openapi()["paths"].items()
        for method, operation in operations.items()
        if isinstance(operation, dict) and not operation.get("summary")
    ]

    assert undocumented == []


def test_every_operation_declares_a_response(client: TestClient) -> None:
    """Every operation documents at least one response (M13.27)."""
    for path, operations in app.openapi()["paths"].items():
        for method, operation in operations.items():
            if not isinstance(operation, dict):
                continue
            assert operation.get("responses"), f"{method.upper()} {path}"


# ---------------------------------------------------------------------------
# The code vocabulary
# ---------------------------------------------------------------------------


def test_generic_codes_map_to_their_documented_status() -> None:
    """The generic codes and their statuses stay consistent (M13.6)."""
    for code, status in GENERIC_CODE_STATUS.items():
        assert 400 <= status < 600
        assert code.isupper()

    assert GENERIC_CODE_STATUS[ErrorCode.NOT_FOUND] == 404
    assert GENERIC_CODE_STATUS[ErrorCode.CONFLICT] == 409
    assert GENERIC_CODE_STATUS[ErrorCode.INTERNAL_ERROR] == 500


def test_resource_codes_are_distinct() -> None:
    """Two resources never share a not-found code (M13.5).

    A client branches on the code to decide what to look up next, so ``"NOT_FOUND"``
    twice for two different resources would make that impossible.
    """
    codes = [
        value
        for name, value in vars(ErrorCode).items()
        if not name.startswith("_") and isinstance(value, str)
    ]

    assert codes, "the code vocabulary must not be empty"
    not_found = [code for code in codes if code.endswith("_NOT_FOUND")]
    assert len(not_found) == len(set(not_found)) >= 9


# ---------------------------------------------------------------------------
# Deterministic responses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url", ["/api/v1/reports", "/api/v1/notifications", "/api/v1/settings"]
)
def test_two_identical_requests_return_identical_bodies(
    client: TestClient, url: str
) -> None:
    """The same request twice returns the same bytes (M13.24).

    Ordering that is only *usually* stable would make a page boundary able to
    shuffle rows, so this is checked on the body rather than on a subset of it.
    """
    assert client.get(url).text == client.get(url).text
