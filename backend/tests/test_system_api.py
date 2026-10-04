"""API tests for the system endpoints (M13.22).

``/system/info``, ``/system/health`` and ``/system/status`` answer three
different questions — what is this build, is it working, and what is it doing —
and the tests are grouped the same way.

Two properties are checked throughout because M13.22 and M13.30 make them
requirements rather than style: a failed probe is reported as a *verdict* rather
than raised, and nothing a response carries can identify a location or a
credential. The database is described by its dialect, never its URL, and a
driver's own message never reaches the client.
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app.api.v1.system import (
    API_PREFIX,
    API_VERSION,
    DOCUMENTED_METHODS,
    STATUS_DEGRADED,
    STATUS_HEALTHY,
)
from app.config.settings import settings
from app.database.session import get_db
from app.main import app
from app.services.capture_manager import get_capture_manager
from app.utils import runtime
from tests.m13_fakes import api_client, capture_manager_override

INFO_URL = "/api/v1/system/info"
HEALTH_URL = "/api/v1/system/health"
STATUS_URL = "/api/v1/system/status"

#: The pipeline stages ``/system/status`` always reports, in order.
SERVICE_NAMES = (
    "persistence",
    "statistics",
    "devices",
    "connections",
    "detection",
    "alerts",
    "correlation",
)


class BrokenSession:
    """A session whose every statement fails, for the probe tests.

    Deliberately not a ``Mock``: the point is that a real failure of the
    database — not a missing object — is reported as a verdict and never as a
    traceback (M13.22/M13.29).
    """

    def execute(self, *_args: object, **_kwargs: object) -> object:
        """Fail every statement, standing in for an unreachable database."""
        raise RuntimeError("simulated database outage")


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    """An isolated client over a fake capture manager and no real database."""
    with api_client({get_capture_manager: capture_manager_override()}) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# GET /system/info
# ---------------------------------------------------------------------------


def test_info_reports_identity(client: TestClient) -> None:
    """``info`` reports the running build and environment (M13.22)."""
    body = client.get(INFO_URL).json()

    assert body["success"] is True
    data = body["data"]
    assert data["app_name"] == settings.app_name
    assert data["app_version"] == settings.app_version
    assert data["environment"] == "test"
    assert data["timezone"] == "UTC"


def test_info_version_matches_the_base_path(client: TestClient) -> None:
    """The reported version is derived from the served prefix (M13.3).

    They are compared to the module constants rather than to a literal, because
    the property being tested is that the label and the path cannot disagree —
    which only holds if it is derived from it.
    """
    data = client.get(INFO_URL).json()["data"]

    assert API_PREFIX == "/api/v1"
    assert data["api_version"] == API_VERSION == "v1"


def test_info_reports_the_documentation_paths(client: TestClient) -> None:
    """The interactive docs and OpenAPI document paths are reported (M13.27)."""
    data = client.get(INFO_URL).json()["data"]

    assert data["docs_url"] == "/docs"
    assert data["openapi_url"] == "/openapi.json"


def test_info_reports_a_live_route_count(client: TestClient) -> None:
    """The route count is the application's own, not a hard-coded number.

    The expected value is recomputed here from the same document the endpoint
    reads — the OpenAPI schema, which is the only thing that describes the whole
    surface — so the test fails if the reported count and the documented surface
    ever disagree. ``app.routes`` is deliberately not used: on FastAPI 0.141 an
    included router stays nested, so it holds one object rather than sixty-one
    routes.
    """
    data = client.get(INFO_URL).json()["data"]
    documented = app.openapi().get("paths", {})
    expected = sum(
        1
        for path, operations in documented.items()
        if str(path).startswith(API_PREFIX)
        for method in operations
        if str(method).lower() in DOCUMENTED_METHODS
    )

    assert data["registered_route_count"] == expected
    assert expected > 1


def test_info_reports_the_database_dialect(client: TestClient) -> None:
    """The engine family is reported so a client can act on it (M13.22)."""
    assert client.get(INFO_URL).json()["data"]["database_dialect"] == "sqlite"


def test_info_does_not_expose_the_database_url(client: TestClient) -> None:
    """No response field identifies where the database lives (M13.30)."""
    text = client.get(INFO_URL).text

    assert "sqlite:///" not in text
    assert ".db" not in text
    assert "password" not in text.lower()


def test_info_needs_no_dependency(client: TestClient) -> None:
    """``info`` answers over a dead database, which is when it matters."""
    with api_client(
        {
            get_capture_manager: capture_manager_override(),
            get_db: lambda: BrokenSession(),
        }
    ) as broken_client:
        response = broken_client.get(INFO_URL)

    assert response.status_code == 200


# ---------------------------------------------------------------------------
# GET /system/health
# ---------------------------------------------------------------------------


def test_health_reports_healthy_when_dependencies_answer(
    client: TestClient,
) -> None:
    """Every probe passes, so the aggregate verdict is healthy (M13.22)."""
    body = client.get(HEALTH_URL).json()

    assert body["success"] is True
    assert body["data"]["status"] == STATUS_HEALTHY
    assert {check["name"] for check in body["data"]["checks"]} == {
        "database",
        "capture",
    }
    assert all(check["ok"] for check in body["data"]["checks"])


def test_health_always_answers_200(client: TestClient) -> None:
    """A down dependency is a verdict in the body, not a status on the request.

    Answering 503 here would stop a caller reading *which* probe failed, which
    is the only useful part of the answer (M13.22).
    """
    with api_client(
        {
            get_capture_manager: capture_manager_override(),
            get_db: lambda: BrokenSession(),
        }
    ) as broken_client:
        response = broken_client.get(HEALTH_URL)

    assert response.status_code == 200


def test_health_reports_degraded_when_the_database_fails() -> None:
    """A failing database probe degrades the verdict and names itself."""
    with api_client(
        {
            get_capture_manager: capture_manager_override(),
            get_db: lambda: BrokenSession(),
        }
    ) as broken_client:
        body = broken_client.get(HEALTH_URL).json()

    assert body["data"]["status"] == STATUS_DEGRADED
    by_name = {check["name"]: check for check in body["data"]["checks"]}
    assert by_name["database"]["ok"] is False
    # Capture is idle, which is healthy: capture is opt-in (M13.22).
    assert by_name["capture"]["ok"] is True


def test_health_does_not_expose_the_driver_message() -> None:
    """The probe reports which dependency failed, never why internally (M13.5)."""
    with api_client(
        {
            get_capture_manager: capture_manager_override(),
            get_db: lambda: BrokenSession(),
        }
    ) as broken_client:
        text = broken_client.get(HEALTH_URL).text

    assert "simulated database outage" not in text
    assert "Traceback" not in text
    assert "RuntimeError" not in text


def test_health_treats_an_idle_capture_as_healthy(client: TestClient) -> None:
    """Capture being stopped is a state, not a fault (M13.22)."""
    checks = client.get(HEALTH_URL).json()["data"]["checks"]
    capture = next(check for check in checks if check["name"] == "capture")

    assert capture["ok"] is True
    assert capture["detail"] == "capture is idle"


# ---------------------------------------------------------------------------
# GET /system/status
# ---------------------------------------------------------------------------


def test_status_reports_every_block(client: TestClient) -> None:
    """The consolidated view carries every block the schema declares (M13.22)."""
    body = client.get(STATUS_URL).json()

    assert body["success"] is True
    assert set(body["data"]) == {
        "status",
        "info",
        "capture",
        "database",
        "services",
        "runtime",
    }


def test_status_reports_each_pipeline_stage(client: TestClient) -> None:
    """Every stage is named, and attachment reflects the live pipeline.

    The fake pipeline holds no persistence, connections, detection, alerting or
    correlation, so those stages report themselves as configured-on but not
    attached — the disagreement the two fields exist to expose (M13.22).
    """
    services = client.get(STATUS_URL).json()["data"]["services"]
    by_name = {service["name"]: service for service in services}

    assert tuple(by_name) == SERVICE_NAMES
    assert by_name["statistics"]["attached"] is True
    assert by_name["devices"]["attached"] is True
    assert by_name["persistence"]["attached"] is False
    assert by_name["correlation"]["attached"] is False


def test_status_reports_capture_state(client: TestClient) -> None:
    """Capture has not been started, and the block says exactly that."""
    capture = client.get(STATUS_URL).json()["data"]["capture"]

    assert capture["running"] is False
    assert capture["status"] == "stopped"
    assert capture["packet_count"] == 0
    assert capture["error_counts"] == {}


def test_status_reports_the_database_as_reachable(client: TestClient) -> None:
    """An answering database is reported reachable, by dialect not by URL."""
    database = client.get(STATUS_URL).json()["data"]["database"]

    assert database["reachable"] is True
    assert database["dialect"] == "sqlite"


def test_status_is_degraded_when_the_database_is_unreachable() -> None:
    """An unreachable database degrades the consolidated verdict (M13.22)."""
    with api_client(
        {
            get_capture_manager: capture_manager_override(),
            get_db: lambda: BrokenSession(),
        }
    ) as broken_client:
        data = broken_client.get(STATUS_URL).json()["data"]

    assert data["status"] == STATUS_DEGRADED
    assert data["database"]["reachable"] is False
    # The rest of the picture is still reported, which is the point of a
    # consolidated view rather than a gate (M13.29).
    assert data["capture"]["running"] is False


def test_status_reports_uptime_recorded_at_startup(client: TestClient) -> None:
    """The lifespan recorded the start, so uptime is a real measurement."""
    metrics = client.get(STATUS_URL).json()["data"]["runtime"]

    assert metrics["uptime_seconds"] is not None
    assert metrics["uptime_seconds"] >= 0.0
    assert metrics["started_at"] is not None
    assert metrics["generated_at"] is not None
    assert metrics["pid"] > 0
    assert metrics["python_version"]


def test_status_reports_uptime_as_absent_when_not_recorded(
    client: TestClient,
) -> None:
    """An unrecorded start is reported as absent, not as a plausible zero.

    ``0.0`` would claim the process started this instant, which is a different
    statement from "this was never recorded" (M13.22).
    """
    runtime.reset_process_started()
    try:
        metrics = client.get(STATUS_URL).json()["data"]["runtime"]
    finally:
        runtime.mark_process_started()

    assert metrics["uptime_seconds"] is None
    assert metrics["started_at"] is None


def test_status_timestamps_are_iso8601_utc(client: TestClient) -> None:
    """API timestamps use one documented format, in UTC (M13.26)."""
    metrics = client.get(STATUS_URL).json()["data"]["runtime"]

    assert metrics["generated_at"].endswith("+00:00")
    assert metrics["started_at"].endswith("+00:00")


# ---------------------------------------------------------------------------
# HTTP conventions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", [INFO_URL, HEALTH_URL, STATUS_URL])
def test_system_routes_are_read_only(client: TestClient, url: str) -> None:
    """Nothing on the system surface can change state (M13.22)."""
    assert client.post(url).status_code == 405
    assert client.put(url).status_code == 405
    assert client.delete(url).status_code == 405


def test_unknown_system_route_is_404(client: TestClient) -> None:
    """An unknown system sub-route answers in the standard envelope."""
    response = client.get("/api/v1/system/nope")

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == "NOT_FOUND"


def test_local_application_security_assumption_is_documented() -> None:
    """The module documents that this is an unauthenticated local API (M13.30)."""
    from app.api import v1

    docstring = v1.system.__doc__ or ""
    assert "no authentication" in docstring.lower()
