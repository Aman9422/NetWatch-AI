"""API tests for the capture control endpoints (status/start/stop)."""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.capture_manager import CaptureManager, get_capture_manager
from app.services.interface_manager import InterfaceManager, get_interface_manager
from tests.fakes import FakeCaptureSniffer, make_sniffer_factory


@pytest.fixture
def sniffer_registry() -> list[FakeCaptureSniffer]:
    """List that records every fake sniffer created during a test."""
    return []


@pytest.fixture
def interface_manager() -> InterfaceManager:
    """An interface manager backed by a fixed, valid interface set."""
    return InterfaceManager(
        discovery=lambda: [
            {"name": "Wi-Fi", "ip_addresses": ["192.168.1.20"], "is_up": True},
            {"name": "Ethernet", "ip_addresses": [], "is_up": False},
        ]
    )


@pytest.fixture
def capture_manager(
    interface_manager: InterfaceManager,
    sniffer_registry: list[FakeCaptureSniffer],
) -> CaptureManager:
    """A capture manager wired to fake sniffers via the shared interface manager."""
    return CaptureManager(
        interface_manager=interface_manager,
        sniffer_factory=make_sniffer_factory(registry=sniffer_registry),
    )


@pytest.fixture
def client(
    interface_manager: InterfaceManager,
    capture_manager: CaptureManager,
) -> Generator[TestClient, None, None]:
    """Test client with both managers overridden by in-memory fakes."""
    app.dependency_overrides[get_interface_manager] = lambda: interface_manager
    app.dependency_overrides[get_capture_manager] = lambda: capture_manager
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.pop(get_interface_manager, None)
        app.dependency_overrides.pop(get_capture_manager, None)


def _select_wifi(client: TestClient) -> None:
    """Select the valid Wi-Fi interface through the API."""
    client.put("/api/v1/capture/interface", json={"name": "Wi-Fi"})


# ---------------------------------------------------------------------------
# GET /capture/status
# ---------------------------------------------------------------------------


def test_status_before_start(client: TestClient) -> None:
    """Status is 'stopped' before any capture has started."""
    response = client.get("/api/v1/capture/status")

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["status"] == "stopped"
    assert body["data"]["interface"] is None
    assert body["data"]["packet_count"] == 0


# ---------------------------------------------------------------------------
# POST /capture/start
# ---------------------------------------------------------------------------


def test_start_with_valid_interface(client: TestClient) -> None:
    """Starting with a valid selected interface returns 200 and 'running'."""
    _select_wifi(client)

    response = client.post("/api/v1/capture/start")

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["status"] == "running"
    assert body["data"]["interface"] == "Wi-Fi"


def test_start_without_interface_is_rejected(client: TestClient) -> None:
    """Starting without a selected interface returns 400 with an error code."""
    response = client.post("/api/v1/capture/start")

    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == "CAPTURE_NO_INTERFACE"


def test_start_when_already_running_is_conflict(
    client: TestClient,
    sniffer_registry: list[FakeCaptureSniffer],
) -> None:
    """A second start while running returns 409 and keeps the session alive."""
    _select_wifi(client)
    client.post("/api/v1/capture/start")

    response = client.post("/api/v1/capture/start")

    assert response.status_code == 409
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == "CAPTURE_ALREADY_RUNNING"
    assert sniffer_registry[0].running is True


def test_status_reports_running_state(
    client: TestClient,
    sniffer_registry: list[FakeCaptureSniffer],
) -> None:
    """Status reflects the live packet count while capturing."""
    _select_wifi(client)
    client.post("/api/v1/capture/start")
    sniffer_registry[0].emit(250)

    response = client.get("/api/v1/capture/status")

    assert response.status_code == 200
    assert response.json()["data"]["status"] == "running"
    assert response.json()["data"]["packet_count"] == 250


# ---------------------------------------------------------------------------
# POST /capture/stop
# ---------------------------------------------------------------------------


def test_stop_when_running(client: TestClient) -> None:
    """Stopping an active capture returns 200 and 'stopped'."""
    _select_wifi(client)
    client.post("/api/v1/capture/start")

    response = client.post("/api/v1/capture/stop")

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["status"] == "stopped"


def test_stop_when_already_stopped_is_conflict(client: TestClient) -> None:
    """Stopping when nothing is running returns 409."""
    response = client.post("/api/v1/capture/stop")

    assert response.status_code == 409
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == "CAPTURE_NOT_RUNNING"


# ---------------------------------------------------------------------------
# Routing conventions
# ---------------------------------------------------------------------------


def test_invalid_method_on_status(client: TestClient) -> None:
    """POST on /capture/status is not allowed."""
    response = client.post("/api/v1/capture/status")

    assert response.status_code == 405


def test_unknown_capture_route_is_404(client: TestClient) -> None:
    """An unknown capture route returns 404."""
    response = client.get("/api/v1/capture/does-not-exist")

    assert response.status_code == 404
