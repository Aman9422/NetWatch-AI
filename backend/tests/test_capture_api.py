"""Tests for the capture interface API endpoints."""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.interface_manager import InterfaceManager, get_interface_manager


def _sample_interfaces() -> list[dict]:
    """Return a normalized list of sample interfaces for tests."""
    return [
        {
            "name": "Wi-Fi",
            "description": None,
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "ip_addresses": ["192.168.1.20"],
            "is_up": True,
        },
        {
            "name": "Ethernet",
            "description": None,
            "mac_address": None,
            "ip_addresses": [],
            "is_up": False,
        },
    ]


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    """Return a test client backed by a mock interface manager."""
    manager = InterfaceManager(discovery=lambda: _sample_interfaces())
    app.dependency_overrides[get_interface_manager] = lambda: manager
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.pop(get_interface_manager, None)


# ---------------------------------------------------------------------------
# GET /capture/interfaces
# ---------------------------------------------------------------------------


def test_list_interfaces(client: TestClient) -> None:
    """GET /capture/interfaces lists all interfaces with normalized data."""
    response = client.get("/api/v1/capture/interfaces")

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    names = [interface["name"] for interface in body["data"]]
    assert names == ["Wi-Fi", "Ethernet"]
    assert body["data"][0]["mac_address"] == "AA:BB:CC:DD:EE:FF"


# ---------------------------------------------------------------------------
# GET /capture/interface
# ---------------------------------------------------------------------------


def test_get_selected_interface_before_selection(client: TestClient) -> None:
    """GET /capture/interface returns 400 when nothing is selected."""
    response = client.get("/api/v1/capture/interface")

    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == "NO_INTERFACE_SELECTED"


def test_get_selected_interface_after_selection(client: TestClient) -> None:
    """GET /capture/interface returns the selected interface."""
    client.put("/api/v1/capture/interface", json={"name": "Wi-Fi"})
    response = client.get("/api/v1/capture/interface")

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["name"] == "Wi-Fi"


# ---------------------------------------------------------------------------
# PUT /capture/interface
# ---------------------------------------------------------------------------


def test_select_valid_interface(client: TestClient) -> None:
    """PUT /capture/interface selects a valid, available interface."""
    response = client.put("/api/v1/capture/interface", json={"name": "Wi-Fi"})

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["message"] == "Interface selected"
    assert body["data"]["name"] == "Wi-Fi"


def test_select_invalid_interface(client: TestClient) -> None:
    """PUT /capture/interface rejects a non-existent interface."""
    response = client.put("/api/v1/capture/interface", json={"name": "Not-Real"})

    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == "INTERFACE_NOT_FOUND"


def test_select_unavailable_interface(client: TestClient) -> None:
    """PUT /capture/interface rejects an interface that is down."""
    response = client.put("/api/v1/capture/interface", json={"name": "Ethernet"})

    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == "INTERFACE_UNAVAILABLE"


def test_select_empty_interface_name(client: TestClient) -> None:
    """PUT /capture/interface rejects an empty interface name."""
    response = client.put("/api/v1/capture/interface", json={"name": "  "})

    assert response.status_code == 422
    body = response.json()
    assert "name" in str(body["detail"])


def test_select_missing_interface_name(client: TestClient) -> None:
    """PUT /capture/interface rejects a request without a name."""
    response = client.put("/api/v1/capture/interface", json={})

    assert response.status_code == 422


def test_select_currently_selected_interface_is_idempotent(client: TestClient) -> None:
    """Selecting the already-selected interface still returns success."""
    client.put("/api/v1/capture/interface", json={"name": "Wi-Fi"})
    response = client.put("/api/v1/capture/interface", json={"name": "Wi-Fi"})

    assert response.status_code == 200
    assert response.json()["success"] is True


def test_selection_changes(client: TestClient) -> None:
    """PUT /capture/interface changes the selected interface after a valid pick."""
    other_interfaces = [
        {"name": "Wi-Fi", "ip_addresses": [], "is_up": True},
        {"name": "Ethernet", "ip_addresses": ["10.0.0.5"], "is_up": True},
    ]
    manager = InterfaceManager(discovery=lambda: other_interfaces)
    app.dependency_overrides[get_interface_manager] = lambda: manager
    try:
        client.put("/api/v1/capture/interface", json={"name": "Wi-Fi"})
        first = client.get("/api/v1/capture/interface")
        assert first.json()["data"]["name"] == "Wi-Fi"

        client.put("/api/v1/capture/interface", json={"name": "Ethernet"})
        second = client.get("/api/v1/capture/interface")
        assert second.json()["data"]["name"] == "Ethernet"
    finally:
        app.dependency_overrides.pop(get_interface_manager, None)


# ---------------------------------------------------------------------------
# HTTP / routing conventions
# ---------------------------------------------------------------------------


def test_invalid_method_on_capture_interface(client: TestClient) -> None:
    """POST on /capture/interface is not allowed."""
    response = client.post("/api/v1/capture/interface", json={"name": "Wi-Fi"})

    assert response.status_code == 405


def test_invalid_capture_endpoint_returns_404(client: TestClient) -> None:
    """An unknown capture route returns HTTP 404."""
    response = client.get("/api/v1/capture/nope")

    assert response.status_code == 404
