"""API tests for the read-only device endpoints (M8.21).

Verifies the response envelope, empty and non-empty states, device lookup,
query-parameter filtering and validation, and HTTP routing conventions.
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app.config.settings import settings
from app.devices.manager import DeviceDiscoveryManager, get_device_manager
from app.main import app
from tests.fakes import PACKET_BASE_TIME, FakeClock, make_normalized_packet

DEVICES_URL = "/api/v1/devices"

MAC_A = "AA:BB:CC:DD:EE:FF"
MAC_B = "22:33:44:55:66:77"
IP_A = "192.168.1.10"
IP_B = "192.168.1.20"

# A timestamp far enough in the past to be "inactive" under the threshold below.
STALE_TIME = PACKET_BASE_TIME - 300.0


@pytest.fixture
def device_manager() -> DeviceDiscoveryManager:
    """A fresh device manager with a deterministic clock for each API test."""
    return DeviceDiscoveryManager(
        inactivity_threshold=60.0,
        retention_seconds=600.0,
        clock=FakeClock(PACKET_BASE_TIME),
    )


@pytest.fixture
def client(device_manager: DeviceDiscoveryManager) -> Generator[TestClient, None, None]:
    """Test client with the device manager overridden by a fresh instance.

    The application environment is temporarily set to ``"test"`` so the lifespan
    skips ``init_db()`` and never touches the real database.
    """
    original_env = settings.app_env
    settings.app_env = "test"
    app.dependency_overrides[get_device_manager] = lambda: device_manager
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.pop(get_device_manager, None)
        settings.app_env = original_env


def _seed_one(manager: DeviceDiscoveryManager) -> None:
    """Track a single active device."""
    manager.process_packet(
        make_normalized_packet(
            source_mac=MAC_A,
            source_ip=IP_A,
            destination_ip=None,
            length=100,
            timestamp=PACKET_BASE_TIME,
        )
    )


def _seed_pair(manager: DeviceDiscoveryManager) -> None:
    """Track two devices, one of them stale."""
    _seed_one(manager)
    manager.process_packet(
        make_normalized_packet(
            source_mac=MAC_B,
            source_ip=IP_B,
            destination_ip=None,
            length=200,
            timestamp=STALE_TIME,
        )
    )


# ---------------------------------------------------------------------------
# GET /devices
# ---------------------------------------------------------------------------


def test_empty_device_list(client: TestClient) -> None:
    """An empty registry returns a well-formed, empty collection."""
    response = client.get(DEVICES_URL)

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["count"] == 0
    assert body["data"]["devices"] == []


def test_one_device_is_returned(
    client: TestClient, device_manager: DeviceDiscoveryManager
) -> None:
    """A single tracked device is exposed with its observed statistics."""
    _seed_one(device_manager)

    data = client.get(DEVICES_URL).json()["data"]

    assert data["count"] == 1
    device = data["devices"][0]
    assert device["device_id"] == f"mac:{MAC_A}"
    assert device["mac_address"] == MAC_A
    assert device["ip_addresses"] == [IP_A]
    assert device["packet_count"] == 1
    assert device["byte_count"] == 100
    assert device["status"] == "active"
    assert device["is_local"] is False


def test_multiple_devices_are_returned(
    client: TestClient, device_manager: DeviceDiscoveryManager
) -> None:
    """Every tracked device appears in the collection."""
    _seed_pair(device_manager)

    data = client.get(DEVICES_URL).json()["data"]

    assert data["count"] == 2
    assert {device["device_id"] for device in data["devices"]} == {
        f"mac:{MAC_A}",
        f"mac:{MAC_B}",
    }


def test_device_payload_has_required_fields(
    client: TestClient, device_manager: DeviceDiscoveryManager
) -> None:
    """The device projection exposes the M8.19 statistics and no risk score."""
    _seed_one(device_manager)

    device = client.get(DEVICES_URL).json()["data"]["devices"][0]

    assert {
        "device_id",
        "mac_address",
        "ip_addresses",
        "first_seen",
        "last_seen",
        "packet_count",
        "byte_count",
        "hostname",
        "vendor",
        "status",
    } <= set(device)
    assert "risk_score" not in device


# ---------------------------------------------------------------------------
# GET /devices/{device_id}
# ---------------------------------------------------------------------------


def test_device_lookup_returns_the_device(
    client: TestClient, device_manager: DeviceDiscoveryManager
) -> None:
    """A known device id resolves to that device."""
    _seed_one(device_manager)

    response = client.get(f"{DEVICES_URL}/mac:{MAC_A}")

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["device_id"] == f"mac:{MAC_A}"


def test_unknown_device_returns_404(client: TestClient) -> None:
    """An unknown device id returns the standard not-found envelope."""
    response = client.get(f"{DEVICES_URL}/mac:{MAC_A}")

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [
        {"field": "device_id", "code": "DEVICE_NOT_FOUND"}
    ]


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


def test_filter_by_status(
    client: TestClient, device_manager: DeviceDiscoveryManager
) -> None:
    """Activity state can be used to narrow the collection."""
    _seed_pair(device_manager)

    active = client.get(DEVICES_URL, params={"status": "active"}).json()["data"]
    inactive = client.get(DEVICES_URL, params={"status": "inactive"}).json()["data"]

    assert [d["device_id"] for d in active["devices"]] == [f"mac:{MAC_A}"]
    assert [d["device_id"] for d in inactive["devices"]] == [f"mac:{MAC_B}"]


def test_filter_by_ip(client: TestClient, device_manager: DeviceDiscoveryManager) -> None:
    """Filtering by address returns only the owning device."""
    _seed_pair(device_manager)

    data = client.get(DEVICES_URL, params={"ip": IP_A}).json()["data"]

    assert data["count"] == 1
    assert data["devices"][0]["device_id"] == f"mac:{MAC_A}"


def test_filter_by_mac_is_normalized(
    client: TestClient, device_manager: DeviceDiscoveryManager
) -> None:
    """A differently-cased MAC filter still matches the device."""
    _seed_pair(device_manager)

    data = client.get(DEVICES_URL, params={"mac": MAC_A.lower()}).json()["data"]

    assert data["count"] == 1
    assert data["devices"][0]["device_id"] == f"mac:{MAC_A}"


def test_unknown_address_yields_an_empty_list(
    client: TestClient, device_manager: DeviceDiscoveryManager
) -> None:
    """A valid filter that matches nothing returns an empty collection."""
    _seed_pair(device_manager)

    data = client.get(DEVICES_URL, params={"ip": "10.9.9.9"}).json()["data"]

    assert data["count"] == 0
    assert data["devices"] == []


def test_limit_truncates_the_collection(
    client: TestClient, device_manager: DeviceDiscoveryManager
) -> None:
    """``limit`` caps how many devices are returned."""
    _seed_pair(device_manager)

    data = client.get(DEVICES_URL, params={"limit": 1}).json()["data"]

    assert data["count"] == 1


# ---------------------------------------------------------------------------
# Query-parameter validation
# ---------------------------------------------------------------------------


def test_invalid_ip_filter_is_rejected(client: TestClient) -> None:
    """An unparseable IP filter fails loudly rather than being ignored."""
    response = client.get(DEVICES_URL, params={"ip": "not-an-ip"})

    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [{"field": "ip", "code": "INVALID_FILTER"}]


def test_invalid_mac_filter_is_rejected(client: TestClient) -> None:
    """An unparseable MAC filter fails loudly rather than being ignored."""
    response = client.get(DEVICES_URL, params={"mac": "not-a-mac"})

    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [{"field": "mac", "code": "INVALID_FILTER"}]


def test_limit_must_be_positive(client: TestClient) -> None:
    """A non-positive limit fails request validation."""
    assert client.get(DEVICES_URL, params={"limit": 0}).status_code == 422


def test_limit_has_an_upper_bound(client: TestClient) -> None:
    """An excessive limit fails request validation."""
    assert client.get(DEVICES_URL, params={"limit": 100_000}).status_code == 422


def test_unknown_status_is_rejected(client: TestClient) -> None:
    """An unsupported activity state fails request validation."""
    assert client.get(DEVICES_URL, params={"status": "haunted"}).status_code == 422


# ---------------------------------------------------------------------------
# HTTP / routing conventions
# ---------------------------------------------------------------------------


def test_post_is_not_allowed(client: TestClient) -> None:
    """The device API is read-only: POST is not allowed."""
    assert client.post(DEVICES_URL).status_code == 405


def test_put_is_not_allowed(client: TestClient) -> None:
    """The device API is read-only: PUT is not allowed."""
    assert client.put(DEVICES_URL).status_code == 405


def test_delete_is_not_allowed(client: TestClient) -> None:
    """The device API is read-only: DELETE is not allowed."""
    assert client.delete(DEVICES_URL).status_code == 405


def test_unknown_route_is_404(client: TestClient) -> None:
    """An unknown device sub-route returns 404."""
    assert client.get(f"{DEVICES_URL}/nested/path").status_code == 404
