"""API tests for the read-only statistics endpoints (M6.19).

Verifies the response envelope, empty and non-empty states, query-parameter
validation, the reset endpoint and HTTP routing conventions.
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app.config.settings import settings
from app.main import app
from app.schemas.packet import PacketType
from app.statistics.manager import TrafficStatisticsManager, get_statistics_manager
from tests.fakes import make_normalized_packet

TRAFFIC_URL = "/api/v1/statistics/traffic"
PROTOCOLS_URL = "/api/v1/statistics/protocols"
TOP_TALKERS_URL = "/api/v1/statistics/top-talkers"
PORTS_URL = "/api/v1/statistics/ports"
RESET_URL = "/api/v1/statistics/reset"


@pytest.fixture
def statistics_manager() -> TrafficStatisticsManager:
    """A fresh statistics manager for each API test."""
    return TrafficStatisticsManager()


@pytest.fixture
def client(statistics_manager: TrafficStatisticsManager) -> Generator[TestClient, None, None]:
    """Test client with the statistics manager overridden by a fresh instance.

    The application environment is temporarily set to ``"test"`` so the lifespan
    skips ``init_db()`` and never touches the real database.
    """
    original_env = settings.app_env
    settings.app_env = "test"
    app.dependency_overrides[get_statistics_manager] = lambda: statistics_manager
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.pop(get_statistics_manager, None)
        settings.app_env = original_env


def _seed(manager: TrafficStatisticsManager) -> None:
    """Record a small, mixed sample of traffic for non-empty-state tests."""
    manager.record_packet(
        make_normalized_packet(
            packet_type=PacketType.TCP,
            protocol="TCP",
            source_ip="192.168.1.10",
            destination_ip="8.8.8.8",
            source_port=52000,
            destination_port=443,
            length=100,
        )
    )
    manager.record_packet(
        make_normalized_packet(
            packet_type=PacketType.DNS,
            protocol="UDP",
            source_ip="192.168.1.20",
            destination_ip="1.1.1.1",
            source_port=53000,
            destination_port=53,
            length=80,
        )
    )


# ---------------------------------------------------------------------------
# GET /statistics/traffic
# ---------------------------------------------------------------------------


def test_traffic_empty_state(client: TestClient) -> None:
    """An empty engine returns a well-formed zero snapshot."""
    response = client.get(TRAFFIC_URL)

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["total_packets"] == 0
    assert body["data"]["total_bytes"] == 0
    assert body["data"]["protocol_statistics"] == []


def test_traffic_non_empty_state(
    client: TestClient, statistics_manager: TrafficStatisticsManager
) -> None:
    """A seeded engine reports the aggregated totals."""
    _seed(statistics_manager)

    response = client.get(TRAFFIC_URL)

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["total_packets"] == 2
    assert data["total_bytes"] == 180
    assert {stat["protocol"] for stat in data["protocol_statistics"]} == {"TCP", "DNS"}


def test_traffic_snapshot_has_required_fields(
    client: TestClient, statistics_manager: TrafficStatisticsManager
) -> None:
    """The snapshot exposes every field listed in the M6.12 structure."""
    _seed(statistics_manager)

    data = client.get(TRAFFIC_URL).json()["data"]

    assert {
        "timestamp",
        "total_packets",
        "total_bytes",
        "packets_per_second",
        "bytes_per_second",
        "protocol_statistics",
        "top_sources",
        "top_destinations",
        "top_ports",
    } <= set(data)


def test_traffic_window_parameter_is_accepted(
    client: TestClient, statistics_manager: TrafficStatisticsManager
) -> None:
    """A supported window label is accepted without error."""
    _seed(statistics_manager)

    response = client.get(TRAFFIC_URL, params={"window": "10s"})

    assert response.status_code == 200


def test_traffic_unknown_window_is_rejected(client: TestClient) -> None:
    """An unsupported window label fails validation."""
    response = client.get(TRAFFIC_URL, params={"window": "5m"})

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# GET /statistics/protocols
# ---------------------------------------------------------------------------


def test_protocols_empty_state(client: TestClient) -> None:
    """No protocols are reported before any packet is seen."""
    response = client.get(PROTOCOLS_URL)

    assert response.status_code == 200
    assert response.json()["data"] == []


def test_protocols_non_empty_state(
    client: TestClient, statistics_manager: TrafficStatisticsManager
) -> None:
    """Protocol entries carry packet, byte and percentage data."""
    _seed(statistics_manager)

    data = client.get(PROTOCOLS_URL).json()["data"]
    by_name = {entry["protocol"]: entry for entry in data}

    assert by_name["TCP"]["packets"] == 1
    assert by_name["TCP"]["bytes"] == 100
    assert by_name["TCP"]["percentage"] == 50.0


# ---------------------------------------------------------------------------
# GET /statistics/top-talkers
# ---------------------------------------------------------------------------


def test_top_talkers_empty_state(client: TestClient) -> None:
    """Empty rankings are returned as empty lists."""
    response = client.get(TOP_TALKERS_URL)

    assert response.status_code == 200
    assert response.json()["data"] == {
        "sources": [],
        "destinations": [],
        "conversations": [],
    }


def test_top_talkers_non_empty_state(
    client: TestClient, statistics_manager: TrafficStatisticsManager
) -> None:
    """Top sources and destinations reflect the seeded traffic."""
    _seed(statistics_manager)

    data = client.get(TOP_TALKERS_URL).json()["data"]

    assert {entry["key"] for entry in data["sources"]} == {"192.168.1.10", "192.168.1.20"}
    assert {entry["key"] for entry in data["destinations"]} == {"8.8.8.8", "1.1.1.1"}


def test_top_talkers_limit_is_validated(client: TestClient) -> None:
    """Out-of-range limits fail validation."""
    assert client.get(TOP_TALKERS_URL, params={"limit": 0}).status_code == 422
    assert client.get(TOP_TALKERS_URL, params={"limit": 5000}).status_code == 422


def test_top_talkers_unknown_metric_is_rejected(client: TestClient) -> None:
    """An unsupported ranking metric fails validation."""
    response = client.get(TOP_TALKERS_URL, params={"by": "magic"})

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# GET /statistics/ports
# ---------------------------------------------------------------------------


def test_ports_empty_state(client: TestClient) -> None:
    """No ports are reported before any packet is seen."""
    response = client.get(PORTS_URL)

    assert response.status_code == 200
    assert response.json()["data"] == []


def test_ports_destination_by_default(
    client: TestClient, statistics_manager: TrafficStatisticsManager
) -> None:
    """The default ranking is by destination port."""
    _seed(statistics_manager)

    data = client.get(PORTS_URL).json()["data"]

    assert {entry["key"] for entry in data} == {"443", "53"}


def test_ports_source_direction(
    client: TestClient, statistics_manager: TrafficStatisticsManager
) -> None:
    """The source direction is available through the query parameter."""
    _seed(statistics_manager)

    data = client.get(PORTS_URL, params={"direction": "source"}).json()["data"]

    assert {entry["key"] for entry in data} == {"52000", "53000"}


def test_ports_unknown_direction_is_rejected(client: TestClient) -> None:
    """An unsupported direction fails validation."""
    response = client.get(PORTS_URL, params={"direction": "sideways"})

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# POST /statistics/reset
# ---------------------------------------------------------------------------


def test_reset_clears_statistics(
    client: TestClient, statistics_manager: TrafficStatisticsManager
) -> None:
    """Reset returns success and empties the counters."""
    _seed(statistics_manager)

    reset_response = client.post(RESET_URL)
    traffic = client.get(TRAFFIC_URL).json()["data"]

    assert reset_response.status_code == 200
    assert reset_response.json()["data"] == {"reset": True}
    assert traffic["total_packets"] == 0


def test_reset_leaves_service_available(client: TestClient) -> None:
    """After reset the endpoints still respond successfully."""
    client.post(RESET_URL)

    assert client.get(TRAFFIC_URL).status_code == 200
    assert client.get(PROTOCOLS_URL).status_code == 200


def test_reset_rejects_get_method(client: TestClient) -> None:
    """GET on the reset endpoint is not allowed."""
    response = client.get(RESET_URL)

    assert response.status_code == 405


# ---------------------------------------------------------------------------
# HTTP / routing conventions
# ---------------------------------------------------------------------------


def test_traffic_rejects_post_method(client: TestClient) -> None:
    """POST on the read-only traffic endpoint is not allowed."""
    assert client.post(TRAFFIC_URL).status_code == 405


def test_protocols_reject_put_method(client: TestClient) -> None:
    """PUT on the read-only protocols endpoint is not allowed."""
    assert client.put(PROTOCOLS_URL).status_code == 405


def test_unknown_statistics_route_is_404(client: TestClient) -> None:
    """An unknown statistics route returns 404."""
    assert client.get("/api/v1/statistics/does-not-exist").status_code == 404
