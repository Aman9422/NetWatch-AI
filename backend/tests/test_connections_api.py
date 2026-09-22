"""API tests for the read-only connection endpoints (M9.22).

Verifies the response envelope, empty and populated states, connection lookup,
query-parameter filtering and validation, and HTTP routing conventions. The M9
API is a verification surface only; the master REST API is M13.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config.settings import settings
from app.connections.identity import connection_id, flow_of
from app.connections.manager import ConnectionTracker, get_connection_tracker
from app.main import app
from app.schemas.connection import ConnectionState
from app.schemas.packet import PacketType
from tests.fakes import PACKET_BASE_TIME, FakeClock, make_normalized_packet

CONNECTIONS_URL = "/api/v1/connections"

SOURCE_IP = "192.168.1.10"
DESTINATION_IP = "8.8.8.8"
SOURCE_PORT = 12345
DESTINATION_PORT = 443


def _identifier(**overrides: Any) -> str:
    """Return the deterministic connection id for a packet's flow."""
    flow = flow_of(make_normalized_packet(**overrides))
    assert flow is not None
    return connection_id(flow.key())


@pytest.fixture
def tracker() -> ConnectionTracker:
    """A fresh, thread-free tracker with a deterministic clock.

    The clock is pinned to the packet fixture's base time so ``POST /expire``
    (which reads the clock) retires only conversations whose packets are older
    than the timeout, rather than every conversation in the registry.
    """
    return ConnectionTracker(
        autostart_cleanup=False, clock=FakeClock(PACKET_BASE_TIME)
    )


@pytest.fixture
def client(tracker: ConnectionTracker) -> Generator[TestClient, None, None]:
    """Test client with the connection tracker overridden by ``tracker``.

    The application environment is temporarily set to ``"test"`` so the
    lifespan skips ``init_db()`` and never touches the real database.
    """
    original_env = settings.app_env
    settings.app_env = "test"
    app.dependency_overrides[get_connection_tracker] = lambda: tracker
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.pop(get_connection_tracker, None)
        settings.app_env = original_env


def _seed_tcp(tracker: ConnectionTracker, **overrides: Any) -> str:
    """Track one TCP conversation and return its connection id."""
    packet = make_normalized_packet(**overrides)
    assert tracker.process_packet(packet) is not None
    return _identifier(**overrides)


def _seed_udp(tracker: ConnectionTracker, **overrides: Any) -> str:
    """Track one UDP conversation and return its connection id."""
    values: dict[str, Any] = {
        "protocol": "UDP",
        "packet_type": PacketType.UDP,
        "destination_port": 53,
    }
    values.update(overrides)
    packet = make_normalized_packet(**values)
    assert tracker.process_packet(packet) is not None
    return _identifier(**values)


def _seed_icmp(tracker: ConnectionTracker, **overrides: Any) -> str:
    """Track one ICMP conversation and return its connection id."""
    values: dict[str, Any] = {
        "protocol": "ICMP",
        "packet_type": PacketType.ICMP,
        "source_port": None,
        "destination_port": None,
    }
    values.update(overrides)
    packet = make_normalized_packet(**values)
    assert tracker.process_packet(packet) is not None
    return _identifier(**values)


def _seed_stale_tcp(tracker: ConnectionTracker, **overrides: Any) -> str:
    """Track one TCP conversation whose packet predates the idle timeout."""
    values: dict[str, Any] = {"timestamp": PACKET_BASE_TIME - 10_000.0}
    values.update(overrides)
    return _seed_tcp(tracker, **values)


# ---------------------------------------------------------------------------
# GET /connections
# ---------------------------------------------------------------------------


def test_empty_connection_list(client: TestClient) -> None:
    """An empty registry returns a well-formed, empty collection."""
    response = client.get(CONNECTIONS_URL)

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["count"] == 0
    assert body["data"]["connections"] == []


def test_one_connection_is_returned(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """A single tracked conversation is exposed with its observed counters."""
    expected_id = _seed_tcp(tracker)

    data = client.get(CONNECTIONS_URL).json()["data"]

    assert data["count"] == 1
    connection = data["connections"][0]
    assert connection["connection_id"] == expected_id
    assert connection["protocol"] == "TCP"
    assert connection["source_ip"] == SOURCE_IP
    assert connection["source_port"] == SOURCE_PORT
    assert connection["destination_ip"] == DESTINATION_IP
    assert connection["destination_port"] == DESTINATION_PORT
    assert connection["packet_count"] == 1
    assert connection["byte_count"] == 100
    assert connection["active"] is True


def test_connection_payload_has_required_fields(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """The projection exposes the M9.6 fields and no threat verdict."""
    _seed_tcp(tracker)

    connection = client.get(CONNECTIONS_URL).json()["data"]["connections"][0]

    assert {
        "connection_id",
        "protocol",
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "first_seen",
        "last_seen",
        "packet_count",
        "byte_count",
        "source_packet_count",
        "source_byte_count",
        "destination_packet_count",
        "destination_byte_count",
        "state",
        "source_device_id",
        "destination_device_id",
    } <= set(connection)
    assert "risk_score" not in connection
    assert "severity" not in connection
    assert "confidence" not in connection


def test_multiple_connections_are_returned(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """Every tracked conversation appears in the collection."""
    first = _seed_tcp(tracker, destination_port=443)
    second = _seed_tcp(tracker, destination_port=8443)

    data = client.get(CONNECTIONS_URL).json()["data"]

    assert data["count"] == 2
    assert {item["connection_id"] for item in data["connections"]} == {
        first,
        second,
    }


def test_bidirectional_traffic_stays_one_conversation(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """A reply is grouped into the same conversation as the request (M9.4)."""
    expected_id = _seed_tcp(tracker)
    reply = make_normalized_packet(
        source_ip=DESTINATION_IP,
        destination_ip=SOURCE_IP,
        source_port=DESTINATION_PORT,
        destination_port=SOURCE_PORT,
        length=60,
        timestamp=PACKET_BASE_TIME + 1,
    )
    assert tracker.process_packet(reply) is not None

    data = client.get(CONNECTIONS_URL).json()["data"]

    assert data["count"] == 1
    connection = data["connections"][0]
    assert connection["connection_id"] == expected_id
    assert connection["packet_count"] == 2
    assert connection["source_packet_count"] == 1
    assert connection["destination_packet_count"] == 1


# ---------------------------------------------------------------------------
# GET /connections/{connection_id}
# ---------------------------------------------------------------------------


def test_connection_lookup_returns_the_connection(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """A known connection id resolves to that conversation."""
    expected_id = _seed_tcp(tracker)

    response = client.get(f"{CONNECTIONS_URL}/{expected_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["connection_id"] == expected_id


def test_connection_lookup_keeps_pipe_delimiters(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """The id's ``|`` and ``:`` characters survive URL routing (M9.5)."""
    expected_id = _seed_tcp(tracker)
    assert "|" in expected_id

    response = client.get(f"{CONNECTIONS_URL}/{expected_id}")

    assert response.status_code == 200
    assert response.json()["data"]["connection_id"] == expected_id


def test_unknown_connection_returns_404(client: TestClient) -> None:
    """An unknown connection id returns the standard not-found envelope."""
    response = client.get(f"{CONNECTIONS_URL}/TCP|10.0.0.1:1|10.0.0.2:2")

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [
        {"field": "connection_id", "code": "CONNECTION_NOT_FOUND"}
    ]


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


def test_filter_by_protocol(client: TestClient, tracker: ConnectionTracker) -> None:
    """Protocol narrows the collection to one transport."""
    tcp_id = _seed_tcp(tracker)
    _seed_udp(tracker)

    data = client.get(CONNECTIONS_URL, params={"protocol": "TCP"}).json()["data"]

    assert data["count"] == 1
    assert data["connections"][0]["connection_id"] == tcp_id


def test_filter_by_protocol_is_case_insensitive(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """A lowercase protocol filter still matches."""
    _seed_tcp(tracker)

    data = client.get(CONNECTIONS_URL, params={"protocol": "tcp"}).json()["data"]

    assert data["count"] == 1


def test_filter_by_destination_port(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """Destination port narrows to the matching conversation."""
    first = _seed_tcp(tracker, destination_port=443)
    _seed_tcp(tracker, destination_port=8443)

    data = client.get(
        CONNECTIONS_URL, params={"destination_port": 443}
    ).json()["data"]

    assert data["count"] == 1
    assert data["connections"][0]["connection_id"] == first


def test_filter_by_source_ip(client: TestClient, tracker: ConnectionTracker) -> None:
    """Source address narrows to the conversations that start there."""
    _seed_tcp(tracker)
    _seed_tcp(tracker, source_ip="10.0.0.5", source_port=60000)

    data = client.get(CONNECTIONS_URL, params={"source_ip": "10.0.0.5"}).json()[
        "data"
    ]

    assert data["count"] == 1
    assert data["connections"][0]["source_ip"] == "10.0.0.5"


def test_filter_by_destination_ip(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """Destination address narrows to the conversations that end there."""
    _seed_tcp(tracker)
    _seed_tcp(
        tracker,
        destination_ip="1.1.1.1",
        source_port=60001,
    )

    data = client.get(CONNECTIONS_URL, params={"destination_ip": "1.1.1.1"}).json()[
        "data"
    ]

    assert data["count"] == 1
    assert data["connections"][0]["destination_ip"] == "1.1.1.1"


def test_filter_by_state(client: TestClient, tracker: ConnectionTracker) -> None:
    """A state filter keeps only conversations in that state."""
    syn = _seed_tcp(tracker, tcp_flags="S")

    data = client.get(CONNECTIONS_URL, params={"state": "observed"}).json()["data"]

    assert data["count"] == 1
    assert data["connections"][0]["connection_id"] == syn
    assert data["connections"][0]["state"] == ConnectionState.OBSERVED.value


def test_unknown_address_filter_yields_an_empty_list(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """A valid filter that matches nothing returns an empty collection."""
    _seed_tcp(tracker)

    data = client.get(CONNECTIONS_URL, params={"source_ip": "10.9.9.9"}).json()[
        "data"
    ]

    assert data["count"] == 0
    assert data["connections"] == []


def test_active_only_defaults_to_true(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """A retired conversation is hidden unless explicitly requested."""
    _seed_tcp(tracker)
    assert tracker.expire_connections(now=PACKET_BASE_TIME + 10_000) == 1

    active = client.get(CONNECTIONS_URL).json()["data"]
    everything = client.get(
        CONNECTIONS_URL, params={"active_only": "false"}
    ).json()["data"]

    assert active["count"] == 0
    assert everything["count"] == 1
    assert everything["connections"][0]["active"] is False


def test_limit_truncates_the_collection(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """``limit`` caps how many connections are returned."""
    _seed_tcp(tracker, destination_port=443)
    _seed_tcp(tracker, destination_port=8443)

    data = client.get(CONNECTIONS_URL, params={"limit": 1}).json()["data"]

    assert data["count"] == 1


def test_icmp_with_a_port_filter_is_rejected(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """ICMP has no ports, so a port filter on it is a client error."""
    _seed_icmp(tracker)

    response = client.get(
        CONNECTIONS_URL, params={"protocol": "ICMP", "source_port": 80}
    )

    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [{"field": "source_port", "code": "INVALID_FILTER"}]


def test_invalid_ip_filter_is_rejected(client: TestClient) -> None:
    """An unparseable IP filter fails loudly rather than being ignored."""
    response = client.get(CONNECTIONS_URL, params={"source_ip": "not-an-ip"})

    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [{"field": "filter", "code": "INVALID_FILTER"}]


# ---------------------------------------------------------------------------
# Query-parameter validation
# ---------------------------------------------------------------------------


def test_unknown_protocol_is_rejected(client: TestClient) -> None:
    """An unsupported transport fails request validation."""
    assert client.get(CONNECTIONS_URL, params={"protocol": "SCTP"}).status_code == 422


def test_unknown_state_is_rejected(client: TestClient) -> None:
    """An unsupported connection state fails request validation."""
    assert (
        client.get(CONNECTIONS_URL, params={"state": "haunted"}).status_code == 422
    )


def test_limit_must_be_positive(client: TestClient) -> None:
    """A non-positive limit fails request validation."""
    assert client.get(CONNECTIONS_URL, params={"limit": 0}).status_code == 422


def test_limit_has_an_upper_bound(client: TestClient) -> None:
    """An excessive limit fails request validation."""
    assert (
        client.get(CONNECTIONS_URL, params={"limit": 100_000}).status_code == 422
    )


def test_negative_port_is_rejected(client: TestClient) -> None:
    """An out-of-range port fails request validation."""
    assert (
        client.get(CONNECTIONS_URL, params={"destination_port": -1}).status_code
        == 422
    )


# ---------------------------------------------------------------------------
# HTTP / routing conventions
# ---------------------------------------------------------------------------


def test_post_is_not_allowed(client: TestClient) -> None:
    """The connection API is read-only: POST is not allowed."""
    assert client.post(CONNECTIONS_URL).status_code == 405


def test_put_is_not_allowed(client: TestClient) -> None:
    """The connection API is read-only: PUT is not allowed."""
    assert client.put(CONNECTIONS_URL).status_code == 405


def test_delete_is_not_allowed(client: TestClient) -> None:
    """The connection API is read-only: DELETE is not allowed."""
    assert client.delete(CONNECTIONS_URL).status_code == 405


# ---------------------------------------------------------------------------
# GET /connections/active
# ---------------------------------------------------------------------------


def test_active_endpoint_lists_only_live_conversations(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """The dedicated active route hides retired conversations."""
    live_id = _seed_tcp(tracker)
    _seed_stale_tcp(tracker, destination_port=8443)
    assert tracker.expire_connections(now=PACKET_BASE_TIME) == 1

    data = client.get(f"{CONNECTIONS_URL}/active").json()["data"]

    assert data["count"] == 1
    assert data["connections"][0]["connection_id"] == live_id
    assert data["connections"][0]["active"] is True


def test_active_endpoint_is_empty_when_nothing_is_tracked(
    client: TestClient,
) -> None:
    """An empty registry returns a well-formed, empty collection."""
    data = client.get(f"{CONNECTIONS_URL}/active").json()["data"]

    assert data["count"] == 0
    assert data["connections"] == []


def test_active_endpoint_respects_limit(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """``limit`` caps how many active conversations are returned."""
    _seed_tcp(tracker, destination_port=443)
    _seed_tcp(tracker, destination_port=8443)

    data = client.get(
        f"{CONNECTIONS_URL}/active", params={"limit": 1}
    ).json()["data"]

    assert data["count"] == 1


def test_active_endpoint_is_not_shadowed_by_the_id_route(
    client: TestClient,
) -> None:
    """``active`` routes to the collection, not to a connection lookup."""
    response = client.get(f"{CONNECTIONS_URL}/active")

    assert response.status_code == 200
    assert response.json()["message"] == "Active connections retrieved"


# ---------------------------------------------------------------------------
# POST /connections/expire
# ---------------------------------------------------------------------------


def test_expire_endpoint_retires_idle_conversations(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """The sweep retires stale conversations and reports the counts."""
    live_id = _seed_tcp(tracker)
    _seed_stale_tcp(tracker, destination_port=8443)

    body = client.post(f"{CONNECTIONS_URL}/expire").json()

    assert body["success"] is True
    assert body["data"] == {"expired": 1, "active": 1, "historical": 1}

    active = client.get(f"{CONNECTIONS_URL}/active").json()["data"]
    assert [item["connection_id"] for item in active["connections"]] == [live_id]


def test_expire_endpoint_is_a_no_op_when_nothing_is_idle(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """A sweep with no idle conversation retires nothing."""
    _seed_tcp(tracker)

    body = client.post(f"{CONNECTIONS_URL}/expire").json()

    assert body["data"] == {"expired": 0, "active": 1, "historical": 0}


def test_expire_endpoint_is_not_reachable_by_get(
    client: TestClient,
) -> None:
    """``expire`` is a POST-only helper; GET falls through to the id route."""
    response = client.get(f"{CONNECTIONS_URL}/expire")

    assert response.status_code == 404
    assert response.json()["errors"] == [
        {"field": "connection_id", "code": "CONNECTION_NOT_FOUND"}
    ]
