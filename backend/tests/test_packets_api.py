"""API tests for the internal packet endpoints (M7.16/M7.20).

These endpoints are the M7 verification surface: a read-only query over stored
packets and a manual retention trigger. The tests drive them through the ASGI
client against an isolated in-memory database (never the developer's
``netwatch.db``), checking the response envelope, filtering, pagination,
validation and error handling.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1 import packets as packets_module
from app.config.settings import settings
from app.database.session import get_db
from app.main import app
from app.persistence.mapping import to_packet_values
from app.persistence.retention import PacketRetentionService
from app.repositories.packet import PacketRepository
from app.schemas.packet import PacketType
from tests.fakes import PACKET_BASE_TIME, make_normalized_packet

PACKETS_URL = "/api/v1/packets"

# Retention window used by the retention-endpoint test.
RETENTION_DAYS = 7


def _row(*, offset: float = 0.0, **overrides) -> dict[str, object]:
    """Map a normalized packet onto a storable row with a shifted timestamp."""
    packet = make_normalized_packet(timestamp=PACKET_BASE_TIME + offset, **overrides)
    values = to_packet_values(packet)
    assert values is not None
    return values


def _row_at(epoch: float) -> dict[str, object]:
    """Map a normalized packet captured at an explicit epoch onto a row."""
    packet = make_normalized_packet(timestamp=epoch)
    values = to_packet_values(packet)
    assert values is not None
    return values


def _iso(offset: float = 0.0) -> str:
    """Return the naive UTC ISO-8601 string for a packet base-time offset."""
    moment = datetime.fromtimestamp(PACKET_BASE_TIME + offset, tz=timezone.utc)
    return moment.replace(tzinfo=None).isoformat()


def _seed(db_engine, rows: list[dict[str, object]]) -> None:
    """Insert packet rows into the isolated database."""
    session = Session(bind=db_engine)
    try:
        PacketRepository(session).write_batch(rows)
    finally:
        session.close()


@pytest.fixture
def client(
    db_engine, monkeypatch: pytest.MonkeyPatch
) -> Generator[TestClient, None, None]:
    """Test client bound to an isolated database with a packets table.

    ``get_db`` is overridden so the endpoints query the temporary engine rather
    than the real one, and the retention service factory is overridden so the
    cleanup endpoint also targets the temporary engine.
    """
    from app import models as _models  # noqa: F401
    from app.database.base import Base

    Base.metadata.create_all(bind=db_engine)

    def _override_get_db() -> Generator[Session, None, None]:
        session = Session(bind=db_engine)
        try:
            yield session
        finally:
            session.close()

    retention = PacketRetentionService(
        session_factory=lambda: Session(bind=db_engine),
        retention_days=RETENTION_DAYS,
    )
    monkeypatch.setattr(
        packets_module, "get_packet_retention_service", lambda: retention
    )

    original_env = settings.app_env
    settings.app_env = "test"
    app.dependency_overrides[get_db] = _override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.pop(get_db, None)
        settings.app_env = original_env
        Base.metadata.drop_all(bind=db_engine)


# ---------------------------------------------------------------------------
# GET /packets
# ---------------------------------------------------------------------------


def test_empty_list_is_well_formed(client: TestClient) -> None:
    """With nothing stored the collection endpoint returns an empty page."""
    response = client.get(PACKETS_URL)

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["count"] == 0
    assert body["data"]["total"] == 0
    assert body["data"]["packets"] == []


def test_one_packet_is_returned(client: TestClient, db_engine) -> None:
    """A single stored packet is exposed with its mapped fields."""
    _seed(db_engine, [_row(source_ip="10.0.0.7", destination_ip="10.0.0.8")])

    data = client.get(PACKETS_URL).json()["data"]

    assert data["count"] == 1
    assert data["total"] == 1
    packet = data["packets"][0]
    assert packet["source_ip"] == "10.0.0.7"
    assert packet["destination_ip"] == "10.0.0.8"
    assert packet["protocol"] == "TCP"
    assert packet["destination_port"] == 443


def test_packet_payload_has_only_stored_columns(client: TestClient, db_engine) -> None:
    """The wire shape carries no payload field (M7.5)."""
    _seed(db_engine, [_row()])

    packet = client.get(PACKETS_URL).json()["data"]["packets"][0]

    assert {
        "id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "packet_length",
        "tcp_flags",
    } <= set(packet)
    assert "payload" not in packet
    assert "payload_length" not in packet


def test_multiple_packets_are_newest_first(client: TestClient, db_engine) -> None:
    """The collection is ordered newest-first and reports the total matching."""
    _seed(db_engine, [_row(offset=i, source_ip=f"10.0.0.{i}") for i in range(3)])

    data = client.get(PACKETS_URL).json()["data"]

    assert data["count"] == 3
    assert data["total"] == 3
    assert [p["source_ip"] for p in data["packets"]] == [
        "10.0.0.2",
        "10.0.0.1",
        "10.0.0.0",
    ]


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


def test_filter_by_source_ip(client: TestClient, db_engine) -> None:
    """The source-IP query parameter narrows the result set."""
    _seed(
        db_engine,
        [
            _row(source_ip="10.0.0.1"),
            _row(source_ip="10.0.0.2"),
        ],
    )

    data = client.get(PACKETS_URL, params={"source_ip": "10.0.0.2"}).json()["data"]

    assert data["count"] == 1
    assert data["packets"][0]["source_ip"] == "10.0.0.2"


def test_filter_by_destination_ip(client: TestClient, db_engine) -> None:
    """The destination-IP query parameter narrows the result set."""
    _seed(db_engine, [_row(destination_ip="10.0.0.9")])

    data = client.get(PACKETS_URL, params={"destination_ip": "10.0.0.9"}).json()["data"]

    assert data["count"] == 1
    assert data["packets"][0]["destination_ip"] == "10.0.0.9"


def test_filter_by_protocol(client: TestClient, db_engine) -> None:
    """The protocol query parameter keeps only the requested label."""
    _seed(
        db_engine,
        [
            _row(protocol="TCP", packet_type=PacketType.TCP),
            _row(source_ip="10.0.0.5", protocol="UDP", packet_type=PacketType.UDP),
        ],
    )

    data = client.get(PACKETS_URL, params={"protocol": "UDP"}).json()["data"]

    assert data["count"] == 1
    assert data["packets"][0]["protocol"] == "UDP"


def test_filter_by_port(client: TestClient, db_engine) -> None:
    """Port query parameters filter by destination and source."""
    _seed(db_engine, [_row(source_port=5000, destination_port=443)])

    by_dest = client.get(PACKETS_URL, params={"destination_port": 443}).json()["data"]
    by_src = client.get(PACKETS_URL, params={"source_port": 5000}).json()["data"]

    assert by_dest["count"] == 1
    assert by_src["count"] == 1


def test_filter_by_time_range(client: TestClient, db_engine) -> None:
    """``since`` / ``until`` restrict the results to a capture window."""
    _seed(db_engine, [_row(offset=i) for i in range(5)])

    data = client.get(
        PACKETS_URL, params={"since": _iso(1), "until": _iso(3)}
    ).json()["data"]

    assert data["count"] == 3


def test_unknown_address_yields_an_empty_page(client: TestClient, db_engine) -> None:
    """A valid filter that matches nothing returns an empty collection."""
    _seed(db_engine, [_row()])

    data = client.get(PACKETS_URL, params={"source_ip": "10.9.9.9"}).json()["data"]

    assert data["count"] == 0
    assert data["packets"] == []


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


def test_limit_truncates_but_total_reports_all(client: TestClient, db_engine) -> None:
    """``limit`` caps the page while ``total`` reports every match."""
    _seed(db_engine, [_row(offset=i) for i in range(5)])

    data = client.get(PACKETS_URL, params={"limit": 2}).json()["data"]

    assert data["count"] == 2
    assert data["total"] == 5


def test_offset_skips_the_newest(client: TestClient, db_engine) -> None:
    """``offset`` walks the newest-first ordering."""
    _seed(db_engine, [_row(offset=i, source_ip=f"10.0.0.{i}") for i in range(5)])

    data = client.get(PACKETS_URL, params={"limit": 2, "offset": 1}).json()["data"]

    assert [p["source_ip"] for p in data["packets"]] == ["10.0.0.3", "10.0.0.2"]


# ---------------------------------------------------------------------------
# Query-parameter validation
# ---------------------------------------------------------------------------


def test_limit_must_be_positive(client: TestClient) -> None:
    """A non-positive limit fails request validation."""
    assert client.get(PACKETS_URL, params={"limit": 0}).status_code == 422


def test_limit_has_an_upper_bound(client: TestClient) -> None:
    """An excessive limit fails request validation."""
    assert client.get(PACKETS_URL, params={"limit": 100_000}).status_code == 422


def test_negative_offset_is_rejected(client: TestClient) -> None:
    """A negative offset fails request validation."""
    assert client.get(PACKETS_URL, params={"offset": -1}).status_code == 422


def test_port_out_of_range_is_rejected(client: TestClient) -> None:
    """A port beyond 65535 fails request validation."""
    response = client.get(PACKETS_URL, params={"destination_port": 70000})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# GET /packets/{packet_id}
# ---------------------------------------------------------------------------


def test_packet_detail_lookup(client: TestClient, db_engine) -> None:
    """A stored packet can be fetched by id."""
    _seed(db_engine, [_row(source_ip="10.0.0.1")])
    packet_id = client.get(PACKETS_URL).json()["data"]["packets"][0]["id"]

    body = client.get(f"{PACKETS_URL}/{packet_id}").json()

    assert body["success"] is True
    assert body["data"]["id"] == packet_id
    assert body["data"]["source_ip"] == "10.0.0.1"


def test_unknown_packet_returns_404(client: TestClient) -> None:
    """An unknown id returns the standard not-found envelope."""
    response = client.get(f"{PACKETS_URL}/999999")

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [{"field": "packet_id", "code": "PACKET_NOT_FOUND"}]


# ---------------------------------------------------------------------------
# POST /packets/retention/cleanup
# ---------------------------------------------------------------------------


def test_retention_cleanup_endpoint_deletes_only_old(
    client: TestClient, db_engine
) -> None:
    """The cleanup endpoint removes expired rows and keeps recent ones."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    old = now - timedelta(days=RETENTION_DAYS + 3)
    recent = now - timedelta(days=1)
    _seed(
        db_engine,
        [
            _row_at(old.timestamp()),
            _row_at(recent.timestamp()),
        ],
    )

    body = client.post(f"{PACKETS_URL}/retention/cleanup").json()

    assert body["success"] is True
    assert body["data"]["deleted"] == 1
    remaining = client.get(PACKETS_URL).json()["data"]["total"]
    assert remaining == 1


# ---------------------------------------------------------------------------
# Routing conventions
# ---------------------------------------------------------------------------


def test_post_to_collection_is_not_allowed(client: TestClient) -> None:
    """The read collection is GET-only."""
    assert client.post(PACKETS_URL).status_code == 405


def test_unknown_route_is_404(client: TestClient) -> None:
    """An unknown packet sub-route returns 404."""
    assert client.get(f"{PACKETS_URL}/nested/path").status_code == 404
