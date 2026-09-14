"""Unit tests for the read-only packet query service (M7.15/M7.19/M7.20).

The service is the single place the query rules live, so these tests pin down
its contract directly against an isolated in-memory database: point lookups,
every named query the roadmap asks for, the wire projection, pagination and the
limits that stop a caller asking SQLite for the whole table.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy.orm import Session

from app.persistence.mapping import to_packet_values
from app.repositories.packet import PacketRepository
from app.schemas.packet import PacketType
from app.services.packet_query import (
    DEFAULT_PACKET_LIMIT,
    MAX_PACKET_LIMIT,
    PacketQueryService,
    to_packet_view,
)
from tests.fakes import PACKET_BASE_TIME, make_normalized_packet


def _row(*, offset: float = 0.0, **overrides) -> dict[str, object]:
    """Map a normalized packet onto a storable row with a shifted timestamp."""
    packet = make_normalized_packet(timestamp=PACKET_BASE_TIME + offset, **overrides)
    values = to_packet_values(packet)
    assert values is not None
    return values


def _utc(offset: float = 0.0) -> datetime:
    """Return a UTC datetime ``offset`` seconds from the packet base time."""
    return datetime.fromtimestamp(PACKET_BASE_TIME + offset, tz=timezone.utc)


def _seed(session: Session, rows: list[dict[str, object]]) -> None:
    """Insert the given rows into the isolated database."""
    PacketRepository(session).write_batch(rows)


# ---------------------------------------------------------------------------
# Empty database
# ---------------------------------------------------------------------------


def test_empty_database_yields_an_empty_page(db_session: Session) -> None:
    """With nothing stored the service returns empty results, not errors."""
    service = PacketQueryService(db_session)

    assert service.list() == []
    assert service.recent() == []
    assert service.count() == 0


def test_unknown_id_returns_none(db_session: Session) -> None:
    """A lookup for an id that was never stored resolves to ``None``."""
    assert PacketQueryService(db_session).get(4242) is None


# ---------------------------------------------------------------------------
# Point lookup and projection
# ---------------------------------------------------------------------------


def test_get_returns_the_stored_packet(db_session: Session) -> None:
    """A stored row is fetched and projected onto its wire shape."""
    _seed(db_session, [_row(source_ip="10.0.0.7", destination_ip="10.0.0.8")])
    stored = PacketRepository(db_session).list(limit=1)[0]

    view = PacketQueryService(db_session).get(stored.id)

    assert view is not None
    assert view.id == stored.id
    assert view.source_ip == "10.0.0.7"
    assert view.destination_ip == "10.0.0.8"


def test_view_carries_the_mapped_fields_only(db_session: Session) -> None:
    """The projection exposes exactly the columns M7 stores (M7.5)."""
    _seed(
        db_session,
        [
            _row(
                source_ip="10.0.0.1",
                destination_ip="10.0.0.2",
                source_port=5000,
                destination_port=443,
                length=512,
                tcp_flags="PA",
                protocol="TCP",
                packet_type=PacketType.TCP,
            )
        ],
    )
    stored = PacketRepository(db_session).list(limit=1)[0]

    view = to_packet_view(stored)

    assert view.source_port == 5000
    assert view.destination_port == 443
    assert view.protocol == "TCP"
    assert view.packet_length == 512
    assert view.tcp_flags == "PA"
    # Payload is never part of the wire shape (M7.5).
    assert "payload_length" not in view.model_dump()
    assert "payload" not in view.model_dump()


def test_view_timestamp_is_iso_8601(db_session: Session) -> None:
    """The capture time is rendered as an ISO-8601 string."""
    _seed(db_session, [_row(offset=0)])
    stored = PacketRepository(db_session).list(limit=1)[0]

    view = to_packet_view(stored)

    expected = datetime.fromtimestamp(PACKET_BASE_TIME, tz=timezone.utc)
    assert view.timestamp == expected.replace(tzinfo=None).isoformat()


# ---------------------------------------------------------------------------
# Ordering, paging and limits
# ---------------------------------------------------------------------------


def test_list_is_newest_first(db_session: Session) -> None:
    """Results are ordered by timestamp descending."""
    _seed(db_session, [_row(offset=i, source_ip=f"10.0.0.{i}") for i in range(3)])

    sources = [view.source_ip for view in PacketQueryService(db_session).list()]

    assert sources == ["10.0.0.2", "10.0.0.1", "10.0.0.0"]


def test_recent_returns_the_newest_page(db_session: Session) -> None:
    """``recent`` is the newest-first list, capped by the limit."""
    _seed(db_session, [_row(offset=i, source_ip=f"10.0.0.{i}") for i in range(5)])

    sources = [view.source_ip for view in PacketQueryService(db_session).recent(2)]

    assert sources == ["10.0.0.4", "10.0.0.3"]


def test_list_applies_limit_and_offset(db_session: Session) -> None:
    """Pagination returns a stable window of the newest-first ordering."""
    _seed(db_session, [_row(offset=i, source_ip=f"10.0.0.{i}") for i in range(5)])

    page = PacketQueryService(db_session).list(limit=2, offset=1)

    assert [view.source_ip for view in page] == ["10.0.0.3", "10.0.0.2"]


def test_default_limit_is_used_when_omitted(db_session: Session) -> None:
    """The default page size is the documented constant."""
    assert DEFAULT_PACKET_LIMIT >= 1
    _seed(db_session, [_row(offset=i) for i in range(3)])

    assert len(PacketQueryService(db_session).list()) == 3


def test_non_positive_limit_is_rejected(db_session: Session) -> None:
    """A nonsensical limit fails loudly instead of being clamped silently."""
    with pytest.raises(ValueError):
        PacketQueryService(db_session).list(limit=0)


def test_limit_above_the_cap_is_rejected(db_session: Session) -> None:
    """A limit above the hard cap is refused (M7.15 DoS guard)."""
    with pytest.raises(ValueError):
        PacketQueryService(db_session).list(limit=MAX_PACKET_LIMIT + 1)


def test_negative_offset_is_rejected(db_session: Session) -> None:
    """A negative offset fails loudly."""
    with pytest.raises(ValueError):
        PacketQueryService(db_session).list(offset=-1)


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


def test_filter_by_source_and_destination(db_session: Session) -> None:
    """Endpoint filters narrow the result set to the matching packets."""
    _seed(
        db_session,
        [
            _row(source_ip="10.0.0.1", destination_ip="10.0.0.9"),
            _row(source_ip="10.0.0.2", destination_ip="10.0.0.9"),
        ],
    )
    service = PacketQueryService(db_session)

    assert [v.source_ip for v in service.list(source_ip="10.0.0.2")] == ["10.0.0.2"]
    assert {v.destination_ip for v in service.list(destination_ip="10.0.0.9")} == {
        "10.0.0.9"
    }
    assert service.list(destination_ip="10.9.9.9") == []


def test_filter_by_protocol(db_session: Session) -> None:
    """The protocol filter keeps only the requested label."""
    _seed(
        db_session,
        [
            _row(protocol="TCP", packet_type=PacketType.TCP),
            _row(source_ip="10.0.0.5", protocol="UDP", packet_type=PacketType.UDP),
        ],
    )

    packets = PacketQueryService(db_session).list(protocol="UDP")

    assert [view.protocol for view in packets] == ["UDP"]


def test_filter_by_port_direction(db_session: Session) -> None:
    """Port filters distinguish source from destination."""
    _seed(db_session, [_row(source_port=5000, destination_port=443)])
    service = PacketQueryService(db_session)

    assert len(service.list(destination_port=443)) == 1
    assert len(service.list(source_port=5000)) == 1
    assert service.list(source_port=443) == []


def test_filter_by_time_range(db_session: Session) -> None:
    """``since`` / ``until`` restrict results to a capture window."""
    _seed(db_session, [_row(offset=i) for i in range(5)])

    packets = PacketQueryService(db_session).list(since=_utc(1), until=_utc(3))

    assert len(packets) == 3


def test_count_matches_the_filters(db_session: Session) -> None:
    """``count`` honours the same filters as ``list``."""
    _seed(
        db_session,
        [
            _row(source_ip="10.0.0.1"),
            _row(source_ip="10.0.0.2"),
            _row(source_ip="10.0.0.1"),
        ],
    )
    service = PacketQueryService(db_session)

    assert service.count() == 3
    assert service.count(source_ip="10.0.0.1") == 2
    assert service.count(source_ip="10.0.0.9") == 0


# ---------------------------------------------------------------------------
# Named queries
# ---------------------------------------------------------------------------


def test_named_ip_queries(db_session: Session) -> None:
    """``by_source_ip`` / ``by_destination_ip`` select the owning packets."""
    _seed(
        db_session,
        [
            _row(source_ip="10.0.0.1", destination_ip="10.0.0.9"),
            _row(source_ip="10.0.0.2", destination_ip="10.0.0.9"),
        ],
    )
    service = PacketQueryService(db_session)

    assert [v.source_ip for v in service.by_source_ip("10.0.0.1")] == ["10.0.0.1"]
    assert len(service.by_destination_ip("10.0.0.9")) == 2


def test_by_protocol_query(db_session: Session) -> None:
    """``by_protocol`` returns packets of one label."""
    _seed(
        db_session,
        [
            _row(protocol="TCP", packet_type=PacketType.TCP),
            _row(source_ip="10.0.0.5", protocol="UDP", packet_type=PacketType.UDP),
        ],
    )

    assert [v.protocol for v in PacketQueryService(db_session).by_protocol("TCP")] == [
        "TCP"
    ]


def test_by_port_in_each_direction(db_session: Session) -> None:
    """``by_port`` honours the requested direction."""
    _seed(db_session, [_row(source_port=5000, destination_port=443)])
    service = PacketQueryService(db_session)

    assert len(service.by_port(443, direction="destination")) == 1
    assert len(service.by_port(5000, direction="source")) == 1
    assert service.by_port(9999, direction="destination") == []


def test_by_port_rejects_an_unknown_direction(db_session: Session) -> None:
    """An unsupported direction fails loudly."""
    with pytest.raises(ValueError):
        PacketQueryService(db_session).by_port(443, direction="sideways")


def test_between_returns_the_window(db_session: Session) -> None:
    """``between`` returns packets inside the requested range."""
    _seed(db_session, [_row(offset=i) for i in range(5)])

    packets = PacketQueryService(db_session).between(_utc(1), _utc(3))

    assert len(packets) == 3
