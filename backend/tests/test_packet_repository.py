"""Unit tests for the packet repository (M7.3/M7.10/M7.20).

The repository is the only code that talks SQL to the ``packets`` table, so
these tests exercise the storage contract directly: staging vs committing,
batch writes in a single transaction, rollback on failure, the read filters the
query service depends on, and retention's ``delete_before``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.packet import Packet
from app.persistence.mapping import to_packet_values
from app.repositories.packet import PacketRepository
from app.schemas.packet import PacketType
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


# ---------------------------------------------------------------------------
# Writes: staging vs committing
# ---------------------------------------------------------------------------


def test_add_stages_without_committing(db_session: Session) -> None:
    """``add`` places a row in the session without writing it yet."""
    repository = PacketRepository(db_session)

    repository.add(Packet(**_row()))
    db_session.rollback()

    assert repository.count() == 0


def test_add_many_returns_the_staged_count(db_session: Session) -> None:
    """``add_many`` reports how many rows it staged."""
    repository = PacketRepository(db_session)

    staged = repository.add_many([Packet(**_row(offset=i)) for i in range(3)])

    assert staged == 3


def test_commit_persists_staged_rows(db_session: Session) -> None:
    """Staged rows are written only after an explicit commit."""
    repository = PacketRepository(db_session)
    repository.add_many([Packet(**_row(offset=i)) for i in range(3)])

    repository.commit()

    assert repository.count() == 3


def test_write_batch_persists_the_whole_batch(db_session: Session) -> None:
    """``write_batch`` inserts every row in one transaction."""
    repository = PacketRepository(db_session)

    written = repository.write_batch([_row(offset=i) for i in range(5)])

    assert written == 5
    assert repository.count() == 5


def test_write_batch_stores_the_mapped_values(db_session: Session) -> None:
    """The exact values from the mapping land in the database."""
    repository = PacketRepository(db_session)
    repository.write_batch(
        [_row(source_ip="10.0.0.1", destination_ip="10.0.0.2", length=321)]
    )

    stored = repository.list(limit=1)[0]

    assert stored.source_ip == "10.0.0.1"
    assert stored.destination_ip == "10.0.0.2"
    assert stored.packet_length == 321
    assert stored.payload_length is None  # payloads are never stored (M7.5)


def test_write_batch_of_nothing_is_a_no_op(db_session: Session) -> None:
    """An empty batch writes nothing and does not fail."""
    repository = PacketRepository(db_session)

    assert repository.write_batch([]) == 0
    assert repository.count() == 0


def test_failed_batch_rolls_back_and_keeps_the_database_usable(
    db_session: Session,
) -> None:
    """A batch that violates a constraint is rolled back, not half-written.

    ``source_ip`` is NOT NULL, so a row without one fails on commit. The batch
    must raise, write nothing, and leave the session able to accept the next
    (valid) batch.
    """
    repository = PacketRepository(db_session)
    repository.write_batch([_row(offset=i) for i in range(2)])

    bad_batch = [_row(offset=10), {**_row(offset=11), "source_ip": None}]

    with pytest.raises(IntegrityError):
        repository.write_batch(bad_batch)

    # The two original rows survive; the failed batch left nothing behind.
    assert repository.count() == 2

    # The repository is still usable after the rollback.
    assert repository.write_batch([_row(offset=20)]) == 1
    assert repository.count() == 3


# ---------------------------------------------------------------------------
# Reads: lookup and filters
# ---------------------------------------------------------------------------


def test_get_by_id_returns_the_stored_packet(db_session: Session) -> None:
    """A stored row can be fetched by primary key."""
    repository = PacketRepository(db_session)
    repository.write_batch([_row(source_ip="10.0.0.7")])

    stored = repository.list(limit=1)[0]
    fetched = repository.get_by_id(stored.id)

    assert fetched is not None
    assert fetched.source_ip == "10.0.0.7"


def test_get_by_id_returns_none_for_unknown_id(db_session: Session) -> None:
    """An unknown id resolves to ``None`` rather than raising."""
    assert PacketRepository(db_session).get_by_id(9999) is None


def test_list_is_newest_first(db_session: Session) -> None:
    """Results are ordered by timestamp descending, then id descending."""
    repository = PacketRepository(db_session)
    repository.write_batch([_row(offset=i, source_ip=f"10.0.0.{i}") for i in range(3)])

    sources = [packet.source_ip for packet in repository.list()]

    assert sources == ["10.0.0.2", "10.0.0.1", "10.0.0.0"]


def test_list_filters_by_source_ip(db_session: Session) -> None:
    """The source-IP filter narrows the result set."""
    repository = PacketRepository(db_session)
    repository.write_batch(
        [
            _row(source_ip="10.0.0.1", destination_ip="10.0.0.9"),
            _row(source_ip="10.0.0.2", destination_ip="10.0.0.9"),
        ]
    )

    packets = repository.list(source_ip="10.0.0.2")

    assert [packet.source_ip for packet in packets] == ["10.0.0.2"]


def test_list_filters_by_protocol(db_session: Session) -> None:
    """The protocol filter narrows the result set to one label."""
    repository = PacketRepository(db_session)
    repository.write_batch(
        [
            _row(protocol="TCP", packet_type=PacketType.TCP),
            _row(
                source_ip="10.0.0.5",
                protocol="UDP",
                packet_type=PacketType.UDP,
            ),
        ]
    )

    packets = repository.list(protocol="UDP")

    assert [packet.protocol for packet in packets] == ["UDP"]


def test_list_filters_by_time_range(db_session: Session) -> None:
    """``since`` / ``until`` restrict results to a capture window."""
    repository = PacketRepository(db_session)
    repository.write_batch([_row(offset=i) for i in range(5)])

    packets = repository.list(since=_utc(1), until=_utc(3))

    assert len(packets) == 3
    assert [packet.timestamp for packet in packets] == [
        _utc(3).replace(tzinfo=None),
        _utc(2).replace(tzinfo=None),
        _utc(1).replace(tzinfo=None),
    ]


def test_list_applies_limit_and_offset(db_session: Session) -> None:
    """Pagination returns a stable window of the newest-first ordering."""
    repository = PacketRepository(db_session)
    repository.write_batch([_row(offset=i) for i in range(5)])

    page = repository.list(limit=2, offset=1)

    assert [packet.timestamp for packet in page] == [
        _utc(3).replace(tzinfo=None),
        _utc(2).replace(tzinfo=None),
    ]


def test_list_rejects_a_non_positive_limit(db_session: Session) -> None:
    """A nonsensical limit fails loudly."""
    with pytest.raises(ValueError):
        PacketRepository(db_session).list(limit=0)


def test_list_rejects_a_negative_offset(db_session: Session) -> None:
    """A negative offset fails loudly."""
    with pytest.raises(ValueError):
        PacketRepository(db_session).list(offset=-1)


def test_count_matches_the_filters(db_session: Session) -> None:
    """``count`` honours the same filters as ``list``."""
    repository = PacketRepository(db_session)
    repository.write_batch(
        [
            _row(source_ip="10.0.0.1"),
            _row(source_ip="10.0.0.2"),
            _row(source_ip="10.0.0.1"),
        ]
    )

    assert repository.count() == 3
    assert repository.count(source_ip="10.0.0.1") == 2
    assert repository.count(source_ip="10.0.0.9") == 0


def test_get_by_port_in_each_direction(db_session: Session) -> None:
    """Port lookups honour the requested direction."""
    repository = PacketRepository(db_session)
    repository.write_batch([_row(source_port=5000, destination_port=443)])

    assert len(repository.get_by_port(443, direction="destination")) == 1
    assert len(repository.get_by_port(5000, direction="source")) == 1
    assert len(repository.get_by_port(9999, direction="destination")) == 0


def test_get_by_port_rejects_an_unknown_direction(db_session: Session) -> None:
    """An unsupported direction fails loudly."""
    with pytest.raises(ValueError):
        PacketRepository(db_session).get_by_port(443, direction="sideways")


def test_count_all_and_count_by_protocol(db_session: Session) -> None:
    """The convenience counters agree with the filtered count."""
    repository = PacketRepository(db_session)
    repository.write_batch([_row(), _row(source_ip="10.0.0.8")])

    assert repository.count_all() == 2
    assert repository.count_by_protocol("TCP") == 2
    assert repository.count_by_protocol("ICMP") == 0


# ---------------------------------------------------------------------------
# Delete (retention)
# ---------------------------------------------------------------------------


def test_delete_before_removes_only_older_rows(db_session: Session) -> None:
    """Rows strictly older than the cutoff are deleted; newer ones survive."""
    repository = PacketRepository(db_session)
    repository.write_batch([_row(offset=day * 86_400) for day in range(3)])

    deleted = repository.delete_before(_utc(86_400))

    assert deleted == 1
    assert repository.count() == 2


def test_delete_before_keeps_the_exact_boundary(db_session: Session) -> None:
    """A row exactly at the cutoff is kept (strict ``<`` comparison)."""
    repository = PacketRepository(db_session)
    repository.write_batch([_row(offset=0)])

    deleted = repository.delete_before(_utc(0))

    assert deleted == 0
    assert repository.count() == 1


def test_delete_before_returns_zero_on_an_empty_table(db_session: Session) -> None:
    """Deleting from an empty table is a no-op."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    assert PacketRepository(db_session).delete_before(cutoff) == 0
