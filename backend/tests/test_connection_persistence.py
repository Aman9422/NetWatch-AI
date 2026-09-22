"""Mapping, persistence and database tests for connections (M9.17, M9.25).

Two layers are covered:

* ``app.connections.mapping`` — pure projection of a runtime connection onto
  ``connections`` column values, with no I/O;
* ``app.connections.persistence`` + ``app.repositories.connection`` — the real
  ``INSERT``/``UPDATE``/query behaviour against an isolated in-memory database.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.connections.connection import Connection
from app.connections.identity import Direction, flow_of
from app.connections.mapping import (
    is_ended,
    is_persistable,
    protocol_label,
    to_connection_values,
    to_utc_datetime,
)
from app.connections.persistence import ConnectionPersistence
from app.connections.state import TcpFlags
from app.models.connection import NetworkConnection
from app.models.device import Device
from app.repositories.connection import ConnectionRepository
from app.schemas.packet import PacketType
from tests.fakes import make_normalized_packet

START = 1_700_000_000.0


def _tcp_connection(*, destination_port: int = 443) -> Connection:
    """Return a TCP conversation with one observed source packet."""
    flow = flow_of(
        make_normalized_packet(destination_port=destination_port)
    )
    assert flow is not None
    connection = Connection.create(flow=flow)
    connection.observe(direction=Direction.SOURCE, length=100, at=START)
    return connection


def _reverse_connection() -> Connection:
    """Return a TCP conversation whose only packet came from the other side."""
    flow = flow_of(
        make_normalized_packet(
            source_ip="8.8.8.8",
            destination_ip="192.168.1.10",
            source_port=443,
            destination_port=12345,
        )
    )
    assert flow is not None
    connection = Connection.create(flow=flow)
    connection.observe(direction=Direction.SOURCE, length=60, at=START + 1)
    return connection


# -- mapping: what may be stored (M9.17) ---------------------------------


def test_an_unobserved_connection_is_not_persistable() -> None:
    flow = flow_of(make_normalized_packet())
    assert flow is not None
    connection = Connection.create(flow=flow)

    assert is_persistable(connection) is False
    assert to_connection_values(connection) is None


def test_mapping_projects_the_aggregate_onto_the_columns() -> None:
    values = to_connection_values(_tcp_connection())
    assert values is not None

    assert values["source_ip"] == "192.168.1.10"
    assert values["destination_ip"] == "8.8.8.8"
    assert values["source_port"] == 12345
    assert values["destination_port"] == 443
    assert values["protocol"] == "TCP"
    assert values["packets_sent"] == 1
    assert values["packets_received"] == 0
    assert values["bytes_sent"] == 100
    assert values["bytes_received"] == 0
    assert values["status"] == "active"
    assert values["start_time"] == to_utc_datetime(START)
    # A conversation still in progress has no end time.
    assert values["end_time"] is None
    assert values["source_device_id"] is None
    assert values["destination_device_id"] is None


def test_reverse_traffic_becomes_the_received_columns() -> None:
    values = to_connection_values(_reverse_connection())
    assert values is not None
    # ``sent``/``received`` follow the conversation's recorded orientation.
    assert values["packets_sent"] == 1
    assert values["bytes_sent"] == 60
    assert values["source_ip"] == "8.8.8.8"
    assert values["destination_ip"] == "192.168.1.10"


def test_a_closed_conversation_is_completed_with_an_end_time() -> None:
    connection = _tcp_connection()
    connection.observe(
        direction=Direction.SOURCE, length=40, at=START + 5, tcp_flags=TcpFlags.parse("R")
    )

    assert is_ended(connection) is True
    values = to_connection_values(connection)
    assert values is not None
    assert values["status"] == "completed"
    assert values["end_time"] == to_utc_datetime(START + 5)


def test_a_timed_out_conversation_is_stored_as_timeout() -> None:
    connection = _tcp_connection()
    connection.retire(at=START + 400.0)

    assert is_ended(connection) is True
    values = to_connection_values(connection)
    assert values is not None
    assert values["status"] == "timeout"
    assert values["end_time"] == to_utc_datetime(START)


def test_icmp_ports_stay_null() -> None:
    flow = flow_of(
        make_normalized_packet(
            protocol="ICMP",
            packet_type=PacketType.ICMP,
            source_port=None,
            destination_port=None,
        )
    )
    assert flow is not None
    connection = Connection.create(flow=flow)
    connection.observe(direction=Direction.SOURCE, length=28, at=START)

    values = to_connection_values(connection)
    assert values is not None
    assert values["protocol"] == "ICMP"
    assert values["source_port"] is None
    assert values["destination_port"] is None


def test_mapping_accepts_injected_device_row_ids() -> None:
    connection = _tcp_connection()
    values = to_connection_values(
        connection, source_device_row_id=7, destination_device_row_id=None
    )
    assert values is not None
    assert values["source_device_id"] == 7
    assert values["destination_device_id"] is None


# -- mapping: labels and timestamps --------------------------------------


def test_protocol_label_falls_back_when_empty() -> None:
    connection = _tcp_connection()
    connection.protocol = ""
    assert protocol_label(connection) == "OTHER"


def test_protocol_label_is_truncated_to_the_column_width() -> None:
    connection = _tcp_connection()
    connection.protocol = "X" * 40
    assert len(protocol_label(connection)) == 20


def test_to_utc_datetime_is_timezone_aware() -> None:
    stamp = to_utc_datetime(START)
    assert isinstance(stamp, datetime)
    assert stamp.tzinfo == timezone.utc


# -- persistence layer (M9.17) ------------------------------------------


def _persistence(session_factory) -> ConnectionPersistence:
    """Return a persistence layer bound to the isolated test database."""
    return ConnectionPersistence(session_factory=session_factory, enabled=True)


def _rows(session_factory) -> list[NetworkConnection]:
    """Return every stored connection, newest first."""
    session = session_factory()
    try:
        return ConnectionRepository(session).list(limit=100)
    finally:
        session.close()


def test_max_per_pass_must_be_positive() -> None:
    with pytest.raises(ValueError):
        ConnectionPersistence(max_per_pass=0)


def test_the_first_write_inserts_and_the_second_updates(session_factory) -> None:
    layer = _persistence(session_factory)
    connection = _tcp_connection()

    assert layer.persist_many([connection]) == 1
    assert layer.get_created_count() == 1
    assert layer.get_updated_count() == 0
    row_id = connection.persisted_row_id
    assert row_id is not None

    connection.observe(direction=Direction.SOURCE, length=50, at=START + 2)
    assert layer.persist_many([connection]) == 1

    assert layer.get_updated_count() == 1
    # The conversation keeps the row it was first written to (M9.17).
    assert connection.persisted_row_id == row_id
    rows = _rows(session_factory)
    assert len(rows) == 1
    assert rows[0].packets_sent == 2
    assert rows[0].bytes_sent == 150


def test_persist_reports_whether_a_row_was_written(session_factory) -> None:
    layer = _persistence(session_factory)
    assert layer.persist(_tcp_connection()) is True

    flow = flow_of(make_normalized_packet())
    assert flow is not None
    unobserved = Connection.create(flow=flow)
    assert layer.persist(unobserved) is False


def test_an_unobserved_connection_is_skipped_not_written(session_factory) -> None:
    layer = _persistence(session_factory)
    flow = flow_of(make_normalized_packet())
    assert flow is not None
    unobserved = Connection.create(flow=flow)

    assert layer.persist_many([unobserved]) == 0
    assert layer.get_skipped_count() == 1
    assert layer.get_written_count() == 0
    assert _rows(session_factory) == []


def test_a_disabled_layer_writes_nothing(session_factory) -> None:
    layer = ConnectionPersistence(session_factory=session_factory, enabled=False)
    assert layer.is_enabled() is False
    assert layer.persist_many([_tcp_connection()]) == 0
    assert layer.get_written_count() == 0
    assert _rows(session_factory) == []


def test_a_pass_writes_at_most_max_per_pass_rows(session_factory) -> None:
    layer = ConnectionPersistence(session_factory=session_factory, max_per_pass=2)
    connections = [
        _tcp_connection(destination_port=port) for port in (80, 81, 82, 83)
    ]

    assert layer.persist_many(connections) == 2
    assert layer.get_deferred_count() == 2
    assert len(_rows(session_factory)) == 2


def test_an_empty_batch_is_a_no_op(session_factory) -> None:
    layer = _persistence(session_factory)
    assert layer.persist_many([]) == 0
    assert layer.get_failed_count() == 0


def test_a_database_that_cannot_be_opened_never_raises(session_factory) -> None:
    def broken_factory():
        raise RuntimeError("database unavailable")

    layer = ConnectionPersistence(session_factory=broken_factory)
    connection = _tcp_connection()

    # The failure is counted, not raised, so the caller's sweep continues.
    assert layer.persist_many([connection]) == 0
    assert layer.get_failed_count() == 1
    # The record stays pending, so a later sweep retries it (M9.20).
    assert connection.dirty is True


def test_counters_can_be_reset(session_factory) -> None:
    layer = _persistence(session_factory)
    layer.persist_many([_tcp_connection()])
    layer.reset()

    assert layer.get_created_count() == 0
    assert layer.get_written_count() == 0


def test_a_reused_tuple_keeps_the_earlier_row(session_factory) -> None:
    layer = _persistence(session_factory)
    connection = _tcp_connection()
    layer.persist_many([connection])
    first_row_id = connection.persisted_row_id

    # Close the conversation, then reopen the same tuple with a fresh SYN.
    connection.observe(
        direction=Direction.SOURCE, length=40, at=START + 5, tcp_flags=TcpFlags.parse("FA")
    )
    connection.observe(
        direction=Direction.DESTINATION,
        length=40,
        at=START + 6,
        tcp_flags=TcpFlags.parse("FA"),
    )
    connection.observe(
        direction=Direction.SOURCE, length=60, at=START + 7, tcp_flags=TcpFlags.parse("S")
    )
    assert connection.persisted_row_id is None

    layer.persist_many([connection])

    rows = _rows(session_factory)
    # The earlier conversation's aggregate survives as its own row (M9.17).
    assert len(rows) == 2
    assert first_row_id is not None
    assert {row.id for row in rows} != {first_row_id}


# -- repository queries (M9.25) ------------------------------------------


def _seed(session_factory) -> None:
    """Store three conversations: two TCP and one UDP, at different times."""
    layer = _persistence(session_factory)
    layer.persist_many(
        [
            _tcp_connection(destination_port=443),
            _tcp_connection(destination_port=8443),
            _reverse_connection(),
        ]
    )


def test_repository_lists_newest_first(session_factory) -> None:
    _seed(session_factory)
    rows = _rows(session_factory)
    assert len(rows) == 3
    starts = [row.start_time for row in rows]
    assert starts == sorted(starts, reverse=True)


def test_repository_filters_by_protocol(session_factory) -> None:
    _seed(session_factory)
    session = session_factory()
    try:
        repository = ConnectionRepository(session)
        assert len(repository.get_by_protocol("TCP")) == 3
        assert repository.get_by_protocol("UDP") == []
    finally:
        session.close()


def test_repository_filters_by_status(session_factory) -> None:
    _seed(session_factory)
    session = session_factory()
    try:
        repository = ConnectionRepository(session)
        assert len(repository.get_active()) == 3
        assert repository.get_completed() == []
    finally:
        session.close()


def test_repository_filters_by_ip_and_ports(session_factory) -> None:
    _seed(session_factory)
    session = session_factory()
    try:
        repository = ConnectionRepository(session)
        assert len(repository.get_by_ip("192.168.1.10")) == 3
        assert len(repository.get_by_ip("8.8.8.8")) == 3
        assert repository.get_by_ip("10.9.9.9") == []
        # Two conversations were recorded from 192.168.1.10:12345, so that port
        # is their recorded source; the third was recorded in reverse, so the
        # same port is its recorded destination (M9.5).
        assert len(repository.list(source_port=12345)) == 2
        assert len(repository.list(destination_port=12345)) == 1
        assert len(repository.list(destination_port=443)) == 1
        assert repository.count() == 3
        assert repository.count_all() == 3
    finally:
        session.close()


def test_repository_queries_by_device(session_factory) -> None:
    session = session_factory()
    try:
        device = Device(ip_address="192.168.1.10", mac_address="AA:BB:CC:DD:EE:FF")
        session.add(device)
        session.commit()
        device_row_id = device.id
    finally:
        session.close()

    connection = _tcp_connection()
    connection.source_device_id = "mac:AA:BB:CC:DD:EE:FF"
    layer = ConnectionPersistence(
        session_factory=session_factory,
        device_id_resolver=lambda runtime_id: (
            device_row_id if runtime_id == "mac:AA:BB:CC:DD:EE:FF" else None
        ),
    )
    layer.persist_many([connection])

    session = session_factory()
    try:
        repository = ConnectionRepository(session)
        # Either endpoint matches, so both device queries find the conversation.
        assert len(repository.get_by_device(device_row_id)) == 1
        assert len(repository.get_by_source_device(device_row_id)) == 1
        assert repository.get_by_destination_device(device_row_id) == []
        assert repository.get_by_device(device_row_id + 100) == []
    finally:
        session.close()


def test_repository_queries_by_time_range(session_factory) -> None:
    _seed(session_factory)
    session = session_factory()
    try:
        repository = ConnectionRepository(session)
        window_start = to_utc_datetime(START - 60)
        window_end = to_utc_datetime(START + 60)
        assert len(repository.get_between(window_start, window_end)) == 3
        # A window that begins after every conversation selects nothing.
        assert (
            repository.get_between(
                to_utc_datetime(START + 600), to_utc_datetime(START + 900)
            )
            == []
        )
    finally:
        session.close()


def test_repository_validates_paging(session_factory) -> None:
    session = session_factory()
    try:
        repository = ConnectionRepository(session)
        with pytest.raises(ValueError):
            repository.list(limit=0)
        with pytest.raises(ValueError):
            repository.list(offset=-1)
    finally:
        session.close()


def test_repository_updates_an_existing_row(session_factory) -> None:
    layer = _persistence(session_factory)
    connection = _tcp_connection()
    layer.persist_many([connection])

    session = session_factory()
    try:
        repository = ConnectionRepository(session)
        row = repository.list()[0]
        repository.update(row, packets_sent=9, status="completed")
    finally:
        session.close()

    rows = _rows(session_factory)
    assert rows[0].packets_sent == 9
    assert rows[0].status == "completed"
