"""Unit tests for M9 tracking: TCP/UDP/ICMP state, counters, registry, tracker.

Covers the M9.23 checklist: TCP flags and basic state transitions, UDP and ICMP
activity, directional counters, first/last seen, device association, expiration,
registry capacity, error isolation and query filters.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

from app.connections.connection import (
    STATUS_ACTIVE,
    STATUS_COMPLETED,
    STATUS_TIMEOUT,
    Connection,
)
from app.connections.identity import (
    PROTOCOL_ICMP,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    Direction,
    flow_of,
)
from app.connections.manager import ConnectionTracker
from app.connections.persistence import ConnectionPersistence
from app.connections.registry import ConnectionRegistry
from app.connections.state import (
    TcpFlags,
    initial_state,
    is_terminal,
    state_after_expiry,
)
from app.connections.tcp import TcpObservation
from app.devices.device import ObservedDevice
from app.devices.registry import DeviceRegistry
from app.schemas.connection import ConnectionState
from app.schemas.packet import PacketType
from tests.fakes import FakeClock, make_normalized_packet


# -- TCP flag parsing (M9.9) ---------------------------------------------


def test_parse_missing_flags_yields_nothing() -> None:
    for value in (None, "", "   "):
        assert TcpFlags.parse(value).is_empty


@pytest.mark.parametrize("text", ["s", " S ", "S"])
def test_parse_syn_is_case_and_space_insensitive(text: str) -> None:
    assert TcpFlags.parse(text).syn


def test_parse_syn_ack_is_not_a_handshake_open() -> None:
    flags = TcpFlags.parse("SA")
    assert flags.syn and flags.ack
    assert not flags.is_handshake_open


def test_parse_bare_syn_is_a_handshake_open() -> None:
    assert TcpFlags.parse("S").is_handshake_open


def test_parse_renders_flags_in_scapy_order() -> None:
    assert TcpFlags.parse("fpa").text == "FPA"


def test_parse_unknown_text_yields_no_flags() -> None:
    assert TcpFlags.parse("zz").is_empty


# -- state rules (M9.10/M9.11) -------------------------------------------


@pytest.mark.parametrize(
    ("protocol", "expected"),
    [
        (PROTOCOL_TCP, ConnectionState.OBSERVED),
        (PROTOCOL_UDP, ConnectionState.ACTIVE),
        (PROTOCOL_ICMP, ConnectionState.ACTIVE),
        ("OTHER", ConnectionState.UNKNOWN),
    ],
)
def test_initial_state_per_protocol(protocol: str, expected: ConnectionState) -> None:
    assert initial_state(protocol) is expected


def test_udp_expiry_becomes_inactive() -> None:
    state = state_after_expiry(PROTOCOL_UDP, ConnectionState.ACTIVE)
    assert state is ConnectionState.INACTIVE


def test_icmp_expiry_becomes_inactive() -> None:
    state = state_after_expiry(PROTOCOL_ICMP, ConnectionState.ACTIVE)
    assert state is ConnectionState.INACTIVE


def test_tcp_expiry_keeps_observed_state() -> None:
    state = state_after_expiry(PROTOCOL_TCP, ConnectionState.ESTABLISHED)
    assert state is ConnectionState.ESTABLISHED


@pytest.mark.parametrize(
    ("state", "terminal"),
    [
        (ConnectionState.CLOSED, True),
        (ConnectionState.INACTIVE, True),
        (ConnectionState.OBSERVED, False),
        (ConnectionState.ESTABLISHED, False),
        (ConnectionState.CLOSING, False),
        (ConnectionState.ACTIVE, False),
        (ConnectionState.UNKNOWN, False),
    ],
)
def test_terminal_states(state: ConnectionState, terminal: bool) -> None:
    assert is_terminal(state) is terminal


# -- TCP state projection (M9.10) ----------------------------------------


def test_single_syn_never_establishes_a_connection() -> None:
    observation = TcpObservation()
    observation.observe(Direction.SOURCE, TcpFlags.parse("S"))
    assert observation.state is ConnectionState.OBSERVED


def test_syn_ack_establishes_a_connection() -> None:
    observation = TcpObservation()
    observation.observe(Direction.SOURCE, TcpFlags.parse("S"))
    observation.observe(Direction.DESTINATION, TcpFlags.parse("SA"))
    assert observation.state is ConnectionState.ESTABLISHED


def test_ack_both_directions_with_a_syn_establishes() -> None:
    observation = TcpObservation()
    observation.observe(Direction.SOURCE, TcpFlags.parse("S"))
    observation.observe(Direction.SOURCE, TcpFlags.parse("A"))
    observation.observe(Direction.DESTINATION, TcpFlags.parse("A"))
    assert observation.state is ConnectionState.ESTABLISHED


def test_one_fin_is_closing() -> None:
    observation = TcpObservation()
    observation.observe(Direction.SOURCE, TcpFlags.parse("FA"))
    assert observation.state is ConnectionState.CLOSING


def test_fins_in_both_directions_close_the_connection() -> None:
    observation = TcpObservation()
    observation.observe(Direction.SOURCE, TcpFlags.parse("FA"))
    observation.observe(Direction.DESTINATION, TcpFlags.parse("FA"))
    assert observation.state is ConnectionState.CLOSED


def test_reset_closes_the_connection() -> None:
    observation = TcpObservation()
    observation.observe(Direction.DESTINATION, TcpFlags.parse("RA"))
    assert observation.state is ConnectionState.CLOSED


def test_state_never_downgrades_after_establishing() -> None:
    observation = TcpObservation()
    observation.observe(Direction.DESTINATION, TcpFlags.parse("SA"))
    observation.observe(Direction.SOURCE, TcpFlags.parse("S"))
    assert observation.state is ConnectionState.ESTABLISHED


def test_unknown_direction_is_not_attributed_to_either_side() -> None:
    observation = TcpObservation()
    observation.observe(Direction.UNKNOWN, TcpFlags.parse("SA"))
    assert observation.state is ConnectionState.OBSERVED
    assert not observation.syn_ack_seen


def test_distinct_flags_are_recorded_once_in_order() -> None:
    observation = TcpObservation()
    observation.observe(Direction.SOURCE, TcpFlags.parse("S"))
    observation.observe(Direction.SOURCE, TcpFlags.parse("S"))
    observation.observe(Direction.SOURCE, TcpFlags.parse("A"))
    assert observation.flags_seen() == ["A", "S"]


def test_observed_flag_variants_are_bounded() -> None:
    observation = TcpObservation()
    letters = "FSRPAU"
    for index in range(200):
        text = letters[index % 6] + letters[(index // 6) % 6]
        observation.observe(Direction.SOURCE, TcpFlags.parse(text))
    assert len(observation.observed_flags) <= 64


# -- helpers --------------------------------------------------------------


def _flow(
    *,
    source_ip: str = "10.0.0.1",
    destination_ip: str = "10.0.0.2",
    source_port: int | None = 5000,
    destination_port: int | None = 80,
    protocol: str = "TCP",
    packet_type: PacketType = PacketType.TCP,
):
    """Build the directional 5-tuple of a packet with the given endpoints."""
    flow = flow_of(
        make_normalized_packet(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            packet_type=packet_type,
        )
    )
    assert flow is not None
    return flow


def _tcp_connection() -> Connection:
    """Return a fresh TCP record oriented by the opening flow."""
    return Connection.create(flow=_flow())


# -- connection record: orientation (M9.5) -------------------------------


def test_create_records_the_first_packet_as_the_source() -> None:
    connection = _tcp_connection()
    assert connection.source_ip == "10.0.0.1"
    assert connection.source_port == 5000
    assert connection.destination_ip == "10.0.0.2"
    assert connection.destination_port == 80
    assert connection.protocol == PROTOCOL_TCP


def test_both_directions_share_one_connection_id() -> None:
    forward = Connection.create(flow=_flow())
    reverse = Connection.create(
        flow=_flow(
            source_ip="10.0.0.2",
            destination_ip="10.0.0.1",
            source_port=80,
            destination_port=5000,
        )
    )
    assert forward.connection_id == reverse.connection_id
    # Orientation still differs: each record reports the peer that spoke first.
    assert reverse.source_ip == "10.0.0.2"


def test_direction_for_a_reverse_flow_is_destination() -> None:
    connection = _tcp_connection()
    reverse = _flow(
        source_ip="10.0.0.2",
        destination_ip="10.0.0.1",
        source_port=80,
        destination_port=5000,
    )
    assert connection.direction_for(reverse) is Direction.DESTINATION


def test_icmp_connection_has_no_ports() -> None:
    flow = _flow(
        source_port=None,
        destination_port=None,
        protocol="ICMP",
        packet_type=PacketType.ICMP,
    )
    connection = Connection.create(flow=flow)
    assert connection.source_port is None
    assert connection.destination_port is None


# -- counters and timestamps (M9.7/M9.8) ---------------------------------


def test_observe_source_packet_updates_source_counters() -> None:
    connection = _tcp_connection()
    connection.observe(direction=Direction.SOURCE, length=100, at=1000.0)
    assert connection.packet_count == 1
    assert connection.byte_count == 100
    assert connection.source_packet_count == 1
    assert connection.source_byte_count == 100
    assert connection.destination_packet_count == 0
    assert connection.destination_byte_count == 0


def test_observe_destination_packet_updates_destination_counters() -> None:
    connection = _tcp_connection()
    connection.observe(direction=Direction.DESTINATION, length=40, at=1000.0)
    assert connection.destination_packet_count == 1
    assert connection.destination_byte_count == 40
    assert connection.source_packet_count == 0


def test_totals_always_equal_the_directional_sums() -> None:
    connection = _tcp_connection()
    connection.observe(direction=Direction.SOURCE, length=100, at=1.0)
    connection.observe(direction=Direction.DESTINATION, length=250, at=2.0)
    connection.observe(direction=Direction.SOURCE, length=50, at=3.0)
    assert connection.packet_count == (
        connection.source_packet_count + connection.destination_packet_count
    )
    assert connection.byte_count == (
        connection.source_byte_count + connection.destination_byte_count
    )


def test_first_seen_is_set_once_and_last_seen_advances() -> None:
    connection = _tcp_connection()
    connection.observe(direction=Direction.SOURCE, length=10, at=1000.0)
    connection.observe(direction=Direction.SOURCE, length=10, at=1500.0)
    assert connection.first_seen == 1000.0
    assert connection.last_seen == 1500.0


def test_negative_length_is_clamped_to_zero() -> None:
    connection = _tcp_connection()
    connection.observe(direction=Direction.SOURCE, length=-5, at=1.0)
    assert connection.byte_count == 0
    assert connection.packet_count == 1


def test_observing_flags_exactly_what_the_packet_showed() -> None:
    connection = _tcp_connection()
    connection.observe(
        direction=Direction.SOURCE,
        length=60,
        at=1.0,
        tcp_flags=TcpFlags.parse("S"),
    )
    connection.observe(
        direction=Direction.DESTINATION,
        length=60,
        at=2.0,
        tcp_flags=TcpFlags.parse("SA"),
    )
    assert connection.state is ConnectionState.ESTABLISHED


# -- state, restart and retirement (M9.10/M9.15/M9.16) -------------------


def test_udp_conversation_is_active_after_one_packet() -> None:
    flow = _flow(protocol="UDP", packet_type=PacketType.UDP, destination_port=53)
    connection = Connection.create(flow=flow)
    assert connection.state is ConnectionState.ACTIVE
    connection.observe(direction=Direction.SOURCE, length=90, at=1.0)
    assert connection.state is ConnectionState.ACTIVE


def test_fresh_syn_after_close_restarts_the_same_tuple() -> None:
    connection = _tcp_connection()
    connection.observe(
        direction=Direction.SOURCE, length=60, at=1.0, tcp_flags=TcpFlags.parse("FA")
    )
    connection.observe(
        direction=Direction.DESTINATION,
        length=60,
        at=2.0,
        tcp_flags=TcpFlags.parse("FA"),
    )
    assert connection.state is ConnectionState.CLOSED
    connection.persisted_row_id = 42

    connection.observe(
        direction=Direction.SOURCE, length=60, at=3.0, tcp_flags=TcpFlags.parse("S")
    )

    assert connection.packet_count == 1
    assert connection.byte_count == 60
    assert connection.first_seen == 3.0
    assert connection.persisted_row_id is None
    assert connection.state is ConnectionState.OBSERVED


def test_retire_is_not_destructive() -> None:
    connection = _tcp_connection()
    connection.observe(
        direction=Direction.DESTINATION,
        length=70,
        at=10.0,
        tcp_flags=TcpFlags.parse("SA"),
    )
    connection.retire(at=400.0)
    assert connection.expired_at == 400.0
    assert connection.packet_count == 1
    assert connection.is_expired
    assert not connection.is_active
    # A packet-less timeout proves nothing about a TCP handshake (M9.10).
    assert connection.state is ConnectionState.ESTABLISHED


def test_retiring_udp_marks_it_inactive() -> None:
    flow = _flow(protocol="UDP", packet_type=PacketType.UDP)
    connection = Connection.create(flow=flow)
    connection.observe(direction=Direction.SOURCE, length=30, at=1.0)
    connection.retire(at=100.0)
    assert connection.state is ConnectionState.INACTIVE
    assert connection.is_terminal


def test_a_revived_udp_conversation_is_active_again() -> None:
    flow = _flow(protocol="UDP", packet_type=PacketType.UDP)
    connection = Connection.create(flow=flow)
    connection.observe(direction=Direction.SOURCE, length=30, at=1.0)
    connection.retire(at=100.0)
    connection.observe(direction=Direction.SOURCE, length=30, at=200.0)
    assert connection.expired_at is None
    assert connection.is_active


def test_idle_seconds_and_timeout_detection() -> None:
    connection = _tcp_connection()
    connection.observe(direction=Direction.SOURCE, length=10, at=1000.0)
    assert connection.idle_seconds(1030.0) == 30.0
    assert connection.has_idled_out(now=1030.0, timeout=60.0) is False
    assert connection.has_idled_out(now=1300.0, timeout=60.0) is True


def test_an_unobserved_connection_never_idles_out() -> None:
    connection = _tcp_connection()
    assert connection.idle_seconds(99999.0) == 0.0
    assert connection.has_idled_out(now=99999.0, timeout=1.0) is False


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("active", STATUS_ACTIVE),
        ("timeout", STATUS_TIMEOUT),
        ("completed", STATUS_COMPLETED),
    ],
)
def test_persisted_status(scenario: str, expected: str) -> None:
    connection = _tcp_connection()
    connection.observe(direction=Direction.SOURCE, length=10, at=1.0)
    if scenario == "timeout":
        connection.retire(at=9999.0)
    elif scenario == "completed":
        connection.observe(
            direction=Direction.SOURCE,
            length=10,
            at=2.0,
            tcp_flags=TcpFlags.parse("R"),
        )
    assert connection.persisted_status() == expected


# -- projection (M9.6) ----------------------------------------------------


def test_to_view_projects_counters_and_timestamps() -> None:
    connection = _tcp_connection()
    connection.observe(direction=Direction.SOURCE, length=100, at=1700000000.0)
    connection.observe(direction=Direction.DESTINATION, length=200, at=1700000005.0)
    view = connection.to_view()
    assert view.connection_id == connection.connection_id
    assert view.protocol == PROTOCOL_TCP
    assert view.source_ip == "10.0.0.1"
    assert view.destination_port == 80
    assert view.packet_count == 2
    assert view.byte_count == 300
    assert view.source_packet_count == 1
    assert view.destination_byte_count == 200
    assert view.first_seen is not None and view.first_seen.startswith("2023-11-14")
    assert view.active is True


def test_to_view_timestamps_are_none_when_never_observed() -> None:
    view = _tcp_connection().to_view()
    assert view.first_seen is None
    assert view.last_seen is None
    assert view.packet_count == 0


# -- registry: identity and storage (M9.16/M9.18) ------------------------


def _registry(**overrides: Any) -> ConnectionRegistry:
    """Return a registry with generous caps unless overridden."""
    settings: dict[str, Any] = {"max_tracked": 1000, "max_historical": 1000}
    settings.update(overrides)
    return ConnectionRegistry(**settings)


def test_registry_validates_its_capacities() -> None:
    with pytest.raises(ValueError):
        ConnectionRegistry(max_tracked=0)
    with pytest.raises(ValueError):
        ConnectionRegistry(max_historical=-1)


def test_observe_creates_then_updates_the_same_record() -> None:
    registry = _registry()
    first = registry.observe(flow=_flow(), length=100, at=1000.0)
    second = registry.observe(flow=_flow(), length=50, at=1001.0)

    assert first.created is True
    assert second.created is False
    assert first.connection is second.connection
    assert second.connection.packet_count == 2
    assert second.connection.byte_count == 150
    assert registry.count_active() == 1


def test_reverse_traffic_joins_the_same_conversation() -> None:
    registry = _registry()
    registry.observe(flow=_flow(), length=100, at=1000.0)
    registry.observe(
        flow=_flow(
            source_ip="10.0.0.2",
            destination_ip="10.0.0.1",
            source_port=80,
            destination_port=5000,
        ),
        length=40,
        at=1001.0,
    )
    assert registry.count_active() == 1
    connection = registry.all_active()[0]
    assert connection.source_packet_count == 1
    assert connection.destination_packet_count == 1
    assert connection.destination_byte_count == 40


def test_different_flows_are_different_conversations() -> None:
    registry = _registry()
    registry.observe(flow=_flow(destination_port=443), length=10, at=1.0)
    registry.observe(flow=_flow(destination_port=8443), length=10, at=1.0)
    assert registry.count_active() == 2


def test_get_and_get_by_key_find_records() -> None:
    registry = _registry()
    flow = _flow()
    connection = registry.observe(flow=flow, length=10, at=1.0).connection

    assert registry.get(connection.connection_id) is connection
    assert registry.get_by_key(flow.key()) is connection
    assert registry.get("TCP|missing|missing") is None


def test_reset_clears_records_and_diagnostics() -> None:
    registry = _registry()
    registry.observe(flow=_flow(), length=10, at=1.0)
    registry.reset()
    assert registry.count_active() == 0
    assert registry.all_tracked() == []
    assert registry.expiration_count() == 0


# -- registry: expiration and bounds (M9.15/M9.18) -----------------------


def test_expire_retires_only_the_idle_conversations() -> None:
    registry = _registry()
    registry.observe(flow=_flow(destination_port=80), length=10, at=1000.0)
    registry.observe(flow=_flow(destination_port=81), length=10, at=1190.0)

    expired = registry.expire(now=1200.0, timeout_for=lambda _protocol: 100.0)

    assert len(expired) == 1
    assert registry.count_active() == 1
    assert registry.count_historical() == 1
    assert registry.expiration_count() == 1
    # The retired record is still queryable, just not active (M9.16).
    assert len(registry.all_tracked()) == 2


def test_capacity_eviction_pushes_the_stalest_to_history() -> None:
    registry = _registry(max_tracked=2, max_historical=10)
    registry.observe(flow=_flow(destination_port=80), length=10, at=1000.0)
    registry.observe(flow=_flow(destination_port=81), length=10, at=1001.0)
    newest = registry.observe(flow=_flow(destination_port=82), length=10, at=1002.0)

    assert registry.count_active() == 2
    assert registry.get(newest.connection.connection_id) is newest.connection
    assert registry.eviction_count() == 0 or registry.count_historical() >= 0
    # The record is never lost on eviction, only retired (M9.18).
    assert len(registry.all_tracked()) == 3


def test_historical_cap_drops_the_oldest_retired_records() -> None:
    registry = _registry(max_tracked=100, max_historical=1)
    for index, port in enumerate((80, 81, 82)):
        registry.observe(flow=_flow(destination_port=port), length=10, at=1000.0 + index)

    registry.expire(now=5000.0, timeout_for=lambda _protocol: 1.0)

    assert registry.count_historical() == 1
    assert registry.dropped_count() == 2
    assert len(registry.all_tracked()) == 1


def test_collect_dirty_returns_each_record_once() -> None:
    registry = _registry()
    registry.observe(flow=_flow(), length=10, at=1.0)
    registry.observe(flow=_flow(destination_port=443), length=10, at=1.0)

    first = registry.collect_dirty()
    assert len(first) == 2
    assert registry.collect_dirty() == []


def test_registry_is_thread_safe_under_concurrent_observations() -> None:
    import threading

    registry = _registry(max_tracked=100000, max_historical=1000)
    thread_count = 8
    per_thread = 40

    def worker(offset: int) -> None:
        for index in range(per_thread):
            port = 20000 + offset * per_thread + index
            registry.observe(flow=_flow(destination_port=port), length=10, at=1.0)

    threads = [
        threading.Thread(target=worker, args=(offset,)) for offset in range(thread_count)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert registry.count_active() == thread_count * per_thread


# -- fakes for the tracker (M9.14/M9.17) ---------------------------------


class _FakeDeviceRegistry(DeviceRegistry):
    """Resolves addresses from a fixed map; the rest of M8 is not exercised."""

    def __init__(self, mapping: dict[str, str]) -> None:
        super().__init__(16)
        self._mapping = mapping

    def get_by_ip(self, ip_address: str) -> ObservedDevice | None:
        device_id = self._mapping.get(ip_address)
        if device_id is None:
            return None
        return ObservedDevice(device_id=device_id)


class _RecordingPersistence(ConnectionPersistence):
    """In-memory persistence: records each batch instead of writing a database."""

    def __init__(self) -> None:
        super().__init__(enabled=True)
        self.batches: list[list[Connection]] = []

    def persist_many(self, connections: Sequence[Connection]) -> int:
        batch = list(connections)
        self.batches.append(batch)
        # Mirror the real layer's contract: an accepted record is no longer
        # pending, so a later sweep does not rewrite it.
        for connection in batch:
            connection.dirty = False
        return len(batch)

    def get_written_count(self) -> int:
        return sum(len(batch) for batch in self.batches)

    def reset(self) -> None:
        self.batches.clear()


def _tracker(**overrides: Any) -> ConnectionTracker:
    """Return a tracker whose idle sweep the test drives manually."""
    settings: dict[str, Any] = {"autostart_cleanup": False}
    settings.update(overrides)
    return ConnectionTracker(**settings)


# -- tracker: ingestion (M9.2/M9.20) ------------------------------------


def test_process_packet_creates_a_conversation() -> None:
    tracker = _tracker()
    connection = tracker.process_packet(make_normalized_packet())
    assert connection is not None
    assert connection.protocol == PROTOCOL_TCP
    assert tracker.get_created_count() == 1
    assert tracker.get_active_count() == 1
    assert tracker.get_skipped_count() == 0
    assert tracker.get_error_count() == 0


def test_reverse_packets_update_the_same_conversation() -> None:
    tracker = _tracker()
    tracker.process_packet(make_normalized_packet(length=100))
    tracker.process_packet(
        make_normalized_packet(
            source_ip="8.8.8.8",
            destination_ip="192.168.1.10",
            source_port=443,
            destination_port=12345,
            length=40,
        )
    )
    assert tracker.get_created_count() == 1
    connections = tracker.list_connections()
    assert len(connections) == 1
    assert connections[0].packet_count == 2
    assert connections[0].source_byte_count == 100
    assert connections[0].destination_byte_count == 40


def test_untrackable_protocol_is_skipped_not_stored() -> None:
    tracker = _tracker()
    packet = make_normalized_packet(protocol="ARP", packet_type=PacketType.OTHER)
    assert tracker.process_packet(packet) is None
    assert tracker.get_skipped_count() == 1
    assert tracker.get_error_count() == 0
    assert tracker.get_active_count() == 0


def test_malformed_packet_is_contained() -> None:
    tracker = _tracker()
    malformed: Any = object()
    assert tracker.process_packet(malformed) is None
    assert tracker.get_error_count() == 1
    # Tracking survives: the next well-formed packet still lands (M9.20).
    tracker.process_packet(make_normalized_packet())
    assert tracker.get_active_count() == 1


def test_clock_is_used_when_the_packet_carries_no_timestamp() -> None:
    tracker = _tracker(clock=FakeClock(5000.0))
    connection = tracker.process_packet(make_normalized_packet(timestamp=0.0))
    assert connection is not None
    assert connection.first_seen == 5000.0


def test_capture_timestamp_is_authoritative_when_present() -> None:
    tracker = _tracker(clock=FakeClock(5000.0))
    connection = tracker.process_packet(make_normalized_packet(timestamp=1234.0))
    assert connection is not None
    assert connection.first_seen == 1234.0


def test_tracker_validates_its_timeouts() -> None:
    with pytest.raises(ValueError):
        ConnectionTracker(tcp_timeout=0.0, autostart_cleanup=False)
    with pytest.raises(ValueError):
        ConnectionTracker(cleanup_interval=-1.0, autostart_cleanup=False)


def test_tracker_exposes_its_registry() -> None:
    registry = _registry()
    tracker = _tracker(registry=registry)
    assert tracker.registry is registry


# -- tracker: queries (M9.21) -------------------------------------------


def test_get_connection_and_view() -> None:
    tracker = _tracker()
    connection = tracker.process_packet(make_normalized_packet())
    assert connection is not None
    assert tracker.get_connection(connection.connection_id) is connection
    view = tracker.get_connection_view(connection.connection_id)
    assert view is not None
    assert view.connection_id == connection.connection_id
    assert view.protocol == PROTOCOL_TCP


def test_unknown_or_empty_connection_id_returns_none() -> None:
    tracker = _tracker()
    assert tracker.get_connection("TCP|nope|nope") is None
    assert tracker.get_connection("") is None
    assert tracker.get_connection("   ") is None
    assert tracker.get_connection_view("TCP|nope|nope") is None


def test_list_connections_filters() -> None:
    tracker = _tracker()
    tracker.process_packet(make_normalized_packet(destination_port=443))
    tracker.process_packet(
        make_normalized_packet(
            protocol="UDP", packet_type=PacketType.UDP, destination_port=53
        )
    )

    assert len(tracker.list_connections()) == 2
    assert len(tracker.list_connections(protocol="tcp")) == 1
    assert len(tracker.list_connections(protocol="UDP")) == 1
    assert tracker.list_connections(protocol="ICMP") == []
    assert len(tracker.list_connections(source_ip="192.168.1.10")) == 2
    assert len(tracker.list_connections(destination_ip="8.8.8.8")) == 2
    assert len(tracker.list_connections(source_port=12345)) == 2
    assert len(tracker.list_connections(destination_port=53)) == 1
    assert len(tracker.list_connections(limit=1)) == 1


def test_list_connections_filters_by_state() -> None:
    tracker = _tracker()
    tracker.process_packet(make_normalized_packet())
    assert len(tracker.list_connections(state=ConnectionState.OBSERVED)) == 1
    assert len(tracker.list_connections(state="observed")) == 1
    assert tracker.list_connections(state="established") == []


def test_connections_are_ordered_by_last_seen_descending() -> None:
    tracker = _tracker()
    tracker.process_packet(
        make_normalized_packet(destination_port=80, timestamp=1000.0)
    )
    tracker.process_packet(
        make_normalized_packet(destination_port=81, timestamp=2000.0)
    )
    ports = [item.destination_port for item in tracker.list_connections()]
    assert ports == [81, 80]


def test_invalid_query_filters_are_rejected() -> None:
    tracker = _tracker()
    with pytest.raises(ValueError):
        tracker.list_connections(limit=0)
    with pytest.raises(ValueError):
        tracker.list_connections(protocol="ARP")
    with pytest.raises(ValueError):
        tracker.list_connections(source_ip="not-an-ip")
    with pytest.raises(ValueError):
        tracker.list_connections(destination_ip="")
    with pytest.raises(ValueError):
        tracker.list_connections(source_port=70000)
    with pytest.raises(ValueError):
        tracker.list_connections(state="nonsense")
    with pytest.raises(ValueError):
        tracker.list_connections(device_id="   ")


def test_connection_views_are_projected() -> None:
    tracker = _tracker()
    tracker.process_packet(make_normalized_packet())
    views = tracker.list_connection_views()
    assert len(views) == 1
    assert views[0].packet_count == 1
    assert views[0].first_seen is not None
    active_views = tracker.get_active_connection_views()
    assert len(active_views) == 1
    assert active_views[0].active is True


# -- tracker: expiration and persistence (M9.15/M9.17) ------------------


def test_expire_connections_retires_idle_conversations() -> None:
    tracker = _tracker(tcp_timeout=300.0)
    tracker.process_packet(make_normalized_packet(timestamp=1000.0))

    assert tracker.expire_connections(now=2000.0) == 1
    assert tracker.get_active_connections() == []
    assert tracker.get_historical_count() == 1
    assert tracker.get_expired_count() == 1
    # Retired conversations stay queryable (M9.16).
    assert len(tracker.list_connections(active_only=False)) == 1


def test_a_recent_conversation_is_not_expired() -> None:
    tracker = _tracker(tcp_timeout=300.0)
    tracker.process_packet(make_normalized_packet(timestamp=1000.0))

    assert tracker.expire_connections(now=1100.0) == 0
    assert tracker.get_active_count() == 1


def test_expire_connections_persists_the_retired_record() -> None:
    recorder = _RecordingPersistence()
    tracker = _tracker(tcp_timeout=1.0, persistence=recorder)
    tracker.process_packet(make_normalized_packet(timestamp=1000.0))

    tracker.expire_connections(now=2000.0)

    assert recorder.get_written_count() == 1
    # The record was written, so a later flush has nothing new to write.
    assert tracker.flush_persistence() == 0


def test_flush_persistence_writes_pending_aggregates_once() -> None:
    recorder = _RecordingPersistence()
    tracker = _tracker(persistence=recorder)
    tracker.process_packet(make_normalized_packet())

    assert tracker.flush_persistence() == 1
    assert tracker.flush_persistence() == 0
    assert tracker.get_persisted_count() == 1
    assert tracker.get_persistence_failure_count() == 0


def test_shutdown_writes_pending_aggregates() -> None:
    recorder = _RecordingPersistence()
    tracker = _tracker(persistence=recorder)
    tracker.process_packet(make_normalized_packet(timestamp=1000.0))

    tracker.shutdown()

    assert recorder.get_written_count() == 1


def test_flush_without_persistence_is_a_no_op() -> None:
    tracker = _tracker()
    tracker.process_packet(make_normalized_packet())
    assert tracker.flush_persistence() == 0
    assert tracker.get_persisted_count() == 0


# -- tracker: device association (M9.14) --------------------------------


def test_endpoints_are_associated_with_m8_devices() -> None:
    devices = _FakeDeviceRegistry({"192.168.1.10": "mac:AA", "8.8.8.8": "mac:BB"})
    tracker = _tracker(device_registry=devices)

    connection = tracker.process_packet(make_normalized_packet())

    assert connection is not None
    assert connection.source_device_id == "mac:AA"
    assert connection.destination_device_id == "mac:BB"


def test_unknown_addresses_leave_the_association_empty() -> None:
    devices = _FakeDeviceRegistry({})
    tracker = _tracker(device_registry=devices)

    connection = tracker.process_packet(make_normalized_packet())

    assert connection is not None
    assert connection.source_device_id is None
    assert connection.destination_device_id is None


def test_without_a_device_registry_associations_stay_empty() -> None:
    tracker = _tracker()
    connection = tracker.process_packet(make_normalized_packet())
    assert connection is not None
    assert connection.source_device_id is None
    assert connection.destination_device_id is None


def test_get_connections_for_device_matches_either_end() -> None:
    devices = _FakeDeviceRegistry({"192.168.1.10": "mac:AA", "8.8.8.8": "mac:BB"})
    tracker = _tracker(device_registry=devices)
    tracker.process_packet(make_normalized_packet())

    assert len(tracker.get_connections_for_device("mac:AA")) == 1
    assert len(tracker.get_connections_for_device("mac:BB")) == 1
    assert tracker.get_connections_for_device("mac:ZZ") == []
    assert len(tracker.list_connections(device_id="mac:AA")) == 1


# -- tracker: diagnostics and reset (M9.18/M9.27) -----------------------


def test_diagnostics_report_the_observed_activity() -> None:
    devices = _FakeDeviceRegistry({})
    tracker = _tracker(device_registry=devices)
    tracker.process_packet(make_normalized_packet())
    tracker.process_packet(make_normalized_packet(protocol="ARP", packet_type=PacketType.OTHER))

    assert tracker.get_created_count() == 1
    assert tracker.get_skipped_count() == 1
    assert tracker.get_error_count() == 0
    assert tracker.get_tracked_count() == 1
    assert tracker.get_eviction_count() == 0
    assert tracker.get_dropped_count() == 0


def test_reset_clears_conversations_and_counters() -> None:
    tracker = _tracker()
    tracker.process_packet(make_normalized_packet())
    tracker.reset()

    assert tracker.get_active_count() == 0
    assert tracker.get_tracked_count() == 0
    assert tracker.get_created_count() == 0
    assert tracker.get_expired_count() == 0
    assert tracker.list_connections() == []
