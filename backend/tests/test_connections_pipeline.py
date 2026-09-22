"""Integration tests: CaptureManager -> PacketProcessor -> devices -> connections.

These tests drive real Scapy packets through the same callback path used in
production (fake sniffer -> PacketPipeline -> PacketProcessor ->
DeviceDiscoveryManager -> ConnectionTracker) and assert that conversations are
created, grouped bidirectionally, associated with devices, counted, expired and
persisted — while the M6 statistics engine and M8 device discovery keep working
alongside (M9.20/M9.24).
"""

from __future__ import annotations

import time
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether

from app.connections.manager import ConnectionTracker
from app.connections.persistence import ConnectionPersistence
from app.devices.manager import DeviceDiscoveryManager
from app.processing.processor import PacketProcessor
from app.repositories.connection import ConnectionRepository
from app.schemas.connection import ConnectionState
from app.services.capture_manager import CaptureManager
from app.services.packet_pipeline import PacketPipeline
from app.statistics.manager import TrafficStatisticsManager
from tests.fakes import (
    FakeCaptureSniffer,
    make_interface_manager,
    make_sniffer_factory,
)

MAC_A = "AA:BB:CC:DD:EE:FF"
MAC_B = "22:33:44:55:66:77"
DEVICE_A = f"mac:{MAC_A}"
DEVICE_B = f"mac:{MAC_B}"
IP_A = "192.168.1.10"
IP_B = "192.168.1.20"


def _traffic() -> list[Any]:
    """Return a short, harmless conversation between two local hosts.

    Three distinct flows: a TCP handshake (both directions), one UDP datagram
    and one ICMP echo. That is three conversations over four packets.
    """
    return [
        Ether(src=MAC_A, dst=MAC_B)
        / IP(src=IP_A, dst=IP_B)
        / TCP(sport=52000, dport=443, flags="S"),
        Ether(src=MAC_B, dst=MAC_A)
        / IP(src=IP_B, dst=IP_A)
        / TCP(sport=443, dport=52000, flags="SA"),
        Ether(src=MAC_A, dst=MAC_B)
        / IP(src=IP_A, dst=IP_B)
        / UDP(sport=53000, dport=53),
        Ether(src=MAC_B, dst=MAC_A) / IP(src=IP_B, dst=IP_A) / ICMP(),
    ]


def _make_manager(
    registry: list[FakeCaptureSniffer],
    statistics: TrafficStatisticsManager,
    devices: DeviceDiscoveryManager,
    connections: ConnectionTracker,
) -> CaptureManager:
    """Return a CaptureManager wired to fakes and the real M5/M6/M8/M9 pipeline."""
    interface_manager = make_interface_manager()
    interface_manager.select_interface("Wi-Fi")
    pipeline = PacketPipeline(
        processor=PacketProcessor(),
        statistics=statistics,
        devices=devices,
        connections=connections,
    )
    return CaptureManager(
        interface_manager=interface_manager,
        sniffer_factory=make_sniffer_factory(registry=registry),
        pipeline=pipeline,
    )


def _run_pipeline(
    registry: list[FakeCaptureSniffer],
    statistics: TrafficStatisticsManager,
    devices: DeviceDiscoveryManager,
    connections: ConnectionTracker,
) -> CaptureManager:
    """Start capture and push the sample conversation through the pipeline."""
    manager = _make_manager(registry, statistics, devices, connections)
    manager.start()
    for packet in _traffic():
        registry[0].emit_packet(packet)
    return manager


def _tracker(
    devices: DeviceDiscoveryManager | None = None,
    persistence: ConnectionPersistence | None = None,
) -> ConnectionTracker:
    """Return a thread-free tracker sharing the pipeline's device registry."""
    return ConnectionTracker(
        device_registry=devices.registry if devices is not None else None,
        persistence=persistence,
        autostart_cleanup=False,
    )


def _conversation(
    tracker: ConnectionTracker, protocol: str
) -> Any:
    """Return the single tracked conversation for ``protocol``."""
    matches = tracker.list_connections(protocol=protocol)
    assert len(matches) == 1
    return matches[0]


# ---------------------------------------------------------------------------
# Creation and grouping
# ---------------------------------------------------------------------------


def test_pipeline_creates_one_conversation_per_flow() -> None:
    """Each distinct 5-tuple becomes its own conversation (M9.3)."""
    registry: list[FakeCaptureSniffer] = []
    devices = DeviceDiscoveryManager()
    connections = _tracker(devices)
    _run_pipeline(registry, TrafficStatisticsManager(), devices, connections)

    assert connections.get_active_count() == 3
    assert {item.protocol for item in connections.get_active_connections()} == {
        "TCP",
        "UDP",
        "ICMP",
    }


def test_pipeline_groups_both_directions_of_one_conversation() -> None:
    """Request and reply share a conversation, with per-direction counters (M9.4)."""
    registry: list[FakeCaptureSniffer] = []
    devices = DeviceDiscoveryManager()
    connections = _tracker(devices)
    _run_pipeline(registry, TrafficStatisticsManager(), devices, connections)

    tcp = _conversation(connections, "TCP")

    assert tcp.source_ip == IP_A
    assert tcp.source_port == 52000
    assert tcp.destination_ip == IP_B
    assert tcp.destination_port == 443
    assert tcp.packet_count == 2
    assert tcp.source_packet_count == 1
    assert tcp.destination_packet_count == 1
    assert tcp.state is ConnectionState.ESTABLISHED


def test_pipeline_tracks_udp_and_icmp_flows() -> None:
    """UDP and ICMP conversations are tracked with their own shapes (M9.11/M9.12)."""
    registry: list[FakeCaptureSniffer] = []
    devices = DeviceDiscoveryManager()
    connections = _tracker(devices)
    _run_pipeline(registry, TrafficStatisticsManager(), devices, connections)

    udp = _conversation(connections, "UDP")
    icmp = _conversation(connections, "ICMP")

    assert udp.source_port == 53000
    assert udp.destination_port == 53
    assert udp.state is ConnectionState.ACTIVE
    assert icmp.source_port is None
    assert icmp.destination_port is None
    assert icmp.state is ConnectionState.ACTIVE


def test_pipeline_counts_bytes_and_timestamps() -> None:
    """Counters and timestamps follow the observed traffic (M9.7/M9.8)."""
    registry: list[FakeCaptureSniffer] = []
    devices = DeviceDiscoveryManager()
    connections = _tracker(devices)
    packets = _traffic()
    _run_pipeline(registry, TrafficStatisticsManager(), devices, connections)

    tcp = _conversation(connections, "TCP")
    tcp_bytes = len(packets[0]) + len(packets[1])

    assert tcp.byte_count == tcp_bytes
    assert tcp.source_byte_count + tcp.destination_byte_count == tcp_bytes
    assert tcp.first_seen <= tcp.last_seen


# ---------------------------------------------------------------------------
# Device association (M9.14)
# ---------------------------------------------------------------------------


def test_pipeline_associates_both_endpoints_with_devices() -> None:
    """Each conversation end names the M8 device that owns it (M9.14)."""
    registry: list[FakeCaptureSniffer] = []
    devices = DeviceDiscoveryManager()
    connections = _tracker(devices)
    _run_pipeline(registry, TrafficStatisticsManager(), devices, connections)

    tcp = _conversation(connections, "TCP")

    assert tcp.source_device_id == DEVICE_A
    assert tcp.destination_device_id == DEVICE_B


def test_pipeline_leaves_unknown_devices_unset() -> None:
    """Without a device registry the association stays unknown, never invented."""
    registry: list[FakeCaptureSniffer] = []
    devices = DeviceDiscoveryManager()
    connections = _tracker(None)
    _run_pipeline(registry, TrafficStatisticsManager(), devices, connections)

    tcp = _conversation(connections, "TCP")

    assert tcp.source_device_id is None
    assert tcp.destination_device_id is None


# ---------------------------------------------------------------------------
# Every consumer keeps running (M9.20)
# ---------------------------------------------------------------------------


def test_pipeline_keeps_every_consumer_in_step() -> None:
    """Statistics, devices and connections all observe the same traffic (M9.20)."""
    registry: list[FakeCaptureSniffer] = []
    statistics = TrafficStatisticsManager()
    devices = DeviceDiscoveryManager()
    connections = _tracker(devices)
    packets = _traffic()
    manager = _run_pipeline(registry, statistics, devices, connections)

    assert manager.get_processed_packet_count() == len(packets)
    assert manager.get_statistics_error_count() == 0
    assert manager.get_device_error_count() == 0
    assert manager.get_connection_error_count() == 0
    assert statistics.get_statistics().total_packets == len(packets)
    assert devices.get_device_count() == 2
    assert connections.get_active_count() == 3


class _RaisingConnectionTracker(ConnectionTracker):
    """Tracker whose ``process_packet`` always fails (M9.20)."""

    def process_packet(self, packet: Any) -> Any:  # type: ignore[override]
        raise RuntimeError("simulated connection tracking failure")


def test_connection_tracking_failure_does_not_stop_capture() -> None:
    """A failing tracker never terminates capture, statistics or discovery (M9.20)."""
    registry: list[FakeCaptureSniffer] = []
    statistics = TrafficStatisticsManager()
    devices = DeviceDiscoveryManager()
    failures = _RaisingConnectionTracker(autostart_cleanup=False)
    packets = _traffic()
    manager = _run_pipeline(registry, statistics, devices, failures)

    assert manager.is_running() is True
    assert manager.get_processed_packet_count() == len(packets)
    assert manager.get_connection_error_count() == len(packets)
    assert statistics.get_statistics().total_packets == len(packets)
    assert devices.get_device_count() == 2


def test_malformed_packet_does_not_break_tracking() -> None:
    """A packet the processor rejects is isolated and later traffic still lands."""
    registry: list[FakeCaptureSniffer] = []
    devices = DeviceDiscoveryManager()
    connections = _tracker(devices)
    manager = _make_manager(registry, TrafficStatisticsManager(), devices, connections)
    manager.start()

    registry[0].emit_packet(None)
    for packet in _traffic():
        registry[0].emit_packet(packet)

    assert manager.get_processing_error_count() == 1
    assert manager.get_connection_error_count() == 0
    assert connections.get_active_count() == 3


# ---------------------------------------------------------------------------
# Expiration and persistence through the pipeline (M9.15/M9.17)
# ---------------------------------------------------------------------------


def test_capture_stop_writes_the_session_aggregates(session_factory) -> None:
    """Stopping a session persists one row per conversation it observed (M9.17)."""
    registry: list[FakeCaptureSniffer] = []
    devices = DeviceDiscoveryManager()
    connections = _tracker(
        devices,
        persistence=ConnectionPersistence(session_factory=session_factory),
    )
    manager = _run_pipeline(
        registry, TrafficStatisticsManager(), devices, connections
    )

    assert connections.get_persisted_count() == 0
    manager.stop()

    session = session_factory()
    try:
        rows = ConnectionRepository(session).list(limit=10)
    finally:
        session.close()

    assert connections.get_persisted_count() == 3
    assert len(rows) == 3
    assert {row.protocol for row in rows} == {"TCP", "UDP", "ICMP"}


def test_expiring_a_conversation_writes_its_aggregate(session_factory) -> None:
    """An idle conversation is retired and its final aggregate recorded (M9.15)."""
    registry: list[FakeCaptureSniffer] = []
    devices = DeviceDiscoveryManager()
    connections = _tracker(
        devices,
        persistence=ConnectionPersistence(session_factory=session_factory),
    )
    _run_pipeline(registry, TrafficStatisticsManager(), devices, connections)

    idle = time.time() + 10_000
    assert connections.expire_connections(now=idle) == 3

    assert connections.get_active_count() == 0
    assert connections.get_historical_count() == 3

    session = session_factory()
    try:
        rows = ConnectionRepository(session).list(limit=10)
    finally:
        session.close()

    # A conversation that simply goes idle keeps its evidence: the established
    # TCP flow is recorded as ``timeout`` while the connectionless UDP/ICMP
    # flows, which have no terminal state, are ``completed`` (M9.10/M9.11).
    assert len(rows) == 3
    assert {row.protocol: row.status for row in rows} == {
        "TCP": "timeout",
        "UDP": "completed",
        "ICMP": "completed",
    }
