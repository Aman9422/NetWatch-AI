"""Integration tests: capture -> processing -> persistence -> SQLite (M7.21).

These tests drive real Scapy packets through the same callback path used in
production (fake sniffer -> PacketPipeline -> PacketProcessor -> PacketPersistence
-> SQLite) and assert that captured packets are normalized, buffered, flushed on
capture stop, and stored with the same values the processor produced — while the
M6 statistics engine and M8 device discovery keep working beside persistence.
"""

from __future__ import annotations

from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from sqlalchemy.orm import Session

from app.devices.manager import DeviceDiscoveryManager
from app.persistence.manager import PacketPersistence
from app.processing.processor import PacketProcessor
from app.repositories.packet import PacketRepository
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
IP_A = "192.168.1.10"
IP_B = "192.168.1.20"


def _traffic() -> list[Any]:
    """Return a short, harmless conversation between two local hosts."""
    return [
        Ether(src=MAC_A, dst=MAC_B)
        / IP(src=IP_A, dst=IP_B)
        / TCP(sport=52000, dport=443),
        Ether(src=MAC_A, dst=MAC_B)
        / IP(src=IP_A, dst=IP_B)
        / UDP(sport=53000, dport=53),
        Ether(src=MAC_B, dst=MAC_A) / IP(src=IP_B, dst=IP_A) / ICMP(),
    ]


def _count(session_factory) -> int:
    """Return how many packet rows are in the isolated database."""
    session: Session = session_factory()
    try:
        return PacketRepository(session).count()
    finally:
        session.close()


def _stored(session_factory) -> list:
    """Return the stored packets, newest first."""
    session: Session = session_factory()
    try:
        return PacketRepository(session).list(limit=100)
    finally:
        session.close()


def _wire(
    registry: list[FakeCaptureSniffer],
    session_factory,
    *,
    persistence: PacketPersistence | None = None,
) -> tuple[CaptureManager, TrafficStatisticsManager, DeviceDiscoveryManager]:
    """Build a CaptureManager wired to the full M5/M6/M7/M8 pipeline."""
    interface_manager = make_interface_manager()
    interface_manager.select_interface("Wi-Fi")
    statistics = TrafficStatisticsManager()
    devices = DeviceDiscoveryManager()
    layer = persistence or PacketPersistence(
        session_factory=session_factory,
        autostart=False,
        batch_size=100,
        flush_interval=60.0,
    )
    pipeline = PacketPipeline(
        processor=PacketProcessor(),
        statistics=statistics,
        devices=devices,
        persistence=layer,
    )
    manager = CaptureManager(
        interface_manager=interface_manager,
        sniffer_factory=make_sniffer_factory(registry=registry),
        pipeline=pipeline,
    )
    return manager, statistics, devices


# ---------------------------------------------------------------------------
# End-to-end persistence
# ---------------------------------------------------------------------------


def test_capture_stop_flushes_packets_to_the_database(session_factory) -> None:
    """Packets captured through the pipeline land in SQLite on stop (M7.18)."""
    registry: list[FakeCaptureSniffer] = []
    manager, _, _ = _wire(registry, session_factory)
    persistence = manager.get_pipeline().persistence
    assert persistence is not None

    manager.start()
    for packet in _traffic():
        registry[0].emit_packet(packet)
    assert manager.is_running() is True

    # Nothing is written until capture stops and flushes (autostart disabled).
    assert _count(session_factory) == 0
    assert persistence.get_enqueued_count() == len(_traffic())

    manager.stop()

    assert _count(session_factory) == len(_traffic())
    assert persistence.get_persisted_count() == len(_traffic())
    assert persistence.get_queue_depth() == 0


def test_stored_values_match_the_normalized_packets(session_factory) -> None:
    """Stored rows carry the same endpoint, port and protocol values as M5."""
    registry: list[FakeCaptureSniffer] = []
    manager, _, _ = _wire(registry, session_factory)

    manager.start()
    for packet in _traffic():
        registry[0].emit_packet(packet)
    manager.stop()

    expected = PacketProcessor().process(
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=52000, dport=443)
    )
    stored = _stored(session_factory)
    tcp_rows = [row for row in stored if row.protocol == "TCP"]

    assert len(tcp_rows) == 1
    row = tcp_rows[0]
    assert row.source_ip == IP_A
    assert row.destination_ip == IP_B
    assert row.source_port == 52000
    assert row.destination_port == 443
    assert row.packet_length == expected.length
    # Payload is never stored (M7.5).
    assert row.payload_length is None


def test_every_packet_type_is_persisted(session_factory) -> None:
    """TCP, UDP and ICMP packets are all stored with their labels."""
    registry: list[FakeCaptureSniffer] = []
    manager, _, _ = _wire(registry, session_factory)

    manager.start()
    for packet in _traffic():
        registry[0].emit_packet(packet)
    manager.stop()

    protocols = sorted(row.protocol for row in _stored(session_factory))

    assert protocols == ["ICMP", "TCP", "UDP"]


def test_capture_and_statistics_and_devices_keep_working(session_factory) -> None:
    """Persistence runs beside M6 statistics and M8 discovery (M7.17)."""
    registry: list[FakeCaptureSniffer] = []
    manager, statistics, devices = _wire(registry, session_factory)

    manager.start()
    for packet in _traffic():
        registry[0].emit_packet(packet)

    snapshot = statistics.get_statistics()

    assert snapshot.total_packets == len(_traffic())
    assert manager.get_processed_packet_count() == len(_traffic())
    assert manager.get_processing_error_count() == 0
    assert manager.get_statistics_error_count() == 0
    assert manager.get_device_error_count() == 0
    assert manager.get_pipeline().get_persistence_error_count() == 0
    assert devices.get_device_count() == 2
    manager.stop()


# ---------------------------------------------------------------------------
# Error isolation (M7.11/M7.17)
# ---------------------------------------------------------------------------


class _RaisingPersistence(PacketPersistence):
    """Persistence layer whose ``record_packet`` always fails."""

    def record_packet(self, packet) -> bool:  # type: ignore[override]
        raise RuntimeError("simulated persistence failure")


def test_persistence_failure_does_not_stop_capture(session_factory) -> None:
    """A failing persistence layer never terminates capture or statistics."""
    registry: list[FakeCaptureSniffer] = []
    failing = _RaisingPersistence(session_factory=session_factory, autostart=False)
    manager, statistics, _ = _wire(registry, session_factory, persistence=failing)

    manager.start()
    for packet in _traffic():
        registry[0].emit_packet(packet)

    assert manager.is_running() is True
    assert manager.get_processed_packet_count() == len(_traffic())
    assert manager.get_pipeline().get_persistence_error_count() == len(_traffic())
    assert statistics.get_statistics().total_packets == len(_traffic())
    manager.stop()


def test_malformed_packet_does_not_break_persistence(session_factory) -> None:
    """A packet the processor rejects is isolated; later traffic still persists."""
    registry: list[FakeCaptureSniffer] = []
    manager, _, _ = _wire(registry, session_factory)

    manager.start()
    registry[0].emit_packet(None)
    for packet in _traffic():
        registry[0].emit_packet(packet)
    manager.stop()

    assert manager.get_processing_error_count() == 1
    assert _count(session_factory) == len(_traffic())


# ---------------------------------------------------------------------------
# Payload policy (M7.5)
# ---------------------------------------------------------------------------


def test_no_payload_is_stored_by_default(session_factory) -> None:
    """Every stored row leaves the payload column empty (M7.5)."""
    registry: list[FakeCaptureSniffer] = []
    manager, _, _ = _wire(registry, session_factory)

    manager.start()
    for packet in _traffic():
        registry[0].emit_packet(packet)
    manager.stop()

    assert all(row.payload_length is None for row in _stored(session_factory))
