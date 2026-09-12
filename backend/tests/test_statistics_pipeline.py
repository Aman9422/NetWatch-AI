"""Integration tests: CaptureManager -> PacketProcessor -> statistics (M6.15/M6.20).

These tests drive real Scapy packets through the same callback path used in
production (fake sniffer -> PacketPipeline -> PacketProcessor ->
TrafficStatisticsManager) and assert that the aggregated statistics move in
step with the observed traffic.
"""

from __future__ import annotations

from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from app.processing.processor import PacketProcessor
from app.services.capture_manager import CaptureManager
from app.services.packet_pipeline import PacketPipeline
from app.statistics.manager import TrafficStatisticsManager
from tests.fakes import FakeCaptureSniffer, make_interface_manager, make_sniffer_factory


def _make_manager(
    registry: list[FakeCaptureSniffer],
    statistics: TrafficStatisticsManager,
) -> CaptureManager:
    """Return a CaptureManager wired to fake sniffers and a real M5/M6 pipeline."""
    interface_manager = make_interface_manager()
    interface_manager.select_interface("Wi-Fi")
    pipeline = PacketPipeline(
        processor=PacketProcessor(),
        statistics=statistics,
    )
    return CaptureManager(
        interface_manager=interface_manager,
        sniffer_factory=make_sniffer_factory(registry=registry),
        pipeline=pipeline,
    )


def _traffic() -> list[Any]:
    """Return a mixed batch of harmless, synthetic local-network packets."""
    return [
        Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=52000, dport=443),
        Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=52001, dport=443),
        Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / UDP(sport=53000, dport=53),
        Ether()
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=51000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")),
        Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / ICMP(),
        Ether(src="aa:bb:cc:dd:ee:ff") / ARP(),
    ]


def test_capture_pipeline_updates_statistics() -> None:
    """Every emitted packet is normalized and reflected in the statistics."""
    registry: list[FakeCaptureSniffer] = []
    statistics = TrafficStatisticsManager()
    manager = _make_manager(registry, statistics)
    manager.start()

    packets = _traffic()
    for packet in packets:
        registry[0].emit_packet(packet)

    snapshot = statistics.get_statistics()

    assert snapshot.total_packets == len(packets)
    assert snapshot.total_bytes == sum(len(packet) for packet in packets)
    assert manager.get_processed_packet_count() == len(packets)


def test_protocol_counters_change_with_traffic() -> None:
    """The protocol distribution reflects the mix of captured protocols."""
    registry: list[FakeCaptureSniffer] = []
    statistics = TrafficStatisticsManager()
    manager = _make_manager(registry, statistics)
    manager.start()

    for packet in _traffic():
        registry[0].emit_packet(packet)

    counts = {stat.protocol: stat.packets for stat in statistics.get_protocol_statistics()}

    assert counts["TCP"] == 2
    assert counts["UDP"] == 1
    assert counts["DNS"] == 1
    assert counts["ICMP"] == 1
    assert counts["ARP"] == 1


def test_top_talkers_update_with_traffic() -> None:
    """The busiest source and destination reflect the captured traffic."""
    registry: list[FakeCaptureSniffer] = []
    statistics = TrafficStatisticsManager()
    manager = _make_manager(registry, statistics)
    manager.start()

    for packet in _traffic():
        registry[0].emit_packet(packet)

    snapshot = statistics.get_statistics()

    assert snapshot.top_sources[0].key == "192.168.1.10"
    assert snapshot.top_destinations[0].key == "8.8.8.8"


def test_port_counters_follow_captured_ports() -> None:
    """Destination ports are aggregated from the captured packets."""
    registry: list[FakeCaptureSniffer] = []
    statistics = TrafficStatisticsManager()
    manager = _make_manager(registry, statistics)
    manager.start()

    for packet in _traffic():
        registry[0].emit_packet(packet)

    ports = {entry.key for entry in statistics.get_top_ports(direction="destination")}

    assert {"443", "53"} <= ports


class _RaisingStatisticsManager(TrafficStatisticsManager):
    """Statistics manager whose ``record_packet`` always fails (M6.15)."""

    def record_packet(self, packet: Any) -> None:  # type: ignore[override]
        raise RuntimeError("simulated statistics failure")


def test_statistics_failure_does_not_stop_capture() -> None:
    """A failing statistics update never terminates packet capture (M6.15)."""
    registry: list[FakeCaptureSniffer] = []
    failing = _RaisingStatisticsManager()
    manager = _make_manager(registry, failing)
    manager.start()

    sniffer = registry[0]
    for packet in _traffic():
        sniffer.emit_packet(packet)

    assert manager.is_running() is True
    assert manager.get_processed_packet_count() == len(_traffic())
    assert manager.get_statistics_error_count() == len(_traffic())
