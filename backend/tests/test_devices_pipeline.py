"""Integration tests: CaptureManager -> PacketProcessor -> devices (M8.22).

These tests drive real Scapy packets through the same callback path used in
production (fake sniffer -> PacketPipeline -> PacketProcessor ->
DeviceDiscoveryManager) and assert that devices are discovered and their
addresses, counters and timestamps track the observed traffic — while the M6
statistics engine keeps working alongside.
"""

from __future__ import annotations

from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether

from app.devices.manager import DeviceDiscoveryManager
from app.processing.processor import PacketProcessor
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


def _make_manager(
    registry: list[FakeCaptureSniffer],
    statistics: TrafficStatisticsManager,
    devices: DeviceDiscoveryManager,
) -> CaptureManager:
    """Return a CaptureManager wired to fake sniffers and the real M5/M6/M8 pipeline."""
    interface_manager = make_interface_manager()
    interface_manager.select_interface("Wi-Fi")
    pipeline = PacketPipeline(
        processor=PacketProcessor(),
        statistics=statistics,
        devices=devices,
    )
    return CaptureManager(
        interface_manager=interface_manager,
        sniffer_factory=make_sniffer_factory(registry=registry),
        pipeline=pipeline,
    )


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


def _run_pipeline(
    registry: list[FakeCaptureSniffer],
    statistics: TrafficStatisticsManager,
    devices: DeviceDiscoveryManager,
) -> CaptureManager:
    """Start capture and push the sample conversation through the pipeline."""
    manager = _make_manager(registry, statistics, devices)
    manager.start()
    for packet in _traffic():
        registry[0].emit_packet(packet)
    return manager


def test_pipeline_discovers_both_hosts() -> None:
    """Both MACs seen on the wire become tracked devices."""
    registry: list[FakeCaptureSniffer] = []
    statistics = TrafficStatisticsManager()
    devices = DeviceDiscoveryManager()
    _run_pipeline(registry, statistics, devices)

    assert devices.get_device_count() == 2
    assert devices.get_device(f"mac:{MAC_A}") is not None
    assert devices.get_device(f"mac:{MAC_B}") is not None
    assert devices.get_error_count() == 0


def test_pipeline_attributes_addresses_and_counters() -> None:
    """Observed IPs, packet counts and byte counts match the traffic (M8.5)."""
    registry: list[FakeCaptureSniffer] = []
    statistics = TrafficStatisticsManager()
    devices = DeviceDiscoveryManager()
    packets = _traffic()
    _run_pipeline(registry, statistics, devices)

    total_bytes = sum(len(packet) for packet in packets)
    device_a = devices.get_device(f"mac:{MAC_A}")
    device_b = devices.get_device(f"mac:{MAC_B}")
    assert device_a is not None and device_b is not None

    assert device_a.ip_addresses == {IP_A}
    assert device_b.ip_addresses == {IP_B}
    assert device_a.packet_count == len(packets)
    assert device_b.packet_count == len(packets)
    assert device_a.byte_count == total_bytes
    assert device_b.byte_count == total_bytes
    assert device_a.packets_sent == 2
    assert device_a.packets_received == 1
    assert device_b.packets_sent == 1
    assert device_b.packets_received == 2


def test_pipeline_records_first_and_last_seen() -> None:
    """Every discovered device carries timing information (M8.4)."""
    registry: list[FakeCaptureSniffer] = []
    statistics = TrafficStatisticsManager()
    devices = DeviceDiscoveryManager()
    _run_pipeline(registry, statistics, devices)

    for device_id in (f"mac:{MAC_A}", f"mac:{MAC_B}"):
        device = devices.get_device(device_id)
        assert device is not None
        assert device.first_seen is not None
        assert device.last_seen is not None
        assert device.last_seen >= device.first_seen


def test_pipeline_keeps_statistics_and_devices_in_step() -> None:
    """The M6 statistics engine keeps working beside device discovery (M8.17)."""
    registry: list[FakeCaptureSniffer] = []
    statistics = TrafficStatisticsManager()
    devices = DeviceDiscoveryManager()
    packets = _traffic()
    manager = _run_pipeline(registry, statistics, devices)

    snapshot = statistics.get_statistics()

    assert snapshot.total_packets == len(packets)
    assert manager.get_processed_packet_count() == len(packets)
    assert manager.get_processing_error_count() == 0
    assert manager.get_statistics_error_count() == 0
    assert manager.get_device_error_count() == 0


class _RaisingDeviceManager(DeviceDiscoveryManager):
    """Device manager whose ``process_packet`` always fails (M8.17)."""

    def process_packet(self, packet: Any) -> None:  # type: ignore[override]
        raise RuntimeError("simulated device discovery failure")


def test_device_discovery_failure_does_not_stop_capture() -> None:
    """A failing device update never terminates capture or statistics (M8.17)."""
    registry: list[FakeCaptureSniffer] = []
    statistics = TrafficStatisticsManager()
    failures = _RaisingDeviceManager()
    packets = _traffic()
    manager = _run_pipeline(registry, statistics, failures)

    assert manager.is_running() is True
    assert manager.get_processed_packet_count() == len(packets)
    assert manager.get_device_error_count() == len(packets)
    assert statistics.get_statistics().total_packets == len(packets)


def test_malformed_packet_does_not_break_discovery() -> None:
    """A packet the processor rejects is isolated and later traffic still lands."""
    registry: list[FakeCaptureSniffer] = []
    statistics = TrafficStatisticsManager()
    devices = DeviceDiscoveryManager()
    manager = _make_manager(registry, statistics, devices)
    manager.start()

    registry[0].emit_packet(None)
    for packet in _traffic():
        registry[0].emit_packet(packet)

    assert manager.get_processing_error_count() == 1
    assert devices.get_device_count() == 2
    assert manager.get_device_error_count() == 0
