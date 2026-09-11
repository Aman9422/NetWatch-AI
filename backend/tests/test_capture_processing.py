"""Integration tests: CaptureManager -> sniffer -> PacketProcessor (M5.17)."""

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from app.processing.processor import PacketProcessor
from app.schemas.packet import NormalizedPacket, PacketType
from app.services.capture_manager import CaptureManager
from tests.fakes import (
    FakeCaptureSniffer,
    make_interface_manager,
    make_sniffer_factory,
)


def _make_manager(
    registry: list[FakeCaptureSniffer],
    processor: PacketProcessor | None = None,
) -> CaptureManager:
    """Return a CaptureManager wired to fake sniffers and a real processor."""
    interface_manager = make_interface_manager()
    interface_manager.select_interface("Wi-Fi")
    return CaptureManager(
        interface_manager=interface_manager,
        sniffer_factory=make_sniffer_factory(registry=registry),
        packet_processor=processor or PacketProcessor(),
    )


def test_captured_packets_reach_the_processor() -> None:
    """Captured Scapy packets are normalized by the shared processor."""
    registry: list[FakeCaptureSniffer] = []
    manager = _make_manager(registry)
    manager.start()

    sniffer = registry[0]
    sniffer.emit_packet(Ether() / IP(src="192.168.1.10") / TCP(sport=1234, dport=443))
    sniffer.emit_packet(Ether() / IP(src="192.168.1.11") / TCP(sport=4321, dport=80))

    assert manager.get_processed_packet_count() == 2
    assert manager.get_processing_error_count() == 0


def test_processor_receives_selected_interface() -> None:
    """The processor is told which interface is being captured."""
    registry: list[FakeCaptureSniffer] = []
    manager = _make_manager(registry)
    manager.start()

    packet = manager.get_packet_processor().process(Ether() / IP() / TCP())

    assert packet.interface == "Wi-Fi"


def test_processing_error_is_isolated() -> None:
    """A malformed packet is counted as an error but does not stop capture."""
    registry: list[FakeCaptureSniffer] = []
    manager = _make_manager(registry)
    manager.start()

    sniffer = registry[0]
    sniffer.emit_packet(Ether() / IP() / TCP())  # ok
    sniffer.emit_packet(None)                    # fails (empty packet)
    sniffer.emit_packet(Ether() / IP() / TCP())  # ok

    assert sniffer.get_packet_count() == 3
    assert manager.get_processed_packet_count() == 2
    assert manager.get_processing_error_count() == 1
    assert manager.is_running() is True


def test_processed_packets_are_normalized_objects() -> None:
    """The processor returns NormalizedPacket objects with real field values."""
    registry: list[FakeCaptureSniffer] = []
    captured: list[NormalizedPacket] = []

    class RecordingProcessor(PacketProcessor):
        """PacketProcessor that records the normalized output for assertions."""

        def process(self, packet, captured_at=None):  # type: ignore[override]
            normalized = super().process(packet, captured_at)
            captured.append(normalized)
            return normalized

    manager = _make_manager(registry, processor=RecordingProcessor())
    manager.start()
    registry[0].emit_packet(
        Ether(src="aa:bb:cc:dd:ee:ff")
        / IP(src="192.168.1.10", dst="142.250.0.1")
        / TCP(sport=52341, dport=443, flags="S")
    )

    assert len(captured) == 1
    packet = captured[0]
    assert isinstance(packet, NormalizedPacket)
    assert packet.source_ip == "192.168.1.10"
    assert packet.destination_ip == "142.250.0.1"
    assert packet.source_port == 52341
    assert packet.destination_port == 443
    assert packet.packet_type == PacketType.TCP
    assert packet.source_mac == "AA:BB:CC:DD:EE:FF"
