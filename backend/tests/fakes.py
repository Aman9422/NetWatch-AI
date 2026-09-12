"""Test doubles shared by the backend test-suite."""

from collections.abc import Callable
from typing import Any

from app.schemas.packet import NormalizedPacket, PacketType
from app.services.capture_sniffer import PacketSink
from app.services.interface_manager import InterfaceManager

# Fixed capture timestamp used by packet fixtures so time-window tests are
# deterministic.
PACKET_BASE_TIME = 1_700_000_000.0


def make_normalized_packet(**overrides: Any) -> NormalizedPacket:
    """Build a :class:`NormalizedPacket` with defaults suited to statistics tests.

    Any field can be overridden through keyword arguments, e.g.
    ``make_normalized_packet(source_ip="10.0.0.1", length=64)``.
    """
    values: dict[str, Any] = {
        "packet_id": 1,
        "timestamp": PACKET_BASE_TIME,
        "length": 100,
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "protocol": "TCP",
        "packet_type": PacketType.TCP,
        "source_port": 12345,
        "destination_port": 443,
    }
    values.update(overrides)
    return NormalizedPacket(**values)


# A minimal set of normalized interfaces used across tests.
SAMPLE_INTERFACES: list[dict] = [
    {
        "name": "Wi-Fi",
        "description": None,
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "ip_addresses": ["192.168.1.20"],
        "is_up": True,
    },
    {
        "name": "Ethernet",
        "description": None,
        "mac_address": None,
        "ip_addresses": [],
        "is_up": False,
    },
]


def make_interface_manager(interfaces: list[dict] | None = None) -> InterfaceManager:
    """Return an InterfaceManager backed by a fixed list of interfaces."""
    data = interfaces if interfaces is not None else SAMPLE_INTERFACES
    return InterfaceManager(discovery=lambda: data)


class FakeCaptureSniffer:
    """In-memory CaptureSniffer used to test the CaptureManager.

    Args:
        interface: The interface name the manager asked to capture on.
        packet_sink: Optional processor-like sink for captured packets (M5).
        fail_on_start: If True, ``start()`` raises a RuntimeError.
        fail_on_stop: If True, ``stop()`` raises a RuntimeError.
    """

    def __init__(
        self,
        interface: str,
        packet_sink: PacketSink | None = None,
        fail_on_start: bool = False,
        fail_on_stop: bool = False,
    ) -> None:
        self.interface = interface
        self.packet_sink = packet_sink
        self.fail_on_start = fail_on_start
        self.fail_on_stop = fail_on_stop
        self.running = False
        self.stopped = False
        self.packet_count = 0
        self.processed_count = 0
        self.processing_error_count = 0

    # -- used by tests ----------------------------------------------------

    def emit(self, count: int) -> None:
        """Simulate ``count`` packets arriving (counter only, no processing)."""
        self.packet_count += count

    def emit_packet(self, packet: Any) -> None:
        """Simulate a packet arriving through the full M5 callback path."""
        self.packet_count += 1
        if self.packet_sink is None:
            return
        try:
            self.packet_sink.process(packet)
        except Exception:  # noqa: BLE001 - mirrors the real sniffer's isolation
            self.processing_error_count += 1
            return
        self.processed_count += 1

    def die(self) -> None:
        """Simulate the capture worker terminating on its own."""
        self.running = False

    # -- CaptureSniffer protocol -----------------------------------------

    def start(self) -> None:
        if self.fail_on_start:
            raise RuntimeError("simulated start failure")
        self.running = True

    def stop(self) -> None:
        if self.fail_on_stop:
            raise RuntimeError("simulated stop failure")
        self.running = False
        self.stopped = True

    def is_running(self) -> bool:
        return self.running

    def get_packet_count(self) -> int:
        return self.packet_count

    def get_processed_count(self) -> int:
        return self.processed_count

    def get_processing_error_count(self) -> int:
        return self.processing_error_count


def make_sniffer_factory(
    fail_on_start: bool = False,
    fail_on_stop: bool = False,
    registry: list[FakeCaptureSniffer] | None = None,
) -> Callable[[str, PacketSink], FakeCaptureSniffer]:
    """Return a sniffer factory producing (and optionally recording) fakes."""

    def factory(interface: str, packet_sink: PacketSink) -> FakeCaptureSniffer:
        sniffer = FakeCaptureSniffer(
            interface,
            packet_sink=packet_sink,
            fail_on_start=fail_on_start,
            fail_on_stop=fail_on_stop,
        )
        if registry is not None:
            registry.append(sniffer)
        return sniffer

    return factory
