"""Test doubles shared by the backend test-suite."""

from collections.abc import Callable

from app.services.interface_manager import InterfaceManager

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
        fail_on_start: If True, ``start()`` raises a RuntimeError.
        fail_on_stop: If True, ``stop()`` raises a RuntimeError.
    """

    def __init__(
        self,
        interface: str,
        fail_on_start: bool = False,
        fail_on_stop: bool = False,
    ) -> None:
        self.interface = interface
        self.fail_on_start = fail_on_start
        self.fail_on_stop = fail_on_stop
        self.running = False
        self.stopped = False
        self.packet_count = 0

    # -- used by tests ----------------------------------------------------

    def emit(self, count: int) -> None:
        """Simulate ``count`` packets arriving."""
        self.packet_count += count

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


def make_sniffer_factory(
    fail_on_start: bool = False,
    fail_on_stop: bool = False,
    registry: list[FakeCaptureSniffer] | None = None,
) -> Callable[[str], FakeCaptureSniffer]:
    """Return a sniffer factory producing (and optionally recording) fakes."""

    def factory(interface: str) -> FakeCaptureSniffer:
        sniffer = FakeCaptureSniffer(
            interface,
            fail_on_start=fail_on_start,
            fail_on_stop=fail_on_stop,
        )
        if registry is not None:
            registry.append(sniffer)
        return sniffer

    return factory
