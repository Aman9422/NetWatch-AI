"""Tests for interface discovery and the InterfaceManager service."""

import pytest

from app.schemas.interface import NetworkInterface
from app.services.interface_discovery import InterfaceDiscoveryError
from app.services.interface_manager import InterfaceManager, InterfaceValidationError


def _sample_interfaces() -> list[dict]:
    """Return a normalized list of sample interfaces for tests."""
    return [
        {
            "name": "Wi-Fi",
            "description": None,
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "ip_addresses": ["192.168.1.20", "fe80::1%12"],
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


def _make_manager(interfaces: list[dict] | None = None) -> InterfaceManager:
    """Return an InterfaceManager backed by a fixed list of interfaces."""
    data = interfaces if interfaces is not None else _sample_interfaces()
    return InterfaceManager(discovery=lambda: data)


# ---------------------------------------------------------------------------
# Schema / normalization
# ---------------------------------------------------------------------------


def test_network_interface_normalizes_mac_and_ips() -> None:
    """MAC is uppercased, whitespace is stripped, and duplicates are removed."""
    interface = NetworkInterface(
        name="Wi-Fi",
        mac_address="aa:bb:cc:dd:ee:ff",
        ip_addresses=[" 192.168.1.20 ", "fe80::1%12", "192.168.1.20"],
        is_up=True,
    )

    assert interface.mac_address == "AA:BB:CC:DD:EE:FF"
    assert interface.ip_addresses == ["192.168.1.20", "fe80::1%12"]
    assert interface.is_up is True


def test_network_interface_normalizes_dash_and_dot_mac() -> None:
    """MACs with dashes/dots (Windows, Cisco) become canonical colon form."""
    dashed = NetworkInterface(name="Wi-Fi", mac_address="CC-28-AA-72-AA-99", is_up=True)
    dotted = NetworkInterface(name="Wi-Fi", mac_address="cc28.aa72.aa99", is_up=True)

    assert dashed.mac_address == "CC:28:AA:72:AA:99"
    assert dotted.mac_address == "CC:28:AA:72:AA:99"


def test_network_interface_rejects_empty_name() -> None:
    """An interface without a name is invalid."""
    with pytest.raises(ValueError):
        NetworkInterface(name="   ")


def test_network_interface_handles_missing_info() -> None:
    """Missing MAC and IPs are represented as None and empty list."""
    interface = NetworkInterface(name="Ethernet", is_up=False)

    assert interface.mac_address is None
    assert interface.ip_addresses == []
    assert interface.is_up is False


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_list_interfaces_returns_normalized_objects() -> None:
    """The manager returns NetworkInterface objects from the discovery callable."""
    manager = _make_manager()
    interfaces = manager.list_interfaces()

    assert len(interfaces) == 2
    assert all(isinstance(i, NetworkInterface) for i in interfaces)
    assert interfaces[0].name == "Wi-Fi"
    assert interfaces[0].mac_address == "AA:BB:CC:DD:EE:FF"
    assert interfaces[1].is_up is False


def test_discovery_failure_propagates() -> None:
    """A discovery error is re-raised by the manager."""

    def broken_discovery() -> list[dict]:
        raise InterfaceDiscoveryError("boom")

    manager = InterfaceManager(discovery=broken_discovery)
    with pytest.raises(InterfaceDiscoveryError):
        manager.list_interfaces()


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


def test_valid_interface_can_be_selected() -> None:
    """A valid, available interface is selected."""
    manager = _make_manager()
    selected = manager.select_interface("Wi-Fi")

    assert selected.name == "Wi-Fi"
    active = manager.get_selected_interface()
    assert active is not None
    assert active.name == "Wi-Fi"


def test_selected_interface_can_be_retrieved() -> None:
    """get_selected_interface returns None before any selection."""
    manager = _make_manager()
    assert manager.get_selected_interface() is None

    manager.select_interface("Wi-Fi")
    active = manager.get_selected_interface()
    assert active is not None
    assert active.name == "Wi-Fi"


def test_invalid_interface_cannot_be_selected() -> None:
    """Selecting a non-existent interface raises a controlled error."""
    manager = _make_manager()
    with pytest.raises(InterfaceValidationError) as exc_info:
        manager.select_interface("Not-Real")

    assert exc_info.value.code == "INTERFACE_NOT_FOUND"
    assert manager.get_selected_interface() is None


def test_selection_changes_correctly() -> None:
    """Selecting a second interface replaces the first."""
    manager = _make_manager(
        [
            {"name": "Wi-Fi", "ip_addresses": [], "is_up": True},
            {"name": "Ethernet", "ip_addresses": ["10.0.0.5"], "is_up": True},
        ]
    )

    manager.select_interface("Wi-Fi")
    manager.select_interface("Ethernet")
    active = manager.get_selected_interface()
    assert active is not None
    assert active.name == "Ethernet"


def test_matching_interface_is_case_insensitive() -> None:
    """Interface lookup is not case sensitive."""
    manager = _make_manager()
    selected = manager.select_interface("wi-fi")
    assert selected.name == "Wi-Fi"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_existing_interface_is_validated() -> None:
    """An existing, available interface passes validation."""
    manager = _make_manager()
    interface = manager.validate_interface("Wi-Fi")
    assert interface.name == "Wi-Fi"


def test_empty_interface_is_rejected() -> None:
    """An empty name is rejected with a controlled error."""
    manager = _make_manager()
    with pytest.raises(InterfaceValidationError) as exc_info:
        manager.validate_interface("   ")

    assert exc_info.value.code == "EMPTY_INTERFACE_NAME"


def test_unavailable_interface_is_rejected() -> None:
    """A down interface is rejected with a controlled error."""
    manager = _make_manager()
    with pytest.raises(InterfaceValidationError) as exc_info:
        manager.validate_interface("Ethernet")

    assert exc_info.value.code == "INTERFACE_UNAVAILABLE"


def test_missing_interface_is_rejected() -> None:
    """A non-existent interface is rejected with a controlled error."""
    manager = _make_manager()
    with pytest.raises(InterfaceValidationError) as exc_info:
        manager.validate_interface("Missing")

    assert exc_info.value.code == "INTERFACE_NOT_FOUND"
