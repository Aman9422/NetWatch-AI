"""Unit tests for device identity rules (M8.2/M8.7/M8.8).

These tests cover the pure, state-free rules that decide *how a device is
identified*: MAC canonicalization, IP validation, trackability, ``device_id``
derivation, and endpoint extraction from a normalized packet.
"""

from __future__ import annotations

import pytest

from app.devices.endpoints import ROLE_DESTINATION, ROLE_SOURCE, extract_endpoints
from app.devices.identity import (
    derive_device_id,
    device_id_for,
    device_id_kind,
    is_broadcast_mac,
    is_multicast_mac,
    is_trackable_endpoint,
    is_trackable_ip,
    is_unicast_mac,
    normalize_ip_address,
    normalize_mac_address,
)
from tests.fakes import make_normalized_packet

CANONICAL_MAC = "AA:BB:CC:DD:EE:FF"
# Unicast (even first octet); a multicast MAC can never identify one device.
OTHER_MAC = "22:33:44:55:66:77"


# -- MAC normalization (M8.7) --------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "AA:BB:CC:DD:EE:FF",
        "aa:bb:cc:dd:ee:ff",
        "AA-BB-CC-DD-EE-FF",
        "aa-bb-cc-dd-ee-ff",
        "aabb.ccdd.eeff",
        "aabbccddeeff",
    ],
)
def test_mac_spellings_collapse_to_one_canonical_form(raw: str) -> None:
    """Every common spelling of one NIC resolves to the same canonical MAC."""
    assert normalize_mac_address(raw) == CANONICAL_MAC


@pytest.mark.parametrize(
    "raw",
    [None, "", "   ", "not-a-mac", "AA:BB:CC:DD:EE", "GG:GG:GG:GG:GG:GG"],
)
def test_unusable_mac_values_normalize_to_none(raw: str | None) -> None:
    """An unusable MAC becomes ``None`` so identity falls back to the IP."""
    assert normalize_mac_address(raw) is None


def test_mac_normalization_is_idempotent() -> None:
    """Normalizing an already-canonical MAC (any case) changes nothing."""
    assert normalize_mac_address(CANONICAL_MAC) == CANONICAL_MAC
    assert normalize_mac_address(CANONICAL_MAC.lower()) == CANONICAL_MAC


def test_mac_classification_flags_group_addresses() -> None:
    """Broadcast, multicast and all-zero MACs cannot identify one interface."""
    assert is_broadcast_mac("FF:FF:FF:FF:FF:FF") is True
    assert is_unicast_mac("FF:FF:FF:FF:FF:FF") is False
    assert is_unicast_mac("00:00:00:00:00:00") is False
    assert is_multicast_mac("01:00:5E:00:00:01") is True
    assert is_unicast_mac("01:00:5E:00:00:01") is False
    assert is_multicast_mac(CANONICAL_MAC) is False
    assert is_unicast_mac(CANONICAL_MAC) is True


# -- IP normalization (M8.8) ---------------------------------------------


def test_ipv4_address_is_normalized() -> None:
    """Surrounding whitespace is stripped from an IPv4 address."""
    assert normalize_ip_address(" 192.168.1.10 ") == "192.168.1.10"


def test_ipv6_address_is_compressed() -> None:
    """IPv6 is folded to its canonical short form so one host has one spelling."""
    assert normalize_ip_address("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"


def test_ipv6_address_is_lowercased() -> None:
    """IPv6 is lowercased so two spellings never create two devices."""
    assert normalize_ip_address("FE80::1") == "fe80::1"


@pytest.mark.parametrize(
    "raw", [None, "", "   ", "not-an-ip", "999.1.1.1", "1.2.3.4.5"]
)
def test_invalid_ip_values_normalize_to_none(raw: str | None) -> None:
    """Invalid address text is discarded rather than guessed at."""
    assert normalize_ip_address(raw) is None


@pytest.mark.parametrize(
    "ip", ["192.168.1.10", "8.8.8.8", "fe80::1", "2001:db8::1"]
)
def test_unicast_addresses_are_trackable(ip: str) -> None:
    """Any concrete unicast address can identify a device."""
    assert is_trackable_ip(ip) is True


@pytest.mark.parametrize(
    "ip",
    ["224.0.0.1", "ff02::1", "0.0.0.0", "::", "255.255.255.255", "not-an-ip"],
)
def test_group_and_unspecified_addresses_are_not_trackable(ip: str) -> None:
    """Multicast, unspecified and broadcast addresses address no single host."""
    assert is_trackable_ip(ip) is False


# -- endpoint trackability -----------------------------------------------


def test_endpoint_with_a_unicast_mac_is_trackable() -> None:
    assert is_trackable_endpoint(CANONICAL_MAC, "192.168.1.10") is True


def test_endpoint_without_a_mac_falls_back_to_the_ip() -> None:
    assert is_trackable_endpoint(None, "192.168.1.10") is True


def test_broadcast_mac_rejects_the_endpoint_even_with_an_ip() -> None:
    """A broadcast MAC is stronger evidence than the IP beside it."""
    assert is_trackable_endpoint("FF:FF:FF:FF:FF:FF", "192.168.1.10") is False


def test_endpoint_with_no_identifier_is_rejected() -> None:
    assert is_trackable_endpoint(None, None) is False


def test_invalid_mac_lets_the_endpoint_fall_back_to_the_ip() -> None:
    assert is_trackable_endpoint("not-a-mac", "192.168.1.10") is True


def test_multicast_ip_is_rejected() -> None:
    assert is_trackable_endpoint(None, "224.0.0.1") is False


# -- device identity -----------------------------------------------------


def test_device_id_prefers_the_mac() -> None:
    """The MAC wins because it follows the hardware across IP changes."""
    assert device_id_for(CANONICAL_MAC, "192.168.1.10") == f"mac:{CANONICAL_MAC}"


def test_device_id_falls_back_to_the_ip() -> None:
    assert device_id_for(None, "192.168.1.10") == "ip:192.168.1.10"


def test_device_id_is_none_without_identifiers() -> None:
    assert device_id_for(None, None) is None


def test_derive_device_id_normalizes_raw_input() -> None:
    """Raw, messy identifiers are normalized before the id is built."""
    assert derive_device_id("aa-bb-cc-dd-ee-ff", None) == f"mac:{CANONICAL_MAC}"
    assert derive_device_id(None, " 2001:0DB8::5 ") == "ip:2001:db8::5"


def test_device_id_kind_reports_the_namespace() -> None:
    assert device_id_kind(f"mac:{CANONICAL_MAC}") == "mac"
    assert device_id_kind("ip:192.168.1.10") == "ip"
    assert device_id_kind("device-1") is None


# -- endpoint extraction (M8.5) ------------------------------------------


def test_both_sides_of_a_packet_become_endpoints() -> None:
    packet = make_normalized_packet(
        source_mac=CANONICAL_MAC,
        destination_mac=OTHER_MAC,
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
    )

    endpoints = extract_endpoints(packet)

    assert [endpoint.role for endpoint in endpoints] == [
        ROLE_SOURCE,
        ROLE_DESTINATION,
    ]
    assert endpoints[0].device_id == f"mac:{CANONICAL_MAC}"
    assert endpoints[0].is_source is True
    assert endpoints[0].is_destination is False
    assert endpoints[1].device_id == f"mac:{OTHER_MAC}"
    assert endpoints[1].is_destination is True


def test_ip_only_endpoints_use_ip_identity() -> None:
    packet = make_normalized_packet(
        source_mac=None,
        destination_mac=None,
        source_ip="192.168.1.10",
        destination_ip="8.8.8.8",
    )

    endpoints = extract_endpoints(packet)

    assert [endpoint.device_id for endpoint in endpoints] == [
        "ip:192.168.1.10",
        "ip:8.8.8.8",
    ]
    assert [endpoint.mac_address for endpoint in endpoints] == [None, None]


def test_broadcast_destination_is_not_an_endpoint() -> None:
    """A broadcast destination (DHCP/ARP) must never be created as a device."""
    packet = make_normalized_packet(
        source_mac=CANONICAL_MAC,
        destination_mac="FF:FF:FF:FF:FF:FF",
        source_ip="192.168.1.10",
        destination_ip="255.255.255.255",
    )

    endpoints = extract_endpoints(packet)

    assert [endpoint.role for endpoint in endpoints] == [ROLE_SOURCE]
    assert endpoints[0].ip_address == "192.168.1.10"


def test_packet_without_identifiers_has_no_endpoints() -> None:
    packet = make_normalized_packet(
        source_mac=None,
        destination_mac=None,
        source_ip=None,
        destination_ip=None,
    )

    assert extract_endpoints(packet) == []


def test_ipv6_endpoints_are_canonicalized() -> None:
    packet = make_normalized_packet(
        source_mac=None,
        destination_mac=None,
        source_ip="fe80::1",
        destination_ip="2001:0DB8::5",
    )

    endpoints = extract_endpoints(packet)

    assert [endpoint.ip_address for endpoint in endpoints] == [
        "fe80::1",
        "2001:db8::5",
    ]
