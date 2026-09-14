"""Device identity rules for NetWatch AI (M8.2/M8.7/M8.8).

This module is the single source of truth for *how a device is identified*:

* canonical MAC normalization,
* IP validation and canonicalization (IPv4 and IPv6),
* the ``device_id`` derivation used as the registry key,
* deciding whether an observed endpoint can belong to a trackable device.

It holds no state and performs no I/O, so every rule here is unit-testable in
isolation.
"""

import ipaddress
import re

from app.schemas.interface import normalize_mac

# A canonical MAC, matching what ``app.schemas.interface.normalize_mac`` yields.
_CANONICAL_MAC = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")

# MACs that never identify a single trackable device.
_BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"
_ZERO_MAC = "00:00:00:00:00:00"

# The classic IPv4 broadcast address.
_IPV4_BROADCAST = "255.255.255.255"

# ``device_id`` namespaces, so an id is self-describing.
_MAC_PREFIX = "mac:"
_IP_PREFIX = "ip:"


def normalize_mac_address(value: str | None) -> str | None:
    """Return a canonical ``AA:BB:CC:DD:EE:FF`` MAC, or ``None`` if unusable.

    ``None`` means "no usable MAC was observed" — the caller must then fall
    back to an IP-based identity rather than inventing a value.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    candidate = normalize_mac(text)
    if _CANONICAL_MAC.fullmatch(candidate):
        return candidate
    return None


def normalize_ip_address(value: str | None) -> str | None:
    """Return a canonical IPv4/IPv6 address, or ``None`` if invalid.

    IPv6 is compressed to its canonical short form (``2001:0db8::1`` →
    ``2001:db8::1``) so one host never appears under two spellings.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def is_broadcast_mac(mac: str) -> bool:
    """Return True for the Ethernet broadcast address."""
    return mac == _BROADCAST_MAC


def is_multicast_mac(mac: str) -> bool:
    """Return True if the MAC's group bit (LSB of the first octet) is set."""
    first_octet = int(mac.split(":", 1)[0], 16)
    return bool(first_octet & 0x01)


def is_unicast_mac(mac: str) -> bool:
    """Return True if ``mac`` can identify one real interface.

    Broadcast, multicast and all-zero MACs cannot, so they are rejected.
    """
    if mac in (_BROADCAST_MAC, _ZERO_MAC):
        return False
    return not is_multicast_mac(mac)


def is_trackable_ip(ip: str) -> bool:
    """Return True if ``ip`` can belong to one trackable device.

    Multicast, unspecified and broadcast addresses address groups or nothing,
    not a single host, so they are excluded.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if address.is_multicast or address.is_unspecified:
        return False
    if isinstance(address, ipaddress.IPv4Address) and str(address) == _IPV4_BROADCAST:
        return False
    return True


def is_trackable_endpoint(mac: str | None, ip: str | None) -> bool:
    """Decide whether an observed ``(mac, ip)`` pair is one real device.

    The MAC is the stronger signal: if a usable MAC is present it decides, and
    a broadcast/multicast MAC excludes the endpoint even when an IP is present.
    Without a MAC, a usable IP is enough.
    """
    normalized_mac = normalize_mac_address(mac)
    if normalized_mac is not None:
        return is_unicast_mac(normalized_mac)
    normalized_ip = normalize_ip_address(ip)
    if normalized_ip is None:
        return False
    return is_trackable_ip(normalized_ip)


def device_id_for(
    normalized_mac: str | None, normalized_ip: str | None
) -> str | None:
    """Build a ``device_id`` from already-normalized identifiers.

    MAC wins because it follows the hardware across IP changes; an IP is only a
    fallback identity for endpoints observed without a MAC. Returns ``None``
    when neither identifier is usable.
    """
    if normalized_mac is not None:
        return f"{_MAC_PREFIX}{normalized_mac}"
    if normalized_ip is not None:
        return f"{_IP_PREFIX}{normalized_ip}"
    return None


def derive_device_id(mac: str | None, ip: str | None) -> str | None:
    """Normalize raw identifiers and derive the device identity."""
    return device_id_for(normalize_mac_address(mac), normalize_ip_address(ip))


def device_id_kind(device_id: str) -> str | None:
    """Return ``"mac"``, ``"ip"`` or ``None`` for a well-formed device id."""
    if device_id.startswith(_MAC_PREFIX):
        return "mac"
    if device_id.startswith(_IP_PREFIX):
        return "ip"
    return None
