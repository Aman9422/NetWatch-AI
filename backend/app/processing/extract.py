"""Low-level protocol field extraction from raw Scapy packets (M5).

This module is the only place that reads Scapy layer objects. It converts a
raw packet into a flat :class:`ExtractedFields` value object that carries no
Scapy types, so the rest of the application never depends on Scapy internals.

Every field is optional: packets missing a layer simply leave that field as
``None``. Nothing is guessed or invented.
"""

import logging
import time
from dataclasses import dataclass
from typing import Any

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from app.processing.errors import PacketProcessingError
from app.processing.protocols import IP_VERSION_4, IP_VERSION_6

logger = logging.getLogger(__name__)


@dataclass
class ExtractedFields:
    """Flat, Scapy-free view of the values read from a raw packet."""

    timestamp: float
    length: int
    source_mac: str | None = None
    destination_mac: str | None = None
    ip_version: int | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol_number: int | None = None
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: str | None = None
    is_tcp: bool = False
    is_udp: bool = False
    is_icmp: bool = False
    is_arp: bool = False
    is_dns: bool = False


def extract_fields(packet: Any, captured_at: float | None = None) -> ExtractedFields:
    """Extract all supported fields from a raw Scapy packet.

    Args:
        packet: A raw Scapy ``Packet`` (or any object exposing ``haslayer``).
        captured_at: Optional capture time override (epoch seconds). When
            omitted the packet's own capture time is used.

    Returns:
        A populated :class:`ExtractedFields`. Missing layers leave ``None``.

    Raises:
        PacketProcessingError: If the packet is too malformed to inspect.
    """
    fields = ExtractedFields(
        timestamp=_resolve_timestamp(packet, captured_at),
        length=_resolve_length(packet),
    )
    _extract_ethernet(packet, fields)
    _extract_network(packet, fields)
    _extract_transport(packet, fields)
    fields.is_dns = _has_layer(packet, DNS)
    return fields


def _extract_ethernet(packet: Any, fields: ExtractedFields) -> None:
    """Extract Layer-2 MAC addresses when an Ethernet layer is present."""
    ether = _get_layer(packet, Ether)
    if ether is None:
        return
    fields.source_mac = _as_str(getattr(ether, "src", None))
    fields.destination_mac = _as_str(getattr(ether, "dst", None))


def _extract_network(packet: Any, fields: ExtractedFields) -> None:
    """Extract IPv4/IPv6/ARP information, preferring IPv4 then IPv6."""
    ipv4 = _get_layer(packet, IP)
    if ipv4 is not None:
        fields.ip_version = IP_VERSION_4
        fields.source_ip = _as_str(getattr(ipv4, "src", None))
        fields.destination_ip = _as_str(getattr(ipv4, "dst", None))
        fields.protocol_number = _as_int(getattr(ipv4, "proto", None))
        return

    ipv6 = _get_layer(packet, IPv6)
    if ipv6 is not None:
        fields.ip_version = IP_VERSION_6
        fields.source_ip = _as_str(getattr(ipv6, "src", None))
        fields.destination_ip = _as_str(getattr(ipv6, "dst", None))
        fields.protocol_number = _as_int(getattr(ipv6, "nh", None))
        return

    fields.is_arp = _has_layer(packet, ARP)


def _extract_transport(packet: Any, fields: ExtractedFields) -> None:
    """Extract TCP/UDP ports, TCP flags, and ICMP presence."""
    tcp = _get_layer(packet, TCP)
    if tcp is not None:
        fields.is_tcp = True
        fields.source_port = _as_int(getattr(tcp, "sport", None))
        fields.destination_port = _as_int(getattr(tcp, "dport", None))
        fields.tcp_flags = _tcp_flags_to_str(getattr(tcp, "flags", None))

    udp = _get_layer(packet, UDP)
    if udp is not None:
        fields.is_udp = True
        fields.source_port = _as_int(getattr(udp, "sport", None))
        fields.destination_port = _as_int(getattr(udp, "dport", None))

    fields.is_icmp = _has_layer(packet, ICMP)


# -- small, defensive helpers ---------------------------------------------


def _resolve_timestamp(packet: Any, captured_at: float | None) -> float:
    """Return the capture time, falling back to now when unavailable."""
    if captured_at is not None:
        return float(captured_at)
    packet_time = getattr(packet, "time", None)
    if packet_time is None:
        return time.time()
    try:
        return float(packet_time)
    except (TypeError, ValueError):
        return time.time()


def _resolve_length(packet: Any) -> int:
    """Return the captured frame length in bytes.

    Raises:
        PacketProcessingError: If the packet cannot even be measured. A packet
            whose length is unreadable is treated as malformed rather than
            silently recorded as a zero-length frame.
    """
    try:
        return max(int(len(packet)), 0)
    except Exception as exc:  # noqa: BLE001 - unreadable packet
        raise PacketProcessingError("Malformed packet: unreadable length") from exc


def _has_layer(packet: Any, layer: type) -> bool:
    """Return True if ``packet`` contains ``layer`` (never raises)."""
    try:
        return bool(packet.haslayer(layer))
    except Exception:  # noqa: BLE001 - malformed packets must not crash us
        return False


def _get_layer(packet: Any, layer: type) -> Any | None:
    """Return the layer instance, or None if absent/unreadable."""
    try:
        return packet.getlayer(layer)
    except Exception:  # noqa: BLE001 - malformed packets must not crash us
        return None


def _as_str(value: Any) -> str | None:
    """Coerce a value to a non-empty string, or None."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _as_int(value: Any) -> int | None:
    """Coerce a value to an int, or None when not numeric."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _tcp_flags_to_str(flags: Any) -> str | None:
    """Render Scapy TCP flags as their compact string form (e.g. ``PA``)."""
    if flags is None:
        return None
    text = str(flags).strip()
    return text or None
