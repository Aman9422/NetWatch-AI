"""Normalized packet schema for NetWatch AI (M5).

This module defines the internal, Scapy-independent representation of a
captured packet. Everything downstream (statistics, detection, ML) should
depend on :class:`NormalizedPacket` rather than on Scapy layer objects.
"""

from enum import Enum

from pydantic import BaseModel, Field, field_validator

from app.schemas.interface import normalize_mac

# Valid values for the IP version field.
_VALID_IP_VERSIONS = (4, 6)

# Maximum length of the TCP-flag string we store.
_MAX_TCP_FLAGS_LENGTH = 20


class PacketType(str, Enum):
    """Deterministic classification of a captured packet.

    This is a *traffic classification*, not a threat verdict. It simply
    describes what kind of packet was observed.
    """

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    DNS = "DNS"
    ARP = "ARP"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    OTHER = "OTHER"


class NormalizedPacket(BaseModel):
    """A protocol-neutral view of a captured packet.

    Fields that do not apply to a given packet are left as ``None``; values are
    never invented. For example, an ARP packet has ``protocol="ARP"`` but
    ``source_port=None``.
    """

    packet_id: int | None = Field(
        default=None, description="Session-scoped sequential identifier"
    )
    timestamp: float = Field(ge=0, description="Capture time, epoch seconds")
    interface: str | None = Field(default=None, description="Capture interface")
    length: int = Field(ge=0, description="Captured frame length in bytes")
    source_mac: str | None = None
    destination_mac: str | None = None
    ip_version: int | None = Field(default=None, description="4, 6, or None")
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str = Field(default="OTHER", description="Transport protocol label")
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    tcp_flags: str | None = Field(default=None, max_length=_MAX_TCP_FLAGS_LENGTH)
    packet_type: PacketType = PacketType.OTHER

    @field_validator("source_mac", "destination_mac")
    @classmethod
    def _normalize_mac(cls, value: str | None) -> str | None:
        """Normalize MACs so the application always sees one canonical format."""
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        return normalize_mac(value)

    @field_validator("ip_version")
    @classmethod
    def _validate_ip_version(cls, value: int | None) -> int | None:
        """Reject any IP version other than 4 or 6."""
        if value is not None and value not in _VALID_IP_VERSIONS:
            raise ValueError("ip_version must be 4, 6, or None")
        return value
