"""Read-only wire schemas for stored packets (M7.16).

These models describe how a *persisted* packet is exposed over the internal
packet endpoint. They are the serializable projection of the M2 ``Packet`` row;
the query service builds them, so this module stays free of ORM imports.

The three exposed columns match exactly what M7 stores — timestamp, endpoints,
ports, protocol, length and TCP flags. No payload field exists, by design
(M7.5).
"""

from pydantic import BaseModel, Field


class PacketView(BaseModel):
    """Serializable snapshot of one stored packet."""

    id: int = Field(description="Primary key of the stored packet")
    timestamp: str = Field(description="Capture time, ISO-8601 UTC")
    source_ip: str
    destination_ip: str
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str = Field(description="TCP, UDP, ICMP, DNS, ARP, ...")
    packet_length: int = Field(description="Captured frame length in bytes")
    tcp_flags: str | None = None


class PacketListData(BaseModel):
    """Payload of the packet-collection endpoint."""

    count: int = Field(default=0, description="Packets returned in this page")
    total: int = Field(default=0, description="Packets matching the filters")
    packets: list[PacketView] = Field(default_factory=list)
