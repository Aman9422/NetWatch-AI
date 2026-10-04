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
    """Payload of the packet-collection endpoint (M13.8/M13.24).

    The page window is echoed beside ``count`` and ``total`` so a client can
    build the next request without remembering what it asked for (M13.24). That
    matters most here: the stored packet table is the largest collection in the
    application, so a client unable to see the window it received could only ever
    read the newest page.
    """

    count: int = Field(default=0, description="Packets returned in this page")
    total: int = Field(default=0, description="Packets matching the filters")
    limit: int | None = Field(
        default=None, description="Maximum packets the page was allowed to hold"
    )
    offset: int = Field(default=0, description="Packets skipped before this page")
    has_more: bool | None = Field(
        default=None, description="Whether a further page may hold more packets"
    )
    packets: list[PacketView] = Field(default_factory=list)
