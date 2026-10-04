"""Read-only wire schemas for tracked connections (M9).

These models describe how a network conversation is exposed over the API. The
runtime representation used by the tracker is
``app.connections.connection.Connection`` (a plain, lock-protected record);
these schemas are its serializable projection.

This is *not* a security model: a connection is an observed conversation, never
a threat verdict, so no risk, severity or confidence field exists here.
"""

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


def to_iso_timestamp(timestamp: float | None) -> str | None:
    """Render epoch seconds as an ISO-8601 UTC string, or ``None``.

    Connections are timed in epoch seconds (like packets), while the API speaks
    ISO-8601 (like devices). This is the single conversion rule for M9.
    """
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


class ConnectionState(str, Enum):
    """Observed state of a network conversation (M9.10/M9.11).

    The first four values describe a TCP conversation, ``active``/``inactive``
    describe a connectionless one (UDP, ICMP), and ``unknown`` covers a record
    that carries no observation.

    This is a *protocol* state derived only from observed traffic. It is not a
    security or risk verdict.
    """

    OBSERVED = "observed"
    ESTABLISHED = "established"
    CLOSING = "closing"
    CLOSED = "closed"
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"


class ConnectionView(BaseModel):
    """Serializable snapshot of one tracked connection (M9.6/M9.21)."""

    connection_id: str = Field(
        description="Deterministic id, e.g. 'TCP|10.0.0.1:52134|1.1.1.1:443'"
    )
    protocol: str = Field(description="TCP, UDP or ICMP")
    source_ip: str
    source_port: int | None = Field(
        default=None, description="None for ICMP or when no port was observed"
    )
    destination_ip: str
    destination_port: int | None = Field(
        default=None, description="None for ICMP or when no port was observed"
    )
    ip_version: int | None = Field(
        default=None, description="4, 6, or None when not observed"
    )
    first_seen: str | None = Field(default=None, description="ISO-8601 UTC")
    last_seen: str | None = Field(default=None, description="ISO-8601 UTC")
    packet_count: int = Field(default=0, description="Total packets, both directions")
    byte_count: int = Field(default=0, description="Total bytes, both directions")
    source_packet_count: int = Field(
        default=0, description="Packets in the recorded source direction"
    )
    source_byte_count: int = Field(default=0)
    destination_packet_count: int = Field(
        default=0, description="Packets in the reverse direction"
    )
    destination_byte_count: int = Field(default=0)
    state: ConnectionState = Field(default=ConnectionState.UNKNOWN)
    source_device_id: str | None = Field(
        default=None, description="M8 device identity, when the address is known"
    )
    destination_device_id: str | None = Field(default=None)
    active: bool = Field(
        default=True, description="True while the conversation is still tracked"
    )


class ConnectionListData(BaseModel):
    """Payload of the connection-collection endpoint (M13.11/M13.24).

    ``count`` is the size of this page. The tracker cannot count a *filtered*
    match set without materialising it, so ``total`` is omitted rather than
    guessed at; ``has_more`` reports whether the page was full.
    """

    count: int = 0
    limit: int | None = Field(
        default=None, description="Maximum items the page was allowed to hold"
    )
    offset: int = Field(default=0, description="Items skipped before this page")
    total: int | None = Field(
        default=None, description="Items matching overall, when countable"
    )
    has_more: bool | None = Field(
        default=None, description="Whether a further page may hold more items"
    )
    connections: list[ConnectionView] = Field(default_factory=list)
