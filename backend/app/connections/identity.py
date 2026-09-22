"""Connection identity rules for NetWatch AI (M9.3/M9.5/M9.13).

This module is the single source of truth for *how a connection is identified*:

* which transport protocols are tracked and how they are recognized,
* the endpoint (address + port) rules,
* the directional 5-tuple (``Flow``),
* the canonical, bidirectional key (``ConnectionKey``) that makes the two
  directions of one conversation resolve to the same connection,
* the deterministic ``connection_id`` text,
* the direction of an observed packet relative to a connection's orientation.

It holds no state and performs no I/O, so every rule here is unit-testable in
isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple

from app.devices.identity import normalize_ip_address
from app.schemas.packet import NormalizedPacket, PacketType

# Transport protocols M9 tracks. Anything else is not a conversation.
PROTOCOL_TCP = "TCP"
PROTOCOL_UDP = "UDP"
PROTOCOL_ICMP = "ICMP"

TRACKED_PROTOCOLS = (PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP)

# Protocols that have no ports at all.
PORTLESS_PROTOCOLS = frozenset({PROTOCOL_ICMP})

# Highest usable port number (parsed defensively, not assumed).
_MAX_PORT = 65535

# Sort value given to a missing port so it orders before port 0.
_MISSING_PORT_SORT_VALUE = -1

# Transport labels read from ``NormalizedPacket.protocol``. The string is
# upper-cased before lookup, so any casing matches.
_TRANSPORT_BY_LABEL: dict[str, str] = {
    PROTOCOL_TCP: PROTOCOL_TCP,
    PROTOCOL_UDP: PROTOCOL_UDP,
    "QUIC": PROTOCOL_UDP,
    PROTOCOL_ICMP: PROTOCOL_ICMP,
    "ICMPV6": PROTOCOL_ICMP,
}

# Fallback classification from ``NormalizedPacket.packet_type`` (M5). DNS rides
# on UDP, so it is tracked as a UDP conversation.
_TRANSPORT_BY_TYPE: dict[PacketType, str] = {
    PacketType.TCP: PROTOCOL_TCP,
    PacketType.UDP: PROTOCOL_UDP,
    PacketType.DNS: PROTOCOL_UDP,
    PacketType.ICMP: PROTOCOL_ICMP,
}


class Direction(str, Enum):
    """Where a packet sits relative to a connection's recorded orientation."""

    SOURCE = "source"
    DESTINATION = "destination"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Endpoint:
    """One side of a conversation: a canonical address and an optional port."""

    ip: str
    port: int | None = None

    @property
    def is_portless(self) -> bool:
        """Return True when this endpoint carries no port (ICMP / unknown)."""
        return self.port is None

    def render(self) -> str:
        """Render the endpoint as ``ip:port``, or just ``ip`` when portless."""
        if self.port is None:
            return self.ip
        return f"{self.ip}:{self.port}"

    def sort_key(self) -> tuple[str, int]:
        """Return the deterministic ordering key for canonicalization."""
        port = self.port if self.port is not None else _MISSING_PORT_SORT_VALUE
        return (self.ip, port)


class Flow(NamedTuple):
    """The directional 5-tuple observed in one packet."""

    protocol: str
    source: Endpoint
    destination: Endpoint

    def key(self) -> "ConnectionKey":
        """Return the canonical, direction-independent key of this flow."""
        return canonical_key(self)


class ConnectionKey(NamedTuple):
    """Canonical bidirectional identity of a conversation.

    ``first`` and ``second`` are the two endpoints in a deterministic order, so
    ``A:52134 -> B:443`` and ``B:443 -> A:52134`` produce the *same* key.
    """

    protocol: str
    first: Endpoint
    second: Endpoint

    def render(self) -> str:
        """Return the deterministic ``connection_id`` text for this key."""
        return connection_id(self)


# -- protocol recognition -------------------------------------------------


def transport_of(packet: NormalizedPacket) -> str | None:
    """Return the transport protocol tracked for ``packet``, or ``None``.

    The M5 transport label is preferred because it is the more specific signal;
    the M5 classification is used as a fallback for packets the label does not
    name (for example a DNS packet whose label is empty).
    """
    label = (packet.protocol or "").strip().upper()
    tracked = _TRANSPORT_BY_LABEL.get(label)
    if tracked is not None:
        return tracked
    return _TRANSPORT_BY_TYPE.get(packet.packet_type)


def is_tracked_protocol(protocol: str) -> bool:
    """Return True when ``protocol`` is one M9 tracks."""
    return protocol in TRACKED_PROTOCOLS


# -- endpoints and flows --------------------------------------------------


def endpoint_of(ip_address: str | None, port: int | None = None) -> Endpoint | None:
    """Build an :class:`Endpoint`, or ``None`` when the address is unusable.

    ``None`` means "the packet did not carry a usable address" — the caller must
    skip the packet rather than invent one. A port that is not a usable TCP/UDP
    port is treated as absent rather than guessed at.
    """
    normalized_ip = normalize_ip_address(ip_address)
    if normalized_ip is None:
        return None
    return Endpoint(ip=normalized_ip, port=normalize_port(port))


def normalize_port(port: object) -> int | None:
    """Return ``port`` as an int in range, or ``None`` when it is not usable."""
    if isinstance(port, bool) or not isinstance(port, int):
        return None
    if port < 0 or port > _MAX_PORT:
        return None
    return port


def flow_of(packet: NormalizedPacket) -> Flow | None:
    """Build the directional 5-tuple of ``packet``, or ``None`` if untrackable.

    ``None`` is returned when the packet carries no usable source/destination
    address or is not a tracked transport protocol. Such a packet must be
    counted as *skipped*, never stored.
    """
    protocol = transport_of(packet)
    if protocol is None:
        return None

    # Ports are never invented: ICMP has none, and a TCP/UDP packet whose ports
    # were not observed keeps ``None``.
    if protocol in PORTLESS_PROTOCOLS:
        source_port = None
        destination_port = None
    else:
        source_port = normalize_port(packet.source_port)
        destination_port = normalize_port(packet.destination_port)

    source = endpoint_of(packet.source_ip, source_port)
    if source is None:
        return None
    destination = endpoint_of(packet.destination_ip, destination_port)
    if destination is None:
        return None

    return Flow(protocol=protocol, source=source, destination=destination)


# -- canonical key --------------------------------------------------------


def canonical_key(flow: Flow) -> ConnectionKey:
    """Return the canonical, direction-independent key of ``flow``."""
    first, second = _ordered(flow.source, flow.destination)
    return ConnectionKey(protocol=flow.protocol, first=first, second=second)


def connection_id(key: ConnectionKey) -> str:
    """Return the deterministic text id of a connection key.

    The rendering is unique per conversation because ``|`` cannot appear inside
    an address (IPv4 or IPv6) or a port, and the protocol is a fixed label.
    """
    return f"{key.protocol}|{key.first.render()}|{key.second.render()}"


def direction_of(flow: Flow, orientation: Endpoint) -> Direction:
    """Return where ``flow`` sits relative to a connection's ``orientation``.

    A connection's orientation is the *source endpoint of the first packet it
    ever saw*, so the opening packet is always ``SOURCE`` direction and the
    conversation's ``source_ip``/``source_port`` always name the peer that spoke
    first — usually the client, and the information a report needs (M9.5).

    A flow whose endpoints are identical (for example loopback to the same port)
    has no observable direction and is reported as ``SOURCE`` as well, which
    keeps the per-direction counters consistent with the totals.
    """
    if flow.source == flow.destination:
        return Direction.SOURCE
    if flow.source == orientation:
        return Direction.SOURCE
    if flow.destination == orientation:
        return Direction.DESTINATION
    return Direction.UNKNOWN


def _ordered(first: Endpoint, second: Endpoint) -> tuple[Endpoint, Endpoint]:
    """Return the two endpoints in canonical (deterministic) order."""
    if first.sort_key() <= second.sort_key():
        return first, second
    return second, first
