"""Transport-level observations shared by the M10 detectors (M10.8–M10.11).

Several detectors key on the same small set of facts about a packet: which
transport it belongs to, whether it opens a TCP handshake, and whether its
source plausibly *initiated* contact. Defining those once here keeps the port
scan and internal scan detectors from drifting apart in what they count.

Transport recognition is delegated to M9's :func:`transport_of`, which already
normalises the M5 protocol label and falls back to the M5 classification (DNS
rides on UDP, QUIC is treated as UDP). Reusing it keeps a single definition of
"this packet is TCP/UDP/ICMP" in the codebase rather than a second one that
could disagree with the connection tracker.

Nothing here holds state and nothing here reads configuration.
"""

from __future__ import annotations

from app.connections.identity import (
    PROTOCOL_ICMP,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    transport_of,
)
from app.connections.state import TcpFlags
from app.schemas.packet import NormalizedPacket

# Ports below this value are well-known or registered service ports. The
# detectors use it to tell a client that chose an ephemeral source port from a
# service that is answering from its own well-known port.
FIRST_EPHEMERAL_PORT = 1024


def flags_of(packet: NormalizedPacket) -> TcpFlags:
    """Return the TCP control flags M5 recorded for ``packet``.

    A packet with no readable flag string yields "no flags observed" rather than
    a guess, exactly as M9 treats it.
    """
    return TcpFlags.parse(packet.tcp_flags)


def is_tcp(packet: NormalizedPacket) -> bool:
    """Return True when ``packet`` is a TCP packet."""
    return transport_of(packet) == PROTOCOL_TCP


def is_udp(packet: NormalizedPacket) -> bool:
    """Return True when ``packet`` is a UDP (or UDP-carried) packet."""
    return transport_of(packet) == PROTOCOL_UDP


def is_icmp(packet: NormalizedPacket) -> bool:
    """Return True when ``packet`` is an ICMP (v4 or v6) packet."""
    return transport_of(packet) == PROTOCOL_ICMP


def is_handshake_open(packet: NormalizedPacket) -> bool:
    """Return True for a pure TCP SYN: the start of a fresh handshake.

    A ``SYN+ACK`` is a reply and is deliberately excluded.
    """
    if not is_tcp(packet):
        return False
    return flags_of(packet).is_handshake_open


def is_connection_attempt(packet: NormalizedPacket) -> bool:
    """Return True when the packet looks like its source *initiating* contact.

    Counting every packet that names a destination port would flag a busy
    server: each reply it sends carries a fresh ephemeral destination port, so a
    server answering many clients could reach any destination-port threshold.
    An attempt is therefore narrowed to traffic the source plausibly started:

    * a TCP pure ``SYN`` — a ``SYN+ACK`` is a reply, and a bare ``ACK`` or a
      payload packet belongs to a conversation that is already open;
    * a UDP (or other datagram) packet sent **from** an ephemeral port, so a
      service answering from port 53 or 123 is not counted while a client
      scanning from an ephemeral port is.

    A packet with no destination port — ICMP, ARP, a bare IP packet — is never a
    connection attempt.
    """
    if packet.destination_port is None:
        return False
    if is_tcp(packet):
        return flags_of(packet).is_handshake_open
    if is_udp(packet):
        source_port = packet.source_port
        return source_port is None or source_port >= FIRST_EPHEMERAL_PORT
    return False
