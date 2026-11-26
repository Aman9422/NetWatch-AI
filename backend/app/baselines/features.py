"""Behavioural feature extraction from normalized packets (M21.4).

This module is the *only* place a behavioural feature is defined, and it is
deliberately a set of pure functions over
:class:`~app.schemas.packet.NormalizedPacket`. That keeps three properties the
milestone asks for:

* **No second capture implementation.** Every value here comes from a packet the
  M5 processor already normalized. Nothing in this module imports Scapy, opens a
  socket or looks at a frame.
* **No invented metrics.** A feature is extracted only when the underlying field
  is actually present. A packet with no destination port contributes no port; it
  does not contribute port ``0``. The distinction between "not observed" and
  "observed as zero" is the difference between a truthful baseline and a
  fabricated one (M21.5/M21.7).
* **Malformed input cannot raise.** A packet missing every field yields ``None``
  rather than an exception, so a broken frame cannot stop the capture thread.

## Attribution policy (M21.4 "Device identity")

A packet is attributed to the device that **sent** it: the endpoint built from
``source_mac`` / ``source_ip``. The destination is recorded as a *peer*, never as
a device.

That asymmetry is deliberate and it is what keeps the router problem out of the
baseline. M15 documented the limitation: on a routed path the frame's L2
destination is the next hop, so keying a device by the destination MAC binds
every far-end address to the gateway's MAC and collapses unrelated hosts into
one record. A *source* endpoint cannot have that problem — the frame header names
the sender, so its MAC and its IP are both genuinely that sender's.

The consequence is stated rather than hidden: **a device that is only ever seen
receiving is not profiled**, and no inbound packet or byte counter is produced.
M21.4 permits exactly this — "add inbound/outbound metrics only if the current
architecture can determine direction accurately" — and on a routed path this
capture path cannot.

## Fallback identity

``source_mac`` is preferred because it survives an IP change. When a packet
carries no usable MAC the canonical source IP is used instead, and the profile is
marked ``identity_kind="ip"`` so a reader knows it is a weaker identity. When
neither is usable — broadcast, multicast, unspecified, all-zero — the packet is
**not attributed at all** and is counted as skipped. It is never attributed to a
placeholder device.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.devices.identity import (
    device_id_for,
    is_trackable_endpoint,
    normalize_ip_address,
    normalize_mac_address,
)
from app.schemas.packet import NormalizedPacket, PacketType

#: Protocol labels counted as behavioural features. These are the labels the M5
#: classifier actually emits (``app/processing/classifier.py``), so a name here
#: can never disagree with what was on the wire.
PROTOCOL_TCP = "TCP"
PROTOCOL_UDP = "UDP"
PROTOCOL_ICMP = "ICMP"

#: Identity kinds a profile can carry.
IDENTITY_MAC = "mac"
IDENTITY_IP = "ip"

#: Highest usable port number.
MAX_PORT = 65535


@dataclass(frozen=True)
class PacketObservation:
    """What one packet contributes to the device that sent it (M21.4).

    Every field is derived from the packet and nothing is defaulted, so a caller
    can tell a missing peer from a peer set of size zero.

    Attributes:
        device_key: Stable identity of the sending device — ``mac:...`` or
            ``ip:...``.
        identity_kind: ``mac`` or ``ip``, matching ``device_key``.
        mac_address: The canonical source MAC, when one was observed.
        ip_address: The canonical source IP, when one was observed.
        peer_ip: The canonical destination IP, when one was observed. A *peer*;
            it never becomes a device identity.
        destination_port: The destination port, when one was observed.
        length: The captured frame length in bytes, clamped to ``>= 0``.
        protocol: The M5 protocol label, upper-cased, or ``""`` when absent.
        packet_type: The M5 classification.
        is_syn: True for a TCP packet carrying SYN without ACK.
    """

    device_key: str
    identity_kind: str
    mac_address: str | None
    ip_address: str | None
    peer_ip: str | None
    destination_port: int | None
    length: int
    protocol: str
    packet_type: PacketType
    is_syn: bool

    @property
    def conversation_key(self) -> str | None:
        """Return the conversation this packet belongs to, or ``None``.

        The key is ``protocol|peer_ip|destination_port``, which is enough to
        answer "has this device talked to this service before?" without importing
        the M9 tracker and without storing an unbounded address set: the caller
        keeps only the cardinality of the keys it remembers.

        ``None`` when the packet has no peer address, because a conversation with
        an unknown far end cannot honestly be counted as a new one.
        """
        if self.peer_ip is None:
            return None
        port = "" if self.destination_port is None else str(self.destination_port)
        return f"{self.protocol or 'OTHER'}|{self.peer_ip}|{port}"


def _is_syn(packet: NormalizedPacket) -> bool:
    """Return True when ``packet`` is a bare TCP SYN.

    The M5 flags are a compact string such as ``"S"``, ``"SA"`` or ``"PA"``. A SYN
    carrying ACK is a *reply* to an attempt rather than an attempt, so it is
    excluded: counting SYN-ACK as "started a conversation" would make every
    accepted inbound connection look like an outbound one.
    """
    flags = (packet.tcp_flags or "").strip().upper()
    if not flags:
        return False
    return "S" in flags and "A" not in flags


def observe(packet: NormalizedPacket) -> PacketObservation | None:
    """Extract one packet's contribution, or ``None`` when unattributable.

    Args:
        packet: A normalized packet from the M5 processor.

    Returns:
        The observation for the sending device, or ``None`` when the packet names
        no trackable sender. ``None`` is a real answer — the caller counts it as
        skipped — and never an exception, because a malformed packet must not
        interrupt packet processing (M21.5).
    """
    try:
        return _observe(packet)
    except Exception:  # noqa: BLE001 - extraction must never stop capture
        # Deliberately a bare ``None`` rather than a re-raise: the caller has no
        # better answer than "this packet told us nothing", and the pipeline
        # already isolates and counts a baseline failure.
        return None


def _observe(packet: NormalizedPacket) -> PacketObservation | None:
    """Implementation of :func:`observe`, allowed to raise internally."""
    source_mac = normalize_mac_address(packet.source_mac)
    source_ip = normalize_ip_address(packet.source_ip)

    # The same gate M8 uses, so the two layers never disagree about what a
    # trackable endpoint is. A broadcast or multicast sender is not a device.
    if not is_trackable_endpoint(source_mac, source_ip):
        return None

    device_key = device_id_for(source_mac, source_ip)
    if device_key is None:
        return None

    peer_ip = normalize_ip_address(packet.destination_ip)
    if peer_ip is not None and peer_ip == source_ip:
        # A packet a host sent to itself is not evidence of peer variety.
        peer_ip = None

    length = packet.length if isinstance(packet.length, int) else 0

    return PacketObservation(
        device_key=device_key,
        identity_kind=IDENTITY_MAC if source_mac is not None else IDENTITY_IP,
        mac_address=source_mac,
        ip_address=source_ip,
        peer_ip=peer_ip,
        destination_port=_normalize_port(packet.destination_port),
        length=max(length, 0),
        protocol=(packet.protocol or "").strip().upper(),
        packet_type=packet.packet_type,
        is_syn=_is_syn(packet),
    )


def _normalize_port(port: object) -> int | None:
    """Return ``port`` as a usable port number, or ``None``.

    ``bool`` is rejected explicitly: ``True`` is an ``int`` in Python and would
    otherwise be accepted as port 1.
    """
    if isinstance(port, bool) or not isinstance(port, int):
        return None
    if port < 0 or port > MAX_PORT:
        return None
    return port


def is_tcp(observation: PacketObservation) -> bool:
    """Return True when the observation is TCP traffic."""
    return observation.protocol == PROTOCOL_TCP


def is_udp(observation: PacketObservation) -> bool:
    """Return True when the observation is UDP traffic."""
    return observation.protocol == PROTOCOL_UDP


def is_icmp(observation: PacketObservation) -> bool:
    """Return True when the observation is ICMP traffic."""
    return observation.protocol == PROTOCOL_ICMP or (
        observation.packet_type is PacketType.ICMP
    )


def is_dns(observation: PacketObservation) -> bool:
    """Return True when the M5 classifier identified the packet as DNS.

    DNS is a classification *on top of* a transport, so a DNS packet counts in
    both its transport total and the DNS total. That is stated here rather than
    left for a reader to discover, because the alternative — making the protocol
    counts sum to the packet count — would mean a DNS packet was either not
    counted as UDP or not counted as DNS.
    """
    return observation.packet_type is PacketType.DNS


__all__ = [
    "IDENTITY_IP",
    "IDENTITY_MAC",
    "MAX_PORT",
    "PROTOCOL_ICMP",
    "PROTOCOL_TCP",
    "PROTOCOL_UDP",
    "PacketObservation",
    "is_dns",
    "is_icmp",
    "is_tcp",
    "is_udp",
    "observe",
]
