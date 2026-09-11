"""Deterministic packet classification (M5.11).

Maps extracted protocol information to a :class:`PacketType` and the
corresponding ``protocol`` label. Classification is purely descriptive: no
detection, scoring, or threat logic happens here.
"""

from app.processing.extract import ExtractedFields
from app.processing.protocols import (
    IP_PROTOCOL_ICMP,
    IP_PROTOCOL_TCP,
    IP_PROTOCOL_UDP,
    IP_VERSION_6,
    PROTOCOL_ARP,
    PROTOCOL_ICMP,
    PROTOCOL_IPV4,
    PROTOCOL_IPV6,
    PROTOCOL_OTHER,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
)
from app.schemas.packet import PacketType

# Transport classification is based on the transport layer when present,
# otherwise on the IP protocol number.
_PROTOCOL_NUMBER_LABELS = {
    IP_PROTOCOL_TCP: PROTOCOL_TCP,
    IP_PROTOCOL_UDP: PROTOCOL_UDP,
    IP_PROTOCOL_ICMP: PROTOCOL_ICMP,
}

_PROTOCOL_NUMBER_TYPES = {
    IP_PROTOCOL_TCP: PacketType.TCP,
    IP_PROTOCOL_UDP: PacketType.UDP,
    IP_PROTOCOL_ICMP: PacketType.ICMP,
}


def classify(fields: ExtractedFields) -> tuple[str, PacketType]:
    """Return the ``(protocol, packet_type)`` pair for extracted fields.

    Precedence:
        1. ARP
        2. DNS (on top of UDP/TCP)
        3. TCP / UDP / ICMP (by transport layer, then IP protocol number)
        4. IPV4 / IPV6 (IP with an unclassified next protocol)
        5. OTHER
    """
    if fields.is_arp:
        return PROTOCOL_ARP, PacketType.ARP

    if fields.is_tcp:
        if fields.is_dns:
            return PROTOCOL_TCP, PacketType.DNS
        return PROTOCOL_TCP, PacketType.TCP

    if fields.is_udp:
        if fields.is_dns:
            return PROTOCOL_UDP, PacketType.DNS
        return PROTOCOL_UDP, PacketType.UDP

    if fields.is_icmp:
        return PROTOCOL_ICMP, PacketType.ICMP

    protocol_number = fields.protocol_number
    if protocol_number is not None:
        number_label = _PROTOCOL_NUMBER_LABELS.get(protocol_number)
        if number_label is not None:
            protocol_type = _PROTOCOL_NUMBER_TYPES[protocol_number]
            if fields.is_dns:
                return number_label, PacketType.DNS
            return number_label, protocol_type

    if fields.ip_version == IP_VERSION_6:
        return PROTOCOL_IPV6, PacketType.IPV6
    if fields.ip_version is not None:
        return PROTOCOL_IPV4, PacketType.IPV4

    return PROTOCOL_OTHER, PacketType.OTHER
