"""Protocol label constants for packet normalization (M5)."""

# Labels stored in ``NormalizedPacket.protocol``.
PROTOCOL_TCP = "TCP"
PROTOCOL_UDP = "UDP"
PROTOCOL_ICMP = "ICMP"
PROTOCOL_ARP = "ARP"
PROTOCOL_IPV4 = "IPV4"
PROTOCOL_IPV6 = "IPV6"
PROTOCOL_OTHER = "OTHER"

# IP protocol numbers we map to human-readable labels.
IP_PROTOCOL_ICMP = 1
IP_PROTOCOL_TCP = 6
IP_PROTOCOL_UDP = 17
IP_PROTOCOL_ICMPV6 = 58

# IP version numbers.
IP_VERSION_4 = 4
IP_VERSION_6 = 6
