"""Unit tests for the M5 PacketProcessor and normalization."""

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from app.processing.errors import PacketProcessingError
from app.processing.processor import PacketProcessor
from app.schemas.packet import PacketType


@pytest.fixture
def processor() -> PacketProcessor:
    """Return a PacketProcessor bound to a test interface."""
    return PacketProcessor(interface="Wi-Fi")


# ---------------------------------------------------------------------------
# Ethernet
# ---------------------------------------------------------------------------


def test_ethernet_mac_extraction(processor: PacketProcessor) -> None:
    """Layer-2 MAC addresses are extracted and normalized."""
    packet = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / IP(
        src="192.168.1.10", dst="192.168.1.20"
    )

    normalized = processor.process(packet)

    assert normalized.source_mac == "AA:BB:CC:DD:EE:FF"
    assert normalized.destination_mac == "11:22:33:44:55:66"


def test_non_ethernet_packet_has_no_mac(processor: PacketProcessor) -> None:
    """A packet without an Ethernet layer leaves MACs as None."""
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2)

    normalized = processor.process(packet)

    assert normalized.source_mac is None
    assert normalized.destination_mac is None


# ---------------------------------------------------------------------------
# IPv4
# ---------------------------------------------------------------------------


def test_ipv4_extraction(processor: PacketProcessor) -> None:
    """IPv4 source/destination addresses and version are extracted."""
    packet = Ether() / IP(src="192.168.1.10", dst="142.250.0.1") / TCP(
        sport=52341, dport=443
    )

    normalized = processor.process(packet)

    assert normalized.ip_version == 4
    assert normalized.source_ip == "192.168.1.10"
    assert normalized.destination_ip == "142.250.0.1"
    assert normalized.packet_type == PacketType.TCP


# ---------------------------------------------------------------------------
# IPv6
# ---------------------------------------------------------------------------


def test_ipv6_extraction(processor: PacketProcessor) -> None:
    """IPv6 source/destination addresses and version are extracted."""
    packet = Ether() / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=1234, dport=80)

    normalized = processor.process(packet)

    assert normalized.ip_version == 6
    assert normalized.source_ip == "fe80::1"
    assert normalized.destination_ip == "fe80::2"


def test_ipv6_without_transport_is_classified_ipv6(
    processor: PacketProcessor,
) -> None:
    """IPv6 with an unclassified next header is classified as IPV6."""
    packet = Ether() / IPv6(src="fe80::1", dst="fe80::2", nh=59)  # 59 = No Next Header

    normalized = processor.process(packet)

    assert normalized.protocol == "IPV6"
    assert normalized.packet_type == PacketType.IPV6


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------


def test_tcp_extraction(processor: PacketProcessor) -> None:
    """TCP ports and flags are extracted."""
    packet = Ether() / IP() / TCP(sport=52341, dport=443, flags="S")

    normalized = processor.process(packet)

    assert normalized.source_port == 52341
    assert normalized.destination_port == 443
    assert normalized.tcp_flags is not None
    assert "S" in normalized.tcp_flags
    assert normalized.packet_type == PacketType.TCP


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------


def test_udp_extraction(processor: PacketProcessor) -> None:
    """UDP ports are extracted."""
    packet = Ether() / IP() / UDP(sport=5353, dport=53)

    normalized = processor.process(packet)

    assert normalized.source_port == 5353
    assert normalized.destination_port == 53
    assert normalized.packet_type == PacketType.UDP
    assert normalized.tcp_flags is None


# ---------------------------------------------------------------------------
# ICMP
# ---------------------------------------------------------------------------


def test_icmp_identification(processor: PacketProcessor) -> None:
    """ICMP packets are identified and carry no ports."""
    packet = Ether() / IP() / ICMP()

    normalized = processor.process(packet)

    assert normalized.protocol == "ICMP"
    assert normalized.packet_type == PacketType.ICMP
    assert normalized.source_port is None
    assert normalized.destination_port is None


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def test_dns_identification(processor: PacketProcessor) -> None:
    """A DNS-over-UDP packet is identified as DNS."""
    packet = (
        Ether()
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=51000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )

    normalized = processor.process(packet)

    assert normalized.packet_type == PacketType.DNS
    assert normalized.protocol == "UDP"
    assert normalized.destination_port == 53


# ---------------------------------------------------------------------------
# Timestamp and length
# ---------------------------------------------------------------------------


def test_timestamp_is_preserved(processor: PacketProcessor) -> None:
    """The packet's capture time is used for the normalized timestamp."""
    packet = Ether() / IP() / TCP()
    packet.time = 1700000000.5

    normalized = processor.process(packet)

    assert normalized.timestamp == pytest.approx(1700000000.5)


def test_length_matches_captured_frame(processor: PacketProcessor) -> None:
    """The normalized length equals the captured frame length."""
    packet = Ether() / IP() / TCP()

    normalized = processor.process(packet)

    assert normalized.length == len(packet)


def test_interface_is_recorded(processor: PacketProcessor) -> None:
    """The capture interface is attached to normalized packets."""
    normalized = processor.process(Ether() / IP() / TCP())
    assert normalized.interface == "Wi-Fi"


# ---------------------------------------------------------------------------
# Classification / packet ids
# ---------------------------------------------------------------------------


def test_arp_is_classified(processor: PacketProcessor) -> None:
    """ARP packets are classified as ARP with no IP fields."""
    packet = Ether(src="aa:bb:cc:dd:ee:ff") / ARP()

    normalized = processor.process(packet)

    assert normalized.packet_type == PacketType.ARP
    assert normalized.protocol == "ARP"
    assert normalized.source_ip is None


def test_unknown_ip_protocol_is_classified_ipv4(processor: PacketProcessor) -> None:
    """An IPv4 packet with an unmapped protocol is classified as IPV4."""
    packet = Ether() / IP(proto=47)  # 47 = GRE (not mapped)

    normalized = processor.process(packet)

    assert normalized.packet_type == PacketType.IPV4
    assert normalized.ip_version == 4


def test_non_ip_packet_is_other(processor: PacketProcessor) -> None:
    """A raw, non-Ethernet/IP packet is classified as OTHER."""
    packet = Raw(b"\x00\x01\x02\x03")

    normalized = processor.process(packet)

    assert normalized.packet_type == PacketType.OTHER
    assert normalized.protocol == "OTHER"
    assert normalized.ip_version is None


def test_packet_ids_increment(processor: PacketProcessor) -> None:
    """Each processed packet receives an increasing identifier."""
    first = processor.process(Ether() / IP() / TCP())
    second = processor.process(Ether() / IP() / TCP())

    assert first.packet_id == 1
    assert second.packet_id == 2


# ---------------------------------------------------------------------------
# Missing layers / empty / malformed
# ---------------------------------------------------------------------------


def test_empty_ethernet_packet_still_processes(processor: PacketProcessor) -> None:
    """A bare Ethernet frame normalizes without crashing."""
    normalized = processor.process(Ether())

    assert normalized.packet_type == PacketType.OTHER
    assert normalized.source_ip is None


def test_none_packet_is_rejected(processor: PacketProcessor) -> None:
    """A None packet raises a controlled processing error."""
    with pytest.raises(PacketProcessingError):
        processor.process(None)


def test_tcp_without_ip_is_handled(processor: PacketProcessor) -> None:
    """A TCP layer without IP still yields ports and a TCP classification."""
    normalized = processor.process(Ether() / TCP(sport=1000, dport=2000))

    assert normalized.source_port == 1000
    assert normalized.destination_port == 2000
    assert normalized.ip_version is None


def test_malformed_packet_raises_controlled_error(processor: PacketProcessor) -> None:
    """A packet object that raises during inspection yields a controlled error."""

    class BrokenPacket:
        """Minimal object whose layer inspection always raises."""

        def haslayer(self, _layer: object) -> bool:
            raise ValueError("corrupt packet")

        def getlayer(self, _layer: object) -> object:
            raise ValueError("corrupt packet")

        def __len__(self) -> int:
            raise ValueError("corrupt packet")

    with pytest.raises(PacketProcessingError) as exc_info:
        processor.process(BrokenPacket())

    assert "Malformed" in exc_info.value.reason
