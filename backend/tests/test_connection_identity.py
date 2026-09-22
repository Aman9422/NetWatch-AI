"""Unit tests for M9 connection identity (M9.3, M9.5, M9.13)."""

import pytest

from app.connections.identity import (
    PROTOCOL_ICMP,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    Direction,
    Endpoint,
    Flow,
    canonical_key,
    connection_id,
    direction_of,
    endpoint_of,
    flow_of,
    is_tracked_protocol,
    normalize_port,
    transport_of,
)
from app.schemas.packet import PacketType
from tests.fakes import make_normalized_packet


# -- protocol recognition -------------------------------------------------


def test_tcp_label_is_tracked() -> None:
    packet = make_normalized_packet(protocol="TCP", packet_type=PacketType.TCP)
    assert transport_of(packet) == PROTOCOL_TCP


def test_udp_label_is_tracked() -> None:
    packet = make_normalized_packet(protocol="UDP", packet_type=PacketType.UDP)
    assert transport_of(packet) == PROTOCOL_UDP


def test_icmp_label_is_tracked() -> None:
    packet = make_normalized_packet(protocol="ICMP", packet_type=PacketType.ICMP)
    assert transport_of(packet) == PROTOCOL_ICMP


def test_icmpv6_label_maps_to_icmp() -> None:
    packet = make_normalized_packet(protocol="ICMPv6", packet_type=PacketType.ICMP)
    assert transport_of(packet) == PROTOCOL_ICMP


def test_dns_packet_is_treated_as_udp() -> None:
    packet = make_normalized_packet(protocol="", packet_type=PacketType.DNS)
    assert transport_of(packet) == PROTOCOL_UDP


def test_untracked_protocol_is_none() -> None:
    packet = make_normalized_packet(protocol="ARP", packet_type=PacketType.OTHER)
    assert transport_of(packet) is None


@pytest.mark.parametrize("protocol", ["tcp", "Tcp", " TCP "])
def test_protocol_label_is_case_and_space_insensitive(protocol: str) -> None:
    packet = make_normalized_packet(protocol=protocol, packet_type=PacketType.OTHER)
    assert transport_of(packet) == PROTOCOL_TCP


def test_is_tracked_protocol_rejects_others() -> None:
    assert is_tracked_protocol(PROTOCOL_TCP)
    assert not is_tracked_protocol("ARP")


# -- ports ----------------------------------------------------------------


@pytest.mark.parametrize("port", [0, 1, 80, 65535])
def test_valid_ports_are_preserved(port: int) -> None:
    assert normalize_port(port) == port


@pytest.mark.parametrize("port", [-1, 65536, 99999])
def test_out_of_range_ports_are_none(port: int) -> None:
    assert normalize_port(port) is None


@pytest.mark.parametrize("port", [None, "80", 3.5, True, False])
def test_unusable_ports_are_none(port: object) -> None:
    assert normalize_port(port) is None


# -- endpoints ------------------------------------------------------------


def test_endpoint_normalizes_ipv4() -> None:
    endpoint = endpoint_of(" 192.168.1.10 ", 443)
    assert endpoint == Endpoint(ip="192.168.1.10", port=443)


def test_endpoint_normalizes_ipv6() -> None:
    endpoint = endpoint_of("2001:DB8::1", 443)
    assert endpoint == Endpoint(ip="2001:db8::1", port=443)


@pytest.mark.parametrize("value", [None, "", "not-an-ip", "999.1.1.1"])
def test_endpoint_without_a_usable_address_is_none(value: str | None) -> None:
    assert endpoint_of(value, 80) is None


def test_endpoint_render_includes_the_port() -> None:
    assert Endpoint(ip="10.0.0.1", port=80).render() == "10.0.0.1:80"


def test_endpoint_render_omits_a_missing_port() -> None:
    assert Endpoint(ip="10.0.0.1").render() == "10.0.0.1"


def test_endpoint_is_portless_without_a_port() -> None:
    assert Endpoint(ip="10.0.0.1").is_portless
    assert not Endpoint(ip="10.0.0.1", port=0).is_portless


# -- flows ----------------------------------------------------------------


def test_flow_of_builds_the_five_tuple() -> None:
    packet = make_normalized_packet(
        source_ip="192.168.1.10",
        destination_ip="142.250.1.1",
        source_port=52134,
        destination_port=443,
    )
    flow = flow_of(packet)
    assert flow is not None
    assert flow.protocol == PROTOCOL_TCP
    assert flow.source == Endpoint(ip="192.168.1.10", port=52134)
    assert flow.destination == Endpoint(ip="142.250.1.1", port=443)


def test_icmp_flow_has_no_ports() -> None:
    packet = make_normalized_packet(
        protocol="ICMP",
        packet_type=PacketType.ICMP,
        source_port=None,
        destination_port=None,
    )
    flow = flow_of(packet)
    assert flow is not None
    assert flow.source.port is None
    assert flow.destination.port is None


def test_untracked_protocol_has_no_flow() -> None:
    packet = make_normalized_packet(protocol="ARP", packet_type=PacketType.OTHER)
    assert flow_of(packet) is None


def test_flow_without_a_source_address_is_none() -> None:
    packet = make_normalized_packet(source_ip=None)
    assert flow_of(packet) is None


def test_flow_without_a_destination_address_is_none() -> None:
    packet = make_normalized_packet(destination_ip=None)
    assert flow_of(packet) is None


def test_flow_never_invents_a_missing_port() -> None:
    packet = make_normalized_packet(source_port=None, destination_port=None)
    flow = flow_of(packet)
    assert flow is not None
    assert flow.source.port is None
    assert flow.destination.port is None


# -- canonical key (M9.5) -------------------------------------------------


def test_same_flow_resolves_to_the_same_key() -> None:
    packet = make_normalized_packet()
    first = flow_of(packet)
    second = flow_of(make_normalized_packet())
    assert first is not None and second is not None
    assert first.key() == second.key()


def test_reverse_flow_resolves_to_the_same_key() -> None:
    forward = flow_of(
        make_normalized_packet(
            source_ip="192.168.1.10",
            destination_ip="142.250.1.1",
            source_port=52134,
            destination_port=443,
        )
    )
    reverse = flow_of(
        make_normalized_packet(
            source_ip="142.250.1.1",
            destination_ip="192.168.1.10",
            source_port=443,
            destination_port=52134,
        )
    )
    assert forward is not None and reverse is not None
    assert forward.key() == reverse.key()


def test_a_different_flow_gets_a_different_key() -> None:
    first = flow_of(make_normalized_packet(destination_port=443))
    second = flow_of(make_normalized_packet(destination_port=8443))
    assert first is not None and second is not None
    assert first.key() != second.key()


def test_a_different_protocol_gets_a_different_key() -> None:
    tcp = flow_of(make_normalized_packet(protocol="TCP", packet_type=PacketType.TCP))
    udp = flow_of(make_normalized_packet(protocol="UDP", packet_type=PacketType.UDP))
    assert tcp is not None and udp is not None
    assert tcp.key() != udp.key()


def test_ipv6_flows_are_canonicalized() -> None:
    upper = flow_of(make_normalized_packet(source_ip="2001:DB8::1"))
    lower = flow_of(make_normalized_packet(source_ip="2001:db8::1"))
    assert upper is not None and lower is not None
    assert upper.key() == lower.key()


def test_canonical_key_is_direction_independent() -> None:
    a = Endpoint(ip="10.0.0.2", port=80)
    b = Endpoint(ip="10.0.0.1", port=5000)
    forward = canonical_key(Flow(PROTOCOL_TCP, a, b))
    reverse = canonical_key(Flow(PROTOCOL_TCP, b, a))
    assert forward == reverse


def test_canonical_key_orders_portless_before_zero() -> None:
    portless = Endpoint(ip="10.0.0.1", port=None)
    zero = Endpoint(ip="10.0.0.1", port=0)
    key = canonical_key(Flow(PROTOCOL_TCP, zero, portless))
    assert key.first == portless
    assert key.second == zero


# -- connection id --------------------------------------------------------


def test_connection_id_renders_the_tuple() -> None:
    flow = flow_of(
        make_normalized_packet(
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            source_port=5000,
            destination_port=80,
        )
    )
    assert flow is not None
    assert connection_id(flow.key()) == "TCP|10.0.0.1:5000|10.0.0.2:80"


def test_connection_id_is_identical_for_both_directions() -> None:
    forward = flow_of(
        make_normalized_packet(
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            source_port=5000,
            destination_port=80,
        )
    )
    reverse = flow_of(
        make_normalized_packet(
            source_ip="10.0.0.2",
            destination_ip="10.0.0.1",
            source_port=80,
            destination_port=5000,
        )
    )
    assert forward is not None and reverse is not None
    assert forward.key().render() == reverse.key().render()


def test_connection_id_is_stable_across_calls() -> None:
    flow = flow_of(make_normalized_packet())
    assert flow is not None
    assert flow.key().render() == flow.key().render()


# -- direction (M9.4) -----------------------------------------------------


def test_opening_packet_is_source_direction() -> None:
    flow = flow_of(
        make_normalized_packet(source_ip="10.0.0.1", source_port=5000)
    )
    assert flow is not None
    assert direction_of(flow, Endpoint(ip="10.0.0.1", port=5000)) is Direction.SOURCE


def test_reply_packet_is_destination_direction() -> None:
    reply = flow_of(
        make_normalized_packet(
            source_ip="10.0.0.2",
            destination_ip="10.0.0.1",
            source_port=80,
            destination_port=5000,
        )
    )
    assert reply is not None
    orientation = Endpoint(ip="10.0.0.1", port=5000)
    assert direction_of(reply, orientation) is Direction.DESTINATION


def test_unrelated_flow_has_unknown_direction() -> None:
    other = flow_of(make_normalized_packet(source_ip="10.9.9.9", source_port=1234))
    assert other is not None
    orientation = Endpoint(ip="10.0.0.1", port=5000)
    assert direction_of(other, orientation) is Direction.UNKNOWN


def test_identical_endpoints_report_source_direction() -> None:
    loopback = flow_of(
        make_normalized_packet(
            source_ip="127.0.0.1", destination_ip="127.0.0.1", source_port=9,
            destination_port=9,
        )
    )
    assert loopback is not None
    orientation = Endpoint(ip="127.0.0.1", port=9)
    assert direction_of(loopback, orientation) is Direction.SOURCE
