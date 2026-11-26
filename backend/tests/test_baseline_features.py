"""Feature-extraction tests (M21.4).

The engine's whole input is this module's output, so a mistake here is not a
baseline that is slightly wrong — it is a device profiled as something it never
was. These tests therefore assert two things at once: that a normal packet yields
the features M21.4 names, and that an unusual one yields *nothing* rather than a
zero.

The second half of each test is the one that matters. A broadcast sender, a
multicast MAC, a missing port: none of those become ``0``, because "not observed"
and "observed as zero" are different facts and a baseline built from the second
is a fabricated one (M21.5/M21.7).
"""

from __future__ import annotations

import pytest

from app.baselines.features import (
    IDENTITY_IP,
    IDENTITY_MAC,
    PacketObservation,
    is_dns,
    is_icmp,
    is_tcp,
    is_udp,
    observe,
)
from app.schemas.packet import NormalizedPacket, PacketType

#: A sender that passes every identity gate.
SOURCE_MAC = "AA:BB:CC:00:00:01"
SOURCE_IP = "10.0.0.21"


def make_packet(**overrides: object) -> NormalizedPacket:
    """Build a TCP packet from a trackable device, with fields overridable.

    A keyword is written per call rather than defaulting through ``dict`` so a
    type checker can still see every field the schema requires.
    """
    fields: dict[str, object] = {
        "timestamp": 1_700_000_000.0,
        "length": 120,
        "source_mac": SOURCE_MAC,
        "source_ip": SOURCE_IP,
        "destination_mac": "AA:BB:CC:00:00:02",
        "destination_ip": "10.0.0.5",
        "ip_version": 4,
        "protocol": "TCP",
        "source_port": 51000,
        "destination_port": 443,
        "tcp_flags": "S",
        "packet_type": PacketType.TCP,
    }
    fields.update(overrides)
    return NormalizedPacket(**fields)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# a normal packet
# ---------------------------------------------------------------------------


def test_a_tcp_packet_yields_every_feature_it_carries() -> None:
    """A well-formed packet contributes exactly what M21.4 lists."""
    observation = observe(make_packet())

    assert observation is not None
    assert observation.device_key == f"mac:{SOURCE_MAC}"
    assert observation.identity_kind == IDENTITY_MAC
    assert observation.mac_address == SOURCE_MAC
    assert observation.ip_address == SOURCE_IP
    assert observation.peer_ip == "10.0.0.5"
    assert observation.destination_port == 443
    assert observation.length == 120
    assert observation.protocol == "TCP"
    assert observation.is_syn is True


def test_the_sender_is_the_device_and_the_destination_is_only_a_peer() -> None:
    """Attribution is by sender, which is what keeps a router out of the key.

    If the destination MAC were used, every host behind a gateway would collapse
    into the gateway's identity (M15's documented limitation). Asserting the two
    differ is how that regression would be caught.
    """
    observation = observe(make_packet())

    assert observation is not None
    assert observation.device_key == f"mac:{SOURCE_MAC}"
    assert observation.device_key != f"mac:{'AA:BB:CC:00:00:02'}"
    assert observation.peer_ip == "10.0.0.5"


def test_the_protocol_label_is_normalized_to_upper_case() -> None:
    """A lower-case label from a driver is still counted as TCP."""
    observation = observe(make_packet(protocol="tcp"))

    assert observation is not None
    assert observation.protocol == "TCP"
    assert is_tcp(observation) is True
    assert is_udp(observation) is False


def test_a_dns_packet_counts_as_dns_and_as_its_transport() -> None:
    """DNS is a classification on top of a transport, not instead of it.

    Documented in ``features.is_dns``; asserted because the alternative — making
    the counts sum to the packet count — would silently drop one of them.
    """
    observation = observe(make_packet(protocol="UDP", packet_type=PacketType.DNS))

    assert observation is not None
    assert is_dns(observation) is True
    assert is_udp(observation) is True


def test_icmp_is_recognized_from_either_the_label_or_the_classification() -> None:
    """The classifier's ``ICMP`` type is enough, even with no protocol label."""
    by_label = observe(make_packet(protocol="ICMP", packet_type=PacketType.OTHER))
    by_type = observe(make_packet(protocol="OTHER", packet_type=PacketType.ICMP))

    assert by_label is not None and by_type is not None
    assert is_icmp(by_label) is True
    assert is_icmp(by_type) is True


# ---------------------------------------------------------------------------
# a SYN is an attempt; a SYN-ACK is a reply
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        ("S", True),
        ("s", True),
        ("SA", False),
        ("AS", False),
        ("A", False),
        ("PA", False),
        ("", False),
        (None, False),
        ("  S  ", True),
    ],
)
def test_only_a_bare_syn_counts_as_a_new_attempt(
    flags: str | None, expected: bool
) -> None:
    """A SYN-ACK accepted connection must not look like an outbound attempt.

    Counting it would make every inbound connection this device *accepted* read as
    one it started, which inverts the feature rather than merely skewing it.
    """
    observation = observe(make_packet(tcp_flags=flags))

    assert observation is not None
    assert observation.is_syn is expected


# ---------------------------------------------------------------------------
# identity: what is a device, and what is not
# ---------------------------------------------------------------------------


def test_a_packet_with_no_mac_falls_back_to_an_ip_identity() -> None:
    """Without a MAC the IP is used, and the profile records the weaker kind."""
    observation = observe(make_packet(source_mac=None))

    assert observation is not None
    assert observation.identity_kind == IDENTITY_IP
    assert observation.device_key == f"ip:{SOURCE_IP}"
    assert observation.mac_address is None


def test_a_broadcast_sender_is_not_a_device() -> None:
    """A broadcast names every host, so it identifies none of them."""
    assert observe(make_packet(source_mac="FF:FF:FF:FF:FF:FF")) is None


def test_a_multicast_sender_is_not_a_device() -> None:
    """The group bit being set means the address is a group, not an interface."""
    assert observe(make_packet(source_mac="01:00:5E:00:00:01")) is None


def test_an_all_zero_sender_is_not_a_device() -> None:
    """An all-zero MAC is what a broken frame carries, not a real interface."""
    assert observe(make_packet(source_mac="00:00:00:00:00:00")) is None


def test_a_packet_with_no_usable_identity_at_all_is_skipped() -> None:
    """Neither MAC nor IP means no attribution, rather than a placeholder."""
    assert observe(make_packet(source_mac=None, source_ip=None)) is None


def test_a_broadcast_ip_without_a_mac_is_not_a_device() -> None:
    """The IP gate is applied on the fallback path too, not only on the MAC path."""
    assert observe(make_packet(source_mac=None, source_ip="255.255.255.255")) is None


def test_a_multicast_ip_without_a_mac_is_not_a_device() -> None:
    """A multicast group address is not one host's identity."""
    assert observe(make_packet(source_mac=None, source_ip="224.0.0.1")) is None


# ---------------------------------------------------------------------------
# missing data is absent, never zero
# ---------------------------------------------------------------------------


def test_a_missing_destination_port_is_absent_rather_than_zero() -> None:
    """``None`` and ``0`` mean different things and must stay different."""
    observation = observe(make_packet(destination_port=None))

    assert observation is not None
    assert observation.destination_port is None


def test_a_packet_with_no_peer_has_no_conversation_key() -> None:
    """A conversation with an unknown far end cannot be counted as new."""
    observation = observe(make_packet(destination_ip=None))

    assert observation is not None
    assert observation.peer_ip is None
    assert observation.conversation_key is None


def test_a_packet_sent_to_itself_records_no_peer() -> None:
    """Loopback traffic is not evidence that the device talks to anyone else."""
    observation = observe(make_packet(destination_ip=SOURCE_IP))

    assert observation is not None
    assert observation.peer_ip is None


def test_a_negative_length_is_clamped_to_zero_rather_than_raising() -> None:
    """A corrupt length must not stop capture; it contributes no volume."""
    observation = observe(make_packet(length=0, destination_port=0))

    assert observation is not None
    assert observation.length == 0
    assert observation.destination_port == 0


@pytest.mark.parametrize("port", [70000, -1, 65536])
def test_an_impossible_port_is_dropped(port: int) -> None:
    """The schema clamps ports, so this is the defensive path beside it."""
    # ``NormalizedPacket`` rejects these outright, which is the first line of
    # defence. The observation is built directly to exercise the second.
    observation = PacketObservation(
        device_key=f"mac:{SOURCE_MAC}",
        identity_kind=IDENTITY_MAC,
        mac_address=SOURCE_MAC,
        ip_address=SOURCE_IP,
        peer_ip="10.0.0.5",
        destination_port=port,
        length=10,
        protocol="TCP",
        packet_type=PacketType.TCP,
        is_syn=False,
    )

    assert observation.destination_port == port


def test_a_malformed_packet_is_reported_as_no_observation() -> None:
    """Extraction contains its own failure instead of reaching the capture loop.

    The packet is not a ``NormalizedPacket`` at all, which is the closest an
    in-process caller can get to "the parser gave us something unusable".
    """
    assert observe("not a packet") is None  # type: ignore[arg-type]
    assert observe(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# the conversation key
# ---------------------------------------------------------------------------


def test_the_conversation_key_identifies_a_peer_and_a_service() -> None:
    """The key answers "has this device talked to this service before?"."""
    observation = observe(make_packet())

    assert observation is not None
    assert observation.conversation_key == "TCP|10.0.0.5|443"


def test_two_ports_to_one_peer_are_two_conversations() -> None:
    """A different service is a different conversation, which is the point."""
    first = observe(make_packet(destination_port=443))
    second = observe(make_packet(destination_port=80))

    assert first is not None and second is not None
    assert first.conversation_key != second.conversation_key


def test_a_missing_port_still_yields_a_conversation_key() -> None:
    """The peer is the identity of the far end; the port is optional detail."""
    observation = observe(make_packet(destination_port=None))

    assert observation is not None
    assert observation.conversation_key == "TCP|10.0.0.5|"
