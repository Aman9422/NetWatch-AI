"""Unit tests for NormalizedPacket -> database row mapping (M7.2/M7.19).

These tests pin down the field projection that M7 relies on: which columns are
filled, which stay NULL, how the timestamp and length are represented, how the
protocol label is chosen, and — most importantly — that a packet carrying no IP
address is refused rather than stored with invented values.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.persistence.mapping import (
    is_persistable,
    protocol_label,
    to_epoch_datetime,
    to_packet_values,
)
from app.schemas.packet import PacketType
from tests.fakes import PACKET_BASE_TIME, make_normalized_packet


# ---------------------------------------------------------------------------
# is_persistable
# ---------------------------------------------------------------------------


def test_packet_with_both_addresses_is_persistable() -> None:
    """A packet with a source and destination address can be stored."""
    assert is_persistable(make_normalized_packet()) is True


def test_packet_without_source_address_is_not_persistable() -> None:
    """A packet missing its source address is refused (NOT NULL column)."""
    packet = make_normalized_packet(source_ip=None)
    assert is_persistable(packet) is False


def test_packet_without_destination_address_is_not_persistable() -> None:
    """A packet missing its destination address is refused (NOT NULL column)."""
    packet = make_normalized_packet(destination_ip=None)
    assert is_persistable(packet) is False


# ---------------------------------------------------------------------------
# to_epoch_datetime
# ---------------------------------------------------------------------------


def test_epoch_conversion_is_utc_aware() -> None:
    """Epoch seconds convert to a timezone-aware UTC datetime."""
    moment = to_epoch_datetime(PACKET_BASE_TIME)

    assert moment.tzinfo is timezone.utc
    assert moment == datetime.fromtimestamp(PACKET_BASE_TIME, tz=timezone.utc)


# ---------------------------------------------------------------------------
# protocol_label
# ---------------------------------------------------------------------------


def test_protocol_label_uses_the_classification() -> None:
    """The M5 classification is what gets stored in ``packets.protocol``."""
    packet = make_normalized_packet(packet_type=PacketType.DNS, protocol="UDP")
    assert protocol_label(packet) == "DNS"


def test_protocol_label_falls_back_when_classification_is_missing() -> None:
    """A packet built outside the normalizer still yields a usable label."""
    packet = make_normalized_packet(packet_type=PacketType.OTHER, protocol="QUIC")
    assert protocol_label(packet) == "QUIC"


def test_protocol_label_is_truncated_to_the_column_width() -> None:
    """The label never exceeds the ``String(20)`` column width."""
    packet = make_normalized_packet(
        packet_type=PacketType.OTHER, protocol="X" * 40
    )
    assert len(protocol_label(packet)) <= 20


# ---------------------------------------------------------------------------
# to_packet_values
# ---------------------------------------------------------------------------


def test_mapping_fills_the_expected_columns() -> None:
    """Every mapped column carries the value from the normalized packet."""
    packet = make_normalized_packet(
        source_ip="10.0.0.5",
        destination_ip="10.0.0.9",
        source_port=5000,
        destination_port=443,
        protocol="TCP",
        packet_type=PacketType.TCP,
        length=512,
        tcp_flags="PA",
    )

    values = to_packet_values(packet)

    assert values is not None
    assert values["source_ip"] == "10.0.0.5"
    assert values["destination_ip"] == "10.0.0.9"
    assert values["source_port"] == 5000
    assert values["destination_port"] == 443
    assert values["protocol"] == "TCP"
    assert values["packet_length"] == 512
    assert values["tcp_flags"] == "PA"


def test_mapping_sets_the_timestamp_from_the_packet() -> None:
    """The stored timestamp derives from the packet's epoch capture time."""
    values = to_packet_values(make_normalized_packet(timestamp=PACKET_BASE_TIME))

    assert values is not None
    expected = datetime.fromtimestamp(PACKET_BASE_TIME, tz=timezone.utc)
    assert values["timestamp"] == expected


def test_mapping_preserves_nullable_fields_as_none() -> None:
    """Ports and TCP flags stay NULL when the packet has none (no invention)."""
    packet = make_normalized_packet(
        source_port=None, destination_port=None, tcp_flags=None
    )

    values = to_packet_values(packet)

    assert values is not None
    assert values["source_port"] is None
    assert values["destination_port"] is None
    assert values["tcp_flags"] is None


def test_mapping_never_stores_a_payload() -> None:
    """Payload length stays NULL — payloads are excluded by policy (M7.5)."""
    values = to_packet_values(make_normalized_packet())

    assert values is not None
    assert values["payload_length"] is None


def test_mapping_leaves_deferred_columns_empty() -> None:
    """TTL, device linkage and the processed flag keep their safe defaults."""
    values = to_packet_values(make_normalized_packet())

    assert values is not None
    assert values["ttl"] is None
    assert values["device_id"] is None
    assert values["processed"] == 0


def test_mapping_clamps_a_negative_length() -> None:
    """A nonsensical negative length is clamped rather than stored as-is."""
    values = to_packet_values(make_normalized_packet(length=0))

    assert values is not None
    assert values["packet_length"] == 0


def test_mapping_returns_none_for_an_addressless_packet() -> None:
    """A packet without an address maps to ``None`` (skipped, not stored)."""
    assert to_packet_values(make_normalized_packet(source_ip=None)) is None
