"""Unit tests for the M6 TrafficStatisticsManager aggregation (M6.18).

These tests exercise the statistics engine in isolation: they feed it
``NormalizedPacket`` objects directly (no Scapy, no capture) and assert the
resulting counters, protocol distribution, per-IP activity, port activity,
traffic direction, reset behaviour and error isolation.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest

from app.schemas.packet import PacketType
from app.schemas.statistics import TrafficDirection
from app.statistics.manager import TrafficStatisticsManager
from tests.fakes import make_normalized_packet


def record(manager: TrafficStatisticsManager, count: int, **overrides: Any) -> None:
    """Record ``count`` packets described by ``overrides`` into ``manager``."""
    for index in range(count):
        manager.record_packet(make_normalized_packet(packet_id=index + 1, **overrides))


def protocol_counts(manager: TrafficStatisticsManager) -> dict[str, int]:
    """Return ``{protocol: packets}`` for the manager's protocol distribution."""
    return {stat.protocol: stat.packets for stat in manager.get_protocol_statistics()}


def direction_counts(manager: TrafficStatisticsManager) -> dict[str, int]:
    """Return ``{direction: packets}`` for the manager's direction distribution."""
    snapshot = manager.get_statistics()
    return {stat.direction.value: stat.packets for stat in snapshot.direction_statistics}


# ---------------------------------------------------------------------------
# Empty state
# ---------------------------------------------------------------------------


def test_empty_snapshot_has_zero_counters() -> None:
    """A fresh manager reports zeros and empty rankings."""
    snapshot = TrafficStatisticsManager().get_statistics()

    assert snapshot.total_packets == 0
    assert snapshot.total_bytes == 0
    assert snapshot.protocol_statistics == []
    assert snapshot.top_sources == []
    assert snapshot.top_destinations == []
    assert snapshot.top_ports == []


# ---------------------------------------------------------------------------
# Packet counts (M6.2)
# ---------------------------------------------------------------------------


def test_single_packet_is_counted() -> None:
    """Recording one packet yields a total of one."""
    manager = TrafficStatisticsManager()
    manager.record_packet(make_normalized_packet())

    assert manager.get_statistics().total_packets == 1


def test_multiple_packets_are_counted() -> None:
    """Recording several packets accumulates the total correctly."""
    manager = TrafficStatisticsManager()
    record(manager, 5)

    assert manager.get_statistics().total_packets == 5


def test_protocol_specific_packet_counts() -> None:
    """Packets are counted per protocol classification."""
    manager = TrafficStatisticsManager()
    record(manager, 3, packet_type=PacketType.TCP, protocol="TCP")
    record(manager, 2, packet_type=PacketType.UDP, protocol="UDP")
    record(manager, 1, packet_type=PacketType.ICMP, protocol="ICMP")

    assert protocol_counts(manager) == {"TCP": 3, "UDP": 2, "ICMP": 1}


# ---------------------------------------------------------------------------
# Bytes (M6.3)
# ---------------------------------------------------------------------------


def test_single_packet_bytes() -> None:
    """The packet length is used verbatim for the byte total."""
    manager = TrafficStatisticsManager()
    manager.record_packet(make_normalized_packet(length=64))

    assert manager.get_statistics().total_bytes == 64


def test_multiple_packet_bytes() -> None:
    """Byte totals are the sum of the observed packet lengths."""
    manager = TrafficStatisticsManager()
    record(manager, 4, length=250)

    assert manager.get_statistics().total_bytes == 1000


def test_bytes_per_protocol() -> None:
    """Byte totals are tracked separately for each protocol."""
    manager = TrafficStatisticsManager()
    record(manager, 2, packet_type=PacketType.TCP, protocol="TCP", length=100)
    record(manager, 1, packet_type=PacketType.UDP, protocol="UDP", length=50)

    stats = {stat.protocol: stat for stat in manager.get_protocol_statistics()}

    assert stats["TCP"].bytes == 200
    assert stats["UDP"].bytes == 50


# ---------------------------------------------------------------------------
# Protocol distribution (M6.4 / M6.11)
# ---------------------------------------------------------------------------


def test_required_protocol_labels_are_tracked() -> None:
    """TCP, UDP, ICMP, DNS, ARP and OTHER all appear as distinct labels."""
    manager = TrafficStatisticsManager()
    manager.record_packet(make_normalized_packet(packet_type=PacketType.TCP, protocol="TCP"))
    manager.record_packet(make_normalized_packet(packet_type=PacketType.UDP, protocol="UDP"))
    manager.record_packet(make_normalized_packet(packet_type=PacketType.ICMP, protocol="ICMP"))
    manager.record_packet(
        make_normalized_packet(
            packet_type=PacketType.DNS, protocol="UDP", destination_port=53
        )
    )
    manager.record_packet(
        make_normalized_packet(
            packet_type=PacketType.ARP,
            protocol="ARP",
            source_ip=None,
            destination_ip=None,
            source_port=None,
            destination_port=None,
        )
    )
    manager.record_packet(
        make_normalized_packet(
            packet_type=PacketType.OTHER,
            protocol="OTHER",
            source_ip=None,
            destination_ip=None,
            source_port=None,
            destination_port=None,
        )
    )

    assert set(protocol_counts(manager)) == {"TCP", "UDP", "ICMP", "DNS", "ARP", "OTHER"}


def test_dns_is_counted_separately_from_udp() -> None:
    """DNS traffic (which rides on UDP) is its own protocol bucket (M6.4)."""
    manager = TrafficStatisticsManager()
    manager.record_packet(
        make_normalized_packet(packet_type=PacketType.UDP, protocol="UDP", destination_port=1000)
    )
    manager.record_packet(
        make_normalized_packet(packet_type=PacketType.DNS, protocol="UDP", destination_port=53)
    )

    counts = protocol_counts(manager)

    assert counts["UDP"] == 1
    assert counts["DNS"] == 1


def test_protocol_percentages_come_from_counters() -> None:
    """Percentages are derived from actual packet counters (M6.11)."""
    manager = TrafficStatisticsManager()
    record(manager, 2, packet_type=PacketType.TCP, protocol="TCP")
    record(manager, 1, packet_type=PacketType.UDP, protocol="UDP")
    record(manager, 1, packet_type=PacketType.DNS, protocol="UDP", destination_port=53)

    percentages = {stat.protocol: stat.percentage for stat in manager.get_protocol_statistics()}

    assert percentages["TCP"] == 50.0
    assert sum(percentages.values()) == pytest.approx(100.0)


def test_unknown_rate_window_is_rejected() -> None:
    """Querying an unsupported window raises a clear error."""
    manager = TrafficStatisticsManager()
    with pytest.raises(ValueError):
        manager.get_rates("5m")


# ---------------------------------------------------------------------------
# Source / destination statistics (M6.5)
# ---------------------------------------------------------------------------


def test_source_aggregation() -> None:
    """Packets are aggregated per source IP, busiest first."""
    manager = TrafficStatisticsManager()
    record(manager, 3, source_ip="192.168.1.10", destination_ip="8.8.8.8")
    record(manager, 1, source_ip="192.168.1.20", destination_ip="8.8.8.8")

    top = manager.get_statistics().top_sources

    assert top[0].key == "192.168.1.10"
    assert top[0].packets == 3
    assert top[1].key == "192.168.1.20"


def test_destination_aggregation() -> None:
    """Packets are aggregated per destination IP, busiest first."""
    manager = TrafficStatisticsManager()
    record(manager, 2, source_ip="192.168.1.10", destination_ip="1.1.1.1")
    record(manager, 5, source_ip="192.168.1.10", destination_ip="8.8.8.8")

    top = manager.get_statistics().top_destinations

    assert top[0].key == "8.8.8.8"
    assert top[0].packets == 5


def test_source_and_destination_bytes_are_tracked() -> None:
    """Byte totals are accumulated per IP as well as per protocol."""
    manager = TrafficStatisticsManager()
    record(manager, 2, source_ip="10.0.0.1", length=128)

    top = manager.get_statistics().top_sources

    assert top[0].bytes == 256


# ---------------------------------------------------------------------------
# Port statistics (M6.5 / M6.6)
# ---------------------------------------------------------------------------


def test_destination_port_tracking() -> None:
    """Destination ports are ranked by packet count."""
    manager = TrafficStatisticsManager()
    record(manager, 4, destination_port=443)
    record(manager, 1, destination_port=80)

    ports = manager.get_top_ports(direction="destination")

    assert ports[0].key == "443"
    assert ports[0].packets == 4


def test_source_port_tracking() -> None:
    """Source ports are ranked independently of destination ports."""
    manager = TrafficStatisticsManager()
    record(manager, 3, source_port=55555)
    record(manager, 1, source_port=44444)

    ports = manager.get_top_ports(direction="source")

    assert ports[0].key == "55555"
    assert ports[0].packets == 3


def test_snapshot_top_ports_are_destination_ports() -> None:
    """The snapshot's ``top_ports`` mirrors the destination-port ranking."""
    manager = TrafficStatisticsManager()
    record(manager, 4, destination_port=443)

    assert manager.get_statistics().top_ports[0].key == "443"


def test_unknown_port_direction_is_rejected() -> None:
    """An unsupported port direction raises a clear error."""
    manager = TrafficStatisticsManager()
    with pytest.raises(ValueError):
        manager.get_top_ports(direction="sideways")


# ---------------------------------------------------------------------------
# Traffic direction (M6.7)
# ---------------------------------------------------------------------------


def test_direction_unknown_without_local_addresses() -> None:
    """Without local address context, direction is reported as unknown."""
    manager = TrafficStatisticsManager()
    record(manager, 1)

    assert direction_counts(manager) == {TrafficDirection.UNKNOWN.value: 1}


def test_direction_outbound_when_source_is_local() -> None:
    """A packet from a local address is outbound."""
    manager = TrafficStatisticsManager(local_addresses_provider=lambda: {"192.168.1.10"})
    record(manager, 1, source_ip="192.168.1.10", destination_ip="8.8.8.8")

    assert direction_counts(manager) == {TrafficDirection.OUTBOUND.value: 1}


def test_direction_inbound_when_destination_is_local() -> None:
    """A packet to a local address is inbound."""
    manager = TrafficStatisticsManager(local_addresses_provider=lambda: {"192.168.1.10"})
    record(manager, 1, source_ip="8.8.8.8", destination_ip="192.168.1.10")

    assert direction_counts(manager) == {TrafficDirection.INBOUND.value: 1}


def test_direction_local_when_both_endpoints_are_local() -> None:
    """A packet between two local addresses is local."""
    manager = TrafficStatisticsManager(
        local_addresses_provider=lambda: {"192.168.1.10", "192.168.1.11"}
    )
    record(manager, 1, source_ip="192.168.1.10", destination_ip="192.168.1.11")

    assert direction_counts(manager) == {TrafficDirection.LOCAL.value: 1}


def test_direction_unknown_when_neither_endpoint_is_local() -> None:
    """Traffic with no local endpoint is unknown rather than guessed."""
    manager = TrafficStatisticsManager(local_addresses_provider=lambda: {"192.168.1.10"})
    record(manager, 1, source_ip="8.8.8.8", destination_ip="1.1.1.1")

    assert direction_counts(manager) == {TrafficDirection.UNKNOWN.value: 1}


def test_direction_provider_failure_is_unknown() -> None:
    """A failing local-address provider falls back to unknown."""

    def boom() -> set[str]:
        raise RuntimeError("interface discovery failed")

    manager = TrafficStatisticsManager(local_addresses_provider=boom)
    record(manager, 1)

    assert direction_counts(manager) == {TrafficDirection.UNKNOWN.value: 1}


def test_direction_provider_is_not_called_per_packet() -> None:
    """The local-address provider is cached, not re-run for every packet.

    Interface discovery costs milliseconds; running it per packet would cap
    capture throughput far below the measured per-packet aggregation cost.
    """
    calls = 0

    def counting_provider() -> set[str]:
        nonlocal calls
        calls += 1
        return {"192.168.1.10"}

    manager = TrafficStatisticsManager(local_addresses_provider=counting_provider)
    record(manager, 500)

    assert calls == 1
    assert direction_counts(manager) == {TrafficDirection.OUTBOUND.value: 500}


def test_setting_a_new_provider_invalidates_the_cache() -> None:
    """Replacing the provider takes effect immediately on the next packet."""
    manager = TrafficStatisticsManager(
        local_addresses_provider=lambda: {"192.168.1.10"}
    )
    record(manager, 1)  # source local -> outbound

    manager.set_local_addresses_provider(lambda: {"8.8.8.8"})
    record(manager, 1)  # destination local -> inbound

    assert direction_counts(manager) == {
        TrafficDirection.OUTBOUND.value: 1,
        TrafficDirection.INBOUND.value: 1,
    }


# ---------------------------------------------------------------------------
# Reset (M6.17)
# ---------------------------------------------------------------------------


def test_reset_clears_all_counters() -> None:
    """Reset clears totals, rankings and time-window data."""
    manager = TrafficStatisticsManager()
    record(manager, 3)
    manager.reset()

    snapshot = manager.get_statistics()

    assert snapshot.total_packets == 0
    assert snapshot.total_bytes == 0
    assert snapshot.protocol_statistics == []
    assert snapshot.top_sources == []
    assert snapshot.top_destinations == []
    assert snapshot.top_ports == []
    assert manager.get_rates("1s") == (0.0, 0.0)


# ---------------------------------------------------------------------------
# Error isolation (M6.15)
# ---------------------------------------------------------------------------


def test_invalid_packet_is_ignored() -> None:
    """An unusable packet is swallowed, not counted and never raised."""
    manager = TrafficStatisticsManager()
    manager.record_packet(object())  # type: ignore[arg-type]

    assert manager.get_statistics().total_packets == 0


def test_failure_does_not_stop_subsequent_packets() -> None:
    """A single bad packet does not prevent later packets being counted."""
    manager = TrafficStatisticsManager()
    manager.record_packet(object())  # type: ignore[arg-type]
    manager.record_packet(make_normalized_packet())

    assert manager.get_statistics().total_packets == 1


# ---------------------------------------------------------------------------
# Thread safety (M6.13)
# ---------------------------------------------------------------------------


def test_concurrent_recording_is_consistent() -> None:
    """Concurrent writers do not lose or double-count packets."""
    manager = TrafficStatisticsManager()
    packets_per_thread = 400
    thread_count = 8

    def worker() -> None:
        for _ in range(packets_per_thread):
            manager.record_packet(make_normalized_packet(length=1))

    workers = [threading.Thread(target=worker) for _ in range(thread_count)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()

    snapshot = manager.get_statistics()

    assert snapshot.total_packets == packets_per_thread * thread_count
    assert snapshot.total_bytes == packets_per_thread * thread_count
