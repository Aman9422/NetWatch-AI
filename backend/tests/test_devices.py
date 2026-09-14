"""Unit tests for device discovery and tracking (M8.20).

These tests drive ``DeviceDiscoveryManager`` directly with normalized packets —
no Scapy, no capture, no API — and assert the behaviour the milestone requires:
discovery, addressing, tracking, status, the MAC/IP registry, cleanup, query
filters, enrichment and error containment.
"""

from __future__ import annotations

import threading
from collections.abc import Callable

import pytest

from app.devices.device import ObservedDevice
from app.devices.local import LocalIdentity
from app.devices.manager import DeviceDiscoveryManager
from app.devices.registry import DeviceRegistry
from app.schemas.device import DeviceStatus
from app.schemas.packet import NormalizedPacket
from tests.fakes import PACKET_BASE_TIME, FakeClock, make_normalized_packet

# Both MACs must be unicast (even first octet), or the identity rules reject
# them: a multicast/broadcast MAC can never identify a single device.
MAC_A = "AA:BB:CC:DD:EE:FF"
MAC_B = "22:33:44:55:66:77"
IP_A = "192.168.1.10"
IP_B = "192.168.1.20"

INACTIVITY = 60.0
RETENTION = 600.0


def make_manager(
    clock: FakeClock | None = None,
    *,
    inactivity_threshold: float = INACTIVITY,
    retention_seconds: float = RETENTION,
    max_devices: int = 4096,
    local_identity_provider: Callable[[], LocalIdentity] | None = None,
    local_hostname_provider: Callable[[], str | None] | None = None,
    hostname_resolver: Callable[[str], str | None] | None = None,
    vendor_resolver: Callable[[str | None], str | None] | None = None,
) -> DeviceDiscoveryManager:
    """Return a manager with deterministic thresholds and an injectable clock."""
    return DeviceDiscoveryManager(
        max_devices=max_devices,
        inactivity_threshold=inactivity_threshold,
        retention_seconds=retention_seconds,
        clock=clock if clock is not None else FakeClock(PACKET_BASE_TIME),
        local_identity_provider=local_identity_provider,
        local_hostname_provider=local_hostname_provider,
        hostname_resolver=hostname_resolver,
        vendor_resolver=vendor_resolver,
    )


def packet(
    *,
    source_mac: str | None = None,
    destination_mac: str | None = None,
    source_ip: str | None = IP_A,
    destination_ip: str | None = None,
    length: int = 100,
    timestamp: float = PACKET_BASE_TIME,
) -> NormalizedPacket:
    """Build a packet that names one endpoint by default."""
    return make_normalized_packet(
        source_mac=source_mac,
        destination_mac=destination_mac,
        source_ip=source_ip,
        destination_ip=destination_ip,
        length=length,
        timestamp=timestamp,
    )


# -- discovery -----------------------------------------------------------


def test_first_packet_creates_a_device() -> None:
    """A single observed endpoint produces exactly one device record."""
    manager = make_manager()

    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))

    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert device.mac_address == MAC_A
    assert device.ip_addresses == {IP_A}
    assert device.packet_count == 1
    assert device.packets_sent == 1
    assert manager.get_device_count() == 1
    assert manager.get_error_count() == 0


def test_later_packets_update_instead_of_duplicating() -> None:
    """Repeated observations of one MAC update the existing record."""
    manager = make_manager()

    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))
    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))

    assert manager.get_device_count() == 1
    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert device.packet_count == 2


def test_mac_identity_wins_over_the_ip() -> None:
    """An endpoint with a MAC is keyed by the MAC, not the address."""
    manager = make_manager()

    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))

    assert manager.get_device(f"mac:{MAC_A}") is not None
    assert manager.get_device(f"ip:{IP_A}") is None
    device = manager.registry.get_by_ip(IP_A)
    assert device is not None
    assert device is manager.registry.get_by_mac(MAC_A)


def test_endpoint_without_a_mac_is_identified_by_ip() -> None:
    """A MAC-less endpoint falls back to an ``ip:`` identity."""
    manager = make_manager()

    manager.process_packet(packet(source_mac=None, source_ip=IP_A))

    device = manager.get_device(f"ip:{IP_A}")
    assert device is not None
    assert device.mac_address is None
    assert device.ip_addresses == {IP_A}


def test_both_endpoints_are_attributed_to_their_devices() -> None:
    """Source and destination are counted on the correct devices (M8.5)."""
    manager = make_manager()

    manager.process_packet(
        packet(
            source_mac=MAC_A,
            source_ip=IP_A,
            destination_mac=MAC_B,
            destination_ip=IP_B,
            length=200,
        )
    )

    source_device = manager.get_device(f"mac:{MAC_A}")
    destination_device = manager.get_device(f"mac:{MAC_B}")
    assert source_device is not None and destination_device is not None
    assert source_device.packets_sent == 1
    assert source_device.packets_received == 0
    assert source_device.byte_count == 200
    assert destination_device.packets_received == 1
    assert destination_device.packets_sent == 0
    assert destination_device.byte_count == 200
    assert manager.get_device_count() == 2


def test_packet_without_trackable_endpoints_is_ignored() -> None:
    """A packet naming no real host changes nothing and raises nothing."""
    manager = make_manager()

    manager.process_packet(
        packet(source_mac=None, source_ip=None, destination_ip=None)
    )

    assert manager.get_device_count() == 0
    assert manager.get_error_count() == 0


# -- addressing ----------------------------------------------------------


def test_device_accumulates_multiple_ip_addresses() -> None:
    """One MAC observed under two addresses stays one device (M8.6)."""
    manager = make_manager()

    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))
    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_B))

    assert manager.get_device_count() == 1
    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert device.ip_addresses == {IP_A, IP_B}
    assert manager.registry.get_by_ip(IP_A) is device
    assert manager.registry.get_by_ip(IP_B) is device


def test_ipv6_addresses_are_tracked_and_canonicalized() -> None:
    """IPv6 endpoints are tracked and folded to one spelling."""
    manager = make_manager()

    manager.process_packet(packet(source_mac=MAC_A, source_ip="FE80::1"))

    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert device.ip_addresses == {"fe80::1"}


def test_device_can_be_observed_without_an_ip() -> None:
    """A MAC-only observation (e.g. some ARP traffic) is still tracked."""
    manager = make_manager()

    manager.process_packet(packet(source_mac=MAC_A, source_ip=None))

    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert device.ip_addresses == set()


def test_ip_only_hosts_seen_over_ipv4_and_ipv6_stay_separate() -> None:
    """Without a MAC there is no evidence the two addresses are one host."""
    manager = make_manager()

    manager.process_packet(packet(source_mac=None, source_ip=IP_A))
    manager.process_packet(packet(source_mac=None, source_ip="fe80::1"))

    assert manager.get_device_count() == 2


# -- tracking (M8.4/M8.5) ------------------------------------------------


def test_first_seen_is_kept_and_last_seen_moves() -> None:
    """``first_seen`` is set once; ``last_seen`` follows the newest packet."""
    clock = FakeClock(PACKET_BASE_TIME)
    manager = make_manager(clock)

    manager.process_packet(
        packet(source_mac=MAC_A, source_ip=IP_A, timestamp=clock.now())
    )
    clock.advance(5)
    manager.process_packet(
        packet(source_mac=MAC_A, source_ip=IP_A, timestamp=clock.now())
    )

    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert device.first_seen == PACKET_BASE_TIME
    assert device.last_seen == PACKET_BASE_TIME + 5


def test_packet_and_byte_counters_accumulate() -> None:
    """Packet and byte totals sum every observation of the device."""
    manager = make_manager()

    for length in (100, 200, 300):
        manager.process_packet(
            packet(source_mac=MAC_A, source_ip=IP_A, length=length)
        )

    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert device.packet_count == 3
    assert device.byte_count == 600
    assert device.packets_sent == 3
    assert device.bytes_sent == 600


def test_direction_counters_separate_sent_and_received() -> None:
    """Sending and receiving are counted independently (M8.5)."""
    manager = make_manager()

    manager.process_packet(
        packet(
            source_mac=MAC_A,
            source_ip=IP_A,
            destination_mac=MAC_B,
            destination_ip=IP_B,
        )
    )
    manager.process_packet(
        packet(
            source_mac=MAC_A,
            source_ip=IP_A,
            destination_mac=MAC_B,
            destination_ip=IP_B,
        )
    )
    manager.process_packet(
        packet(
            source_mac=MAC_B,
            source_ip=IP_B,
            destination_mac=MAC_A,
            destination_ip=IP_A,
        )
    )

    device_a = manager.get_device(f"mac:{MAC_A}")
    device_b = manager.get_device(f"mac:{MAC_B}")
    assert device_a is not None and device_b is not None
    assert (device_a.packets_sent, device_a.packets_received) == (2, 1)
    assert (device_b.packets_sent, device_b.packets_received) == (1, 2)
    assert device_a.packet_count == 3
    assert device_b.packet_count == 3


# -- status (M8.9) -------------------------------------------------------


def test_status_is_active_while_traffic_is_recent() -> None:
    """A device seen within the threshold is active."""
    clock = FakeClock(PACKET_BASE_TIME)
    manager = make_manager(clock)
    manager.process_packet(
        packet(source_mac=MAC_A, source_ip=IP_A, timestamp=clock.now())
    )

    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert (
        device.status(now=clock.now(), inactivity_threshold=INACTIVITY)
        is DeviceStatus.ACTIVE
    )


def test_status_becomes_inactive_after_the_threshold() -> None:
    """Inactivity is decided by last-seen age, never by traffic volume."""
    clock = FakeClock(PACKET_BASE_TIME)
    manager = make_manager(clock)
    manager.process_packet(
        packet(source_mac=MAC_A, source_ip=IP_A, timestamp=clock.now())
    )
    clock.advance(INACTIVITY + 1)

    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert (
        device.status(now=clock.now(), inactivity_threshold=INACTIVITY)
        is DeviceStatus.INACTIVE
    )


def test_high_traffic_does_not_keep_a_stale_device_active() -> None:
    """Volume is irrelevant — an old device is inactive regardless of bytes."""
    clock = FakeClock(PACKET_BASE_TIME)
    manager = make_manager(clock)
    manager.process_packet(
        packet(
            source_mac=MAC_A,
            source_ip=IP_A,
            length=5_000_000,
            timestamp=clock.now(),
        )
    )
    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    clock.advance(INACTIVITY + 1)

    assert (
        device.status(now=clock.now(), inactivity_threshold=INACTIVITY)
        is DeviceStatus.INACTIVE
    )


def test_status_is_unknown_without_a_timestamp() -> None:
    """A record with no timing information reports ``unknown``."""
    device = ObservedDevice(device_id=f"mac:{MAC_A}")

    assert (
        device.status(now=PACKET_BASE_TIME, inactivity_threshold=INACTIVITY)
        is DeviceStatus.UNKNOWN
    )


# -- registry mappings (M8.16) ------------------------------------------


def test_ip_moving_to_a_new_mac_repoints_and_counts_a_conflict() -> None:
    """An address that changes owner is repointed; the devices never merge."""
    manager = make_manager()

    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))
    manager.process_packet(packet(source_mac=MAC_B, source_ip=IP_A))

    assert manager.get_device_count() == 2
    assert manager.get_conflict_count() == 1
    assert manager.get_upgrade_count() == 0
    device_a = manager.get_device(f"mac:{MAC_A}")
    device_b = manager.get_device(f"mac:{MAC_B}")
    assert device_a is not None and device_b is not None
    assert device_a.ip_addresses == set()
    assert device_b.ip_addresses == {IP_A}
    assert manager.registry.get_by_ip(IP_A) is device_b


def test_ip_only_record_is_upgraded_when_a_mac_appears() -> None:
    """An ``ip:`` record adopts a MAC without losing its counters (M8.16)."""
    manager = make_manager()

    manager.process_packet(packet(source_mac=None, source_ip=IP_A, length=100))
    manager.process_packet(packet(source_mac=None, source_ip=IP_A, length=100))
    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A, length=100))

    assert manager.get_device_count() == 1
    assert manager.get_upgrade_count() == 1
    assert manager.get_conflict_count() == 0
    assert manager.get_device(f"ip:{IP_A}") is None
    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert device.packet_count == 3
    assert device.byte_count == 300
    assert device.first_seen == PACKET_BASE_TIME
    assert device.ip_addresses == {IP_A}


def test_two_mac_devices_are_never_silently_merged() -> None:
    """Two MACs that share an address stay two distinct devices."""
    manager = make_manager()

    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))
    manager.process_packet(packet(source_mac=MAC_B, source_ip=IP_A))

    assert manager.get_device(f"mac:{MAC_A}") is not None
    assert manager.get_device(f"mac:{MAC_B}") is not None


def test_registry_requires_a_positive_capacity() -> None:
    """A registry with no capacity is rejected outright."""
    with pytest.raises(ValueError):
        DeviceRegistry(max_devices=0)


# -- cleanup (M8.13/M8.14) ----------------------------------------------


def test_remove_expired_devices_removes_only_stale_records() -> None:
    """Only devices past the retention window are cleaned up."""
    clock = FakeClock(PACKET_BASE_TIME)
    manager = make_manager(clock)

    manager.process_packet(
        packet(source_mac=MAC_A, source_ip=IP_A, timestamp=clock.now())
    )
    clock.advance(100)
    manager.process_packet(
        packet(source_mac=MAC_B, source_ip=IP_B, timestamp=clock.now())
    )
    clock.advance(RETENTION)  # A is now 700s old, B is exactly 600s old.

    removed = manager.remove_expired_devices()

    assert removed == 1
    assert manager.get_device(f"mac:{MAC_A}") is None
    assert manager.get_device(f"mac:{MAC_B}") is not None
    assert manager.get_device_count() == 1


def test_removing_a_device_clears_its_mappings() -> None:
    """Cleanup leaves no stale MAC/IP mapping behind."""
    clock = FakeClock(PACKET_BASE_TIME)
    manager = make_manager(clock)
    manager.process_packet(
        packet(source_mac=MAC_A, source_ip=IP_A, timestamp=clock.now())
    )
    clock.advance(RETENTION + 1)

    removed = manager.remove_expired_devices()

    assert removed == 1
    assert manager.registry.get_by_mac(MAC_A) is None
    assert manager.registry.get_by_ip(IP_A) is None
    assert manager.list_ip_addresses() == []


def test_a_quiet_device_is_not_removed_by_inactivity_alone() -> None:
    """Traffic stopping changes status, it does not delete the device."""
    clock = FakeClock(PACKET_BASE_TIME)
    manager = make_manager(clock)
    manager.process_packet(
        packet(source_mac=MAC_A, source_ip=IP_A, timestamp=clock.now())
    )

    clock.advance(INACTIVITY + 1)
    removed = manager.remove_expired_devices()

    assert removed == 0
    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert (
        device.status(now=clock.now(), inactivity_threshold=INACTIVITY)
        is DeviceStatus.INACTIVE
    )


# -- capacity (M8.14) ---------------------------------------------------


def test_capacity_cap_evicts_the_stalest_device() -> None:
    """The registry stays bounded by evicting the least recently seen device."""
    clock = FakeClock(PACKET_BASE_TIME)
    manager = make_manager(clock, max_devices=2)

    for index, mac in enumerate((MAC_A, MAC_B, "44:55:66:77:88:99")):
        manager.process_packet(
            packet(
                source_mac=mac,
                source_ip=f"192.168.1.{index + 10}",
                timestamp=clock.now(),
            )
        )
        clock.advance(1)

    assert manager.get_device_count() == 2
    assert manager.get_eviction_count() == 1
    assert manager.get_device(f"mac:{MAC_A}") is None


def test_capacity_never_evicts_the_device_just_observed() -> None:
    """The newest observation always survives, even at capacity one."""
    manager = make_manager(max_devices=1)

    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))
    manager.process_packet(packet(source_mac=MAC_B, source_ip=IP_B))

    assert manager.get_device_count() == 1
    assert manager.get_device(f"mac:{MAC_B}") is not None


# -- queries and filters (M8.18/M8.19) ----------------------------------


def test_list_devices_is_sorted_by_most_recently_seen() -> None:
    """The most recently active device is listed first."""
    clock = FakeClock(PACKET_BASE_TIME)
    manager = make_manager(clock)
    manager.process_packet(
        packet(source_mac=MAC_A, source_ip=IP_A, timestamp=clock.now())
    )
    clock.advance(10)
    manager.process_packet(
        packet(source_mac=MAC_B, source_ip=IP_B, timestamp=clock.now())
    )

    ordered = [device.mac_address for device in manager.list_devices()]

    assert ordered == [MAC_B, MAC_A]


def test_list_devices_filters_by_status() -> None:
    """Activity state can be used as a filter."""
    clock = FakeClock(PACKET_BASE_TIME)
    manager = make_manager(clock)
    manager.process_packet(
        packet(source_mac=MAC_A, source_ip=IP_A, timestamp=clock.now())
    )
    clock.advance(INACTIVITY + 1)
    manager.process_packet(
        packet(source_mac=MAC_B, source_ip=IP_B, timestamp=clock.now())
    )

    inactive = manager.list_devices(status="inactive")
    active = manager.list_devices(status=DeviceStatus.ACTIVE)

    assert [device.mac_address for device in inactive] == [MAC_A]
    assert [device.mac_address for device in active] == [MAC_B]


def test_list_devices_filters_by_ip_and_mac() -> None:
    """Address filters are normalized before matching."""
    manager = make_manager()
    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))

    assert [d.mac_address for d in manager.list_devices(ip=IP_A)] == [MAC_A]
    assert manager.list_devices(ip="10.0.0.1") == []
    assert [d.mac_address for d in manager.list_devices(mac=MAC_A.lower())] == [MAC_A]
    assert manager.list_devices(mac=MAC_B) == []


def test_list_devices_respects_a_limit() -> None:
    manager = make_manager()
    for index in range(3):
        manager.process_packet(
            packet(
                source_mac=f"AA:BB:CC:DD:EE:{index:02X}",
                source_ip=f"192.168.1.{index + 10}",
            )
        )

    assert len(manager.list_devices(limit=2)) == 2


def test_list_devices_rejects_a_non_positive_limit() -> None:
    manager = make_manager()
    with pytest.raises(ValueError):
        manager.list_devices(limit=0)


def test_list_devices_rejects_an_unknown_status() -> None:
    manager = make_manager()
    with pytest.raises(ValueError):
        manager.list_devices(status="bogus")


def test_get_device_view_returns_none_for_an_unknown_id() -> None:
    manager = make_manager()
    assert manager.get_device_view(f"mac:{MAC_A}") is None


def test_device_view_projects_status_and_counters() -> None:
    """The API projection carries the observed statistics (M8.19)."""
    clock = FakeClock(PACKET_BASE_TIME)
    manager = make_manager(clock)
    manager.process_packet(
        packet(source_mac=MAC_A, source_ip=IP_A, timestamp=clock.now())
    )

    view = manager.get_device_view(f"mac:{MAC_A}")

    assert view is not None
    assert view.device_id == f"mac:{MAC_A}"
    assert view.mac_address == MAC_A
    assert view.ip_addresses == [IP_A]
    assert view.status is DeviceStatus.ACTIVE
    assert view.packet_count == 1
    assert view.byte_count == 100
    assert view.first_seen is not None
    assert view.last_seen is not None


# -- enrichment: local identity, hostname, vendor (M8.10/M8.11/M8.12) ----


def test_local_device_is_flagged_and_given_the_local_hostname() -> None:
    """The monitoring host is identified from interfaces, not hard-coded."""
    local = LocalIdentity(mac_addresses=frozenset({MAC_A}))
    manager = make_manager(
        local_identity_provider=lambda: local,
        local_hostname_provider=lambda: "monitor-host",
    )

    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))

    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert device.is_local is True
    assert device.hostname == "monitor-host"


def test_remote_device_is_not_flagged_local() -> None:
    local = LocalIdentity(mac_addresses=frozenset({MAC_A}))
    manager = make_manager(
        local_identity_provider=lambda: local,
        local_hostname_provider=lambda: "monitor-host",
    )

    manager.process_packet(packet(source_mac=MAC_B, source_ip=IP_B))

    device = manager.get_device(f"mac:{MAC_B}")
    assert device is not None
    assert device.is_local is False
    assert device.hostname is None


def test_local_identity_provider_is_cached_between_packets() -> None:
    """Interface enumeration must not run once per packet (M8.10)."""
    calls: list[int] = []

    def provider() -> LocalIdentity:
        calls.append(1)
        return LocalIdentity(mac_addresses=frozenset({MAC_A}))

    manager = make_manager(local_identity_provider=provider)
    for _ in range(50):
        manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))

    assert len(calls) == 1


def test_hostname_resolver_fills_in_a_hostname() -> None:
    """A configured resolver enriches a device without blocking ingestion."""
    manager = make_manager(hostname_resolver=lambda _ip: "printer.lan")
    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))

    manager.resolve_hostname(f"mac:{MAC_A}")

    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert device.hostname == "printer.lan"


def test_hostname_resolver_failure_is_ignored() -> None:
    """A failing resolver leaves the hostname unknown and never raises."""

    def resolver(_ip: str) -> str | None:
        raise RuntimeError("simulated DNS failure")

    manager = make_manager(hostname_resolver=resolver)
    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))
    manager.resolve_hostname(f"mac:{MAC_A}")

    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert device.hostname is None
    assert manager.get_error_count() == 0


def test_vendor_resolver_attaches_a_vendor() -> None:
    """A vendor is only recorded when a resolver supplies one (M8.12)."""
    manager = make_manager(vendor_resolver=lambda _mac: "Acme Networks")
    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))

    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert device.vendor == "Acme Networks"


def test_no_vendor_is_invented_without_a_resolver() -> None:
    manager = make_manager()
    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))

    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert device.vendor is None


def test_vendor_resolver_failure_does_not_break_discovery() -> None:
    """Enrichment is best-effort; a failure must not lose the device."""

    def resolver(_mac: str | None) -> str | None:
        raise RuntimeError("simulated OUI lookup failure")

    manager = make_manager(vendor_resolver=resolver)
    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))

    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert device.vendor is None
    assert manager.get_error_count() == 0


# -- error handling (M8.17) ---------------------------------------------


def test_malformed_packet_is_counted_and_dropped() -> None:
    """A packet that cannot be read is swallowed, never raised."""
    manager = make_manager()

    manager.process_packet(object())  # type: ignore[arg-type]

    assert manager.get_error_count() == 1
    assert manager.get_device_count() == 0


def test_update_device_returns_none_for_an_unknown_id() -> None:
    manager = make_manager()
    assert manager.update_device(f"mac:{MAC_B}", hostname="x") is None


def test_update_device_applies_fields_to_a_known_device() -> None:
    manager = make_manager()
    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))

    updated = manager.update_device(f"mac:{MAC_A}", hostname="nas.lan", vendor="Acme")

    assert updated is not None
    assert updated.hostname == "nas.lan"
    assert updated.vendor == "Acme"


def test_reset_clears_devices_mappings_and_diagnostics() -> None:
    manager = make_manager()
    manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))
    manager.process_packet(object())  # type: ignore[arg-type]

    manager.reset()

    assert manager.get_device_count() == 0
    assert manager.get_error_count() == 0
    assert manager.get_conflict_count() == 0
    assert manager.get_upgrade_count() == 0
    assert manager.get_eviction_count() == 0
    assert manager.registry.get_by_mac(MAC_A) is None
    assert manager.registry.get_by_ip(IP_A) is None


# -- constructor validation ---------------------------------------------


def test_negative_inactivity_threshold_is_rejected() -> None:
    with pytest.raises(ValueError):
        DeviceDiscoveryManager(inactivity_threshold=-1.0)


def test_retention_must_exceed_the_inactivity_threshold() -> None:
    with pytest.raises(ValueError):
        DeviceDiscoveryManager(inactivity_threshold=100.0, retention_seconds=100.0)


# -- concurrency (M8.15) ------------------------------------------------


def test_concurrent_packets_are_counted_exactly() -> None:
    """Concurrent observers never lose an increment (M8.15)."""
    manager = make_manager()
    thread_count = 4
    packets_per_thread = 250

    def feed() -> None:
        for _ in range(packets_per_thread):
            manager.process_packet(packet(source_mac=MAC_A, source_ip=IP_A))

    threads = [threading.Thread(target=feed) for _ in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    device = manager.get_device(f"mac:{MAC_A}")
    assert device is not None
    assert device.packet_count == thread_count * packets_per_thread
    assert manager.get_error_count() == 0


def test_readers_can_run_while_packets_are_being_processed() -> None:
    """Reads during ingestion are consistent and never raise (M8.15)."""
    manager = make_manager()
    failures: list[BaseException] = []
    stop = threading.Event()

    def reader() -> None:
        try:
            while not stop.is_set():
                manager.list_device_views()
                manager.get_device_count()
        except BaseException as error:  # noqa: BLE001 - surfaced by the assertion
            failures.append(error)

    def writer() -> None:
        for index in range(500):
            manager.process_packet(
                packet(
                    source_mac=f"AA:BB:CC:DD:{index // 256:02X}:{index % 256:02X}",
                    source_ip=None,
                )
            )

    reader_thread = threading.Thread(target=reader)
    writer_thread = threading.Thread(target=writer)
    reader_thread.start()
    writer_thread.start()
    writer_thread.join()
    stop.set()
    reader_thread.join()

    assert failures == []
    assert manager.get_device_count() > 0
