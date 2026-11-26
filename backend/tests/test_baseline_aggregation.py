"""Window-aggregation tests (M21.5).

The aggregator is where "a packet happened" becomes "this device did this much in
this minute", and three of M21's requirements live or die here:

* **Windows are floored on the packet clock**, so two runs over the same traffic
  produce the same windows regardless of when aggregation started.
* **A device changing IP keeps its window**, because the key is the MAC identity
  and not the address.
* **Nothing is silently overwritten.** A device transmitting while the flush
  thread is behind must keep every window it filled; only ``close_expired`` or
  ``drain`` removes one.

The last one is a regression test rather than a hypothetical: keying the map by
device alone lost every window but the newest, which made a device's sample count
depend on how quickly the disk drained a backlog.
"""

from __future__ import annotations

import pytest

from app.baselines.aggregation import (
    WindowAggregator,
    WindowCounters,
    floor_window,
    window_start_datetime,
)
from app.baselines.features import PacketObservation
from app.schemas.packet import PacketType

DEVICE = "mac:aa:bb:cc:dd:ee:01"
OTHER = "mac:aa:bb:cc:dd:ee:02"

#: A whole number of minutes, so flooring is exact and readable.
BASE = 1_700_000_040.0


def observation(
    *,
    device_key: str = DEVICE,
    mac: str = "aa:bb:cc:dd:ee:01",
    ip: str = "10.0.0.21",
    peer: str | None = "10.0.0.5",
    port: int | None = 443,
    length: int = 100,
    protocol: str = "TCP",
    packet_type: PacketType = PacketType.TCP,
) -> PacketObservation:
    """Build one observation, defaulting to a plain TCP packet."""
    return PacketObservation(
        device_key=device_key,
        identity_kind="mac",
        mac_address=mac,
        ip_address=ip,
        peer_ip=peer,
        destination_port=port,
        length=length,
        protocol=protocol,
        packet_type=packet_type,
        is_syn=False,
    )


# ---------------------------------------------------------------------------
# flooring
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        (0.0, 0.0),
        (59.9, 0.0),
        (60.0, 60.0),
        (61.0, 60.0),
        (119.999, 60.0),
        (120.0, 120.0),
    ],
)
def test_a_window_starts_at_a_multiple_of_its_length(
    timestamp: float, expected: float
) -> None:
    """Boundaries are deterministic and independent of when aggregation began."""
    assert floor_window(timestamp, 60.0) == expected


def test_a_window_length_of_zero_is_rejected() -> None:
    """Zero would put every packet in one window or in infinitely many."""
    with pytest.raises(ValueError):
        floor_window(1.0, 0.0)


def test_a_window_start_is_stored_as_naive_utc() -> None:
    """One conversion, so a window row and a profile row cannot disagree."""
    moment = window_start_datetime(BASE)

    assert moment.tzinfo is None
    assert moment.year == 2023


# ---------------------------------------------------------------------------
# one device, one window
# ---------------------------------------------------------------------------


def test_packets_in_one_window_accumulate_into_one_sample() -> None:
    """Everything within a window is folded into a single counter set."""
    aggregator = WindowAggregator(window_seconds=60.0)
    for _ in range(5):
        aggregator.observe_packet(observation(length=100), at=BASE)

    closed = aggregator.drain()

    assert len(closed) == 1
    counters = closed[0]
    assert counters.packet_count == 5
    assert counters.byte_count == 500
    assert counters.tcp_packets == 5
    assert counters.first_seen == BASE
    assert counters.last_seen == BASE


def test_protocol_counts_are_kept_separately() -> None:
    """A mixed window reports each transport, and DNS on top of its transport."""
    aggregator = WindowAggregator(window_seconds=60.0)
    aggregator.observe_packet(observation(protocol="TCP"), at=BASE)
    aggregator.observe_packet(observation(protocol="UDP"), at=BASE)
    aggregator.observe_packet(observation(protocol="ICMP"), at=BASE)
    aggregator.observe_packet(
        observation(protocol="UDP", packet_type=PacketType.DNS), at=BASE
    )

    counters = aggregator.drain()[0]

    assert counters.packet_count == 4
    assert counters.tcp_packets == 1
    assert counters.udp_packets == 2
    assert counters.icmp_packets == 1
    assert counters.dns_packets == 1


def test_distinct_peers_and_ports_are_counted_not_stored() -> None:
    """A profile reports how many peers, never which ones (M21.8)."""
    aggregator = WindowAggregator(window_seconds=60.0)
    for peer, port in [
        ("10.0.0.5", 443),
        ("10.0.0.5", 80),
        ("10.0.0.6", 443),
    ]:
        aggregator.observe_packet(observation(peer=peer, port=port), at=BASE)

    counters = aggregator.drain()[0]

    assert counters.unique_peers == 2
    assert counters.unique_destination_ports == 2


def test_a_repeated_conversation_is_not_a_new_connection() -> None:
    """Only the first sighting of a conversation counts as a new connection."""
    aggregator = WindowAggregator(window_seconds=60.0)
    aggregator.observe_packet(observation(peer="10.0.0.5", port=443), at=BASE)
    aggregator.observe_packet(observation(peer="10.0.0.5", port=443), at=BASE)
    aggregator.observe_packet(observation(peer="10.0.0.6", port=443), at=BASE)

    counters = aggregator.drain()[0]

    assert counters.new_connections == 2


def test_a_packet_with_no_peer_contributes_no_connection_and_no_key() -> None:
    """A conversation with an unknown far end cannot honestly be counted."""
    aggregator = WindowAggregator(window_seconds=60.0)
    aggregator.observe_packet(observation(peer=None, port=None), at=BASE)

    counters = aggregator.drain()[0]

    assert counters.packet_count == 1
    assert counters.unique_peers == 0
    assert counters.new_connections == 0
    assert counters.conversation_keys == set()


# ---------------------------------------------------------------------------
# window boundaries
# ---------------------------------------------------------------------------


def test_two_windows_of_one_device_are_two_samples() -> None:
    """Crossing a boundary starts a new window; it does not extend the old one."""
    aggregator = WindowAggregator(window_seconds=60.0)
    aggregator.observe_packet(observation(), at=BASE)
    aggregator.observe_packet(observation(), at=BASE + 60.0)

    closed = aggregator.drain()

    assert len(closed) == 2
    assert {counters.window_start for counters in closed} == {BASE, BASE + 60.0}
    assert all(counters.packet_count == 1 for counters in closed)


def test_an_unflushed_window_survives_a_later_one() -> None:
    """The defect this replaced: a newer window used to overwrite the older.

    A device transmitting while the flush thread is behind must keep every window
    it filled. Losing one would make the sample count depend on flush timing
    rather than on observed behaviour.
    """
    aggregator = WindowAggregator(window_seconds=60.0)
    for index in range(6):
        aggregator.observe_packet(observation(), at=BASE + index * 60.0)

    assert aggregator.pending_windows == 6
    assert aggregator.tracked_devices == 1

    closed = aggregator.drain()

    assert len(closed) == 6
    assert sorted(counters.window_start for counters in closed) == [
        BASE + index * 60.0 for index in range(6)
    ]


def test_close_expired_keeps_the_current_window_and_closes_the_rest() -> None:
    """The window a packet at ``now`` would fall in is never closed early."""
    aggregator = WindowAggregator(window_seconds=60.0)
    aggregator.observe_packet(observation(), at=BASE)
    aggregator.observe_packet(observation(), at=BASE + 60.0)

    closed = aggregator.close_expired(now=BASE + 60.0)

    assert len(closed) == 1
    assert closed[0].window_start == BASE
    assert aggregator.pending_windows == 1


def test_a_closed_window_is_not_returned_twice() -> None:
    """Which is what makes a flush idempotent at the in-memory layer too."""
    aggregator = WindowAggregator(window_seconds=60.0)
    aggregator.observe_packet(observation(), at=BASE)

    assert len(aggregator.close_expired(now=BASE + 60.0)) == 1
    assert aggregator.close_expired(now=BASE + 60.0) == []


def test_drain_closes_the_current_window_as_well() -> None:
    """Shutdown keeps a partial window: those are real observations."""
    aggregator = WindowAggregator(window_seconds=60.0)
    aggregator.observe_packet(observation(), at=BASE)
    aggregator.observe_packet(observation(), at=BASE + 1.0)

    closed = aggregator.drain()

    assert len(closed) == 1
    assert closed[0].packet_count == 2
    assert aggregator.pending_windows == 0


# ---------------------------------------------------------------------------
# two devices stay two devices
# ---------------------------------------------------------------------------


def test_two_devices_never_share_a_window() -> None:
    """Separation is the whole point: one device's traffic is not another's."""
    aggregator = WindowAggregator(window_seconds=60.0)
    aggregator.observe_packet(observation(device_key=DEVICE), at=BASE)
    aggregator.observe_packet(
        observation(device_key=OTHER, mac="aa:bb:cc:dd:ee:02"), at=BASE
    )

    closed = aggregator.drain()
    by_device = {counters.device_key: counters for counters in closed}

    assert len(closed) == 2
    assert by_device[DEVICE].packet_count == 1
    assert by_device[OTHER].packet_count == 1


def test_a_device_keeping_its_mac_across_an_ip_change_keeps_its_windows() -> None:
    """A DHCP lease change must not split one device into two baselines.

    The key is the M8 string identity, which is ``mac:...`` whenever a MAC was
    observed, so the address moving is invisible to aggregation.
    """
    aggregator = WindowAggregator(window_seconds=60.0)
    aggregator.observe_packet(observation(ip="10.0.0.21"), at=BASE)
    aggregator.observe_packet(observation(ip="10.0.0.99"), at=BASE + 60.0)

    closed = aggregator.drain()

    assert len(closed) == 2
    assert {counters.device_key for counters in closed} == {DEVICE}


def test_a_different_mac_is_a_different_device_even_from_the_same_ip() -> None:
    """Reusing an address is not the same as being the same device.

    The IP-keyed fallback identity is what can legitimately collide here, which is
    why a MAC is preferred whenever one is present.
    """
    aggregator = WindowAggregator(window_seconds=60.0)
    aggregator.observe_packet(observation(device_key=DEVICE, ip="10.0.0.21"), at=BASE)
    aggregator.observe_packet(
        observation(device_key=OTHER, mac="aa:bb:cc:dd:ee:02", ip="10.0.0.21"),
        at=BASE,
    )

    closed = aggregator.drain()

    assert {counters.device_key for counters in closed} == {DEVICE, OTHER}


# ---------------------------------------------------------------------------
# bounded by construction
# ---------------------------------------------------------------------------


def test_the_device_cap_evicts_the_stalest_window() -> None:
    """A flood of spoofed addresses costs an eviction, not unbounded memory."""
    aggregator = WindowAggregator(window_seconds=60.0, max_devices=2)
    for index in range(4):
        aggregator.observe_packet(
            observation(device_key=f"mac:aa:bb:cc:dd:ee:{index:02x}"),
            at=BASE + index,
        )

    assert aggregator.pending_windows == 2
    assert aggregator.get_eviction_count() == 2


def test_the_newest_window_is_never_the_one_evicted() -> None:
    """Evicting the observation that triggered the eviction would lose it."""
    aggregator = WindowAggregator(window_seconds=60.0, max_devices=2)
    for index in range(4):
        aggregator.observe_packet(
            observation(device_key=f"mac:aa:bb:cc:dd:ee:{index:02x}"),
            at=BASE + index,
        )

    survivors = {counters.device_key for counters in aggregator.drain()}

    assert "mac:aa:bb:cc:dd:ee:03" in survivors


def test_the_peer_cap_marks_the_cardinality_as_truncated() -> None:
    """A full set reports a floor rather than a number it never measured."""
    aggregator = WindowAggregator(window_seconds=60.0, max_peers=2)
    for index in range(5):
        aggregator.observe_packet(observation(peer=f"10.0.0.{index}"), at=BASE)

    counters = aggregator.drain()[0]

    assert counters.unique_peers == 2
    assert counters.peers_truncated is True


def test_the_port_cap_marks_the_cardinality_as_truncated() -> None:
    """A port flood is contained the same way a peer flood is."""
    aggregator = WindowAggregator(window_seconds=60.0, max_ports=2)
    for port in (80, 443, 8080, 9000):
        aggregator.observe_packet(observation(port=port), at=BASE)

    counters = aggregator.drain()[0]

    assert counters.unique_destination_ports == 2
    assert counters.ports_truncated is True


def test_the_connection_key_cap_stops_claiming_new_connections() -> None:
    """Past the cap a new conversation cannot be told from a forgotten one."""
    aggregator = WindowAggregator(window_seconds=60.0, max_connection_keys=2)
    for port in (80, 443, 8080):
        aggregator.observe_packet(observation(port=port), at=BASE)

    counters = aggregator.drain()[0]

    assert counters.new_connections == 2
    assert aggregator.get_conversation_cap_count() == 1


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"window_seconds": 0.0}, "window_seconds"),
        ({"max_devices": 0}, "max_devices"),
        ({"max_peers": 0}, "max_peers"),
        ({"max_ports": 0}, "max_ports"),
        ({"max_connection_keys": 0}, "max_connection_keys"),
    ],
)
def test_a_nonsensical_cap_is_rejected(
    kwargs: dict[str, float], message: str
) -> None:
    """A zero cap would make every observation a skip, silently."""
    with pytest.raises(ValueError, match=message):
        WindowAggregator(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# resetting one device
# ---------------------------------------------------------------------------


def test_forget_device_drops_all_of_its_windows_and_its_memory() -> None:
    """A reset must clear every window, or an older one could undo it on flush."""
    aggregator = WindowAggregator(window_seconds=60.0)
    aggregator.observe_packet(observation(), at=BASE)
    aggregator.observe_packet(observation(), at=BASE + 60.0)
    aggregator.observe_packet(observation(device_key=OTHER), at=BASE)

    aggregator.forget_device(DEVICE)

    survivors = aggregator.drain()

    assert {counters.device_key for counters in survivors} == {OTHER}

    # And the conversation memory is gone, so the first packet afterwards counts
    # as a new connection again.
    aggregator.observe_packet(observation(peer="10.0.0.5", port=443), at=BASE + 120.0)
    assert aggregator.drain()[0].new_connections == 1


def test_reset_clears_every_window_and_every_counter() -> None:
    """Used by tests and by a full reload; it leaves nothing behind."""
    aggregator = WindowAggregator(window_seconds=60.0, max_devices=1)
    aggregator.observe_packet(observation(device_key=DEVICE), at=BASE)
    aggregator.observe_packet(observation(device_key=OTHER), at=BASE)

    aggregator.reset()

    assert aggregator.pending_windows == 0
    assert aggregator.get_eviction_count() == 0
    assert aggregator.get_skipped_count() == 0
    assert aggregator.get_conversation_cap_count() == 0


def test_an_unusable_observation_is_skipped_rather_than_raised() -> None:
    """One unattributable packet must not interrupt capture (M21.5)."""
    aggregator = WindowAggregator(window_seconds=60.0)

    assert aggregator.observe_packet(None, at=BASE) is False  # type: ignore[arg-type]
    assert aggregator.get_skipped_count() == 1
    assert aggregator.pending_windows == 0


def test_a_window_that_observed_nothing_is_not_a_sample() -> None:
    """The guard that stops a zero-valued row being written (M21.5)."""
    counters = WindowCounters(
        device_key=DEVICE,
        identity_kind="mac",
        window_start=BASE,
        window_seconds=60.0,
    )

    assert counters.observed is False
    assert counters.packet_count == 0
