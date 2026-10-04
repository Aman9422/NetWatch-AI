"""Tests for bounded buffering and rate control (M14.15/M14.16).

Two different guarantees are tested here, and they are easy to conflate:

* **A queue has a fixed cap and never exceeds it.** The cap is set per channel when
  the connection is built and is never raised, so a client that stops reading cannot
  make the server allocate without limit. When the cap is reached the *oldest*
  message is discarded, because a stale packet is worth less than the one that just
  arrived — and the drop is counted, because an invisible drop is indistinguishable
  from a bug.
* **A channel has a rate ceiling.** Only the packet channel has one, and it is
  applied per channel rather than per connection, so ten subscribers cannot multiply
  the publishing work by ten.

The distinction the design draws, and that the file pins down, is that a dropped
alert event is not a *lost alert*: the alert is in SQLite and is served by
``GET /api/v1/alerts``. The socket is a live view of that record. So the alerts
channel is deliberately given the largest queue of the four and no rate ceiling, and
neither of those is an accident of configuration.

The rate limiter's token bucket is tested directly as well as through the manager.
Going through the manager only ever exercises a bucket that starts full and is
drained within microseconds; passing ``now`` explicitly is what makes the refill
behaviour — the part a real deployment lives with — deterministic instead of
timing-dependent.
"""

from __future__ import annotations

import asyncio

import pytest

from app.websockets.channels import CHANNELS, Channel
from app.websockets.event import EventType
from app.websockets.policy import (
    ChannelPolicy,
    DropStrategy,
    PolicySet,
    TokenBucket,
    build_policy_set,
    default_policies,
)
from tests.ws_fakes import (
    asyncio_test,
    clean_websockets,  # noqa: F401 - fixture, imported for this module
    connect_fake,
    make_event,
    make_manager,
    make_policies,
    managed,
    packet_event,
    policies_from,
    queued_count,
    queued_messages,
    settings_with,
    settle,
)


def _packets(queue_size: int, *, rate: float | None = None) -> PolicySet:
    """Return a policy table with the packet queue depth and rate set.

    The packet channel is the one every buffering test drives, so it is the one
    parameterised; the other three keep their documented values.
    """
    return make_policies(packet_queue_size=queue_size, packet_rate=rate)


def _sequences(connection) -> list[int]:
    """Return the envelope sequence of every queued message, in queue order."""
    return [message["sequence"] for message in queued_messages(connection)]


# ---------------------------------------------------------------------------
# The cap comes from the policy, not from the connection (M14.15)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_the_queue_depth_comes_from_the_channel_policy() -> None:
    """A connection is sized before it can receive anything, from its channel."""
    manager = make_manager(policies=_packets(7, rate=None))
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.PACKETS)

        assert connection.max_queue == 7
        assert connection.queue.maxsize == 7


@asyncio_test
async def test_each_channel_uses_its_own_queue_depth() -> None:
    """The channels are deliberately not uniform, so this is per channel."""
    manager = make_manager(
        policies=make_policies(packet_queue_size=4, alert_queue_size=9)
    )
    async with managed(manager):
        _, on_packets = await connect_fake(manager, Channel.PACKETS)
        _, on_alerts = await connect_fake(manager, Channel.ALERTS)

        assert on_packets.max_queue == 4
        assert on_alerts.max_queue == 9


def test_the_documented_defaults_are_the_ones_the_design_states() -> None:
    """The four depths and the one ceiling, asserted against the design's table."""
    policies = default_policies()

    assert policies.queue_size(Channel.PACKETS) == 256
    assert policies.queue_size(Channel.DASHBOARD) == 32
    assert policies.queue_size(Channel.ALERTS) == 512
    assert policies.queue_size(Channel.SYSTEM) == 128
    assert policies.policy(Channel.PACKETS).max_events_per_second == 200.0


def test_every_channel_drops_the_oldest() -> None:
    """One strategy, stated explicitly rather than implied by an ``if``."""
    for channel in CHANNELS:
        assert default_policies().policy(channel).drop_strategy == (
            DropStrategy.DROP_OLDEST
        )


def test_the_policy_table_is_built_from_the_settings() -> None:
    """``build_policy_set`` is the only place settings meet the socket layer."""
    policies = policies_from(
        packet_ws_queue_size=12,
        packet_ws_max_events_per_second=33.0,
        packet_ws_enabled=False,
        websocket_alert_queue_size=77,
    )

    assert policies.queue_size(Channel.PACKETS) == 12
    assert policies.policy(Channel.PACKETS).max_events_per_second == 33.0
    assert policies.policy(Channel.PACKETS).enabled is False
    assert policies.queue_size(Channel.ALERTS) == 77


def test_a_queue_size_below_one_is_refused_at_construction() -> None:
    """A depth of zero would make every event a drop: a bug, not a choice."""
    with pytest.raises(ValueError):
        ChannelPolicy(channel=Channel.PACKETS, queue_size=0)


def test_a_negative_rate_is_refused_at_construction() -> None:
    """A negative ceiling would silently drop everything, so it fails loudly."""
    with pytest.raises(ValueError):
        ChannelPolicy(channel=Channel.PACKETS, queue_size=4, max_events_per_second=-1.0)


# ---------------------------------------------------------------------------
# Below, at and over the cap (M14.15)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_a_queue_below_its_limit_keeps_every_message() -> None:
    """Under the cap nothing is discarded and nothing is counted as discarded."""
    manager = make_manager(policies=_packets(4, rate=None))
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.PACKETS)

        for sequence in range(1, 4):
            manager.broadcast(packet_event(sequence=sequence))

        assert queued_count(connection) == 3
        assert connection.counters.dropped_queue_full == 0
        assert _sequences(connection) == [1, 2, 3]


@asyncio_test
async def test_a_queue_exactly_at_its_limit_keeps_every_message() -> None:
    """The cap is inclusive: a full queue is not yet an overflow."""
    manager = make_manager(policies=_packets(4, rate=None))
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.PACKETS)

        for sequence in range(1, 5):
            manager.broadcast(packet_event(sequence=sequence))

        assert queued_count(connection) == 4
        assert connection.counters.dropped_queue_full == 0
        assert _sequences(connection) == [1, 2, 3, 4]


@asyncio_test
async def test_a_queue_over_its_limit_drops_the_oldest() -> None:
    """Two events over a three-deep queue means the two oldest are gone."""
    manager = make_manager(policies=_packets(3, rate=None))
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.PACKETS)

        for sequence in range(1, 6):
            manager.broadcast(packet_event(sequence=sequence))

        assert queued_count(connection) == 3
        assert connection.counters.dropped_queue_full == 2
        assert _sequences(connection) == [3, 4, 5]


@asyncio_test
async def test_the_newest_event_is_the_one_that_survives_a_race() -> None:
    """A live view wants the current observation, not the stale one.

    Stated as its own test because it is the *choice* in the drop policy, not a
    side effect of the queue implementation: dropping the newest would be equally
    easy to write and would make a subscriber see a stale packet forever.
    """
    manager = make_manager(policies=_packets(1, rate=None))
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.PACKETS)

        for sequence in range(1, 6):
            manager.broadcast(packet_event(sequence=sequence))

        assert _sequences(connection) == [5]


@asyncio_test
async def test_a_flood_never_grows_the_queue_past_its_cap() -> None:
    """The bound holds at every point during an overrun, not only at the end.

    Checked after every broadcast rather than once at the end: "the queue never
    exceeds its cap" is a statement about every instant, and a queue that spiked
    and then drained would satisfy an end-of-run assertion while still being
    unbounded memory in production.
    """
    manager = make_manager(policies=_packets(5, rate=None))
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.PACKETS)

        for sequence in range(1, 201):
            manager.broadcast(packet_event(sequence=sequence))
            assert queued_count(connection) <= 5

        assert queued_count(connection) == 5
        assert connection.counters.dropped_queue_full == 195
        assert _sequences(connection) == [196, 197, 198, 199, 200]


@asyncio_test
async def test_the_drop_counter_is_kept_per_connection() -> None:
    """A dashboard must be able to name the one client that is not keeping up."""
    manager = make_manager(policies=_packets(2, rate=None))
    async with managed(manager):
        _, first = await connect_fake(manager, Channel.PACKETS)
        _, second = await connect_fake(manager, Channel.PACKETS)

        for sequence in range(1, 5):
            manager.broadcast(packet_event(sequence=sequence))

        assert first.counters.dropped_queue_full == 2
        assert second.counters.dropped_queue_full == 2
        assert queued_count(first) == 2
        assert queued_count(second) == 2


@asyncio_test
async def test_a_full_queue_still_counts_as_a_delivery() -> None:
    """The connection did receive the event; it discarded an older one for room."""
    manager = make_manager(policies=_packets(2, rate=None))
    async with managed(manager):
        await connect_fake(manager, Channel.PACKETS)

        assert manager.broadcast(packet_event(sequence=1)) == 1
        assert manager.broadcast(packet_event(sequence=2)) == 1
        assert manager.broadcast(packet_event(sequence=3)) == 1


@asyncio_test
async def test_the_sender_draining_the_queue_makes_room_again() -> None:
    """The cap bounds the *buffer*, not throughput: a reading client is unlimited.

    Each event is offered and then given to the sender before the next, so the
    queue is empty each time and the drop path is never taken — which is what
    distinguishes a bounded queue from a clipped feed.
    """
    manager = make_manager(policies=_packets(2, rate=None))
    async with managed(manager):
        socket, connection = await connect_fake(manager, Channel.PACKETS)

        for sequence in range(1, 6):
            manager.broadcast(packet_event(sequence=sequence))
            await settle()

        assert connection.counters.dropped_queue_full == 0
        assert socket.types() == [EventType.PACKET_OBSERVED] * 5


# ---------------------------------------------------------------------------
# The packet channel's rate ceiling (M14.16)
# ---------------------------------------------------------------------------


def test_only_the_packet_channel_carries_a_rate_ceiling() -> None:
    """The other three are bounded by their producer, not by a bucket.

    An alert is raised at most once per deduplication window per rule and source, so
    its rate is already bounded by M11; a dashboard tick is bounded by its interval.
    Putting a bucket on either would mean discarding a security event to save work
    that is already cheap.
    """
    policies = default_policies()

    assert policies.policy(Channel.PACKETS).max_events_per_second == 200.0
    for channel in (Channel.DASHBOARD, Channel.ALERTS, Channel.SYSTEM):
        assert policies.policy(channel).max_events_per_second is None


@asyncio_test
async def test_the_packet_channel_allows_a_burst_up_to_its_bucket() -> None:
    """The bucket is sized to one second of allowance, so a burst fits initially.

    A quiet period is not wasted: it is exactly what lets a short burst through
    without the client seeing a hard per-second edge.
    """
    manager = make_manager(policies=_packets(64, rate=3.0))
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.PACKETS)

        accepted = [
            manager.broadcast(packet_event(sequence=sequence))
            for sequence in range(1, 4)
        ]

        assert accepted == [1, 1, 1]
        assert queued_count(connection) == 3
        assert connection.counters.dropped_queue_full == 0


@asyncio_test
async def test_the_packet_channel_refuses_once_the_bucket_is_empty() -> None:
    """One event per second means the second event cannot go out immediately."""
    manager = make_manager(policies=_packets(64, rate=1.0))
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.PACKETS)

        assert manager.broadcast(packet_event(sequence=1)) == 1
        assert manager.broadcast(packet_event(sequence=2)) == 0

        assert queued_count(connection) == 1
        assert manager.get_counters()["dropped_rate_limited"] == 1


@asyncio_test
async def test_a_rate_limited_event_reaches_no_subscriber() -> None:
    """The ceiling is a channel ceiling: nobody receives the event it refused."""
    manager = make_manager(policies=_packets(64, rate=1.0))
    async with managed(manager):
        _, first = await connect_fake(manager, Channel.PACKETS)
        _, second = await connect_fake(manager, Channel.PACKETS)

        manager.broadcast(packet_event(sequence=1))
        manager.broadcast(packet_event(sequence=2))

        assert queued_count(first) == 1
        assert queued_count(second) == 1
        assert _sequences(first) == [1]


@asyncio_test
async def test_a_rate_limited_event_is_not_counted_as_a_broadcast() -> None:
    """``broadcast`` counts fan-outs it performed, so a refusal is not one.

    Distinguishing the two counters is what lets the benchmark say whether a low
    delivery number came from the ceiling or from an empty registry.
    """
    manager = make_manager(policies=_packets(64, rate=1.0))
    async with managed(manager):
        await connect_fake(manager, Channel.PACKETS)

        manager.broadcast(packet_event(sequence=1))
        manager.broadcast(packet_event(sequence=2))

        counters = manager.get_counters()
        assert counters["broadcast"] == 1
        assert counters["delivered"] == 1
        assert counters["dropped_rate_limited"] == 1


@asyncio_test
async def test_the_ceiling_is_per_channel_not_per_connection() -> None:
    """Ten subscribers must not multiply the publishing work by ten.

    Three clients on a one-per-second channel still see one event in total: the
    budget is the channel's, and it is spent once rather than once per socket.
    """
    manager = make_manager(policies=_packets(64, rate=1.0), max_connections_per_channel=8)
    async with managed(manager):
        connections = []
        for _ in range(3):
            _, connection = await connect_fake(manager, Channel.PACKETS)
            connections.append(connection)

        assert manager.broadcast(packet_event(sequence=1)) == 3
        assert manager.broadcast(packet_event(sequence=2)) == 0

        for connection in connections:
            assert queued_count(connection) == 1

        assert manager.get_counters()["dropped_rate_limited"] == 1


@asyncio_test
async def test_the_alert_channel_is_not_rate_limited() -> None:
    """A burst of alerts is delivered in full, because an alert is the product.

    The alerts channel has the largest queue of the four and no ceiling: a dropped
    alert *event* is not a lost alert, but there is no reason to make one happen for
    a saving that the alert rate already provides.
    """
    manager = make_manager(policies=make_policies(alert_queue_size=512))
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.ALERTS)

        delivered = [
            manager.broadcast(
                make_event(
                    event_type=EventType.ALERT_CREATED,
                    channel=Channel.ALERTS,
                    sequence=sequence,
                )
            )
            for sequence in range(1, 101)
        ]

        assert delivered == [1] * 100
        assert connection.counters.dropped_queue_full == 0
        assert manager.get_counters()["dropped_rate_limited"] == 0


@asyncio_test
async def test_a_burst_that_exhausts_the_packet_bucket_leaves_alerts_untouched() -> None:
    """The two channels side by side, which is the comparison M14.15 asks for."""
    manager = make_manager(
        policies=make_policies(packet_queue_size=64, packet_rate=5.0, alert_queue_size=64)
    )
    async with managed(manager):
        _, on_packets = await connect_fake(manager, Channel.PACKETS)
        _, on_alerts = await connect_fake(manager, Channel.ALERTS)

        packets = sum(
            manager.broadcast(packet_event(sequence=sequence))
            for sequence in range(1, 11)
        )
        alerts = sum(
            manager.broadcast(
                make_event(
                    event_type=EventType.ALERT_CREATED,
                    channel=Channel.ALERTS,
                    sequence=sequence,
                )
            )
            for sequence in range(1, 11)
        )

        assert packets == 5
        assert alerts == 10
        assert queued_count(on_packets) == 5
        assert queued_count(on_alerts) == 10
        assert manager.get_counters()["dropped_rate_limited"] == 5


@asyncio_test
async def test_a_rate_limited_channel_is_served_again_once_tokens_refill() -> None:
    """A ceiling is a rate, not a ban: the channel recovers on its own.

    The only timing-dependent test in the file, and it is written with a rate wide
    enough (100/s) that a 50 ms wait is several tokens rather than a coin toss — the
    alternative would be a one-second sleep per assertion.
    """
    manager = make_manager(policies=_packets(64, rate=100.0))
    async with managed(manager):
        await connect_fake(manager, Channel.PACKETS)

        for sequence in range(1, 401):
            manager.broadcast(packet_event(sequence=sequence))

        assert manager.get_counters()["dropped_rate_limited"] >= 50
        served = manager.get_counters()["broadcast"]

        await asyncio.sleep(0.05)

        assert manager.broadcast(packet_event(sequence=10_000)) == 1
        assert manager.get_counters()["broadcast"] == served + 1


# ---------------------------------------------------------------------------
# The token bucket on its own (M14.16)
# ---------------------------------------------------------------------------


def test_an_unlimited_bucket_never_refuses() -> None:
    """``None`` is how "no ceiling" is expressed, rather than a huge number."""
    bucket = TokenBucket(None)

    assert bucket.unlimited is True
    assert bucket.rate_per_second is None
    assert all(bucket.allow() for _ in range(10_000))


def test_a_bucket_starts_full_and_allows_exactly_its_capacity() -> None:
    """A fresh bucket holds one second of allowance, which is a burst."""
    bucket = TokenBucket(3.0)
    moment = 1_000_000.0

    assert [bucket.allow(now=moment) for _ in range(3)] == [True, True, True]
    assert bucket.allow(now=moment) is False


def test_a_bucket_refills_continuously_rather_than_once_a_second() -> None:
    """Half a token's worth of time buys half a token, not nothing.

    A bucket that reset on the second would refuse here and then allow a full burst
    at the boundary, which is the hard edge M14.16 avoids.
    """
    bucket = TokenBucket(2.0)
    moment = 1_000_000.0
    bucket.allow(now=moment)
    bucket.allow(now=moment)

    assert bucket.allow(now=moment + 0.25) is False
    assert bucket.allow(now=moment + 0.50) is True


def test_a_bucket_never_holds_more_than_its_capacity() -> None:
    """A long quiet period banks one second of allowance, not an unbounded credit."""
    bucket = TokenBucket(1.0)

    assert bucket.allow(now=1_000.0) is True
    assert bucket.allow(now=1_100.0) is True
    assert bucket.allow(now=1_100.0) is False


def test_a_bucket_does_not_refill_into_the_past() -> None:
    """A clock that moves backwards must not mint tokens."""
    bucket = TokenBucket(1.0)

    assert bucket.allow(now=1_000.0) is True
    assert bucket.allow(now=1_000.0) is False
    assert bucket.allow(now=999.0) is False
    assert bucket.allow(now=1_000.5) is True


def test_a_zero_rate_bucket_refuses_every_event() -> None:
    """A rate of zero is a valid policy that means "switched off", not a crash."""
    bucket = TokenBucket(0.0)

    assert bucket.unlimited is False
    assert bucket.allow(now=1_000.0) is False


def test_the_policy_set_consults_the_channels_own_bucket() -> None:
    """Two channels, two budgets: one being spent does not spend the other's."""
    policies = make_policies(packet_rate=2.0)
    moment = 1_000_000.0

    assert policies.allow(Channel.PACKETS, now=moment) is True
    assert policies.allow(Channel.PACKETS, now=moment) is True
    assert policies.allow(Channel.PACKETS, now=moment) is False
    assert policies.allow(Channel.ALERTS, now=moment) is True


def test_a_disabled_channel_is_refused_before_its_bucket_is_consulted() -> None:
    """``packet_ws_enabled`` off is a zero-cost path, not a spent token."""
    policies = make_policies(packet_enabled=False, packet_rate=None)

    assert policies.is_enabled(Channel.PACKETS) is False
    assert policies.allow(Channel.PACKETS) is False
    assert policies.is_enabled(Channel.ALERTS) is True


def test_the_settings_path_builds_a_bucket_per_channel() -> None:
    """One bucket per channel, carrying the ceiling the settings asked for."""
    policies = build_policy_set(settings_with(packet_ws_max_events_per_second=5.0))

    assert set(policies.buckets) == set(CHANNELS)
    assert policies.buckets[Channel.PACKETS].rate_per_second == 5.0
    assert policies.buckets[Channel.ALERTS].unlimited is True
