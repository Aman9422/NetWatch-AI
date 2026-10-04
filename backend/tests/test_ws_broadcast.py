"""Tests for channel fan-out and client isolation (M14.27).

M14.6 makes channel separation *structural*: a channel is a property of the
connection, fixed when it dialled its path, and the manager keeps one registry per
channel. Fan-out walks only that channel's registry, so a packet subscriber cannot
receive an alert because of a filter that somebody forgot to apply — there is no
filter, and no code path from a packet event to an alert subscriber.

This file tests that property from the outside: who receives a broadcast, who does
not, what the return value means, and what happens to the rest of a channel when one
client turns out to be broken (M14.14).

Two observables are used deliberately, because they answer different questions:

* the **queue** — asserted on synchronously, immediately after ``broadcast`` returns,
  with no ``await`` in between. Nothing has run, so the queue shows exactly what the
  fan-out decided;
* the **socket** — asserted on after yielding to the loop, which is where the
  *sender* task has drained the queue onto the socket. A write failure is only
  observable there, because it is the sender that discovers it.

The file covers one subscriber, many subscribers, the delivery count, channel
isolation in both directions, directed sends, a client that vanished, a client that
stalls, and that neither of those disturbs the rest of the channel.
"""

from __future__ import annotations

import asyncio

from app.websockets.channels import CHANNELS, Channel
from app.websockets.event import EventType
from tests.ws_fakes import (
    asyncio_test,
    clean_websockets,  # noqa: F401 - fixture, imported for this module
    capture_status,
    connect_fake,
    make_event,
    make_manager,
    make_policies,
    managed,
    packet_event,
    queued_count,
    queued_types,
    settle,
)

#: The channel each event type travels on, per the design's §6 vocabulary.
CHANNEL_FOR_EVENT_TYPE = {
    EventType.PACKET_OBSERVED: Channel.PACKETS,
    EventType.DASHBOARD_UPDATED: Channel.DASHBOARD,
    EventType.ALERT_CREATED: Channel.ALERTS,
    EventType.SERVICE_STATUS: Channel.SYSTEM,
}


def _unlimited_packets():
    """Return a policy table with no packet rate ceiling.

    Rate control is tested in ``test_ws_backpressure.py``; every test here wants to
    observe fan-out, so the ceiling is lifted rather than repeatedly worked around.
    """
    return make_policies(packet_rate=None)


# ---------------------------------------------------------------------------
# One subscriber and many (M14.2)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_broadcast_reaches_a_single_subscriber() -> None:
    """The smallest case: one client on the channel gets the event."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        socket, _ = await connect_fake(manager, Channel.PACKETS)

        assert manager.broadcast(packet_event()) == 1
        await settle()

        assert socket.types() == [EventType.PACKET_OBSERVED]


@asyncio_test
async def test_broadcast_reaches_every_subscriber_on_the_channel() -> None:
    """Fan-out is to all of them, not to the first one found."""
    manager = make_manager(policies=_unlimited_packets(), max_connections_per_channel=8)
    async with managed(manager):
        sockets = []
        for _ in range(5):
            socket, _ = await connect_fake(manager, Channel.PACKETS)
            sockets.append(socket)

        assert manager.broadcast(packet_event()) == 5
        await settle()

        assert all(
            socket.types() == [EventType.PACKET_OBSERVED] for socket in sockets
        )


@asyncio_test
async def test_broadcast_returns_the_number_of_clients_it_was_queued_for() -> None:
    """The return value is a delivery count, which is what makes it diagnosable."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        await connect_fake(manager, Channel.PACKETS)
        await connect_fake(manager, Channel.PACKETS)

        assert manager.broadcast(packet_event()) == 2


@asyncio_test
async def test_broadcast_with_no_subscribers_delivers_to_nobody() -> None:
    """An event nobody wants is cheap: no queue, no write, and a zero back."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        assert manager.broadcast(packet_event()) == 0
        assert manager.get_counters()["broadcast"] == 1


@asyncio_test
async def test_broadcast_queues_one_encoded_frame_per_client() -> None:
    """The event is encoded once and offered to each subscriber unchanged.

    The queue is inspected without yielding, so this is the fan-out decision itself
    rather than the sender's timing.
    """
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        _, first = await connect_fake(manager, Channel.PACKETS)
        _, second = await connect_fake(manager, Channel.PACKETS)

        manager.broadcast(packet_event())

        assert queued_count(first) == 1
        assert queued_count(second) == 1
        assert queued_types(first) == queued_types(second)


# ---------------------------------------------------------------------------
# Channel separation (M14.6)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_a_packet_event_reaches_only_the_packet_channel() -> None:
    """Structural separation: the alerts subscriber is not even considered."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        _, on_packets = await connect_fake(manager, Channel.PACKETS)
        _, on_alerts = await connect_fake(manager, Channel.ALERTS)
        _, on_system = await connect_fake(manager, Channel.SYSTEM)

        assert manager.broadcast(packet_event()) == 1

        assert queued_count(on_packets) == 1
        assert queued_count(on_alerts) == 0
        assert queued_count(on_system) == 0


@asyncio_test
async def test_an_event_reaches_only_its_own_channel_for_every_type() -> None:
    """Each documented event type lands on exactly one channel's subscribers."""
    manager = make_manager(policies=_unlimited_packets(), max_connections_per_channel=8)
    async with managed(manager):
        connections = {}
        for channel in CHANNELS:
            _, connection = await connect_fake(manager, channel)
            connections[channel] = connection

        for event_type, owning_channel in CHANNEL_FOR_EVENT_TYPE.items():
            manager.broadcast(make_event(event_type=event_type, channel=owning_channel))

        for channel, connection in connections.items():
            for event_type, owning_channel in CHANNEL_FOR_EVENT_TYPE.items():
                if owning_channel is channel:
                    continue
                assert event_type not in queued_types(connection)


@asyncio_test
async def test_a_system_event_does_not_reach_the_packet_channel() -> None:
    """The reverse direction of the same property, stated on its own.

    ``capture.started`` is the event a dashboard most wants and a packet subscriber
    has no use for; a leak in either direction would be equally wrong.
    """
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        _, on_packets = await connect_fake(manager, Channel.PACKETS)
        _, on_system = await connect_fake(manager, Channel.SYSTEM)

        from app.websockets.builders import capture_event

        manager.broadcast(capture_event(EventType.CAPTURE_STARTED, capture_status()))

        assert queued_count(on_system) == 1
        assert queued_count(on_packets) == 0
# ---------------------------------------------------------------------------
# Directed sends (M14.2)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_send_delivers_to_one_connection_only() -> None:
    """``send`` is the directed counterpart of ``broadcast``: a ping, not a topic."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        _, target = await connect_fake(manager, Channel.SYSTEM)
        _, other = await connect_fake(manager, Channel.SYSTEM)

        assert manager.send(target.client_id, make_event()) is True

        assert queued_count(target) == 1
        assert queued_count(other) == 0


@asyncio_test
async def test_send_returns_false_for_an_unknown_id() -> None:
    """A directed send to nobody is a ``False``, not an error (M14.18)."""
    manager = make_manager()
    async with managed(manager):
        assert manager.send("wsc-not-here", make_event()) is False


@asyncio_test
async def test_send_returns_false_for_a_closed_connection() -> None:
    """A client that has already gone cannot be sent to, and says so."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.SYSTEM)

        await manager.disconnect(connection.client_id)

        assert manager.send(connection.client_id, make_event()) is False


@asyncio_test
async def test_send_refuses_an_oversized_event() -> None:
    """The size cap applies to the directed path as well as to fan-out (M14.22)."""
    manager = make_manager(
        max_event_bytes=64, policies=_unlimited_packets()
    )
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.PACKETS)

        assert manager.send(connection.client_id, packet_event()) is False
        assert queued_count(connection) == 0
        assert manager.get_counters()["rejected_oversized"] == 1


# ---------------------------------------------------------------------------
# A channel that has been switched off (M14.16)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_broadcast_to_a_disabled_channel_delivers_nothing() -> None:
    """``packet_ws_enabled`` off means no packet event is queued at all.

    The connection is still accepted and would still be pinged — only the event is
    suppressed, which is what makes the switch cost zero rather than merely less.
    """
    manager = make_manager(policies=make_policies(packet_enabled=False))
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.PACKETS)

        assert manager.broadcast(packet_event()) == 0
        assert queued_count(connection) == 0
        assert manager.get_counters()["dropped_disabled"] == 1


@asyncio_test
async def test_a_disabled_packet_channel_does_not_affect_the_others() -> None:
    """The switch is per channel, which is the whole point of having it."""
    manager = make_manager(policies=make_policies(packet_enabled=False))
    async with managed(manager):
        _, on_packets = await connect_fake(manager, Channel.PACKETS)
        _, on_system = await connect_fake(manager, Channel.SYSTEM)

        manager.broadcast(packet_event())
        manager.broadcast(make_event())

        assert queued_count(on_packets) == 0
        assert queued_count(on_system) == 1


# ---------------------------------------------------------------------------
# A broken client is removed, the others are served (M14.14)
# ---------------------------------------------------------------------------


async def _wait_for_send_error(manager, *, timeout: float = 2.0) -> None:
    """Wait until the manager has recorded a send failure.

    The failure is discovered by the connection's own sender task, so it becomes
    visible only once the loop has had turns to run it. Polling the counter is
    deterministic; yielding a fixed number of times is a guess about scheduling.

    The sleep is a *real* one rather than ``sleep(0)``, because one of the failures
    this waits for is the send timeout, and that is a wall-clock deadline: a zero
    sleep yields the loop without letting any time pass, so the timer never fires
    and the helper would return having observed nothing. Raising on the deadline
    rather than falling through keeps a scheduling problem loud instead of letting
    it surface as a confusing assertion further down.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if manager.get_counters()["send_errors"]:
            await settle()
            return
        await asyncio.sleep(0.005)
    raise AssertionError("no send failure was recorded within the timeout")


@asyncio_test
async def test_a_failed_send_removes_only_that_client() -> None:
    """A client that vanished mid-session is retired, and nobody else is touched."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        _, good = await connect_fake(manager, Channel.PACKETS)
        _, bad = await connect_fake(manager, Channel.PACKETS, fail_after=0)

        assert manager.broadcast(packet_event()) == 2

        await _wait_for_send_error(manager)
        await settle()

        assert manager.get_counters()["send_errors"] == 1
        assert manager.get_connection(bad.client_id) is None
        assert manager.get_connection(good.client_id) is good
        assert manager.get_connection_count() == 1


@asyncio_test
async def test_the_survivors_keep_receiving_after_a_failure() -> None:
    """Fan-out after the failure reaches the remaining client, not zero clients."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        socket, good = await connect_fake(manager, Channel.PACKETS)
        await connect_fake(manager, Channel.PACKETS, fail_after=0)

        manager.broadcast(packet_event())
        await _wait_for_send_error(manager)
        await settle()

        assert manager.broadcast(packet_event()) == 1
        await settle()

        assert manager.get_connection(good.client_id) is good
        assert socket.types() == [
            EventType.PACKET_OBSERVED,
            EventType.PACKET_OBSERVED,
        ]


@asyncio_test
async def test_a_send_failure_is_counted_and_visible() -> None:
    """Isolation must not hide a fault that keeps happening (M14.30)."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        _, bad = await connect_fake(manager, Channel.PACKETS, fail_after=0)

        manager.broadcast(packet_event())
        await _wait_for_send_error(manager)
        await settle()

        assert bad.counters.send_errors == 1
        assert manager.get_counters()["send_errors"] == 1
        assert manager.get_counters()["connections_closed"] == 1


@asyncio_test
async def test_a_client_that_stalls_is_retired_without_holding_up_its_channel() -> None:
    """A subscriber that stops reading is bounded by the send timeout (M14.14).

    The fan-out itself cannot block — it only offers to a queue — so what this test
    pins down is the other half: the stalled *write* is timed out and that one
    connection is retired, while the healthy client on the same channel is served.
    """
    manager = make_manager(
        policies=_unlimited_packets(), send_timeout_seconds=0.02
    )
    async with managed(manager):
        _, stalled = await connect_fake(manager, Channel.SYSTEM, hang=True)
        healthy, healthy_connection = await connect_fake(manager, Channel.SYSTEM)

        assert manager.broadcast(make_event()) == 2

        await _wait_for_send_error(manager)
        await settle()

        assert manager.get_connection(stalled.client_id) is None
        assert manager.get_connection(healthy_connection.client_id) is (
            healthy_connection
        )
        assert healthy.types() == [EventType.SERVICE_STATUS]


@asyncio_test
async def test_a_broken_client_does_not_break_another_clients_channel() -> None:
    """A failure on one channel leaves the other channels alone (M14.6/M14.14)."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        _, on_alerts = await connect_fake(manager, Channel.ALERTS)
        _, on_system = await connect_fake(manager, Channel.SYSTEM, fail_after=0)

        manager.broadcast(make_event(channel=Channel.SYSTEM))
        await _wait_for_send_error(manager)
        await settle()

        assert manager.broadcast(make_event(event_type=EventType.ALERT_CREATED, channel=Channel.ALERTS)) == 1
        assert queued_count(on_alerts) == 1
        assert manager.get_connection_count() == 1
