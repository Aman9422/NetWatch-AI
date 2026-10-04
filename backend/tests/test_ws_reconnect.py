"""Tests for reconnection (M14.19).

M14.19 is a single sentence in the milestone list — "support reconnect" — and the
design's answer to it is deliberate and minimal: **a reconnect is a new
connection.** There is no session, no resume token, no replay buffer and no
per-client identity, so a client that reconnects gets exactly what a client that
connects for the first time gets.

That is a choice with consequences, and they are what this file pins down:

* the new socket has a new connection id, a new queue and fresh counters — nothing
  is carried across from the socket it replaced;
* nothing that was published while the client was away is delivered to it
  afterwards. The live view is not a log, and the design says so rather than
  pretending a socket can be a durable queue: a client that needs the events it
  missed reads them from ``GET /api/v1/packets`` and friends, which is the record
  the socket is a view of;
* the reconnect is nevertheless a *continuation* in one respect — the process-wide
  event sequence keeps climbing, so a client can see that a gap is a gap rather
  than a continuation;
* the per-channel queue depth and the keepalive state are re-derived for the new
  socket, because they are properties of a connection and the old one is gone.

The last section covers the shutdown boundary, where the manager must stop
accepting new connections (M14.20) — a reconnecting client arriving into a
shutdown is refused with a reason rather than registered against an unbindable
loop and left silent.

The write-failure path is covered without a polling helper: a ``fail_after=0``
socket raises on its first write with no ``await`` before the raise, so the sender
discovers it on the loop's first turn and a single ``settle()`` is enough to
observe it. The *timeout* path, which is the one that needs real wall-clock time,
belongs to ``test_ws_backpressure.py`` and is tested there.
"""

from __future__ import annotations

from app.websockets.channels import Channel
from app.websockets.event import EventType
from tests.ws_fakes import (
    FakeSocket,
    asyncio_test,
    clean_websockets,  # noqa: F401 - fixture, imported for this module
    connect_fake,
    make_manager,
    make_policies,
    managed,
    packet_event,
    queued_count,
    settle,
)


def _unlimited_packets():
    """Return a policy table with no packet rate ceiling."""
    return make_policies(packet_rate=None)


# ---------------------------------------------------------------------------
# A reconnect is a new connection (M14.19)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_a_reconnect_is_a_new_connection_with_a_new_id() -> None:
    """Nothing about the previous socket is reused, starting with its identity."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        _, first = await connect_fake(manager, Channel.PACKETS)
        await manager.disconnect(first.client_id)
        _, second = await connect_fake(manager, Channel.PACKETS)

        assert second.client_id != first.client_id
        assert second.queue is not first.queue
        assert second.is_closed is False


@asyncio_test
async def test_the_registry_holds_one_connection_after_a_reconnect() -> None:
    """The replacement is not in addition to the connection it replaced."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        _, first = await connect_fake(manager, Channel.PACKETS)
        await manager.disconnect(first.client_id)
        _, second = await connect_fake(manager, Channel.PACKETS)

        assert manager.get_connection_count() == 1
        assert manager.get_connection(first.client_id) is None
        assert manager.get_connection(second.client_id) is second


@asyncio_test
async def test_the_new_connection_starts_with_fresh_counters() -> None:
    """Counters describe one socket's life, so a reconnect is not a continuation."""
    manager = make_manager(policies=make_policies(packet_queue_size=2, packet_rate=None))
    async with managed(manager):
        _, first = await connect_fake(manager, Channel.PACKETS)
        for sequence in range(1, 6):
            manager.broadcast(packet_event(sequence=sequence))
        assert first.counters.dropped_queue_full == 3

        await manager.disconnect(first.client_id)
        _, second = await connect_fake(manager, Channel.PACKETS)

        assert second.counters.offered == 0
        assert second.counters.sent == 0
        assert second.counters.dropped_queue_full == 0
        assert second.awaiting_pong is False


@asyncio_test
async def test_the_new_connection_gets_its_channels_queue_depth() -> None:
    """The bound is re-derived from the policy, not inherited from the socket."""
    manager = make_manager(policies=make_policies(packet_queue_size=6, packet_rate=None))
    async with managed(manager):
        _, first = await connect_fake(manager, Channel.PACKETS)
        await manager.disconnect(first.client_id)
        _, second = await connect_fake(manager, Channel.PACKETS)

        assert second.max_queue == 6
        assert second.queue.maxsize == 6


@asyncio_test
async def test_a_reconnect_can_choose_a_different_channel() -> None:
    """A channel is a property of the connection, so a new connection may differ.

    M14.6 fixes a channel for a connection's lifetime and M14 has no message that
    changes one, so "changing channel" is expressed the only way the design allows:
    by opening a different socket.
    """
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        _, on_packets = await connect_fake(manager, Channel.PACKETS)
        await manager.disconnect(on_packets.client_id)
        _, on_alerts = await connect_fake(manager, Channel.ALERTS)

        assert on_alerts.channel is Channel.ALERTS
        assert on_packets.channel is Channel.PACKETS


# ---------------------------------------------------------------------------
# No history is replayed (M14.19)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_a_reconnect_receives_nothing_it_missed() -> None:
    """The events published while it was away are gone, not queued for it.

    This is the load-bearing decision of M14.19. A live view that replayed its
    backlog would need a per-client buffer outliving the connection, and an
    unbounded one at that; the design instead points a client at the REST
    endpoints, which hold the record.
    """
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        first_socket, first = await connect_fake(manager, Channel.PACKETS)
        for sequence in range(1, 4):
            manager.broadcast(packet_event(sequence=sequence))
        await settle()
        assert first_socket.types() == [EventType.PACKET_OBSERVED] * 3
        assert queued_count(first) == 0

        await manager.disconnect(first.client_id)

        # Published while nobody is subscribed: not queued anywhere, not replayed.
        manager.broadcast(packet_event(sequence=4))

        second_socket, second = await connect_fake(manager, Channel.PACKETS)
        await settle()

        assert second_socket.types() == []
        assert queued_count(second) == 0


@asyncio_test
async def test_a_reconnect_receives_what_is_published_after_it_arrives() -> None:
    """The live view resumes from the reconnect, not from the original connect."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        _, first = await connect_fake(manager, Channel.PACKETS)
        manager.broadcast(packet_event(sequence=1))
        await manager.disconnect(first.client_id)

        socket, _ = await connect_fake(manager, Channel.PACKETS)
        manager.broadcast(packet_event(sequence=2))
        await settle()

        assert socket.types() == [EventType.PACKET_OBSERVED]


@asyncio_test
async def test_the_event_sequence_keeps_climbing_across_a_reconnect() -> None:
    """The sequence is process-wide, so a client can tell a gap from a restart.

    The one thing that *is* continuous across a reconnect: were it reset with each
    connection, a client that reconnected and saw sequence 1 again could not
    distinguish "it restarted" from "I missed nothing", which is exactly what the
    field exists to tell it (M14.7).
    """
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        first_socket, first = await connect_fake(manager, Channel.PACKETS)
        manager.broadcast(packet_event())
        await settle()
        before = first_socket.messages()[-1]["sequence"]

        await manager.disconnect(first.client_id)
        second_socket, _ = await connect_fake(manager, Channel.PACKETS)
        manager.broadcast(packet_event())
        await settle()
        after = second_socket.messages()[-1]["sequence"]

        assert after > before


# ---------------------------------------------------------------------------
# Reconnecting after a failure, and alongside another socket (M14.14/M14.19)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_a_client_that_reconnects_after_a_failed_write_is_served_again() -> None:
    """The realistic reconnect: a network blip retired the socket, not the client.

    The write failure costs the affected connection and nothing else, so the very
    next connection on the same channel behaves exactly as the first one did.
    """
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        _, broken = await connect_fake(manager, Channel.PACKETS, fail_after=0)
        manager.broadcast(packet_event(sequence=1))
        await settle()

        assert manager.get_connection(broken.client_id) is None
        assert manager.get_counters()["send_errors"] == 1

        socket, replacement = await connect_fake(manager, Channel.PACKETS)
        assert manager.broadcast(packet_event(sequence=2)) == 1
        await settle()

        assert manager.get_connection(replacement.client_id) is replacement
        assert socket.types() == [EventType.PACKET_OBSERVED]


@asyncio_test
async def test_a_client_that_reconnects_after_a_keepalive_retirement_is_served_again() -> None:
    """Being retired for silence is not a ban: the client may come back."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        _, quiet = await connect_fake(manager, Channel.SYSTEM)
        await manager.heartbeat_tick()
        await manager.heartbeat_tick()

        assert manager.get_connection(quiet.client_id) is None
        assert manager.get_counters()["heartbeat_timeouts"] == 1

        _, again = await connect_fake(manager, Channel.SYSTEM)
        assert await manager.heartbeat_tick() == 1
        assert again.awaiting_pong is True


@asyncio_test
async def test_two_live_sockets_from_one_client_are_two_connections() -> None:
    """The registry holds connections, not clients (M14.5), so there is no dedupe.

    A browser that opens a second tab, or that reconnects before its old socket has
    finished closing, gets a second connection rather than having its first one
    cancelled on its behalf — M14 keeps no client identity to deduplicate with, and
    inventing one would mean tracking a client across sockets, which is the session
    the design declines to have.
    """
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        first_socket, first = await connect_fake(manager, Channel.PACKETS)
        second_socket, second = await connect_fake(manager, Channel.PACKETS)

        assert first.client_id != second.client_id
        assert manager.get_connection_count() == 2
        assert manager.broadcast(packet_event()) == 2
        await settle()

        assert first_socket.types() == [EventType.PACKET_OBSERVED]
        assert second_socket.types() == [EventType.PACKET_OBSERVED]


@asyncio_test
async def test_disconnecting_the_old_socket_does_not_disturb_the_new_one() -> None:
    """Cleanup is per connection: retiring one must not touch a live sibling."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        _, first = await connect_fake(manager, Channel.PACKETS)
        socket, second = await connect_fake(manager, Channel.PACKETS)

        await manager.disconnect(first.client_id)

        assert manager.get_connection(second.client_id) is second
        assert manager.broadcast(packet_event()) == 1
        await settle()
        assert socket.types() == [EventType.PACKET_OBSERVED]


# ---------------------------------------------------------------------------
# The shutdown boundary (M14.20)
# ---------------------------------------------------------------------------


def test_a_manager_that_never_started_still_admits_connections() -> None:
    """The flag only means "closed" once a shutdown has set it.

    A manager built without its lifespan — every ``test_ws_*`` module, and any code
    that constructs one directly — must admit connections, or the check would break
    the seam the tests drive.
    """
    manager = make_manager()

    assert manager.check_admission(Channel.SYSTEM) is None


@asyncio_test
async def test_a_reconnect_after_shutdown_is_refused() -> None:
    """M14.20: shutdown stops accepting new connections, and says why.

    Without this the socket would be registered against a loop that is no longer
    bound, receive nothing forever, and never be told anything is wrong — worse for
    the client than a refusal it can act on by reconnecting once the server is back.
    """
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        await manager.start()
        assert manager.check_admission(Channel.PACKETS) is None

        await manager.shutdown()

        reason = manager.check_admission(Channel.PACKETS)
        assert reason is not None
        assert "shutting down" in reason


@asyncio_test
async def test_a_restarted_manager_admits_connections_again() -> None:
    """A restart clears the flag, so a reload is not a one-way door (M14.20)."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        await manager.start()
        await manager.shutdown()
        assert manager.check_admission(Channel.PACKETS) is not None

        await manager.start()

        assert manager.check_admission(Channel.PACKETS) is None
        _, connection = await connect_fake(manager, Channel.PACKETS)
        assert manager.broadcast(packet_event()) == 1
        assert connection.counters.offered == 1


@asyncio_test
async def test_a_refused_reconnect_is_counted_like_any_other_refusal() -> None:
    """A refused socket is visible, so a client hammering a stopping server is seen."""
    manager = make_manager(policies=_unlimited_packets())
    async with managed(manager):
        await manager.start()
        await manager.shutdown()

        await manager.refuse(FakeSocket(), "The WebSocket layer is shutting down")

        assert manager.get_counters()["connections_refused"] == 1
