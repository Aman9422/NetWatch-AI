"""Unit tests for the WebSocket manager's lifecycle and registry (M14.25).

``WebSocketManager`` is the one object M14 has that owns sockets, queues and the
event loop at once, so its own behaviour — who is registered, what a disconnect
does, what the caps refuse — is tested here directly, against a fake socket rather
than an ASGI stack. The fan-out behaviour it also implements is tested in
``test_ws_broadcast.py``; this file stops at "who is connected and in what state".

Everything here is an ``async`` test driven by :func:`tests.ws_fakes.asyncio_test`
and wrapped by :func:`tests.ws_fakes.managed`, so every test that registers a
client also has the manager shut it down. A sender task left pending when the loop
closes is reported as "Task was destroyed but it is pending", and that noise is
exactly what would hide a genuine teardown bug.

The file covers, in order:

* connecting: registration, state, the sender task, and the queue depth the
  channel policy dictates;
* the registry as an operation in its own right — ``subscribe``/``unsubscribe``,
  which is what ``connect``/``disconnect`` are built from and the seam a test can
  drive without a socket;
* disconnecting: removal, idempotence, the close code and the task being
  cancelled;
* counting, both process-wide and per channel;
* admission: the process cap, the channel cap and the master switch;
* refusal: the close code, and a client that vanished before the close;
* shutdown: every client closed with "going away", the registry cleared, the loop
  unbound, and the whole thing idempotent and safe when startup never ran;
* the keepalive tick and the diagnostic snapshot the benchmark reads.
"""

from __future__ import annotations

from app.websockets.channels import CHANNELS, Channel
from app.websockets.connection import ConnectionState, build_connection
from app.websockets.event import EventType
from app.websockets.manager import CLOSE_GOING_AWAY, CLOSE_POLICY_VIOLATION
from tests.ws_fakes import (
    FakeSocket,
    asyncio_test,
    clean_websockets,  # noqa: F401 - fixture, imported for this module
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

# ---------------------------------------------------------------------------
# Connecting: registration, state and the queue (M14.2/M14.4/M14.5)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_connect_registers_the_connection_on_its_channel() -> None:
    """A connected client is in the registry, tagged with the channel it dialled."""
    manager = make_manager()
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.PACKETS)

        assert manager.get_connection(connection.client_id) is connection
        assert connection.channel is Channel.PACKETS
        assert manager.get_connection_count() == 1
        assert manager.get_connection_count(Channel.PACKETS) == 1


@asyncio_test
async def test_connect_marks_the_connection_connected() -> None:
    """The lifecycle leaves ``CONNECTING`` only once the client is registered."""
    manager = make_manager()
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.SYSTEM)

        assert connection.state is ConnectionState.CONNECTED
        assert connection.is_closed is False


@asyncio_test
async def test_connect_starts_a_sender_task() -> None:
    """Each connection owns exactly one task, and that task is the only writer."""
    manager = make_manager()
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.SYSTEM)

        assert connection.sender_task is not None
        assert connection.sender_task.done() is False


@asyncio_test
async def test_connect_sizes_the_queue_from_the_channel_policy() -> None:
    """The buffer bound is fixed before the client can receive anything (M14.15)."""
    manager = make_manager(policies=make_policies(packet_queue_size=7))
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.PACKETS)

        assert connection.max_queue == 7
        assert connection.queue.maxsize == 7


@asyncio_test
async def test_each_channel_gets_its_own_queue_depth() -> None:
    """The channels are deliberately not uniform, and the depth follows the policy."""
    manager = make_manager(
        policies=make_policies(dashboard_queue_size=3, alert_queue_size=9)
    )
    async with managed(manager):
        _, dashboard = await connect_fake(manager, Channel.DASHBOARD)
        _, alerts = await connect_fake(manager, Channel.ALERTS)

        assert dashboard.max_queue == 3
        assert alerts.max_queue == 9


@asyncio_test
async def test_connect_gives_each_client_a_distinct_id() -> None:
    """Ids are unique, so a log line names one socket."""
    manager = make_manager()
    async with managed(manager):
        _, first = await connect_fake(manager, Channel.SYSTEM)
        _, second = await connect_fake(manager, Channel.SYSTEM)

        assert first.client_id != second.client_id
        assert first.client_id.startswith("wsc-")


@asyncio_test
async def test_get_connection_returns_none_for_an_unknown_id() -> None:
    """An unknown id is ``None``, because cleanup callers race (M14.18)."""
    manager = make_manager()
    async with managed(manager):
        assert manager.get_connection("wsc-does-not-exist") is None


@asyncio_test
async def test_get_connections_returns_them_in_connect_order() -> None:
    """Insertion order is preserved, so diagnostics read chronologically."""
    manager = make_manager()
    async with managed(manager):
        _, first = await connect_fake(manager, Channel.SYSTEM)
        _, second = await connect_fake(manager, Channel.PACKETS)
        _, third = await connect_fake(manager, Channel.SYSTEM)

        assert [item.client_id for item in manager.get_connections()] == [
            first.client_id,
            second.client_id,
            third.client_id,
        ]


@asyncio_test
async def test_get_connections_can_be_scoped_to_one_channel() -> None:
    """A per-channel view is what the fan-out walks, so it must be exact."""
    manager = make_manager()
    async with managed(manager):
        _, on_packets = await connect_fake(manager, Channel.PACKETS)
        await connect_fake(manager, Channel.SYSTEM)

        scoped = manager.get_connections(Channel.PACKETS)

        assert [item.client_id for item in scoped] == [on_packets.client_id]


@asyncio_test
async def test_a_client_can_connect_on_every_channel_at_once() -> None:
    """Four channels mean four independent sockets, each capped separately."""
    manager = make_manager(max_connections=8, max_connections_per_channel=4)
    async with managed(manager):
        for channel in CHANNELS:
            await connect_fake(manager, channel)

        assert manager.get_connection_count() == len(CHANNELS)
        for channel in CHANNELS:
            assert manager.get_connection_count(channel) == 1


# ---------------------------------------------------------------------------
# The registry as an operation in its own right (M14.2/M14.5)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_subscribe_registers_a_connection_without_a_socket() -> None:
    """``subscribe`` is the registry seam ``connect`` is built from (M14.2)."""
    manager = make_manager()
    async with managed(manager):
        connection = build_connection(Channel.ALERTS, queue_size=4)

        manager.subscribe(connection)

        assert manager.get_connection(connection.client_id) is connection
        assert manager.get_connection_count(Channel.ALERTS) == 1


@asyncio_test
async def test_unsubscribe_reports_whether_the_connection_was_there() -> None:
    """A repeat removal returns ``False`` rather than raising (M14.18)."""
    manager = make_manager()
    async with managed(manager):
        connection = build_connection(Channel.ALERTS, queue_size=4)
        manager.subscribe(connection)

        assert manager.unsubscribe(connection.client_id) is True
        assert manager.unsubscribe(connection.client_id) is False
        assert manager.get_connection(connection.client_id) is None


@asyncio_test
async def test_subscribe_is_idempotent() -> None:
    """Subscribing twice registers one connection and one registry slot."""
    manager = make_manager()
    async with managed(manager):
        connection = build_connection(Channel.SYSTEM, queue_size=2)

        manager.subscribe(connection)
        manager.subscribe(connection)

        assert manager.get_connection_count() == 1
        assert len(manager.get_connections()) == 1
# ---------------------------------------------------------------------------
# Disconnecting (M14.4/M14.18)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_disconnect_removes_the_connection_from_the_registry() -> None:
    """A closed client is gone, so no later fan-out can reach it."""
    manager = make_manager()
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.SYSTEM)

        assert await manager.disconnect(connection.client_id) is True

        assert manager.get_connection(connection.client_id) is None
        assert manager.get_connection_count() == 0


@asyncio_test
async def test_disconnect_closes_the_socket_with_going_away() -> None:
    """1001 tells a client to reconnect rather than treat the close as an error."""
    manager = make_manager()
    async with managed(manager):
        socket, connection = await connect_fake(manager, Channel.SYSTEM)

        await manager.disconnect(connection.client_id)

        assert socket.closed is True
        assert socket.close_code == CLOSE_GOING_AWAY


@asyncio_test
async def test_disconnect_cancels_the_sender_task() -> None:
    """The queue drain ends with the connection, so nothing writes to a dead socket."""
    manager = make_manager()
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.SYSTEM)
        task = connection.sender_task
        assert task is not None

        await manager.disconnect(connection.client_id)
        await settle()

        assert connection.sender_task is None
        assert task.cancelled() is True


@asyncio_test
async def test_disconnect_marks_the_connection_closed() -> None:
    """``CLOSED`` is terminal, which is what makes cleanup-on-any-path safe."""
    manager = make_manager()
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.SYSTEM)

        await manager.disconnect(connection.client_id)

        assert connection.state is ConnectionState.CLOSED
        assert connection.is_closed is True


@asyncio_test
async def test_disconnect_is_idempotent() -> None:
    """Cleanup runs from the route and from a send failure, so a repeat is a no-op."""
    manager = make_manager()
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.SYSTEM)

        first = await manager.disconnect(connection.client_id)
        second = await manager.disconnect(connection.client_id)

        assert first is True
        assert second is False


@asyncio_test
async def test_disconnect_returns_false_for_an_unregistered_id() -> None:
    """An unknown id is a no-op rather than an error (M14.18)."""
    manager = make_manager()
    async with managed(manager):
        assert await manager.disconnect("wsc-not-a-client") is False


@asyncio_test
async def test_disconnect_leaves_the_other_clients_alone() -> None:
    """One client leaving does not disturb the rest of its channel (M14.14)."""
    manager = make_manager()
    async with managed(manager):
        _, leaving = await connect_fake(manager, Channel.SYSTEM)
        _, staying = await connect_fake(manager, Channel.SYSTEM)

        await manager.disconnect(leaving.client_id)

        assert manager.get_connection(staying.client_id) is staying
        assert manager.get_connection_count() == 1


@asyncio_test
async def test_connection_count_returns_to_zero_after_everyone_leaves() -> None:
    """The counter follows the registry exactly, in both directions."""
    manager = make_manager()
    async with managed(manager):
        _, first = await connect_fake(manager, Channel.SYSTEM)
        _, second = await connect_fake(manager, Channel.PACKETS)
        assert manager.get_connection_count() == 2

        await manager.disconnect(first.client_id)
        await manager.disconnect(second.client_id)

        assert manager.get_connection_count() == 0
        for channel in CHANNELS:
            assert manager.get_connection_count(channel) == 0


# ---------------------------------------------------------------------------
# Admission and refusal (M14.5/M14.22)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_admission_admits_a_client_under_both_caps() -> None:
    """With room to spare, admission returns no reason at all."""
    manager = make_manager()
    async with managed(manager):
        assert manager.check_admission(Channel.PACKETS) is None


@asyncio_test
async def test_admission_refuses_past_the_process_cap() -> None:
    """A connection flood is refused rather than absorbed."""
    manager = make_manager(max_connections=2, max_connections_per_channel=4)
    async with managed(manager):
        await connect_fake(manager, Channel.SYSTEM)
        await connect_fake(manager, Channel.PACKETS)

        reason = manager.check_admission(Channel.ALERTS)

        assert reason is not None
        assert "Too many WebSocket connections" in reason


@asyncio_test
async def test_admission_refuses_past_the_channel_cap() -> None:
    """One channel cannot crowd the others out of the process budget."""
    manager = make_manager(max_connections=8, max_connections_per_channel=1)
    async with managed(manager):
        await connect_fake(manager, Channel.PACKETS)

        assert manager.check_admission(Channel.PACKETS) is not None
        assert manager.check_admission(Channel.SYSTEM) is None


@asyncio_test
async def test_admission_refuses_when_the_layer_is_disabled() -> None:
    """The master switch refuses before any socket state exists (M14.33)."""
    manager = make_manager(enabled=False)
    async with managed(manager):
        reason = manager.check_admission(Channel.SYSTEM)

        assert reason is not None
        assert "disabled" in reason


@asyncio_test
async def test_admission_frees_a_slot_when_a_client_leaves() -> None:
    """The cap is on live connections, not on connections ever made."""
    manager = make_manager(max_connections=1, max_connections_per_channel=1)
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.PACKETS)
        assert manager.check_admission(Channel.PACKETS) is not None

        await manager.disconnect(connection.client_id)

        assert manager.check_admission(Channel.PACKETS) is None


@asyncio_test
async def test_refuse_closes_with_a_policy_violation_code() -> None:
    """A refused client learns why from the close frame, not from silence."""
    manager = make_manager()
    async with managed(manager):
        socket = FakeSocket()

        await manager.refuse(socket, "Too many WebSocket connections")

        assert socket.closed is True
        assert socket.close_code == CLOSE_POLICY_VIOLATION
        assert socket.close_reason == "Too many WebSocket connections"


@asyncio_test
async def test_refuse_is_counted() -> None:
    """Refusals are visible, so a flood is measurable rather than mysterious."""
    manager = make_manager()
    async with managed(manager):
        await manager.refuse(FakeSocket(), "Too many WebSocket connections")

        assert manager.get_counters()["connections_refused"] == 1


@asyncio_test
async def test_refuse_never_registers_the_client() -> None:
    """A refused socket is closed, never registered, so no broadcast can reach it."""
    manager = make_manager()
    async with managed(manager):
        await manager.refuse(FakeSocket(), "Too many WebSocket connections")

        assert manager.get_connection_count() == 0
        assert manager.get_connections() == []


@asyncio_test
async def test_refuse_contains_a_socket_that_fails_to_close() -> None:
    """A client that vanished between the check and the close must not raise.

    The refusal path runs on a route, and an exception there would turn an
    ordinary "this client is already gone" into a server error.
    """

    class _CloseFails(FakeSocket):
        """A socket whose close raises, standing in for a vanished client."""

        async def close(self, code: int = 1000, reason: str | None = None) -> None:
            raise RuntimeError("socket already gone")

    manager = make_manager()
    async with managed(manager):
        await manager.refuse(_CloseFails(), "The WebSocket layer is disabled")

        assert manager.get_counters()["connections_refused"] == 1
# ---------------------------------------------------------------------------
# Startup and shutdown (M14.20)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_is_running_is_false_before_startup() -> None:
    """No loop bound means no subscriber can be reached, and that is visible."""
    manager = make_manager()

    assert manager.is_running is False


@asyncio_test
async def test_start_binds_the_running_loop() -> None:
    """Startup is what makes a publish able to reach the loop (M14.21)."""
    manager = make_manager()
    async with managed(manager):
        await manager.start()

        assert manager.is_running is True


@asyncio_test
async def test_start_is_a_no_op_when_the_layer_is_disabled() -> None:
    """A disabled layer stays unrunnable, so it can never accept a connection."""
    manager = make_manager(enabled=False)
    async with managed(manager):
        await manager.start()

        assert manager.is_running is False


@asyncio_test
async def test_shutdown_closes_every_connection_with_going_away() -> None:
    """Every client is closed on the way out, and told why."""
    manager = make_manager()
    sockets = []
    for channel in CHANNELS:
        socket, _ = await connect_fake(manager, channel)
        sockets.append(socket)

    await manager.shutdown()

    assert all(socket.closed for socket in sockets)
    assert all(socket.close_code == CLOSE_GOING_AWAY for socket in sockets)


@asyncio_test
async def test_shutdown_cancels_every_sender_task() -> None:
    """No task outlives the application: that is what makes a reload clean."""
    manager = make_manager()
    await manager.start()
    _, first = await connect_fake(manager, Channel.SYSTEM)
    _, second = await connect_fake(manager, Channel.PACKETS)
    tasks = [first.sender_task, second.sender_task]
    assert all(task is not None for task in tasks)

    await manager.shutdown()
    await settle()

    assert all(task is not None and task.cancelled() for task in tasks)


@asyncio_test
async def test_shutdown_clears_the_registry_and_unbinds_the_loop() -> None:
    """Nothing survives a shutdown: no connection, no registry, no bound loop."""
    manager = make_manager()
    await manager.start()
    await connect_fake(manager, Channel.SYSTEM)

    await manager.shutdown()

    assert manager.get_connection_count() == 0
    assert manager.get_connections() == []
    assert manager.is_running is False


@asyncio_test
async def test_shutdown_is_idempotent() -> None:
    """A second shutdown is a no-op, so a lifespan and a test may both call it."""
    manager = make_manager()
    await manager.start()
    await connect_fake(manager, Channel.SYSTEM)

    await manager.shutdown()
    await manager.shutdown()

    assert manager.get_connection_count() == 0
    assert manager.get_counters()["connections_closed"] == 1


@asyncio_test
async def test_shutdown_is_safe_when_startup_never_ran() -> None:
    """A test that builds the manager without starting it still tears down quietly."""
    manager = make_manager()

    await manager.shutdown()

    assert manager.is_running is False


@asyncio_test
async def test_a_publish_after_shutdown_is_dropped_rather_than_raising() -> None:
    """The loop is gone, so there is nowhere to hand an event — counted, not raised.

    This is what keeps a shutdown race from reaching the capture thread (M14.14).
    """
    manager = make_manager()
    await manager.start()
    await manager.shutdown()

    assert manager.publish(make_event()) is False
    assert manager.get_counters()["dropped_no_loop"] == 1


# ---------------------------------------------------------------------------
# The keepalive tick (M14.24)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_heartbeat_tick_pings_a_client_on_every_channel() -> None:
    """One ping per client per interval, and the ping is a normal queued event."""
    manager = make_manager(policies=make_policies(packet_rate=None))
    async with managed(manager):
        connections = []
        for channel in CHANNELS:
            _, connection = await connect_fake(manager, channel)
            connections.append(connection)

        sent = await manager.heartbeat_tick()

        assert sent == len(CHANNELS)
        for connection in connections:
            assert queued_types(connection) == [EventType.PING]


@asyncio_test
async def test_heartbeat_tick_marks_the_connection_as_awaiting_a_pong() -> None:
    """One outstanding ping per client, which is what bounds a half-open socket."""
    manager = make_manager(policies=make_policies(packet_rate=None))
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.SYSTEM)

        await manager.heartbeat_tick()

        assert connection.awaiting_pong is True
        assert connection.counters.pings_sent == 1


@asyncio_test
async def test_heartbeat_tick_retires_a_client_that_never_answered() -> None:
    """Two intervals without a reply is the documented lifetime of a dead socket."""
    manager = make_manager(policies=make_policies(packet_rate=None))
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.SYSTEM)
        assert connection is not None

        assert await manager.heartbeat_tick() == 1
        assert manager.get_connection_count() == 1

        assert await manager.heartbeat_tick() == 0

        assert manager.get_connection_count() == 0
        assert manager.get_counters()["heartbeat_timeouts"] == 1


@asyncio_test
async def test_heartbeat_tick_keeps_a_client_that_answered() -> None:
    """A pong clears the mark, so a live client is pinged again, not retired."""
    manager = make_manager(policies=make_policies(packet_rate=None))
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.SYSTEM)

        await manager.heartbeat_tick()
        connection.note_pong()

        assert await manager.heartbeat_tick() == 1

        assert manager.get_connection_count() == 1
        assert connection.awaiting_pong is True


@asyncio_test
async def test_heartbeat_tick_does_nothing_with_no_connections() -> None:
    """An idle process sends no keepalive, which is the point of the interval."""
    manager = make_manager()
    async with managed(manager):
        assert await manager.heartbeat_tick() == 0
        assert manager.get_counters()["heartbeat_pings"] == 0


# ---------------------------------------------------------------------------
# Diagnostics (M14.33)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_counters_track_accepted_and_closed_connections() -> None:
    """The two counters a leak would show up in are kept accurately."""
    manager = make_manager()
    async with managed(manager):
        _, first = await connect_fake(manager, Channel.SYSTEM)
        await connect_fake(manager, Channel.PACKETS)

        await manager.disconnect(first.client_id)

        counters = manager.get_counters()
        assert counters["connections_accepted"] == 2
        assert counters["connections_closed"] == 1


@asyncio_test
async def test_get_stats_reports_configuration_counters_and_channels() -> None:
    """The snapshot the benchmark reads states the effective configuration."""
    manager = make_manager(
        max_connections=5, max_connections_per_channel=2, max_event_bytes=1234
    )
    async with managed(manager):
        await manager.start()
        await connect_fake(manager, Channel.PACKETS)

        stats = manager.get_stats()

        assert stats["enabled"] is True
        assert stats["running"] is True
        assert stats["connection_count"] == 1
        assert stats["max_connections"] == 5
        assert stats["max_connections_per_channel"] == 2
        assert stats["max_event_bytes"] == 1234
        # ``get_stats`` is a loose diagnostic dictionary, so the two container
        # fields are narrowed before use rather than indexed blindly.
        channels = stats["channels"]
        connections = stats["connections"]
        assert isinstance(channels, dict)
        assert isinstance(connections, list)
        assert set(channels) == {channel.value for channel in CHANNELS}
        assert len(connections) == 1


@asyncio_test
async def test_channel_stats_reports_policy_and_live_depth() -> None:
    """A measurement can be read without also opening the settings object."""
    manager = make_manager(
        policies=make_policies(
            packet_queue_size=11, packet_rate=42.0, alert_queue_size=99
        )
    )
    async with managed(manager):
        await connect_fake(manager, Channel.PACKETS)

        stats = manager.channel_stats()

        assert stats["packets"]["connections"] == 1
        assert stats["packets"]["queue_size"] == 11
        assert stats["packets"]["max_events_per_second"] == 42.0
        assert stats["packets"]["priority"] == "telemetry"
        assert stats["alerts"]["queue_size"] == 99
        assert stats["alerts"]["priority"] == "security"
        assert stats["system"]["priority"] == "state"


@asyncio_test
async def test_channel_stats_reports_the_queued_depth() -> None:
    """Queue depth is reported live, so a backed-up client is visible."""
    manager = make_manager(policies=make_policies(packet_rate=None))
    async with managed(manager):
        _, connection = await connect_fake(manager, Channel.PACKETS)

        manager.broadcast(packet_event())

        assert manager.channel_stats()["packets"]["queued"] == 1
        assert queued_count(connection) == 1
