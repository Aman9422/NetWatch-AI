"""End-to-end tests over the real ASGI application (M14.31).

Every other ``test_ws_*`` module drives the manager directly, which is what makes
them fast and precise. This one does the opposite: it speaks WebSocket to the
*real* application through Starlette's ``TestClient``, so the pieces the unit tests
deliberately bypass are exercised — the router and its four paths, the admission
check, the accept-then-refuse sequence, the receive loop, the close codes, and the
fact that the manager the routes reach is the process-wide singleton the lifespan
started rather than one a test built.

What only an end-to-end test can catch, and therefore what is asserted here:

* the four documented paths exist and each serves its own channel (M14.3/M14.6);
* a frame written by the *server* arrives at a *client* as the documented JSON
  envelope, not merely as an object the manager queued (M14.7/M14.17);
* a client frame is read, judged and answered — ping/pong and every refusal
  (M14.23);
* a refused client is closed with a status code the client can see, rather than
  registered and then ignored (M14.22);
* channel separation holds across two real sockets at once, not just across two
  registry entries (M14.6).

Two habits keep the file deterministic, and both are about the same problem: the
application runs on its own event loop in another thread, so nothing the test does
happens atomically with respect to it.

* **Registration is awaited, never assumed.** ``websocket_connect`` returns once
  the handshake is accepted, which is *before* ``connect`` registers the socket.
  A frame published in that window would have no subscriber, so every test waits
  for the registry to show the connection before publishing.
* **Frames are read by type.** The dashboard tick fires once a second on the
  dashboard channel, so "the next frame" is not a well-defined thing to assert
  there. Reading until the expected type arrives is what makes these tests
  independent of which tick happened to land first.

The flood test is deliberately tolerant about the count of refusal frames it sees
before the close. The route queues an ``error`` event and then closes the socket
directly, and a close can overtake a queued frame that the sender task has not
written yet; the design promises a refusal is answered and counted, and that a
flooding client is disconnected, not that the last error frame wins the race. The
test asserts exactly those promises.
"""

from __future__ import annotations

import contextlib
import time

import pytest
from starlette.websockets import WebSocketDisconnect

from app.config.settings import settings
from app.websockets import builders, get_websocket_manager
from app.websockets.channels import CHANNEL_PATHS, CHANNELS, Channel
from app.websockets.event import EventType
from app.websockets.manager import WebSocketManager
from app.websockets.messages import (
    REFUSAL_MISSING_TYPE,
    REFUSAL_NOT_JSON,
    REFUSAL_NOT_TEXT,
    REFUSAL_TOO_LARGE,
    REFUSAL_UNKNOWN_TYPE,
)
from tests.fakes import PACKET_BASE_TIME, make_normalized_packet
from tests.ws_fakes import clean_websockets  # noqa: F401 - fixture, per module

#: How long a wait for the application's own thread to catch up may take. These
#: are polls against a live server, so the bound is generous and the interval is
#: short: a passing test returns as soon as the state is reached.
WAIT_TIMEOUT_SECONDS = 5.0
WAIT_INTERVAL_SECONDS = 0.005

#: The packet a ``packet.observed`` event in this file describes.
PACKET_ID = 7


def _manager() -> WebSocketManager:
    """Return the manager the running application built."""
    return get_websocket_manager()


def _path(channel: Channel) -> str:
    """Return the documented path for ``channel``."""
    return CHANNEL_PATHS[channel]


def _await_connection_count(channel: Channel, expected: int) -> None:
    """Wait until ``channel`` holds ``expected`` connections.

    Raises:
        AssertionError: If the count does not reach ``expected`` in time, so a
            scheduling problem is reported where it happened rather than as a
            confusing failure several assertions later.
    """
    manager = _manager()
    deadline = time.monotonic() + WAIT_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if manager.get_connection_count(channel) == expected:
            return
        time.sleep(WAIT_INTERVAL_SECONDS)
    raise AssertionError(
        f"{channel.value} never reached {expected} connection(s); "
        f"it holds {manager.get_connection_count(channel)}"
    )


def _await_total_connection_count(expected: int) -> None:
    """Wait until the process holds ``expected`` connections in total."""
    manager = _manager()
    deadline = time.monotonic() + WAIT_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if manager.get_connection_count() == expected:
            return
        time.sleep(WAIT_INTERVAL_SECONDS)
    raise AssertionError(
        f"the process never reached {expected} connection(s); "
        f"it holds {manager.get_connection_count()}"
    )


def _await_counter(connection, name: str, expected: int) -> None:
    """Wait until one of a connection's counters reaches ``expected``.

    The client's own frame is read by the application's loop in another thread, so
    a counter it increments is only reliable once it has been waited for. Polling
    the value the route itself maintains is exact where sleeping a fixed amount is
    a guess.
    """
    deadline = time.monotonic() + WAIT_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if getattr(connection.counters, name) >= expected:
            return
        time.sleep(WAIT_INTERVAL_SECONDS)
    raise AssertionError(
        f"{name} never reached {expected}; it is {getattr(connection.counters, name)}"
    )


def _receive_of_type(websocket, event_type: str, *, attempts: int = 20) -> dict:
    """Read frames until one of ``event_type`` arrives, and return it.

    Needed because a channel is not obliged to be silent: the dashboard tick is
    published on its own channel once a second, so a test that asserted on "the
    next frame" there would be racing the tick rather than testing the endpoint.
    """
    for _ in range(attempts):
        message = websocket.receive_json()
        if message["type"] == event_type:
            return message
    raise AssertionError(f"no {event_type} frame arrived within {attempts} frames")


def _packet_event():
    """Build the ``packet.observed`` event this file publishes."""
    return builders.packet_event(
        make_normalized_packet(packet_id=PACKET_ID), timestamp=PACKET_BASE_TIME
    )


def _service_event(state: str = "running"):
    """Build a ``service.status`` event for the system channel."""
    return builders.service_event("websockets", state)


#: The complete field set of a packet payload (M14.8), so a test can assert that
#: nothing was added to it — least of all a payload.
PACKET_FIELDS = frozenset(
    {
        "packet_id",
        "timestamp",
        "interface",
        "source_ip",
        "destination_ip",
        "protocol",
        "source_port",
        "destination_port",
        "length",
        "packet_type",
    }
)


def _assert_envelope(message: dict, *, event_type: str, channel: Channel) -> None:
    """Assert the six envelope fields a client may rely on (M14.7)."""
    assert message["schema_version"] == 1
    assert message["type"] == event_type
    assert message["channel"] == channel.value
    assert message["event_id"].startswith("evt-")
    assert message["timestamp"].endswith("+00:00")
    assert isinstance(message["sequence"], int)
    assert isinstance(message["data"], dict)


# ---------------------------------------------------------------------------
# The four endpoints exist and each serves its own channel (M14.3/M14.6)
# ---------------------------------------------------------------------------


def test_every_documented_path_accepts_a_connection(client) -> None:
    """Each of the four paths completes a handshake and registers its channel.

    Asserted channel by channel rather than as "a connection succeeded": the
    failure this catches is a route mounted on the wrong path or serving the wrong
    channel, which a single connection would not reveal.
    """
    for channel in CHANNELS:
        with client.websocket_connect(_path(channel)):
            _await_connection_count(channel, 1)
            assert _manager().get_connection_count() == 1
        _await_connection_count(channel, 0)


def test_a_disconnect_unregisters_the_client(client) -> None:
    """Leaving the context manager is an ordinary disconnect, and cleanup runs.

    The end-to-end form of M14.18: the route's ``finally`` block is what removes
    the connection, and this is the only test that drives it through a real client
    closing rather than through a direct ``disconnect`` call.
    """
    with client.websocket_connect(_path(Channel.SYSTEM)):
        _await_connection_count(Channel.SYSTEM, 1)

    _await_total_connection_count(0)
    assert _manager().get_connections() == []


# ---------------------------------------------------------------------------
# A server frame arrives as the documented envelope (M14.7/M14.17)
# ---------------------------------------------------------------------------


def test_a_published_packet_arrives_as_the_documented_envelope(client) -> None:
    """The whole point of the layer: a real client receives the real JSON."""
    with client.websocket_connect(_path(Channel.PACKETS)) as websocket:
        _await_connection_count(Channel.PACKETS, 1)

        assert _manager().publish(_packet_event()) is True

        message = _receive_of_type(websocket, EventType.PACKET_OBSERVED)

    _assert_envelope(
        message, event_type=EventType.PACKET_OBSERVED, channel=Channel.PACKETS
    )
    assert message["source"] == "pipeline.packets"
    assert message["data"]["packet_id"] == PACKET_ID


def test_a_packet_event_carries_the_documented_fields_and_nothing_else(client) -> None:
    """M14.8's field list is exhaustive, and it deliberately has no payload.

    The assertion is an equality on the key set rather than "these keys are
    present", because the rule being tested is a *ceiling*: the next field M5 adds
    to a normalized packet must not appear on the wire until M14.8 says it may.
    """
    with client.websocket_connect(_path(Channel.PACKETS)) as websocket:
        _await_connection_count(Channel.PACKETS, 1)

        _manager().publish(_packet_event())
        message = _receive_of_type(websocket, EventType.PACKET_OBSERVED)

    assert set(message["data"]) == PACKET_FIELDS
    for forbidden in ("payload", "raw", "bytes", "metadata", "hexdump"):
        assert forbidden not in message["data"]


def test_a_state_change_arrives_on_the_system_channel(client) -> None:
    """The system channel carries what it is for, not only what a test sends."""
    with client.websocket_connect(_path(Channel.SYSTEM)) as websocket:
        _await_connection_count(Channel.SYSTEM, 1)

        _manager().publish(_service_event("capturing"))

        message = _receive_of_type(websocket, EventType.SERVICE_STATUS)

    _assert_envelope(
        message, event_type=EventType.SERVICE_STATUS, channel=Channel.SYSTEM
    )
    assert message["data"] == {"service": "websockets", "state": "capturing"}


# ---------------------------------------------------------------------------
# The keepalive, over the wire (M14.23/M14.24)
# ---------------------------------------------------------------------------


def test_a_client_ping_is_answered_with_a_matching_pong(client) -> None:
    """A ping earns exactly a pong, carrying the client's own nonce back."""
    with client.websocket_connect(_path(Channel.SYSTEM)) as websocket:
        _await_connection_count(Channel.SYSTEM, 1)

        websocket.send_json({"type": "ping", "nonce": "abc-123"})

        message = _receive_of_type(websocket, EventType.PONG)

    assert message["data"] == {"nonce": "abc-123"}
    assert message["channel"] == Channel.SYSTEM.value


def test_a_client_pong_is_accepted_and_counted(client) -> None:
    """A pong is evidence of life, not a request: counted, never answered.

    Observed through the connection's own counter rather than by waiting for a
    frame that must not come — a "prove nothing arrived" assertion could only mean
    anything by timing out, which fails slowly rather than precisely.
    """
    with client.websocket_connect(_path(Channel.SYSTEM)) as websocket:
        _await_connection_count(Channel.SYSTEM, 1)
        connection = _manager().get_connections(Channel.SYSTEM)[0]

        websocket.send_json({"type": "pong", "nonce": "abc-123"})

        _await_counter(connection, "pongs_received", 1)

        assert connection.awaiting_pong is False


# ---------------------------------------------------------------------------
# Client input is refused, never acted on (M14.22/M14.23)
# ---------------------------------------------------------------------------


def test_an_unknown_message_type_is_refused(client) -> None:
    """Only `ping` and `pong` exist; anything else is named and refused."""
    with client.websocket_connect(_path(Channel.SYSTEM)) as websocket:
        _await_connection_count(Channel.SYSTEM, 1)

        websocket.send_json({"type": "shutdown-everything"})

        message = _receive_of_type(websocket, EventType.ERROR)

    assert message["data"]["reason"] == REFUSAL_UNKNOWN_TYPE
    assert message["data"]["field"] == "message"
    # The refusal names the rule; it never echoes the client's own bytes back.
    assert "shutdown-everything" not in str(message)


def test_a_client_cannot_widen_what_it_receives(client) -> None:
    """No client message selects a channel, a topic or a filter (M14.22/M14.23).

    The most valuable thing to try, because a subscription message is what a
    server-push-only design must not have: if one worked, a packet subscriber could
    ask for alerts and the per-channel policy would stop meaning anything.
    """
    with client.websocket_connect(_path(Channel.PACKETS)) as websocket:
        _await_connection_count(Channel.PACKETS, 1)

        websocket.send_json({"type": "subscribe", "channel": "alerts"})
        message = _receive_of_type(websocket, EventType.ERROR)

        assert message["data"]["reason"] == REFUSAL_UNKNOWN_TYPE

        # The connection is still a packet subscriber, and still exactly one.
        connections = _manager().get_connections(Channel.PACKETS)
        assert len(connections) == 1
        assert connections[0].channel is Channel.PACKETS
        assert _manager().get_connection_count(Channel.ALERTS) == 0


def test_malformed_json_is_refused(client) -> None:
    """Garbage from something that is not a client costs a length check, then one parse."""
    with client.websocket_connect(_path(Channel.SYSTEM)) as websocket:
        _await_connection_count(Channel.SYSTEM, 1)

        websocket.send_text("{not json at all")

        message = _receive_of_type(websocket, EventType.ERROR)

    assert message["data"]["reason"] == REFUSAL_NOT_JSON
    assert "not json at all" not in str(message)


def test_a_message_without_a_type_is_refused(client) -> None:
    """A JSON object is not a message: the type field is what makes it one."""
    with client.websocket_connect(_path(Channel.SYSTEM)) as websocket:
        _await_connection_count(Channel.SYSTEM, 1)

        websocket.send_json({"hello": "world"})

        message = _receive_of_type(websocket, EventType.ERROR)

    assert message["data"]["reason"] == REFUSAL_MISSING_TYPE


def test_a_binary_frame_is_refused_with_its_own_reason(client) -> None:
    """A byte frame and broken JSON need different fixes, so they read differently."""
    with client.websocket_connect(_path(Channel.SYSTEM)) as websocket:
        _await_connection_count(Channel.SYSTEM, 1)

        websocket.send_bytes(b"\x00\x01\x02\x03")

        message = _receive_of_type(websocket, EventType.ERROR)

    assert message["data"]["reason"] == REFUSAL_NOT_TEXT


def test_an_oversized_message_is_refused_before_it_is_parsed(client) -> None:
    """The cap is checked first, so a large frame cannot spend the JSON parser."""
    limit = int(settings.websocket_max_client_message_bytes)
    filler = "x" * (limit + 64)

    with client.websocket_connect(_path(Channel.SYSTEM)) as websocket:
        _await_connection_count(Channel.SYSTEM, 1)

        websocket.send_json({"type": "ping", "nonce": filler})

        message = _receive_of_type(websocket, EventType.ERROR)

    assert message["data"]["reason"] == REFUSAL_TOO_LARGE
    # Not one byte of the rejected frame is reflected back.
    assert "xxxx" not in str(message)


def test_a_flood_of_invalid_messages_disconnects_the_client(client) -> None:
    """A garbage flood must not consume the server indefinitely (M14.23).

    The count of refusal frames is deliberately not asserted exactly: the route
    queues an `error` and then closes the socket directly, and a close can overtake
    a queued frame the sender has not written yet. What is asserted is what the
    design promises — every answered frame names the rule, and the client is
    disconnected.
    """
    limit = int(settings.websocket_max_invalid_messages)
    received: list[dict] = []

    # The whole session sits inside the expectation, not just the reads: the
    # *server* closes this socket, and the test client may surface that when the
    # session is exited rather than when a frame is asked for. Which of the two it
    # is is an artefact of the client, not of the behaviour under test.
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(_path(Channel.SYSTEM)) as websocket:
            _await_connection_count(Channel.SYSTEM, 1)

            for _ in range(limit):
                websocket.send_json({"type": "not-a-real-type"})

            for _ in range(limit + 1):
                received.append(websocket.receive_json())

    # The connection is gone from the registry, so nothing is left holding a
    # queue the server will never drain.
    _await_total_connection_count(0)
    assert received, "at least one refusal must be answered before the close"
    assert all(message["type"] == EventType.ERROR for message in received)
    assert all(
        message["data"]["reason"] == REFUSAL_UNKNOWN_TYPE for message in received
    )


# ---------------------------------------------------------------------------
# Separation and the caps, across live sockets (M14.6/M14.22)
# ---------------------------------------------------------------------------


def test_separation_holds_across_two_live_sockets(client) -> None:
    """Two sockets, three events, and neither sees the other's traffic.

    Interleaved deliberately — packet, system, packet — so a leak in either
    direction changes *which* frame a subscriber reads first rather than merely
    adding one it could be written off as noise. That is why the frames are read
    with a plain ``receive_json`` and their type asserted: the skipping helper used
    by the other tests would walk straight past a leaked frame and report success,
    which is precisely the failure this test exists to catch.

    These two channels are used because neither carries anything else while the
    test runs. The dashboard tick is bounded to its own channel and refuses to
    sample without a dashboard subscriber, and the keepalive interval is far
    longer than a test, so "the first frame" is well defined on both sockets.
    """
    with client.websocket_connect(_path(Channel.PACKETS)) as packets:
        with client.websocket_connect(_path(Channel.SYSTEM)) as system:
            _await_connection_count(Channel.PACKETS, 1)
            _await_connection_count(Channel.SYSTEM, 1)

            _manager().publish(_packet_event())
            _manager().publish(_service_event("first"))
            _manager().publish(_packet_event())

            first = packets.receive_json()
            second = packets.receive_json()
            state = system.receive_json()

    assert first["type"] == EventType.PACKET_OBSERVED
    assert second["type"] == EventType.PACKET_OBSERVED
    assert first["channel"] == Channel.PACKETS.value
    assert second["channel"] == Channel.PACKETS.value
    assert second["sequence"] > first["sequence"]

    assert state["type"] == EventType.SERVICE_STATUS
    assert state["channel"] == Channel.SYSTEM.value
    assert state["data"]["state"] == "first"


def test_the_per_channel_cap_is_enforced_over_the_wire(client) -> None:
    """The last subscriber the caps allow is admitted; the next one is refused.

    Asserted through the manager rather than the exception alone, because the
    invariant is that a refused socket is *never registered*: admitting and then
    dropping would leave a broadcast able to reach a client that was never let in
    (M14.22).

    The cap is read as the smaller of the process and per-channel limits instead of
    being taken from one of them, because the manager enforces both. A test that
    assumed only the per-channel number would start being refused earlier than it
    expected the moment the process cap was configured below it.
    """
    cap = min(
        int(settings.websocket_max_connections),
        int(settings.websocket_max_connections_per_channel),
    )
    before = _manager().get_counters()["connections_refused"]

    with contextlib.ExitStack() as stack:
        for _ in range(cap):
            stack.enter_context(client.websocket_connect(_path(Channel.PACKETS)))
        _await_connection_count(Channel.PACKETS, cap)

        # The handshake is accepted and *then* refused, so the disconnect may be
        # reported when the session opens or when the first frame is asked for.
        # Either is the same outcome for the client, so either is accepted.
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(_path(Channel.PACKETS)) as refused:
                refused.receive_json()

        _await_total_connection_count(cap)
        assert _manager().get_connection_count(Channel.PACKETS) == cap
        assert _manager().get_counters()["connections_refused"] == before + 1

    _await_total_connection_count(0)
