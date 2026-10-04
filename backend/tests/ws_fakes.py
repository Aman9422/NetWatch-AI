"""Shared builders and doubles for the M14 WebSocket tests.

The M14 surface has four channels, a manager, a policy table and a set of
publishers, and every test file needs the same few things: a socket that records
what was written to it instead of an ASGI stack, a manager whose thresholds are
small enough to reach, and event builders that produce exactly one documented
shape.

Putting those here follows the convention the rest of the suite uses
(``tests.fakes``, ``tests.m13_fakes``, ``tests.alert_fakes``): builders live in a
``*_fakes`` module and hold no assertions.

Three doubles carry most of the weight:

* :class:`FakeSocket` — records every frame, can be told to fail after *n* sends,
  and can be told to hang inside a send. Those behaviours are what M14.14 and
  M14.15 are about, so a test can produce a broken or a slow client with no
  network involved.
* :func:`queued_messages` — pulls the encoded frames straight out of a
  connection's queue. Fan-out, dropping and rate limiting are all decided on the
  dispatch side, so a test that inspects the queue observes them without needing
  the sender task to have run at a particular moment.
* :func:`asyncio_test` — the suite has no ``pytest-asyncio`` (see
  ``backend/requirements.txt``), so every async test in ``test_ws_*`` is a plain
  synchronous function decorated with this, which runs the coroutine on a fresh
  loop. The alternative — a hand-written ``asyncio.run`` in each test — buries the
  assertions under boilerplate.

and one fixture, :func:`clean_websockets`, imported explicitly by each
``test_ws_*`` module rather than installed globally: the other 1600 tests have no
business resetting the WebSocket singletons.
"""

from __future__ import annotations

import asyncio
import functools
import json
from collections.abc import AsyncIterator, Callable, Coroutine, Generator
from contextlib import asynccontextmanager
from typing import Any, TypeVar

import pytest

from app.config.settings import Settings
from app.schemas.capture import CaptureStatusData
from app.websockets.channels import CHANNELS, Channel
from app.websockets.connection import ClientConnection
from app.websockets.event import (
    EventType,
    JsonDocument,
    WebSocketEvent,
    iso_utc,
    next_sequence,
    reset_sequence,
)
from app.websockets.manager import WebSocketManager
from app.websockets.policy import (
    ChannelPolicy,
    PolicySet,
    TokenBucket,
    build_policy_set,
    default_policies,
)
from tests.fakes import PACKET_BASE_TIME, make_normalized_packet

T = TypeVar("T")


def asyncio_test(
    fn: Callable[..., Coroutine[Any, Any, T]],
) -> Callable[..., T]:
    """Run an ``async def`` test on a fresh event loop (test infrastructure).

    Needed because the suite deliberately carries no ``pytest-asyncio``: an
    ``async def`` test without a plugin is silently skipped by pytest, which would
    look like a passing suite while nothing ran. This wrapper is explicit and
    loud — the test body is a real coroutine, and the loop it runs on is created
    and closed per test so no task, queue or bound loop leaks between them.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> T:
        return asyncio.run(fn(*args, **kwargs))

    return wrapper


class FakeSocket:
    """A stand-in for a Starlette ``WebSocket`` (M14.14/M14.15).

    Args:
        fail_after: Fail the send once ``n`` frames have already been written,
            standing in for a client that vanished mid-session.
        hang: Sleep inside every send until the send timeout cancels it,
            standing in for a client that is connected but not reading.
    """

    def __init__(self, *, fail_after: int | None = None, hang: bool = False) -> None:
        self.sent: list[str] = []
        self.closed = False
        self.close_code: int | None = None
        self.close_reason: str | None = None
        self.fail_after = fail_after
        self.hang = hang

    async def send_text(self, data: str) -> None:
        """Record one frame, or fail, or block, exactly as configured."""
        if self.fail_after is not None and len(self.sent) >= self.fail_after:
            raise RuntimeError("simulated socket failure")
        if self.hang:
            await asyncio.sleep(3600)
        self.sent.append(data)

    async def close(self, code: int = 1000, reason: str | None = None) -> None:
        """Record the close and its code, as the real socket would send them."""
        self.closed = True
        self.close_code = code
        self.close_reason = reason

    def messages(self) -> list[dict]:
        """Return every frame this socket received, decoded."""
        return [json.loads(item) for item in self.sent]

    def types(self) -> list[str]:
        """Return the event type of every frame this socket received."""
        return [message["type"] for message in self.messages()]

    def payloads(self) -> list[dict]:
        """Return the ``data`` of every frame this socket received."""
        return [message["data"] for message in self.messages()]


def make_manager(
    *,
    policies: PolicySet | None = None,
    max_connections: int = 8,
    max_connections_per_channel: int = 4,
    max_event_bytes: int = 4096,
    send_timeout_seconds: float = 0.5,
    enabled: bool = True,
) -> WebSocketManager:
    """Return a manager with thresholds small enough for a test to reach."""
    return WebSocketManager(
        policies=policies if policies is not None else default_policies(),
        max_connections=max_connections,
        max_connections_per_channel=max_connections_per_channel,
        max_event_bytes=max_event_bytes,
        send_timeout_seconds=send_timeout_seconds,
        enabled=enabled,
    )


def make_policies(
    *,
    packet_queue_size: int = 256,
    packet_rate: float | None = 200.0,
    packet_enabled: bool = True,
    dashboard_queue_size: int = 32,
    alert_queue_size: int = 512,
    system_queue_size: int = 128,
) -> PolicySet:
    """Return a policy table with the packet channel's knobs exposed.

    The packet channel is the one the tests exercise for rate control and queue
    depth, so its values are arguments while the other three keep the documented
    defaults — a test that changes one channel should not have to restate three.
    """
    policies: dict[Channel, ChannelPolicy] = {
        Channel.PACKETS: ChannelPolicy(
            channel=Channel.PACKETS,
            queue_size=packet_queue_size,
            max_events_per_second=packet_rate,
            priority="telemetry",
            enabled=packet_enabled,
        ),
        Channel.DASHBOARD: ChannelPolicy(
            channel=Channel.DASHBOARD,
            queue_size=dashboard_queue_size,
            priority="telemetry",
        ),
        Channel.ALERTS: ChannelPolicy(
            channel=Channel.ALERTS, queue_size=alert_queue_size, priority="security"
        ),
        Channel.SYSTEM: ChannelPolicy(
            channel=Channel.SYSTEM, queue_size=system_queue_size, priority="state"
        ),
    }
    return PolicySet(
        policies=policies,
        buckets={
            channel: TokenBucket(policy.max_events_per_second)
            for channel, policy in policies.items()
        },
    )


def settings_with(**overrides: object) -> Settings:
    """Return a ``Settings`` built with ``overrides`` (M14.16).

    Constructed directly rather than read from the cached module-level instance,
    so a developer's ``.env`` cannot change what a test asserts.
    """
    return Settings(**overrides)  # type: ignore[arg-type]


def policies_from(**overrides: object) -> PolicySet:
    """Return the policy table ``settings_with(**overrides)`` produces."""
    return build_policy_set(settings_with(**overrides))


def make_event(
    *,
    event_type: str = EventType.SERVICE_STATUS,
    channel: Channel = Channel.SYSTEM,
    data: JsonDocument | None = None,
    sequence: int | None = None,
) -> WebSocketEvent:
    """Build one enveloped event with a fixed timestamp (M14.7)."""
    return WebSocketEvent(
        type=event_type,
        channel=channel,
        timestamp=iso_utc(PACKET_BASE_TIME) or "",
        source="tests",
        sequence=next_sequence() if sequence is None else sequence,
        data=data if data is not None else {},
    )


def packet_event(packet_id: int = 1, sequence: int | None = None) -> WebSocketEvent:
    """Build a real ``packet.observed`` event through the M14 builder (M14.8)."""
    from app.websockets import builders

    event = builders.packet_event(
        make_normalized_packet(packet_id=packet_id), timestamp=PACKET_BASE_TIME
    )
    if sequence is None:
        return event
    return event.model_copy(update={"sequence": sequence})


def capture_status(
    *, status: str = "running", interface: str | None = "Wi-Fi", packet_count: int = 7
) -> CaptureStatusData:
    """Build the capture state a ``capture.*`` event carries (M14.11)."""
    return CaptureStatusData(
        status=status, interface=interface, packet_count=packet_count
    )


async def connect_fake(
    manager: WebSocketManager, channel: Channel, **socket_kwargs: object
) -> tuple[FakeSocket, ClientConnection]:
    """Connect a fake socket to ``channel`` and return both halves."""
    socket = FakeSocket(**socket_kwargs)  # type: ignore[arg-type]
    connection = await manager.connect(socket, channel)
    return socket, connection


@asynccontextmanager
async def managed(manager: WebSocketManager) -> AsyncIterator[WebSocketManager]:
    """Yield ``manager`` and shut it down however the test ends.

    Every test that connects a socket starts a sender task, and a task still
    pending when ``asyncio.run`` closes the loop is reported as "Task was
    destroyed but it is pending" — noise that can bury a real failure. One helper
    that always calls ``shutdown`` keeps the M14 tests quiet, and because
    ``shutdown`` is idempotent it is safe for a test that shut down explicitly.
    """
    try:
        yield manager
    finally:
        await manager.shutdown()


async def settle() -> None:
    """Let queued loop callbacks and sender tasks run.

    ``broadcast`` is synchronous but the *sender* task that moves a queued frame
    onto a socket is not, so a test that asserts on ``socket.sent`` has to yield
    to the loop first. One sleep of zero is not always enough — a task scheduled
    by ``call_soon`` needs the loop to reach it — so a couple of turns are given.
    """
    for _ in range(3):
        await asyncio.sleep(0)


def queued_messages(connection: ClientConnection) -> list[dict]:
    """Drain a connection's queue and decode what was in it.

    Draining rather than peeking is deliberate: the queue is the observable the
    dispatch side writes to, so decoding exactly what is in it asserts on the
    fan-out decision rather than on the sender's timing.
    """
    messages: list[dict] = []
    while not connection.queue.empty():
        messages.append(json.loads(connection.queue.get_nowait()))
    return messages


def queued_types(connection: ClientConnection) -> list[str]:
    """Return the event types queued for ``connection``, in order."""
    return [message["type"] for message in queued_messages(connection)]


def queued_count(connection: ClientConnection) -> int:
    """Return how many messages are waiting in ``connection``'s queue."""
    return connection.queue.qsize()


@pytest.fixture(autouse=True)
def clean_websockets() -> Generator[None, None, None]:
    """Give one M14 test a fresh singleton layer and a fresh sequence.

    Imported explicitly by each ``test_ws_*`` module rather than installed
    globally: the other tests have no business resetting the WebSocket
    singletons, and a module that needs a clean layer should say so. Resetting
    *before* the client fixture runs is what matters — the application lifespan
    then binds its loop and builds its registry on the fresh manager.
    """
    from app.websockets import reset_websockets

    reset_websockets()
    reset_sequence()
    try:
        yield
    finally:
        reset_websockets()
        reset_sequence()


__all__ = [
    "CHANNELS",
    "FakeSocket",
    "asyncio_test",
    "capture_status",
    "clean_websockets",
    "connect_fake",
    "make_event",
    "make_manager",
    "make_policies",
    "managed",
    "packet_event",
    "policies_from",
    "queued_count",
    "queued_messages",
    "queued_types",
    "settle",
    "settings_with",
]
