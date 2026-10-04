"""Unit tests for the publish seam (M14.13).

The publisher is the only part of M14 the rest of the application touches, so its
contract is worth pinning down precisely. It has exactly three implementations and
one job: hand an event over, never wait, never raise, and report whether the event
was accepted. Every service in M4→M12 depends on those four properties holding for
*any* input, including a manager that has been shut down and a manager that is
simply broken.

The file covers:

* the two real implementations and the null one, and that ``None`` becomes the null
  one rather than a ``None`` check at every publish site;
* ``enabled`` mirroring the underlying layer, which is what lets a caller report
  whether the real-time view is on without opening the manager;
* the containment guarantee of M14.14 — a manager that raises must not raise
  through a publisher, because the caller is the capture thread;
* the paths that legitimately take an event and deliver it to nobody: no bound loop
  (before startup, after shutdown) and the disabled layer;
* the cross-thread handoff of M14.21 working from a genuinely different thread, not
  merely from the loop's own thread.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

from app.websockets.channels import Channel
from app.websockets.event import EventType, WebSocketEvent
from app.websockets.publisher import (
    EventPublisher,
    NullEventPublisher,
    WebSocketEventPublisher,
    build_publisher,
    ensure_publisher,
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
    settle,
)


class _ExplodingManager:
    """A manager whose ``publish`` raises, standing in for a broken transport.

    Structurally a dispatch target: it has the two attributes the publisher reads
    and nothing else, so it cannot accidentally work for another reason.
    """

    @property
    def enabled(self) -> bool:
        """Report the layer as on, so only the raise is under test."""
        return True

    def publish(self, event: WebSocketEvent) -> bool:
        """Raise, as a transport bug would."""
        raise RuntimeError("transport is broken")


# ---------------------------------------------------------------------------
# The contract and the implementations that satisfy it (M14.13)
# ---------------------------------------------------------------------------


def test_both_implementations_satisfy_the_publisher_protocol() -> None:
    """``EventPublisher`` is runtime-checkable, so conformance is assertable.

    The check matters because the services are typed against the protocol, and an
    implementation that drifted from it would otherwise fail only at a call site.
    """
    assert isinstance(NullEventPublisher(), EventPublisher)
    assert isinstance(WebSocketEventPublisher(_ExplodingManager()), EventPublisher)


def test_the_null_publisher_accepts_nothing_and_reports_it() -> None:
    """``False`` means "no subscriber will see this", in every implementation."""
    publisher = NullEventPublisher()

    assert publisher.enabled is False
    assert publisher.publish(make_event()) is False
    assert publisher.publish_many([make_event(), make_event()]) == 0


def test_the_null_publisher_never_raises() -> None:
    """It is the default collaborator, so it must be total for any event."""
    publisher = NullEventPublisher()

    assert publisher.publish(make_event(data={"nested": {"deep": [1, 2, 3]}})) is False


def test_build_publisher_returns_a_null_publisher_for_no_manager() -> None:
    """``build_publisher(None)`` is the one place "no manager" becomes "no sink"."""
    assert isinstance(build_publisher(None), NullEventPublisher)


def test_build_publisher_wraps_a_manager() -> None:
    """A manager with the right shape is wrapped, not adapted per call site."""
    manager = make_manager()

    publisher = build_publisher(manager)

    assert isinstance(publisher, WebSocketEventPublisher)
    assert publisher.manager is manager


def test_ensure_publisher_returns_the_publisher_it_was_given() -> None:
    """An injected publisher is used as-is, never re-wrapped."""
    publisher = NullEventPublisher()

    assert ensure_publisher(publisher) is publisher


def test_ensure_publisher_substitutes_a_null_publisher_for_none() -> None:
    """This substitution is what keeps the branch out of every publish site."""
    assert isinstance(ensure_publisher(None), NullEventPublisher)


def test_the_publisher_reports_the_layer_it_forwards_to() -> None:
    """``enabled`` is the layer's own answer, so a caller cannot disagree with it."""
    enabled = WebSocketEventPublisher(make_manager(enabled=True))
    disabled = WebSocketEventPublisher(make_manager(enabled=False))

    assert enabled.enabled is True
    assert disabled.enabled is False


# ---------------------------------------------------------------------------
# Containment (M14.14)
# ---------------------------------------------------------------------------


def test_a_manager_that_raises_does_not_raise_through_the_publisher() -> None:
    """The caller is the capture thread, so this call must be total.

    A ``TypeError`` from a projection, an attribute that no longer exists, a
    transport bug: none of them may travel back up the pipeline.
    """
    publisher = WebSocketEventPublisher(_ExplodingManager())

    assert publisher.publish(make_event()) is False


def test_publish_many_counts_only_the_events_a_broken_manager_took() -> None:
    """A partially broken batch reports what actually got through, which is none."""
    publisher = WebSocketEventPublisher(_ExplodingManager())

    assert publisher.publish_many([make_event(), make_event(), make_event()]) == 0
# ---------------------------------------------------------------------------
# The paths that deliver to nobody (M14.14/M14.21)
# ---------------------------------------------------------------------------


def test_a_publish_with_no_bound_loop_is_dropped_rather_than_raising() -> None:
    """Before startup there is no loop, so there is nowhere to hand the event.

    This is the case a unit test of the pipeline hits, and the one M14.21 requires
    to be a counted drop rather than an exception: a service must be publishable
    with no application running around it.
    """
    manager = make_manager()

    assert manager.publish(make_event()) is False
    assert manager.get_counters()["dropped_no_loop"] == 1


def test_a_publish_to_a_disabled_layer_is_dropped_and_counted() -> None:
    """The master switch costs nothing per event, not even a loop lookup."""
    manager = make_manager(enabled=False)

    assert manager.publish(make_event()) is False
    assert manager.get_counters()["dropped_disabled"] == 1


def test_a_publish_after_shutdown_is_dropped_rather_than_raising() -> None:
    """A shutdown race must not reach the capture thread (M14.14)."""

    async def scenario() -> bool:
        manager = make_manager()
        async with managed(manager):
            await manager.start()
        return manager.publish(make_event())

    assert asyncio.run(scenario()) is False


@asyncio_test
async def test_publish_many_reports_how_many_events_were_accepted() -> None:
    """A batch result is the count that actually reached the loop."""
    manager = make_manager()
    async with managed(manager):
        await manager.start()
        publisher = build_publisher(manager)

        accepted = publisher.publish_many([make_event(), make_event()])

        assert accepted == 2
        assert manager.get_counters()["published"] == 2


# ---------------------------------------------------------------------------
# The handoff actually delivering (M14.13/M14.21)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_a_publisher_hands_an_event_to_the_connected_channel() -> None:
    """The end-to-end shape: a service publishes, a subscriber has the event."""
    manager = make_manager(policies=make_policies(packet_rate=None))
    async with managed(manager):
        await manager.start()
        socket, _ = await connect_fake(manager, Channel.PACKETS)
        publisher = build_publisher(manager)

        assert publisher.publish(packet_event()) is True
        await settle()

        # Asserted on the socket, not on the connection's queue: the sender task
        # drains the queue as soon as the loop turns, so by the time this test can
        # look the frame has already been written. ``queued_*`` is for the tests
        # that inspect fan-out without yielding to the loop at all.
        assert socket.types() == [EventType.PACKET_OBSERVED]


@asyncio_test
async def test_a_publish_from_a_worker_thread_reaches_the_loop() -> None:
    """M14.21's whole reason for existing, exercised from another thread.

    The capture pipeline runs on a Scapy worker thread, so ``publish`` has to work
    when it is called from one. Doing it here — rather than calling ``publish`` from
    the loop's own thread — is what actually tests ``call_soon_threadsafe`` instead
    of a direct call.
    """
    manager = make_manager(policies=make_policies(packet_rate=None))
    async with managed(manager):
        await manager.start()
        socket, _ = await connect_fake(manager, Channel.PACKETS)
        publisher = build_publisher(manager)

        with ThreadPoolExecutor(max_workers=1) as pool:
            accepted = pool.submit(publisher.publish, packet_event()).result()

        for _ in range(50):
            if socket.sent:
                break
            await settle()

        assert accepted is True
        assert socket.types() == [EventType.PACKET_OBSERVED]


@asyncio_test
async def test_publishing_from_a_worker_thread_never_blocks() -> None:
    """The call returns before the loop has done anything with the event.

    That is the property that protects capture: a busy or stalled loop cannot slow
    the publisher down, because the publisher only schedules and returns.
    """
    manager = make_manager(policies=make_policies(packet_rate=None))
    async with managed(manager):
        await manager.start()
        publisher = build_publisher(manager)

        def publish_ten() -> int:
            return publisher.publish_many([packet_event() for _ in range(10)])

        with ThreadPoolExecutor(max_workers=1) as pool:
            accepted = pool.submit(publish_ten).result()

        assert accepted == 10
        assert manager.get_counters()["published"] == 10
