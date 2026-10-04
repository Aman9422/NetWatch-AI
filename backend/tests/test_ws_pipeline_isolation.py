"""Tests for failure isolation between the pipeline and the socket layer (M14.30).

M14.14 states the requirement this file exists to prove: a WebSocket failure must
never stop capture, processing, statistics, device tracking, connection tracking,
detection, alerting or correlation. M14.30 is the milestone's own name for that
test.

The structure of the proof is the pipeline's call order. Every consumer runs
*before* the live event is published, so a publisher that fails cannot be reached
until after statistics, devices, connections, detection, alerting and correlation
have all already done their work for a packet. What is asserted here is therefore
both halves of the claim:

* the consumers advanced — the packets were counted, the devices attributed, the
  conversation tracked, the finding made, the alert stored, the incident opened;
* no consumer recorded an error, and the pipeline published nothing, so the
  WebSocket fault stayed where it belongs (M14.14's "a broken client is removed,
  not propagated", and its sibling: a broken *layer* is counted, not propagated).

Three kinds of failure are forced, because "the WebSocket layer failed" is not one
thing:

1. **The publisher raises.** The worst case — the whole seam is broken. Contained
   by ``publish_packet``, which is the one call site the pipeline has.
2. **The manager has no loop.** The layer is off, or shutting down, or the process
   is a unit test with no application around it. ``publish`` returns ``False`` and
   counts ``dropped_no_loop``; nothing raises, and the pipeline is unaffected.
3. **The manager's loop-side fan-out raises.** The publish call *succeeded* — the
   callback was scheduled — and the failure happens later, on the loop, with no
   caller to raise into. Contained by ``_dispatch`` and counted as
   ``publish_errors``. This is the case that would otherwise surface as "Task
   exception was never retrieved" and be invisible.

The harness is the real pipeline with every M6–M12 consumer wired, and packets
enter it exactly as they do in production except that the Scapy callback is
replaced by a direct call to ``process``. That is the same normalizer, the same
consumers and the same order; only the sniffer is absent, because the sniffer is
not what is under test.
"""

from __future__ import annotations

import asyncio
from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from app.alerts.engine import AlertEngine
from app.connections.manager import ConnectionTracker
from app.correlation.engine import CorrelationEngine
from app.detection.engine import DetectionEngine
from app.detection.rules.port_scan import PortScanRule
from app.devices.manager import DeviceDiscoveryManager
from app.processing.processor import PacketProcessor
from app.services.packet_pipeline import PacketPipeline
from app.statistics.manager import TrafficStatisticsManager
from app.websockets.channels import Channel
from app.websockets.event import EventType, WebSocketEvent
from app.websockets.manager import WebSocketManager
from app.websockets.publisher import build_publisher
from tests.alert_fakes import make_service, stored_alert_count
from tests.correlation_fakes import make_engine
from tests.ws_fakes import (
    asyncio_test,
    clean_websockets,  # noqa: F401 - fixture, imported for this module
    connect_fake,
    make_event,
    make_manager,
    make_policies,
    managed,
    settle,
)

MAC_A = "AA:BB:CC:DD:EE:FF"
MAC_B = "22:33:44:55:66:77"
SOURCE_IP = "192.168.1.10"
DESTINATION_IP = "8.8.8.8"

#: A threshold low enough that a handful of packets trips the rule, so the alert
#: and correlation stages are genuinely exercised rather than skipped for want of
#: a finding.
PORT_SCAN_THRESHOLD = 5
FIRST_PORT = 4000


def _syn(destination_port: int) -> Any:
    """Build one TCP SYN from the test source to ``destination_port``."""
    return (
        Ether(src=MAC_A, dst=MAC_B)
        / IP(src=SOURCE_IP, dst=DESTINATION_IP)
        / TCP(sport=52000, dport=destination_port, flags="S")
    )


def _sweep(count: int) -> list[Any]:
    """Return ``count`` SYNs across distinct destination ports."""
    return [_syn(FIRST_PORT + index) for index in range(count)]


#: One more SYN than the rule needs, so a finding is produced on the last packet.
A_SWEEP = PORT_SCAN_THRESHOLD + 1


class ExplodingPublisher:
    """An ``EventPublisher`` whose every call raises (M14.14).

    Structurally the protocol — two methods — and deliberately nothing else, so a
    test that passes cannot be exercising some accident of the real publisher.
    """

    def __init__(self) -> None:
        self.attempts = 0

    @property
    def enabled(self) -> bool:
        """Report the layer as on, so the failure is not a configured one."""
        return True

    def publish(self, event: WebSocketEvent) -> bool:
        """Raise, as a broken transport would."""
        self.attempts += 1
        raise RuntimeError("simulated WebSocket failure")

    def publish_many(self, events: Any) -> int:
        """Raise, for the same reason as :meth:`publish`."""
        self.attempts += 1
        raise RuntimeError("simulated WebSocket failure")


class ExplodingBroadcastManager(WebSocketManager):
    """A manager whose loop-side fan-out always fails (M14.14).

    ``publish`` still succeeds — it only schedules — so the failure lands on the
    loop with no caller left to raise into, which is precisely the case
    ``_dispatch`` exists to contain.
    """

    def broadcast(self, event: WebSocketEvent) -> int:
        """Raise, as a bug in the fan-out would."""
        raise RuntimeError("simulated fan-out failure")


class PipelineHarness:
    """The real pipeline with every M6–M12 consumer wired to a publisher."""

    def __init__(self, *, events: Any, session_factory: Any) -> None:
        self.statistics = TrafficStatisticsManager()
        self.devices = DeviceDiscoveryManager()
        self.connections = ConnectionTracker(
            device_registry=self.devices.registry, autostart_cleanup=False
        )
        self.detection = DetectionEngine(
            [
                PortScanRule(
                    unique_port_threshold=PORT_SCAN_THRESHOLD, window_seconds=60.0
                )
            ]
        )
        self.alerts = AlertEngine(make_service(session_factory))
        self.correlation: CorrelationEngine = make_engine()
        self.pipeline = PacketPipeline(
            processor=PacketProcessor(),
            statistics=self.statistics,
            devices=self.devices,
            connections=self.connections,
            detection=self.detection,
            alerts=self.alerts,
            correlation=self.correlation,
            events=events,
        )

    def feed(self, packets: list[Any]) -> None:
        """Push every packet through the real pipeline, in order."""
        for packet in packets:
            self.pipeline.process(packet)

    def assert_every_consumer_advanced(self, packets: list[Any]) -> None:
        """Assert all seven stages did their work for ``packets``.

        The shared assertion of every test in this file: whatever the WebSocket
        layer did, this is what the rest of the application must have done.
        """
        assert self.pipeline.get_processed_count() == len(packets)
        assert self.statistics.get_statistics().total_packets == len(packets)
        assert self.devices.get_device_count() == 2
        assert self.connections.get_active_count() == len(packets)
        assert len(self.detection.get_findings()) == 1
        assert self.correlation.count_incidents() == 1

    def assert_no_stage_recorded_an_error(self) -> None:
        """Assert no consumer failed — the counters M14.14 requires to stay zero."""
        assert self.pipeline.get_processing_error_count() == 0
        assert self.pipeline.get_statistics_error_count() == 0
        assert self.pipeline.get_device_error_count() == 0
        assert self.pipeline.get_connection_error_count() == 0
        assert self.pipeline.get_detection_error_count() == 0
        assert self.pipeline.get_alert_error_count() == 0
        assert self.pipeline.get_correlation_error_count() == 0


# ---------------------------------------------------------------------------
# 1. The publisher raises (M14.14)
# ---------------------------------------------------------------------------


def test_a_raising_publisher_does_not_stop_any_consumer(session_factory: Any) -> None:
    """The worst case: the whole publish seam is broken, and nothing else cares.

    Every stage is asserted rather than only the last one, because "capture kept
    running" would be satisfied by a pipeline that silently abandoned statistics,
    devices, connections, detection, alerting and correlation on the way.
    """
    publisher = ExplodingPublisher()
    harness = PipelineHarness(events=publisher, session_factory=session_factory)
    packets = _sweep(A_SWEEP)

    harness.feed(packets)

    harness.assert_every_consumer_advanced(packets)
    harness.assert_no_stage_recorded_an_error()
    assert stored_alert_count(session_factory) == 1
    assert publisher.attempts == len(packets)


def test_a_raising_publisher_is_never_counted_as_a_publish(session_factory: Any) -> None:
    """The pipeline counts accepted publishes, so a contained failure is a zero.

    This is the observable that makes the isolation honest: the pipeline's own
    counter says nothing reached the stream, so a reader comparing it against the
    manager's counters can see the loss rather than infer it.
    """
    harness = PipelineHarness(
        events=ExplodingPublisher(), session_factory=session_factory
    )

    harness.feed(_sweep(A_SWEEP))

    assert harness.pipeline.get_published_packet_count() == 0


def test_the_live_event_is_published_after_every_consumer_has_finished(
    session_factory: Any,
) -> None:
    """M14.8's ordering, asserted from inside the publish itself.

    A publisher that reads the application's state at the moment it is called is
    the only way to observe the order ``process`` really uses: the counters are
    checked at the seam rather than afterwards, when every stage has finished and
    the order would be invisible.
    """
    observed: list[dict[str, int]] = []

    class RecordingPublisher:
        """A publisher that snapshots the application each time it is called."""

        @property
        def enabled(self) -> bool:
            """Report the layer as on."""
            return True

        def publish(self, event: WebSocketEvent) -> bool:
            """Record the state this event was published into, and accept it."""
            observed.append(
                {
                    "processed": harness.pipeline.get_processed_count(),
                    "alerts": stored_alert_count(session_factory),
                    "incidents": harness.correlation.count_incidents(),
                }
            )
            return True

        def publish_many(self, events: Any) -> int:
            """Accept several events, one at a time."""
            return sum(1 for event in events if self.publish(event))

    harness = PipelineHarness(events=RecordingPublisher(), session_factory=session_factory)
    harness.feed(_sweep(A_SWEEP))

    assert len(observed) == A_SWEEP
    # The packet is already counted by the time its own event is published: the
    # event describes work that has happened, not work that is about to.
    assert all(state["processed"] >= 1 for state in observed)
    # And on the last packet, the alert and the incident it belongs to exist.
    assert observed[-1]["alerts"] == 1
    assert observed[-1]["incidents"] == 1


# ---------------------------------------------------------------------------
# 2. The manager has no loop (M14.14/M14.21)
# ---------------------------------------------------------------------------


def test_a_manager_with_no_bound_loop_is_a_counted_drop(session_factory: Any) -> None:
    """Before startup, or after shutdown, there is nowhere to hand an event.

    The path a unit test and a shutdown race both take: counted, never raised, and
    the pipeline is unaffected — which is what keeps the capture thread safe when
    the application is not running around it.
    """
    manager = make_manager(policies=make_policies(packet_rate=None))
    harness = PipelineHarness(
        events=build_publisher(manager), session_factory=session_factory
    )
    packets = _sweep(A_SWEEP)

    harness.feed(packets)

    harness.assert_every_consumer_advanced(packets)
    harness.assert_no_stage_recorded_an_error()
    assert harness.pipeline.get_published_packet_count() == 0
    assert manager.get_counters()["dropped_no_loop"] == len(packets)
    assert manager.get_counters()["publish_errors"] == 0


def test_a_disabled_layer_is_a_zero_cost_path(session_factory: Any) -> None:
    """``websockets_enabled`` false costs one boolean per packet, nothing more."""
    manager = make_manager(enabled=False, policies=make_policies(packet_rate=None))
    harness = PipelineHarness(
        events=build_publisher(manager), session_factory=session_factory
    )
    packets = _sweep(A_SWEEP)

    harness.feed(packets)

    harness.assert_every_consumer_advanced(packets)
    harness.assert_no_stage_recorded_an_error()
    assert manager.get_counters()["dropped_disabled"] == len(packets)
    assert harness.pipeline.get_published_packet_count() == 0


@asyncio_test
async def test_a_layer_shut_down_mid_run_does_not_stop_the_pipeline(
    session_factory: Any,
) -> None:
    """The realistic end: the socket layer goes away and capture carries on.

    Shot down *while* packets are flowing, which is the case that matters: the
    frames that were delivered are delivered, the ones after the shutdown are
    counted as dropped, and every consumer keeps its state intact throughout.
    """
    manager = make_manager(policies=make_policies(packet_rate=None))
    async with managed(manager):
        await manager.start()
        socket, _ = await connect_fake(manager, Channel.PACKETS)
        harness = PipelineHarness(
            events=build_publisher(manager), session_factory=session_factory
        )
        packets = _sweep(A_SWEEP)

        harness.feed(packets)
        await settle()

        assert socket.types() == [EventType.PACKET_OBSERVED] * len(packets)
        assert harness.pipeline.get_published_packet_count() == len(packets)

        await manager.shutdown()
        delivered = len(socket.sent)

        harness.pipeline.process(_syn(FIRST_PORT + 100))
        await settle()

        assert len(socket.sent) == delivered
        assert harness.pipeline.get_processed_count() == len(packets) + 1
        assert harness.pipeline.get_published_packet_count() == len(packets)
        assert manager.get_counters()["dropped_no_loop"] == 1
        harness.assert_no_stage_recorded_an_error()


# ---------------------------------------------------------------------------
# 3. The manager's loop-side fan-out raises (M14.14)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_a_loop_side_fan_out_failure_is_contained_and_counted() -> None:
    """The failure with no caller left to raise into, which is the easy one to miss.

    ``publish`` returns ``True`` here because it only schedules; the raise happens
    later, inside the loop callback. Without ``_dispatch``'s containment that would
    reach the loop's exception handler as "Task exception was never retrieved" and
    nobody would ever count it — the fault would be real and invisible, which is
    the one outcome M14.14's third mechanism forbids.
    """
    manager = ExplodingBroadcastManager(policies=make_policies(packet_rate=None))
    async with managed(manager):
        await manager.start()
        pipeline = PacketPipeline(events=build_publisher(manager))
        packets = _sweep(A_SWEEP)

        for packet in packets:
            pipeline.process(packet)
        await settle()

        assert pipeline.get_processed_count() == len(packets)
        assert pipeline.get_statistics_error_count() == 0
        assert pipeline.get_device_error_count() == 0
        # Accepted at the call site, failed on the loop: both facts at once.
        assert pipeline.get_published_packet_count() == len(packets)
        assert manager.get_counters()["publish_errors"] == len(packets)


@asyncio_test
async def test_the_loop_survives_a_failing_dispatch() -> None:
    """Containment is not a one-off: the tenth failure is handled like the first.

    A loop that logged the first failure and then died would pass a single-event
    test and fail in production, so the same manager is driven ten times and the
    loop is then proved to still be executing work by scheduling a marker onto it.
    """
    manager = ExplodingBroadcastManager(policies=make_policies(packet_rate=None))
    async with managed(manager):
        await manager.start()
        publisher = build_publisher(manager)
        event = make_event()

        for _ in range(10):
            assert publisher.publish(event) is True
        await settle()

        assert manager.get_counters()["publish_errors"] == 10

        # The loop is still alive and still running callbacks: the marker is set
        # by the loop itself, after ten contained failures.
        loop = asyncio.get_running_loop()
        marker = asyncio.Event()
        loop.call_soon(marker.set)
        await asyncio.wait_for(marker.wait(), timeout=1.0)

        assert marker.is_set() is True
        assert manager.is_running is True
