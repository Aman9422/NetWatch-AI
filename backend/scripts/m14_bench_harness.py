"""Shared machinery for the M14 performance baseline (M14.33).

``benchmark_m14.py`` measures the WebSocket layer; this module builds the things
it measures, so the measurement file is about measuring and this one is about
wiring. Two halves:

* **the live stack** — the real M6–M12 consumers and the real M4 pipeline, over a
  throwaway SQLite file, publishing through the *process* publisher so the events
  a benchmark drives travel the production publish site, the production publisher
  and the production manager's thread handoff (M14.13/M14.21). Only the capture
  sniffer is absent, because the benchmark drives the pipeline directly rather
  than pretending to capture;
* **the clients** — a socket reader that can wait with a deadline (so a missing
  frame is a reported failure, not a hung run) and a client that deliberately
  never drains, which is how the bounded-queue policy is measured rather than
  asserted (M14.15).

Nothing here is a mock of the thing being measured: the manager, the connections,
the policy table, the envelopes and the pipeline are the shipped ones. The
throwaway database, the recorded publisher and the two client helpers are the
only additions, and each exists to make a measurement possible without touching
the developer's data or hanging on a frame that never comes.

Settings are read once by the manager when it is first constructed, so
:func:`lab_websocket_settings` must wrap the first ``get_websocket_manager()``
call as well as every later one; the file's callers do that.
"""

from __future__ import annotations

import queue
import shutil
import sys
import tempfile
import threading
import time
from collections.abc import Generator, Iterable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Make the backend root importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, event  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.alerts.engine import AlertEngine  # noqa: E402
from app.alerts.service import AlertService  # noqa: E402
from app.config.settings import Settings, settings  # noqa: E402
from app.connections.manager import ConnectionTracker  # noqa: E402
from app.connections.persistence import ConnectionPersistence  # noqa: E402
from app.correlation.engine import CorrelationEngine  # noqa: E402
from app.correlation.persistence import IncidentRiskWriter  # noqa: E402
from app.correlation.registry import IncidentRegistry  # noqa: E402
from app.correlation.window import CorrelationWindow  # noqa: E402
from app.detection import DetectionEngine, build_default_rules  # noqa: E402
from app.devices.manager import DeviceDiscoveryManager  # noqa: E402
from app.main import app  # noqa: E402
from app.persistence.manager import PacketPersistence  # noqa: E402
from app.risk.contributions import ScoringBounds  # noqa: E402
from app.risk.engine import RiskScoringEngine  # noqa: E402
from app.services.packet_pipeline import PacketPipeline  # noqa: E402
from app.statistics.manager import TrafficStatisticsManager  # noqa: E402
from app.websockets import get_websocket_manager  # noqa: E402
from app.websockets.channels import Channel  # noqa: E402
from app.websockets.event import WebSocketEvent  # noqa: E402
from app.websockets.manager import WebSocketManager  # noqa: E402
from app.websockets.policy import build_policy_set  # noqa: E402
from app.websockets.publisher import EventPublisher  # noqa: E402

#: How long a reader waits for one frame before failing. Generous enough for the
#: slowest legitimate producer and short enough that an event which never arrives
#: is reported rather than waited on.
READ_TIMEOUT_SECONDS = 10.0

#: Sentinel a reader queues when its socket ends, so a close is told apart from a
#: frame. An object rather than ``None``: a frame could never be ``None``, but the
#: asymmetry is free and removes the question.
_SOCKET_CLOSED = object()

#: Lab detection thresholds, so a handful of packets exercises the real rules
#: quickly. Verification and benchmark configuration, not the shipped default.
PORT_SCAN_THRESHOLD = 5
INTERNAL_SCAN_THRESHOLD = 5

#: One source, a public scan target and a private sweep target — the pair of
#: detectors the correlation layer groups into one ``scan_sequence`` incident, so
#: the run produces real alert and incident events as well as packet ones.
SOURCE_IP = "192.168.1.10"
PUBLIC_DESTINATION = "8.8.8.8"
SWEEP_PREFIX = "192.168.1."
SWEEP_FIRST_HOST = 30

#: The interface the processor records on each normalized packet. Set explicitly
#: so a packet payload carries a name rather than ``None``, and so the figure does
#: not depend on the machine's NICs.
CAPTURE_INTERFACE = "Wi-Fi"

_ETHERNET_SRC = "AA:BB:CC:DD:EE:FF"
_ETHERNET_DST = "22:33:44:55:66:77"

#: Connection caps for the run. Far above the number of clients any phase opens,
#: so a "many simultaneous clients" measurement describes the manager rather than
#: the cap, and a refusal is never mistaken for latency.
LAB_MAX_CONNECTIONS = 4096
LAB_MAX_CONNECTIONS_PER_CHANNEL = 1024

#: Dashboard tick: effectively off, for the same reason as the heartbeat. The
#: tick publishes a ``dashboard.updated`` on its own timer, and a frame that
#: arrived unasked-for would be timed as though it were the one the measurement
#: sent. The transport is what M14.33 measures; how often the tick fires is
#: M14.9's behaviour, verified in ``verify_m14.py``.
QUIET_DASHBOARD_SECONDS = 3600.0

#: Heartbeat: effectively off. A keepalive ping arriving mid-measurement is a
#: frame the readers did not ask for, and the keepalive is M14.24's behaviour to
#: verify, not M14.33's to measure.
QUIET_HEARTBEAT_SECONDS = 3600.0


# -- the isolated database ----------------------------------------------------


def connect_database(db_path: Path) -> tuple[Any, Any]:
    """Create the isolated SQLite database and a session factory (M14.33).

    Foreign keys are enforced, so an alert's evidence must reference a row that
    really exists — the same constraint the shipped database carries, and the one
    that would otherwise let an insert succeed here and fail in production.
    """
    from app import models as _models  # noqa: F401  (register every table)
    from app.database.base import Base

    engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)

    def factory() -> Session:
        return Session(bind=engine)

    return engine, factory


def seed_rule_catalogue(factory: Any) -> None:
    """Populate ``detection_rules``, so the alert table's foreign key resolves.

    The catalogue must exist before the pipeline stores an alert, and
    ``high_bandwidth`` is added explicitly because the shipped seed omits it while
    the default rule set references it.
    """
    from app.database.seed import seed_detection_rules
    from app.models.detection_rule import DetectionRule

    session = factory()
    try:
        seed_detection_rules(session)
        if (
            session.query(DetectionRule)
            .filter(DetectionRule.rule_key == "high_bandwidth")
            .first()
            is None
        ):
            session.add(
                DetectionRule(
                    rule_key="high_bandwidth",
                    rule_name="High Bandwidth",
                    description="Detects a sustained high traffic rate.",
                    detection_type="high_bandwidth",
                    severity="high",
                    threshold_config=(
                        '{"bytes_per_second": 1000000, "time_window_seconds": 5}'
                    ),
                )
            )
        session.commit()
    finally:
        session.close()


# -- traffic the pipeline can process ----------------------------------------


class _LowRatesSource:
    """A rates source reporting no traffic (M10.12).

    The bandwidth detector reads M6's rates rather than the packet stream, so
    reporting zeros keeps it quiet and the run about the rules the benchmark
    drives on purpose.
    """

    def get_rates(self, window: str = "1s") -> tuple[float, float]:
        """Return zero packets and bytes per second."""
        return 0.0, 0.0


def scan_packets(count: int) -> list[Any]:
    """Return ``count`` SYNs from one source across distinct ports (M10.8)."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    return [
        Ether(src=_ETHERNET_SRC, dst=_ETHERNET_DST)
        / IP(src=SOURCE_IP, dst=PUBLIC_DESTINATION)
        / TCP(sport=52000, dport=4000 + index, flags="S")
        for index in range(count)
    ]


def sweep_packets(count: int) -> list[Any]:
    """Return ``count`` UDP attempts to distinct private hosts (M10.11)."""
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    return [
        Ether(src=_ETHERNET_SRC, dst=_ETHERNET_DST)
        / IP(src=SOURCE_IP, dst=f"{SWEEP_PREFIX}{SWEEP_FIRST_HOST + index}")
        / UDP(sport=53000, dport=53)
        for index in range(count)
    ]


def _flow_packet(index: int) -> Any:
    """Return one ordinary packet, distinct enough to be real work for M8/M9.

    Distinct sources and ports mean the device registry and the connection tracker
    both do their real thing (a new device, a new conversation) rather than
    updating one entry, and the destination rotates within TEST-NET-3 so nothing
    here trips a detector. These are the packets the throughput figures are
    measured over, so they have to be representative rather than convenient.
    """
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    return (
        Ether(src=_ETHERNET_SRC, dst=_ETHERNET_DST)
        / IP(src=f"10.{(index >> 8) & 0xFF}.{index & 0xFF}.7", dst="203.0.113.9")
        / TCP(sport=40000 + (index % 5000), dport=443, flags="A")
    )


def load_packets(count: int) -> list[Any]:
    """Return a pool of ``count`` distinct ordinary packets, built once.

    Scapy objects are not cheap to construct, and constructing them inside the
    timed loop would report Scapy's builder cost as the pipeline's. Building a
    pool outside the loop and cycling through it keeps the figure about the
    pipeline. Cycling also repeats flows, which is what real traffic does once a
    conversation exists.
    """
    return [_flow_packet(index) for index in range(count)]


# -- the publisher ------------------------------------------------------------


class RecordingPublisher:
    """The process publisher, with everything that passes through recorded.

    It forwards each event to the real publisher unchanged — so the event still
    travels the real manager — and keeps it so the benchmark can later re-publish
    an *actual* ``alert.created`` event, built by the production builder from a
    real M11 alert, instead of a hand-made approximation of one. It is a strict
    decorator: it adds a list and changes nothing else, so no figure measured
    through it describes anything but the shipped path.
    """

    __slots__ = ("_inner", "events")

    def __init__(self, inner: EventPublisher) -> None:
        self._inner = inner
        self.events: list[WebSocketEvent] = []

    @property
    def enabled(self) -> bool:
        """Return whether the underlying layer is switched on."""
        return bool(getattr(self._inner, "enabled", False))

    def publish(self, event: WebSocketEvent) -> bool:
        """Record ``event`` and forward it."""
        self.events.append(event)
        return bool(self._inner.publish(event))

    def publish_many(self, events: Iterable[WebSocketEvent]) -> int:
        """Record and forward several events."""
        accepted = 0
        for event in events:
            if self.publish(event):
                accepted += 1
        return accepted

    def of_type(self, event_type: str, *, limit: int | None = None) -> list[WebSocketEvent]:
        """Return the recorded events of ``event_type``, oldest first."""
        found = [item for item in self.events if item.type == event_type]
        return found if limit is None else found[:limit]


# -- the live stack -----------------------------------------------------------


@dataclass
class LabStack:
    """The real M4→M12 pipeline over the isolated database (M14.33).

    Everything is the production object; what the benchmark adds is the throwaway
    session factory, the recording publisher in front of the process publisher and
    the packet pool.
    """

    pipeline: PacketPipeline
    factory: Any
    devices: DeviceDiscoveryManager
    statistics: TrafficStatisticsManager
    connections: ConnectionTracker
    recording: RecordingPublisher
    packets: list[Any] = field(default_factory=list)

    def process(self, packets: Sequence[Any]) -> None:
        """Drive ``packets`` through the real pipeline, timed by the caller."""
        for packet in packets:
            self.pipeline.process(packet)


def build_lab_stack(factory: Any, events: EventPublisher) -> LabStack:
    """Wire the production pipeline over the isolated database (M14.33).

    Every consumer is the real one — M6 statistics, M7 persistence, M8 device
    discovery, M9 connection tracking, M10 detection, M11 alerting and M12
    correlation — and all of them are given the publisher, so the events the run
    measures come from the production publish sites. The only non-production
    object is the session factory.
    """
    recording = RecordingPublisher(events)
    devices = DeviceDiscoveryManager()
    lab_settings = Settings(
        port_scan_unique_port_threshold=PORT_SCAN_THRESHOLD,
        internal_scan_unique_destination_threshold=INTERNAL_SCAN_THRESHOLD,
    )
    registry = devices.registry

    def resolve_device(ip_address: str) -> str | None:
        """Return the M8 device id owning ``ip_address``, or ``None`` (M10.4)."""
        device = registry.get_by_ip(ip_address)
        return device.device_id if device is not None else None

    detection = DetectionEngine(
        build_default_rules(lab_settings),
        rates_source=_LowRatesSource(),
        device_resolver=resolve_device,
    )
    clock = time.time
    alerts = AlertEngine(
        AlertService(
            session_factory=factory,
            resolvers=None,
            events=recording,
            clock=clock,
        )
    )
    connections = ConnectionTracker(
        device_registry=devices.registry,
        persistence=ConnectionPersistence(session_factory=factory),
        autostart_cleanup=False,
    )
    statistics = TrafficStatisticsManager()
    pipeline = PacketPipeline(
        statistics=statistics,
        persistence=PacketPersistence(session_factory=factory, autostart=False),
        devices=devices,
        connections=connections,
        detection=detection,
        alerts=alerts,
        correlation=CorrelationEngine(
            window=CorrelationWindow(
                seconds=900.0, proximity_seconds=300.0, max_span_seconds=900.0
            ),
            registry=IncidentRegistry(
                max_incidents=1024,
                retention_seconds=3600.0,
                max_members=64,
                max_reasons=16,
                clock=clock,
            ),
            risk=RiskScoringEngine(ScoringBounds(volume_alerts=5)),
            anchor_threshold=0.55,
            min_confidence=0.5,
            risk_persistence=IncidentRiskWriter(factory),
            events=recording,
            clock=clock,
        ),
        events=recording,
    )
    pipeline.set_interface(CAPTURE_INTERFACE)
    return LabStack(
        pipeline=pipeline,
        factory=factory,
        devices=devices,
        statistics=statistics,
        connections=connections,
        recording=recording,
    )


# -- configuration and the running application --------------------------------


@contextmanager
def lab_websocket_settings() -> Generator[None, None, None]:
    """Apply the lab WebSocket configuration, and restore it afterwards (M14.33).

    Four values are changed and every one restored: the two connection caps, so a
    "many simultaneous clients" phase runs well inside them rather than into a
    refusal; and both background timers, pushed far beyond any plausible run
    length so the run is quiet. That last part matters more than it looks. The
    keepalive and the dashboard tick each publish on a timer of their own, and a
    frame that arrived unasked-for would be timed as though it were the frame a
    measurement sent. Their behaviour is M14.24's and M14.9's to verify and
    ``verify_m14.py`` does; M14.33 measures the transport, so the run isolates it.
    """
    keys = (
        "websocket_max_connections",
        "websocket_max_connections_per_channel",
        "websocket_dashboard_interval_seconds",
        "websocket_heartbeat_interval_seconds",
    )
    original = {key: getattr(settings, key) for key in keys}
    try:
        settings.websocket_max_connections = LAB_MAX_CONNECTIONS
        settings.websocket_max_connections_per_channel = LAB_MAX_CONNECTIONS_PER_CHANNEL
        settings.websocket_dashboard_interval_seconds = QUIET_DASHBOARD_SECONDS
        settings.websocket_heartbeat_interval_seconds = QUIET_HEARTBEAT_SECONDS
        yield
    finally:
        for key, value in original.items():
            setattr(settings, key, value)


@contextmanager
def serving() -> Generator[TestClient, None, None]:
    """Yield a client over the real application, over the isolated store (M14.33).

    The environment is temporarily ``"test"`` so the lifespan skips ``init_db()``
    and never touches the developer's database. Entering this context is what runs
    the lifespan, so the manager's loop is bound and the background tasks started
    before the first socket dials in — which is what makes a publish from the
    benchmark's own thread a real cross-thread publish rather than a drop to
    ``dropped_no_loop`` (M14.20/M14.21).
    """
    original_env = settings.app_env
    settings.app_env = "test"
    try:
        with TestClient(app) as client:
            yield client
    finally:
        settings.app_env = original_env


@contextmanager
def isolated_app_sessions(factory: Any) -> Generator[None, None, None]:
    """Point the process-wide session factory at the run's throwaway database.

    ``app.websockets.dashboard`` builds its open-alert count over
    ``app.persistence.session_factory.app_session_factory``, which in a normal
    process is the developer's ``netwatch.db``. The benchmark publishes dashboard
    payloads through that same sampler, so without this the run would read — and
    its figure would depend on — a file this script promises not to touch.
    Patching the attribute for the duration is what makes the payload come from the
    isolated store instead (M14.9/M14.33).
    """
    import app.persistence.session_factory as session_module

    original = session_module.app_session_factory
    session_module.app_session_factory = factory
    try:
        yield
    finally:
        session_module.app_session_factory = original


@contextmanager
def suppressed_publishing() -> Generator[None, None, None]:
    """Stop the pipeline publishing packets at all, for the zero rung (M14.33).

    The ladder needs a rung where M14 costs *nothing*, and passing ``None`` or a
    null publisher does not give one. ``publish_packet`` builds the event and only
    then hands it to the publisher (see ``app.websockets.events``), so a discarded
    event still costs a full M5 projection — a real cost, but not the transport's.
    With this patch the pipeline's call site is a function that returns ``False``,
    which is the pipeline exactly as M4-M12 shipped it before M14 wired a call in.

    The patch is applied to ``app.services.packet_pipeline``'s own reference rather
    than to ``app.websockets.events``, because the pipeline bound the name at import
    time and calls it from its module globals: replacing the publisher module's
    attribute would change nothing at the call site.

    The difference between this rung and the next is the cost of *building* a
    ``packet.observed`` for every packet; the difference between the next rung and
    the last is the cost of *delivering* it. Reporting those two separately is the
    point of the ladder.
    """
    import app.services.packet_pipeline as pipeline_module

    original = pipeline_module.publish_packet

    def _no_publish(_publisher: EventPublisher, _packet: Any) -> bool:
        """Accept a packet's publish call and do nothing with it."""
        return False

    pipeline_module.publish_packet = _no_publish
    try:
        yield
    finally:
        pipeline_module.publish_packet = original


# -- clients ------------------------------------------------------------------


class SocketReader:
    """A live WebSocket client that can wait with a deadline (M14.33).

    Frames are read on a thread of its own and queued, so :meth:`next_frame` can
    time out. A blocking ``receive_json`` on the measuring thread would hang the
    whole run whenever an event the backend should have published did not appear,
    which is exactly the fault a benchmark must report rather than wait on.
    """

    def __init__(self, socket: Any, channel: Channel) -> None:
        self._socket: Any = socket
        self.channel = channel
        #: The connection's configured queue depth, so a printed figure can say
        #: what the bound was. Set by the caller that knows the policy; it is
        #: cosmetic and nothing here reads it.
        self.max_queue_hint: int = 0
        self._incoming: queue.Queue[Any] = queue.Queue()
        self._thread = threading.Thread(
            target=self._pump, name=f"bench-m14-{channel.value}", daemon=True
        )
        self._thread.start()

    def _pump(self) -> None:
        """Read frames until the socket closes, queueing them for ``next_frame``."""
        while True:
            try:
                message = self._socket.receive_json()
            except Exception:  # noqa: BLE001 - a closed socket is a normal end
                break
            self._incoming.put(message)
        self._incoming.put(_SOCKET_CLOSED)

    def next_frame(self, timeout: float = READ_TIMEOUT_SECONDS) -> dict[str, Any]:
        """Return the next frame, or raise if none arrives within ``timeout``.

        Raises:
            AssertionError: On a timeout or a closed socket, so a missing event is
                reported where it was expected instead of hanging the run.
        """
        try:
            message = self._incoming.get(timeout=timeout)
        except queue.Empty:
            raise AssertionError(
                f"{self.channel.value}: no frame arrived within {timeout}s"
            ) from None
        if message is _SOCKET_CLOSED:
            raise AssertionError(f"{self.channel.value}: the socket closed")
        return dict(message)

    def drain(self) -> int:
        """Discard everything already queued, returning how many were discarded."""
        discarded = 0
        while True:
            try:
                message = self._incoming.get_nowait()
            except queue.Empty:
                return discarded
            if message is _SOCKET_CLOSED:
                return discarded
            discarded += 1

    def collect(self, *, quiet_seconds: float) -> list[dict[str, Any]]:
        """Read every frame still arriving, then stop once nothing arrives.

        Used where the question is *how many* frames came through rather than how
        long each took: a rate is delivered events over a window, and reading with
        a deadline turns "nothing more is coming" into a return instead of a hang.
        A closed socket ends the read the same way a quiet one does, because either
        means no further frame will arrive.
        """
        collected: list[dict[str, Any]] = []
        while True:
            try:
                collected.append(self.next_frame(timeout=quiet_seconds))
            except AssertionError:
                return collected


class StallingSocket:
    """A client that accepts frames and never takes them (M14.15).

    ``send_text`` parks on a barrier that is never released, so the manager's
    sender task blocks on its first write, the connection's bounded queue fills,
    and the drop policy has to engage. That is the only way to observe a bounded
    buffer: a client that drains — as every real one does, and as Starlette's test
    transport always does — never lets the queue reach its cap.
    """

    def __init__(self) -> None:
        self.sent: list[str] = []
        self.closed = False
        self._gate = None

    async def _barrier(self) -> None:
        """Wait forever, on this loop, so the sender task never completes a write."""
        import asyncio

        if self._gate is None:
            self._gate = asyncio.Event()
        await self._gate.wait()

    async def send_text(self, data: str) -> None:
        """Accept the frame's identity and then park instead of writing it."""
        self.sent.append(data)
        await self._barrier()

    async def close(self, code: int = 1000, reason: str | None = None) -> None:
        """Record the close without touching a real socket."""
        self.closed = True


async def measure_overrun(
    channel: Channel, events: Sequence[WebSocketEvent], *, manager: WebSocketManager
) -> dict[str, Any]:
    """Broadcast into a stalled client and report the bounded buffer's behaviour.

    Runs entirely on one loop, which is the only place a queue may be touched
    (M14.21). The connection is registered by the real :meth:`connect`, the events
    are offered by the real :meth:`broadcast`, and the depth is sampled after each
    one so the high-water mark is observed rather than derived from the policy.

    Returns:
        The queue cap, the observed high-water depth, how many events were
        dropped, how many the manager refused for rate, and how many the client
        actually received.
    """
    import asyncio

    from app.websockets import builders

    socket = StallingSocket()
    connection = await manager.connect(socket, channel)
    depth_high_water = 0
    for _ in events:
        manager.broadcast(builders.ping_event(channel))
        # One turn of the loop lets the sender task run — it consumes the queued
        # message and then parks on the stalled write. Without the yield the
        # sender never starts and the queue would fill for the wrong reason.
        await asyncio.sleep(0)
        depth_high_water = max(depth_high_water, connection.queued)
    counters = connection.counters
    await manager.shutdown()
    return {
        "channel": channel.value,
        "queue_size": int(connection.max_queue),
        "depth_high_water": depth_high_water,
        "dropped_queue_full": int(counters.dropped_queue_full),
        "offered": int(counters.offered),
        "sent": int(counters.sent),
        "manager_dropped_rate_limited": int(
            manager.get_counters()["dropped_rate_limited"]
        ),
        "manager_dropped_disabled": int(manager.get_counters()["dropped_disabled"]),
    }


def overrun_for(channel: Channel, *, events: int) -> dict[str, Any]:
    """Run :func:`measure_overrun` on a fresh manager, on its own loop (M14.15).

    The manager is separate from the process one on purpose: a stalled connection
    has to be unregistered afterwards, and doing that to the running application's
    registry would make the remaining phases describe something else. The policy
    table is still the shipped one, read from settings, so the caps and the rate
    ceiling measured here are the ones the application runs with.
    """
    import asyncio

    async def run() -> dict[str, Any]:
        manager = WebSocketManager(policies=build_policy_set(settings))
        await manager.start()
        try:
            return await measure_overrun(
                channel, [None] * events, manager=manager  # type: ignore[list-item]
            )
        finally:
            await manager.shutdown()

    return asyncio.run(run())


def temp_workdir(prefix: str = "netwatch_bench_m14_") -> Path:
    """Create a throwaway directory for the run's database, removed by the caller."""
    return Path(tempfile.mkdtemp(prefix=prefix))


def remove_workdir(workdir: Path) -> None:
    """Delete the run's throwaway directory, ignoring a file still held open."""
    shutil.rmtree(workdir, ignore_errors=True)


def process_manager() -> WebSocketManager:
    """Return the process-wide manager the application's lifespan started (M14.2)."""
    return get_websocket_manager()
