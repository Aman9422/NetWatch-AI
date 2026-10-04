"""M14 verification script — the live WebSocket layer over real backend data (M14.32).

Two modes:

  sample  (default)  Drive controlled packets through the *real* M4→M12 pipeline
                     over an isolated temporary SQLite database, with a real
                     WebSocket client attached to all four channels, then assert
                     that what the pipeline did arrived on the wire. The client is
                     Starlette's ``TestClient.websocket_connect``, so the frames
                     travel the real router, the real admission check, the real
                     receive loop and the real sender task — the only substitution
                     is the capture sniffer, because a test may not put a NIC in
                     promiscuous mode. No admin rights and no Npcap needed.
  live               Start the application under uvicorn on a loopback port and
                     speak real WebSocket over real HTTP to all four channels.

What it verifies, against the M14 completion criteria:

  * every packet the pipeline processed arrived as exactly one ``packet.observed``
    event, carrying the documented field set and no payload (M14.8);
  * a controlled detection produced an ``alert.created`` event and a controlled
    incident an ``incident.created`` event, with the risk score read from the
    incident rather than recomputed here (M14.10/M14.12);
  * the dashboard tick fires while a dashboard client is connected and agrees with
    ``GET /api/v1/dashboard/summary`` on every count it carries (M14.9);
  * a capture session produced ``capture.started`` and ``capture.stopped``, the
    latter carrying the session's final packet count (M14.11);
  * separation holds over the wire: no frame arrived on a channel other than the
    one it names (M14.6);
  * the keepalive is two-way — the server pings and accepts the client's pong, and
    a client ping is answered with a matching pong (M14.23/M14.24);
  * client input is refused rather than acted on, with the reason named and the
    client's own bytes never echoed (M14.22/M14.23);
  * the counters M14.14 and M14.33 report on stayed at zero for the run, and every
    client left the registry when it closed (M14.14/M14.18).

Two things about this script are worth stating because they look like cheating and
are not.

**The dashboard tick reads process-wide services, so this script makes those
services be the ones the run built.** ``app.websockets.dashboard`` imports its
collaborators *inside* each sampling function — deliberately, so importing the
WebSocket package does not pull the whole M4→M12 stack into the process. That
means a module-attribute patch reaches it, which is how the tick and the REST
routes are made to read the *same* stack. Without it the comparison would be
between a tick reading an idle process-wide manager and a route reading the real
one, and "they agree" would mean nothing.

**The keepalive is verified with a short interval, and the event flow with a long
one.** The heartbeat is verified in its own phase at a fraction of a second, since
the alternative is waiting out the shipped twenty-second default. The event flow
then runs with the heartbeat effectively off, because it holds four sockets open
at once and a reader can only answer a ping on the socket it is currently reading
— a client that is legitimately mid-test would otherwise be retired for not
answering a keepalive it never saw.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\verify_m14.py
    & ".venv\\Scripts\\python.exe" scripts\\verify_m14.py live --port 8012
"""

from __future__ import annotations

import argparse
import contextlib
import json
import queue
import shutil
import socket
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Make the backend root importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from scapy.layers.inet import IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from sqlalchemy import create_engine, event  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402

from app.alerts import get_alert_engine  # noqa: E402
from app.alerts.engine import AlertEngine  # noqa: E402
from app.alerts.queries import AlertQueries  # noqa: E402
from app.alerts.service import AlertService  # noqa: E402
from app.api.v1.deps import get_alert_queries  # noqa: E402
from app.config.settings import Settings, settings  # noqa: E402
from app.connections.manager import ConnectionTracker, get_connection_tracker  # noqa: E402
from app.connections.persistence import ConnectionPersistence  # noqa: E402
from app.correlation import get_correlation_engine  # noqa: E402
from app.correlation.engine import CorrelationEngine  # noqa: E402
from app.correlation.persistence import IncidentRiskWriter  # noqa: E402
from app.correlation.registry import IncidentRegistry  # noqa: E402
from app.correlation.window import CorrelationWindow  # noqa: E402
from app.database.session import get_db  # noqa: E402
from app.detection import (  # noqa: E402
    DetectionEngine,
    build_default_rules,
    get_detection_engine,
)
from app.devices.manager import DeviceDiscoveryManager, get_device_manager  # noqa: E402
from app.main import app  # noqa: E402
from app.persistence.manager import PacketPersistence  # noqa: E402
from app.risk.contributions import ScoringBounds  # noqa: E402
from app.risk.engine import RiskScoringEngine  # noqa: E402
from app.services.capture_manager import CaptureManager, get_capture_manager  # noqa: E402
from app.services.capture_sniffer import PacketSink  # noqa: E402
from app.services.interface_manager import (  # noqa: E402
    InterfaceManager,
    get_interface_manager,
)
from app.services.packet_pipeline import PacketPipeline  # noqa: E402
from app.statistics.manager import (  # noqa: E402
    TrafficStatisticsManager,
    get_statistics_manager,
)
from app.websockets import (  # noqa: E402
    builders,
    get_event_publisher,
    get_websocket_manager,
    reset_websockets,
)
from app.websockets.channels import CHANNEL_PATHS, CHANNELS, Channel  # noqa: E402
from app.websockets.event import EventType, reset_sequence  # noqa: E402
from app.websockets.messages import (  # noqa: E402
    REFUSAL_NOT_JSON,
    REFUSAL_TOO_LARGE,
    REFUSAL_UNKNOWN_TYPE,
)
from app.websockets.publisher import EventPublisher  # noqa: E402

_BANNER_WIDTH = 70

#: The versioned REST base, used only for the dashboard agreement check (M13.3).
API = "/api/v1"

#: The interface the capture manager is told to use — a synthetic one offered by
#: this script's discovery function, not the machine's NICs, so the run cannot
#: depend on what hardware is present.
CAPTURE_INTERFACE = "Wi-Fi"

SAMPLE_INTERFACES: list[dict[str, Any]] = [
    {
        "name": CAPTURE_INTERFACE,
        "description": "verify_m14 synthetic interface",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "ip_addresses": ["192.168.1.20"],
        "is_up": True,
    },
    {
        "name": "Ethernet",
        "description": "verify_m14 synthetic interface",
        "mac_address": None,
        "ip_addresses": [],
        "is_up": False,
    },
]

#: Lab detection thresholds, so a handful of packets exercises the real rules
#: quickly. This is a verification configuration, not the shipped default (M10.7).
PORT_SCAN_THRESHOLD = 5
INTERNAL_SCAN_THRESHOLD = 5

#: One source, a public scan target and a private sweep target — the pair of
#: detectors that the correlation layer groups into one ``scan_sequence`` incident.
SOURCE_IP = "192.168.1.10"
PUBLIC_DESTINATION = "8.8.8.8"
SWEEP_PREFIX = "192.168.1."
SWEEP_FIRST_HOST = 30

#: The alert and correlation layers use the real wall clock, because the packets
#: are dated by the pipeline from the clock as they arrive.
CLOCK = time.time

#: Keepalive phase: a fraction of a second, so the server's own ping is observed
#: without waiting out the shipped default.
FAST_HEARTBEAT_SECONDS = 0.25

#: Event-flow phase: long enough that no ping can arrive while four sockets are
#: held open by a reader that can only answer one of them at a time.
QUIET_HEARTBEAT_SECONDS = 60.0

#: Dashboard tick: fast enough that a tick lands after the capture without a wait.
FAST_DASHBOARD_SECONDS = 0.2

#: Connection caps, small so the cap can be reached and exceeded in a moment.
LAB_MAX_CONNECTIONS = 8
LAB_MAX_CONNECTIONS_PER_CHANNEL = 2

#: The complete field set of a packet payload (M14.8), so the check can assert the
#: payload is a *ceiling* rather than a floor — least of all a packet payload.
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

#: The complete field set of a dashboard tick (M14.9), checked the same way.
DASHBOARD_FIELDS = frozenset(
    {
        "capture_running",
        "interface",
        "packet_count",
        "packets_per_second",
        "bytes_per_second",
        "device_count",
        "active_connections",
        "open_alerts",
        "active_incidents",
    }
)

#: How many frames a read helper will consume before it gives up. Generous: a
#: frame that never arrives should be reported as such rather than hang the run.
FRAME_BUDGET = 400


class FakeCaptureSniffer:
    """An in-process stand-in for the Scapy sniffer (M4/M14.32).

    It implements the same structural contract the real sniffer does — ``start``,
    ``stop``, ``is_running`` and the counters — and hands every emitted packet to
    the pipeline through the ``process`` call the real sniffer uses. The capture
    manager therefore drives the production path; only the socket is replaced.
    """

    def __init__(self, interface: str, packet_sink: PacketSink | None = None) -> None:
        self.interface = interface
        self.packet_sink = packet_sink
        self.running = False
        self.packet_count = 0
        self.processed_count = 0
        self.processing_error_count = 0

    def emit_packet(self, packet: Any) -> None:
        """Deliver one packet through the pipeline, as the real sniffer would."""
        self.packet_count += 1
        if self.packet_sink is None:
            return
        try:
            self.packet_sink.process(packet)
        except Exception:  # noqa: BLE001 - mirrors the sniffer's own isolation
            self.processing_error_count += 1
            return
        self.processed_count += 1

    # -- CaptureSniffer protocol -----------------------------------------

    def start(self) -> None:
        """Mark the capture worker as running."""
        self.running = True

    def stop(self) -> None:
        """Mark the capture worker as stopped."""
        self.running = False

    def is_running(self) -> bool:
        """Return whether the capture worker is running."""
        return self.running

    def get_packet_count(self) -> int:
        """Return how many packets were emitted through this sniffer."""
        return self.packet_count

    def get_processed_count(self) -> int:
        """Return how many packets the pipeline accepted."""
        return self.processed_count

    def get_processing_error_count(self) -> int:
        """Return how many packets the pipeline rejected."""
        return self.processing_error_count


def _make_sniffer_factory(
    registry: list[FakeCaptureSniffer],
) -> Callable[[str, PacketSink], FakeCaptureSniffer]:
    """Return a sniffer factory that records every sniffer it creates."""

    def factory(interface: str, packet_sink: PacketSink) -> FakeCaptureSniffer:
        sniffer = FakeCaptureSniffer(interface, packet_sink=packet_sink)
        registry.append(sniffer)
        return sniffer

    return factory


def _connect_database(db_path: Path) -> tuple[Any, Any]:
    """Create the isolated SQLite database and a session factory (M14.32).

    Foreign keys are enforced, so an alert's evidence must reference a row that
    really exists — the same constraint the shipped database carries.
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


def _seed_rule_catalogue(factory: Any) -> None:
    """Populate ``detection_rules``, so the alert table's foreign key resolves.

    The alert table has a foreign key into the seeded rule catalogue, so the
    catalogue must exist before the pipeline stores an alert.
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


class _LowRatesSource:
    """A rates source that reports no traffic (M10.12).

    The bandwidth detector reads M6's rates rather than the packet stream, so
    reporting zeros keeps it quiet and the run about the rules the script drives.
    """

    def get_rates(self, window: str = "1s") -> tuple[float, float]:
        """Return zero packets and bytes per second."""
        return 0.0, 0.0


def _scan_packets(count: int) -> list[Any]:
    """Return ``count`` raw SYNs from one source across distinct ports (M10.8)."""
    return [
        Ether(src="AA:BB:CC:DD:EE:FF", dst="22:33:44:55:66:77")
        / IP(src=SOURCE_IP, dst=PUBLIC_DESTINATION)
        / TCP(sport=52000, dport=4000 + index, flags="S")
        for index in range(count)
    ]


def _sweep_packets(count: int) -> list[Any]:
    """Return ``count`` raw UDP attempts to distinct private hosts (M10.9)."""
    return [
        Ether(src="AA:BB:CC:DD:EE:FF", dst="22:33:44:55:66:77")
        / IP(src=SOURCE_IP, dst=f"{SWEEP_PREFIX}{SWEEP_FIRST_HOST + index}")
        / UDP(sport=53000, dport=53)
        for index in range(count)
    ]
@dataclass
class _Stack:
    """The live application, wired end to end over the isolated database.

    Holding the collaborators rather than re-deriving them is what lets both the
    dependency overrides and the module patches hand the *same* objects to the
    routes and to the dashboard tick, so a tick can only agree with a route if
    they really are reading one stack.
    """

    pipeline: PacketPipeline
    manager: CaptureManager
    interfaces: InterfaceManager
    sniffer_registry: list[FakeCaptureSniffer]
    statistics: TrafficStatisticsManager
    devices: DeviceDiscoveryManager
    connections: ConnectionTracker
    detection: DetectionEngine
    alerts: AlertEngine
    correlation: CorrelationEngine
    risk_writer: IncidentRiskWriter

    def capture(self, packets: Sequence[Any]) -> None:
        """Run one real capture session over the fake sniffer (M14.8/M14.11).

        The interface is chosen on the M4 :class:`InterfaceManager`, which is
        where selection lives, then the manager is started and the packets are
        emitted through the sniffer's sink callback — the real capture path.
        Stopping flushes persistence and the connection aggregates, so what the
        API reads afterwards is a complete store (M7.18/M9.17).
        """
        self.interfaces.select_interface(CAPTURE_INTERFACE)
        self.manager.start()
        sniffer = self.sniffer_registry[-1]
        for packet in packets:
            sniffer.emit_packet(packet)
        self.manager.stop()


def _build_detection_engine(devices: DeviceDiscoveryManager) -> DetectionEngine:
    """Build a detection engine over lab thresholds (M10.7).

    Two thresholds are lowered so a handful of synthetic packets demonstrates a
    detector, exactly as the M10 and M13 verifiers do. This is a verification
    configuration, not the shipped default.
    """
    lab_settings = Settings(
        port_scan_unique_port_threshold=PORT_SCAN_THRESHOLD,
        internal_scan_unique_destination_threshold=INTERNAL_SCAN_THRESHOLD,
    )
    devices_registry = devices.registry

    def resolve_device(ip_address: str) -> str | None:
        """Return the M8 device id owning ``ip_address``, or ``None`` (M10.4)."""
        device = devices_registry.get_by_ip(ip_address)
        return device.device_id if device is not None else None

    return DetectionEngine(
        build_default_rules(lab_settings),
        rates_source=_LowRatesSource(),
        device_resolver=resolve_device,
    )


def _build_stack(factory: Any, events: EventPublisher) -> _Stack:
    """Wire the production pipeline over the isolated database (M14.32).

    Every layer is the real one — M6 statistics, M7 persistence, M8 device
    discovery, M9 connection tracking, M10 detection, M11 alerting and M12
    correlation — and all of them are given the live publisher, so the events this
    run asserts on come from the production publish sites rather than from
    anywhere in this script. The only non-production objects are the sniffer and
    the session factory.
    """
    devices = DeviceDiscoveryManager()
    detection = _build_detection_engine(devices)
    alerts = AlertEngine(
        AlertService(
            session_factory=factory, resolvers=None, events=events, clock=CLOCK
        )
    )
    connections = ConnectionTracker(
        device_registry=devices.registry,
        persistence=ConnectionPersistence(session_factory=factory),
        autostart_cleanup=False,
    )
    persistence = PacketPersistence(session_factory=factory, autostart=False)
    risk_writer = IncidentRiskWriter(factory)
    correlation = CorrelationEngine(
        window=CorrelationWindow(
            seconds=900.0, proximity_seconds=300.0, max_span_seconds=900.0
        ),
        registry=IncidentRegistry(
            max_incidents=1024,
            retention_seconds=3600.0,
            max_members=64,
            max_reasons=16,
            clock=CLOCK,
        ),
        risk=RiskScoringEngine(ScoringBounds(volume_alerts=5)),
        anchor_threshold=0.55,
        min_confidence=0.5,
        risk_persistence=risk_writer,
        events=events,
        clock=CLOCK,
    )
    statistics = TrafficStatisticsManager()
    pipeline = PacketPipeline(
        statistics=statistics,
        persistence=persistence,
        devices=devices,
        connections=connections,
        detection=detection,
        alerts=alerts,
        correlation=correlation,
        events=events,
    )
    registry: list[FakeCaptureSniffer] = []
    interfaces = InterfaceManager(discovery=lambda: SAMPLE_INTERFACES)
    manager = CaptureManager(
        interface_manager=interfaces,
        sniffer_factory=_make_sniffer_factory(registry),
        pipeline=pipeline,
        events=events,
    )
    return _Stack(
        pipeline=pipeline,
        manager=manager,
        interfaces=interfaces,
        sniffer_registry=registry,
        statistics=statistics,
        devices=devices,
        connections=connections,
        detection=detection,
        alerts=alerts,
        correlation=correlation,
        risk_writer=risk_writer,
    )


@contextmanager
def _lab_websocket_settings() -> Generator[None, None, None]:
    """Apply the lab WebSocket configuration, and restore it afterwards (M14.32).

    The manager reads the caps and the policy table once, when it is first
    constructed, so the process cap has to be lowered *before* the first
    ``get_websocket_manager()`` call — which is why the reset and the construction
    both sit inside this block in the run rather than in a phase of their own.
    The intervals are re-pointed per phase by :func:`_phase_settings`, and every
    value this touches is restored on the way out, so the run leaves the process
    configured as it found it.
    """
    keys = (
        "websocket_heartbeat_interval_seconds",
        "websocket_dashboard_interval_seconds",
        "websocket_max_connections",
        "websocket_max_connections_per_channel",
    )
    original = {key: getattr(settings, key) for key in keys}
    try:
        settings.websocket_max_connections = LAB_MAX_CONNECTIONS
        settings.websocket_max_connections_per_channel = (
            LAB_MAX_CONNECTIONS_PER_CHANNEL
        )
        settings.websocket_heartbeat_interval_seconds = QUIET_HEARTBEAT_SECONDS
        settings.websocket_dashboard_interval_seconds = FAST_DASHBOARD_SECONDS
        yield
    finally:
        for key, value in original.items():
            setattr(settings, key, value)


def _phase_settings(*, heartbeat_seconds: float, dashboard_seconds: float) -> None:
    """Point the *next* lifespan at the intervals a phase needs (M14.9/M14.24).

    ``start_websockets`` reads both settings as it starts the tick and the
    heartbeat, so assigning them between phases is what gives the keepalive check
    a fraction of a second and the event-flow check an interval long enough that
    no ping can arrive while four sockets are held open at once.
    """
    settings.websocket_heartbeat_interval_seconds = heartbeat_seconds
    settings.websocket_dashboard_interval_seconds = dashboard_seconds


@contextmanager
def _patch_process_services(
    stack: _Stack, factory: Any
) -> Generator[None, None, None]:
    """Point the process-wide service accessors at ``stack`` (M14.32).

    ``app.websockets.dashboard`` reaches each collaborator through
    ``from app.<layer> import get_<thing>`` *inside* the sampling function, which
    is what makes a module-attribute assignment reach it. The REST routes are
    handled separately, through ``app.dependency_overrides``, because a route
    resolved its dependency function once at definition time and an attribute
    patch would not reach it. Both are needed, and between them the tick and the
    routes read the same objects — which is the only way "the tick agrees with the
    endpoint" is a claim worth making (M14.9).
    """
    import app.connections.manager as connections_module
    import app.correlation as correlation_package
    import app.devices.manager as devices_module
    import app.persistence.session_factory as session_module
    import app.services.capture_manager as capture_module
    import app.statistics.manager as statistics_module

    replacements: dict[Any, tuple[str, Any]] = {
        capture_module: ("get_capture_manager", lambda: stack.manager),
        statistics_module: ("get_statistics_manager", lambda: stack.statistics),
        devices_module: ("get_device_manager", lambda: stack.devices),
        connections_module: ("get_connection_tracker", lambda: stack.connections),
        correlation_package: ("get_correlation_engine", lambda: stack.correlation),
        # The tick's open-alert count comes from the M11 aggregation, which is
        # built over the *application's* session factory. Pointing that at the
        # throwaway database is what makes the tick's alert count the same number
        # the alerts route reports instead of a zero from an empty real database.
        session_module: ("app_session_factory", factory),
    }
    original = {
        module: (name, getattr(module, name))
        for module, (name, _replacement) in replacements.items()
    }
    for module, (name, replacement) in replacements.items():
        setattr(module, name, replacement)
    try:
        yield
    finally:
        for module, (name, value) in original.items():
            setattr(module, name, value)


def _build_overrides(stack: _Stack, factory: Any, db_engine: Any) -> dict[Any, Any]:
    """Return the dependency overrides that point the API at ``stack`` (M13.28).

    Each key is the *dependency function* a route declares in ``Depends``, so the
    route still resolves its collaborator through FastAPI and the wiring remains
    the application's rather than this script's.
    """
    from app import models as _models  # noqa: F401  (register every table)
    from app.database.base import Base

    Base.metadata.create_all(bind=db_engine)

    def db_override() -> Generator[Session, None, None]:
        session = Session(bind=db_engine)
        try:
            yield session
        finally:
            session.close()

    return {
        get_db: db_override,
        get_statistics_manager: lambda: stack.statistics,
        get_device_manager: lambda: stack.devices,
        get_connection_tracker: lambda: stack.connections,
        get_detection_engine: lambda: stack.detection,
        get_correlation_engine: lambda: stack.correlation,
        get_capture_manager: lambda: stack.manager,
        get_interface_manager: lambda: stack.interfaces,
        # The lifecycle *write* path needs the engine the pipeline wrote through.
        get_alert_engine: lambda: stack.alerts,
        # The alert read service needs a *factory*, not a session.
        get_alert_queries: lambda: AlertQueries(session_factory=factory),
    }


@contextmanager
def _serve(
    stack: _Stack, factory: Any, db_engine: Any
) -> Generator[TestClient, None, None]:
    """Yield a client over the real application, wired to ``stack`` (M14.32).

    The environment is temporarily ``"test"`` so the lifespan skips ``init_db()``
    and never touches the developer's database, and every override is removed
    afterwards so nothing leaks into a later request. Entering this context is what
    runs the lifespan, so the manager's loop is bound and the heartbeat and
    dashboard tasks are running before the first socket dials in (M14.20).
    """
    overrides = _build_overrides(stack, factory, db_engine)
    original_env = settings.app_env
    settings.app_env = "test"
    for dependency, value in overrides.items():
        app.dependency_overrides[dependency] = value
    try:
        with TestClient(app) as client:
            yield client
    finally:
        for dependency in overrides:
            app.dependency_overrides.pop(dependency, None)
        settings.app_env = original_env


#: How long a reader waits for one frame before failing (M14.32). Generous
#: enough for the slowest legitimate producer — the dashboard tick and the
#: heartbeat both fire well inside a second — and short enough that a missing
#: event is reported rather than waited on.
READ_TIMEOUT_SECONDS = 10.0

#: The sentinel the reader thread queues when the socket closes (M14.32). An
#: object rather than ``None``, so no frame could ever be mistaken for a close.
_SOCKET_CLOSED = object()


class ChannelReader:
    """A live WebSocket client on one channel, recording what it receives (M14.32).

    Frames are read *by type* rather than positionally, because a channel is
    shared with the server's own traffic: the keepalive can ping any channel and
    the dashboard tick fires on its own, so "the next frame" is not a well-defined
    thing to assert. Every frame it reads is recorded, and that recording is what
    the separation check walks — which is what turns M14.6 from an assumption in
    the design document into an assertion about this run.
    """

    def __init__(self, socket: Any, channel: Channel) -> None:
        self._socket: Any = socket
        self.channel = channel
        self.frames: list[dict[str, Any]] = []
        self.answered_pings = 0
        # Reading happens on a thread of its own so the wait has a deadline. A
        # blocking receive_json on this thread would hang the whole run when an
        # event the backend should have published did not appear.
        self._incoming: queue.Queue[Any] = queue.Queue()
        self._reader = threading.Thread(
            target=self._pump, name=f"verify-m14-{channel.value}", daemon=True
        )
        self._reader.start()

    def _pump(self) -> None:
        """Read frames until the socket closes, queueing them for read()."""
        while True:
            try:
                message = self._socket.receive_json()
            except Exception:  # noqa: BLE001 - a closed socket is a normal end
                break
            self._incoming.put(message)
        self._incoming.put(_SOCKET_CLOSED)

    def send(self, message: dict[str, Any]) -> None:
        """Send one client message, as a browser would."""
        self._socket.send_json(message)

    def send_text(self, text: str) -> None:
        """Send one raw text frame."""
        self._socket.send_text(text)

    def read(self) -> dict[str, Any]:
        """Read one frame, record it, and answer a keepalive if it is a ping.

        Answering is deliberate: this client behaves like a well-behaved browser,
        so an unread channel is not retired for failing to answer a keepalive it
        was never given the chance to read. It is also what lets the keepalive
        check assert, from the manager's own counters, that its pings were
        answered rather than merely sent.
        """
        try:
            message = self._incoming.get(timeout=READ_TIMEOUT_SECONDS)
        except queue.Empty:
            raise AssertionError(
                f"{self.channel.value}: no frame arrived within "
                f"{READ_TIMEOUT_SECONDS}s; {len(self.frames)} frame(s) received, "
                f"types={sorted({str(m.get('type')) for m in self.frames})}"
            ) from None
        if message is _SOCKET_CLOSED:
            raise AssertionError(
                f"{self.channel.value}: the socket closed while a frame was "
                f"expected; {len(self.frames)} frame(s) received"
            )
        frame: dict[str, Any] = dict(message)
        self.frames.append(frame)
        if frame.get("type") == EventType.PING:
            self.answered_pings += 1
            self.send({"type": "pong"})
        return frame

    def read_until(self, event_type: str, *, count: int = 1) -> list[dict[str, Any]]:
        """Read until ``count`` frames of ``event_type`` have arrived, and return them.

        Raises:
            AssertionError: If they do not arrive within the frame budget, so a
                missing event is reported where it was expected instead of hanging
                the run.
        """
        wanted: list[dict[str, Any]] = []
        for _ in range(FRAME_BUDGET):
            message = self.read()
            if message.get("type") == event_type:
                wanted.append(message)
                if len(wanted) >= count:
                    return wanted
        raise AssertionError(
            f"{self.channel.value}: only {len(wanted)} of {count} {event_type} "
            f"frame(s) arrived within {FRAME_BUDGET} frames"
        )

    def read_for(self, required: dict[str, int]) -> None:
        """Read until each event type in ``required`` has arrived often enough.

        Reading for *all* the types a check needs, rather than for one type at a
        time, is what keeps the recording authoritative. A single-type read stops
        as soon as its own count is met and swallows whatever else arrived in
        between, so the next type would then be waited for after it had already
        gone past. Here every frame is recorded first and the counts are checked
        against the recording, which makes an interleaved arrival harmless.
        """
        def satisfied() -> bool:
            return all(
                len(self.types_of(event_type)) >= count
                for event_type, count in required.items()
            )

        if satisfied():
            return
        for _ in range(FRAME_BUDGET):
            self.read()
            if satisfied():
                return
        held = {name: len(self.types_of(name)) for name in required}
        raise AssertionError(
            f"{self.channel.value}: waited for {required}, received {held} within "
            f"{FRAME_BUDGET} frames"
        )

    def types_of(self, event_type: str) -> list[dict[str, Any]]:
        """Return every recorded frame of ``event_type``, in arrival order."""
        return [
            message for message in self.frames if message.get("type") == event_type
        ]

    def foreign_frames(self) -> list[dict[str, Any]]:
        """Return every recorded frame that named a channel other than this one.

        The manager keeps one registry per channel and a broadcast walks only that
        channel's entries, so this list must be empty — a single entry would mean a
        subscriber can be shown traffic it did not dial for (M14.6).
        """
        return [
            message
            for message in self.frames
            if message.get("channel") != self.channel.value
        ]

    def assert_envelope(self, message: dict[str, Any]) -> None:
        """Assert the six envelope fields a client may rely on (M14.7)."""
        assert message.get("schema_version") == 1, message
        assert str(message.get("event_id")).startswith("evt-"), message
        assert str(message.get("timestamp")).endswith("+00:00"), message
        assert isinstance(message.get("sequence"), int), message
        assert isinstance(message.get("data"), dict), message
        assert message.get("type") in EventType.__dict__.values() or isinstance(
            message.get("type"), str
        ), message


def _await_connections(manager: Any, expected: dict[Channel, int]) -> None:
    """Wait until each channel holds its expected number of connections (M14.32).

    ``websocket_connect`` returns once the handshake is accepted, which is before
    the route has registered the socket. Publishing into that window would have no
    subscriber, so waiting is what makes "the client received it" a statement
    about the broadcast rather than about a scheduling accident.
    """
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if all(
            manager.get_connection_count(channel) == count
            for channel, count in expected.items()
        ):
            return
        time.sleep(0.005)
    held = {
        channel.value: manager.get_connection_count(channel) for channel in expected
    }
    raise AssertionError(f"connections never reached {expected}; holding {held}")


def _get_data(client: TestClient, url: str, **params: Any) -> dict[str, Any]:
    """GET a route, require the success envelope, and return ``data`` (M13.4)."""
    response = client.get(url, params=params or None)
    if response.status_code != 200:
        raise AssertionError(f"{url} -> {response.status_code}: {response.text[:200]}")
    body = response.json()
    if body.get("success") is not True:
        raise AssertionError(f"{url} did not report success: {body}")
    return dict(body["data"])


def _receive_or_none(socket: Any) -> Any:
    """Read one frame with a deadline, returning ``None`` if none arrives (M14.32).

    For the places where the *absence* of a frame is the expected outcome — a
    connection the cap should refuse. A plain ``receive_json`` there would block
    forever if the refusal did not happen, turning a reportable failure into a
    hang.
    """
    incoming: queue.Queue[Any] = queue.Queue()

    def pump() -> None:
        try:
            incoming.put(socket.receive_json())
        except Exception:  # noqa: BLE001 - a closed socket simply reports nothing
            incoming.put(None)

    threading.Thread(target=pump, daemon=True).start()
    try:
        return incoming.get(timeout=READ_TIMEOUT_SECONDS)
    except queue.Empty:
        return None


def _check_keepalive(client: TestClient, failures: list[str]) -> None:
    """Verify the keepalive in both directions, over a real socket (M14.24).

    Run at a fraction of a second so the shipped twenty-second default is not
    waited out. Two different claims are asserted: that the *server* pinged on its
    own timer (the heartbeat task is alive and reached this client), and that a
    *client* ping was answered with a pong carrying the client's own nonce (the
    receive loop answers rather than ignoring). A keepalive that only ever went
    one way would pass neither.
    """
    print("\n--- Keepalive, both directions (M14.23/M14.24) ---")
    manager = get_websocket_manager()
    before = manager.get_counters()
    with client.websocket_connect(CHANNEL_PATHS[Channel.SYSTEM]) as socket:
        reader = ChannelReader(socket, Channel.SYSTEM)
        ping = reader.read_until(EventType.PING, count=1)[0]
        print(
            f"  server ping            : {ping['type']} "
            f"(interval {settings.websocket_heartbeat_interval_seconds}s, "
            f"nonce {ping['data'].get('nonce')!r})"
        )
        reader.send({"type": "ping", "nonce": "verify-m14"})
        pong = reader.read_until(EventType.PONG, count=1)[0]
        print(f"  client ping -> pong    : nonce={pong['data'].get('nonce')!r}")
        if pong["data"].get("nonce") != "verify-m14":
            failures.append(
                "a client ping was not answered with a pong carrying its nonce "
                "(M14.23)"
            )
        _await_connections(manager, {Channel.SYSTEM: 1})
    after = manager.get_counters()
    answered = after["heartbeat_pings"] - before["heartbeat_pings"]
    timeouts = after["heartbeat_timeouts"] - before["heartbeat_timeouts"]
    print(f"  heartbeat pings sent   : {answered} (retirements {timeouts})")
    if answered < 1:
        failures.append(
            "the heartbeat sent no ping while a client was connected (M14.24)"
        )
    if timeouts:
        failures.append(
            f"the heartbeat retired {timeouts} client(s) that were answering (M14.24)"
        )


def _check_dashboard_agreement(
    tick: dict[str, Any],
    summary: dict[str, Any],
    expected_packets: int,
    failures: list[str],
) -> None:
    """Assert the live tick and the summary endpoint report the same numbers (M14.9).

    This is the check that gives M14.9 its meaning. The tick is not a second
    aggregation, it is the same services read at a different moment, and comparing
    every count it carries against the endpoint that reads those same services is
    what demonstrates that.

    Only the counts are compared. The rates are recomputed per read from the
    elapsed time and cannot be equal across two reads, so asserting on them would
    be a flaky test of the clock rather than of the dashboard.
    """
    print("\n--- Dashboard tick vs /dashboard/summary (M14.9) ---")
    data = tick["data"]
    if set(data) != DASHBOARD_FIELDS:
        failures.append(
            "the dashboard tick carried "
            f"{sorted(data)}, not the documented field set (M14.9)"
        )
    capture = summary["capture"]["data"]
    devices = summary["devices"]["data"]
    connections = summary["connections"]["data"]
    alerts = summary["alerts"]["data"]
    incidents = summary["incidents"]["data"]
    comparisons: tuple[tuple[str, Any, Any], ...] = (
        ("packet_count", data.get("packet_count"), capture.get("packet_count")),
        ("capture_running", data.get("capture_running"), capture.get("running")),
        ("device_count", data.get("device_count"), devices.get("total")),
        (
            "active_connections",
            data.get("active_connections"),
            connections.get("active"),
        ),
        ("open_alerts", data.get("open_alerts"), alerts.get("open")),
        ("active_incidents", data.get("active_incidents"), incidents.get("active")),
    )
    for name, live, endpoint in comparisons:
        print(f"  {name:<20}: tick={live!r} summary={endpoint!r}")
        if live != endpoint:
            failures.append(
                f"the dashboard tick's {name} ({live!r}) disagrees with the summary "
                f"endpoint ({endpoint!r}) (M14.9)"
            )
    if data.get("packet_count") != expected_packets:
        failures.append(
            "the dashboard tick did not report the packets the session captured "
            f"({data.get('packet_count')} of {expected_packets}) (M14.9)"
        )


def _check_refusals(reader: ChannelReader, failures: list[str]) -> None:
    """Verify client input is refused, named, and never echoed (M14.22/M14.23).

    Three probes, each reaching a different refusal on the same socket: garbage
    that is not JSON, a well-formed message with an unsupported type, and a frame
    over the size cap. They are sent on one connection and kept under
    ``websocket_max_invalid_messages``, because the point is the refusal, not the
    disconnect that follows too many of them.
    """
    print("\n--- Client input is refused (M14.22/M14.23) ---")
    limit = int(settings.websocket_max_client_message_bytes)
    oversized_nonce = "x" * (limit + 64)
    probes: tuple[tuple[str, Any, str], ...] = (
        ("garbage", "{not json at all", REFUSAL_NOT_JSON),
        ("unknown type", {"type": "shutdown-everything"}, REFUSAL_UNKNOWN_TYPE),
        ("oversized", {"type": "ping", "nonce": oversized_nonce}, REFUSAL_TOO_LARGE),
    )
    for name, payload, expected in probes:
        if isinstance(payload, str):
            reader.send_text(payload)
        else:
            reader.send(payload)
        message = reader.read_until(EventType.ERROR, count=1)[0]
        reason = message["data"].get("reason")
        print(
            f"  {name:<14}: {reason!r} (field={message['data'].get('field')!r})"
        )
        if reason != expected:
            failures.append(
                f"a {name} client message was refused with {reason!r}, not "
                f"{expected!r} (M14.23)"
            )
        echoed = json.dumps(message)
        for fragment in ("not json at all", "shutdown-everything", "xxxxxxxxxx"):
            if fragment in echoed:
                failures.append(
                    f"the refusal of a {name} message echoed the client's own bytes "
                    "(M14.22)"
                )
                break


def _check_event_flow(
    client: TestClient,
    stack: _Stack,
    packets: Sequence[Any],
    failures: list[str],
) -> None:
    """Verify the whole M14.8–M14.12 flow over four live sockets (M14.32).

    One phase, one capture session, four subscribers: the packets the pipeline
    processes, the alerts their detections raise, the incident those alerts
    correlate into, the capture state change that brackets it and the dashboard
    tick that summarises it. Every frame is produced by the production publish
    sites — this function publishes nothing itself except the one separation probe
    at the end, and even that goes through the pipeline.
    """
    print("\n--- Event flow over four live sockets (M14.6-M14.12) ---")
    manager = get_websocket_manager()
    expected_packets = len(packets)
    readers: dict[Channel, ChannelReader] = {}

    with contextlib.ExitStack() as sockets:
        for channel in CHANNELS:
            socket = sockets.enter_context(
                client.websocket_connect(CHANNEL_PATHS[channel])
            )
            readers[channel] = ChannelReader(socket, channel)
        _await_connections(manager, dict.fromkeys(CHANNELS, 1))
        print(f"  connected              : {', '.join(c.value for c in CHANNELS)}")

        stack.capture(packets)

        packets_reader = readers[Channel.PACKETS]
        observed = packets_reader.read_until(
            EventType.PACKET_OBSERVED, count=expected_packets
        )
        published = stack.pipeline.get_published_packet_count()
        print(
            f"  packet.observed        : {len(observed)} frames "
            f"(pipeline published {published} of {expected_packets} packets)"
        )
        if len(observed) != expected_packets:
            failures.append(
                f"the packets channel carried {len(observed)} events for "
                f"{expected_packets} processed packets (M14.8)"
            )
        if published != expected_packets:
            failures.append(
                f"the pipeline published {published} of {expected_packets} packets, "
                "so the live stream lost one that capture had (M14.8/M14.14)"
            )
        for frame in observed:
            if set(frame["data"]) != PACKET_FIELDS:
                failures.append(
                    "a packet event carried "
                    f"{sorted(frame['data'])}, not the documented field set (M14.8)"
                )
                break
            leaked = [
                key
                for key in ("payload", "raw", "bytes", "metadata", "hexdump")
                if key in frame["data"]
            ]
            if leaked:
                failures.append(
                    f"a packet event carried {leaked}, which M14.8 forbids (M14.8)"
                )
                break
        sequences = [int(frame["sequence"]) for frame in observed]
        if sequences != sorted(sequences):
            failures.append(
                "packet events arrived out of sequence order, so a client cannot "
                "detect a gap (M14.7)"
            )
        packets_reader.assert_envelope(observed[0])

        alerts_reader = readers[Channel.ALERTS]
        alerts_reader.read_for(
            {EventType.ALERT_CREATED: 2, EventType.INCIDENT_CREATED: 1}
        )
        created = alerts_reader.types_of(EventType.ALERT_CREATED)[:2]
        incidents = alerts_reader.types_of(EventType.INCIDENT_CREATED)[:1]
        rules = sorted({str(frame["data"].get("rule_id")) for frame in created})
        print(f"  alert.created          : {len(created)} frames, rules={rules}")
        if "port_scan" not in rules:
            failures.append(
                f"no alert event named the port-scan detector (rules were {rules}) "
                "(M14.10)"
            )
        for frame in created:
            if frame["data"].get("status") != "open":
                failures.append(
                    "an alert.created event did not carry an open alert (M14.10)"
                )
                break
        incident = incidents[0]
        print(
            f"  incident.created       : alerts={incident['data'].get('alert_count')} "
            f"risk={incident['data'].get('risk_score')} "
            f"band={incident['data'].get('risk_band')!r}"
        )
        if int(incident["data"].get("risk_score") or 0) <= 0:
            failures.append(
                "the incident event carried no risk score, so the score was not read "
                "from the incident (M14.12)"
            )
        if incident["data"].get("risk_band") in (None, "minimal"):
            failures.append(
                "the incident event reported a minimal risk band for correlated "
                "scan activity (M14.12)"
            )

        system_reader = readers[Channel.SYSTEM]
        system_reader.read_for(
            {EventType.CAPTURE_STARTED: 1, EventType.CAPTURE_STOPPED: 1}
        )
        started = system_reader.types_of(EventType.CAPTURE_STARTED)[0]
        stopped = system_reader.types_of(EventType.CAPTURE_STOPPED)[0]
        print(
            f"  capture.started/stopped: interface={started['data'].get('interface')!r} "
            f"/ packets={stopped['data'].get('packet_count')}"
        )
        if started["data"].get("interface") != CAPTURE_INTERFACE:
            failures.append(
                "capture.started did not name the interface the session used (M14.11)"
            )
        if stopped["data"].get("packet_count") != expected_packets:
            failures.append(
                "capture.stopped did not carry the session's packet count "
                f"({stopped['data'].get('packet_count')} of {expected_packets}) "
                "(M14.11)"
            )

        dashboard_reader = readers[Channel.DASHBOARD]
        # Two ticks, and the second is used: the first may have been sampled
        # before the capture finished, and the point of the comparison below is
        # the state *after* it.
        dashboard_reader.read_until(EventType.DASHBOARD_UPDATED, count=2)
        tick = dashboard_reader.types_of(EventType.DASHBOARD_UPDATED)[-1]
        summary = _get_data(client, f"{API}/dashboard/summary")
        unavailable = summary.get("unavailable_sections") or []
        if unavailable:
            failures.append(
                f"the dashboard summary reported unavailable sections: {unavailable} "
                "(M13.19)"
            )
        _check_dashboard_agreement(tick, summary, expected_packets, failures)

        # Positional separation probe. A service event is published, then a packet
        # is pushed through the real pipeline, and each subscriber's *next* frame
        # must be its own. Any leak earlier in the run is already caught by the
        # recorded-frame check below; this catches one that would otherwise sit
        # behind frames already read.
        manager.publish(builders.service_event("verify", "probe"))
        stack.pipeline.process(_scan_packets(1)[0])
        next_packets = packets_reader.read()
        next_system = system_reader.read()
        if next_packets.get("type") != EventType.PACKET_OBSERVED:
            failures.append(
                "the packets socket's next frame was "
                f"{next_packets.get('type')!r}, not a packet event (M14.6)"
            )
        if next_system.get("type") != EventType.SERVICE_STATUS:
            failures.append(
                "the system socket's next frame was "
                f"{next_system.get('type')!r}, not the service event (M14.6)"
            )

        total = sum(len(reader.frames) for reader in readers.values())
        foreign: list[str] = []
        for channel, reader in readers.items():
            leaked = reader.foreign_frames()
            if leaked:
                foreign.append(
                    f"{channel.value} received {len(leaked)} frame(s) naming "
                    f"{sorted({str(m.get('channel')) for m in leaked})}"
                )
        print(
            f"  separation             : {total} frames read, "
            f"{len(foreign)} foreign"
        )
        for entry in foreign:
            failures.append(f"channel separation was broken over the wire: {entry} (M14.6)")

        _check_refusals(system_reader, failures)

    _await_connections(manager, dict.fromkeys(CHANNELS, 0))


def _check_cap(client: TestClient, failures: list[str]) -> None:
    """Verify the per-channel cap refuses rather than registering (M14.22).

    Deliberately its own phase and its own channel, so the sockets the flow check
    holds cannot be confused with the ones this one opens. What is asserted is not
    that a client was *dropped* but that it was never *admitted*: a client that
    entered the registry and was then closed would still be reachable by a
    broadcast in flight, which is the failure M14.22 names.
    """
    print("\n--- Connection cap over the wire (M14.22) ---")
    manager = get_websocket_manager()
    cap = LAB_MAX_CONNECTIONS_PER_CHANNEL
    with contextlib.ExitStack() as sockets:
        for _ in range(cap):
            sockets.enter_context(
                client.websocket_connect(CHANNEL_PATHS[Channel.ALERTS])
            )
        _await_connections(manager, {Channel.ALERTS: cap})
        before = manager.get_counters()["connections_refused"]
        handshake_rejected = False
        served_a_frame = True
        try:
            with client.websocket_connect(CHANNEL_PATHS[Channel.ALERTS]) as extra:
                served_a_frame = _receive_or_none(extra) is not None
        except WebSocketDisconnect:
            handshake_rejected = True
            served_a_frame = False
        counted = manager.get_counters()["connections_refused"] - before
        held = manager.get_connection_count(Channel.ALERTS)
        print(
            f"  cap {cap}, then one more  : handshake_rejected="
            f"{handshake_rejected} served_a_frame={served_a_frame} "
            f"counted={counted} registered={held}"
        )
        # Two shapes of refusal exist and both are a refusal: the transport can
        # reject the handshake outright, or accept it and close it at once, which
        # surfaces here as "no frame was ever served". What must not happen is the
        # third shape — a socket past the cap being served an event — and the
        # registry and the counter are the evidence for that, because a socket
        # admitted and closed immediately would still have been reachable by a
        # broadcast in flight.
        if served_a_frame:
            failures.append(
                f"a connection past the per-channel cap of {cap} was served a "
                "frame, so it was admitted (M14.22)"
            )
        if held != cap:
            failures.append(
                f"a refused socket entered the registry ({held} registered, cap "
                f"{cap}) (M14.22)"
            )
        if counted != 1:
            failures.append(
                f"the refusal was counted {counted} time(s), not once (M14.22)"
            )
    _await_connections(manager, {Channel.ALERTS: 0})


def _check_counters(stack: _Stack, failures: list[str]) -> None:
    """Verify the run left no fault hidden and no client behind (M14.14/M14.18).

    The counters are the check that isolation cannot hide a fault: a layer that
    kept the pipeline alive while failing on every event would pass every
    functional assertion above and fail here, which is exactly why M14.14 requires
    the numbers to exist.
    """
    print("\n--- Counters and cleanup (M14.14/M14.18/M14.33) ---")
    manager = get_websocket_manager()
    counters = manager.get_counters()
    stages: dict[str, int] = {
        "processing": stack.pipeline.get_processing_error_count(),
        "statistics": stack.pipeline.get_statistics_error_count(),
        "devices": stack.pipeline.get_device_error_count(),
        "persistence": stack.pipeline.get_persistence_error_count(),
        "connections": stack.pipeline.get_connection_error_count(),
        "detection": stack.pipeline.get_detection_error_count(),
        "alerts": stack.pipeline.get_alert_error_count(),
        "correlation": stack.pipeline.get_correlation_error_count(),
    }
    print(f"  pipeline stage errors  : {stages}")
    for stage, error_count in stages.items():
        if error_count:
            failures.append(
                f"the {stage} stage recorded {error_count} error(s) (M14.14)"
            )
    dropped = (
        counters["dropped_no_loop"]
        + counters["dropped_disabled"]
        + counters["dropped_rate_limited"]
        + counters["rejected_oversized"]
    )
    print(
        f"  manager counters       : published={counters['published']} "
        f"broadcast={counters['broadcast']} delivered={counters['delivered']} "
        f"dropped={dropped}"
    )
    print(
        f"  failure counters       : publish_errors={counters['publish_errors']} "
        f"send_errors={counters['send_errors']} "
        f"accepted={counters['connections_accepted']} "
        f"refused={counters['connections_refused']} "
        f"closed={counters['connections_closed']}"
    )
    for name in ("publish_errors", "send_errors"):
        if counters[name]:
            failures.append(
                f"the WebSocket layer recorded {counters[name]} {name}, so a fault "
                "was counted rather than isolated (M14.14)"
            )
    if counters["connections_accepted"] < 1:
        failures.append("no connection was ever accepted (M14.3)")
    if manager.get_connection_count():
        failures.append(
            f"{manager.get_connection_count()} client(s) were still registered at "
            "the end of the run (M14.18)"
        )
    for channel in CHANNELS:
        stats = manager.channel_stats()[channel.value]
        print(
            f"    {channel.value:<10} queue_size={stats['queue_size']} "
            f"rate={stats['max_events_per_second']} priority={stats['priority']} "
            f"enabled={stats['enabled']} connections={stats['connections']}"
        )
def _print_banner(db_path: Path, packets: Sequence[Any]) -> None:
    """Print the run's fixed conditions before any check output (M14.32)."""
    print("=" * _BANNER_WIDTH)
    print("M14 SAMPLE MODE — the live WebSocket layer over real backend data")
    print("=" * _BANNER_WIDTH)
    print(f"database    : {db_path}")
    print(
        f"packets     : {len(packets)} driven through the real capture path "
        "(fake sniffer, real M4-M12 pipeline)"
    )
    print(f"channels    : {', '.join(channel.value for channel in CHANNELS)}")
    print(
        f"lab config  : heartbeat {FAST_HEARTBEAT_SECONDS}s (keepalive phase) then "
        f"{QUIET_HEARTBEAT_SECONDS}s, dashboard {FAST_DASHBOARD_SECONDS}s, caps "
        f"{LAB_MAX_CONNECTIONS} total / {LAB_MAX_CONNECTIONS_PER_CHANNEL} per channel"
    )


def _report_failures(failures: list[str], *, mode: str) -> int:
    """Print the failures and return the process exit code."""
    print("\n" + "=" * _BANNER_WIDTH)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        print(f"{mode.capitalize()} mode finished with {len(failures)} failure(s).")
        return 1
    print(f"{mode.capitalize()} mode complete - all checks passed.")
    return 0


def run_sample_mode() -> int:
    """Drive the pipeline, then verify the live layer over its real data (M14.32)."""
    workdir = Path(tempfile.mkdtemp(prefix="netwatch_m14_"))
    db_path = workdir / "verify_m14.db"
    database, factory = _connect_database(db_path)
    failures: list[str] = []
    try:
        _seed_rule_catalogue(factory)
        # A fresh manager, built under the lab caps below, and a fresh sequence so
        # this run's own numbering starts at one.
        reset_websockets()
        reset_sequence()
        with _lab_websocket_settings():
            publisher = get_event_publisher()
            # ``enabled`` belongs to the manager and the concrete publishers, not
            # to the ``EventPublisher`` protocol, so the manager is what is asked
            # (M14.16).
            if not get_websocket_manager().enabled:
                failures.append(
                    "the WebSocket layer is disabled (websockets_enabled is false), "
                    "so there is nothing to verify (M14.16)"
                )
                return _report_failures(failures, mode="sample")
            stack = _build_stack(factory, publisher)
            packets = _scan_packets(PORT_SCAN_THRESHOLD + 2) + _sweep_packets(
                INTERNAL_SCAN_THRESHOLD + 2
            )
            _print_banner(db_path, packets)
            # The patch is what makes the dashboard tick read *this* run's
            # services, so the tick and the REST route it is compared against are
            # looking at the same objects (M14.9).
            with _patch_process_services(stack, factory):
                # Phase one: the keepalive, at a fraction of a second (M14.24).
                _phase_settings(
                    heartbeat_seconds=FAST_HEARTBEAT_SECONDS,
                    dashboard_seconds=FAST_DASHBOARD_SECONDS,
                )
                with _serve(stack, factory, database) as client:
                    _check_keepalive(client, failures)
                # Phase two: the event flow, with the heartbeat effectively off.
                # Four sockets are held open at once and a reader can only answer a
                # ping on the socket it is currently reading, so a short interval
                # would retire a client that is legitimately mid-check (M14.24).
                _phase_settings(
                    heartbeat_seconds=QUIET_HEARTBEAT_SECONDS,
                    dashboard_seconds=FAST_DASHBOARD_SECONDS,
                )
                with _serve(stack, factory, database) as client:
                    _check_event_flow(client, stack, packets, failures)
                    _check_cap(client, failures)
                _check_counters(stack, failures)
    finally:
        database.dispose()
        shutil.rmtree(workdir, ignore_errors=True)
        reset_websockets()
    return _report_failures(failures, mode="sample")


#: How long the live-mode client waits for a frame before giving up (M14.32).
LIVE_TIMEOUT_SECONDS = 10.0


def _wait_for_server(client: httpx.Client, *, attempts: int = 60) -> bool:
    """Poll the OpenAPI document until the server answers, or give up (M14.32).

    ``attempts`` at ~0.25s each gives the lifespan about fifteen seconds to
    finish, which is ample locally and short enough that a failure to bind is
    reported rather than waited on.
    """
    for _ in range(attempts):
        try:
            if client.get("/openapi.json").status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    return False


def _free_port(host: str, requested: int) -> int:
    """Return ``requested`` if it can be bound, else an unused port (M14.32).

    Binding port 0 and reading the assignment back is how the OS picks a free
    port; the probe socket is closed immediately, so the window in which another
    process could take it is tiny and a failure is reported rather than hidden.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((host, requested))
            return requested
        except OSError:
            pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((host, 0))
        return int(probe.getsockname()[1])


def _live_receive_of_type(
    socket: Any, event_type: str, *, attempts: int = 10
) -> dict[str, Any]:
    """Read from a live socket until a frame of ``event_type`` arrives (M14.32).

    Reading by type rather than positionally is necessary here for the same reason
    it is in sample mode: the dashboard channel pushes a tick on its own timer, so
    "the next frame" is not well defined on the socket a check is holding.
    """
    for _ in range(attempts):
        message = json.loads(socket.recv(timeout=LIVE_TIMEOUT_SECONDS))
        if message.get("type") == event_type:
            return dict(message)
    raise AssertionError(f"no {event_type} frame arrived within {attempts} frames")


def _check_live_channel(base_url: str, channel: Channel, failures: list[str]) -> None:
    """Speak real WebSocket to one live channel and check what it answers (M14.32).

    A client ``ping`` is the probe on every channel, including the ones that are
    legitimately silent on an idle installation: the pong proves the route exists,
    the handshake was accepted and the receive loop answers, none of which depends
    on a capture session being started. The dashboard channel is additionally
    required to *push* a tick, because pushing one is that channel's whole job.
    """
    from websockets.sync.client import connect as websocket_connect

    url = f"{base_url}{CHANNEL_PATHS[channel]}"
    with websocket_connect(url, open_timeout=LIVE_TIMEOUT_SECONDS) as socket:
        socket.send(json.dumps({"type": "ping", "nonce": channel.value}))
        pong = _live_receive_of_type(socket, EventType.PONG)
        print(
            f"  {CHANNEL_PATHS[channel]:<15} ping -> {pong.get('type')} "
            f"channel={pong.get('channel')} nonce={pong.get('data', {}).get('nonce')}"
        )
        if pong.get("data", {}).get("nonce") != channel.value:
            failures.append(
                f"{url} did not answer the client's ping with its own nonce (M14.23)"
            )
        if pong.get("channel") != channel.value:
            failures.append(
                f"{url} answered on channel {pong.get('channel')!r}, not "
                f"{channel.value!r} (M14.6)"
            )
        socket.send(json.dumps({"type": "not-a-real-type"}))
        refused = _live_receive_of_type(socket, EventType.ERROR)
        print(
            f"  {CHANNEL_PATHS[channel]:<15} refused -> "
            f"{refused.get('data', {}).get('reason')!r}"
        )
        if refused.get("data", {}).get("reason") != REFUSAL_UNKNOWN_TYPE:
            failures.append(f"{url} did not refuse an unknown message type (M14.23)")
        if channel is not Channel.DASHBOARD:
            return
        tick = _live_receive_of_type(socket, EventType.DASHBOARD_UPDATED)
        print(f"  {CHANNEL_PATHS[channel]:<15} tick -> {tick.get('type')}")
        if not DASHBOARD_FIELDS.issubset(set(tick.get("data", {}))):
            failures.append(
                "the dashboard tick did not carry the documented fields (M14.9)"
            )


def run_live_mode(host: str, port: int) -> int:
    """Start the application under uvicorn and speak real WebSocket to it (M14.32).

    This is the mode M14.32 describes literally: a running server, real sockets
    and the documented URLs. It handshakes and reads only — no capture is started
    and nothing is written — so it is safe to point at a working installation.
    """
    import uvicorn

    failures: list[str] = []
    chosen = _free_port(host, port)
    config = uvicorn.Config(app, host=host, port=chosen, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    print("=" * _BANNER_WIDTH)
    print("M14 LIVE MODE — the running application over real WebSocket")
    print("=" * _BANNER_WIDTH)
    print(f"base url : http://{host}:{chosen}")
    if chosen != port:
        print(f"note     : port {port} was busy, so {chosen} was used")
    print("database : the configured one; this mode only reads and handshakes")

    client = httpx.Client(
        base_url=f"http://{host}:{chosen}", timeout=LIVE_TIMEOUT_SECONDS
    )
    try:
        if not _wait_for_server(client):
            failures.append(
                f"the application did not answer on http://{host}:{chosen} within "
                "the startup window"
            )
            return _report_failures(failures, mode="live")

        print("\n--- The four channels over real WebSocket (M14.3/M14.6) ---")
        base_url = f"ws://{host}:{chosen}"
        for channel in CHANNELS:
            try:
                _check_live_channel(base_url, channel, failures)
            except Exception as error:  # noqa: BLE001 - reported, not raised
                failures.append(
                    f"{CHANNEL_PATHS[channel]} could not be used: {error!r} (M14.3)"
                )

        print("\n--- The REST surface beside it still answers (M13.3/M13.4) ---")
        for path in (f"{API}/system/health", f"{API}/dashboard/summary"):
            response = client.get(path)
            body = response.json() if response.status_code == 200 else {}
            print(f"  {path:<26} {response.status_code} success={body.get('success')}")
            if response.status_code != 200 or body.get("success") is not True:
                failures.append(
                    f"{path} did not answer in the success envelope (M13.4)"
                )
    finally:
        client.close()
        server.should_exit = True
        thread.join(timeout=10.0)
    return _report_failures(failures, mode="live")


def main() -> int:
    """Parse arguments and dispatch to the selected mode (M14.32)."""
    parser = argparse.ArgumentParser(
        description="Verify the M14 WebSocket layer over real backend data (M14.32)."
    )
    parser.add_argument(
        "mode",
        nargs="?",
        default="sample",
        choices=("sample", "live"),
        help="sample = isolated pipeline + sockets (default), live = a running server",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Live-mode bind address")
    parser.add_argument(
        "--port",
        type=int,
        default=8012,
        help="Live-mode port (a free one is chosen if busy)",
    )
    args = parser.parse_args()
    if args.mode == "live":
        return run_live_mode(args.host, args.port)
    return run_sample_mode()


if __name__ == "__main__":
    raise SystemExit(main())
