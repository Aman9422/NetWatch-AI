"""M13 verification script — the REST API served over real backend data (M13.36).

Two modes:

  sample  (default)  Drive controlled packets through the *real* pipeline over an
                     isolated temporary SQLite database, then serve the real
                     FastAPI application (``app.main:app``) through a TestClient
                     whose dependencies are overridden to that very stack. Every
                     response below is therefore produced by the production
                     routers reading state the production capture path wrote — no
                     mock, no fixture, no hand-built payload. Verifies the
                     documented surfaces, the OpenAPI document and the standard
                     envelopes, and prints what each API group returned. No admin
                     rights and no Npcap needed.
  live               Start the application under uvicorn on a loopback port and
                     issue real HTTP requests to it, to confirm the documented
                     URLs answer outside the in-process test client. Requires the
                     configured database to exist and to be initialised.

What it verifies, against the M13 completion criteria:

  * ``/docs``, ``/redoc`` and ``/openapi.json`` all answer (M13.27);
  * the OpenAPI document lists every M13 group under ``/api/v1`` (M13.3/M13.27);
  * capture exposes the interfaces, the selection, the status and the start/stop
    controls, and reports a session it really ran (M13.7);
  * packets, statistics, devices, connections and detections answer from the data
    the pipeline stored, with the filters and paging M13.8-M13.12 specify;
  * alerts, their evidence, and the incident the alerts correlate into are all
    readable, and the lifecycle verbs reach the same store the pipeline wrote
    (M13.13-M13.16);
  * the dashboard summary aggregates the same services and agrees with the
    individual routes (M13.19);
  * analytics expose implemented data, reports and notifications expose stored
    metadata, baselines refuse rather than fabricate, and the system endpoints
    answer without leaking a secret (M13.17/M13.18/M13.20-M13.23/M13.30);
  * the success and error envelopes are the documented ones, an unknown route is
    a ``404`` and an out-of-range page is a ``422`` (M13.4/M13.5/M13.6/M13.24).

The one substitution in sample mode is the sniffer: a test may not put a real NIC
in promiscuous mode, so a small in-process double implements the same
``PacketSink`` contract and the packets still travel the real capture → pipeline
path. The database is a throwaway file under the OS temp directory, created and
removed by this script, so running it never touches the developer's
``netwatch.db``.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\verify_m13.py
    & ".venv\\Scripts\\python.exe" scripts\\verify_m13.py live --port 8011
"""

from __future__ import annotations

import argparse
import json
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

_BANNER_WIDTH = 66

#: The versioned base every route below is asserted against (M13.3).
API = "/api/v1"

#: The interface the capture manager is told to use. It is a synthetic interface
#: offered by the script's own discovery function, not the machine's NICs, so the
#: run cannot depend on what hardware is present.
CAPTURE_INTERFACE = "Wi-Fi"

#: The interfaces the synthetic discovery reports. ``Wi-Fi`` is up (so it can be
#: selected and captured on) and ``Ethernet`` is down, which lets the run show
#: that a down interface is listed but refused.
SAMPLE_INTERFACES: list[dict] = [
    {
        "name": CAPTURE_INTERFACE,
        "description": "verify_m13 synthetic interface",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "ip_addresses": ["192.168.1.20"],
        "is_up": True,
    },
    {
        "name": "Ethernet",
        "description": "verify_m13 synthetic interface",
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
#: are dated by the pipeline from the clock as they arrive. Sharing one clock
#: keeps "now" consistent between the layers a request reads back.
CLOCK = time.time

#: The API groups the OpenAPI document must document, as path prefixes (M13.27).
EXPECTED_GROUPS: tuple[str, ...] = (
    "capture",
    "packets",
    "statistics",
    "devices",
    "connections",
    "detections",
    "alerts",
    "evidence",
    "incidents",
    "analytics",
    "dashboard",
    "baselines",
    "reports",
    "settings",
    "system",
    "notifications",
)


class FakeCaptureSniffer:
    """An in-process stand-in for the Scapy sniffer (M4/M13.36).

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


def _connect_database(db_path: Path):
    """Create the isolated SQLite database and a session factory (M13.36).

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


def _seed_rule_catalogue(factory) -> None:
    """Populate ``detection_rules`` and the settings a listing would read.

    The alert table has a foreign key into the seeded rule catalogue, so the
    catalogue must exist before the pipeline stores an alert. A couple of
    settings rows are added too, so ``GET /settings`` returns real stored values
    rather than an empty page.
    """
    from app.database.seed import seed_detection_rules
    from app.models.detection_rule import DetectionRule
    from app.models.setting import Setting

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
        for key, value, data_type in (
            ("default_theme", "dark", "string"),
            ("packet_retention_days", "30", "int"),
            ("api_key_sample", "must-never-be-listed", "string"),
        ):
            if session.query(Setting).filter(Setting.setting_key == key).first() is None:
                session.add(
                    Setting(setting_key=key, setting_value=value, data_type=data_type)
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


@dataclass
class _Stack:
    """The live application, wired end to end over the isolated database.

    Holding the collaborators rather than re-deriving them is what lets the
    dependency overrides hand the API the *same* objects the pipeline fed, so a
    response can only be correct if the pipeline really wrote what the route
    reads. That is the property M13.36's "real backend data" asks for.
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
        """Run one real capture session over the fake sniffer (M13.7).

        The interface is chosen on the M4 :class:`InterfaceManager`, which is
        where selection lives, then the manager is started and the packets are
        emitted through the sniffer's sink callback — the real capture path.
        Stopping flushes persistence and the connection aggregates, so a route
        reads a complete store afterwards (M7.18/M9.17).
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
    detector, exactly as the M10 verifier does. This is a verification
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


def _build_stack(factory) -> _Stack:
    """Wire the production pipeline over the isolated database (M13.36).

    Every layer is the real one: the M6 statistics manager, M7 persistence, M8
    device discovery, M9 connection tracking, M10 detection, M11 alerting and M12
    correlation, all fed by the M4 capture manager. The only non-production
    object is the sniffer, created per session by the factory, plus the session
    factory itself.
    """
    devices = DeviceDiscoveryManager()
    detection = _build_detection_engine(devices)
    alerts = AlertEngine(
        AlertService(session_factory=factory, resolvers=None, clock=CLOCK)
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
    )
    registry: list[FakeCaptureSniffer] = []
    interfaces = InterfaceManager(discovery=lambda: SAMPLE_INTERFACES)
    manager = CaptureManager(
        interface_manager=interfaces,
        sniffer_factory=_make_sniffer_factory(registry),
        pipeline=pipeline,
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


def _build_overrides(stack: _Stack, factory, db_engine) -> dict:
    """Return the dependency overrides that point the API at ``stack`` (M13.28).

    Each key is the *dependency function* a route declares in ``Depends``, so the
    route still resolves its collaborator through FastAPI and the wiring is the
    application's rather than the script's.
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
        # The lifecycle *write* path needs the engine the pipeline wrote through,
        # not the process-wide one (M13.28).
        get_alert_engine: lambda: stack.alerts,
        # The alert read service needs a *factory*, not a session (M13.28).
        get_alert_queries: lambda: AlertQueries(session_factory=factory),
    }


@contextmanager
def _serve(stack: _Stack, factory, db_engine) -> Generator[TestClient, None, None]:
    """Yield a client over the real application, wired to ``stack`` (M13.36).

    The environment is temporarily ``"test"`` so the lifespan skips ``init_db()``
    and never touches the developer's database, and every override is removed
    afterwards so nothing leaks into a later request.
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


def _get(client: TestClient, url: str, **params: Any):
    """GET a route and return the response, without asserting anything."""
    return client.get(url, params=params or None)


def _get_data(client: TestClient, url: str, **params: Any) -> dict:
    """GET a route, assert the standard envelope, and return ``data`` (M13.4)."""
    response = _get(client, url, **params)
    if response.status_code != 200:
        raise AssertionError(f"{url} -> {response.status_code}: {response.text[:200]}")
    body = response.json()
    if body.get("success") is not True:
        raise AssertionError(f"{url} did not report success: {body}")
    return body["data"]


def _count_of(payload: dict) -> int:
    """Return the number of rows a collection payload holds.

    The collection endpoints agree on ``count`` for the page and ``total`` for the
    whole match set (M13.24), with ``items`` only where the resource has no
    better name for its rows.
    """
    for key in ("count", "total"):
        value = payload.get(key)
        if isinstance(value, int):
            return value
    return 0
def _check_docs(client: TestClient, failures: list[str]) -> dict:
    """Verify the documented URLs and that every group is in the document (M13.27).

    ``/docs`` and ``/redoc`` are the interactive renderings and ``/openapi.json``
    is the machine-readable contract. All three are checked because M13.27 names
    all three, and the document is then walked for the M13 groups so a router
    that was built but never mounted is caught here rather than by a reader.
    """
    print("\n--- Documentation surface (M13.27) ---")
    expected_types = {
        "/docs": "text/html",
        "/redoc": "text/html",
        "/openapi.json": "application/json",
    }
    for url, content_type in expected_types.items():
        response = _get(client, url)
        served = response.headers.get("content-type", "")
        print(f"  {url:<16} status={response.status_code} type={served.split(';')[0]}")
        if response.status_code != 200:
            failures.append(f"{url} answered {response.status_code}, not 200 (M13.27)")
        elif content_type not in served:
            failures.append(f"{url} served {served!r}, expected {content_type}")

    document = _get(client, "/openapi.json").json()
    paths = document.get("paths") or {}
    print(f"  documented paths: {len(paths)}")
    for group in EXPECTED_GROUPS:
        prefix = f"{API}/{group}"
        matched = [
            path
            for path in paths
            if path == prefix or str(path).startswith(f"{prefix}/")
        ]
        marker = "ok " if matched else "MISSING"
        print(f"    [{marker}] {prefix:<26} {len(matched)} path(s)")
        if not matched:
            failures.append(f"the OpenAPI document lists no path under {prefix} (M13.27)")
    return document


def _check_envelopes(client: TestClient, failures: list[str]) -> None:
    """Verify the success and error envelopes and the common statuses (M13.4-M13.6).

    Four things are checked, each on a real request: a success carries
    ``success``/``message``/``data``; an unknown route is a ``404`` in the error
    envelope; an out-of-range page is a FastAPI ``422`` before any handler runs;
    and a wrong filter value is the controlled ``400`` the API documents.
    """
    print("\n--- Envelopes and status codes (M13.4/M13.5/M13.6/M13.24) ---")

    response = _get(client, f"{API}/statistics/traffic")
    body = response.json()
    shape = sorted(body)
    print(f"  success envelope keys  : {shape}")
    if body.get("success") is not True or "data" not in body or "message" not in body:
        failures.append("a successful response did not use the documented envelope")

    response = _get(client, f"{API}/not-a-real-route")
    body = response.json()
    print(f"  unknown route          : {response.status_code} {body.get('errors')}")
    if response.status_code != 404:
        failures.append("an unknown route did not answer 404 (M13.6)")
    if body.get("success") is not False or not body.get("errors"):
        failures.append("an unknown route did not use the documented error envelope")

    response = _get(client, f"{API}/packets", limit=0)
    print(f"  limit=0                : {response.status_code}")
    if response.status_code != 422:
        failures.append("an out-of-range page size was not a 422 (M13.24)")

    # An *enumerated* filter is validated: an unknown severity is a 400 rather
    # than a silently wider result set (M13.25).
    response = _get(client, f"{API}/alerts", severity="NOTASEVERITY")
    body = response.json()
    codes = [entry.get("code") for entry in body.get("errors", [])]
    print(f"  bad severity filter    : {response.status_code} {codes}")
    if response.status_code != 400 or "INVALID_FILTER" not in codes:
        failures.append("an unknown severity was not the controlled 400 (M13.25)")

    # An unusable timestamp is refused rather than dropped, because dropping it
    # would silently widen the window (M13.25/M13.26). The packet route takes
    # ``since``/``until``, not the ``start_time`` the milestone text sketches.
    response = _get(client, f"{API}/packets", since="not-a-time")
    print(f"  malformed since        : {response.status_code}")
    if response.status_code != 400:
        failures.append("a malformed timestamp was not a controlled 400 (M13.25)")

    # A protocol label is free-form, not an enumeration, so an unknown one selects
    # nothing. That is the truthful answer, and the property being checked is that
    # it is not converted into a valid protocol (M13.25).
    response = _get(client, f"{API}/packets", protocol="NOTAPROTOCOL")
    body = response.json()
    print(
        f"  unknown protocol label : {response.status_code} "
        f"total={body.get('data', {}).get('total')}"
    )
    if response.status_code != 200 or body["data"]["total"] != 0:
        failures.append("an unknown protocol label did not select nothing (M13.25)")


def _check_capture(client: TestClient, expected_packets: int, failures: list[str]) -> None:
    """Verify the M4 capture surface end to end (M13.7).

    The session itself already ran (that is how there is any data to read), so
    this checks what the API reports about it and exercises the controls: a
    second ``start`` while one is running, a ``stop`` when none is, an unknown
    interface and a down one. Each is a documented status rather than a guess.
    """
    print("\n--- Capture (M13.7) ---")

    interfaces = _get_data(client, f"{API}/capture/interfaces")
    names = [entry["name"] for entry in interfaces]
    print(f"  interfaces             : {names}")
    if names != [CAPTURE_INTERFACE, "Ethernet"]:
        failures.append(f"the interface listing returned {names}, expected both (M13.7)")

    selected = _get_data(client, f"{API}/capture/interface")
    print(f"  selected interface     : {selected['name']}")
    if selected["name"] != CAPTURE_INTERFACE:
        failures.append("the selected interface is not the one the session used (M13.7)")

    status = _get_data(client, f"{API}/capture/status")
    print(
        f"  status                 : {status['status']} "
        f"packets={status['packet_count']}"
    )
    if status["status"] != "stopped":
        failures.append("the capture session that ran is not reported as stopped (M13.7)")
    # The session counted the packets the sniffer emitted, which is the evidence
    # that a real capture ran rather than that a counter was seeded.
    processed = client.get(f"{API}/system/status").json()["data"]["capture"]
    if processed["processed_packet_count"] != expected_packets:
        failures.append(
            "the capture subsystem did not report the packets it processed "
            f"({processed['processed_packet_count']} of {expected_packets}) (M13.22)"
        )

    # A down interface is listed but refused, and an unknown one is refused with
    # its own code — the two are different failures (M13.7/M13.25).
    response = client.put(f"{API}/capture/interface", json={"name": "Ethernet"})
    codes = [entry.get("code") for entry in response.json().get("errors", [])]
    print(f"  select down interface  : {response.status_code} {codes}")
    if response.status_code != 400 or "INTERFACE_UNAVAILABLE" not in codes:
        failures.append("a down interface was not refused with INTERFACE_UNAVAILABLE")

    response = client.put(f"{API}/capture/interface", json={"name": "NoSuchNic"})
    codes = [entry.get("code") for entry in response.json().get("errors", [])]
    print(f"  select unknown nic     : {response.status_code} {codes}")
    if response.status_code != 400 or "INTERFACE_NOT_FOUND" not in codes:
        failures.append("an unknown interface was not refused with INTERFACE_NOT_FOUND")

    response = client.put(f"{API}/capture/interface", json={"name": ""})
    print(f"  select empty name      : {response.status_code}")
    if response.status_code != 422:
        failures.append("an empty interface name was not a 422 request error (M13.6)")

    # Start, a second start, then stop twice: the controls, with their conflicts.
    first = client.post(f"{API}/capture/start")
    second = client.post(f"{API}/capture/start")
    print(
        f"  start / start again    : {first.status_code} / {second.status_code}"
    )
    if first.status_code != 200:
        failures.append(f"capture did not start through the API ({first.status_code})")
    if second.status_code != 409:
        failures.append("a second capture session was not refused with a 409 (M13.6)")

    stopped = client.post(f"{API}/capture/stop")
    again = client.post(f"{API}/capture/stop")
    print(f"  stop / stop again      : {stopped.status_code} / {again.status_code}")
    if stopped.status_code != 200 or again.status_code != 409:
        failures.append("the capture stop controls did not report 200 then 409 (M13.7)")


def _check_data_groups(
    client: TestClient, expected_packets: int, failures: list[str]
) -> None:
    """Verify packets, statistics, devices, connections and detections (M13.8-M13.12).

    Each group is asserted against the number the pipeline actually produced, so
    an endpoint that returned a fixture — or nothing at all — cannot pass.
    """
    print("\n--- Packets, statistics, devices, connections, detections ---")

    packets = _get_data(client, f"{API}/packets")
    print(
        f"  packets                : count={packets['count']} total={packets['total']} "
        f"limit={packets['limit']} offset={packets['offset']} "
        f"has_more={packets.get('has_more')}"
    )
    if packets["total"] != expected_packets:
        failures.append(
            f"the packet API reports {packets['total']} packets, "
            f"the pipeline stored {expected_packets} (M13.8)"
        )
    if "payload" in (packets["packets"][0] if packets["packets"] else {}):
        failures.append("the packet API returned a payload, which M7 never stores (M13.8)")

    tcp_only = _get_data(client, f"{API}/packets", protocol="TCP")
    udp_only = _get_data(client, f"{API}/packets", protocol="UDP")
    print(f"  filtered tcp/udp       : {tcp_only['total']} / {udp_only['total']}")
    if tcp_only["total"] + udp_only["total"] != expected_packets:
        failures.append("the protocol filter did not partition the stored packets (M13.8)")

    page_one = _get_data(client, f"{API}/packets", limit=3, offset=0)
    page_two = _get_data(client, f"{API}/packets", limit=3, offset=3)
    first_ids = {row["id"] for row in page_one["packets"]}
    second_ids = {row["id"] for row in page_two["packets"]}
    print(f"  page 1 / page 2        : {sorted(first_ids)} / {sorted(second_ids)}")
    if first_ids & second_ids:
        failures.append("two pages of one query repeated a row (M13.24)")

    traffic = _get_data(client, f"{API}/statistics/traffic")
    protocols = _get_data(client, f"{API}/statistics/protocols")
    talkers = _get_data(client, f"{API}/statistics/top-talkers")
    ports = _get_data(client, f"{API}/statistics/ports")
    print(
        f"  statistics/traffic     : total_packets={traffic['total_packets']}"
    )
    print(
        f"  statistics/protocols   : "
        f"{[(row['protocol'], row['packets']) for row in protocols]}"
    )
    print(
        f"  statistics/top-talkers : "
        f"{[(row['key'], row['packets']) for row in talkers['sources'][:3]]}"
    )
    print(f"  statistics/ports       : {len(ports) if isinstance(ports, list) else ports}")
    if traffic["total_packets"] != expected_packets:
        failures.append("the statistics API does not agree with the packets captured (M13.9)")

    devices = _get_data(client, f"{API}/devices")
    observed = sorted(
        address for device in devices["devices"] for address in device["ip_addresses"]
    )
    print(f"  devices                : total={devices['total']} addresses={observed}")
    if SOURCE_IP not in observed:
        failures.append("the device API did not report the traffic's source (M13.10)")
    if "risk_score" in (devices["devices"][0] if devices["devices"] else {}):
        failures.append("the device API computed risk, which M13.10 forbids")

    single_device = _get_data(client, f"{API}/devices", ip=SOURCE_IP)
    print(f"  devices?ip=source      : total={single_device['total']}")
    if single_device["total"] < 1:
        failures.append("the device IP filter found nothing (M13.10)")

    connections = _get_data(client, f"{API}/connections")
    tcp_connections = _get_data(client, f"{API}/connections", protocol="TCP")
    print(
        f"  connections            : total={connections['count']} "
        f"tcp_only={tcp_connections['count']}"
    )
    if connections["count"] < 1:
        failures.append("the connection API reported no conversation (M13.11)")
    # The session held both TCP and UDP conversations, so the protocol filter must
    # *narrow* the set. Asserting equality would have been asserting that every
    # conversation was TCP, which is not what this scenario captured (M13.11).
    if not 0 < tcp_connections["count"] < connections["count"]:
        failures.append(
            "the connection protocol filter did not narrow the listing "
            f"({tcp_connections['count']} of {connections['count']}) (M13.11)"
        )

    detections = _get_data(client, f"{API}/detections")
    port_scan_only = _get_data(client, f"{API}/detections", rule_id="port_scan")
    rules = _get_data(client, f"{API}/detections/rules")
    print(
        f"  detections             : total={detections['total']} "
        f"rules={[row['rule_id'] for row in rules['rules']]}"
    )
    if detections["total"] < 1:
        failures.append("the detection API reported no finding (M13.12)")
    if port_scan_only["total"] < 1:
        failures.append("the detection rule filter found nothing (M13.12)")
    if detections["findings"] and "severity" in detections["findings"][0]:
        failures.append("a finding carried a severity, which M13.12 forbids")
def _check_aggregates(
    client: TestClient, expected_packets: int, failures: list[str]
) -> None:
    """Verify the dashboard summary and the analytics routes (M13.18/M13.19).

    The dashboard is checked for agreement with the routes it summarises rather
    than only for answering: it reports the same packet count the statistics
    route does, and the same alert and incident totals the collections do. That
    is the property that makes it an aggregate rather than a second source.
    """
    print("\n--- Dashboard and analytics (M13.18/M13.19) ---")

    summary = _get_data(client, f"{API}/dashboard/summary")
    unavailable = summary.get("unavailable_sections") or []
    print(f"  dashboard sections     : {sorted(k for k in summary if k != 'generated_at')}")
    print(f"  unavailable sections   : {unavailable}")
    if unavailable:
        failures.append(f"the dashboard reported unavailable sections: {unavailable} (M13.19)")

    dash_packets = summary["traffic"]["data"]["total_packets"]
    print(f"  dashboard packet count : {dash_packets}")
    if dash_packets != expected_packets:
        failures.append(
            "the dashboard's packet count disagrees with the statistics route (M13.19)"
        )

    alerts_total = summary["alerts"]["data"]["total"]
    incidents_total = summary["incidents"]["data"]["total"]
    print(
        f"  dashboard alerts/incidents: {alerts_total} / {incidents_total} "
        f"(risk={summary['incidents']['data'].get('highest_risk_score')})"
    )
    if alerts_total < 1 or incidents_total < 1:
        failures.append("the dashboard did not report the alerts and incident (M13.19)")

    traffic = _get_data(client, f"{API}/analytics/traffic")
    protocols = _get_data(client, f"{API}/analytics/protocols")
    devices = _get_data(client, f"{API}/analytics/devices")
    connections = _get_data(client, f"{API}/analytics/connections")
    threats = _get_data(client, f"{API}/analytics/threats")
    print(f"  analytics/traffic      : total_packets={traffic['total_packets']}")
    print(
        f"  analytics/protocols    : "
        f"{[(row['protocol'], row['packets']) for row in protocols['protocols']]}"
    )
    print(f"  analytics/devices      : total={devices['total']}")
    print(
        f"  analytics/connections  : tracked={connections['tracked']} "
        f"active={connections['active']} ranked={len(connections['top'])}"
    )
    print(
        f"  analytics/threats      : alerts={threats.get('alerts_total')} "
        f"incidents={threats.get('incidents_total')} "
        f"findings={threats.get('findings_retained')}"
    )
    if traffic["total_packets"] != expected_packets:
        failures.append("the analytics traffic view disagrees with the capture (M13.18)")
    if not threats.get("alerts_total"):
        failures.append("the analytics threat view reported no alert (M13.18)")


def _check_alerts_and_incidents(client: TestClient, failures: list[str]) -> None:
    """Verify alerts, evidence, incidents and their lifecycles (M13.13-M13.16).

    The reads come first, then the lifecycle verbs, then a re-read: the point of
    the last step is that a change made over HTTP is the change the *store* now
    holds, which is what "the route uses the service's rules" means in practice.
    """
    print("\n--- Alerts, evidence and incidents (M13.13-M13.16) ---")

    alerts = _get_data(client, f"{API}/alerts")
    if not alerts["alerts"]:
        failures.append("the alert API returned no alert from the captured traffic (M13.13)")
        return
    alert = alerts["alerts"][0]
    print(
        f"  alerts                 : total={alerts['total']} "
        f"has_more={alerts.get('has_more')} "
        f"first={alert['rule_id']}/{alert['severity']}/{alert['status']}"
    )
    # Two detectors fired from one source, so the listing holds both. The first
    # row is the newest, which is the internal sweep rather than the scan, so the
    # assertion is over the set rather than over position.
    titles = {row["title"] for row in alerts["alerts"]}
    if "Port Scan" not in titles:
        failures.append(f"the stored alerts are titled {sorted(titles)} (M13.13)")

    severity_filtered = _get_data(client, f"{API}/alerts", severity="high")
    status_filtered = _get_data(client, f"{API}/alerts", status="open")
    print(
        f"  alerts?severity=high   : {severity_filtered['total']} "
        f"| ?status=open: {status_filtered['total']}"
    )
    if severity_filtered["total"] < 1 or status_filtered["total"] < 1:
        failures.append("the alert severity/status filters found nothing (M13.13)")

    detail = _get_data(client, f"{API}/alerts/{alert['alert_id']}")
    # The detail view wraps the alert beside its evidence, so the alert's own
    # fields sit under ``alert`` rather than at the top level (M13.13).
    detail_alert = detail["alert"]
    print(
        f"  alert detail           : {detail_alert['alert_id']} "
        f"status={detail_alert['status']} evidence={len(detail['evidence'])}"
    )
    if detail_alert["alert_id"] != alert["alert_id"]:
        failures.append("the alert detail route returned a different alert (M13.13)")

    evidence = _get_data(client, f"{API}/alerts/{alert['alert_id']}/evidence")
    kinds = sorted(row["evidence_type"] for row in evidence["evidence"])
    print(f"  evidence               : count={evidence['count']} types={kinds}")
    if not evidence["evidence"]:
        failures.append("the stored alert carries no evidence (M13.14)")
    # Evidence references the resource rather than copying it, so no payload
    # travels with it (M13.14).
    if any("payload" in row for row in evidence["evidence"]):
        failures.append("evidence duplicated a packet payload (M13.14)")

    evidence_id = next(
        (
            row.get("evidence_id")
            for row in evidence["evidence"]
            if isinstance(row.get("evidence_id"), int)
        ),
        None,
    )
    if evidence_id is not None:
        one = _get_data(client, f"{API}/evidence/{evidence_id}")
        print(f"  evidence/{evidence_id}          : alert_id={one['alert_id']}")
        if one["alert_id"] != alert["alert_id"]:
            failures.append("an evidence record named a different owning alert (M13.14)")
    response = _get(client, f"{API}/evidence/99999999")
    if response.status_code != 404:
        failures.append("an unknown evidence id did not answer 404 (M13.14)")

    incidents = _get_data(client, f"{API}/incidents")
    if not incidents["incidents"]:
        failures.append("the incident API returned no incident from the alerts (M13.15)")
        return
    summary = incidents["incidents"][0]
    incident_id = summary["incident_id"]
    detail = _get_data(client, f"{API}/incidents/{incident_id}")
    open_only = _get_data(client, f"{API}/incidents/open")
    print(
        f"  incidents              : total={incidents['total']} "
        f"status={summary['status']} risk={summary['risk_score']} "
        f"({summary['risk_band']})"
    )
    print(
        f"  incident detail        : alerts={detail['alert_ids']} "
        f"rules={detail['rule_ids']} correlation_confidence="
        f"{detail['correlation_confidence']}"
    )
    if detail["risk_score"] != summary["risk_score"]:
        failures.append("the incident detail and listing disagree on the risk score (M13.15)")
    if summary["risk_band"] == "minimal":
        failures.append("the correlated incident was scored as minimal (M13.15)")
    if not detail["finding_ids"]:
        failures.append("the incident does not name the findings behind it (M13.15)")
    if "port_scan" not in detail["rule_ids"]:
        failures.append("the incident does not name the detector that raised it (M13.15)")
    if [row["incident_id"] for row in open_only["incidents"]] != [incident_id]:
        failures.append("the open-incident view does not match the listing (M13.15)")

    response = _get(client, f"{API}/incidents/does-not-exist")
    if response.status_code != 404:
        failures.append("an unknown incident id did not answer 404 (M13.15)")

    # -- lifecycle: the verbs must reach the service's rules (M13.13/M13.16) ----
    print("  -- lifecycle over HTTP --")
    changed = client.post(f"{API}/alerts/{alert['alert_id']}/acknowledge")
    reread = _get_data(client, f"{API}/alerts/{alert['alert_id']}")["alert"]
    print(
        f"  alert acknowledge      : {changed.status_code} "
        f"status now {reread['status']!r}"
    )
    if changed.status_code != 200 or reread["status"] != "acknowledged":
        failures.append("acknowledging an alert through the API did not persist (M13.13)")

    closed = client.post(f"{API}/alerts/{alert['alert_id']}/resolve")
    refused = client.post(f"{API}/alerts/{alert['alert_id']}/acknowledge")
    codes = [entry.get("code") for entry in refused.json().get("errors", [])]
    print(
        f"  resolve then re-acknowledge: {closed.status_code} then "
        f"{refused.status_code} {codes}"
    )
    if closed.status_code != 200:
        failures.append("resolving an acknowledged alert through the API failed (M13.13)")
    if refused.status_code != 409 or "INVALID_TRANSITION" not in codes:
        failures.append("a move out of a terminal alert state was not a 409 (M13.13)")

    moved = client.post(f"{API}/incidents/{incident_id}/investigate")
    listing = _get_data(client, f"{API}/incidents")
    print(
        f"  incident investigate   : {moved.status_code} "
        f"status now {listing['incidents'][0]['status']!r}"
    )
    if moved.status_code != 200 or listing["incidents"][0]["status"] != "investigating":
        failures.append("investigating an incident through the API did not persist (M13.16)")

    resolved = client.post(f"{API}/incidents/{incident_id}/resolve")
    reopened = client.post(f"{API}/incidents/{incident_id}/investigate")
    final = _get_data(client, f"{API}/incidents/{incident_id}")
    print(
        f"  resolve then reopen    : {resolved.status_code} then "
        f"{reopened.status_code} (status {final['status']!r})"
    )
    if resolved.status_code != 200:
        failures.append("resolving an incident through the API did not succeed (M13.16)")
    if reopened.status_code != 409:
        failures.append(
            "reopening a resolved incident was not refused by the M12 table (M13.16)"
        )
    if final["status"] != "resolved":
        failures.append("the refused transition changed the incident anyway (M13.16)")


def _check_application_surfaces(client: TestClient, failures: list[str]) -> None:
    """Verify reports, notifications, settings, system and baselines (M13.17-M13.23).

    The two refusals are checked as carefully as the successes: ``/baselines`` and
    ``POST /reports/generate`` answer ``501`` because the subsystem is missing,
    and an endpoint that invented data for them would be the failure M13.17 and
    M13.20 exist to prevent.
    """
    print("\n--- Reports, notifications, settings, system, baselines ---")

    reports = _get_data(client, f"{API}/reports")
    print(f"  reports                : total={reports['total']} limit={reports['limit']}")
    response = _get(client, f"{API}/reports/999999")
    print(f"  reports/999999          : {response.status_code}")
    if response.status_code != 404:
        failures.append("an unknown report id did not answer 404 (M13.20)")
    response = client.post(f"{API}/reports/generate")
    codes = [entry.get("code") for entry in response.json().get("errors", [])]
    print(f"  reports/generate       : {response.status_code} {codes}")
    if response.status_code != 501 or "FEATURE_NOT_IMPLEMENTED" not in codes:
        failures.append("report generation did not refuse with 501 (M13.20)")

    notifications = _get_data(client, f"{API}/notifications")
    print(
        f"  notifications          : total={notifications['total']} "
        f"has_more={notifications.get('has_more')}"
    )
    response = _get(client, f"{API}/notifications/999999")
    if response.status_code != 404:
        failures.append("an unknown notification id did not answer 404 (M13.23)")

    settings = _get_data(client, f"{API}/settings")
    keys = [entry["key"] for entry in settings["settings"]]
    print(
        f"  settings               : count={settings['count']} keys={keys} "
        f"mutable={settings['mutable_keys']} withheld={settings['internal_key_count']}"
    )
    if "api_key_sample" in keys:
        failures.append("a secret-named setting was listed, which M13.21 forbids")
    if settings["internal_key_count"] < 1:
        failures.append("the settings listing withheld nothing, though a secret exists")
    response = _get(client, f"{API}/settings/api_key_sample")
    print(f"  settings/secret key    : {response.status_code}")
    if response.status_code != 404:
        failures.append("a secret-named setting was readable by name (M13.21)")

    updated = client.put(
        f"{API}/settings", json={"values": {"default_theme": "light"}}
    )
    body = updated.json()
    print(
        f"  PUT settings           : {updated.status_code} "
        f"restart_required={body.get('data', {}).get('restart_required')}"
    )
    if updated.status_code != 200:
        failures.append("a valid settings change was not accepted (M13.21)")
    elif body["data"].get("restart_required") is not True:
        failures.append("a settings change did not report restart_required (M13.21)")
    rejected = client.put(f"{API}/settings", json={"values": {"default_theme": "neon"}})
    print(f"  PUT bad value          : {rejected.status_code}")
    if rejected.status_code != 400:
        failures.append("an out-of-range settings value was not a controlled 400 (M13.21)")

    status = _get_data(client, f"{API}/system/status")
    health = _get_data(client, f"{API}/system/health")
    info = _get_data(client, f"{API}/system/info")
    probes = {check["name"]: check["ok"] for check in health["checks"]}
    print(f"  system/health          : {health['status']} probes={probes}")
    print(
        f"  system/status          : {status['status']} "
        f"db={status['database']['dialect']} "
        f"services={[s['name'] for s in status['services']]}"
    )
    print(
        f"  system/info            : {info['app_name']} {info['app_version']} "
        f"env={info['environment']} routes={info['registered_route_count']}"
    )
    if health["status"] != "healthy":
        failures.append(f"the health probe reported {health['status']} (M13.22)")
    if not all(probes.values()):
        failures.append(f"a health probe failed: {probes} (M13.22)")
    if status["database"]["reachable"] is not True:
        failures.append("the system status did not reach the database (M13.22)")
    # Nothing internal is exposed: no URL, no credential-shaped field (M13.30).
    flattened = str(info).lower()
    for forbidden in ("password", "secret", "token", "api_key", "://"):
        if forbidden in flattened:
            failures.append(f"the system info payload exposed {forbidden!r} (M13.30)")
    if not info.get("registered_route_count"):
        failures.append("the system info could not count the documented routes (M13.22)")

    for url in (f"{API}/baselines", f"{API}/baselines/mac:AA:BB:CC:DD:EE:FF"):
        response = _get(client, url)
        codes = [entry.get("code") for entry in response.json().get("errors", [])]
        print(f"  {url.split('/api/v1/')[1]:<24} : {response.status_code} {codes}")
        if response.status_code != 501 or "FEATURE_NOT_IMPLEMENTED" not in codes:
            failures.append(
                f"{url} did not refuse with 501 while the baseline engine is "
                "unimplemented (M13.17)"
            )
def _run_sample_checks(
    client: TestClient, expected_packets: int, failures: list[str]
) -> None:
    """Run every sample-mode check against one wired client (M13.36).

    The order is deliberate. Reads come before the lifecycle verbs so the counts
    the earlier checks assert cannot have been changed by a later one, and the
    aggregates are checked while the stores are still in the state capture left
    them.
    """
    _check_docs(client, failures)
    _check_envelopes(client, failures)
    _check_capture(client, expected_packets, failures)
    _check_data_groups(client, expected_packets, failures)
    _check_aggregates(client, expected_packets, failures)
    _check_alerts_and_incidents(client, failures)
    _check_application_surfaces(client, failures)


def run_sample_mode() -> int:
    """Drive the pipeline, then verify the REST API over its real data (M13.36)."""
    workdir = Path(tempfile.mkdtemp(prefix="netwatch_m13_"))
    db_path = workdir / "verify_m13.db"
    database, factory = _connect_database(db_path)
    failures: list[str] = []
    try:
        _seed_rule_catalogue(factory)
        stack = _build_stack(factory)
        packets = _scan_packets(PORT_SCAN_THRESHOLD + 2) + _sweep_packets(
            INTERNAL_SCAN_THRESHOLD + 2
        )

        print("=" * _BANNER_WIDTH)
        print("M13 SAMPLE MODE - the REST API served over real backend data")
        print("=" * _BANNER_WIDTH)
        print(f"database : {db_path}")
        print(
            f"packets  : {len(packets)} driven through the real capture path "
            "(fake sniffer, real pipeline)"
        )

        stack.capture(packets)
        findings = stack.detection.get_findings()
        incidents = stack.correlation.get_incidents()
        print(
            f"after capture: processed={stack.pipeline.get_processed_count()} "
            f"findings={len(findings)} incidents={len(incidents)}"
        )
        print(
            "stage errors: "
            f"processing={stack.pipeline.get_processing_error_count()} "
            f"persistence={stack.pipeline.get_persistence_error_count()} "
            f"statistics={stack.pipeline.get_statistics_error_count()} "
            f"devices={stack.pipeline.get_device_error_count()} "
            f"connections={stack.pipeline.get_connection_error_count()} "
            f"detection={stack.pipeline.get_detection_error_count()} "
            f"alerts={stack.pipeline.get_alert_error_count()} "
            f"correlation={stack.pipeline.get_correlation_error_count()}"
        )
        if not incidents:
            failures.append(
                "the pipeline produced no incident, so the incident API has "
                "nothing real to serve (M12.25)"
            )

        with _serve(stack, factory, database) as client:
            _run_sample_checks(client, len(packets), failures)
    finally:
        database.dispose()
        shutil.rmtree(workdir, ignore_errors=True)
    return _report_failures(failures, mode="sample")


#: The live-mode paths whose *wiring* is verified over real HTTP. Live mode does
#: not assert row counts: it runs against the configured database, which may
#: legitimately be empty, so the claim it makes is that the routes answer in the
#: documented envelope rather than that a particular capture happened.
LIVE_PATHS: tuple[str, ...] = (
    f"{API}/capture/interfaces",
    f"{API}/capture/status",
    f"{API}/packets",
    f"{API}/statistics/traffic",
    f"{API}/statistics/protocols",
    f"{API}/statistics/top-talkers",
    f"{API}/devices",
    f"{API}/connections",
    f"{API}/detections",
    f"{API}/alerts",
    f"{API}/incidents",
    f"{API}/incidents/open",
    f"{API}/analytics/traffic",
    f"{API}/analytics/protocols",
    f"{API}/analytics/devices",
    f"{API}/analytics/connections",
    f"{API}/analytics/threats",
    f"{API}/dashboard/summary",
    f"{API}/reports",
    f"{API}/notifications",
    f"{API}/settings",
    f"{API}/system/status",
    f"{API}/system/health",
    f"{API}/system/info",
)


def _wait_for_server(client: httpx.Client, *, attempts: int = 60) -> bool:
    """Poll the OpenAPI document until the server answers, or give up (M13.36).

    ``attempts`` at ~0.25s each gives the lifespan about fifteen seconds to
    finish, which is ample for a local application and short enough that a
    failure to bind is reported rather than waited on.
    """
    for _ in range(attempts):
        try:
            response = client.get("/openapi.json")
            if response.status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    return False


def _free_port(host: str, requested: int) -> int:
    """Return ``requested`` if it can be bound, else an unused port.

    Binding port 0 and reading back the assignment is how the OS picks a free
    port; the socket is closed immediately, so the window in which another
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


def run_live_mode(host: str, port: int) -> int:
    """Start the application under uvicorn and verify it over real HTTP (M13.36).

    This is the mode M13.36 describes literally: a running server, real sockets
    and the documented URLs. It reads only — no capture is started and nothing is
    written — so it is safe to point at a working installation.
    """
    # Imported here so sample mode, which never binds a socket, does not need it.
    import uvicorn

    failures: list[str] = []
    chosen = _free_port(host, port)
    config = uvicorn.Config(app, host=host, port=chosen, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    print("=" * _BANNER_WIDTH)
    print("M13 LIVE MODE - the running application over real HTTP")
    print("=" * _BANNER_WIDTH)
    print(f"base url : http://{host}:{chosen}")
    if chosen != port:
        print(f"note     : port {port} was busy, so {chosen} was used")
    print("database : the configured one; this mode only reads")

    client = httpx.Client(base_url=f"http://{host}:{chosen}", timeout=10.0)
    try:
        if not _wait_for_server(client):
            failures.append(
                f"the application did not answer on http://{host}:{chosen} within "
                "the startup window"
            )
            return _report_failures(failures, mode="live")

        print("\n--- Documentation surface (M13.27) ---")
        for url, content_type in (
            ("/docs", "text/html"),
            ("/redoc", "text/html"),
            ("/openapi.json", "application/json"),
        ):
            response = client.get(url)
            served = response.headers.get("content-type", "").split(";")[0]
            print(f"  {url:<16} status={response.status_code} type={served}")
            if response.status_code != 200 or content_type not in served:
                failures.append(f"{url} did not answer as {content_type} (M13.27)")

        document = client.get("/openapi.json").json()
        paths = document.get("paths") or {}
        print(f"  documented paths: {len(paths)}")
        for group in EXPECTED_GROUPS:
            prefix = f"{API}/{group}"
            if not any(str(path).startswith(prefix) for path in paths):
                failures.append(f"the document lists no path under {prefix} (M13.27)")

        print("\n--- Read-only route wiring (M13.7-M13.23) ---")
        for path in LIVE_PATHS:
            response = client.get(path)
            try:
                body = response.json()
            except ValueError:
                failures.append(f"{path} did not return JSON")
                print(f"  {path:<34} {response.status_code} (not JSON)")
                continue
            rows = ""
            if isinstance(body.get("data"), dict):
                data = body["data"]
                count = _count_of(data)
                if count:
                    rows = f" count={count}"
            print(f"  {path:<34} {response.status_code}{rows}")
            if response.status_code != 200:
                failures.append(f"{path} answered {response.status_code}, not 200")
            elif body.get("success") is not True:
                failures.append(f"{path} did not use the success envelope (M13.4)")

        # The error envelope, over a real socket (M13.5).
        response = client.get(f"{API}/not-a-real-route")
        body = response.json()
        print(f"  {API}/not-a-real-route      {response.status_code} {body.get('errors')}")
        if response.status_code != 404 or body.get("success") is not False:
            failures.append("an unknown route did not answer 404 in the envelope")
    finally:
        client.close()
        server.should_exit = True
        thread.join(timeout=10.0)
    return _report_failures(failures, mode="live")


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


def main() -> int:
    """Parse arguments and dispatch to the selected mode (M13.36)."""
    parser = argparse.ArgumentParser(
        description="Verify the M13 REST API over real backend data (M13.36)."
    )
    parser.add_argument(
        "mode",
        nargs="?",
        default="sample",
        choices=("sample", "live"),
        help="sample = isolated pipeline + API (default), live = a running server",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Live-mode bind address")
    parser.add_argument(
        "--port", type=int, default=8011, help="Live-mode port (a free one is chosen if busy)"
    )
    args = parser.parse_args()

    if args.mode == "live":
        return run_live_mode(args.host, args.port)
    return run_sample_mode()


if __name__ == "__main__":
    raise SystemExit(main())
