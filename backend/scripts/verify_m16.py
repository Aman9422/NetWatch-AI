"""M16 verification script — the analytics layer over real backend data (M16.18).

Two modes:

  sample  (default)  Drive controlled packets through the *real* pipeline over an
                     isolated temporary SQLite database, then serve the real
                     FastAPI application (``app.main:app``) through a TestClient
                     whose dependencies are overridden to that very stack. Every
                     analytics response below is therefore produced by the
                     production routes reading state the production capture path
                     wrote — no mock, no fixture, no hand-built payload.
  live               Start the application under uvicorn on a loopback port and
                     issue real HTTP requests to it, to confirm the five
                     analytics URLs answer outside the in-process test client.
                     Requires the configured database to exist and be initialised.

What it verifies, against the M16 completion criteria:

  * all five routes answer in the M13 envelope and carry a resolved ``period``
    (M16.11/M16.7);
  * the window is ``[since, until)``: a bound on the newest stored packet
    includes it as ``since`` and excludes it as ``until`` (M16.7/M13.26);
  * the persisted blocks agree with what the pipeline actually wrote — packet
    counts, byte sums, the protocol breakdown and the alert totals (M16.2-M16.6);
  * an empty window is an *available* section holding zeroes, with no timestamps
    invented, which is the opposite answer from an unreadable one (M16.8);
  * a window that cannot be honoured is refused with a ``400`` naming the reason
    — inverted, too long, an unknown bucket, or a bucket producing too many
    points — rather than being silently narrowed (M16.7);
  * results are bounded: ``limit`` is capped at the documented ceiling, a
    requested bucket that would overflow the point ceiling is refused, and the
    series never exceeds the bucket ceiling (M16.2/M16.7);
  * rankings reorder with ``by`` and are total (name tie-break), and protocol
    shares are taken against the window's own total (M16.2/M16.3);
  * findings, alerts and incidents stay three distinct things on the threat
    route, and the stored alert vocabularies sum to the stored total (M16.6);
  * the page size, the enum filters and the malformed-timestamp path behave as
    M13 documented, so M13's conventions are preserved (M16.11).

The one substitution in sample mode is the sniffer, which is dispensed with
entirely: the packets are handed to :meth:`~app.services.packet_pipeline.PacketPipeline.process`,
which is the seam the capture callback itself calls. Normalization, statistics,
persistence, device discovery, connection tracking, detection, alerting and
correlation all run for real. The database is a throwaway file under the OS temp
directory, created and removed by this script, so running it never touches the
developer's ``netwatch.db``.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\verify_m16.py
    & ".venv\\Scripts\\python.exe" scripts\\verify_m16.py live --port 8016
"""

from __future__ import annotations

import argparse
import shutil
import socket
import sys
import tempfile
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
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
from app.analytics.metrics import MAX_GROUPS  # noqa: E402
from app.analytics.window import (  # noqa: E402
    BUCKET_SIZES,
    DEFAULT_WINDOW_SECONDS,
    MAX_BUCKETS,
    MAX_WINDOW_SECONDS,
)
from app.api.v1.analytics import DEFAULT_TOP_LIMIT, MAX_TOP_LIMIT  # noqa: E402
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
from app.services.capture_manager import get_capture_manager  # noqa: E402
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

#: The five routes M16 owns (M16.11), so a loop over them cannot drift from the
#: list the closure criteria name.
ANALYTICS_ROUTES: tuple[str, ...] = (
    "traffic",
    "protocols",
    "devices",
    "connections",
    "threats",
)

#: Lab detection thresholds, so a handful of packets exercises the real rules
#: quickly. This is a verification configuration, not the shipped default (M10.7).
PORT_SCAN_THRESHOLD = 5
INTERNAL_SCAN_THRESHOLD = 5

#: One source, a public scan target and a private sweep target — the pair of
#: detectors that the correlation layer groups into one ``scan_sequence`` incident.
SOURCE_IP = "192.168.1.10"
SECOND_SOURCE_IP = "192.168.1.11"
PUBLIC_DESTINATION = "8.8.8.8"
SWEEP_PREFIX = "192.168.1."
SWEEP_FIRST_HOST = 30

#: The alert and correlation layers use the real wall clock, because the packets
#: are dated by the pipeline from the clock as they arrive. Sharing one clock
#: keeps "now" consistent between the layers a request reads back.
CLOCK = time.time

#: How far back the driven packets are dated, in seconds. Long enough that the
#: default one-hour window still spans them, short enough that they are clearly
#: "recent" rather than at the window's edge.
_PACKET_BACKDATE_SECONDS = 1800.0

#: The natural-language labels every analytics breakdown uses for the three
#: states of a value. Named here so the checks read as sentences.
AVAILABLE_AND_EMPTY = "an available section holding zeroes"

#: The five routes in live mode. Live mode asserts *wiring* over real HTTP, not
#: row counts: the configured database may legitimately be empty, so the claim is
#: that the documented URLs answer in the documented envelope (M16.11).
LIVE_PATHS: tuple[str, ...] = tuple(
    f"{API}/analytics/{name}" for name in ANALYTICS_ROUTES
)
def _iso_from_epoch(epoch_seconds: float) -> str:
    """Render epoch seconds as the ISO-8601 UTC string the API accepts.

    M13.26 is the convention: ISO-8601 with an explicit ``+00:00`` offset, which
    is what every query filter and every response field uses.
    """
    return datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc).isoformat()


def _epoch_of(value: str) -> float:
    """Parse an ISO-8601 instant the API returned into epoch seconds.

    ``fromisoformat`` handles the ``+00:00`` offset the API emits, so a timestamp
    read from a response can be turned back into a bound without guessing at its
    format.
    """
    return datetime.fromisoformat(value).timestamp()


def _connect_database(db_path: Path):
    """Create the isolated SQLite database and a session factory (M16.18).

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
    """Populate ``detection_rules``, which the alert table references (M11.9).

    The alert table has a foreign key into the seeded rule catalogue, so the
    catalogue must exist before the pipeline can store an alert. The same rows the
    M13 verifier seeds are written, so the two scripts describe the same store.
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


@dataclass
class _Stack:
    """The live application, wired end to end over the isolated database.

    Holding the collaborators rather than re-deriving them is what lets the
    dependency overrides hand the API the *same* objects the pipeline fed, so an
    analytics response can only be correct if the pipeline really wrote what the
    route reads. That is the property M16.18's "real backend data" asks for.
    """

    pipeline: PacketPipeline
    statistics: TrafficStatisticsManager
    devices: DeviceDiscoveryManager
    connections: ConnectionTracker
    detection: DetectionEngine
    alerts: AlertEngine
    correlation: CorrelationEngine

    def capture(self, packets: list[Any], captured_at: float) -> None:
        """Drive ``packets`` through the real pipeline, dated at ``captured_at``.

        ``captured_at`` is passed explicitly so every driven packet shares one
        instant: M16's window checks need to know exactly where the stored rows
        sit relative to a bound, and a wall clock sampled per packet would make
        the last packet's instant unpredictable.
        """
        for packet in packets:
            self.pipeline.process(packet, captured_at)
        self.pipeline.flush_persistence()
        self.pipeline.flush_connections()


def _build_stack(factory) -> _Stack:
    """Wire the production pipeline over the isolated database (M16.18).

    Every layer is the real one: the M6 statistics manager, M7 persistence, M8
    device discovery, M9 connection tracking, M10 detection, M11 alerting and M12
    correlation, fed by the real :class:`~app.services.packet_pipeline.PacketPipeline`.
    The only substitutions are the session factory and the rates source.
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
        risk_persistence=IncidentRiskWriter(factory),
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
    return _Stack(
        pipeline=pipeline,
        statistics=statistics,
        devices=devices,
        connections=connections,
        detection=detection,
        alerts=alerts,
        correlation=correlation,
    )


def _build_overrides(stack: _Stack, factory, db_engine) -> dict:
    """Return the dependency overrides that point the API at ``stack`` (M13.28).

    Each key is the *dependency function* a route declares in ``Depends``, so the
    route still resolves its collaborator through FastAPI and the wiring is the
    application's rather than the script's. The analytics service takes six of
    them, which is why every one below is listed even when only the analytics
    routes are exercised: a missing override would silently point a route at the
    developer's database or at a hardware interface this machine may not have.
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

    interfaces = InterfaceManager(discovery=lambda: [])

    return {
        get_db: db_override,
        get_statistics_manager: lambda: stack.statistics,
        get_device_manager: lambda: stack.devices,
        get_connection_tracker: lambda: stack.connections,
        get_detection_engine: lambda: stack.detection,
        get_correlation_engine: lambda: stack.correlation,
        get_alert_engine: lambda: stack.alerts,
        get_alert_queries: lambda: AlertQueries(session_factory=factory),
        get_interface_manager: lambda: interfaces,
    }


@contextmanager
def _serve(stack: _Stack, factory, db_engine) -> Generator[TestClient, None, None]:
    """Yield a client over the real application, wired to ``stack`` (M16.18).

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


def _error_codes(response) -> list[str]:
    """Return the error codes an error envelope carries (M13.5)."""
    try:
        body = response.json()
    except ValueError:
        return []
    return [entry.get("code") for entry in body.get("errors", [])]


def _stored_of(data: dict) -> dict:
    """Return the persisted block of an analytics payload, or an empty dict."""
    section = data.get("stored") or data.get("windowed") or {}
    inner = section.get("data")
    return inner if isinstance(inner, dict) else {}


def _section_of(data: dict) -> dict:
    """Return the persisted *section* (with its availability flags)."""
    section = data.get("stored") or data.get("windowed") or {}
    return section if isinstance(section, dict) else {}


def _scan_packets(count: int, source: str) -> list[Any]:
    """Return ``count`` raw SYNs from one source across distinct ports (M10.8)."""
    return [
        Ether(src="AA:BB:CC:DD:EE:FF", dst="22:33:44:55:66:77")
        / IP(src=source, dst=PUBLIC_DESTINATION)
        / TCP(sport=52000, dport=4000 + index, flags="S")
        for index in range(count)
    ]


def _sweep_packets(count: int, source: str) -> list[Any]:
    """Return ``count`` raw UDP attempts to distinct private hosts (M10.9)."""
    return [
        Ether(src="AA:BB:CC:DD:EE:FF", dst="22:33:44:55:66:77")
        / IP(src=source, dst=f"{SWEEP_PREFIX}{SWEEP_FIRST_HOST + index}")
        / UDP(sport=53000, dport=53)
        for index in range(count)
    ]
def _naive_utc(epoch_seconds: float) -> datetime:
    """Convert epoch seconds to the naive UTC datetime the stores persist."""
    return datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc).replace(
        tzinfo=None
    )


def _expected_packets(factory, since: float, until: float) -> tuple[int, int]:
    """Return ``(packets, bytes)`` in ``[since, until)``, read from the table.

    This is deliberately a *direct* read rather than a second call to the
    analytics layer: comparing the route against itself would prove nothing. The
    expectation comes from the same rows through SQLAlchemy, so the two agree only
    if the analytics SQL is right.
    """
    from app.models.packet import Packet
    from sqlalchemy import func, select

    session = factory()
    try:
        statement = (
            select(
                func.count(),
                func.coalesce(func.sum(Packet.packet_length), 0),
            )
            .where(Packet.timestamp >= _naive_utc(since))
            .where(Packet.timestamp < _naive_utc(until))
        )
        row = session.execute(statement).one()
        return int(row[0] or 0), int(row[1] or 0)
    finally:
        session.close()


def _expected_alerts(factory, since: float, until: float) -> int:
    """Return how many alert rows were created in ``[since, until)``."""
    from app.models.alert import Alert
    from sqlalchemy import func, select

    session = factory()
    try:
        statement = (
            select(func.count())
            .where(Alert.created_at >= _naive_utc(since))
            .where(Alert.created_at < _naive_utc(until))
        )
        return int(session.scalar(statement) or 0)
    finally:
        session.close()


def _check_routes_and_period(client: TestClient, failures: list[str]) -> None:
    """Verify all five routes answer in the envelope and carry a period (M16.11).

    The period is checked field by field because every persisted block on the same
    response is only interpretable if those fields are present and coherent: a
    window whose ``buckets`` disagrees with its length and bucket size would make
    every series below it unreadable.
    """
    print("\n--- The five routes and their period (M16.11/M16.7) ---")

    for name in ANALYTICS_ROUTES:
        response = _get(client, f"{API}/analytics/{name}")
        body = response.json()
        period = body.get("data", {}).get("period") or {}
        print(
            f"  analytics/{name:<12} status={response.status_code} "
            f"since={period.get('since')} until={period.get('until')} "
            f"bucket={period.get('bucket_seconds')}s points={period.get('buckets')} "
            f"defaulted={period.get('defaulted')}"
        )
        if response.status_code != 200:
            failures.append(f"analytics/{name} answered {response.status_code} (M16.11)")
            continue
        if body.get("success") is not True or "data" not in body:
            failures.append(f"analytics/{name} did not use the M13 envelope (M16.11)")
            continue
        if not period:
            failures.append(f"analytics/{name} carried no period (M16.7)")
            continue
        if period.get("defaulted") is not True:
            failures.append(
                f"analytics/{name} did not report its defaulted one-hour window "
                "(M16.7)"
            )
        seconds = period.get("seconds")
        if not isinstance(seconds, (int, float)) or abs(
            seconds - DEFAULT_WINDOW_SECONDS
        ) > 2.0:
            failures.append(
                f"analytics/{name} defaulted to {seconds}s, not the documented "
                f"{DEFAULT_WINDOW_SECONDS}s (M16.7)"
            )
        bucket = period.get("bucket_seconds")
        if bucket not in BUCKET_SIZES:
            failures.append(
                f"analytics/{name} resolved to an undocumented bucket of {bucket}s "
                f"(M16.7)"
            )
        if not isinstance(period.get("buckets"), int) or period["buckets"] > MAX_BUCKETS:
            failures.append(
                f"analytics/{name} listed {period.get('buckets')} points, over the "
                f"{MAX_BUCKETS} ceiling (M16.7)"
            )


def _stored_bounds(client: TestClient) -> tuple[float, float] | None:
    """Return the persisted instants of the driven traffic, in epoch seconds.

    The bounds are read from the API's own ``first_timestamp``/``last_timestamp``
    rather than assumed, so the window checks below are built on what the store
    really holds. That is what makes them a check of the *window rule* rather than
    of this script's arithmetic.
    """
    data = _get_data(client, f"{API}/analytics/traffic")
    stored = _stored_of(data)
    first, last = stored.get("first_timestamp"), stored.get("last_timestamp")
    if not first or not last:
        return None
    return _epoch_of(first), _epoch_of(last)


def _check_stored_agreement(
    client: TestClient, factory, bounds: tuple[float, float], failures: list[str]
) -> None:
    """Verify the persisted traffic agrees with the rows the pipeline wrote (M16.2).

    The comparison is against a direct SQL read of the same table, so the route is
    being checked rather than restated. The byte total is compared as well as the
    count because a query that grouped or filtered wrongly would usually still
    return the right number of *rows* while summing the wrong lengths.
    """
    print("\n--- Persisted traffic against the store (M16.2) ---")
    first, last = bounds
    since = first - 1.0
    until = last + 1.0
    expected_packets, expected_bytes = _expected_packets(factory, since, until)

    data = _get_data(
        client,
        f"{API}/analytics/traffic",
        since=_iso_from_epoch(since),
        until=_iso_from_epoch(until),
    )
    stored = _stored_of(data)
    period = data["period"]
    print(
        f"  window      : {stored.get('total_packets')} packet(s), "
        f"{stored.get('total_bytes')} byte(s)"
    )
    print(
        f"  expected    : {expected_packets} packet(s), {expected_bytes} byte(s) "
        "from the packets table"
    )
    print(
        f"  first/last  : {stored.get('first_timestamp')} / "
        f"{stored.get('last_timestamp')}"
    )
    print(
        f"  average     : {stored.get('average_packet_bytes')} B/packet "
        f"| distinct protocols={stored.get('distinct_protocols')}"
    )
    if stored.get("total_packets") != expected_packets:
        failures.append(
            f"the stored traffic block reports {stored.get('total_packets')} "
            f"packets, the table holds {expected_packets} in that window (M16.2)"
        )
    if stored.get("total_bytes") != expected_bytes:
        failures.append(
            f"the stored traffic block sums {stored.get('total_bytes')} bytes, "
            f"the table holds {expected_bytes} (M16.2)"
        )
    if period.get("defaulted") is not False:
        failures.append("an explicit window was reported as defaulted (M16.7)")
    if data.get("stored_packet_count") != expected_packets:
        failures.append(
            "the M13 stored_packet_count did not mirror the stored block (M16.2)"
        )
    # No stored packet means no size and no instant: ``null`` rather than zero.
    if expected_packets and stored.get("average_packet_bytes") is None:
        failures.append("a non-empty window reported no average packet size (M16.2)")
    if not expected_packets and stored.get("first_timestamp") is not None:
        failures.append("an empty window invented a first timestamp (M16.8)")


def _check_window_is_half_open(
    client: TestClient, bounds: tuple[float, float], failures: list[str]
) -> None:
    """Verify ``since`` is inclusive and ``until`` exclusive (M16.7/M13.26).

    The boundary is the newest stored instant, which is the one value that can
    distinguish the two conventions: including it as ``since`` must select the
    traffic, and excluding it as ``until`` must select nothing.
    """
    print("\n--- The window is [since, until) (M16.7/M13.26) ---")
    _first, last = bounds

    inclusive = _get_data(
        client,
        f"{API}/analytics/traffic",
        since=_iso_from_epoch(last),
        until=_iso_from_epoch(last + 5.0),
    )
    exclusive = _get_data(
        client,
        f"{API}/analytics/traffic",
        since=_iso_from_epoch(last - 5.0),
        until=_iso_from_epoch(last),
    )
    included = _stored_of(inclusive).get("total_packets")
    excluded = _stored_of(exclusive).get("total_packets")
    print(f"  since=<last> : {included} packet(s) (last instant is included)")
    print(f"  until=<last> : {excluded} packet(s) (last instant is excluded)")
    if not included:
        failures.append(
            "a window whose `since` is the newest stored instant selected nothing, "
            "so `since` is not inclusive (M16.7)"
        )
    if excluded:
        failures.append(
            f"a window whose `until` is the newest stored instant selected "
            f"{excluded} packet(s), so `until` is not exclusive (M16.7)"
        )


def _check_empty_window(
    client: TestClient, bounds: tuple[float, float], failures: list[str]
) -> None:
    """Verify an empty window is available and full of zeroes, not absent (M16.8).

    This is the distinction M16.8 exists for: "the store holds nothing in this
    window" and "the store could not be read" are different answers, and the
    first must not look like the second.
    """
    print("\n--- An empty window is available, not unavailable (M16.8) ---")
    first, _last = bounds
    since = first - 7200.0
    params = {
        "since": _iso_from_epoch(since),
        "until": _iso_from_epoch(since + 600.0),
    }

    for name, section_name in (
        ("traffic", "stored"),
        ("protocols", "stored"),
        ("connections", "stored"),
        ("threats", "stored"),
    ):
        data = _get_data(client, f"{API}/analytics/{name}", **params)
        section = data.get(section_name) or {}
        payload = section.get("data") or {}
        count = payload.get("total", payload.get("total_packets", 0))
        print(
            f"  analytics/{name:<12} available={section.get('available')} "
            f"error={section.get('error')!r} rows={count}"
        )
        if section.get("available") is not True:
            failures.append(
                f"an empty window made analytics/{name} unavailable "
                f"({section.get('error')!r}), which conflates empty with unreadable "
                "(M16.8)"
            )
        if section.get("error") is not None:
            failures.append(
                f"an available analytics/{name} section carried an error (M16.8)"
            )
        if count:
            failures.append(
                f"an empty window reported {count} row(s) on analytics/{name} "
                "(M16.8)"
            )

    # The device window reads the in-process registry instead of a table, so it is
    # checked too: it must still answer, and answer with the registry's own count.
    devices = _get_data(client, f"{API}/analytics/devices", **params)
    windowed = devices.get("windowed") or {}
    print(
        f"  analytics/devices windowed available={windowed.get('available')} "
        f"in_period={(windowed.get('data') or {}).get('total')}"
    )
    if windowed.get("available") is not True:
        failures.append(
            "the device window was unavailable, though it reads no table (M16.8)"
        )
    if (windowed.get("data") or {}).get("total"):
        failures.append(
            "a window two hours before the traffic listed devices in it (M16.4)"
        )
def _expected_connections(factory, since: float, until: float) -> int:
    """Return how many conversation rows began in ``[since, until)`` (M16.5)."""
    from app.models.connection import NetworkConnection
    from sqlalchemy import func, select

    session = factory()
    try:
        statement = (
            select(func.count())
            .where(NetworkConnection.start_time >= _naive_utc(since))
            .where(NetworkConnection.start_time < _naive_utc(until))
        )
        return int(session.scalar(statement) or 0)
    finally:
        session.close()


def _check_refusals(client: TestClient, failures: list[str]) -> None:
    """Verify an unhonourable window is refused with a reason (M16.7/M16.11).

    Each case is a request the API cannot answer as asked. The property under test
    is that it says so — a ``400`` carrying ``INVALID_FILTER`` — rather than
    quietly answering a narrower or wider question, which would be worse than an
    error because it would look like a valid answer.
    """
    print("\n--- A window that cannot be honoured is refused (M16.7) ---")
    now = time.time()
    cases: list[tuple[str, dict[str, Any]]] = [
        (
            "inverted (since > until)",
            {
                "since": _iso_from_epoch(now),
                "until": _iso_from_epoch(now - 600.0),
            },
        ),
        (
            "empty (since == until)",
            {
                "since": _iso_from_epoch(now),
                "until": _iso_from_epoch(now),
            },
        ),
        (
            f"longer than {int(MAX_WINDOW_SECONDS / 86400)} days",
            {
                "since": _iso_from_epoch(now - MAX_WINDOW_SECONDS - 60.0),
                "until": _iso_from_epoch(now),
            },
        ),
        (
            "undocumented bucket size",
            {
                "since": _iso_from_epoch(now - 600.0),
                "until": _iso_from_epoch(now),
                "bucket_seconds": 7,
            },
        ),
        (
            f"a 10s bucket over an hour (>{MAX_BUCKETS} points)",
            {
                "since": _iso_from_epoch(now - 3600.0),
                "until": _iso_from_epoch(now),
                "bucket_seconds": 10,
            },
        ),
        ("malformed since", {"since": "not-a-time"}),
        ("malformed until", {"until": "2026-13-45T99:99:99Z"}),
    ]

    for label, params in cases:
        response = _get(client, f"{API}/analytics/traffic", **params)
        codes = _error_codes(response)
        print(f"  {label:<38} -> {response.status_code} {codes}")
        if response.status_code != 400 or "INVALID_FILTER" not in codes:
            failures.append(
                f"{label!r} was not refused with a controlled 400/INVALID_FILTER "
                f"(got {response.status_code} {codes}) (M16.7)"
            )

    # The bounded parameters are FastAPI's own validation, which runs before a
    # handler does, so they are 422 rather than the controlled 400 (M13.24).
    for label, params in (
        ("limit=0", {"limit": 0}),
        (f"limit={MAX_TOP_LIMIT + 1}", {"limit": MAX_TOP_LIMIT + 1}),
        ("by=notametric", {"by": "notametric"}),
        ("bucket_seconds=0", {"bucket_seconds": 0}),
    ):
        response = _get(client, f"{API}/analytics/traffic", **params)
        print(f"  {label:<38} -> {response.status_code}")
        if response.status_code != 422:
            failures.append(
                f"{label} was not a 422 request error (got {response.status_code}) "
                "(M13.24)"
            )


def _check_series_bounds(
    client: TestClient, failures: list[str]
) -> None:
    """Verify a series is bounded, aligned and inside its window (M16.7).

    Three properties together: the point count never exceeds the ceiling, every
    bucket start is an exact multiple of the bucket size (so two requests describe
    the same buckets), and every bucket lies inside the window it was asked for.
    """
    print("\n--- Series bounds and alignment (M16.7) ---")
    now = time.time()
    for minutes, bucket in ((60, None), (1440, None), (30, 10)):
        params: dict[str, Any] = {
            "since": _iso_from_epoch(now - minutes * 60.0),
            "until": _iso_from_epoch(now),
        }
        if bucket is not None:
            params["bucket_seconds"] = bucket

        data = _get_data(client, f"{API}/analytics/traffic", **params)
        period = data["period"]
        series = _stored_of(data).get("series") or []
        size = period["bucket_seconds"]
        print(
            f"  {minutes:>4}m bucket={size:>4}s points={period['buckets']:>3} "
            f"returned={len(series):>3} (<= {MAX_BUCKETS})"
        )
        if period["buckets"] > MAX_BUCKETS:
            failures.append(
                f"a {minutes}m window listed {period['buckets']} points, over "
                f"{MAX_BUCKETS} (M16.7)"
            )
        if len(series) > MAX_BUCKETS:
            failures.append(
                f"a {minutes}m series returned {len(series)} points, over "
                f"{MAX_BUCKETS} (M16.7)"
            )
        if len(series) > period["buckets"]:
            failures.append(
                f"a {minutes}m series returned more points than its own period "
                "declares (M16.7)"
            )
        for point in series:
            start = _epoch_of(point["start"])
            if int(start) % size != 0:
                failures.append(
                    f"a bucket started at {point['start']}, which is not a multiple "
                    f"of {size}s (M16.7)"
                )
                break
            if start < _epoch_of(period["since"]) - size or start >= _epoch_of(
                period["until"]
            ):
                failures.append(
                    f"a bucket at {point['start']} falls outside the window "
                    "(M16.7)"
                )
                break


def _check_protocol_shares(
    client: TestClient, factory, bounds: tuple[float, float], failures: list[str]
) -> None:
    """Verify protocol shares are taken against the window's own total (M16.3).

    The percentages are recomputed from the rows themselves, so a breakdown that
    divided by the returned rows instead of the window's population would be
    caught: with a small window the two denominators differ.
    """
    print("\n--- Protocol shares are shares of the window (M16.3) ---")
    first, last = bounds
    since, until = first - 1.0, last + 1.0

    data = _get_data(
        client,
        f"{API}/analytics/protocols",
        since=_iso_from_epoch(since),
        until=_iso_from_epoch(until),
    )
    stored = _stored_of(data)
    entries = stored.get("protocols") or []
    total = stored.get("total_packets") or 0
    print(
        f"  stored      : total={total} distinct={stored.get('distinct_protocols')} "
        f"returned={stored.get('count')} truncated={stored.get('truncated')}"
    )
    for entry in entries:
        share = entry.get("percentage")
        expected = (entry.get("packets", 0) / total * 100.0) if total else 0.0
        print(
            f"    {entry.get('protocol'):<8} {entry.get('packets'):>6} packet(s) "
            f"{entry.get('bytes'):>9} byte(s) {share}%"
        )
        if share is None or abs(share - expected) > 0.02:
            failures.append(
                f"protocol {entry.get('protocol')} reported {share}%, not the "
                f"{expected:.2f}% its own packets imply (M16.3)"
            )

    counted_packets = sum(entry.get("packets", 0) for entry in entries)
    if not stored.get("truncated") and counted_packets != total:
        failures.append(
            f"an untruncated protocol breakdown accounts for {counted_packets} of "
            f"{total} packets (M16.3)"
        )
    if stored.get("truncated") and stored.get("distinct_protocols", 0) <= stored.get(
        "count", 0
    ):
        failures.append("a breakdown reported truncated without more distinct groups")
    shares = sum(entry.get("percentage") or 0.0 for entry in entries)
    print(f"  shares sum  : {shares:.2f}%")
    if not entries:
        failures.append("the window's protocol breakdown was empty (M16.3)")
    elif not stored.get("truncated") and abs(shares - 100.0) > 0.05:
        failures.append(
            f"an untruncated breakdown's shares sum to {shares:.2f}%, not 100% "
            "(M16.3)"
        )


def _check_rankings(
    client: TestClient, bounds: tuple[float, float], failures: list[str]
) -> None:
    """Verify a ranking follows ``by``, is ordered and is capped (M16.2).

    Both metrics are asked for over the same window. The property is not that the
    two rows differ — they need not — but that each list is ordered by the metric
    that was requested, which is what makes ``by`` mean something.
    """
    print("\n--- Rankings follow `by` and are capped (M16.2) ---")
    first, last = bounds
    params: dict[str, Any] = {
        "since": _iso_from_epoch(first - 1.0),
        "until": _iso_from_epoch(last + 1.0),
    }

    for metric in ("packets", "bytes"):
        data = _get_data(
            client, f"{API}/analytics/traffic", by=metric, limit=MAX_TOP_LIMIT, **params
        )
        stored = _stored_of(data)
        for key in ("top_sources", "top_destinations", "top_ports"):
            entries = stored.get(key) or []
            ordered = [entry.get(metric, 0) for entry in entries]
            print(f"  by={metric:<8} {key:<18} {len(entries)} entries {ordered[:5]}")
            if len(entries) > MAX_GROUPS:
                failures.append(
                    f"{key} returned {len(entries)} entries, over the {MAX_GROUPS} "
                    "cap (M16.2)"
                )
            if ordered != sorted(ordered, reverse=True):
                failures.append(
                    f"{key} was not ordered by {metric}: {ordered[:5]} (M16.2)"
                )
            if stored.get("rank_by") and stored["rank_by"] != metric:
                failures.append(
                    f"{key} reported rank_by={stored['rank_by']} for by={metric} "
                    "(M16.2)"
                )

    # The live half of the route must carry the same ordering guarantee.
    live = _get_data(client, f"{API}/analytics/protocols", by="bytes")
    counts = [entry.get("bytes", 0) for entry in live.get("protocols") or []]
    print(f"  live protocols by=bytes : {counts}")
    if counts != sorted(counts, reverse=True):
        failures.append("the live protocol list was not ordered by bytes (M16.3)")
    if live.get("rank_by") != "bytes":
        failures.append("the protocol route did not echo its ranking metric (M16.3)")


def _check_connections(
    client: TestClient, factory, bounds: tuple[float, float], failures: list[str]
) -> None:
    """Verify the stored conversation block agrees with the table (M16.5).

    The status breakdown must account for every row in the window, and the
    duration statistics must be either present with samples or ``null`` with none
    — never a zero standing in for "no conversation ended".
    """
    print("\n--- Stored conversations against the table (M16.5) ---")
    first, last = bounds
    since, until = first - 1.0, last + 1.0
    expected = _expected_connections(factory, since, until)

    data = _get_data(
        client,
        f"{API}/analytics/connections",
        since=_iso_from_epoch(since),
        until=_iso_from_epoch(until),
    )
    stored = _stored_of(data)
    duration = stored.get("duration") or {}
    print(
        f"  stored      : total={stored.get('total')} active={stored.get('active')} "
        f"expected={expected}"
    )
    print(
        f"  by_status   : {stored.get('by_status')} | by_protocol: "
        f"{stored.get('by_protocol')}"
    )
    print(
        f"  duration    : samples={duration.get('samples')} "
        f"min={duration.get('min_seconds')} mean={duration.get('mean_seconds')} "
        f"max={duration.get('max_seconds')}"
    )
    if stored.get("total") != expected:
        failures.append(
            f"the stored conversation block reports {stored.get('total')} rows, "
            f"the table holds {expected} that began in the window (M16.5)"
        )
    by_status = stored.get("by_status") or {}
    if sum(by_status.values()) != stored.get("total"):
        failures.append(
            f"the connection status breakdown sums to {sum(by_status.values())}, "
            f"not the window's {stored.get('total')} (M16.5)"
        )
    samples = duration.get("samples")
    if samples:
        if not all(
            duration.get(key) is not None
            for key in ("min_seconds", "mean_seconds", "max_seconds")
        ):
            failures.append(
                "a duration block with samples reported a null statistic (M16.5)"
            )
        elif (
            duration["min_seconds"] > duration["mean_seconds"]
            or duration["mean_seconds"] > duration["max_seconds"]
        ):
            failures.append(
                f"the duration statistics are not ordered: {duration} (M16.5)"
            )
    elif any(
        duration.get(key) is not None
        for key in ("min_seconds", "mean_seconds", "max_seconds")
    ):
        failures.append(
            "a duration block with no samples reported a statistic instead of null "
            "(M16.5)"
        )


def _check_threats(
    client: TestClient, factory, bounds: tuple[float, float], failures: list[str]
) -> None:
    """Verify findings, alerts and incidents stay three distinct things (M16.6).

    Every vocabulary the stored block reports is checked to account for exactly the
    window's rows, so a breakdown that dropped a state or double-counted one would
    show up as a sum that does not match. The three notions of "how bad" —
    severity, confidence and risk band — are confirmed present as three separate
    fields, and the alert-to-incident references are checked against the registry.
    """
    print("\n--- Threat analytics across M10, M11 and M12 (M16.6) ---")
    first, last = bounds
    since, until = first - 1.0, last + 1.0
    expected_alerts = _expected_alerts(factory, since, until)

    data = _get_data(
        client,
        f"{API}/analytics/threats",
        since=_iso_from_epoch(since),
        until=_iso_from_epoch(until),
    )
    stored = _stored_of(data)
    findings = data.get("findings") or {}
    links = data.get("incident_links") or {}
    print(
        f"  live        : alerts={data.get('alerts_total')} "
        f"open={data.get('alerts_open')} incidents={data.get('incidents_total')} "
        f"active={data.get('incidents_active')} "
        f"highest_risk={data.get('highest_risk_score')}"
    )
    print(
        f"  findings    : retained={findings.get('retained')} "
        f"in_window={findings.get('in_window')} "
        f"mean_confidence={findings.get('mean_confidence')} "
        f"rules={len(findings.get('by_rule') or [])}"
    )
    print(
        f"  stored      : total={stored.get('total')} expected={expected_alerts} "
        f"without_rule_key={stored.get('without_rule_key')}"
    )
    print(
        f"    severity  : {stored.get('by_severity')}\n"
        f"    status    : {stored.get('by_status')}\n"
        f"    risk band : {stored.get('by_risk_band')}\n"
        f"    confidence: {stored.get('by_confidence_range')}"
    )
    print(
        f"  incident links: incidents={links.get('incidents_total')} "
        f"with_alerts={links.get('incidents_with_alerts')} "
        f"alerts_in_incidents={links.get('alerts_in_incidents')}"
    )

    if not data.get("alerts_total"):
        failures.append("the threat route reported no alert from the driven scans (M16.6)")
    if not data.get("incidents_total"):
        failures.append(
            "the threat route reported no incident, though two detectors fired "
            "(M16.6)"
        )
    if data.get("alerts_by_severity") is None or data.get("alerts_by_status") is None:
        failures.append("the live alert breakdowns were absent (M16.6)")
    # The three notions must be three fields, not one collapsed number.
    for field in ("by_severity", "by_confidence_range", "by_risk_band"):
        if field not in stored:
            failures.append(
                f"the stored alert block did not keep {field} distinct (M16.6)"
            )
    if stored.get("total") != expected_alerts:
        failures.append(
            f"the stored alert block reports {stored.get('total')} alerts, the "
            f"table holds {expected_alerts} in the window (M16.6)"
        )
    for field in ("by_severity", "by_status", "by_risk_band", "by_confidence_range"):
        breakdown = stored.get(field) or {}
        if sum(breakdown.values()) != stored.get("total"):
            failures.append(
                f"the stored alert {field} sums to {sum(breakdown.values())}, not "
                f"the window's {stored.get('total')} (M16.6)"
            )
    rules = stored.get("rules") or []
    ranked = sum(entry.get("alerts", 0) for entry in rules)
    if ranked + (stored.get("without_rule_key") or 0) != stored.get("total"):
        failures.append(
            f"the rule ranking accounts for {ranked} alerts plus "
            f"{stored.get('without_rule_key')} keyless ones, not the window's "
            f"{stored.get('total')} (M16.6)"
        )
    if findings.get("in_window", 0) > findings.get("retained", 0):
        failures.append(
            "the findings summary counted more in-window findings than it retains "
            "(M16.6)"
        )
    if links.get("incidents_with_alerts", 0) > links.get("incidents_total", 0):
        failures.append(
            "more incidents were reported as carrying alerts than exist (M16.6)"
        )
    if links.get("alerts_in_incidents", 0) > data.get("alerts_total", 0):
        failures.append(
            "incident links name more distinct alerts than the alert store holds "
            "(M16.6)"
        )


def _check_devices(
    client: TestClient, bounds: tuple[float, float], failures: list[str]
) -> None:
    """Verify the device route reports the registry and scores nothing (M16.4).

    The windowed block re-filters the registry by ``last_seen``, so a window that
    spans the traffic must list the sources it saw, and a window before it must
    list none. No row may carry a risk score, because M8 computes none (M13.10).
    """
    print("\n--- Device analytics over the real registry (M16.4) ---")
    first, last = bounds

    covering = _get_data(
        client,
        f"{API}/analytics/devices",
        since=_iso_from_epoch(first - 1.0),
        until=_iso_from_epoch(last + 1.0),
    )
    windowed = covering.get("windowed") or {}
    inner = windowed.get("data") or {}
    addresses = sorted(
        address for device in inner.get("top") or [] for address in device["ip_addresses"]
    )
    print(
        f"  registry    : total={covering.get('total')} "
        f"by_status={covering.get('by_status')}"
    )
    print(
        f"  in window   : total={inner.get('total')} "
        f"by_status={inner.get('by_status')} addresses={addresses[:5]}"
    )
    if covering.get("total", 0) < 1:
        failures.append("the registry reported no device after real traffic (M16.4)")
    if inner.get("total", 0) < 1:
        failures.append(
            "a window spanning the traffic listed no device, though the registry "
            "observed its sources (M16.4)"
        )
    for row in covering.get("top") or []:
        if "risk_score" in row:
            failures.append("a ranked device carried a risk score, which M8 has none of (M16.4)")
        if "first_seen" not in row or "last_seen" not in row:
            failures.append("a ranked device omitted its M8 observation bounds (M16.4)")
        break
    for entry in inner.get("top") or []:
        if entry.get("status") is None:
            failures.append("a windowed device carried no M8 activity state (M16.4)")
        break


def _run_sample_checks(
    client: TestClient, factory, bounds: tuple[float, float], failures: list[str]
) -> None:
    """Run every sample-mode check against one wired client (M16.18).

    The order is deliberate: the reads come before the refusal cases, so the
    figures the earlier checks assert cannot have been changed by a later request,
    and the bounds are read once from the store and reused, so every window below
    is built on the same instants.
    """
    _check_routes_and_period(client, failures)
    _check_stored_agreement(client, factory, bounds, failures)
    _check_window_is_half_open(client, bounds, failures)
    _check_empty_window(client, bounds, failures)
    _check_devices(client, bounds, failures)
    _check_connections(client, factory, bounds, failures)
    _check_threats(client, factory, bounds, failures)
    _check_protocol_shares(client, factory, bounds, failures)
    _check_rankings(client, bounds, failures)
    _check_series_bounds(client, failures)
    _check_refusals(client, failures)


#: The counts driven by sample mode. Small, so the run is seconds rather than
#: minutes; the scans are over the lab thresholds, so the real detectors fire.
_SCAN_COUNT = PORT_SCAN_THRESHOLD + 4
_SWEEP_COUNT = INTERNAL_SCAN_THRESHOLD


def run_sample_mode() -> int:
    """Drive the pipeline, then verify the analytics layer over its real data."""
    workdir = Path(tempfile.mkdtemp(prefix="netwatch_m16_"))
    db_path = workdir / "verify_m16.db"
    database, factory = _connect_database(db_path)
    failures: list[str] = []
    try:
        _seed_rule_catalogue(factory)
        stack = _build_stack(factory)
        packets = _scan_packets(_SCAN_COUNT, SOURCE_IP) + _sweep_packets(
            _SWEEP_COUNT, SECOND_SOURCE_IP
        )
        captured_at = time.time() - _PACKET_BACKDATE_SECONDS

        print("=" * _BANNER_WIDTH)
        print("M16 SAMPLE MODE - the analytics layer over real backend data")
        print("=" * _BANNER_WIDTH)
        print(f"database : {db_path}")
        print(
            f"packets  : {len(packets)} driven through the real pipeline "
            f"({_SCAN_COUNT} TCP SYNs, {_SWEEP_COUNT} UDP sweeps)"
        )
        print(f"dated at : {_iso_from_epoch(captured_at)}")

        stack.capture(packets, captured_at)
        print(
            f"after capture: processed={stack.pipeline.get_processed_count()} "
            f"findings={len(stack.detection.get_findings())} "
            f"incidents={len(stack.correlation.get_incidents())}"
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
        if stack.pipeline.get_processed_count() != len(packets):
            failures.append(
                f"the pipeline processed {stack.pipeline.get_processed_count()} of "
                f"{len(packets)} driven packets, so the store is not what this run "
                "believes it is (M16.18)"
            )

        with _serve(stack, factory, database) as client:
            bounds = _stored_bounds(client)
            if bounds is None:
                failures.append(
                    "the packet the pipeline persisted was not readable through the "
                    "analytics route, so no window could be checked (M16.2)"
                )
            else:
                print(
                    f"\nstored bounds: {_iso_from_epoch(bounds[0])} .. "
                    f"{_iso_from_epoch(bounds[1])}"
                )
                _run_sample_checks(client, factory, bounds, failures)
    finally:
        database.dispose()
        shutil.rmtree(workdir, ignore_errors=True)
    return _report_failures(failures, mode="sample")


def _wait_for_server(client: httpx.Client, *, attempts: int = 60) -> bool:
    """Poll the OpenAPI document until the server answers, or give up (M16.18)."""
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
    """Return ``requested`` if it can be bound, else an unused port."""
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
    """Start the application under uvicorn and verify it over real HTTP (M16.18).

    This is the mode M16.18 describes literally: a running server, real sockets and
    the documented URLs. It reads only — nothing is written — so it is safe to
    point at a working installation.
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
    print("M16 LIVE MODE - the running application over real HTTP")
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

        print("\n--- The five analytics routes over real HTTP (M16.11) ---")
        for path in LIVE_PATHS:
            response = client.get(path)
            try:
                body = response.json()
            except ValueError:
                failures.append(f"{path} did not return JSON")
                print(f"  {path:<34} {response.status_code} (not JSON)")
                continue
            data = body.get("data") or {}
            period = data.get("period") or {}
            section = data.get("stored") or data.get("windowed") or {}
            print(
                f"  {path:<34} {response.status_code} "
                f"bucket={period.get('bucket_seconds')}s "
                f"available={section.get('available')}"
            )
            if response.status_code != 200:
                failures.append(f"{path} answered {response.status_code}, not 200")
            elif body.get("success") is not True:
                failures.append(f"{path} did not use the success envelope (M13.4)")
            elif not period:
                failures.append(f"{path} carried no period (M16.7)")
            elif section.get("available") is not True:
                failures.append(
                    f"{path} reported its stored block as unavailable over a "
                    "configured database (M16.8)"
                )

        # A window the running service cannot honour must still refuse in the
        # documented envelope, over a real socket (M16.7).
        response = client.get(
            f"{API}/analytics/traffic",
            params={"since": "not-a-time"},
        )
        codes = _error_codes(response)
        print(f"  malformed since -> {response.status_code} {codes}")
        if response.status_code != 400 or "INVALID_FILTER" not in codes:
            failures.append(
                "a malformed window bound was not the controlled 400 over real "
                "HTTP (M16.7)"
            )
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
    """Parse arguments and dispatch to the selected mode (M16.18)."""
    parser = argparse.ArgumentParser(
        description="Verify the M16 analytics layer over real backend data (M16.18)."
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
        "--port",
        type=int,
        default=8016,
        help="Live-mode port (a free one is chosen if busy)",
    )
    args = parser.parse_args()

    if args.mode == "live":
        return run_live_mode(args.host, args.port)
    return run_sample_mode()


if __name__ == "__main__":
    raise SystemExit(main())
