"""M16 performance baseline — the analytics layer over a known store (M16.13).

M16.13 asks that the analytics layer stay suitable for a local SQLite deployment
and that the measurements be recorded as *local development* figures. This script
measures the three places M16 can cost something, and nothing else:

* **request latency** — the wall time of a real HTTP request through the real
  application (``app.main:app``), for each of the five analytics routes, with the
  default window and with an explicit one;
* **aggregate query time** — the same family of questions asked directly of
  :class:`~app.analytics.packet_queries.PacketAnalytics`,
  :class:`~app.analytics.connection_queries.ConnectionAnalytics` and
  :class:`~app.analytics.alert_queries.AlertAnalytics`, with no FastAPI and no JSON
  in the way, so the part of a route that is SQLite work is *measured* rather than
  inferred by subtraction;
* **window resolution cost** — :func:`~app.analytics.window.resolve_window`, which
  every route calls before it touches a table. It is pure arithmetic and should be
  negligible; it is measured so that claim is checked rather than asserted.

What is deliberately *not* measured: capture, packet normalization, M6 statistics,
M7 persistence, M8 discovery, M9 tracking, M10 detection, M11 alerting and M12
correlation. Those are M5–M12 costs and each milestone has its own baseline. This
one starts from a seeded store, because M16.13 is about what the analytics *layer*
adds on top of data that already exists.

**Why the store is seeded rather than captured.** Driving packets through the real
pipeline would measure the pipeline, not the analytics, and would take minutes
rather than seconds. Rows are inserted directly through the models instead, into a
throwaway SQLite file under the OS temp directory that this script creates and
removes — the developer's ``netwatch.db`` is never opened.

**What the in-memory half reports.** ``/analytics/devices`` and the live halves of
the other four routes read in-process services (the M8 registry, the M9 tracker,
the M10 engine, the M12 registry). Those are empty in this process, which is the
honest state of a freshly started backend that has captured nothing: the figures
below therefore describe the routes' *fixed* cost plus their database work, and the
device route is measured over an empty registry. The stored blocks — which are what
M16 added — are measured over a seeded store, because that is where the new work
is.

**This is a local, single-machine baseline, not a capacity claim.** One process,
one SQLite file, an in-process test client (so no loopback network stack), on an
otherwise idle machine. The seed is deterministic, so two runs are comparable;
what the numbers are good for is comparing a route or a window shape against
another, and re-measuring after a change.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m16.py
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m16.py --packets 100000
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m16.py --span-minutes 1440
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m16.py --sizes 1000,10000
"""

from __future__ import annotations

import argparse
import logging
import math
import platform
import shutil
import sqlite3
import statistics as stats
import sys
import tempfile
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Make the backend root importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, event  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.alerts.dedup import KEY_SEPARATOR  # noqa: E402
from app.alerts.queries import AlertQueries  # noqa: E402
from app.analytics.alert_queries import AlertAnalytics  # noqa: E402
from app.analytics.connection_queries import ConnectionAnalytics  # noqa: E402
from app.analytics.metrics import DEFAULT_RANK_METRIC, MAX_GROUPS  # noqa: E402
from app.analytics.packet_queries import PacketAnalytics  # noqa: E402
from app.analytics.window import (  # noqa: E402
    MAX_BUCKETS,
    MAX_WINDOW_SECONDS,
    AnalyticsWindow,
    iso_from_epoch,
    resolve_window,
)
from app.api.v1.analytics import DEFAULT_TOP_LIMIT  # noqa: E402
from app.api.v1.deps import get_alert_queries  # noqa: E402
from app.config.settings import settings  # noqa: E402
from app.connections.manager import (  # noqa: E402
    ConnectionTracker,
    get_connection_tracker,
)
from app.connections.persistence import ConnectionPersistence  # noqa: E402
from app.database.session import get_db  # noqa: E402
from app.devices.manager import (  # noqa: E402
    DeviceDiscoveryManager,
    get_device_manager,
)
from app.main import app  # noqa: E402
from app.services.capture_manager import (  # noqa: E402
    CaptureManager,
    get_capture_manager,
)
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

#: The versioned base every route below is measured against (M13.3).
API = "/api/v1"

#: The five routes M16 owns (M16.11).
ANALYTICS_ROUTES: tuple[str, ...] = (
    "traffic",
    "protocols",
    "devices",
    "connections",
    "threats",
)

#: Protocol labels alternated across the seeded packets, so a protocol breakdown
#: has more than one group and a ranking is a real ranking.
_PROTOCOLS = ("TCP", "UDP", "ICMP")

#: Distinct source addresses the seeded packets are spread over. Small enough that
#: the rankings are dense, large enough that a top-10 is a real selection.
_SOURCE_COUNT = 250

#: Distinct destination ports the seeded packets are spread over.
_PORT_COUNT = 200

#: How many conversations and alerts are seeded relative to the packet count. Both
#: tables are much smaller than ``packets`` in a real run — M9 writes one row per
#: conversation, M11 one per alert — so they are seeded at a fraction of it.
_CONNECTION_RATIO = 0.01
_ALERT_RATIO = 0.002

#: The M11 severities and the states the seeded alerts are spread over.
_SEVERITIES = ("critical", "high", "medium", "low")
_ALERT_STATUSES = ("open", "acknowledged", "resolved", "dismissed")
_CONNECTION_STATUSES = ("active", "completed", "timeout")

#: Detector rule ids the seeded alerts carry a correlation key for, so the stored
#: rule ranking is exercised rather than measured on a single group.
_RULE_KEYS = ("port_scan", "syn_flood", "icmp_flood", "high_bandwidth")

#: How many rows are written per commit while seeding.
_SEED_BATCH = 1000

#: Repeated requests a measurement discards before recording. The first request to
#: a route pays for lazy construction, which is a once-per-process cost.
_WARMUP_REQUESTS = 3

#: The window lengths the request sweep compares, in minutes. 60 is the documented
#: default; 5 and 1440 are a short and a long window, which are the two shapes that
#: resolve to a different bucket size.
_WINDOW_MINUTES: tuple[int, ...] = (5, 60, 1440)

_LOGGER_NAME = "netwatch.benchmark.m16"


@dataclass(frozen=True)
class SeedPlan:
    """What the throwaway store holds, and when it happened (M16.13).

    The instants are absolute epoch seconds decided once, before seeding, so every
    seeded row is dated relative to the same base and two runs describe the same
    store shape. ``end_epoch`` is the newest seeded instant, not "now": the rows are
    placed *before* the run starts so that a default window resolved during the run
    still spans all of them.
    """

    packets: int
    connections: int
    alerts: int
    start_epoch: float
    end_epoch: float

    @property
    def span_seconds(self) -> float:
        """Return how long the seeded traffic spans, in seconds."""
        return self.end_epoch - self.start_epoch


def _plan(count: int, span_seconds: float) -> SeedPlan:
    """Return the seed plan for ``count`` packets over ``span_seconds``.

    The span ends one second before the run's start instant, so a window whose
    ``until`` is ``now`` (the documented default) still includes the newest row.
    """
    now = time.time()
    return SeedPlan(
        packets=max(count, 1),
        connections=max(int(count * _CONNECTION_RATIO), 1),
        alerts=max(int(count * _ALERT_RATIO), 1),
        start_epoch=now - 1.0 - span_seconds,
        end_epoch=now - 1.0,
    )


def _iso(epoch_seconds: float) -> str:
    """Render an instant as the ISO-8601 UTC string the API accepts (M13.26)."""
    return iso_from_epoch(epoch_seconds)


def _naive_utc(epoch_seconds: float) -> datetime:
    """Convert epoch seconds to the naive UTC datetime the stores persist.

    Every timestamp column in this schema holds a UTC wall-clock value with no
    offset (M7, M9, M11 all write it that way), so a bound or a seeded row must be
    naive-UTC too. Converting through :mod:`datetime` with an explicit UTC tzinfo
    and then dropping it is what keeps a seeded row interchangeable with a captured
    one.
    """
    return datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc).replace(
        tzinfo=None
    )


def _connect_database(db_path: Path):
    """Create the isolated SQLite database and a session factory (M13.37/M16.13).

    Foreign keys are enabled, so the store carries the same constraint the shipped
    one does, and no other pragma is changed: the figures should describe the
    shipped engine rather than a differently tuned one.
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


def _seed_packets(factory, plan: SeedPlan) -> None:
    """Insert the plan's packet rows directly into the store (M16.13).

    Only metadata is written, because metadata is all M7 ever stores (M7.5), so no
    figure below is inflated by data the production path would never have written.
    The instants are spread evenly across the plan's span, which is what makes a
    time series have more than one non-empty bucket.
    """
    from app.models.packet import Packet

    span = max(plan.span_seconds, 1.0)
    step = span / plan.packets
    session = factory()
    try:
        batch: list[Any] = []
        for index in range(plan.packets):
            source_index = index % _SOURCE_COUNT
            port_index = index % _PORT_COUNT
            batch.append(
                Packet(
                    timestamp=_naive_utc(plan.start_epoch + index * step),
                    source_ip=(
                        f"10.{(source_index >> 8) & 0xFF}."
                        f"{source_index & 0xFF}.{index & 0x3F}"
                    ),
                    destination_ip="203.0.113.9",
                    # Every thirtieth row carries no source port, so the reported
                    # "packets without a port" counts are exercised rather than
                    # being trivially zero.
                    source_port=None if index % 30 == 0 else 40000 + port_index,
                    destination_port=(
                        None if index % 37 == 0 else 1 + (port_index % 1024)
                    ),
                    protocol=_PROTOCOLS[index % len(_PROTOCOLS)],
                    packet_length=64 + (index % 1400),
                    ttl=64,
                )
            )
            if len(batch) >= _SEED_BATCH:
                session.add_all(batch)
                session.commit()
                batch.clear()
        if batch:
            session.add_all(batch)
            session.commit()
    finally:
        session.close()


def _seed_connections(factory, plan: SeedPlan) -> None:
    """Insert the plan's conversation rows directly into the store (M16.13).

    Each row is shaped like one M9 writes: a ``start_time`` inside the span, a
    status from M9's vocabulary, and an ``end_time`` for every conversation that is
    not still active — so the duration statistics have samples and the "still
    running" exclusion has rows to exclude.
    """
    from app.models.connection import NetworkConnection

    span = max(plan.span_seconds, 1.0)
    step = span / plan.connections
    session = factory()
    try:
        batch: list[Any] = []
        for index in range(plan.connections):
            started = plan.start_epoch + index * step
            status = _CONNECTION_STATUSES[index % len(_CONNECTION_STATUSES)]
            ended = None if status == "active" else started + 5.0 + (index % 90)
            batch.append(
                NetworkConnection(
                    source_ip=f"10.0.0.{index % _SOURCE_COUNT}",
                    destination_ip="203.0.113.9",
                    source_port=40000 + (index % _PORT_COUNT),
                    destination_port=443 if index % 2 == 0 else 53,
                    protocol="TCP" if index % 2 == 0 else "UDP",
                    packets_sent=10 + (index % 50),
                    packets_received=12 + (index % 60),
                    bytes_sent=1500 + (index % 4000),
                    bytes_received=2000 + (index % 6000),
                    start_time=_naive_utc(started),
                    end_time=None if ended is None else _naive_utc(ended),
                    status=status,
                )
            )
            if len(batch) >= _SEED_BATCH:
                session.add_all(batch)
                session.commit()
                batch.clear()
        if batch:
            session.add_all(batch)
            session.commit()
    finally:
        session.close()


def _seed_alerts(factory, plan: SeedPlan) -> None:
    """Insert the plan's alert rows directly into the store (M16.13).

    The rows span every M11 severity, every lifecycle state and every M12 risk
    band, and all but every twentieth carries a correlation key of the shape M11
    writes (``rule_id | source_ip | ...``, M11.9) — so the stored rule ranking, the
    severity and status histograms, the risk-band and confidence histograms and the
    "alerts with no rule key" count are all exercised by data rather than measured
    on empty tables or on a single group.
    """
    from app.models.alert import Alert

    span = max(plan.span_seconds, 1.0)
    step = span / plan.alerts
    session = factory()
    try:
        batch: list[Any] = []
        for index in range(plan.alerts):
            created = plan.start_epoch + index * step
            rule_key = _RULE_KEYS[index % len(_RULE_KEYS)]
            source_ip = f"10.0.0.{index % _SOURCE_COUNT}"
            batch.append(
                Alert(
                    title=f"{rule_key} sample {index}",
                    description=None,
                    source_ip=source_ip,
                    destination_ip="203.0.113.9",
                    severity=_SEVERITIES[index % len(_SEVERITIES)],
                    # Spread across the whole 0-100 range so all four M12 bands
                    # hold rows and the banding is a real selection.
                    risk_score=(index * 7) % 101,
                    confidence=(index * 11) % 101,
                    status=_ALERT_STATUSES[index % len(_ALERT_STATUSES)],
                    # One alert in twenty carries no key, so the count of unranked
                    # alerts is a real number rather than a constant zero.
                    correlation_key=(
                        None
                        if index % 20 == 0
                        else f"{rule_key}{KEY_SEPARATOR}{source_ip}{KEY_SEPARATOR}{index}"
                    ),
                    created_at=_naive_utc(created),
                )
            )
            if len(batch) >= _SEED_BATCH:
                session.add_all(batch)
                session.commit()
                batch.clear()
        if batch:
            session.add_all(batch)
            session.commit()
    finally:
        session.close()


def _seed_store(factory, plan: SeedPlan) -> None:
    """Seed every table the analytics routes read (M16.13)."""
    _seed_packets(factory, plan)
    _seed_connections(factory, plan)
    _seed_alerts(factory, plan)


def _build_overrides(factory, db_engine) -> dict:
    """Return the dependency overrides that point the API at the seeded store.

    Each key is a *dependency function* a route declares in ``Depends``, so the
    route still resolves its collaborator through FastAPI and the wiring stays the
    application's rather than this script's (M13.28). Only dependencies that would
    otherwise escape the isolated store — or start the production capture pipeline
    — are replaced:

    * ``get_db`` — every session-backed route reads the seeded database;
    * ``get_alert_queries`` — the alert read service holds a session *factory*
      rather than a session, so it would otherwise read the developer's file;
    * ``get_capture_manager`` — the real factory builds the process-wide pipeline,
      which starts a persistence worker and points at the developer's database. A
      manager over a bare pipeline is stood up instead: nothing to capture on,
      nothing written, no thread;
    * ``get_interface_manager`` — the real one enumerates this machine's NICs.
      Reporting none keeps a run independent of the hardware it happens to run on;
    * ``get_statistics_manager`` / ``get_device_manager`` /
      ``get_connection_tracker`` — the in-memory stores the live halves read.
      Fresh, empty instances make a run reproducible and keep the connection
      tracker off the developer's file.

    The detection and correlation engines are deliberately *not* replaced: both are
    in-memory, so the threats route measures the empty registries a freshly started
    process holds before any capture runs.
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

    devices = DeviceDiscoveryManager()
    connections = ConnectionTracker(
        device_registry=devices.registry,
        persistence=ConnectionPersistence(session_factory=factory),
        autostart_cleanup=False,
    )
    statistics = TrafficStatisticsManager()
    interfaces = InterfaceManager(discovery=lambda: [])
    capture = CaptureManager(interface_manager=interfaces, pipeline=PacketPipeline())

    return {
        get_db: db_override,
        get_alert_queries: lambda: AlertQueries(session_factory=factory),
        get_capture_manager: lambda: capture,
        get_interface_manager: lambda: interfaces,
        get_statistics_manager: lambda: statistics,
        get_device_manager: lambda: devices,
        get_connection_tracker: lambda: connections,
    }


@contextmanager
def _client(factory, db_engine) -> Generator[TestClient, None, None]:
    """Yield a client over the real application, reading the seeded store.

    Every response timed below is produced by the production router, over the
    production analytics service, serialized into the production envelope — the
    figure is the analytics layer's cost, not a re-implementation of it.

    The environment is temporarily ``"test"`` so the application's lifespan skips
    ``init_db()`` and never touches the developer's database, and every override is
    removed afterwards so nothing leaks into a later run.
    """
    overrides = _build_overrides(factory, db_engine)
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


@dataclass
class Sample:
    """One measured thing: its identity, its answer and its times.

    ``summary`` is a short description of what the response (or the direct call)
    actually held, so a reader can see that a window really selected data rather
    than that a fast figure was measured over nothing.
    """

    label: str
    route: str
    status: int
    summary: str
    milliseconds: list[float] = field(default_factory=list)

    @property
    def mean(self) -> float:
        """Return the mean time in milliseconds."""
        return stats.fmean(self.milliseconds) if self.milliseconds else 0.0

    @property
    def median(self) -> float:
        """Return the median time in milliseconds.

        The median is the headline figure: a mean is moved by a single slow call,
        and on a machine doing anything else at the same time that is the norm.
        """
        return stats.median(self.milliseconds) if self.milliseconds else 0.0

    @property
    def p95(self) -> float:
        """Return the 95th-percentile time in milliseconds."""
        return _percentile(self.milliseconds, 95.0)

    @property
    def worst(self) -> float:
        """Return the slowest time in milliseconds."""
        return max(self.milliseconds) if self.milliseconds else 0.0


def _percentile(values: list[float], fraction: float) -> float:
    """Return the ``fraction``-th percentile of ``values`` (nearest rank)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = math.ceil(fraction / 100.0 * len(ordered))
    return ordered[min(max(rank - 1, 0), len(ordered) - 1)]


def _render_route(url: str, params: dict[str, Any] | None) -> str:
    """Return a displayable route, with its query string when it has one."""
    if not params:
        return url
    query = "&".join(f"{key}={value}" for key, value in params.items())
    return f"{url}?{query}"


def _full_window_params(plan: SeedPlan) -> dict[str, Any]:
    """Return bounds that span every seeded row, with a minute of margin.

    The margin matters: the window is compared against naive-UTC timestamps that
    were converted from the seeded instants, and a bound sitting exactly on the
    first or last seeded row would make the measurement depend on a rounding
    rather than on the query.
    """
    return {
        "since": _iso(plan.start_epoch - 60.0),
        "until": _iso(plan.end_epoch + 60.0),
    }


def _resolved_window(plan: SeedPlan) -> AnalyticsWindow:
    """Return the same full-coverage window, resolved, for the direct queries."""
    return resolve_window(
        since=plan.start_epoch - 60.0,
        until=plan.end_epoch + 60.0,
        bucket_seconds=None,
        now=time.time(),
    )


def _measure(
    client: TestClient,
    label: str,
    url: str,
    *,
    iterations: int,
    params: dict[str, Any] | None = None,
    summarize: Callable[[dict], str] | None = None,
    warmup: int = _WARMUP_REQUESTS,
) -> Sample:
    """Time ``iterations`` requests to ``url`` and return them as a ``Sample``.

    A wrong status raises rather than being timed: a figure for a route that
    answered 404 would be a figure for the wrong thing, and reporting it silently
    would be worse than stopping.

    ``warmup`` requests are issued first and discarded, because the first request
    to a route pays for lazy construction that happens once per process and is not
    part of a request's steady-state cost.
    """
    for _ in range(warmup):
        response = client.get(url, params=params)
        if response.status_code != 200:
            raise AssertionError(
                f"{_render_route(url, params)} answered {response.status_code} "
                f"during warm-up: {response.text[:200]}"
            )

    samples: list[float] = []
    body: dict[str, Any] | None = None
    status = 0
    for _ in range(iterations):
        start = time.perf_counter()
        response = client.get(url, params=params)
        samples.append((time.perf_counter() - start) * 1000.0)
        status = response.status_code
        body = response.json() if response.status_code == 200 else None

    data = body.get("data") if isinstance(body, dict) else None
    summary = ""
    if summarize is not None and isinstance(data, dict):
        summary = summarize(data)
    return Sample(
        label=label,
        route=_render_route(url, params),
        status=status,
        summary=summary,
        milliseconds=samples,
    )


def _time_call(call: Callable[[], Any], iterations: int, warmup: int) -> list[float]:
    """Time ``iterations`` calls to ``call`` in milliseconds, after warming up.

    Used for the costs that are not HTTP requests — an aggregate query and a window
    resolution — so they are measured the same way the requests are, rather than by
    a different method that would make the figures incomparable.
    """
    for _ in range(warmup):
        call()
    samples: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        call()
        samples.append((time.perf_counter() - start) * 1000.0)
    return samples


def _stored_of(data: dict) -> dict:
    """Return the persisted block of an analytics payload, or an empty dict."""
    section = data.get("stored") or data.get("windowed") or {}
    inner = section.get("data")
    return inner if isinstance(inner, dict) else {}


def _describe_traffic(data: dict) -> str:
    """Describe what the traffic response held."""
    stored = _stored_of(data)
    return (
        f"live={data.get('total_packets', 0):,} "
        f"stored={stored.get('total_packets', 0):,} "
        f"points={len(stored.get('series') or [])}"
    )


def _describe_protocols(data: dict) -> str:
    """Describe what the protocol response held."""
    stored = _stored_of(data)
    return (
        f"live={data.get('count', 0)} "
        f"stored={stored.get('count', 0)}/{stored.get('distinct_protocols', 0)}"
    )


def _describe_devices(data: dict) -> str:
    """Describe what the device response held."""
    stored = _stored_of(data)
    return f"registry={data.get('total', 0)} in_period={stored.get('total', 0)}"


def _describe_connections(data: dict) -> str:
    """Describe what the connection response held."""
    stored = _stored_of(data)
    duration = stored.get("duration") or {}
    return (
        f"tracked={data.get('tracked', 0)} "
        f"stored={stored.get('total', 0)} "
        f"durations={duration.get('samples', 0)}"
    )


def _describe_threats(data: dict) -> str:
    """Describe what the threat response held."""
    stored = _stored_of(data)
    findings = data.get("findings") or {}
    return (
        f"alerts={data.get('alerts_total', 0)} "
        f"stored={stored.get('total', 0)} "
        f"findings={findings.get('in_window', 0)}"
    )


#: The summarizer for each route, so the table shows what was actually selected.
_DESCRIBERS: dict[str, Callable[[dict], str]] = {
    "traffic": _describe_traffic,
    "protocols": _describe_protocols,
    "devices": _describe_devices,
    "connections": _describe_connections,
    "threats": _describe_threats,
}


def _phase_requests(
    client: TestClient, plan: SeedPlan, iterations: int
) -> list[Sample]:
    """Measure the five analytics routes over the seeded window (M16.13).

    Every route is asked over an explicit window that spans the whole seed, so the
    figure is the cost of aggregating the entire store rather than of selecting a
    sliver of it. The device route's *stored* half is measured the same way; its
    live half reads an empty registry, which the docstring states.
    """
    params = _full_window_params(plan)
    return [
        _measure(
            client,
            f"analytics/{name}",
            f"{API}/analytics/{name}",
            iterations=iterations,
            params=params,
            summarize=_DESCRIBERS[name],
        )
        for name in ANALYTICS_ROUTES
    ]


def _phase_default_window(client: TestClient, iterations: int) -> list[Sample]:
    """Measure the same five routes when the caller sends no bounds (M16.7).

    This is the path a first page load takes and it is not the same question as the
    sweep above: the window is resolved from the clock, and only the last hour of
    the store falls inside it. Both are measured because both are real, and the
    difference between them is what the window actually selects.
    """
    return [
        _measure(
            client,
            f"analytics/{name} (default)",
            f"{API}/analytics/{name}",
            iterations=iterations,
            summarize=_DESCRIBERS[name],
        )
        for name in ANALYTICS_ROUTES
    ]


def _phase_window_sweep(
    client: TestClient, plan: SeedPlan, iterations: int
) -> list[Sample]:
    """Measure one route as the window lengthens (M16.7/M16.13).

    The window is what M16.7 makes bounded, and its length is what decides the
    bucket size — so this sweep is the measurement that shows a long window costs
    more because it aggregates more rows, not because it returns more points. The
    bucket the window resolved to is reported beside the figure so the two can be
    read together.
    """
    samples: list[Sample] = []
    for minutes in _WINDOW_MINUTES:
        until = plan.end_epoch + 1.0
        params = {"since": _iso(until - minutes * 60.0), "until": _iso(until)}

        def describe(data: dict, minutes: int = minutes) -> str:
            stored = _stored_of(data)
            period = data.get("period") or {}
            return (
                f"{minutes}m bucket={period.get('bucket_seconds')}s "
                f"stored={stored.get('total_packets', 0):,}"
            )

        samples.append(
            _measure(
                client,
                f"traffic since=-{minutes}m",
                f"{API}/analytics/traffic",
                iterations=iterations,
                params=params,
                summarize=describe,
            )
        )
    return samples


def _phase_queries(engine, plan: SeedPlan, iterations: int) -> list[Sample]:
    """Measure the aggregate queries directly, with no HTTP in the way (M16.13).

    This is what separates SQLite's share of a route from everything else in it.
    The classes are the ones the service itself calls, over the same engine the
    routes used, so the comparison is against the same store rather than a
    different one.
    """
    window = _resolved_window(plan)
    session = Session(bind=engine)
    try:
        packets = PacketAnalytics(session)
        connections = ConnectionAnalytics(session)
        alerts = AlertAnalytics(session)
        cases: list[tuple[str, Callable[[], Any], Callable[[Any], str]]] = [
            (
                "PacketAnalytics.totals",
                lambda: packets.totals(window),
                lambda value: f"{value.packets:,} packet(s)",
            ),
            (
                "PacketAnalytics.series",
                lambda: packets.series(window),
                lambda value: f"{len(value)} bucket(s)",
            ),
            (
                "PacketAnalytics.protocols",
                lambda: packets.protocols(window),
                lambda value: f"{len(value)} group(s)",
            ),
            (
                "PacketAnalytics.distinct_protocols",
                lambda: packets.distinct_protocols(window),
                lambda value: f"distinct={value}",
            ),
            (
                "PacketAnalytics.top_sources",
                lambda: packets.top_sources(
                    window, limit=DEFAULT_TOP_LIMIT, by=DEFAULT_RANK_METRIC
                ),
                lambda value: f"{len(value)} of {MAX_GROUPS} max",
            ),
            (
                "PacketAnalytics.top_destination_ports",
                lambda: packets.top_destination_ports(
                    window, limit=DEFAULT_TOP_LIMIT, by="bytes"
                ),
                lambda value: f"{len(value)} port(s)",
            ),
            (
                "PacketAnalytics.stored_count",
                packets.stored_count,
                lambda value: f"{value:,} row(s)",
            ),
            (
                "ConnectionAnalytics.totals",
                lambda: connections.totals(window),
                lambda value: f"{value.connections:,} conversation(s)",
            ),
            (
                "ConnectionAnalytics.duration_stats",
                lambda: connections.duration_stats(window),
                lambda value: f"{value.samples} sample(s)",
            ),
            (
                "ConnectionAnalytics.count_by_status",
                lambda: connections.count_by_status(window),
                lambda value: f"{len(value)} state(s)",
            ),
            (
                "ConnectionAnalytics.series",
                lambda: connections.series(window),
                lambda value: f"{len(value)} bucket(s)",
            ),
            (
                "AlertAnalytics.totals",
                lambda: alerts.totals(window),
                lambda value: f"{value.alerts:,} alert(s)",
            ),
            (
                "AlertAnalytics.count_by_risk_band",
                lambda: alerts.count_by_risk_band(window),
                lambda value: f"{len(value)} band(s)",
            ),
            (
                "AlertAnalytics.count_by_confidence_range",
                lambda: alerts.count_by_confidence_range(window),
                lambda value: f"{len(value)} range(s)",
            ),
            (
                "AlertAnalytics.top_rules",
                lambda: alerts.top_rules(window, limit=10),
                lambda value: f"{len(value)} rule(s)",
            ),
            (
                "AlertAnalytics.series",
                lambda: alerts.series(window),
                lambda value: f"{len(value)} bucket(s)",
            ),
        ]
        samples: list[Sample] = []
        for label, call, describe in cases:
            samples.append(
                Sample(
                    label=label,
                    route="aggregate query (no HTTP)",
                    status=200,
                    summary=describe(call()),
                    milliseconds=_time_call(call, iterations, _WARMUP_REQUESTS),
                )
            )
        return samples
    finally:
        session.close()


def _phase_resolution(iterations: int) -> list[Sample]:
    """Measure window resolution, which every route performs (M16.7/M16.13).

    It is pure arithmetic over a table of bucket sizes, so it should be a rounding
    error beside a query. Measuring it is how that stops being an assumption: if a
    future change made resolution scan something, this row would say so.
    """
    now = time.time()
    cases: list[tuple[str, Callable[[], Any]]] = [
        (
            "resolve(default)",
            lambda: resolve_window(
                since=None, until=None, bucket_seconds=None, now=now
            ),
        ),
        (
            "resolve(60m)",
            lambda: resolve_window(
                since=now - 3600.0, until=now, bucket_seconds=None, now=now
            ),
        ),
        (
            "resolve(30d, the ceiling)",
            lambda: resolve_window(
                since=now - MAX_WINDOW_SECONDS, until=now, bucket_seconds=None, now=now
            ),
        ),
        (
            "resolve(30m, explicit 10s)",
            lambda: resolve_window(
                since=now - 1800.0, until=now, bucket_seconds=10, now=now
            ),
        ),
    ]
    return [
        Sample(
            label=label,
            route="app.analytics.window.resolve_window",
            status=200,
            summary=(
                f"{call().buckets} bucket(s) of {call().bucket_seconds}s"
            ),
            milliseconds=_time_call(call, iterations, _WARMUP_REQUESTS),
        )
        for label, call in cases
    ]


def _print_table(title: str, samples: list[Sample]) -> None:
    """Print one phase's figures as a table, all in milliseconds.

    The median is printed first because it is the figure to quote: on a machine
    doing anything else at the same time, one slow call moves the mean and leaves
    the median alone, and there is no isolation here to prevent that. The summary
    column says what was measured, so a fast row over an empty window is visibly
    different from a fast row over the whole store.
    """
    print("\n" + "-" * _BANNER_WIDTH)
    print(f"{title}")
    print("-" * _BANNER_WIDTH)
    print(
        f"  {'measurement':<34} {'p50':>7} {'mean':>7} {'p95':>7} {'max':>7}  what"
    )
    for sample in samples:
        print(
            f"  {sample.label:<34} {sample.median:>7.2f} {sample.mean:>7.2f} "
            f"{sample.p95:>7.2f} {sample.worst:>7.2f}  {sample.summary}"
        )
    every = [value for sample in samples for value in sample.milliseconds]
    if every:
        print(
            f"  {len(samples)} measurement(s), {len(every)} timed call(s), "
            f"median across all {stats.median(every):.2f} ms"
        )


def _print_header(args: argparse.Namespace, plan: SeedPlan, sizes: list[int]) -> None:
    """Print what this run is, so a recorded baseline is self-describing.

    A latency figure without the machine, the interpreter and the store shape
    beside it cannot be compared with anything, so the header records all of them
    rather than only the numbers.
    """
    print("=" * _BANNER_WIDTH)
    print("M16 performance baseline - the analytics layer over a seeded store")
    print("=" * _BANNER_WIDTH)
    print(f"  store              : {plan.packets:,} packets, "
          f"{plan.connections:,} connections, {plan.alerts:,} alerts")
    print(f"  seeded span        : {plan.span_seconds / 60.0:.0f} minute(s)")
    print(f"  iterations         : {args.iterations} timed call(s) per measurement")
    print(f"  warm-up requests   : {_WARMUP_REQUESTS} discarded per measurement")
    print(f"  window sweep       : {list(_WINDOW_MINUTES)} minutes "
          f"(bucket ceiling {MAX_BUCKETS} points)")
    print(f"  growth table sizes : {sizes}")
    print(f"  python             : {platform.python_version()} ({platform.machine()})")
    print(f"  platform           : {platform.system()} {platform.release()}")
    print(f"  sqlite             : {sqlite3.sqlite_version}")
    print(
        "  note               : in-process client, one SQLite file, no network "
        "stack - a local baseline, not a capacity claim"
    )


def _run_main_sweep(workdir: Path, args: argparse.Namespace, plan: SeedPlan) -> None:
    """Seed one store and run every phase against it (M16.13)."""
    db_path = workdir / f"bench_m16_{plan.packets}.db"
    engine, factory = _connect_database(db_path)
    try:
        print(f"\nSeeding {plan.packets:,} packet rows into {db_path.name} ...")
        started = time.perf_counter()
        _seed_store(factory, plan)
        print(f"  seeded in {time.perf_counter() - started:.2f}s")

        with _client(factory, engine) as client:
            _print_table(
                "The five analytics routes, over the whole seeded window (M16.11)",
                _phase_requests(client, plan, args.iterations),
            )
            _print_table(
                "The same five routes with no bounds - the one-hour default (M16.7)",
                _phase_default_window(client, args.iterations),
            )
            _print_table(
                "One route as the window lengthens (M16.7)",
                _phase_window_sweep(client, plan, args.iterations),
            )
        _print_table(
            "Aggregate query time, no HTTP (M16.2-M16.6)",
            _phase_queries(engine, plan, args.iterations),
        )
        _print_table(
            "Window resolution, performed by every route (M16.7)",
            _phase_resolution(args.iterations),
        )
    finally:
        engine.dispose()


def _run_size_sweep(
    workdir: Path, args: argparse.Namespace, sizes: list[int], span_seconds: float
) -> None:
    """Measure the heaviest route and the count as the store grows (M16.13).

    "Representative result sizes" is the part of M16.13 that a single store cannot
    answer: whether a route's cost grows with the table is exactly what decides
    whether the SQL-side aggregation is doing its job. Each size is a separate
    throwaway store, so one row is not affected by another.
    """
    print("\n" + "=" * _BANNER_WIDTH)
    print("Representative result sizes - how cost moves with the store (M16.13)")
    print("=" * _BANNER_WIDTH)

    print(
        f"  {'packets':>10}  {'traffic p50':>11}  {'traffic p95':>11}  "
        f"{'db totals p50':>13}  {'db series p50':>13}"
    )
    for size in sizes:
        db_path = workdir / f"size_{size}.db"
        engine, factory = _connect_database(db_path)
        try:
            plan = _plan(size, span_seconds)
            _seed_store(factory, plan)
            with _client(factory, engine) as client:
                traffic = _measure(
                    client,
                    "analytics/traffic",
                    f"{API}/analytics/traffic",
                    iterations=args.iterations,
                    params=_full_window_params(plan),
                )
            window = _resolved_window(plan)
            session = Session(bind=engine)
            try:
                packets = PacketAnalytics(session)
                totals = _time_call(
                    lambda: packets.totals(window), args.iterations, _WARMUP_REQUESTS
                )
                series = _time_call(
                    lambda: packets.series(window), args.iterations, _WARMUP_REQUESTS
                )
            finally:
                session.close()
            print(
                f"  {size:>10,}  {traffic.median:>11.2f}  {traffic.p95:>11.2f}  "
                f"{stats.median(totals):>13.2f}  {stats.median(series):>13.2f}"
            )
        finally:
            engine.dispose()


def _print_closing_note() -> None:
    """State plainly what the figures above are, and are not.

    A benchmark that does not say what it left out invites the numbers to be read
    as a throughput claim. This one is deliberately not that: it is one process over
    one SQLite file with the transport replaced by a function call, and it measures
    a read-only layer over a store that nothing else is writing to.
    """
    print("\n" + "=" * _BANNER_WIDTH)
    print("Read these as a local baseline, not as capacity")
    print("=" * _BANNER_WIDTH)
    print("  * measured  : the five analytics routes, the aggregate queries behind")
    print("                them, and window resolution")
    print("  * excluded  : capture, normalization, M6 statistics, M7 persistence,")
    print("                M8 discovery, M9 tracking, M10 detection, M11 alerting,")
    print("                M12 correlation - each has its own milestone baseline")
    print("  * in-memory : the M8 registry, M9 tracker, M10 engine and M12 registry")
    print("                are empty here, so the live halves measure a fresh process")
    print("  * transport : in-process (TestClient), so no loopback network cost")
    print("  * store     : one SQLite file, single process, single machine, unwritten")
    print("  * use       : compare routes and window shapes, and re-run after a change")


def _parse_sizes(args: argparse.Namespace) -> list[int]:
    """Return the store sizes for the growth table, largest last.

    The size the main sweep used is always included, so the growth table ends on
    the same store the other figures describe and the two can be read together.
    """
    sizes: set[int] = {args.packets}
    for chunk in args.sizes.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            value = int(chunk)
        except ValueError:
            raise SystemExit(f"--sizes expects integers, got {chunk!r}") from None
        if value < 1:
            raise SystemExit(f"--sizes values must be at least 1, got {value}")
        sizes.add(value)
    return sorted(sizes)


def _parse_args() -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(
        description="M16 performance baseline for the analytics layer (M16.13)."
    )
    parser.add_argument(
        "--packets",
        type=int,
        default=10_000,
        help="packet rows to seed into the measured store (default 10000)",
    )
    parser.add_argument(
        "--span-minutes",
        type=float,
        default=60.0,
        help="minutes the seeded rows span (default 60, the documented window)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=20,
        help="timed calls per measurement (default 20)",
    )
    parser.add_argument(
        "--sizes",
        default="1000,50000",
        help="comma-separated extra store sizes for the growth table",
    )
    args = parser.parse_args()
    if args.packets < 1:
        parser.error("--packets must be at least 1")
    if args.iterations < 1:
        parser.error("--iterations must be at least 1")
    if args.span_minutes <= 0:
        parser.error("--span-minutes must be positive")
    if args.span_minutes * 60.0 > MAX_WINDOW_SECONDS:
        parser.error(
            f"--span-minutes must not exceed {int(MAX_WINDOW_SECONDS / 60.0)} "
            "minutes, the longest window the API accepts (M16.7)"
        )
    return args


def _configure_logging() -> None:
    """Quiet the application's loggers so the figures are readable.

    The layers under the analytics API log at INFO as they work, which is right in
    a service and noise over a table of measurements. Nothing is disabled: the
    level is raised, so a warning or worse would still be seen.
    """
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    for name in ("app", "httpx", "httpcore", _LOGGER_NAME):
        logging.getLogger(name).setLevel(logging.WARNING)


def main() -> int:
    """Run every phase and print the baseline (M16.13)."""
    args = _parse_args()
    _configure_logging()
    sizes = _parse_sizes(args)
    span_seconds = args.span_minutes * 60.0
    plan = _plan(args.packets, span_seconds)

    workdir = Path(tempfile.mkdtemp(prefix="netwatch_bench_m16_"))
    try:
        _print_header(args, plan, sizes)
        _run_main_sweep(workdir, args, plan)
        _run_size_sweep(workdir, args, sizes, span_seconds)
        _print_closing_note()
    finally:
        # The stores are throwaway and the developer's database was never touched,
        # so removing the directory is the whole cleanup.
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
