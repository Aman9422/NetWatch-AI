"""M17 performance baseline — report generation over a known store (M17.13).

M17.13 asks that the reporting layer stay suitable for the local SQLite deployment
and that the measurements be recorded as *local development* figures. This script
measures where a report's cost actually is, and nothing else:

* **generation latency, end to end** — a real ``POST /reports/generate`` through
  the real application (``app.main:app``), for CSV and PDF, over a window covering
  the whole seeded store. This is the figure a user waits for;
* **the stage breakdown** — the same report assembled *without* HTTP, so the three
  costs inside it are separated rather than inferred: the analytics queries the
  assembler makes (M16), the rendering of the content model (M17.7/M17.8), and the
  artifact write (M17.9);
* **the row-limit effect** — the same generation at three configured ceilings, to
  show that a report's cost is bounded by the configured cap rather than by the
  size of the store (M17.13);
* **the period-length effect** — a daily, a weekly and a thirty-day period over the
  same store, because the period is the only thing that decides how many rows the
  analytics queries aggregate;
* **the storage and metadata costs** — one artifact write of a fixed payload, which
  is the write a generation performs.

What is deliberately *not* measured: capture, packet normalization, M6 statistics,
M7 persistence, M8 discovery, M9 tracking, M10 detection, M11 alerting and M12
correlation. Those are M5-M12 costs and each has its own milestone baseline. This
one starts from a seeded store, because M17.13 is about what the *reporting* layer
adds on top of data that already exists.

**Why the store is seeded rather than captured.** Driving packets through the real
pipeline would measure the pipeline, not the reports, and would take minutes rather
than seconds. Rows are inserted directly through the models instead, into a
throwaway SQLite file under the OS temp directory that this script creates and
removes. The developer's ``netwatch.db`` is never opened, and because the reports
layer writes artifacts, the storage directory is a throwaway one too.

**What the in-memory half reports.** The device section reads the M8 registry and
the threat section reads the M10 engine and M12 registry. Those are empty here,
which is the honest state of a freshly started backend that has captured nothing:
the figures therefore describe the route's fixed cost plus its database work, and
the stored blocks that make up the bulk of a report are measured over a seeded
store.

**This is a local, single-machine baseline, not a capacity claim.** One process,
one SQLite file, an in-process test client (so no loopback network stack), on an
otherwise idle machine. The seed is deterministic, so two runs are comparable;
what the numbers are good for is comparing formats, row limits and period lengths
against each other, and re-measuring after a change.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m17.py
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m17.py --packets 100000
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m17.py --iterations 30
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m17.py --span-hours 168
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

from fastapi import Depends  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, event  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.alerts.dedup import KEY_SEPARATOR  # noqa: E402
from app.alerts.queries import AlertQueries  # noqa: E402
from app.analytics.service import AnalyticsService  # noqa: E402
from app.analytics.window import iso_from_epoch  # noqa: E402
from app.api.v1.deps import (  # noqa: E402
    get_alert_queries,
    get_analytics_service,
    get_db,
    get_report_service,
)
from app.config.settings import Settings, settings  # noqa: E402
from app.connections.manager import ConnectionTracker  # noqa: E402
from app.correlation.engine import CorrelationEngine  # noqa: E402
from app.correlation.registry import IncidentRegistry  # noqa: E402
from app.correlation.window import CorrelationWindow  # noqa: E402
from app.detection import DetectionEngine, build_default_rules  # noqa: E402
from app.devices.manager import DeviceDiscoveryManager  # noqa: E402
from app.main import app  # noqa: E402
from app.reports.assembler import build_report_content  # noqa: E402
from app.reports.period import (  # noqa: E402
    CUSTOM,
    DAILY,
    MAX_REPORT_PERIOD_SECONDS,
    WEEKLY,
    ReportPeriod,
    resolve_custom,
    resolve_daily,
    resolve_weekly,
)
from app.reports.renderers import render_report  # noqa: E402
from app.reports.requests import SUPPORTED_FORMATS  # noqa: E402
from app.reports.service import ReportService  # noqa: E402
from app.reports.status import ReportStatus  # noqa: E402
from app.reports.storage import ReportStorage  # noqa: E402
from app.risk.contributions import ScoringBounds  # noqa: E402
from app.risk.engine import RiskScoringEngine  # noqa: E402
from app.statistics.manager import TrafficStatisticsManager  # noqa: E402

_BANNER_WIDTH = 66

#: The versioned base every route below is measured against (M13.3).
API = "/api/v1"
REPORTS_URL = f"{API}/reports"
GENERATE_URL = f"{REPORTS_URL}/generate"

#: Protocol labels alternated across the seeded packets, so a protocol breakdown
#: has more than one group and a ranking is a real ranking.
_PROTOCOLS = ("TCP", "UDP", "ICMP")

#: Distinct source addresses and destination ports the seeded packets spread over.
_SOURCE_COUNT = 250
_PORT_COUNT = 200

#: How many conversations and alerts are seeded relative to the packet count.
_CONNECTION_RATIO = 0.01
_ALERT_RATIO = 0.002

_SEVERITIES = ("critical", "high", "medium", "low")
_ALERT_STATUSES = ("open", "acknowledged", "resolved", "dismissed")
_CONNECTION_STATUSES = ("active", "completed", "timeout")
_RULE_KEYS = ("port_scan", "syn_flood", "icmp_flood", "high_bandwidth")

#: How many rows are written per commit while seeding.
_SEED_BATCH = 1000

#: Repeated calls a measurement discards before recording. The first request to a
#: route pays for lazy construction, and the first PDF render pays for a font
#: lookup, neither of which is a steady-state cost.
_WARMUP_CALLS = 2

#: The configured row ceilings the row-limit phase compares. The last is far above
#: the analytics layer's own group cap, so it measures the cap rather than the
#: setting.
_ROW_LIMITS = (5, 100, 100_000)

#: The row limit the generation phase uses: the shipped default, so the headline
#: figure is the configuration a user actually runs.
_DEFAULT_ROW_LIMIT = 100


@dataclass(frozen=True)
class SeedPlan:
    """What the throwaway store holds, and when it happened (M17.13).

    The instants are absolute epoch seconds decided once, before seeding, so every
    seeded row is dated relative to the same base and two runs describe the same
    store shape.
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

    The span ends one second before the run's start instant, so a period whose
    ``until`` is the newest seeded row still includes it.
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
    """Convert epoch seconds to the naive UTC datetime the stores persist."""
    return datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc).replace(
        tzinfo=None
    )


def _connect_database(db_path: Path):
    """Create the isolated SQLite database and a session factory (M17.13).

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
    """Insert the plan's packet rows directly into the store (M17.13).

    Only metadata is written, because metadata is all M7 ever stores (M7.5), so no
    figure below is inflated by data the production path would never have written.
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
                    source_port=None if index % 30 == 0 else 40000 + port_index,
                    destination_port=None if index % 37 == 0 else 1 + (port_index % 1024),
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
    """Insert the plan's conversation rows directly into the store (M17.13).

    Each row is shaped like one M9 writes: a ``start_time`` inside the span, a
    status from M9's vocabulary, and an ``end_time`` for every conversation that is
    not still active, so the duration statistics have samples.
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
    """Insert the plan's alert rows directly into the store (M17.13).

    The rows span every M11 severity, every lifecycle state and every M12 risk
    band, and all but every twentieth carries a correlation key of the shape M11
    writes, so the threat section's histograms are exercised by data rather than
    measured over empty tables or over a single group.
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
                    risk_score=(index * 7) % 101,
                    confidence=(index * 11) % 101,
                    status=_ALERT_STATUSES[index % len(_ALERT_STATUSES)],
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
    """Seed every table the reporting layer reads (M17.13)."""
    _seed_packets(factory, plan)
    _seed_connections(factory, plan)
    _seed_alerts(factory, plan)


@dataclass
class AnalyticsEnvironment:
    """The six M16 collaborators a report is assembled from (M17.3).

    The in-memory ones are fresh and empty, which is the state of a backend that
    has captured nothing in this process; the alert read service is backed by the
    seeded store, because the stored alert blocks are what a report mostly is.
    """

    statistics: TrafficStatisticsManager
    devices: DeviceDiscoveryManager
    tracker: ConnectionTracker
    detections: DetectionEngine
    correlations: CorrelationEngine
    alerts: AlertQueries


def _build_environment(factory) -> AnalyticsEnvironment:
    """Return a fresh environment of analytics collaborators over ``factory``."""
    return AnalyticsEnvironment(
        statistics=TrafficStatisticsManager(),
        devices=DeviceDiscoveryManager(),
        tracker=ConnectionTracker(autostart_cleanup=False),
        detections=DetectionEngine(build_default_rules(Settings())),
        correlations=CorrelationEngine(
            window=CorrelationWindow(
                seconds=900.0, proximity_seconds=300.0, max_span_seconds=900.0
            ),
            registry=IncidentRegistry(
                max_incidents=256,
                retention_seconds=3600.0,
                max_members=64,
                max_reasons=16,
                clock=time.time,
            ),
            risk=RiskScoringEngine(ScoringBounds(volume_alerts=5)),
            anchor_threshold=0.55,
            min_confidence=0.5,
            risk_persistence=None,
            clock=time.time,
        ),
        alerts=AlertQueries(session_factory=factory),
    )


def _analytics_over(db: Session, environment: AnalyticsEnvironment) -> AnalyticsService:
    """Return the M16 analytics service over one session and ``environment``."""
    return AnalyticsService(
        db=db,
        statistics=environment.statistics,
        devices=environment.devices,
        tracker=environment.tracker,
        alerts=environment.alerts,
        detections=environment.detections,
        correlations=environment.correlations,
    )


def _build_overrides(db_engine, artifacts: Path, environment) -> dict:
    """Return the dependency overrides that point the API at the seeded store.

    Each key is the *dependency function* a route declares in ``Depends``, so the
    route still resolves its collaborator through FastAPI and the wiring stays the
    application's rather than this script's (M13.28). The reports service is
    assembled exactly as the application assembles it -- same session, same
    analytics service over it -- with only the storage directory replaced, so a
    measured generation writes a real artifact into a throwaway directory.
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

    def reports_override(
        db: Session = Depends(get_db),
        analytics: AnalyticsService = Depends(get_analytics_service),
    ) -> ReportService:
        """Build the reporting service over this request's session and storage."""
        return ReportService(
            db=db, analytics=analytics, storage=ReportStorage(artifacts)
        )

    def analytics_override() -> Generator[AnalyticsService, None, None]:
        """Yield the analytics service over its own session, closed afterwards.

        The application assembles the service per request because its session is
        request-scoped; a generator dependency reproduces that exactly, so each
        measured request opens and closes one connection rather than accumulating
        sessions for the length of the run. The six collaborators are the seeded
        environment's, so the alert blocks are read from the seeded store.
        """
        session = Session(bind=db_engine)
        try:
            yield _analytics_over(session, environment)
        finally:
            session.close()

    return {
        get_db: db_override,
        get_analytics_service: analytics_override,
        get_alert_queries: lambda: environment.alerts,
        get_report_service: reports_override,
    }


@contextmanager
def _client(
    db_engine, artifacts: Path, environment
) -> Generator[TestClient, None, None]:
    """Yield a client over the real application, reading the seeded store.

    Every response timed below is produced by the production router, over the
    production reporting service, rendered by the production renderers -- the
    figure is the reporting layer's cost, not a re-implementation of it.

    The environment is temporarily ``"test"`` so the application's lifespan skips
    ``init_db()`` and never touches the developer's database, and the storage
    directory is temporarily the throwaway one, so a generation cannot write into
    the configured ``reports/`` directory either.
    """
    overrides = _build_overrides(db_engine, artifacts, environment)
    original_env = settings.app_env
    original_directory = settings.report_storage_dir
    settings.app_env = "test"
    settings.report_storage_dir = str(artifacts)
    for dependency, value in overrides.items():
        app.dependency_overrides[dependency] = value
    try:
        with TestClient(app) as client:
            yield client
    finally:
        for dependency in overrides:
            app.dependency_overrides.pop(dependency, None)
        settings.app_env = original_env
        settings.report_storage_dir = original_directory


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

        The median is the headline figure: on a machine doing anything else at the
        same time, one slow call moves the mean and leaves the median alone.
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


def _time_calls(call: Callable[[], Any], iterations: int, warmup: int) -> list[float]:
    """Time ``iterations`` calls to ``call`` in milliseconds, after warming up."""
    for _ in range(warmup):
        call()
    samples: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        call()
        samples.append((time.perf_counter() - start) * 1000.0)
    return samples


def _report_of(body: dict[str, Any]) -> dict[str, Any]:
    """Return the report block of a generation payload, or an empty dict."""
    inner = body.get("data")
    if not isinstance(inner, dict):
        return {}
    report = inner.get("report")
    return report if isinstance(report, dict) else {}


# ---------------------------------------------------------------------------
# Presenting a measurement
# ---------------------------------------------------------------------------


def _rule(character: str = "=") -> str:
    """Return one full-width horizontal rule."""
    return character * _BANNER_WIDTH


def _heading(title: str) -> None:
    """Print one phase heading."""
    print()
    print(_rule())
    print(title)
    print(_rule())


def _print_table(header: tuple[str, ...], rows: list[tuple[str, ...]]) -> None:
    """Print one aligned table, sized to its own content.

    The widths are computed per table rather than fixed, because several columns
    are prose ("daily preset, 2026-10-10") and a fixed width would either clip a
    label or leave the figures far from their heading.
    """
    widths = [len(cell) for cell in header]
    for row in rows:
        for index, cell in enumerate(row):
            if index < len(widths):
                widths[index] = max(widths[index], len(str(cell)))
    print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(header)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))


#: The columns every timing table prints, so one phase's table lines up with the
#: next one's and a reader can compare two phases by scanning one column.
TIMING_COLUMNS: tuple[str, ...] = (
    "measurement",
    "status",
    "median ms",
    "mean ms",
    "p95 ms",
    "worst ms",
    "what it produced",
)


def _sample_row(sample: Sample) -> tuple[str, ...]:
    """Render one measurement as a table row."""
    return (
        sample.label,
        str(sample.status),
        f"{sample.median:.2f}",
        f"{sample.mean:.2f}",
        f"{sample.p95:.2f}",
        f"{sample.worst:.2f}",
        sample.summary,
    )


def _print_samples(samples: list[Sample]) -> None:
    """Print one phase's measurements as an aligned table."""
    _print_table(TIMING_COLUMNS, [_sample_row(sample) for sample in samples])


@dataclass
class _Exchange:
    """The most recent request a timed callable performed.

    A timing helper returns durations only, so the callable records what it last
    received here. The summary printed beside a figure therefore comes from the
    measured call itself and not from a second request made afterwards, which would
    describe a different report.
    """

    status: int = 0
    body: dict[str, Any] = field(default_factory=dict)


def _human_bytes(size: object) -> str:
    """Render a byte count in the unit a reader thinks in."""
    if not isinstance(size, (int, float)):
        return "n/a"
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(value) < 1024.0 or unit == "GiB":
            return f"{int(value)} B" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{value:.2f} GiB"


def _summary_value(body: dict[str, Any], label: str) -> str:
    """Return one summary figure's value from a generation payload."""
    inner = body.get("data")
    if not isinstance(inner, dict):
        return ""
    summary = inner.get("summary")
    if not isinstance(summary, list):
        return ""
    for metric in summary:
        if isinstance(metric, dict) and metric.get("label") == label:
            return str(metric.get("value", ""))
    return ""


def _generation_summary(report: dict[str, Any], body: dict[str, Any]) -> str:
    """Describe what one generation produced, so a fast figure is a fast *report*.

    The headline figures are read back out of the response's own summary block, so
    a reader can see that the measured window really selected the seeded records
    rather than that a fast number was measured over an empty one.
    """
    if not report:
        return "no report block in the response"
    packets = _summary_value(body, "Packets stored in period") or "n/a"
    alerts = _summary_value(body, "Alerts recorded in period") or "n/a"
    return (
        f"{report.get('report_type')} {report.get('format')} "
        f"{report.get('status')} {_human_bytes(report.get('file_size'))} "
        f"| packets={packets} alerts={alerts}"
    )


def _content_summary(content) -> str:
    """Describe an assembled report: its sections, its tables and its rows."""
    tables = [table for section in content.sections for table in section.tables]
    rows = sum(len(table.rows) for table in tables)
    available = sum(1 for section in content.sections if section.available)
    return (
        f"{available}/{len(content.sections)} sections available, "
        f"{len(content.summary)} summary metrics, {len(tables)} tables, "
        f"{rows} rows"
    )


# ---------------------------------------------------------------------------
# The phases
# ---------------------------------------------------------------------------


def _store_period(plan: SeedPlan) -> ReportPeriod:
    """Return the custom period covering everything the plan seeded.

    Both bounds are pulled one second outside the seeded span, so the first and the
    last seeded row both fall inside a half-open interval that starts before the
    first and ends after the last.
    """
    return resolve_custom(
        since=plan.start_epoch - 1.0,
        until=plan.end_epoch + 1.0,
    )


def _measured_generation(
    *,
    client: TestClient,
    body: dict[str, Any],
    iterations: int,
    warmup: int,
    label: str,
) -> Sample:
    """Time ``POST /reports/generate`` with ``body`` (M17.12).

    The body is supplied by the caller rather than built here, so a phase can ask
    the route the exact question it means to compare: the whole seeded store, a
    calendar preset, or the layer's longest allowed period.
    """
    exchange = _Exchange()

    def call() -> None:
        response = client.post(GENERATE_URL, json=body)
        exchange.status = response.status_code
        exchange.body = response.json()

    times = _time_calls(call, iterations, warmup)
    return Sample(
        label=label,
        route=GENERATE_URL,
        status=exchange.status,
        summary=_generation_summary(_report_of(exchange.body), exchange.body),
        milliseconds=times,
    )


def _custom_generation_body(
    period: ReportPeriod, *, output_format: str, title: str
) -> dict[str, Any]:
    """Return a generation body asking about an explicit half-open period.

    Both custom bodies in this script go through here, so only the *window* differs
    between the headline question and the ceiling question and neither can drift
    into formatting its bounds differently.
    """
    return {
        "report_type": CUSTOM,
        "format": output_format,
        "title": title,
        "since": period.iso_since(),
        "until": period.iso_until(),
    }


def _store_generation_body(
    plan: SeedPlan, *, output_format: str, title: str
) -> dict[str, Any]:
    """Return a generation body asking about the whole seeded store.

    A custom period is used for the headline figure rather than a preset, so the
    request selects exactly the seeded data whichever calendar day the benchmark
    happens to run on. A daily report generated on a quiet day would measure a
    report about nothing.
    """
    return _custom_generation_body(
        _store_period(plan), output_format=output_format, title=title
    )


def _preset_generation_body(report_type: str, *, title: str) -> dict[str, Any]:
    """Return a generation body for a calendar preset, carrying no bounds.

    A preset derives its period from the UTC calendar and the API refuses one that
    also carries bounds, so the body names only the type -- which is what makes this
    phase exercise the preset's own resolution rather than a custom period that
    happens to have the same bounds.
    """
    return {"report_type": report_type, "format": "CSV", "title": title}


def _generation_samples(
    client: TestClient, plan: SeedPlan, iterations: int, warmup: int
) -> list[Sample]:
    """Measure a generation in every format the layer supports (M17.7/M17.8)."""
    return [
        _measured_generation(
            client=client,
            body=_store_generation_body(
                plan,
                output_format=output_format,
                title=f"Benchmark generation ({output_format})",
            ),
            iterations=iterations,
            warmup=warmup,
            label=f"POST /reports/generate ({output_format})",
        )
        for output_format in SUPPORTED_FORMATS
    ]


@dataclass
class _StageCosts:
    """The three costs inside one generation, measured apart (M17.13)."""

    assembly: Sample
    rendering: Sample
    write: Sample
    payload_bytes: int


def _stage_costs(
    *,
    db_engine,
    environment: AnalyticsEnvironment,
    artifacts: Path,
    plan: SeedPlan,
    iterations: int,
    warmup: int,
) -> _StageCosts:
    """Time assembly, rendering and the artifact write as three separate steps.

    The decomposition is exactly the one ``ReportService.generate`` performs, done
    without the metadata row and without HTTP: the same assembler over the same
    analytics service, the same renderer, the same storage. Splitting it is what
    turns "a report takes N milliseconds" into "N is mostly *this*".

    The assembly call opens and closes its own session, because that is what a
    request does; a session reused across iterations would accumulate an identity
    map and make the later figures describe a warm cache instead of a query.
    """
    period = _store_period(plan)
    generated_at = _iso(time.time())
    storage = ReportStorage(artifacts)
    holder: dict[str, Any] = {}

    def assemble() -> None:
        session = Session(bind=db_engine)
        try:
            holder["content"] = build_report_content(
                analytics=_analytics_over(session, environment),
                period=period,
                output_format="CSV",
                generated_at=generated_at,
                title="Benchmark stage sample",
                row_limit=_DEFAULT_ROW_LIMIT,
            )
        finally:
            session.close()

    assembly_times = _time_calls(assemble, iterations, warmup)
    content = holder.get("content")
    if content is None:
        raise RuntimeError("the stage sample could not be assembled")

    render_times = _time_calls(lambda: render_report(content), iterations, warmup)
    payload = render_report(content)
    write_times = _time_calls(
        lambda: storage.write(filename="benchmark-stage-sample.csv", payload=payload),
        iterations,
        warmup,
    )
    return _StageCosts(
        assembly=Sample(
            label="assemble (analytics queries -> content model)",
            route="build_report_content",
            status=200,
            summary=_content_summary(content),
            milliseconds=assembly_times,
        ),
        rendering=Sample(
            label="render (content model -> bytes)",
            route="render_report",
            status=200,
            summary=f"CSV encoder, {_human_bytes(len(payload))} out per call",
            milliseconds=render_times,
        ),
        write=Sample(
            label="write artifact (temp file + fsync + replace)",
            route="ReportStorage.write",
            status=200,
            summary=f"{_human_bytes(len(payload))} written per call",
            milliseconds=write_times,
        ),
        payload_bytes=len(payload),
    )


def _row_limit_samples(
    client: TestClient, plan: SeedPlan, iterations: int, warmup: int
) -> list[Sample]:
    """Measure the same generation at three configured row ceilings (M17.13).

    The setting is the only thing that changes: the store, the period and the format
    are the same in every row. A column that stays flat is what shows the cost is
    bounded by the configured cap rather than by how much the store holds, which is
    the claim M17.13 makes. The last ceiling is far above the analytics layer's own
    group cap, so it measures that cap rather than the setting.
    """
    original = settings.report_max_table_rows
    samples: list[Sample] = []
    try:
        for limit in _ROW_LIMITS:
            settings.report_max_table_rows = limit
            samples.append(
                _measured_generation(
                    client=client,
                    body=_store_generation_body(
                        plan,
                        output_format="CSV",
                        title=f"Benchmark row limit {limit}",
                    ),
                    iterations=iterations,
                    warmup=warmup,
                    label=f"row limit {limit}",
                )
            )
    finally:
        settings.report_max_table_rows = original
    return samples


def _period_samples(
    client: TestClient, plan: SeedPlan, iterations: int, warmup: int
) -> list[Sample]:
    """Measure generation over a daily, a weekly and the longest allowed period.

    All three cover the same store, so the only difference is how many instants the
    analytics queries have to scan. The two presets are resolved from the UTC
    calendar here only to *name* the window in the table; the request itself carries
    the preset so the route resolves it. The third is at the layer's own ceiling
    (:data:`MAX_REPORT_PERIOD_SECONDS`), which is the largest question a caller can
    ask and therefore the worst case this layer can be made to answer.
    """
    now = plan.end_epoch + 1.0
    daily = resolve_daily(now=now)
    weekly = resolve_weekly(now=now)
    thirty_days = resolve_custom(since=now - MAX_REPORT_PERIOD_SECONDS, until=now)
    questions: tuple[tuple[str, dict[str, Any]], ...] = (
        (
            f"daily preset ({daily.label()})",
            _preset_generation_body(DAILY, title=f"Benchmark daily {daily.label()}"),
        ),
        (
            f"weekly preset ({weekly.label()})",
            _preset_generation_body(WEEKLY, title=f"Benchmark weekly {weekly.label()}"),
        ),
        (
            "custom at the period ceiling (30 days)",
            _custom_generation_body(
                thirty_days,
                output_format="CSV",
                title="Benchmark thirty-day period",
            ),
        ),
    )
    return [
        _measured_generation(
            client=client,
            body=body,
            iterations=iterations,
            warmup=warmup,
            label=label,
        )
        for label, body in questions
    ]


#: The payload size the fixed artifact write uses. Large enough that the write and
#: its ``fsync`` cost something measurable, small enough to stay a fair sample of
#: the artifacts a report of a few hundred rows actually produces.
_ARTIFACT_BYTES = 64 * 1024

#: Packets seeded when the command line names no count. Enough that a scan of the
#: packet table costs something measurable, few enough that seeding takes seconds
#: rather than minutes.
_DEFAULT_PACKETS = 10_000

#: How long the seeded traffic spans when the command line names no span, in hours.
#: A week, so the previous completed UTC day *and* the previous completed UTC week
#: both fall inside the store and the preset rows of the period phase really select
#: records.
_DEFAULT_SPAN_HOURS = 168.0

#: Generations per measurement when the command line names no count.
_DEFAULT_ITERATIONS = 10


def _storage_samples(
    factory, artifacts: Path, iterations: int, warmup: int
) -> list[Sample]:
    """Time the two writes a generation performs, apart from the report itself.

    The artifact is written at a fixed payload size, because the write's cost is a
    function of the bytes and not of what the bytes say; the metadata insert is one
    row, so its cost is the cost of committing one row. Neither is timed through the
    route, because both are steps *inside* the figure phase 1 reports.
    """
    from app.repositories.report import ReportRepository

    payload = b"x" * _ARTIFACT_BYTES
    storage = ReportStorage(artifacts)
    write_times = _time_calls(
        lambda: storage.write(filename="benchmark-fixed-payload.csv", payload=payload),
        iterations,
        warmup,
    )

    def insert() -> None:
        session = factory()
        try:
            moment = datetime.now(timezone.utc).replace(tzinfo=None)
            ReportRepository(session).create_report(
                name="Benchmark metadata row",
                report_type=CUSTOM,
                report_format="CSV",
                file_path="benchmark-metadata.csv",
                generated_at=moment,
                status=ReportStatus.COMPLETED,
                period_start=moment,
                period_end=moment,
                generated_by=None,
            )
        finally:
            session.close()

    insert_times = _time_calls(insert, iterations, warmup)
    return [
        Sample(
            label=f"write one {_human_bytes(_ARTIFACT_BYTES)} artifact",
            route="ReportStorage.write",
            status=200,
            summary="temp file + fsync + atomic replace, fixed payload",
            milliseconds=write_times,
        ),
        Sample(
            label="insert one report metadata row",
            route="ReportRepository.create_report",
            status=200,
            summary="one row, one commit",
            milliseconds=insert_times,
        ),
    ]


def _parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    """Return the parsed command line."""
    parser = argparse.ArgumentParser(
        prog="benchmark_m17.py",
        description=(
            "Measure M17 report generation over a seeded local SQLite store. Every "
            "figure is a local development measurement and not a capacity claim."
        ),
    )
    parser.add_argument(
        "--packets",
        type=int,
        default=_DEFAULT_PACKETS,
        help=f"packet rows to seed (default: {_DEFAULT_PACKETS})",
    )
    parser.add_argument(
        "--span-hours",
        type=float,
        default=_DEFAULT_SPAN_HOURS,
        help=(
            "how long the seeded traffic spans, in hours "
            f"(default: {_DEFAULT_SPAN_HOURS:g})"
        ),
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=_DEFAULT_ITERATIONS,
        help=f"generations per measurement (default: {_DEFAULT_ITERATIONS})",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=_WARMUP_CALLS,
        help=(
            "warm-up calls discarded before each measurement "
            f"(default: {_WARMUP_CALLS})"
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="let the application's own INFO logging through while measuring",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="keep the throwaway store and its artifacts instead of removing them",
    )
    return parser.parse_args(argv)


def _print_environment(plan: SeedPlan, *, iterations: int, warmup: int) -> None:
    """Print what the run measures over: the machine, the store and the settings."""
    print(_rule())
    print("M17 report generation -- local development baseline (M17.13)")
    print(_rule())
    print(f"machine             : {platform.platform()}")
    print(f"python              : {platform.python_version()}")
    print(f"sqlite              : {sqlite3.sqlite_version}")
    print("store               : throwaway SQLite file in a temporary directory")
    print("artifacts           : throwaway directory, same temporary directory")
    print("client              : in-process (no loopback network stack)")
    print()
    print(f"seeded packets      : {plan.packets:,}")
    print(f"seeded conversations: {plan.connections:,}")
    print(f"seeded alerts       : {plan.alerts:,}")
    print(f"seeded span         : {plan.span_seconds / 3600.0:.2f} h")
    print(f"row limit setting   : {settings.report_max_table_rows}")
    print(f"period ceiling      : {int(MAX_REPORT_PERIOD_SECONDS)} s")
    print(
        f"iterations          : {iterations} per measurement, "
        f"{warmup} warm-up call(s)"
    )
    print(_rule("-"))
    print("Figures are wall-clock milliseconds measured in this process: one machine,")
    print("one SQLite file, an in-process client. They are local development figures")
    print("and are not a production capacity claim (M17.13).")


def main(argv: list[str] | None = None) -> int:
    """Run every phase over a throwaway store and print the baseline (M17.13)."""
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    arguments = _parse_arguments(argv)
    if arguments.verbose:
        logging.disable(logging.NOTSET)
    else:
        # The application logs a line per generation and per artifact write through
        # its own handlers, and those lines make a table of figures unreadable. Only
        # INFO and below are dropped, so a warning or an error still reaches the
        # operator and nothing real is hidden.
        logging.disable(logging.INFO)
    span_seconds = float(arguments.span_hours) * 3600.0

    if arguments.packets < 1:
        print("--packets must be at least 1", file=sys.stderr)
        return 2
    if span_seconds <= 0.0:
        print("--span-hours must be positive", file=sys.stderr)
        return 2
    if span_seconds > MAX_REPORT_PERIOD_SECONDS:
        print(
            "--span-hours is longer than the "
            f"{int(MAX_REPORT_PERIOD_SECONDS)} s report period ceiling, so no report "
            "could cover the seeded store",
            file=sys.stderr,
        )
        return 2
    if arguments.iterations < 1:
        print("--iterations must be at least 1", file=sys.stderr)
        return 2
    if arguments.warmup < 0:
        print("--warmup must not be negative", file=sys.stderr)
        return 2

    plan = _plan(arguments.packets, span_seconds)
    workspace = Path(tempfile.mkdtemp(prefix="netwatch-m17-bench-"))
    database_path = workspace / "benchmark.db"
    artifacts = workspace / "reports"

    _print_environment(
        plan, iterations=arguments.iterations, warmup=arguments.warmup
    )
    engine, factory = _connect_database(database_path)
    try:
        print()
        print(f"seeding {plan.packets:,} packet row(s) ...")
        seeding_started = time.perf_counter()
        _seed_store(factory, plan)
        print(f"seeded in {time.perf_counter() - seeding_started:.2f} s")

        environment = _build_environment(factory)
        with _client(engine, artifacts, environment) as client:
            _heading("1. Generation, end to end (a report over the whole seeded store)")
            _print_samples(
                _generation_samples(
                    client, plan, arguments.iterations, arguments.warmup
                )
            )

            _heading("2. Where one generation's time goes (assembly, render, write)")
            stages = _stage_costs(
                db_engine=engine,
                environment=environment,
                artifacts=artifacts,
                plan=plan,
                iterations=arguments.iterations,
                warmup=arguments.warmup,
            )
            _print_samples([stages.assembly, stages.rendering, stages.write])

            _heading("3. Configured row limit (same store, same period, same format)")
            _print_samples(
                _row_limit_samples(client, plan, arguments.iterations, arguments.warmup)
            )

            _heading("4. Period length (same store, different windows)")
            _print_samples(
                _period_samples(client, plan, arguments.iterations, arguments.warmup)
            )

            _heading("5. Storage and metadata writes")
            _print_samples(
                _storage_samples(
                    factory, artifacts, arguments.iterations, arguments.warmup
                )
            )

        _heading("Reading these figures")
        for line in (
            "* The median is the headline: one slow call moves the mean, not the median.",
            "* 'assemble' is the analytics work plus the content model; 'render' and",
            "  'write' are the two steps after it. A generation is those three plus the",
            "  HTTP layer and the metadata row.",
            "* The row-limit column should stay flat: a report's cost is bounded by the",
            "  configured cap and not by how much the store holds (M17.13).",
            "* The period column grows with the window because the window decides how",
            "  many rows SQLite scans. That is the query, not a defect.",
            "* The device, incident and detection-counter blocks are empty here, exactly",
            "  as they are in a backend that has captured nothing, so the stored blocks",
            "  of the seeded store are what these figures describe.",
            "* A preset row shows the packets the *calendar* window selected, which is",
            "  why it is smaller than the whole-store row: it is the previous completed",
            "  UTC day or week and not the seeded span.",
        ):
            print(line)
        print()
        print("Recorded M17.13 baseline: this machine, this store, the medians above.")
    finally:
        engine.dispose()
        if arguments.keep:
            print(f"kept the throwaway store at {workspace}")
        else:
            shutil.rmtree(workspace, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
