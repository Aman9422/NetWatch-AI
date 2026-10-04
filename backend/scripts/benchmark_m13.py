"""M13 performance baseline — the REST API over a known store (M13.37).

M13.37 asks for figures at the three places a request can cost something, and
this script measures exactly those and nothing else:

* **request latency** — the wall time of a real HTTP request through the real
  application (``app.main:app``), split into the kinds M13.37 names: a simple
  endpoint that touches no store, a list endpoint, a filtered query, a paginated
  query and the dashboard aggregate;
* **database query time** — the same list and count measured directly on
  :class:`~app.services.packet_query.PacketQueryService`, with no FastAPI and no
  JSON in the way, so the part of a list request that is database work is
  *measured* rather than inferred by subtraction;
* **JSON serialization cost** — the time to render a page payload, which is the
  other part of a list request that is not query time.

What is deliberately *not* measured: capture, packet normalization, statistics,
device tracking, connection tracking, detection, alerting and correlation. Those
are M5–M12 costs and each milestone has its own baseline; this one starts from a
seeded store because M13.37 is about what the API layer adds on top.

The store is a throwaway SQLite file under the OS temp directory, created and
removed by this script, so a run never touches the developer's ``netwatch.db``.
Rows are inserted directly through the model rather than driven through the
capture path: driving 10,000 packets through normalization, statistics, device
tracking, connection tracking, detection and correlation would measure those
layers, not this one, and would take minutes rather than seconds.

**This is a local, single-machine baseline, not a capacity claim.** It is one
process, one SQLite file, an in-process test client (so no loopback network
stack) on an otherwise idle machine. The absolute numbers are therefore far more
optimistic than a deployed service would see. What they are good for is
comparing endpoints against each other, and re-measuring after a change: the
seed is deterministic, so two runs of this script are comparable.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m13.py
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m13.py --packets 50000
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m13.py --iterations 100
"""

from __future__ import annotations

import argparse
import json
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

from app.alerts.queries import AlertQueries  # noqa: E402
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
from app.services.packet_query import (  # noqa: E402
    DEFAULT_PACKET_LIMIT,
    PacketQueryService,
)
from app.statistics.manager import (  # noqa: E402
    TrafficStatisticsManager,
    get_statistics_manager,
)

_BANNER_WIDTH = 66

#: The versioned base every route below is measured against (M13.3).
API = "/api/v1"

#: Fixed observation time for the seeded rows, so no row's age depends on when
#: the script happened to start and two runs describe the same store.
#: 2026-01-01T00:00:00Z.
_BASE_TIME = 1_767_225_600.0

#: Protocol labels alternated across the seeded rows, so a protocol filter keeps
#: about half the store and is a real filter rather than a no-op.
_PROTOCOLS = ("TCP", "UDP")

#: How many rows are written per commit while seeding: large enough that the
#: insert cost stays in the seconds, small enough not to hold a whole store of
#: ORM objects in one transaction.
_SEED_BATCH = 1000

#: The page sizes swept by the paginated measurement. 10 exercises the small-page
#: path, 100 is the documented default and 1000 the documented maximum, so the
#: sweep covers the whole range the pagination contract allows (M13.24).
_PAGE_SIZES = (10, DEFAULT_PACKET_LIMIT, 1000)

#: The address the filtered-query measurement asks for. Every seeded row has a
#: unique source, so this selects exactly one row and is the cheapest possible
#: address lookup.
_FILTER_SOURCE_IP = "10.0.0.10"

#: Repeated requests a measurement discards before it starts recording. The first
#: request to a route pays for lazy construction (the routers, the query service,
#: the dependants), which is a once-per-process cost and would otherwise be
#: reported as the route's latency.
_WARMUP_REQUESTS = 3

_LOGGER_NAME = "netwatch.benchmark.m13"


def _timestamp_for(index: int) -> datetime:
    """Return the naive UTC timestamp for the ``index``-th seeded row.

    It is naive because that is what M7 stores: the capture path converts to UTC
    and drops the offset, so a seeded row is shaped like a captured one.
    """
    return datetime.fromtimestamp(
        _BASE_TIME + index * 0.001, tz=timezone.utc
    ).replace(tzinfo=None)


def _connect_database(db_path: Path):
    """Create the isolated SQLite database and a session factory (M13.37).

    Foreign keys are enabled, so the store carries the same constraint the
    shipped one does, and the same pragmas are otherwise left alone — the figures
    should describe the shipped engine, not a differently configured one.
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


def _seed_packets(factory, count: int) -> None:
    """Insert ``count`` packet rows directly into the store (M13.37).

    Only metadata is written, because metadata is all M7 ever stores — no row
    here carries a payload (M7.5), so nothing measured below is inflated by data
    the production path would never have written.
    """
    from app.models.packet import Packet

    session = factory()
    try:
        batch: list[Any] = []
        for index in range(count):
            batch.append(
                Packet(
                    timestamp=_timestamp_for(index),
                    source_ip=f"10.{(index >> 16) & 0xFF}.{(index >> 8) & 0xFF}.{index & 0xFF}",
                    destination_ip="203.0.113.9",
                    source_port=40000 + (index % 2000),
                    destination_port=443,
                    protocol=_PROTOCOLS[index % len(_PROTOCOLS)],
                    packet_length=64 + (index % 512),
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


def _build_overrides(factory, db_engine) -> dict:
    """Return the dependency overrides that point the API at the seeded store.

    Each key is a *dependency function* a route declares in ``Depends``, so the
    route still resolves its collaborator through FastAPI and the wiring stays the
    application's rather than this script's (M13.28).

    Only dependencies that would otherwise escape the isolated store — or start
    the production capture pipeline — are replaced:

    * ``get_db`` — every session-backed route reads the seeded database;
    * ``get_alert_queries`` — the alert read service holds a session *factory*
      rather than a session, so it would otherwise read the developer's file;
    * ``get_capture_manager`` — the real factory builds the process-wide
      pipeline, which starts a persistence worker and points at the developer's
      database. A manager over a bare pipeline is stood up instead: nothing to
      capture on, nothing written, no thread;
    * ``get_interface_manager`` — the real one enumerates this machine's NICs.
      Reporting none keeps a run independent of the hardware it happens to run
      on;
    * ``get_statistics_manager`` / ``get_device_manager`` /
      ``get_connection_tracker`` — the in-memory stores the manager-backed
      routes read. Fresh instances over the isolated factory make a run
      reproducible and keep the connection tracker off the developer's file.

    The detection and correlation engines are deliberately *not* replaced: both
    are in-memory, so a route that reads them measures the API layer over the
    empty registry a freshly started process holds before any capture runs.
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
    production query service, serialized into the production envelope — the
    figure is the API layer's cost, not a re-implementation of it.

    The environment is temporarily ``"test"`` so the application's lifespan skips
    ``init_db()`` and never touches the developer's database, and every override
    is removed afterwards so nothing leaks into a later run.
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
    """One measured endpoint: its identity, its answer, and its request times.

    ``rows`` is the size of the result set the route reported, so a reader can
    see that a filter really narrowed the set rather than measuring an empty
    page, or a route that ignored the filter.
    """

    label: str
    route: str
    status: int
    rows: int | None
    milliseconds: list[float] = field(default_factory=list)

    @property
    def mean(self) -> float:
        """Return the mean request time in milliseconds."""
        return stats.fmean(self.milliseconds) if self.milliseconds else 0.0

    @property
    def median(self) -> float:
        """Return the median request time in milliseconds.

        The median is the headline figure: a mean is moved by a single slow
        request, and on a machine doing anything else at the time that is the
        norm rather than the exception.
        """
        return stats.median(self.milliseconds) if self.milliseconds else 0.0

    @property
    def p95(self) -> float:
        """Return the 95th-percentile request time in milliseconds."""
        return _percentile(self.milliseconds, 95.0)

    @property
    def worst(self) -> float:
        """Return the slowest request time in milliseconds."""
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


def _rows_of(payload: Any) -> int | None:
    """Return the result-set size a collection payload reports, or ``None``.

    The collection routes agree on ``count`` for the page and ``total`` for the
    whole match set (M13.24), with ``items`` where the resource has no better
    name for its rows; an aggregate such as the dashboard reports neither, which
    is why this can legitimately return ``None``.
    """
    if not isinstance(payload, dict):
        return None
    for key in ("count", "total"):
        value = payload.get(key)
        if isinstance(value, int):
            return value
    items = payload.get("items")
    if isinstance(items, list):
        return len(items)
    return None


def _measure(
    client: TestClient,
    label: str,
    url: str,
    *,
    iterations: int,
    params: dict[str, Any] | None = None,
    warmup: int = _WARMUP_REQUESTS,
) -> Sample:
    """Time ``iterations`` requests to ``url`` and return them as a ``Sample``.

    A wrong status raises rather than being timed: a figure for a route that
    answered 404 would be a figure for the wrong thing, and reporting it silently
    would be worse than stopping.

    ``warmup`` requests are issued first and discarded, because the first request
    to a route pays for lazy construction that happens once per process and is
    not part of a request's steady-state cost.
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

    rows = _rows_of(body.get("data") if isinstance(body, dict) else None)
    return Sample(
        label=label,
        route=_render_route(url, params),
        status=status,
        rows=rows,
        milliseconds=samples,
    )


def _time_call(call: Callable[[], Any], iterations: int, warmup: int) -> list[float]:
    """Time ``iterations`` calls to ``call`` in milliseconds, after warming up.

    Used for the two costs that are not HTTP requests — a database query and a
    JSON render — so they are measured the same way the requests are, rather than
    by a different method that would make the figures incomparable.
    """
    for _ in range(warmup):
        call()
    samples: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        call()
        samples.append((time.perf_counter() - start) * 1000.0)
    return samples


def _phase_simple(client: TestClient, iterations: int) -> list[Sample]:
    """Measure the endpoints that touch no store at all (M13.37).

    These are the floor: whatever they cost is what the framework, the envelope
    and the response model add before any data is involved.
    """
    return [
        _measure(client, "system/info", f"{API}/system/info", iterations=iterations),
        _measure(client, "system/health", f"{API}/system/health", iterations=iterations),
        _measure(
            client, "capture/status", f"{API}/capture/status", iterations=iterations
        ),
        _measure(
            client,
            "statistics/traffic",
            f"{API}/statistics/traffic",
            iterations=iterations,
        ),
    ]


def _phase_lists(client: TestClient, iterations: int) -> list[Sample]:
    """Measure the list endpoints at their default page (M13.37).

    ``packets`` is the store-backed case and carries a full page of rows;
    ``alerts`` and ``notifications`` are store-backed and empty, which is the
    other end of the same code path; ``devices`` and ``connections`` are
    in-memory and empty. Reporting all five side by side is what separates the
    cost of the page from the cost of the request.
    """
    return [
        _measure(client, "packets (page)", f"{API}/packets", iterations=iterations),
        _measure(client, "alerts (empty)", f"{API}/alerts", iterations=iterations),
        _measure(
            client,
            "notifications (empty)",
            f"{API}/notifications",
            iterations=iterations,
        ),
        _measure(client, "devices (empty)", f"{API}/devices", iterations=iterations),
        _measure(
            client, "connections (empty)", f"{API}/connections", iterations=iterations
        ),
    ]


def _phase_filters(client: TestClient, iterations: int) -> list[Sample]:
    """Measure the same route under different filters (M13.37).

    The four differ in what the filter costs and in how much it keeps: a protocol
    keeps about half the store, a destination port keeps all of it, an address
    keeps exactly one row, and a timestamp keeps the first few seconds. Comparing
    them is what shows whether a filter is answered from an index or by a scan.
    """
    midpoint = datetime.fromtimestamp(_BASE_TIME + 5.0, tz=timezone.utc).isoformat()
    return [
        _measure(
            client,
            "packets?protocol=TCP",
            f"{API}/packets",
            iterations=iterations,
            params={"protocol": "TCP"},
        ),
        _measure(
            client,
            "packets?destination_port=443",
            f"{API}/packets",
            iterations=iterations,
            params={"destination_port": 443},
        ),
        _measure(
            client,
            "packets?source_ip=<one>",
            f"{API}/packets",
            iterations=iterations,
            params={"source_ip": _FILTER_SOURCE_IP},
        ),
        _measure(
            client,
            "packets?since=<iso>",
            f"{API}/packets",
            iterations=iterations,
            params={"since": midpoint},
        ),
    ]


def _phase_pagination(
    client: TestClient, store_size: int, iterations: int
) -> list[Sample]:
    """Measure the paging contract across its whole range (M13.24/M13.37).

    Each allowed page size is measured twice: at the head of the store, and at an
    offset in its middle. A page is only cheap if both are, and the offset is the
    case that an implementation pays for on every row it steps over.
    """
    samples: list[Sample] = []
    mid = max(store_size // 2, 0)
    for size in _PAGE_SIZES:
        samples.append(
            _measure(
                client,
                f"packets limit={size} offset=0",
                f"{API}/packets",
                iterations=iterations,
                params={"limit": size, "offset": 0},
            )
        )
        samples.append(
            _measure(
                client,
                f"packets limit={size} offset={mid}",
                f"{API}/packets",
                iterations=iterations,
                params={"limit": size, "offset": mid},
            )
        )
    return samples


def _phase_dashboard(client: TestClient, iterations: int) -> list[Sample]:
    """Measure the aggregate that reads every service at once (M13.19/M13.37).

    It is the heaviest route in M13: one request resolves the capture status, the
    statistics, the device and connection counters, the alert and incident
    collections and the recent findings, so its figure is a floor for what a
    frontend poll of the same data costs as separate calls.
    """
    return [
        _measure(
            client,
            "dashboard/summary",
            f"{API}/dashboard/summary",
            iterations=iterations,
        )
    ]


def _phase_serialization(client: TestClient, iterations: int) -> list[Sample]:
    """Measure what rendering a page payload costs (M13.37).

    Two payloads are timed: the ``data`` block the route builds and the whole
    envelope around it. The difference between them is the envelope's own cost,
    and the difference between the ``data`` figure here and the list route's
    figure above is the part of a list request that is neither the database nor
    the render — the framework, the dependency resolution and the response.
    """
    payload = client.get(f"{API}/packets").json()
    data = payload["data"]
    rows = _rows_of(data)
    return [
        Sample(
            label="json.dumps(data)",
            route=f"{API}/packets data block",
            status=200,
            rows=rows,
            milliseconds=_time_call(
                lambda: json.dumps(data), iterations, _WARMUP_REQUESTS
            ),
        ),
        Sample(
            label="json.dumps(envelope)",
            route=f"{API}/packets full body",
            status=200,
            rows=rows,
            milliseconds=_time_call(
                lambda: json.dumps(payload), iterations, _WARMUP_REQUESTS
            ),
        ),
    ]


def _count_of_result(value: Any) -> int:
    """Return how many rows a query service call produced.

    ``count`` returns the number itself while the list calls return the rows, so
    one helper keeps the timing loop uniform across both kinds of call.
    """
    return value if isinstance(value, int) else len(value)


def _phase_database(engine, iterations: int) -> list[Sample]:
    """Measure the query service directly, with no HTTP in the way (M13.37).

    This is what separates the database's share of a list request from
    everything else in it. It runs over the same engine the routes used, so the
    comparison is against the same store rather than a different one.
    """
    session = Session(bind=engine)
    try:
        service = PacketQueryService(session)
        cases = (
            ("count()", service.count),
            (
                f"list(limit={DEFAULT_PACKET_LIMIT})",
                lambda: service.list(limit=DEFAULT_PACKET_LIMIT),
            ),
            ("list(limit=1000)", lambda: service.list(limit=1000)),
            (
                "list(protocol=TCP)",
                lambda: service.list(protocol="TCP", limit=DEFAULT_PACKET_LIMIT),
            ),
        )
        samples: list[Sample] = []
        for label, call in cases:
            milliseconds = _time_call(call, iterations, _WARMUP_REQUESTS)
            samples.append(
                Sample(
                    label=label,
                    route="PacketQueryService (no HTTP)",
                    status=200,
                    rows=_count_of_result(call()),
                    milliseconds=milliseconds,
                )
            )
        return samples
    finally:
        session.close()


def _print_table(title: str, samples: list[Sample]) -> None:
    """Print one phase's figures as a table, all in milliseconds.

    The median is printed first because it is the figure to quote: on a machine
    that is doing anything else at the same time, one slow request moves the mean
    and leaves the median alone, and there is no isolation here to prevent that.
    """
    print("\n" + "-" * _BANNER_WIDTH)
    print(f"{title}")
    print("-" * _BANNER_WIDTH)
    header = (
        f"  {'route':<30} {'rows':>7}  {'p50':>7} {'mean':>7} {'p95':>7} {'max':>7}"
    )
    print(header)
    for sample in samples:
        rows = "-" if sample.rows is None else f"{sample.rows:,}"
        print(
            f"  {sample.label:<30} {rows:>7}  "
            f"{sample.median:>7.2f} {sample.mean:>7.2f} "
            f"{sample.p95:>7.2f} {sample.worst:>7.2f}"
        )
    every = [value for sample in samples for value in sample.milliseconds]
    if every:
        print(
            f"  {len(samples)} route(s), {len(every)} timed call(s), "
            f"median across all {stats.median(every):.2f} ms"
        )


def _print_header(args: argparse.Namespace, sizes: list[int]) -> None:
    """Print what this run is, so a recorded baseline is self-describing.

    A latency figure without the machine, the interpreter and the store size
    beside it cannot be compared with anything, so the header records all three
    rather than only the numbers.
    """
    print("=" * _BANNER_WIDTH)
    print("M13 performance baseline - the REST API over a seeded store (M13.37)")
    print("=" * _BANNER_WIDTH)
    print(f"  store              : {args.packets:,} packets")
    print(f"  iterations         : {args.iterations} timed requests per route")
    print(f"  warm-up requests   : {_WARMUP_REQUESTS} discarded per route")
    print(f"  page sizes swept   : {list(_PAGE_SIZES)}")
    print(f"  growth table sizes : {sizes}")
    print(f"  python             : {platform.python_version()} ({platform.machine()})")
    print(f"  platform           : {platform.system()} {platform.release()}")
    print(f"  sqlite             : {sqlite3.sqlite_version}")
    print(
        "  note               : in-process client, one SQLite file, no network "
        "stack - a local baseline, not a capacity claim"
    )


def _run_main_sweep(workdir: Path, args: argparse.Namespace) -> None:
    """Seed one store and run every phase against it (M13.37)."""
    db_path = workdir / f"bench_{args.packets}.db"
    engine, factory = _connect_database(db_path)
    try:
        print(f"\nSeeding {args.packets:,} packet rows into {db_path.name} ...")
        started = time.perf_counter()
        _seed_packets(factory, args.packets)
        print(f"  seeded in {time.perf_counter() - started:.2f}s")

        with _client(factory, engine) as client:
            _print_table(
                "Simple endpoints - resolve no store (M13.37)",
                _phase_simple(client, args.iterations),
            )
            _print_table(
                "List endpoints - default page (M13.37)",
                _phase_lists(client, args.iterations),
            )
            _print_table(
                "Filtered queries on /packets (M13.25/M13.37)",
                _phase_filters(client, args.iterations),
            )
            _print_table(
                f"Pagination of /packets over {args.packets:,} rows "
                "(M13.24/M13.37)",
                _phase_pagination(client, args.packets, args.iterations),
            )
            _print_table(
                "Dashboard aggregate (M13.19/M13.37)",
                _phase_dashboard(client, args.iterations),
            )
            _print_table(
                "JSON serialization of a page (M13.37)",
                _phase_serialization(client, args.iterations),
            )
            _print_table(
                "Database query time, no HTTP (M13.37)",
                _phase_database(engine, args.iterations),
            )
    finally:
        engine.dispose()


def _run_size_sweep(
    workdir: Path, args: argparse.Namespace, sizes: list[int]
) -> None:
    """Measure the list route and the count as the store grows (M13.37).

    "Test representative result sizes" is the part of M13.37 that a single store
    cannot answer: the cost of a page is not a constant, and whether it grows
    with the store — or with the offset — is exactly what a reader needs to know
    before trusting the pagination contract at scale. Each size is a separate
    throwaway store, so one row here is not affected by another.
    """
    print("\n" + "=" * _BANNER_WIDTH)
    print("Representative result sizes - how cost moves with the store (M13.37)")
    print("=" * _BANNER_WIDTH)

    print(f"  {'store':>9}  {'page p50':>9}  {'page p95':>9}  "
          f"{'db list p50':>12}  {'db count p50':>13}")
    for size in sizes:
        db_path = workdir / f"size_{size}.db"
        engine, factory = _connect_database(db_path)
        try:
            _seed_packets(factory, size)
            with _client(factory, engine) as client:
                page = _measure(
                    client,
                    "packets (page)",
                    f"{API}/packets",
                    iterations=args.iterations,
                )
            session = Session(bind=engine)
            try:
                service = PacketQueryService(session)
                db_list = _time_call(
                    lambda: service.list(limit=DEFAULT_PACKET_LIMIT),
                    args.iterations,
                    _WARMUP_REQUESTS,
                )
                db_count = _time_call(
                    service.count, args.iterations, _WARMUP_REQUESTS
                )
            finally:
                session.close()
            print(
                f"  {size:>9,}  {page.median:>9.2f}  {page.p95:>9.2f}  "
                f"{stats.median(db_list):>12.2f}  {stats.median(db_count):>13.2f}"
            )
        finally:
            engine.dispose()


def _print_closing_note() -> None:
    """State plainly what the figures above are, and are not.

    A benchmark that does not say what it left out invites the numbers to be read
    as a throughput claim. This one is deliberately not that: it is one process
    over one SQLite file with the transport replaced by a function call.
    """
    print("\n" + "=" * _BANNER_WIDTH)
    print("Read these as a local baseline, not as API capacity")
    print("=" * _BANNER_WIDTH)
    print("  * measured  : request latency, database query time, JSON rendering")
    print("  * excluded  : capture, normalization, statistics, device and")
    print("                connection tracking, detection, alerting, correlation")
    print("  * transport : in-process (TestClient), so no loopback network cost")
    print("  * store     : one SQLite file, single process, single machine")
    print("  * use       : compare endpoints, and re-run after a change")


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
        description="M13 performance baseline for the REST API (M13.37)."
    )
    parser.add_argument(
        "--packets",
        type=int,
        default=10_000,
        help="packet rows to seed into the measured store (default 10000)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=30,
        help="timed requests per route (default 30)",
    )
    parser.add_argument(
        "--sizes",
        default="1000,5000",
        help="comma-separated extra store sizes for the growth table",
    )
    args = parser.parse_args()
    if args.packets < 1:
        parser.error("--packets must be at least 1")
    if args.iterations < 1:
        parser.error("--iterations must be at least 1")
    return args


def _configure_logging() -> None:
    """Quiet the application's loggers so the figures are readable.

    The layers under the API log at INFO as they work, which is right in a
    service and noise over a table of measurements. Nothing is disabled: the
    level is raised, so a warning or worse would still be seen.
    """
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    for name in ("app", "httpx", "httpcore", _LOGGER_NAME):
        logging.getLogger(name).setLevel(logging.WARNING)


def main() -> int:
    """Run every phase and print the baseline (M13.37)."""
    args = _parse_args()
    _configure_logging()
    sizes = _parse_sizes(args)

    workdir = Path(tempfile.mkdtemp(prefix="netwatch_bench_m13_"))
    try:
        _print_header(args, sizes)
        _run_main_sweep(workdir, args)
        _run_size_sweep(workdir, args, sizes)
        _print_closing_note()
    finally:
        # The stores are throwaway and the developer's database was never
        # touched, so removing the directory is the whole cleanup.
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
