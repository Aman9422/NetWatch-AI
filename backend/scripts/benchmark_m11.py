"""M11 performance baseline — measure the alert layer's cost and its API (M11.33).

The alert layer sits after detection, so this measures **what turning a finding
into a stored alert costs** on top of a pipeline that already captures,
normalizes, aggregates and detects:

  * findings processed per second and alerts created per second,
  * the cost of the deduplication lookup (the repeated-observation path),
  * alert write latency through the M11 repository to SQLite,
  * the evidence write overhead (minimal vs fully-populated evidence sets),
  * Python memory held by the service (``tracemalloc``),
  * API response times for the read-only alert endpoints.

This is a local, single-machine baseline for the M11 alert code only. It is NOT a
production-capacity claim: it excludes real capture (Scapy/Npcap), the M5
normalization step, the M6/M7/M8/M9/M10 consumers, the network stack, JSON
serialization at the wire and any network filesystem. Alert writes are the most
database-bound part of the pipeline, so these numbers are dominated by SQLite on
the local disk and will differ on other hardware and workloads.

The database is a throwaway file under the OS temp directory, created and removed
by this script, so running it never touches the developer's ``netwatch.db``.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m11.py
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m11.py --findings 20000 --api-iterations 200
"""

from __future__ import annotations

import argparse
import logging
import shutil
import statistics as stats
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

# Make the backend root importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from sqlalchemy import create_engine, event  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.alerts.engine import AlertEngine  # noqa: E402
from app.alerts.queries import AlertQueries, AlertQuery  # noqa: E402
from app.alerts.resolvers import FindingResolvers, ResolutionLimits  # noqa: E402
from app.alerts.service import AlertService  # noqa: E402
from app.alerts.timestamps import to_utc_datetime  # noqa: E402
from app.detection.finding import DetectionFinding  # noqa: E402

_BANNER_WIDTH = 66

# A fixed destination and a fixed past timestamp keep the run deterministic.
_DESTINATION_IP = "8.8.8.8"
_PAST_TIMESTAMP = 1_000_000.0

# Rule used for every synthetic finding; the mapping fixes its severity, so the
# alert layer path exercised is the real one.
_RULE_ID = "port_scan"
_RULE_NAME = "Port Scan"
_EVIDENCE = {"unique_destination_ports": 37, "unique_port_threshold": 20}

# Most packet references one alert may carry (mirrors the configured default).
_BENCH_MAX_PACKETS = 5

# Deduplication window used for the run: long enough that every synthetic
# observation shares a key's window.
_BENCH_DEDUP_WINDOW_SECONDS = 300.0


def _incident_ip(index: int) -> str:
    """Return a stable, unique private address for incident number ``index``."""
    third = (index // 256) % 256
    fourth = index % 256
    return f"10.{0}.{third}.{fourth}"


def _finding(index: int, *, timestamp: float) -> DetectionFinding:
    """Build one synthetic port-scan finding for incident ``index``."""
    return DetectionFinding(
        rule_id=_RULE_ID,
        rule_name=_RULE_NAME,
        timestamp=timestamp,
        source_ip=_incident_ip(index),
        destination_ip=_DESTINATION_IP,
        protocol="TCP",
        description="Possible port scan detected",
        evidence=dict(_EVIDENCE),
        confidence=0.8,
    )


def _connect_database(db_path: Path):
    """Create a throwaway SQLite database and a session factory (M11.16).

    Foreign keys are enforced, so the packet evidence the benchmark writes points
    at packet rows that really exist — the same guarantee the runtime database
    gives.
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


def _insert_packets(factory, count: int) -> list[int]:
    """Insert ``count`` real packet rows and return their ids (M11.13)."""
    from app.models.packet import Packet

    session = factory()
    try:
        ids: list[int] = []
        for index in range(count):
            packet = Packet(
                timestamp=to_utc_datetime(_PAST_TIMESTAMP),
                source_ip=_incident_ip(index),
                destination_ip=_DESTINATION_IP,
                protocol="TCP",
                packet_length=74,
            )
            session.add(packet)
            session.flush()
            ids.append(int(packet.id))
        session.commit()
        return ids
    finally:
        session.close()


class _FixedPacket:
    """A packet-row double carrying only the fields the evidence builder reads."""

    def __init__(self, packet_id: int) -> None:
        self.id = packet_id
        self.source_ip = "10.0.0.1"
        self.destination_ip = _DESTINATION_IP
        self.protocol = "TCP"
        self.packet_length = 74
        self.timestamp = to_utc_datetime(_PAST_TIMESTAMP)


class _PacketSource:
    """A packet source returning a fixed set of rows for every lookup (M11.13)."""

    def __init__(self, packet_ids: list[int]) -> None:
        self._packets = [_FixedPacket(packet_id) for packet_id in packet_ids]
        self.calls = 0

    def list(self, **_filters) -> list[_FixedPacket]:
        """Return the fixed packet list, counting the lookup."""
        self.calls += 1
        return list(self._packets)


def _make_service(
    factory,
    *,
    packet_ids: list[int] | None = None,
    max_evidence: int = 64,
    packet_evidence_enabled: bool = True,
) -> AlertService:
    """Build an alert service over the throwaway database.

    When ``packet_ids`` is supplied the service resolves packet evidence, which
    is how the evidence-overhead phase populates an alert fully; otherwise it
    runs with no resolvers and an alert carries its own two records.
    """
    resolvers = None
    if packet_ids:
        resolvers = FindingResolvers(
            packet_source=_PacketSource(packet_ids),
            connection_source=None,
            rule_source=None,
            limits=ResolutionLimits(
                max_packets=_BENCH_MAX_PACKETS,
                packet_window_seconds=5.0,
                max_connections=5,
            ),
        )
    return AlertService(
        session_factory=factory,
        resolvers=resolvers,
        dedup_window_seconds=_BENCH_DEDUP_WINDOW_SECONDS,
        max_evidence=max_evidence,
        packet_evidence_enabled=packet_evidence_enabled,
    )


def benchmark_create(workdir: Path, findings: int) -> None:
    """Time the alert-creation path: distinct incidents, every one stored (M11.33)."""
    engine, factory = _connect_database(workdir / "create.db")
    try:
        service = _make_service(factory)
        alert_engine = AlertEngine(service)

        start = time.perf_counter()
        for index in range(findings):
            alert_engine.process_finding(_finding(index, timestamp=_PAST_TIMESTAMP))
        elapsed = time.perf_counter() - start

        counters = alert_engine.get_counters()
        throughput = findings / elapsed if elapsed > 0 else 0.0
        per_finding_us = (elapsed / findings) * 1_000_000 if findings else 0.0
        alerts_per_sec = counters.alerts_created / elapsed if elapsed > 0 else 0.0
        per_alert_us = (
            (elapsed / counters.alerts_created) * 1_000_000
            if counters.alerts_created
            else 0.0
        )

        print("=" * _BANNER_WIDTH)
        print("M11 PERFORMANCE BASELINE — alert layer (M11.33)")
        print("=" * _BANNER_WIDTH)
        print("--- Create path: one distinct incident per finding ---")
        print(f"  findings processed    : {findings:,}")
        print(f"  alerts created        : {counters.alerts_created:,}")
        print(f"  wall time             : {elapsed:.3f} s")
        print(f"  findings/sec          : {throughput:,.0f}")
        print(f"  alerts/sec            : {alerts_per_sec:,.0f}")
        print(f"  per finding           : {per_finding_us:.1f} us")
        print(f"  per alert (write)     : {per_alert_us:.1f} us")
        print(f"  errors                : {counters.errors:,}")
    finally:
        engine.dispose()


def benchmark_dedup(workdir: Path, findings: int, incidents: int) -> None:
    """Time the deduplication path: repeated observations of few incidents (M11.9)."""
    engine, factory = _connect_database(workdir / "dedup.db")
    try:
        service = _make_service(factory)
        alert_engine = AlertEngine(service)

        start = time.perf_counter()
        for index in range(findings):
            alert_engine.process_finding(
                _finding(index % incidents, timestamp=_PAST_TIMESTAMP)
            )
        elapsed = time.perf_counter() - start

        counters = alert_engine.get_counters()
        lookups = findings / elapsed if elapsed > 0 else 0.0
        per_lookup_us = (elapsed / findings) * 1_000_000 if findings else 0.0
        folded_per_sec = counters.duplicates_folded / elapsed if elapsed > 0 else 0.0

        print("\n--- Deduplication path: repeated observations of few incidents ---")
        print(f"  findings processed    : {findings:,}")
        print(f"  distinct incidents    : {incidents:,}")
        print(f"  alerts created        : {counters.alerts_created:,}")
        print(f"  duplicates folded     : {counters.duplicates_folded:,}")
        print(f"  wall time             : {elapsed:.3f} s")
        print(f"  dedup lookups/sec     : {lookups:,.0f}")
        print(f"  per finding           : {per_lookup_us:.1f} us")
        print(f"  folds/sec             : {folded_per_sec:,.0f}")
        print(f"  errors                : {counters.errors:,}")
    finally:
        engine.dispose()


def benchmark_evidence(workdir: Path, findings: int) -> None:
    """Compare minimal and fully-populated evidence sets (M11.11-M11.13)."""
    minimal_us, minimal_rows = _evidence_pass(
        workdir / "evidence_min.db", findings, packet_ids=None
    )
    rich_us, rich_rows = _evidence_pass(
        workdir / "evidence_rich.db", findings, packet_ids="rich"
    )

    print("\n--- Evidence write overhead ---")
    print(f"  minimal evidence      : {minimal_us:.1f} us/alert  "
          f"({minimal_rows:.1f} record(s)/alert)")
    print(f"  populated evidence    : {rich_us:.1f} us/alert  "
          f"({rich_rows:.1f} record(s)/alert)")
    delta = rich_us - minimal_us
    print(f"  evidence overhead     : {delta:.1f} us/alert")
    print(
        "  note                  : packet references are bounded by "
        f"{_BENCH_MAX_PACKETS}/alert, so the set cannot grow with network volume"
    )


def _evidence_pass(
    db_path: Path, findings: int, *, packet_ids
) -> tuple[float, float]:
    """Run one evidence configuration and return (us per alert, avg records)."""
    if db_path.exists():
        db_path.unlink()
    engine, factory = _connect_database(db_path)
    try:
        resolved_ids = _insert_packets(factory, _BENCH_MAX_PACKETS) if packet_ids else None
        service = _make_service(
            factory,
            packet_ids=resolved_ids,
            packet_evidence_enabled=packet_ids is not None,
        )
        alert_engine = AlertEngine(service)

        records = 0
        created = 0
        start = time.perf_counter()
        for index in range(findings):
            outcome = alert_engine.process_finding(
                _finding(index, timestamp=_PAST_TIMESTAMP)
            )
            if outcome.created and outcome.alert is not None:
                created += 1
                records += outcome.alert.evidence_count
        elapsed = time.perf_counter() - start

        per_alert_us = (elapsed / created) * 1_000_000 if created else 0.0
        avg_records = (records / created) if created else 0.0
        return per_alert_us, avg_records
    finally:
        engine.dispose()


def benchmark_memory(workdir: Path, findings: int) -> None:
    """Measure the Python heap the alert layer holds (M11.33).

    ``tracemalloc`` adds substantial overhead, so this runs separately from the
    throughput measurement; only the memory figures should be read from it.
    """
    engine, factory = _connect_database(workdir / "memory.db")
    try:
        service = _make_service(factory)
        alert_engine = AlertEngine(service)

        tracemalloc.start()
        before, _ = tracemalloc.get_traced_memory()
        for index in range(findings):
            alert_engine.process_finding(_finding(index, timestamp=_PAST_TIMESTAMP))
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        counters = alert_engine.get_counters()
        print("\n--- Memory (tracemalloc) ---")
        print(f"  findings processed    : {findings:,}")
        print(f"  heap before           : {before / 1024 / 1024:.2f} MiB")
        print(f"  heap after            : {current / 1024 / 1024:.2f} MiB")
        print(f"  peak heap             : {peak / 1024 / 1024:.2f} MiB")
        print(f"  alerts created        : {counters.alerts_created:,}")
        print(
            "  note                  : alert state is the counters and the "
            "deduplication window; stored alerts live in SQLite, so the Python "
            "heap does not grow with the number of alerts"
        )
    finally:
        engine.dispose()


def _mute_library_loggers() -> None:
    """Silence the per-alert INFO lines the alert service logs.

    ``app.main`` calls ``configure_logging`` at import time, which resets the root
    logger to the configured level, so this is applied again once that module has
    been imported.
    """
    logging.getLogger().setLevel(logging.WARNING)


def benchmark_api(workdir: Path, iterations: int, seeded: int) -> None:
    """Time the read-only alert endpoints through the ASGI test client (M11.18)."""
    from fastapi.testclient import TestClient

    from app.api.v1.alerts import get_alert_engine, get_alert_queries
    from app.config.settings import settings
    from app.main import app

    # Importing app.main ran configure_logging(), which reset the root logger.
    _mute_library_loggers()

    engine, factory = _connect_database(workdir / "api.db")
    try:
        service = _make_service(factory)
        alert_engine = AlertEngine(service)
        for index in range(seeded):
            alert_engine.process_finding(_finding(index, timestamp=_PAST_TIMESTAMP))

        queries = AlertQueries(session_factory=factory)
        page = queries.list_alerts(AlertQuery(limit=1))
        detail_id = page.alerts[0].alert_id if page.alerts else None

        endpoints: list[tuple[str, dict[str, int] | None]] = [
            ("/api/v1/alerts", {"limit": 100}),
            ("/api/v1/alerts/summary", None),
            ("/api/v1/alerts/diagnostics", None),
        ]
        if detail_id is not None:
            endpoints.append((f"/api/v1/alerts/{detail_id}", None))

        original_env = settings.app_env
        settings.app_env = "test"  # skip init_db() during startup
        app.dependency_overrides[get_alert_queries] = lambda: queries
        app.dependency_overrides[get_alert_engine] = lambda: alert_engine

        print("\n--- API response time (TestClient, in-process) ---")
        muted = ("httpx", "app.main", "app.api.v1.alerts")
        previous_levels = {name: logging.getLogger(name).level for name in muted}
        for name in muted:
            logging.getLogger(name).setLevel(logging.WARNING)
        try:
            with TestClient(app) as client:
                for endpoint, params in endpoints:
                    samples: list[float] = []
                    for _ in range(iterations):
                        start = time.perf_counter()
                        response = client.get(endpoint, params=params)
                        samples.append((time.perf_counter() - start) * 1000.0)
                        if response.status_code != 200:
                            raise RuntimeError(
                                f"{endpoint} returned HTTP {response.status_code}"
                            )
                    label = endpoint if params is None else f"{endpoint}?limit=100"
                    print(
                        f"  {label:<36} avg {stats.mean(samples):6.2f} ms  "
                        f"max {max(samples):6.2f} ms"
                    )
        finally:
            for name, level in previous_levels.items():
                logging.getLogger(name).setLevel(level)
            app.dependency_overrides.pop(get_alert_queries, None)
            app.dependency_overrides.pop(get_alert_engine, None)
            settings.app_env = original_env
    finally:
        engine.dispose()


def main() -> int:
    """Parse arguments and run the baseline measurements."""
    # The alert service logs one INFO line per alert created; over thousands of
    # findings that buries the measurements, so the library loggers are muted for
    # the run. The API phase additionally mutes the request loggers while it times.
    _mute_library_loggers()

    parser = argparse.ArgumentParser(
        description="Measure the M11 alert layer performance baseline."
    )
    parser.add_argument(
        "--findings", type=int, default=5_000, help="Findings processed per phase"
    )
    parser.add_argument(
        "--incidents",
        type=int,
        default=50,
        help="Distinct incidents the deduplication phase cycles through",
    )
    parser.add_argument(
        "--evidence-findings",
        type=int,
        default=2_000,
        help="Findings used for the evidence-overhead phase",
    )
    parser.add_argument(
        "--memory-findings",
        type=int,
        default=2_000,
        help="Findings used for the tracemalloc phase (it is much slower)",
    )
    parser.add_argument(
        "--api-iterations", type=int, default=200, help="Requests timed per endpoint"
    )
    parser.add_argument(
        "--api-alerts",
        type=int,
        default=1_000,
        help="Alerts seeded before the API phase",
    )
    args = parser.parse_args()

    for name, value in (
        ("--findings", args.findings),
        ("--incidents", args.incidents),
        ("--evidence-findings", args.evidence_findings),
        ("--memory-findings", args.memory_findings),
        ("--api-iterations", args.api_iterations),
        ("--api-alerts", args.api_alerts),
    ):
        if value < 1:
            print(f"{name} must be at least 1")
            return 1

    workdir = Path(tempfile.mkdtemp(prefix="netwatch_m11_bench_"))
    try:
        benchmark_create(workdir, args.findings)
        benchmark_dedup(workdir, args.findings, args.incidents)
        benchmark_evidence(workdir, args.evidence_findings)
        benchmark_memory(workdir, args.memory_findings)
        benchmark_api(workdir, args.api_iterations, args.api_alerts)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
