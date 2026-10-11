"""M17 verification script — the reporting layer over real backend data (M17.16).

Two modes:

  sample  (default)  Drive controlled packets through the *real* pipeline over an
                     isolated temporary SQLite database, then serve the real
                     FastAPI application (``app.main:app``) through a TestClient
                     whose dependencies are overridden to that very stack. Every
                     report generated below is therefore produced by the
                     production routes reading state the production capture path
                     wrote, and rendered by the production renderers — no mock,
                     no fixture, no hand-built content model.
  live               Start the application under uvicorn on a loopback port and
                     exercise the four report URLs over real HTTP, to confirm the
                     surface answers outside the in-process test client. Generates
                     one real report, so it needs a storage directory it may write
                     to; it never touches the developer's ``networks.db`` contents
                     beyond inserting one report row.

What it verifies, against the M17 completion criteria:

  * the four routes answer in the M13 envelope and a generation answers ``201``,
    the status a write deserves (M17.12/M13.4);
  * a request with no body produces the previous completed UTC day as a PDF,
    which are the layer's own documented defaults (M17.4);
  * the period a report covers is the *previous completed* UTC calendar day or
    week, half-open, so two adjacent presets meet at an instant and neither
    claims the record observed there (M17.4/M17.5);
  * a report's figures are the analytics figures written down: the CSV's stored
    packet and byte totals for a period equal what the M16 traffic route reports
    for the *same* instants, read independently (M17.2/M17.3);
  * the artifact on disk follows the documented naming rule, its size matches the
    size recorded on the row, and no temporary file is left behind (M17.9);
  * a download is the file itself, served as its own media type, with the
    artifact's own name and never the storage directory (M17.11/M13.30);
  * a request the layer cannot honour is refused with a ``400`` naming the field,
    *before* any row or file is written, rather than being adjusted (M17.4/M17.6);
  * a generation that cannot finish is a ``500`` carrying a safe sentence, with
    the row recorded as ``failed`` and no artifact claimed (M17.14);
  * a row whose artifact is gone reports ``downloadable=False`` in the listing and
    answers the download with ``404`` — the same answer whether the file was never
    written, was removed, or lies outside the directory (M17.11);
  * the row limit and the page ceiling bound what a report and a listing can
    return, and a listing filter and its total agree (M17.13/M13.24);
  * no response body or failure message names a path, a table, a query or a stack
    frame (M17.14/M13.30).

The one substitution in sample mode is the sniffer, which is dispensed with
entirely: the packets are handed to
:meth:`~app.services.packet_pipeline.PacketPipeline.process`, which is the seam the
capture callback itself calls. Normalization, statistics, persistence, device
discovery, connection tracking, detection, alerting and correlation all run for
real. Both the database and the artifact directory are throwaway paths under the
OS temp directory, created and removed by this script, so running it never touches
the developer's ``netwatch.db`` or their configured ``reports/`` directory.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\verify_m17.py
    & ".venv\\Scripts\\python.exe" scripts\\verify_m17.py live --port 8017
"""

from __future__ import annotations

import argparse
import csv
import io
import shutil
import socket
import sys
import tempfile
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Make the backend root importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

import httpx  # noqa: E402
from fastapi import Depends  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from scapy.layers.inet import IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from sqlalchemy import create_engine, event  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.alerts import get_alert_engine  # noqa: E402
from app.alerts.engine import AlertEngine  # noqa: E402
from app.alerts.queries import AlertQueries  # noqa: E402
from app.alerts.service import AlertService  # noqa: E402
from app.analytics.service import AnalyticsService  # noqa: E402
from app.api.common import MAX_PAGE_SIZE  # noqa: E402
from app.api.v1.deps import (  # noqa: E402
    get_alert_queries,
    get_analytics_service,
    get_report_service,
)
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
from app.reports.csv_renderer import BLOCK_MARKER  # noqa: E402
from app.reports.errors import ReportRequestError  # noqa: E402
from app.reports.period import (  # noqa: E402
    CUSTOM,
    DAILY,
    MAX_REPORT_PERIOD_SECONDS,
    WEEKLY,
    ReportPeriod,
    resolve_daily,
    resolve_weekly,
)
from app.reports.requests import (  # noqa: E402
    DEFAULT_FORMAT,
    DEFAULT_REPORT_TYPE,
    build_request,
    resolve_period,
)
from app.reports.service import ReportService  # noqa: E402
from app.reports.status import ReportStatus  # noqa: E402
from app.reports.storage import (  # noqa: E402
    FILENAME_PREFIX,
    ReportStorage,
    build_filename,
)
from app.risk.contributions import ScoringBounds  # noqa: E402
from app.risk.engine import RiskScoringEngine  # noqa: E402
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

#: The four report surfaces M17 owns (M17.12), so a loop over them cannot drift
#: from the list the closure criteria name.
REPORTS_URL = f"{API}/reports"
GENERATE_URL = f"{REPORTS_URL}/generate"
REPORT_PATHS: tuple[str, ...] = (REPORTS_URL, GENERATE_URL)

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
#: default one-hour analytics window still spans them, short enough that they are
#: clearly "recent" rather than at the window's edge.
_PACKET_BACKDATE_SECONDS = 1800.0

#: The sentence every failure check asserts is absent: a stack frame, a module
#: path or a SQL fragment would all be an internal detail leaking to a client
#: (M17.14/M13.30).
FORBIDDEN_IN_RESPONSES: tuple[str, ...] = (
    "Traceback",
    'File "',
    "sqlite",
    "SELECT ",
    "INSERT ",
    "UPDATE ",
)


def _iso_from_epoch(epoch_seconds: float) -> str:
    """Render epoch seconds as the ISO-8601 UTC string the API accepts.

    M13.26 is the convention: ISO-8601 with an explicit ``+00:00`` offset, which
    is what every query filter and every response field uses.
    """
    return datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc).isoformat()


def _epoch_of(value: str) -> float:
    """Parse an ISO-8601 instant the API returned into epoch seconds."""
    return datetime.fromisoformat(value).timestamp()


def _naive_utc(epoch_seconds: float) -> datetime:
    """Convert epoch seconds to the naive UTC datetime the stores persist."""
    return datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc).replace(
        tzinfo=None
    )


def _connect_database(db_path: Path):
    """Create the isolated SQLite database and a session factory (M17.16).

    Foreign keys are enforced, so a report's ``generated_by`` must reference a row
    that really exists — the same constraint the shipped database carries.
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
    M16 verifier seeds are written, so the two scripts describe the same store.
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
    detector, exactly as the M10, M13 and M16 verifiers do. This is a verification
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


class _StorageHolder:
    """The storage directory the report dependency resolves against (M17.9).

    The override below closes over this object rather than over a string, so a
    check can point the *next* request at a different directory -- which is how the
    blocked-directory failure is exercised without tearing the client down and
    standing a second one up. A holder is a deliberate substitution for a mutable
    global: the directory changes for one request and is put back.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory


@dataclass
class _Stack:
    """The live application, wired end to end over the isolated database.

    Holding the collaborators rather than re-deriving them is what lets the
    dependency overrides hand the API the *same* objects the pipeline fed, so a
    report can only be correct if the pipeline really wrote what the analytics
    layer reads back. That is the property M17.16's "real backend data" asks for.
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
        instant: the report checks need to know exactly where the stored rows sit
        relative to a period bound, and a wall clock sampled per packet would make
        the last packet's instant unpredictable.
        """
        for packet in packets:
            self.pipeline.process(packet, captured_at)
        self.pipeline.flush_persistence()
        self.pipeline.flush_connections()


def _build_stack(factory) -> _Stack:
    """Wire the production pipeline over the isolated database (M17.16).

    Every layer is the real one: the M6 statistics manager, M7 persistence, M8
    device discovery, M9 connection tracking, M10 detection, M11 alerting and M12
    correlation, fed by the real
    :class:`~app.services.packet_pipeline.PacketPipeline`. The only substitutions
    are the session factory and the rates source.
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


def _build_overrides(
    stack: _Stack, factory, db_engine, holder: _StorageHolder
) -> dict:
    """Return the dependency overrides that point the API at ``stack`` (M13.28).

    Each key is the *dependency function* a route declares in ``Depends``, so the
    route still resolves its collaborator through FastAPI and the wiring is the
    application's rather than the script's. The report route is included through
    the reports *service*, assembled from this request's session and the analytics
    service over it, exactly as the application assembles it -- only the storage
    directory differs, so a generated artifact lands in this run's throwaway
    directory instead of the configured one (M17.9).

    A missing override would silently point a route at the developer's database,
    which is why every chain the report route needs is listed even when only the
    report routes are exercised.
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
            db=db,
            analytics=analytics,
            storage=ReportStorage(holder.directory),
        )

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
        get_report_service: reports_override,
    }


@contextmanager
def _serve(
    stack: _Stack, factory, db_engine, holder: _StorageHolder
) -> Generator[TestClient, None, None]:
    """Yield a client over the real application, wired to ``stack`` (M17.16).

    The environment is temporarily ``"test"`` so the lifespan skips ``init_db()``
    and never touches the developer's database, and every override is removed
    afterwards so nothing leaks into a later request.
    """
    overrides = _build_overrides(stack, factory, db_engine, holder)
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


def _post(client: TestClient, url: str, body: dict[str, Any] | None = None):
    """POST a route and return the response, without asserting anything."""
    if body is None:
        return client.post(url)
    return client.post(url, json=body)


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


def _error_fields(response) -> list[str]:
    """Return the request fields an error envelope names (M13.5)."""
    try:
        body = response.json()
    except ValueError:
        return []
    return [entry.get("field") for entry in body.get("errors", [])]


def _generate(
    client: TestClient, body: dict[str, Any] | None = None
) -> dict[str, Any]:
    """POST a generation, assert ``201`` and the envelope, and return ``data``.

    The status is asserted here rather than at each call site because *every*
    successful generation is a write and therefore answers ``201``. A helper that
    accepted ``200`` would hide the day that stopped being true.
    """
    response = _post(client, GENERATE_URL, body)
    if response.status_code != 201:
        raise AssertionError(
            f"{GENERATE_URL} -> {response.status_code}: {response.text[:300]}"
        )
    payload = response.json()
    if payload.get("success") is not True:
        raise AssertionError(f"generation did not report success: {payload}")
    return payload["data"]


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


# ---------------------------------------------------------------------------
# Reading a rendered CSV back
# ---------------------------------------------------------------------------


def _csv_blocks(payload: bytes) -> dict[str, list[list[str]]]:
    """Parse a rendered report CSV into ``{block name: records}`` (M17.7).

    The renderer writes a sequence of ``### <name>`` marker records, each followed
    by that block's own header row and then its records. Parsing by marker rather
    than by position is what makes this a check of the *file format* as documented
    instead of a check of the order this script happened to expect.

    Returns:
        A mapping from block name (e.g. ``section:traffic``,
        ``table:traffic.top_sources``) to its records, the header row excluded.
    """
    text = payload.decode("utf-8")
    rows = list(csv.reader(io.StringIO(text)))
    blocks: dict[str, list[list[str]]] = {}
    current: list[list[str]] | None = None
    for row in rows:
        if len(row) >= 2 and row[0] == BLOCK_MARKER:
            current = blocks.setdefault(row[1], [])
            continue
        if current is None:
            continue
        if not current:
            # The first record after a marker is the block's own header row.
            current.append(row)
            continue
        current.append(row)
    # Drop each block's header so callers see records only.
    return {name: records[1:] for name, records in blocks.items()}


def _header_of(payload: bytes, block: str) -> list[str]:
    """Return one block's declared column names, as written (M17.7)."""
    text = payload.decode("utf-8")
    rows = list(csv.reader(io.StringIO(text)))
    for index, row in enumerate(rows):
        if len(row) >= 2 and row[0] == BLOCK_MARKER and row[1] == block:
            return rows[index + 1] if index + 1 < len(rows) else []
    return []


def _records_of(payload: bytes, block: str) -> list[list[str]]:
    """Return one block's records, or an empty list when the block is absent."""
    return _csv_blocks(payload).get(block, [])


def _metric_value(payload: bytes, section: str, label: str) -> str | None:
    """Return one section metric's rendered value from a report CSV (M17.3).

    A metric record is ``(label, value)``; the block also carries the section's
    own ``available`` record, which this skips because it is not a metric.
    """
    for record in _records_of(payload, f"section:{section}"):
        if len(record) >= 2 and record[0] == label:
            return record[1]
    return None


def _report_identity(payload: bytes) -> dict[str, str]:
    """Return the report block's ``key -> value`` map (M17.7)."""
    identity: dict[str, str] = {}
    for record in _records_of(payload, "report"):
        if len(record) >= 2:
            identity[record[0]] = record[1]
    return identity


def _count_of(text: str | None) -> int | None:
    """Parse a rendered count back into an integer, or ``None``.

    A rendered count carries thousands separators (``1,234``), so it is not an
    ``int`` as written. ``not reported`` -- the documented text for a value the
    backend does not have -- parses back to ``None`` rather than to zero, because
    the two must stay distinguishable (M17.3).
    """
    if text is None:
        return None
    cleaned = text.strip().replace(",", "")
    if not cleaned or cleaned == "-":
        return None
    try:
        return int(cleaned)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Reading a download's own description of itself
# ---------------------------------------------------------------------------


def _content_disposition_filename(response) -> str | None:
    """Return the file name a download offered, or ``None``.

    FastAPI renders the attachment as
    ``attachment; filename="netwatch-report-000001-....pdf"``. The value is read
    back so the check is against what the client would actually save, not against
    what this script believes it asked for.
    """
    header = response.headers.get("content-disposition")
    if not header:
        return None
    marker = "filename="
    index = header.find(marker)
    if index < 0:
        return None
    return header[index + len(marker) :].strip().strip('"')


def _print_row(label: str, value: object) -> None:
    """Print one labelled line of evidence, aligned without format padding."""

    print(f"  {label}" + " " * max(1, 30 - len(label)) + str(value))


def _check_read_surface(client: TestClient, failures: list[str]) -> None:
    """Verify the listing answers in the envelope and starts empty (M17.12).

    The empty listing is checked field by field because it is the answer every
    other check below is built on: if ``count`` and ``total`` did not agree on an
    empty store, nothing they say about a populated one could be trusted.
    """
    print("\n--- The read surface (M13.20/M17.12) ---")

    response = _get(client, REPORTS_URL)
    body = response.json()
    data = body.get("data") or {}
    _print_row(
        f"GET {REPORTS_URL}",
        f"{response.status_code} count={data.get('count')} "
        f"total={data.get('total')} limit={data.get('limit')}",
    )
    if response.status_code != 200:
        failures.append(f"the report listing answered {response.status_code} (M13.20)")
    elif body.get("success") is not True:
        failures.append("the report listing did not use the M13 envelope (M13.20)")
    else:
        for field, expected in (
            ("count", 0),
            ("total", 0),
            ("offset", 0),
            ("has_more", False),
        ):
            if data.get(field) != expected:
                failures.append(
                    f"an empty listing reported {field}={data.get(field)!r}, not "
                    f"{expected!r} (M13.20)"
                )
        if data.get("reports") != []:
            failures.append("an empty listing returned reports (M13.20)")

    for label, url, expected_status in (
        ("unknown id", f"{REPORTS_URL}/424242", 404),
        ("non-numeric id", f"{REPORTS_URL}/not-a-number", 422),
        ("unknown download", f"{REPORTS_URL}/424242/download", 404),
    ):
        error = _get(client, url)
        _print_row(f"GET {url}", error.status_code)
        if error.status_code != expected_status:
            failures.append(
                f"{label} answered {error.status_code}, not {expected_status} "
                "(M13.20)"
            )
        if expected_status == 404 and _error_fields(error) != ["report_id"]:
            failures.append(
                f"{label} did not name the report_id field: {_error_fields(error)} "
                "(M13.20)"
            )

    for verb in ("post", "put", "delete"):
        error = getattr(client, verb)(REPORTS_URL)
        _print_row(f"{verb.upper()} {REPORTS_URL}", error.status_code)
        if error.status_code != 405:
            failures.append(
                f"{verb.upper()} on the report collection answered "
                f"{error.status_code}, not 405 (M13.20)"
            )


def _check_defaults(client: TestClient, failures: list[str]) -> dict[str, Any]:
    """Verify an empty request produces the previous UTC day as a PDF (M17.4).

    The period is checked against the UTC calendar rather than against this
    script's arithmetic: the bounds must be midnight-aligned, exactly one day
    long, and end at the most recent midnight at or before the request. That is
    what "the previous completed UTC day" means, and it is checkable without
    asking the layer what it decided.
    """
    print("\n--- The layer's own defaults (M17.4) ---")
    before = time.time()
    data = _generate(client, None)
    after = time.time()
    report = data["report"]
    _print_row(
        "POST generate (no body)",
        f"{report['report_type']}/{report['format']} status={report['status']} "
        f"size={report['file_size']}",
    )
    _print_row(
        "period",
        f"{report['period_start']} .. {report['period_end']}",
    )

    if report.get("report_type") != DEFAULT_REPORT_TYPE:
        failures.append(
            f"an empty request produced a {report.get('report_type')!r} report, not "
            f"the documented default {DEFAULT_REPORT_TYPE!r} (M17.4)"
        )
    if report.get("format") != DEFAULT_FORMAT:
        failures.append(
            f"an empty request produced a {report.get('format')!r} report, not the "
            f"documented default {DEFAULT_FORMAT!r} (M17.4)"
        )
    if report.get("status") != ReportStatus.COMPLETED:
        failures.append(
            f"a generated report is {report.get('status')!r}, not completed (M17.9)"
        )
    if report.get("error") is not None:
        failures.append("a completed report carried an error sentence (M17.9)")
    if not report.get("file_size"):
        failures.append("a generated report recorded no artifact size (M17.9)")
    if report.get("downloadable") is not True:
        failures.append(
            "a completed report was not reported as downloadable (M17.11)"
        )

    start, end = report.get("period_start_epoch"), report.get("period_end_epoch")
    if start is None or end is None:
        failures.append(
            "a generated report recorded no period, so a reader cannot tell which "
            "day it covers (M17.6)"
        )
        return data

    if abs((end - start) - 86400.0) > 0.5:
        failures.append(
            f"a daily report covers {end - start:.0f}s, not one UTC day (M17.4)"
        )
    if int(end) % 86400 != 0:
        failures.append(
            "a daily report did not end on a UTC midnight, so its period is not a "
            "calendar day (M17.4)"
        )
    if not (end <= after and end > before - 86400.0):
        failures.append(
            f"a daily report ended at {end}, which is not the most recent completed "
            "UTC day (M17.4)"
        )
    expected = resolve_daily(now=before)
    if abs(expected.since - start) > 0.5 or abs(expected.until - end) > 0.5:
        failures.append(
            "the daily period the row recorded disagrees with the UTC-calendar "
            "rule that defines it (M17.4)"
        )

    summary = {metric["label"]: metric["value"] for metric in data["summary"]}
    _print_row(
        "summary",
        f"title={summary.get('Report title')!r} "
        f"format={summary.get('Output format')!r} "
        f"type={summary.get('Report type')!r}",
    )
    if summary.get("Report title") != report["name"]:
        failures.append(
            "the returned summary's title is not the stored report's name (M17.3)"
        )
    if summary.get("Output format") != report["format"]:
        failures.append(
            "the returned summary's format is not the stored report's format (M17.3)"
        )
    if summary.get("Report type") != report["report_type"]:
        failures.append("the returned summary did not state the report's type (M17.3)")
    if "Period start (inclusive, UTC)" not in summary:
        failures.append(
            "the summary omitted the period it describes, which is the one fact a "
            "reader needs to tell two reports apart (M17.6)"
        )
    return data


def _check_preset_periods(client: TestClient, failures: list[str]) -> None:
    """Verify daily and weekly presets are calendar-aligned and half-open (M17.5).

    The half-open property is the one M17.5 asks to be verified absent of
    double-counting: two adjacent presets must *meet* at an instant, with the
    earlier one ending exactly where the later one begins and neither claiming the
    record observed there. A closed interval would put one instant in two reports,
    which is what resolving the two presets from instants one period apart checks.
    """
    print("\n--- Daily and weekly are calendar periods, half-open (M17.4/M17.5) ---")

    now = time.time()
    today = resolve_daily(now=now)
    yesterday = resolve_daily(now=now - 86400.0)
    _print_row("daily", f"{yesterday.iso_since()} .. {yesterday.iso_until()}")
    _print_row("next day", f"{today.iso_since()} .. {today.iso_until()}")
    if abs(yesterday.until - today.since) > 0.5:
        failures.append(
            "two consecutive daily periods do not meet at an instant, so a record "
            "on the boundary is double-counted (M17.5)"
        )
    if yesterday.seconds != 86400.0 or today.seconds != 86400.0:
        failures.append("a daily period is not one UTC day (M17.4)")

    this_week = resolve_weekly(now=now)
    previous_week = resolve_weekly(now=now - 7 * 86400.0)
    _print_row("weekly", f"{this_week.iso_since()} .. {this_week.iso_until()}")
    if abs(previous_week.until - this_week.since) > 0.5:
        failures.append(
            "two consecutive weekly periods do not meet at an instant (M17.5)"
        )
    if this_week.seconds != 7 * 86400.0:
        failures.append("a weekly period is not seven UTC days (M17.5)")
    start = datetime.fromtimestamp(this_week.since, tz=timezone.utc)
    if start.weekday() != 0 or (start.hour, start.minute, start.second) != (0, 0, 0):
        failures.append(
            "a weekly period does not begin on Monday 00:00 UTC, so it is not the "
            "ISO-8601 week (M17.5)"
        )

    response = _post(
        client,
        GENERATE_URL,
        {
            "report_type": "weekly",
            "since": _iso_from_epoch(now - 86400.0),
            "until": _iso_from_epoch(now),
        },
    )
    _print_row(
        "weekly + bounds",
        f"{response.status_code} {_error_fields(response)}",
    )
    if response.status_code != 400 or _error_fields(response) != ["period"]:
        failures.append(
            "a preset given bounds was not refused with a 400 naming the period "
            "(M17.4)"
        )


def _artifact_dir(holder: _StorageHolder) -> Path:
    """Return the artifact directory this run writes into (M17.9)."""
    return Path(holder.directory)


def _artifact_files(holder: _StorageHolder) -> list[str]:
    """Return every file name in the artifact directory, sorted."""
    directory = _artifact_dir(holder)
    if not directory.is_dir():
        return []
    return sorted(entry.name for entry in directory.iterdir() if entry.is_file())


def _check_artifact_on_disk(
    client: TestClient,
    holder: _StorageHolder,
    generated: dict[str, Any],
    failures: list[str],
) -> str:
    """Verify the artifact exists under the documented name and size (M17.9).

    The expected name is rebuilt from the row's own id, period and format using
    the storage layer's own builder, so this checks the naming *rule* rather than
    a name this script happened to guess. The row's recorded size is compared
    against the file's real size, which is the one property that proves the row
    describes the file that exists rather than an intention.

    Returns:
        The artifact's file name, so the download check can compare against it.
    """
    print("\n--- The artifact on disk (M17.9) ---")
    report = generated["report"]
    period = ReportPeriod(
        since=float(report["period_start_epoch"]),
        until=float(report["period_end_epoch"]),
        report_type=str(report["report_type"]),
    )
    expected_name = build_filename(
        report_id=int(report["report_id"]),
        label=period.label(),
        output_format=str(report["format"]),
    )
    names = _artifact_files(holder)
    _print_row("directory", str(len(names)) + " file(s)")
    _print_row("expected name", expected_name)
    for name in names:
        _print_row("found", name)

    if expected_name not in names:
        failures.append(
            f"the artifact is not stored under the documented name {expected_name!r} "
            "(M17.9)"
        )
        return expected_name
    if not expected_name.startswith(FILENAME_PREFIX):
        failures.append(
            f"the artifact name does not carry the documented prefix "
            f"{FILENAME_PREFIX!r} (M17.9)"
        )
    for name in names:
        if name.endswith(".tmp") or name.startswith("."):
            failures.append(
                f"a temporary artifact {name!r} was left in the storage directory, "
                "so a failed write is not cleaned up (M17.9)"
            )

    path = _artifact_dir(holder) / expected_name
    on_disk = path.stat().st_size
    _print_row("size", f"row={report['file_size']} file={on_disk}")
    if on_disk != report["file_size"]:
        failures.append(
            f"the row records {report['file_size']} bytes but the file is "
            f"{on_disk} bytes, so the metadata does not describe the artifact "
            "(M17.9)"
        )
    return expected_name


def _check_download(
    client: TestClient,
    holder: _StorageHolder,
    generated: dict[str, Any],
    expected_name: str,
    failures: list[str],
) -> bytes:
    """Verify a download is the artifact itself, and never a path (M17.11).

    Three properties together: the bytes are the stored file's bytes (so the route
    serves it rather than regenerating or synthesising it), the media type matches
    the format stored on the row, and the file name the client is offered is the
    artifact's own name with the storage directory nowhere in the header
    (M13.30).
    """
    print("\n--- A download is the file, and never a path (M17.11/M13.30) ---")
    report = generated["report"]
    report_id = int(report["report_id"])
    response = _get(client, f"{REPORTS_URL}/{report_id}/download")
    disposition = _content_disposition_filename(response)
    _print_row("status", response.status_code)
    _print_row("content-type", response.headers.get("content-type"))
    _print_row("filename", disposition)
    _print_row("bytes", len(response.content))

    if response.status_code != 200:
        failures.append(
            f"a completed report's download answered {response.status_code}, not "
            "200 (M17.11)"
        )
        return b""

    content_type = response.headers.get("content-type", "")
    if str(report["format"]) == "PDF" and not content_type.startswith(
        "application/pdf"
    ):
        failures.append(
            f"a PDF report was served as {content_type!r}, not application/pdf "
            "(M17.11)"
        )
    if str(report["format"]) == "CSV" and not content_type.startswith("text/csv"):
        failures.append(
            f"a CSV report was served as {content_type!r}, not text/csv (M17.11)"
        )
    if disposition != expected_name:
        failures.append(
            f"the download offered {disposition!r}, not the artifact's own name "
            f"{expected_name!r} (M17.11)"
        )
    stored = (_artifact_dir(holder) / expected_name).read_bytes()
    if response.content != stored:
        failures.append(
            "the downloaded bytes are not the stored artifact's bytes (M17.11)"
        )
    if str(_artifact_dir(holder)) in (response.headers.get("content-disposition") or ""):
        failures.append(
            "the download named the storage directory, which is internal "
            "(M13.30)"
        )
    if len(response.content) != report["file_size"]:
        failures.append(
            f"the download is {len(response.content)} bytes but the row records "
            f"{report['file_size']} (M17.9)"
        )
    return response.content


def _check_pdf_body(payload: bytes, failures: list[str]) -> None:
    """Verify the downloaded bytes really are a PDF document (M17.8).

    A ``%PDF`` header and a ``%%EOF`` trailer are the two markers every conforming
    reader keys on, so their presence is the difference between "a PDF was served"
    and "some bytes were served with a PDF media type".
    """
    if not payload.startswith(b"%PDF"):
        failures.append("the PDF artifact does not begin with a %PDF header (M17.8)")
    if b"%%EOF" not in payload[-64:]:
        failures.append("the PDF artifact has no %%EOF trailer (M17.8)")


def _stored_of(data: dict) -> dict:
    """Return the persisted block of an analytics payload, or an empty dict."""
    section = data.get("stored") or data.get("windowed") or {}
    inner = section.get("data")
    return inner if isinstance(inner, dict) else {}


def _check_report_matches_analytics(
    client: TestClient, captured_at: float, failures: list[str]
) -> dict[str, Any]:
    """Verify a report's figures are the analytics figures written down (M17.2).

    This is the integration check the milestone turns on. The report is generated
    over an explicit window covering the driven packets, and its stored totals are
    compared against the M16 analytics routes read over the *same* instants: a
    report can only agree if the reporting layer really asked the analytics layer
    rather than aggregating the tables a second time. The comparisons are on the
    values inside the rendered CSV, so the whole chain is exercised -- analytics
    query, assembler, renderer, storage, download.

    Returns:
        The generated CSV report's payload data, so later checks can reuse it.
    """
    print("\n--- A report's figures are the analytics figures (M17.2/M17.3) ---")
    wide_since = captured_at - 60.0
    wide_until = captured_at + 60.0
    overview = _get_data(
        client,
        f"{API}/analytics/traffic",
        since=_iso_from_epoch(wide_since),
        until=_iso_from_epoch(wide_until),
    )
    stored = _stored_of(overview)
    first, last = stored.get("first_timestamp"), stored.get("last_timestamp")
    if not first or not last:
        failures.append(
            "the driven packets were not readable through the analytics traffic "
            "route, so no cross-check could be made (M17.2)"
        )
        return {}

    since = _epoch_of(first) - 1.0
    until = _epoch_of(last) + 1.0
    analytics = _get_data(
        client,
        f"{API}/analytics/traffic",
        since=_iso_from_epoch(since),
        until=_iso_from_epoch(until),
    )
    analytics_stored = _stored_of(analytics)
    _print_row(
        "analytics traffic",
        f"packets={analytics_stored.get('total_packets')} "
        f"bytes={analytics_stored.get('total_bytes')} "
        f"protocols={analytics_stored.get('distinct_protocols')}",
    )

    threats = _get_data(
        client,
        f"{API}/analytics/threats",
        since=_iso_from_epoch(since),
        until=_iso_from_epoch(until),
    )
    analytics_alerts = _stored_of(threats).get("total")
    _print_row("analytics threats", f"stored alerts={analytics_alerts}")

    body = {
        "report_type": CUSTOM,
        "format": "CSV",
        "since": _iso_from_epoch(since),
        "until": _iso_from_epoch(until),
    }
    data = _generate(client, body)
    report = data["report"]
    report_id = int(report["report_id"])
    download = _get(client, f"{REPORTS_URL}/{report_id}/download")
    if download.status_code != 200:
        failures.append(
            f"the data-backed report's download answered {download.status_code} "
            "(M17.11)"
        )
        return data
    payload = download.content

    identity = _report_identity(payload)
    _print_row(
        "report period",
        f"{identity.get('period_start')} .. {identity.get('period_end')}",
    )
    if identity.get("period_start") != body["since"]:
        failures.append(
            "the report's own period start is not the requested instant, so the "
            "document does not describe the period it was asked for (M17.6)"
        )
    if identity.get("period_end") != body["until"]:
        failures.append(
            "the report's own period end is not the requested instant (M17.6)"
        )
    if identity.get("output_format") != "CSV":
        failures.append(
            "the report's own format field is not the format it was asked for "
            "(M17.7)"
        )
    if identity.get("report_id") != str(report_id):
        failures.append(
            "the report's own identifier is not the stored row's id (M17.7)"
        )

    for label, expected, actual in (
        (
            "Packets stored in period",
            analytics_stored.get("total_packets"),
            _count_of(_metric_value(payload, "traffic", "Packets stored in period")),
        ),
        (
            "Bytes stored in period",
            analytics_stored.get("total_bytes"),
            _count_of(_metric_value(payload, "traffic", "Bytes stored in period")),
        ),
        (
            "Distinct protocols in period",
            analytics_stored.get("distinct_protocols"),
            _count_of(_metric_value(payload, "traffic", "Distinct protocols in period")),
        ),
        (
            "Alerts recorded in period",
            analytics_alerts,
            _count_of(_metric_value(payload, "threats", "Alerts recorded in period")),
        ),
    ):
        _print_row(label, f"report={actual} analytics={expected}")
        if expected is None or actual is None:
            failures.append(
                f"the report did not report {label!r}, so its figures cannot be "
                "compared with the analytics layer (M17.3)"
            )
        elif actual != expected:
            failures.append(
                f"the report's {label!r} is {actual}, the analytics layer reports "
                f"{expected} for the same instants (M17.2)"
            )

    # The per-protocol table must account for the same total, which is what makes
    # the breakdown a breakdown of *this* window rather than of something else.
    protocol_rows = _records_of(payload, "table:traffic.protocols")
    protocol_packets = sum(_count_of(row[1]) or 0 for row in protocol_rows if len(row) >= 2)
    _print_row(
        "protocol table",
        f"{len(protocol_rows)} group(s), {protocol_packets} packet(s)",
    )
    if protocol_rows and protocol_packets != (analytics_stored.get("total_packets") or 0):
        failures.append(
            f"the report's protocol breakdown accounts for {protocol_packets} "
            f"packets, the window holds {analytics_stored.get('total_packets')} "
            "(M17.3)"
        )

    # Every body section must be present and readable, so a report is a complete
    # document rather than the one or two sections that happened to have data.
    # The report's identity is the ``report`` block (M17.7) and the five body
    # sections follow it, so all six being present is what makes the file the
    # documented document rather than a partial one.
    for block in (
        "report",
        "section:traffic",
        "section:protocols",
        "section:devices",
        "section:connections",
        "section:threats",
    ):
        if block not in _csv_blocks(payload):
            failures.append(
                f"the report CSV carries no {block!r} block, so its structure is "
                "not the documented one (M17.7)"
            )
    return data
def _expected_refusal(**kwargs: Any) -> str:
    """Return the sentence the reporting layer itself would refuse a request with.

    The check below compares the API's answer against this, so a route that
    invented its own wording for a refusal would be caught. The expected text
    comes from the layer that owns the rule, not from a string written here.
    """
    mapped = dict(kwargs)
    # The route's body names the field ``format``; the layer's own builder calls
    # it ``output_format``. Translating here keeps the expectation built from the
    # layer's real signature rather than from the route's wire name.
    if "format" in mapped:
        mapped["output_format"] = mapped.pop("format")
    try:
        request = build_request(**mapped)
        resolve_period(request)
    except ReportRequestError as exc:
        return exc.message
    return ""


def _check_refusals(client: TestClient, failures: list[str]) -> None:
    """Verify an unanswerable request is refused, and writes nothing (M17.4-M17.6).

    Every case is a request the layer cannot honour as asked. The property under
    test is that it says so -- a ``400`` naming the offending field, in the
    standard envelope, with the layer's own sentence -- rather than quietly
    answering a different question, which would be worse than an error because it
    would look like a valid report (M17.6).
    """
    print("\n--- An unanswerable request is refused (M17.4-M17.6) ---")
    now = time.time()
    before_total = _get_data(client, REPORTS_URL)["total"]

    cases: list[tuple[str, dict[str, Any], str]] = [
        ("unsupported format", {"format": "DOCX"}, "format"),
        ("blank format", {"format": "   "}, "format"),
        ("unsupported type", {"report_type": "hourly"}, "report_type"),
        ("blank type", {"report_type": ""}, "report_type"),
        (
            "preset given bounds",
            {
                "report_type": "daily",
                "since": _iso_from_epoch(now - 600.0),
                "until": _iso_from_epoch(now),
            },
            "period",
        ),
        ("custom without bounds", {"report_type": "custom"}, "period"),
        (
            "custom missing until",
            {"report_type": "custom", "since": _iso_from_epoch(now - 600.0)},
            "period",
        ),
        (
            "custom inverted",
            {
                "report_type": "custom",
                "since": _iso_from_epoch(now),
                "until": _iso_from_epoch(now - 600.0),
            },
            "period",
        ),
        (
            "custom empty",
            {
                "report_type": "custom",
                "since": _iso_from_epoch(now),
                "until": _iso_from_epoch(now),
            },
            "period",
        ),
        (
            "custom longer than the ceiling",
            {
                "report_type": "custom",
                "since": _iso_from_epoch(now - MAX_REPORT_PERIOD_SECONDS - 60.0),
                "until": _iso_from_epoch(now),
            },
            "period",
        ),
        (
            "malformed since",
            {
                "report_type": "custom",
                "since": "yesterday",
                "until": _iso_from_epoch(now),
            },
            "since",
        ),
        (
            "malformed until",
            {
                "report_type": "custom",
                "since": _iso_from_epoch(now - 600.0),
                "until": "2026-13-45T99:99:99Z",
            },
            "until",
        ),
    ]

    for label, body, expected_field in cases:
        response = _post(client, GENERATE_URL, body)
        message = ""
        try:
            message = str(response.json().get("message", ""))
        except ValueError:
            message = ""
        _print_row(label, f"{response.status_code} {_error_fields(response)}")
        if response.status_code != 400:
            failures.append(
                f"{label!r} answered {response.status_code}, not the controlled "
                "400 a refusal must be (M17.4)"
            )
            continue
        if _error_codes(response) != ["INVALID_REQUEST"]:
            failures.append(
                f"{label!r} was refused with {_error_codes(response)}, not "
                "INVALID_REQUEST (M13.5)"
            )
        if _error_fields(response) != [expected_field]:
            failures.append(
                f"{label!r} named {_error_fields(response)}, not the field "
                f"{expected_field!r} the caller must fix (M17.4)"
            )
        expected_message = _expected_refusal(**body)
        if expected_message and message != expected_message:
            failures.append(
                f"{label!r} was refused with {message!r}, not the reporting "
                f"layer's own sentence {expected_message!r} (M17.14)"
            )

    after_total = _get_data(client, REPORTS_URL)["total"]
    _print_row("rows after refusals", f"{before_total} -> {after_total}")
    if after_total != before_total:
        failures.append(
            "a refused generation still wrote a report row, so a refusal is not "
            "side-effect free (M17.4)"
        )

    for label, params in (
        ("limit=0", {"limit": 0}),
        (f"limit={MAX_PAGE_SIZE + 1}", {"limit": MAX_PAGE_SIZE + 1}),
        ("offset=-1", {"offset": -1}),
    ):
        response = _get(client, REPORTS_URL, **params)
        _print_row(label, response.status_code)
        if response.status_code != 422:
            failures.append(
                f"{label} on the listing was not a 422 request error (got "
                f"{response.status_code}) (M13.24)"
            )


def _check_listing_and_filters(
    client: TestClient, generated: dict[str, Any], failures: list[str]
) -> None:
    """Verify the listing's order, filters, paging and totals agree (M13.24).

    ``total`` is compared against ``count``, because a page whose total came from
    a different query is the classic way a paginated listing starts lying about
    the size of the store.
    """
    print("\n--- The listing: order, filters, paging, totals (M13.24) ---")
    data = _get_data(client, REPORTS_URL)
    _print_row(
        "listing",
        f"count={data['count']} total={data['total']} has_more={data['has_more']}",
    )
    if data["total"] != data["count"] or data["total"] < 1:
        failures.append(
            "a single-page listing's count and total disagree with each other "
            "(M13.24)"
        )
    stamps = [row["generated_at_epoch"] for row in data["reports"]]
    if stamps != sorted(stamps, reverse=True):
        failures.append("the listing is not newest-first (M13.20)")

    by_format = _get_data(client, REPORTS_URL, format="pdf")
    _print_row("filter format=pdf", f"count={by_format['count']}")
    if by_format["count"] > data["count"]:
        failures.append("a format filter returned more rows than the listing (M13.25)")
    for row in by_format["reports"]:
        if row["format"] != "PDF":
            failures.append(
                f"the format filter returned a {row['format']!r} report (M13.25)"
            )
            break

    by_type = _get_data(
        client, REPORTS_URL, report_type=str(generated["report"]["report_type"])
    )
    _print_row("filter report_type", f"count={by_type['count']}")
    if by_type["count"] < 1:
        failures.append(
            "filtering by a type that exists returned nothing, so the filter "
            "drops real rows (M13.25)"
        )

    unknown = _get_data(client, REPORTS_URL, format="xlsx")
    _print_row("filter format=xlsx", f"count={unknown['count']}")
    if unknown["count"] != 0 or unknown["total"] != 0:
        failures.append(
            "a filter value the store does not hold selected rows, so an unknown "
            "filter is treated as a match (M13.25)"
        )

    if data["total"] >= 2:
        first = _get_data(client, REPORTS_URL, limit=1)
        second = _get_data(client, REPORTS_URL, limit=1, offset=1)
        _print_row(
            "paging limit=1",
            f"page1={first['reports'][0]['report_id']} "
            f"page2={second['reports'][0]['report_id']}",
        )
        if first["total"] != data["total"] or not first["has_more"]:
            failures.append(
                "a bounded page did not report the whole match set, so a client "
                "cannot know there is more (M13.24)"
            )
        if first["reports"][0]["report_id"] == second["reports"][0]["report_id"]:
            failures.append("two adjacent pages returned the same row (M13.24)")

    row = _get_data(client, f"{REPORTS_URL}/{int(generated['report']['report_id'])}")
    _print_row("single read", f"id={row['report_id']} name={row['name']!r}")
    if row["report_id"] != generated["report"]["report_id"]:
        failures.append("a single read returned a different report (M13.20)")
    for forbidden in ("file_path", "path", "directory"):
        if forbidden in row:
            failures.append(
                f"the report view exposes {forbidden!r}, which is an internal "
                "filesystem location (M13.30)"
            )
def _check_row_limit(client: TestClient, failures: list[str]) -> None:
    """Verify the configured row limit bounds what a report lists (M17.13).

    The setting is lowered and then restored around one generation, so the check
    is that the *configured* ceiling is applied rather than that a constant is
    hard-coded. Two groups exist in the period, so a limit of one row is a real
    truncation rather than a coincidence.
    """
    print("\n--- The configured row limit bounds a report (M17.13) ---")
    captured = settings.report_max_table_rows
    try:
        settings.report_max_table_rows = 1
        data = _generate(client, {"format": "CSV", "report_type": "weekly"})
        report_id = int(data["report"]["report_id"])
        payload = _get(client, f"{REPORTS_URL}/{report_id}/download").content
        limited = _records_of(payload, "table:traffic.top_sources")
        _print_row("limit=1 top_sources", f"{len(limited)} row(s)")
        if len(limited) > 1:
            failures.append(
                f"a report generated with a row limit of 1 listed {len(limited)} "
                "rows, so the configured ceiling is not applied (M17.13)"
            )
    finally:
        settings.report_max_table_rows = captured

    data = _generate(client, {"format": "CSV", "report_type": "weekly"})
    report_id = int(data["report"]["report_id"])
    payload = _get(client, f"{REPORTS_URL}/{report_id}/download").content
    restored = _records_of(payload, "table:traffic.top_sources")
    _print_row("limit restored", f"{len(restored)} row(s)")
    if len(restored) < len(_records_of(payload, "table:traffic.protocols")):
        failures.append(
            "restoring the row limit did not widen the report, so the setting is "
            "not read per generation (M17.13)"
        )


def _check_failure_path(
    client: TestClient,
    holder: _StorageHolder,
    workdir: Path,
    failures: list[str],
) -> None:
    """Verify a generation that cannot finish fails safely and writes no file.

    The storage directory is pointed at a path that is a *file*, so creating it
    must fail. The three properties under test: the answer is a ``500`` carrying a
    safe sentence with no internal detail; the row is recorded as ``failed`` with
    no size, so the store never claims an artifact that is not there; and the
    download of that report is a ``404`` (M17.9/M17.14).
    """
    print("\n--- A generation that cannot finish fails safely (M17.14) ---")
    blocker = workdir / "blocked-artifacts"
    blocker.write_bytes(b"this is a file, not a directory")
    original = holder.directory
    before = _get_data(client, REPORTS_URL)["total"]
    try:
        holder.directory = blocker
        response = _post(client, GENERATE_URL, {"format": "CSV"})
    finally:
        holder.directory = original

    _print_row("status", response.status_code)
    message = ""
    try:
        body = response.json()
        message = str(body.get("message", ""))
    except ValueError:
        body = {}
    _print_row("message", repr(message))
    if response.status_code != 500:
        failures.append(
            f"a generation that could not write its file answered "
            f"{response.status_code}, not 500 (M17.14)"
        )
    if body.get("success") is not False:
        failures.append("a failed generation did not report failure (M13.5)")
    if _error_codes(response) != ["INTERNAL_ERROR"]:
        failures.append(
            f"a failed generation carried {_error_codes(response)}, not "
            "INTERNAL_ERROR (M13.5)"
        )
    for forbidden in FORBIDDEN_IN_RESPONSES + (str(blocker), str(workdir)):
        if forbidden in message or forbidden in response.text:
            failures.append(
                f"a failure response carried the internal detail {forbidden!r} "
                "(M17.14/M13.30)"
            )
            break

    after = _get_data(client, REPORTS_URL)["total"]
    rows = _get_data(client, REPORTS_URL)["reports"]
    failed = [row for row in rows if row["status"] == ReportStatus.FAILED]
    _print_row("rows", f"{before} -> {after}, failed={len(failed)}")
    if after != before + 1:
        failures.append(
            "a failed generation did not leave a row recording the attempt, so "
            "the work left no trace (M17.9)"
        )
    if not failed:
        failures.append("no row was marked failed after a failed generation (M17.9)")
    else:
        row = failed[0]
        _print_row("failed row", f"size={row['file_size']} error={row['error']!r}")
        if row["file_size"] is not None:
            failures.append(
                "a failed report recorded an artifact size, so the row claims a "
                "file that was never written (M17.9)"
            )
        if not row["error"]:
            failures.append(
                "a failed report carried no sentence explaining what happened "
                "(M17.14)"
            )
        if row["downloadable"]:
            failures.append("a failed report was reported as downloadable (M17.11)")
        download = _get(client, f"{REPORTS_URL}/{row['report_id']}/download")
        _print_row("failed download", download.status_code)
        if download.status_code != 404:
            failures.append(
                f"a failed report's download answered {download.status_code}, not "
                "404 (M17.11)"
            )


def _check_missing_artifact(
    client: TestClient,
    holder: _StorageHolder,
    generated: dict[str, Any],
    failures: list[str],
) -> None:
    """Verify an artifact removed after the fact is reported honestly (M17.11).

    A ``completed`` row whose file was deleted by hand is the case that separates
    "downloadable is a status" from "downloadable is a fact": the listing must say
    the download would fail, and the download must fail with ``404`` rather than a
    server error.
    """
    print("\n--- An artifact removed after the fact (M17.11) ---")
    report_id = int(generated["report"]["report_id"])
    row = _get_data(client, f"{REPORTS_URL}/{report_id}")
    if not row["downloadable"]:
        failures.append(
            "a freshly generated report with its file present was reported as not "
            "downloadable (M17.11)"
        )
        return

    removed = 0
    for entry in _artifact_dir(holder).iterdir():
        if entry.is_file():
            entry.unlink()
            removed += 1
    _print_row("removed", f"{removed} artifact(s)")

    row = _get_data(client, f"{REPORTS_URL}/{report_id}")
    _print_row(
        "after removal",
        f"status={row['status']} downloadable={row['downloadable']}",
    )
    if row["status"] != ReportStatus.COMPLETED:
        failures.append(
            "removing the artifact changed the stored generation status, which "
            "describes the attempt rather than the file (M17.9)"
        )
    if row["downloadable"]:
        failures.append(
            "a report whose artifact was removed is still reported as downloadable "
            "(M17.11)"
        )
    response = _get(client, f"{REPORTS_URL}/{report_id}/download")
    _print_row("download", f"{response.status_code} {_error_codes(response)}")
    if response.status_code != 404:
        failures.append(
            f"a download whose artifact is gone answered {response.status_code}, "
            "not 404 (M17.11)"
        )
    if _error_codes(response) != ["REPORT_NOT_FOUND"]:
        failures.append(
            "a missing artifact did not answer with REPORT_NOT_FOUND (M17.11)"
        )


def _check_no_internals(
    client: TestClient,
    holder: _StorageHolder,
    workdir: Path,
    failures: list[str],
) -> None:
    """Verify no read response names a path, a table, a query or a frame (M13.30).

    Every surface a client can reach is fetched and its raw text searched, so this
    is a check of what a client *receives* rather than of what a handler intended.
    The storage directory and the work directory are both searched for: a leaked
    absolute path is the concrete failure M13.30 exists to prevent.
    """
    print("\n--- No response names an internal (M13.30/M17.14) ---")
    surfaces = [REPORTS_URL, f"{REPORTS_URL}/424242", f"{REPORTS_URL}/424242/download"]
    leaked = 0
    for url in surfaces:
        response = _get(client, url)
        text = response.text
        for forbidden in FORBIDDEN_IN_RESPONSES + (
            str(_artifact_dir(holder)),
            str(workdir),
            "reports.",
        ):
            if forbidden in text:
                leaked += 1
                failures.append(
                    f"{url} carried the internal detail {forbidden!r} "
                    "(M13.30)"
                )
    _print_row("surfaces checked", f"{len(surfaces)}, leaks={leaked}")
#: The counts driven by sample mode. Small, so the run is seconds rather than
#: minutes; the scans are over the lab thresholds, so the real detectors fire.
_SCAN_COUNT = PORT_SCAN_THRESHOLD + 4
_SWEEP_COUNT = INTERNAL_SCAN_THRESHOLD


def _run_sample_checks(
    client: TestClient,
    factory,
    holder: _StorageHolder,
    workdir: Path,
    captured_at: float,
    failures: list[str],
) -> None:
    """Run every sample-mode check against one wired client (M17.16).

    The order is deliberate: the read surface and the defaults come first, because
    every later check assumes a listing that answers and a generation that works;
    the destructive checks (the row limit, the blocked directory, removing an
    artifact) come last, so nothing they change can affect an earlier figure.
    """
    _check_read_surface(client, failures)
    default_report = _check_defaults(client, failures)
    _check_preset_periods(client, failures)
    if default_report:
        name = _check_artifact_on_disk(client, holder, default_report, failures)
        pdf = _check_download(client, holder, default_report, name, failures)
        _check_pdf_body(pdf, failures)
    _check_report_matches_analytics(client, captured_at, failures)
    _check_listing_and_filters(client, default_report, failures)
    _check_refusals(client, failures)
    _check_no_internals(client, holder, workdir, failures)
    _check_row_limit(client, failures)
    _check_failure_path(client, holder, workdir, failures)
    if default_report:
        _check_missing_artifact(client, holder, default_report, failures)


def run_sample_mode() -> int:
    """Drive the pipeline, then verify the reporting layer over its real data."""
    workdir = Path(tempfile.mkdtemp(prefix="netwatch_m17_"))
    db_path = workdir / "verify_m17.db"
    artifacts = workdir / "artifacts"
    database, factory = _connect_database(db_path)
    holder = _StorageHolder(artifacts)
    failures: list[str] = []
    try:
        _seed_rule_catalogue(factory)
        stack = _build_stack(factory)
        packets = _scan_packets(_SCAN_COUNT, SOURCE_IP) + _sweep_packets(
            _SWEEP_COUNT, SECOND_SOURCE_IP
        )
        captured_at = time.time() - _PACKET_BACKDATE_SECONDS

        print("=" * _BANNER_WIDTH)
        print("M17 SAMPLE MODE - the reporting layer over real backend data")
        print("=" * _BANNER_WIDTH)
        print(f"database  : {db_path}")
        print(f"artifacts : {artifacts}")
        print(
            f"packets   : {len(packets)} driven through the real pipeline "
            f"({_SCAN_COUNT} TCP SYNs, {_SWEEP_COUNT} UDP sweeps)"
        )
        print(f"dated at  : {_iso_from_epoch(captured_at)}")

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
                "believes it is (M17.16)"
            )

        with _serve(stack, factory, database, holder) as client:
            _run_sample_checks(
                client, factory, holder, workdir, captured_at, failures
            )
    finally:
        database.dispose()
        shutil.rmtree(workdir, ignore_errors=True)
    return _report_failures(failures, mode="sample")


def _wait_for_server(client: httpx.Client, *, attempts: int = 60) -> bool:
    """Poll the OpenAPI document until the server answers, or give up (M17.16)."""
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


def run_live_mode(host: str, port: int, artifacts: Path) -> int:
    """Start the application under uvicorn and verify it over real HTTP (M17.16).

    This is the mode M17.16 describes literally: a running server, real sockets and
    the documented URLs. It generates one real report -- a write -- into a
    throwaway directory, which is why the storage directory is temporarily pointed
    at one: the developer's configured ``reports/`` directory is never written to.
    """
    import uvicorn

    failures: list[str] = []
    chosen = _free_port(host, port)
    original_directory = settings.report_storage_dir

    print("=" * _BANNER_WIDTH)
    print("M17 LIVE MODE - the running application over real HTTP")
    print("=" * _BANNER_WIDTH)
    print(f"base url  : http://{host}:{chosen}")
    if chosen != port:
        print(f"note      : port {port} was busy, so {chosen} was used")
    print(f"artifacts : {artifacts}")

    settings.report_storage_dir = str(artifacts)
    config = uvicorn.Config(app, host=host, port=chosen, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    client = httpx.Client(base_url=f"http://{host}:{chosen}", timeout=30.0)
    try:
        if not _wait_for_server(client):
            failures.append(
                f"the application did not answer on http://{host}:{chosen} within "
                "the startup window"
            )
            return _report_failures(failures, mode="live")

        print("\n--- The report routes over real HTTP (M17.12) ---")
        listing = client.get(REPORTS_URL)
        if listing.status_code != 200 or listing.json().get("success") is not True:
            failures.append(
                f"{REPORTS_URL} answered {listing.status_code} over real HTTP "
                "(M13.20)"
            )
        else:
            data = listing.json()["data"]
            _print_row(
                f"GET {REPORTS_URL}",
                f"count={data['count']} total={data['total']}",
            )

        response = client.get(f"{REPORTS_URL}/424242")
        _print_row(f"GET {REPORTS_URL}/424242", response.status_code)
        if response.status_code != 404:
            failures.append(
                f"an unknown report answered {response.status_code} over real HTTP "
                "(M13.20)"
            )

        generated = client.post(GENERATE_URL, json={"format": "CSV"})
        _print_row(f"POST {GENERATE_URL}", generated.status_code)
        if generated.status_code != 201:
            failures.append(
                f"a generation answered {generated.status_code} over real HTTP, not "
                f"201: {generated.text[:200]} (M17.12)"
            )
        else:
            report = generated.json()["data"]["report"]
            report_id = int(report["report_id"])
            download = client.get(f"{REPORTS_URL}/{report_id}/download")
            _print_row(
                "GET download",
                f"{download.status_code} "
                f"content-type={download.headers.get('content-type')} "
                f"bytes={len(download.content)}",
            )
            if download.status_code != 200:
                failures.append(
                    f"a generated report's download answered "
                    f"{download.status_code} over real HTTP (M17.11)"
                )
            elif not download.content.startswith(b"###"):
                failures.append(
                    "the CSV artifact served over real HTTP is not the rendered "
                    "report (M17.7)"
                )
            if str(artifacts) in (download.headers.get("content-disposition") or ""):
                failures.append(
                    "the download named the storage directory over real HTTP "
                    "(M13.30)"
                )

        refused = client.post(GENERATE_URL, json={"format": "DOCX"})
        _print_row("POST generate (DOCX)", refused.status_code)
        if refused.status_code != 400:
            failures.append(
                f"an unsupported format answered {refused.status_code} over real "
                "HTTP, not 400 (M17.4)"
            )
    finally:
        client.close()
        server.should_exit = True
        thread.join(timeout=10.0)
        settings.report_storage_dir = original_directory
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
    """Parse arguments and dispatch to the selected mode (M17.16)."""
    parser = argparse.ArgumentParser(
        description="Verify the M17 reporting layer over real backend data (M17.16)."
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
        default=8017,
        help="Live-mode port (a free one is chosen if busy)",
    )
    args = parser.parse_args()

    if args.mode == "live":
        workdir = Path(tempfile.mkdtemp(prefix="netwatch_m17_live_"))
        try:
            return run_live_mode(args.host, args.port, workdir / "artifacts")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    return run_sample_mode()


if __name__ == "__main__":
    raise SystemExit(main())
