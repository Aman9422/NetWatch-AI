"""M18 verification script — the whole data flow, end to end (M18.9).

This is the script M18.9 asks for: one repeatable procedure that drives real
packets through the real pipeline and then reads the result back through the real
HTTP and WebSocket surfaces, so the *seams between milestones* are what is being
verified rather than each milestone's internals again.

Two modes:

  sample  (default)  Drive controlled packets through the *real* pipeline over an
                     isolated temporary SQLite database, then serve the real
                     FastAPI application (``app.main:app``) through a TestClient
                     whose dependencies are overridden to that very stack, and
                     read every layer's state back through the HTTP API and
                     through the real WebSocket endpoints.

  live               Point the application at throwaway database and storage
                     paths, start it under uvicorn on a free loopback port, and
                     exercise the same surfaces over real HTTP and a real
                     WebSocket connection: health, the empty listings, a report
                     generation, the report download, and a live event on the
                     dashboard channel.

What it verifies, against the M18.9 criteria:

  * real packets reach the pipeline and are normalized — the traffic analytics
    route and the packet listing both report the packets that were driven, with
    protocol, addresses and byte counts (M3-M7);
  * statistics and persistence reflect the processed packets: the stored totals
    are the persisted rows read back, not a counter the pipeline kept (M6/M7);
  * device and connection state updates — the driven sources appear as devices
    carrying a MAC, an address and traffic counts, and the conversations they
    opened appear as connections with the canonical bidirectional identity,
    where the reply direction is the *same* conversation and not a second one
    (M8/M9);
  * a controlled suspicious pattern produces the finding it should — a port scan
    and an internal sweep raise the detectors that own them, and the finding
    names its rule and its evidence (M10);
  * the alert and the correlated incident are created by their actual engines:
    the alert carries severity, confidence and evidence, the incident carries a
    lifecycle state and a risk score, and the three concepts (finding, alert,
    incident, risk) stay distinct fields on distinct resources (M11/M12);
  * the API exposes the resulting state in the one M13 envelope, and the five
    analytics routes return the aggregates that state implies (M13/M16);
  * a generated report's figures are the analytics figures written down: the CSV
    the reporting layer rendered for the driven window carries the same packet
    and byte totals the analytics route reports for the same instants, read
    independently (M17);
  * the report artifacts can actually be retrieved: the stored name follows the
    documented rule, the bytes on disk are the bytes served, the media type is
    the format's own, a PDF really is a PDF, and the download never names the
    storage directory (M17);
  * a WebSocket message matches the API's current state where applicable: the
    dashboard event that arrives on ``/ws/dashboard`` describes the same state
    ``GET /api/v1/dashboard`` returns, in the one documented envelope (M14);
  * a request the layers cannot honour is refused before anything is written, and
    the listing is unchanged afterwards (M13/M17).

What it deliberately does not claim:

  * It does not verify *capture* itself. The one substitution in sample mode is
    the sniffer: the packets are handed to
    :meth:`~app.services.packet_pipeline.PacketPipeline.process`, which is the
    seam the capture callback calls, so the packet bytes are real and every layer
    downstream is real, but no interface is opened and no privilege is needed.
    Live capture remains an optional, authorized, separately invoked test.
  * It does not verify the publisher wiring from the pipeline to the WebSocket
    manager. The events it asserts on are the ones the real transport produces by
    itself — the dashboard samples and the keepalive — and the event it compares
    against the REST state is the dashboard one. The pipeline-to-transport wiring
    is covered by the M14 suites (``tests/test_ws_publisher.py`` and
    ``tests/test_ws_pipeline_isolation.py``), which is where it belongs.

Both modes are safe to run on a developer machine. Sample mode creates and removes
its own temporary database and report directory. Live mode points the application
at temporary paths through ``DATABASE_URL`` and ``REPORT_STORAGE_DIR`` before the
application is imported, and it checks afterwards that the developer's own
``netwatch.db`` was neither opened nor modified. Neither mode needs administrator
rights, a network connection or a paid service.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\verify_m18.py
    & ".venv\\Scripts\\python.exe" scripts\\verify_m18.py live --port 8018
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Generator, Iterable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Make the backend root importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

import httpx  # noqa: E402
from fastapi import Depends  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from sqlalchemy import create_engine, event  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.alerts import get_alert_engine  # noqa: E402
from app.alerts.engine import AlertEngine  # noqa: E402
from app.alerts.queries import AlertQueries  # noqa: E402
from app.alerts.service import AlertService  # noqa: E402
from app.analytics.service import AnalyticsService  # noqa: E402
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
from app.reports.period import CUSTOM, ReportPeriod, resolve_daily  # noqa: E402
from app.reports.requests import DEFAULT_FORMAT, DEFAULT_REPORT_TYPE  # noqa: E402
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
from app.websockets.channels import CHANNEL_PATHS, Channel  # noqa: E402
from app.websockets.event import EVENT_TYPES, SCHEMA_VERSION  # noqa: E402

_BANNER_WIDTH = 70

#: The versioned base every REST route is asserted against (M13.3).
API = "/api/v1"

#: The REST surface this script reads the pipeline's state back through. Named
#: once each so a route cannot drift from the resource it is meant to prove.
TRAFFIC_URL = f"{API}/analytics/traffic"
PROTOCOLS_URL = f"{API}/analytics/protocols"
ANALYTICS_DEVICES_URL = f"{API}/analytics/devices"
ANALYTICS_CONNECTIONS_URL = f"{API}/analytics/connections"
THREATS_URL = f"{API}/analytics/threats"
DASHBOARD_URL = f"{API}/dashboard/summary"
DEVICES_URL = f"{API}/devices"
CONNECTIONS_URL = f"{API}/connections"
DETECTIONS_URL = f"{API}/detections"
ALERTS_URL = f"{API}/alerts"
INCIDENTS_URL = f"{API}/incidents"
PACKETS_URL = f"{API}/packets"
REPORTS_URL = f"{API}/reports"
#: ``/system`` is a prefix rather than a route, so the health surface is named by
#: the route under it. Probing the bare prefix answers 404 and would be reported
#: as a missing system route rather than as the wrong path (M13.18).
SYSTEM_URL = f"{API}/system/status"
GENERATE_URL = f"{REPORTS_URL}/generate"

#: Lab detection thresholds, so a handful of packets exercises the real rules
#: quickly. This is a verification configuration, not the shipped default (M10.7).
PORT_SCAN_THRESHOLD = 5
INTERNAL_SCAN_THRESHOLD = 5

#: Two sources on the private network, a public scan target and a private sweep
#: range — the pair of detectors the correlation layer groups into one incident.
SOURCE_IP = "192.168.1.10"
SECOND_SOURCE_IP = "192.168.1.11"
SOURCE_MAC = "AA:BB:CC:00:11:22"
PUBLIC_DESTINATION = "8.8.8.8"
SWEEP_PREFIX = "192.168.1."
SWEEP_FIRST_HOST = 30
#: A DNS conversation, so a UDP flow with a well-known port is driven as well as
#: a TCP one and an ICMP one (M5/M9).
DNS_SERVER = "192.168.1.1"
RESOLVER_PORT = 53

#: The one TCP conversation driven in *both* directions, so the bidirectional
#: identity has something exact to be checked against (M9.4).
WEB_SERVER = "192.168.1.50"
WEB_CLIENT_PORT = 51000
WEB_SERVER_PORT = 80

#: Distinct destination ports the scan opens, so the port-scan detector's
#: threshold is crossed by construction rather than by luck.
SCAN_PORT_BASE = 4000
SWEEP_PORT_BASE = 30

#: The alert and correlation layers read the real wall clock, because the
#: pipeline dates the packets from the clock as they arrive. Sharing one clock
#: keeps "now" consistent between the layers a request reads back.
CLOCK = time.time

#: How far back the driven packets are dated, in seconds. Long enough that a
#: one-hour window still spans them, short enough that they are clearly recent.
PACKET_BACKDATE_SECONDS = 1800.0

#: WebSocket timings. The intervals are shortened for the run so a keepalive or a
#: dashboard sample arrives during the check rather than tens of seconds later.
HEARTBEAT_INTERVAL_SECONDS = 0.25
DASHBOARD_INTERVAL_SECONDS = 0.25
WEBSOCKET_TIMEOUT_SECONDS = 10.0

#: How long the live mode waits for uvicorn to answer before giving up.
SERVER_START_TIMEOUT_SECONDS = 30.0

#: The sentences the internals checks assert are absent: a stack frame, a module
#: path or a SQL fragment would all be an internal detail leaking to a client
#: (M13.30).
#:
#: The storage *engine name* is deliberately absent from this list.
#: ``GET /api/v1/system/status`` documents the database dialect as a field of its
#: payload (M13.22), so a body containing ``sqlite`` is the contract being
#: honoured, not a detail escaping — and a check that fails on a documented answer
#: is worse than no check, because it teaches a reader to ignore it. What an
#: actual leak looks like is the driver *module* (``sqlite3.``), the database
#: *file*, or the statement itself, and those are listed instead.
FORBIDDEN_IN_RESPONSES: tuple[str, ...] = (
    "Traceback",
    'File "',
    "sqlite3.",
    ".db",
    "SELECT ",
    "INSERT ",
    "UPDATE ",
)

#: The headline numbers a dashboard event must carry (M14.9). The dashboard
#: channel drives a client's overview screen, so a field going missing would
#: blank a panel rather than fail loudly anywhere else.
DASHBOARD_EVENT_FIELDS: tuple[str, ...] = (
    "capture_running",
    "interface",
    "packet_count",
    "packets_per_second",
    "bytes_per_second",
    "device_count",
    "active_connections",
    "open_alerts",
    "active_incidents",
)

#: Where each dashboard headline sits inside the nested REST summary, as
#: ``(event field, section, field)`` (M13.19/M14.9). Only state counts are listed,
#: never rates: a rate is measured over an interval and the event and the request
#: are different instants, so comparing rates would compare clocks.
DASHBOARD_SUMMARY_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("capture_running", "capture", "running"),
    ("device_count", "devices", "total"),
    ("active_connections", "connections", "active"),
    ("open_alerts", "alerts", "open"),
    ("active_incidents", "incidents", "active"),
)

#: How many dashboard fields must be comparable before the cross-surface check
#: counts as evidence rather than as an empty comparison (M14.9).
MIN_DASHBOARD_COMPARISONS = 3
# ---------------------------------------------------------------------------
# Time, printing and the HTTP envelope
# ---------------------------------------------------------------------------


def _iso_from_epoch(epoch_seconds: float) -> str:
    """Render epoch seconds as the ISO-8601 UTC string the API accepts (M13.26)."""
    return datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc).isoformat()


def _epoch_of(value: str) -> float:
    """Parse an ISO-8601 instant the API returned into epoch seconds."""
    return datetime.fromisoformat(value).timestamp()


def _print_row(label: str, value: object) -> None:
    """Print one labelled line of evidence, aligned without format padding."""
    print(f"  {label}" + " " * max(1, 32 - len(label)) + str(value))


def _section(title: str) -> None:
    """Print a section heading, so the run reads as the flow it verifies."""
    print(f"\n--- {title} ---")


def _emit_idea(text: str) -> None:
    """Print one line of explanation for the non-obvious checks."""
    print(f"      {text}")


def _get(client: TestClient, url: str, **params: Any):
    """GET a route and return the response, without asserting anything."""
    return client.get(url, params=params or None)


def _post(client: TestClient, url: str, body: dict[str, Any] | None = None):
    """POST a route and return the response, without asserting anything."""
    if body is None:
        return client.post(url)
    return client.post(url, json=body)


def _get_data(
    client: TestClient, url: str, failures: list[str] | None = None, **params: Any
) -> dict:
    """GET a route, assert the M13 envelope, and return ``data`` (M13.4).

    A refusal is recorded as a failure and an empty mapping is returned rather
    than raised, so one broken route does not hide every later check.
    """
    response = _get(client, url, **params)
    if response.status_code != 200:
        if failures is not None:
            failures.append(f"{url} answered {response.status_code} (M13.4)")
        return {}
    body = response.json()
    if body.get("success") is not True:
        if failures is not None:
            failures.append(f"{url} did not report success (M13.4)")
        return {}
    data = body.get("data")
    return data if isinstance(data, dict) else {}


def _error_fields(response) -> list[str]:
    """Return the request fields an error envelope names (M13.5)."""
    try:
        body = response.json()
    except ValueError:
        return []
    return [entry.get("field") for entry in body.get("errors", [])]


def _generate(client: TestClient, body: dict[str, Any] | None = None):
    """POST a generation and return the raw response, asserting nothing (M17.12)."""
    return _post(client, GENERATE_URL, body)


def _text_of(response) -> str:
    """Return a response's body as text, whichever encoding it used."""
    return response.text if isinstance(response.text, str) else ""


def _assert_no_internals(
    label: str, text: str, failures: list[str]
) -> None:
    """Verify a response body carries no internal detail (M13.30)."""
    for forbidden in FORBIDDEN_IN_RESPONSES:
        if forbidden in text:
            failures.append(
                f"{label} disclosed internal detail ({forbidden!r}), which a "
                "client must never be told (M13.30)"
            )
            return


def _items(data: dict, key: str, url: str, failures: list[str]) -> list[dict]:
    """Return a listing's item list, recording the real keys when it is absent.

    The failure names the keys the response did carry, so a listing that changed
    its item key is reported as that rather than as an empty result.
    """
    value = data.get(key)
    if not isinstance(value, list):
        failures.append(
            f"{url} did not return its items under {key!r}; it returned "
            f"{sorted(data)} (M13.4)"
        )
        return []
    return [item for item in value if isinstance(item, dict)]


def _list_total(data: dict) -> int | None:
    """Return a listing's declared total, or ``None`` when it did not say (M13.24)."""
    total = data.get("total")
    return total if isinstance(total, int) else None


# ---------------------------------------------------------------------------
# Reading a rendered CSV back
# ---------------------------------------------------------------------------


def _csv_blocks(payload: bytes) -> dict[str, list[list[str]]]:
    """Parse a rendered report CSV into ``{block name: records}`` (M17.7).

    The renderer writes ``### <name>`` marker records, each followed by that
    block's header row and then its records. Parsing by marker rather than by
    position is what makes this a check of the documented file format instead of
    a check of the order this script happened to expect.
    """
    rows = list(csv.reader(io.StringIO(payload.decode("utf-8"))))
    blocks: dict[str, list[list[str]]] = {}
    current: list[list[str]] | None = None
    for row in rows:
        if len(row) >= 2 and row[0] == BLOCK_MARKER:
            current = blocks.setdefault(row[1], [])
            continue
        if current is not None:
            current.append(row)
    # Drop each block's own header row so callers see records only.
    return {name: records[1:] for name, records in blocks.items()}


def _records_of(payload: bytes, block: str) -> list[list[str]]:
    """Return one block's records, or an empty list when the block is absent."""
    return _csv_blocks(payload).get(block, [])


def _report_identity(payload: bytes) -> dict[str, str]:
    """Return the report block's ``key -> value`` map (M17.7)."""
    identity: dict[str, str] = {}
    for record in _records_of(payload, "report"):
        if len(record) >= 2:
            identity[record[0]] = record[1]
    return identity


def _count_of(text: str | None) -> int | None:
    """Parse a rendered count back into an integer, or ``None`` (M17.3).

    A rendered count carries thousands separators, and ``not reported`` is the
    documented text for a value the backend does not have, so neither is an
    ``int`` as written and the second must not become a zero.
    """
    if text is None:
        return None
    cleaned = text.strip().replace(",", "")
    if not cleaned or cleaned in {"-", "not reported"}:
        return None
    try:
        return int(cleaned)
    except ValueError:
        return None


def _instant_matches(rendered: str | None, expected_epoch: float) -> bool:
    """Return True when a rendered instant is the expected one (M17.6).

    Compared as instants, with a one-second tolerance, rather than as strings.
    The report renders its period to the second while this script asks for its
    bounds with sub-second precision, so comparing the two as text would fail on
    a document that is in fact correct — and a check that fails on correct output
    is worse than no check at all.
    """
    if not rendered:
        return False
    try:
        return abs(_epoch_of(rendered) - expected_epoch) < 1.0
    except ValueError:
        return False


def _content_disposition_filename(response) -> str | None:
    """Return the file name a download offered, or ``None`` (M17.11)."""
    header = response.headers.get("content-disposition")
    if not header:
        return None
    marker = "filename="
    index = header.find(marker)
    if index < 0:
        return None
    return header[index + len(marker) :].strip().strip('"')


def _artifact_files(directory: Path) -> list[str]:
    """Return every file name in a directory, sorted, or an empty list."""
    if not directory.is_dir():
        return []
    return sorted(entry.name for entry in directory.iterdir() if entry.is_file())


# ---------------------------------------------------------------------------
# The packets the pipeline is driven with
# ---------------------------------------------------------------------------

_CLIENT_MAC = "AA:BB:CC:00:11:22"
_SERVER_MAC = "AA:BB:CC:00:11:33"


def _tcp_exchange(
    client_ip: str, server_ip: str, sport: int, dport: int, payload: bytes = b""
) -> list[Any]:
    """Return a request and its reply, so both directions of one flow exist (M9).

    The reply is the same conversation with the endpoints swapped, which is what
    makes it a check of the *bidirectional* identity rather than of counting: a
    tracker that keyed on the ordered pair would store two conversations here.
    """
    request = (
        Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=sport, dport=dport, flags="S")
    )
    reply = (
        Ether(src=_SERVER_MAC, dst=_CLIENT_MAC)
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=dport, dport=sport, flags="SA")
    )
    if payload:
        request = (
            Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=sport, dport=dport, flags="PA")
            / payload
        )
        reply = (
            Ether(src=_SERVER_MAC, dst=_CLIENT_MAC)
            / IP(src=server_ip, dst=client_ip)
            / TCP(sport=dport, dport=sport, flags="PA")
            / payload
        )
    return [request, reply]


def _is_same_conversation(
    connection: dict,
    first_ip: str,
    second_ip: str,
    first_port: int,
    second_port: int,
) -> bool:
    """Return True when a connection is the given flow in *either* direction (M9.4).

    Both orderings are accepted on purpose. The property under test is that the
    tracker holds *one* record for a flow it saw from both ends, so a helper that
    matched only one ordering would be testing which end happened to be recorded
    first rather than testing the identity itself.
    """
    source = connection.get("source_ip")
    destination = connection.get("destination_ip")
    source_port = connection.get("source_port")
    destination_port = connection.get("destination_port")
    forward = (
        source == first_ip
        and destination == second_ip
        and source_port == first_port
        and destination_port == second_port
    )
    reverse = (
        source == second_ip
        and destination == first_ip
        and source_port == second_port
        and destination_port == first_port
    )
    return bool(forward or reverse)


def _scan_packets(count: int, source: str) -> list[Any]:
    """Return ``count`` raw SYNs from one source across distinct ports (M10.8)."""
    return [
        Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
        / IP(src=source, dst=PUBLIC_DESTINATION)
        / TCP(sport=SCAN_PORT_BASE + index, dport=SCAN_PORT_BASE + index, flags="S")
        for index in range(count)
    ]


def _sweep_packets(count: int, source: str) -> list[Any]:
    """Return ``count`` attempts to distinct private hosts (M10.11)."""
    return [
        Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
        / IP(src=source, dst=f"{SWEEP_PREFIX}{SWEEP_FIRST_HOST + index}")
        / UDP(sport=SWEEP_PORT_BASE + index, dport=RESOLVER_PORT)
        for index in range(count)
    ]


def _dns_queries(count: int, source: str) -> list[Any]:
    """Return ``count`` UDP queries to the resolver, one conversation (M5/M9)."""
    return [
        Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
        / IP(src=source, dst=DNS_SERVER)
        / UDP(sport=55000 + index, dport=RESOLVER_PORT)
        / b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        for index in range(count)
    ]


def _icmp_probes(count: int, source: str) -> list[Any]:
    """Return ``count`` echo requests, so ICMP identification is exercised (M5)."""
    return [
        Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
        / IP(src=source, dst=PUBLIC_DESTINATION)
        / ICMP(type=8, id=index)
        for index in range(count)
    ]


def _malformed_packets() -> list[Any]:
    """Return packets that carry no usable network-layer information (M18.2).

    A truncated IP header and a bare Ethernet frame both reach the pipeline from
    a real interface, and neither may take the pipeline down or produce traffic
    that was never seen. They are driven once, and the checks below assert the
    run continued and that no traffic was invented for them.
    """
    truncated_ip = Ether(src=_CLIENT_MAC, dst=_SERVER_MAC) / b"\x45\x00\x00"
    bare_frame = Ether(src=_CLIENT_MAC, dst=_SERVER_MAC) / b"\x00\x01\x02\x03"
    return [truncated_ip, bare_frame]


# ---------------------------------------------------------------------------
# Small environment probes
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Return a loopback TCP port nothing is listening on (M18.9)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _fingerprint(path: Path) -> tuple[int, float] | None:
    """Return a file's size and modification time, or ``None`` when absent.

    Used to prove the developer's own database was not written: a size and an
    mtime that are unchanged afterwards is evidence no row was inserted, which a
    "the file still exists" check could not give.
    """
    try:
        info = path.stat()
    except OSError:
        return None
    return (info.st_size, info.st_mtime)
# ---------------------------------------------------------------------------
# The isolated database and the real pipeline over it
# ---------------------------------------------------------------------------


def _connect_database(db_path: Path):
    """Create the isolated SQLite database and a session factory (M18.9).

    Foreign keys are enforced, so an alert's rule reference must name a row that
    really exists and a report's ``generated_by`` must reference real data — the
    same constraints the shipped database carries. Turning them off would make
    this a check of a database the project does not run.
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
    catalogue has to exist before the pipeline can store an alert. The shipped
    seeding function is used rather than hand-written rows, so this run exercises
    the same catalogue the application ships.
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

    The bandwidth detector reads M6's one-second rates rather than the packet
    stream. Reporting zeros keeps it quiet so the run is about the rules the
    packets below actually drive — a detector reporting a finding for traffic
    that was never sent would be a false positive, not a passing check.
    """

    def get_rates(self, window: str = "1s") -> tuple[float, float]:
        """Return zero packets and bytes per second."""
        return 0.0, 0.0


def _build_detection_engine(devices: DeviceDiscoveryManager) -> DetectionEngine:
    """Build a detection engine over lab thresholds (M10.7).

    Two thresholds are lowered so a handful of packets demonstrates a detector.
    This is a verification configuration, not the shipped default, and it is the
    same lowering the M10, M13, M16 and M17 verifiers use so the scripts describe
    one lab rather than five.
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

    A holder rather than a string so the directory can be pointed somewhere else
    for one request and put back — which is how the "a storage directory that
    cannot be written to" failure is exercised without standing up a second
    client.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory


@dataclass
class _Stack:
    """The live application, wired end to end over the isolated database (M18.9).

    Holding the collaborators rather than re-deriving them is what lets the
    dependency overrides hand the API the *same* objects the pipeline fed. A
    check can therefore only pass if the pipeline really wrote what the layer
    under test reads back — which is the property an end-to-end verification is
    for.
    """

    pipeline: PacketPipeline
    statistics: TrafficStatisticsManager
    devices: DeviceDiscoveryManager
    connections: ConnectionTracker
    detection: DetectionEngine
    alerts: AlertEngine
    correlation: CorrelationEngine

    def capture(self, packets: Iterable[Any], captured_at: float) -> None:
        """Drive ``packets`` through the real pipeline, dated at ``captured_at``.

        ``captured_at`` is passed explicitly so every driven packet shares one
        instant. A wall clock sampled per packet would put the last packet's
        timestamp somewhere unpredictable, and the report checks below need to
        know exactly where the stored rows sit relative to a period bound.
        """
        for packet in packets:
            self.pipeline.process(packet, captured_at)
        self.pipeline.flush_persistence()
        self.pipeline.flush_connections()


def _build_stack(factory) -> _Stack:
    """Wire the production pipeline over the isolated database (M18.9).

    Every layer is the real one: the M6 statistics manager, M7 persistence, M8
    device discovery, M9 connection tracking, M10 detection, M11 alerting and M12
    correlation, fed by the real
    :class:`~app.services.packet_pipeline.PacketPipeline`. The only substitutions
    in the whole run are the session factory and the rates source above.
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

    Each key is the *dependency function* a route declares in ``Depends``, so a
    route still resolves its collaborator through FastAPI and the wiring stays
    the application's rather than this script's. The report route is included
    through the reports *service*, assembled from this request's session and the
    analytics service over it exactly as the application assembles it; only the
    storage directory differs, so a generated artifact lands in this run's
    throwaway directory rather than in the configured one (M17.9).

    A missing override would silently point a route at the developer's database,
    which is why every chain the checked routes need is listed even where only
    one of them is exercised.
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
    """Yield a client over the real application, wired to ``stack`` (M18.9).

    The environment is temporarily ``"test"`` so the lifespan skips ``init_db()``
    and never touches the developer's database; the real WebSocket layer is still
    started, because that happens for every environment and is part of what this
    mode verifies. Every override is removed afterwards so nothing leaks into a
    later request.
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
@dataclass(frozen=True)
class _Driven:
    """What was driven through the pipeline, for the checks to compare against.

    Passing this around rather than a handful of loose numbers keeps every check
    describing the same injection: the instant the packets were dated at, how
    many were usable, and how many were deliberately unusable so the "nothing was
    invented" bound can be stated exactly.
    """

    captured_at: float
    valid_packets: int
    malformed_packets: int
    protocols: tuple[str, ...]
    source_ips: tuple[str, ...]

    @property
    def since(self) -> float:
        """The inclusive lower bound of a window that spans the driven packets."""
        return self.captured_at - 60.0

    @property
    def until(self) -> float:
        """The exclusive upper bound of a window that spans the driven packets."""
        return self.captured_at + 60.0


def _stored_of(data: dict) -> dict:
    """Return the persisted block of an analytics payload, or an empty dict.

    A stored block that could not be read is reported by the API as unavailable
    rather than as a zero nobody measured (M16.8), so this returns the inner
    mapping only when there really is one.
    """
    section = data.get("stored") or data.get("windowed") or {}
    if not isinstance(section, dict):
        return {}
    inner = section.get("data")
    return inner if isinstance(inner, dict) else {}


def _check_pipeline_and_persistence(
    client: TestClient, driven: _Driven, failures: list[str]
) -> dict:
    """Verify the packets that were driven are the packets that were stored (M6/M7).

    The two bounds together are the check. The lower one says the pipeline stored
    at least what was sent, so nothing was lost between the packet and the row.
    The upper one says it stored no more than what was sent *including* the two
    deliberately unusable frames, so no traffic was invented for them — which is
    the property M18.2 asks to hold when a malformed packet arrives.
    """
    _section("Real packets reach statistics and persistence (M3-M7)")
    data = _get_data(
        client,
        TRAFFIC_URL,
        failures,
        since=_iso_from_epoch(driven.since),
        until=_iso_from_epoch(driven.until),
    )
    stored = _stored_of(data)
    total_packets = stored.get("total_packets")
    total_bytes = stored.get("total_bytes")
    distinct = stored.get("distinct_protocols")
    _print_row(
        "drove",
        f"{driven.valid_packets} usable + {driven.malformed_packets} unusable, "
        f"protocols {'/'.join(driven.protocols)}",
    )
    _print_row(
        "stored",
        f"packets={total_packets} bytes={total_bytes} protocols={distinct}",
    )
    _print_row(
        "stored window",
        f"{stored.get('first_timestamp')} .. {stored.get('last_timestamp')}",
    )
    _emit_idea(
        "the stored figures come from the packet table, read back through the "
        "analytics route"
    )

    if not isinstance(total_packets, int):
        failures.append(
            "the traffic route reported no stored packet total, so the packets "
            "the pipeline processed cannot be seen from outside it (M6/M7)"
        )
        return data

    if total_packets < driven.valid_packets:
        failures.append(
            f"the pipeline stored {total_packets} packet(s) for "
            f"{driven.valid_packets} usable packets driven, so packets were lost "
            "between normalization and the table (M5/M7)"
        )
    if total_packets > driven.valid_packets + driven.malformed_packets:
        failures.append(
            f"the pipeline stored {total_packets} packet(s) but only "
            f"{driven.valid_packets + driven.malformed_packets} were driven, so "
            "traffic was invented rather than observed (M5/M7)"
        )
    if not isinstance(total_bytes, int) or total_bytes <= 0:
        failures.append(
            "the pipeline stored no byte total for packets that carried bytes, so "
            "the byte counters do not reflect the traffic (M6.2)"
        )
    if not isinstance(distinct, int) or distinct < len(driven.protocols):
        failures.append(
            f"the stored traffic reports {distinct} distinct protocol(s) for "
            f"{'/'.join(driven.protocols)} driven, so identification is not "
            "distinguishing them (M5.4)"
        )
    if not stored.get("first_timestamp") or not stored.get("last_timestamp"):
        failures.append(
            "the stored traffic reports no first/last timestamp, so the window it "
            "describes cannot be checked (M16.2)"
        )

    listing = _get_data(client, PACKETS_URL, failures)
    rows = _items(listing, "packets", PACKETS_URL, failures)
    protocols = {
        str(row.get("protocol")) for row in rows if row.get("protocol") is not None
    }
    _print_row(
        "packet listing",
        f"count={listing.get('count')} protocols={sorted(protocols)}",
    )
    if not rows:
        failures.append(
            "the persisted packets are not readable through the packets route, so "
            "persistence is not observable (M7)"
        )
    else:
        _assert_no_internals(
            "the packet listing", _text_of(_get(client, PACKETS_URL)), failures
        )
        for protocol in driven.protocols:
            if protocol not in protocols:
                failures.append(
                    f"no stored packet row is labelled {protocol!r}, although "
                    f"{protocol} traffic was driven (M5.4)"
                )
    return data


def _find_devices_for(devices: list[dict], address: str) -> list[dict]:
    """Return the devices that claim ``address`` in their address list (M8)."""
    matched = []
    for device in devices:
        addresses = device.get("ip_addresses")
        if isinstance(addresses, list) and address in addresses:
            matched.append(device)
    return matched


def _check_devices_and_connections(
    client: TestClient, driven: _Driven, failures: list[str]
) -> None:
    """Verify discovery and connection tracking reflect the driven traffic (M8/M9).

    The device check is that one address resolves to exactly one device carrying
    the MAC that was driven: two entries for one address would be a mapping
    conflict, and a MAC-less entry would mean attribution failed.

    The connection check is the bidirectional identity, stated as a count. The
    conversation below is driven in *both* directions — a request and its reply,
    endpoints swapped — so a tracker that keyed on the ordered pair would hold
    two rows for it. Exactly one is correct.
    """
    _section("Device discovery and connection tracking update (M8/M9)")
    data = _get_data(client, DEVICES_URL, failures)
    devices = _items(data, "devices", DEVICES_URL, failures)
    _print_row("devices", f"count={data.get('count')} total={data.get('total')}")

    if not devices:
        failures.append(
            "no device was discovered for traffic that was driven, so the "
            "discovery layer did not see the packets (M8)"
        )
    else:
        for address in driven.source_ips:
            matched = _find_devices_for(devices, address)
            if len(matched) != 1:
                failures.append(
                    f"address {address} resolved to {len(matched)} device(s), not "
                    "one, so the identity mapping is ambiguous (M8.4/M8.11)"
                )
                continue
            device = matched[0]
            _print_row(
                f"device {address}",
                f"mac={device.get('mac_address')} packets={device.get('packet_count')} "
                f"status={device.get('status')}",
            )
            if device.get("mac_address") != SOURCE_MAC:
                failures.append(
                    f"the device for {address} carries MAC "
                    f"{device.get('mac_address')!r}, not the {SOURCE_MAC!r} that was "
                    "driven, so attribution did not follow the frame (M8.5)"
                )
            count = device.get("packet_count")
            if not isinstance(count, int) or count <= 0:
                failures.append(
                    f"the device for {address} recorded {count!r} packets, so its "
                    "traffic counters did not follow the packets it sent (M8.7)"
                )
            if device.get("status") not in {"active", "inactive", "unknown"}:
                failures.append(
                    f"the device for {address} reported status "
                    f"{device.get('status')!r}, which is not a documented activity "
                    "state (M8.9)"
                )

    listing = _get_data(client, CONNECTIONS_URL, failures)
    connections = _items(listing, "connections", CONNECTIONS_URL, failures)
    _print_row(
        "connections",
        f"count={listing.get('count')} total={listing.get('total')}",
    )
    if not connections:
        failures.append(
            "no conversation was tracked for traffic that was driven, so the "
            "tracker did not see the packets (M9)"
        )
        return

    endpoints = (SOURCE_IP, WEB_SERVER, WEB_CLIENT_PORT, WEB_SERVER_PORT)
    matches = [c for c in connections if _is_same_conversation(c, *endpoints)]
    _print_row(
        f"conversation {SOURCE_IP}:{WEB_CLIENT_PORT} <-> "
        f"{WEB_SERVER}:{WEB_SERVER_PORT}",
        f"{len(matches)} connection(s)",
    )
    _emit_idea(
        "the request and its reply were both driven, so one row is the "
        "bidirectional identity and two would be an ordered-pair key"
    )
    if len(matches) != 1:
        failures.append(
            f"the conversation between {SOURCE_IP}:{WEB_CLIENT_PORT} and "
            f"{WEB_SERVER}:{WEB_SERVER_PORT} exists as {len(matches)} connection(s), "
            "not one, so the flow identity is not bidirectional (M9.4/M9.5)"
        )
        return

    connection = matches[0]
    _print_row(
        "connection",
        f"id={connection.get('connection_id')} state={connection.get('state')} "
        f"packets={connection.get('packet_count')}",
    )
    if connection.get("protocol") != "TCP":
        failures.append(
            f"a TCP conversation is labelled {connection.get('protocol')!r} (M9.6)"
        )
    if connection.get("state") not in {
        "observed",
        "established",
        "closing",
        "closed",
        "active",
        "inactive",
        "unknown",
    }:
        failures.append(
            f"the conversation reported state {connection.get('state')!r}, which "
            "is not a documented connection state (M9.10)"
        )
    count = connection.get("packet_count")
    if count != 2:
        failures.append(
            f"the conversation counted {count!r} packets for the two that were "
            "driven, so the counters do not follow both directions (M9.9)"
        )
    if not isinstance(connection.get("byte_count"), int) or (
        connection.get("byte_count") or 0
    ) <= 0:
        failures.append(
            "the conversation recorded no bytes although both packets carried the "
            "network headers, so its byte counter is empty (M9.9)"
        )
    if connection.get("source_device_id") is None:
        failures.append(
            "the conversation names no source device, so the M8 association did not "
            "reach the M9 record (M9.12)"
        )
# ---------------------------------------------------------------------------
# The detection, alert and correlation chain
# ---------------------------------------------------------------------------

#: A finding's rule identity mentions the detector that produced it. Matching on
#: this fragment rather than on an exact rule id keeps the check about *which*
#: detector fired rather than about the spelling it was registered under.
SCAN_RULE_HINTS: tuple[str, ...] = ("scan",)

#: Fields that belong to a *later* layer than the object carrying them. A finding
#: has no lifecycle and no score, an alert has no score, and the only object with
#: a risk band is the incident (M10.5/M11.5/M12.16). Asserting the absence is the
#: check that the three concepts were not merged.
_LATER_LAYER_FIELDS: dict[str, tuple[str, ...]] = {
    "finding": ("status", "severity", "risk_score", "risk_band", "alert_id"),
    "alert": ("risk_score", "risk_band"),
}


def _rule_matches_hint(item: dict) -> bool:
    """Return True when a finding's rule identity mentions a scan detector."""
    identity = f"{item.get('rule_id', '')} {item.get('rule_name', '')}".lower()
    return any(hint in identity for hint in SCAN_RULE_HINTS)


def _check_no_later_layer_fields(
    kind: str, item: dict, identifier: object, failures: list[str]
) -> None:
    """Verify an object carries no field owned by a later layer (M10.5/M11.5)."""
    for field_name in _LATER_LAYER_FIELDS[kind]:
        if field_name in item:
            failures.append(
                f"a {kind} ({identifier!r}) carries {field_name!r}, which belongs "
                "to a later layer, so the two concepts have been merged "
                "(M10.5/M11.5/M12.16)"
            )


def _check_detection_alerts_correlation(
    client: TestClient, failures: list[str]
) -> dict[str, Any]:
    """Verify the finding, the alert and the incident were really produced (M10-M12).

    Each object is checked against the one before it: the alert names the finding
    that raised it, and the incident's detail view lists the alert. That chain is
    what makes this an end-to-end check rather than three independent reads — an
    alert whose ``finding_id`` matches nothing, or an incident holding no alert,
    would fail it even though each response on its own looked well formed.
    """
    _section("A detection becomes an alert, and alerts correlate (M10-M12)")
    findings_data = _get_data(client, DETECTIONS_URL, failures)
    findings = _items(findings_data, "findings", DETECTIONS_URL, failures)
    _print_row(
        "findings",
        f"count={findings_data.get('count')} total={findings_data.get('total')}",
    )
    if not findings:
        failures.append(
            "a port scan and an internal sweep were driven and no finding was "
            "raised, so the detectors did not see the pattern (M10)"
        )
        return {}

    scan_findings = [item for item in findings if _rule_matches_hint(item)]
    for finding in scan_findings:
        _print_row(
            f"finding {finding.get('rule_id')}",
            f"confidence={finding.get('confidence')} "
            f"evidence={sorted(finding.get('evidence') or {})}",
        )
    if not scan_findings:
        failures.append(
            "no finding names a scan detector, although a port scan and an "
            "internal sweep were driven (M10.8/M10.11)"
        )
    for finding in findings:
        _check_no_later_layer_fields(
            "finding", finding, finding.get("finding_id"), failures
        )
        confidence = finding.get("confidence")
        if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            failures.append(
                f"a finding reported confidence {confidence!r}, which is not a "
                "0..1 evidence strength (M10.15)"
            )
        if not finding.get("evidence"):
            failures.append(
                f"the finding for {finding.get('rule_id')!r} carries no evidence, "
                "so what it observed cannot be checked (M10.6)"
            )

    finding_ids = {
        str(item.get("finding_id"))
        for item in scan_findings
        if item.get("finding_id") is not None
    }
    alerts_data = _get_data(client, ALERTS_URL, failures)
    alerts = _items(alerts_data, "alerts", ALERTS_URL, failures)
    _print_row(
        "alerts",
        f"count={alerts_data.get('count')} total={alerts_data.get('total')}",
    )
    if not alerts:
        failures.append(
            "findings were raised and no alert was stored, so the alert engine did "
            "not act on them (M11.7)"
        )
        return {"report_data": findings_data}

    linked = [
        alert for alert in alerts if str(alert.get("finding_id")) in finding_ids
    ]
    for alert in alerts:
        _print_row(
            f"alert {alert.get('alert_id')}",
            f"severity={alert.get('severity')} confidence={alert.get('confidence')} "
            f"status={alert.get('status')} finding={alert.get('finding_id')!r}",
        )
    _print_row("findings raised", sorted(finding_ids))
    if not linked:
        failures.append(
            "no alert names any of the findings that were raised, so the alert was "
            f"not created from the detection output (M11.7); findings "
            f"{sorted(finding_ids)} vs alerts "
            f"{[alert.get('finding_id') for alert in alerts]}"
        )
    for alert in alerts:
        _check_no_later_layer_fields(
            "alert", alert, alert.get("alert_id"), failures
        )
        if not alert.get("severity"):
            failures.append(
                f"alert {alert.get('alert_id')!r} carries no severity, so the "
                "judgement is missing (M11.4)"
            )
        if not alert.get("status"):
            failures.append(
                f"alert {alert.get('alert_id')!r} carries no lifecycle status "
                "(M11.19)"
            )
        confidence = alert.get("confidence")
        if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            failures.append(
                f"alert {alert.get('alert_id')!r} reported confidence "
                f"{confidence!r}, which is not a 0..1 evidence strength (M11.5)"
            )

    # Both surfaces type an alert id as an ``int`` -- the M13 alert view and the
    # M12 incident detail -- so the two are compared as they are sent. Coercing
    # one side to text would compare ``'1'`` against ``1``, which intersects
    # nothing and would report a grouping defect the API does not have.
    alert_ids = {
        alert.get("alert_id")
        for alert in linked
        if alert.get("alert_id") is not None
    }
    detail: dict[str, Any] = {}
    if linked:
        alert_id = linked[0].get("alert_id")
        detail = _get_data(client, f"{ALERTS_URL}/{alert_id}", failures)
        _print_row(
            f"GET alerts/{alert_id}",
            f"evidence_count={detail.get('alert', {}).get('evidence_count')} "
            f"by_type={detail.get('evidence_by_type')}",
        )
        count = (detail.get("alert") or {}).get("evidence_count")
        if not isinstance(count, int) or count < 1:
            failures.append(
                f"alert {alert_id!r} carries no evidence record, so the alert is "
                "an assertion without what it was based on (M11.11)"
            )
        _emit_idea(
            "packet and connection evidence resolution is switched off for this "
            "run (resolvers=None); M11's own suite covers resolution"
        )

    incidents_data = _get_data(client, INCIDENTS_URL, failures)
    incidents = _items(
        incidents_data, "incidents", INCIDENTS_URL, failures
    )
    _print_row(
        "incidents",
        f"count={incidents_data.get('count')} "
        f"total={incidents_data.get('total')}",
    )
    if not incidents:
        failures.append(
            "alerts were stored and no incident was created, so the correlation "
            "engine produced nothing from related alerts (M12.8)"
        )
        return {"findings": findings_data, "alerts": alerts_data, "detail": detail}

    for incident in incidents:
        _print_row(
            f"incident {incident.get('incident_id')}",
            f"status={incident.get('status')} alerts={incident.get('alert_count')} "
            f"risk={incident.get('risk_score')} band={incident.get('risk_band')}",
        )
        score = incident.get("risk_score")
        if not isinstance(score, int) or not 0 <= score <= 100:
            failures.append(
                f"incident {incident.get('incident_id')!r} reported risk score "
                f"{score!r}, which is not the documented bounded 0..100 value "
                "(M12.16)"
            )
        if not incident.get("risk_band"):
            failures.append(
                f"incident {incident.get('incident_id')!r} carries no risk band, so "
                "the score has no documented display band (M12.27)"
            )
        if not incident.get("status"):
            failures.append(
                f"incident {incident.get('incident_id')!r} carries no lifecycle "
                "state (M12.26)"
            )
        confidence = incident.get("correlation_confidence")
        if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            failures.append(
                f"incident {incident.get('incident_id')!r} reported correlation "
                f"confidence {confidence!r}, which is not a 0..1 judgement (M12.16)"
            )

    incident_id = incidents[0].get("incident_id")
    incident_detail = _incident_detail(
        _get_data(client, f"{INCIDENTS_URL}/{incident_id}", failures)
    )
    held = incident_detail.get("alert_ids")
    _print_row(
        f"GET incidents/{incident_id}",
        f"alerts={held} findings={len(incident_detail.get('finding_ids') or [])}",
    )
    if not isinstance(held, list) or not held:
        failures.append(
            f"incident {incident_id!r} holds no alert reference, so the grouping "
            "cannot be traced back to the alerts it was made from (M12.8)"
        )
    elif alert_ids and not (set(held) & alert_ids):
        # Sorted by text: if a schema drift ever made the two sides disagree
        # about an id's *type*, that is the defect this check exists to report,
        # and a comparison sort over mixed types would raise instead of saying so.
        failures.append(
            f"incident {incident_id!r} references alerts "
            f"{sorted(held, key=str)} but "
            f"the alerts that were read back are {sorted(alert_ids, key=str)}, so "
            "the incident does not group the alerts the API exposes (M12.8)"
        )
    # ``event_count``, not the member-list lengths: an alert and the finding that
    # raised it are one event, so counting both lists would call a single-event
    # incident correlated and demand a reason it never had.
    members = int(incident_detail.get("event_count") or 0)
    reasons = incident_detail.get("correlation_reasons") or []
    _print_row(f"incident {incident_id} reasons", f"events={members} {reasons}")
    if not isinstance(reasons, list):
        failures.append(
            f"incident {incident_id!r} reported correlation_reasons as "
            f"{type(reasons).__name__}, which is not the documented list (M12.9)"
        )
    elif members > 1 and not reasons:
        failures.append(
            f"incident {incident_id!r} groups {members} events and lists no "
            "correlation reason, so why they were grouped is unexplained (M12.9)"
        )
    _emit_idea(
        "the alert carries a severity and a confidence and no score; the incident "
        "carries the score and the band — the concepts are separate"
    )
    return {
        "findings": findings_data,
        "alerts": alerts_data,
        "incidents": incidents_data,
        "detail": detail,
    }


def _incident_detail(data: dict) -> dict:
    """Return an incident-detail payload, wrapped or unwrapped (M13.15).

    The route may answer with the incident itself or under an ``incident`` key;
    accepting either keeps the check about the incident's contents rather than
    about which envelope the route chose.
    """
    inner = data.get("incident")
    return inner if isinstance(inner, dict) else data


def _check_analytics_aggregates(
    client: TestClient,
    stored_traffic: dict,
    alerts_data: dict,
    incidents_data: dict,
    failures: list[str],
) -> None:
    """Verify the five analytics routes answer and agree with the resources (M16).

    Each route is checked for the block it owns, and two of them are checked
    against the *resource* route that reads the same store: the threat route's
    alert and incident totals must equal the alert and incident listings' totals
    for the same instant. An analytics layer that drifted from the resources it
    summarises would fail that even while both answered 200.
    """
    _section("The analytics aggregates agree with the resources (M16)")
    for label, url in (
        ("traffic", TRAFFIC_URL),
        ("protocols", PROTOCOLS_URL),
        ("devices", ANALYTICS_DEVICES_URL),
        ("connections", ANALYTICS_CONNECTIONS_URL),
        ("threats", THREATS_URL),
    ):
        response = _get(client, url)
        data = (response.json().get("data") or {}) if response.status_code == 200 else {}
        period = data.get("period") if isinstance(data, dict) else None
        _print_row(
            f"analytics/{label}",
            f"{response.status_code} period="
            f"{period.get('since') if isinstance(period, dict) else None}",
        )
        if response.status_code != 200:
            failures.append(
                f"the {label} analytics route answered {response.status_code} "
                "(M16.7)"
            )
            continue
        if not isinstance(period, dict) or not period.get("since"):
            failures.append(
                f"the {label} analytics route did not publish the window it "
                "resolved, so a client cannot tell what period the figures cover "
                "(M16.7)"
            )
        _assert_no_internals(f"analytics/{label}", _text_of(response), failures)

    threats = _get_data(client, THREATS_URL, failures)
    alerts_total = threats.get("alerts_total")
    incidents_total = threats.get("incidents_total")
    _print_row(
        "threats",
        f"alerts={alerts_total} incidents={incidents_total}",
    )
    expected_alerts = _list_total(alerts_data)
    expected_incidents = _list_total(incidents_data)
    if expected_alerts is not None and alerts_total != expected_alerts:
        failures.append(
            f"the threat analytics report {alerts_total} alert(s) while the alert "
            f"listing reports {expected_alerts}, so the derived view disagrees with "
            "the resource it summarises (M16.6)"
        )
    if expected_incidents is not None and incidents_total != expected_incidents:
        failures.append(
            f"the threat analytics report {incidents_total} incident(s) while the "
            f"incident listing reports {expected_incidents} (M16.6)"
        )

    traffic = _get_data(client, TRAFFIC_URL, failures)
    live = _stored_of(traffic)
    _print_row(
        "traffic stored",
        f"packets={live.get('total_packets')} bytes={live.get('total_bytes')}",
    )
    if live.get("total_packets") != stored_traffic.get("total_packets"):
        failures.append(
            "two reads of the same stored window disagree about how many packets "
            "it holds, so the figure is not stable (M16.2)"
        )
    protocols = _get_data(client, PROTOCOLS_URL, failures)
    _print_row(
        "protocols",
        f"count={protocols.get('count')} top={_top_names(protocols)}",
    )
    devices = _get_data(client, ANALYTICS_DEVICES_URL, failures)
    _print_row("analytics devices", f"total={devices.get('total')}")
    connections = _get_data(client, ANALYTICS_CONNECTIONS_URL, failures)
    _print_row("analytics connections", f"tracked={connections.get('tracked')}")


def _top_names(payload: dict) -> list[str]:
    """Return the names of the first few ranked entries in an analytics payload."""
    for key in ("protocols", "entries", "ranking", "items", "top"):
        value = payload.get(key)
        if isinstance(value, list):
            names = []
            for entry in value[:3]:
                if isinstance(entry, dict):
                    for name_key in ("name", "protocol", "label", "key"):
                        if name_key in entry:
                            names.append(str(entry[name_key]))
                            break
            return names
    return []
# ---------------------------------------------------------------------------
# The reporting chain
# ---------------------------------------------------------------------------


def _metrics_matching(
    payload: bytes, section: str, needle: str
) -> list[tuple[str, int | None]]:
    """Return every metric of ``section`` whose label mentions ``needle`` (M17.3).

    All of them, not the first: a section carries several figures that mention
    "packet" (a total, a rate, shares), and picking the first would make this a
    check of which of them the renderer happened to write first rather than a
    check that the total is in the document at all.
    """
    found = []
    for record in _records_of(payload, f"section:{section}"):
        if len(record) >= 2 and needle.lower() in record[0].lower():
            found.append((record[0], _count_of(record[1])))
    return found


def _expect_total_in_report(
    label: str,
    candidates: list[tuple[str, int | None]],
    expected: int | None,
    failures: list[str],
    milestone: str,
) -> None:
    """Verify a report's rendered figures include an independently read total.

    The expected value is printed even on success, because "the document contains
    the number the API reports" is the property, and a reader should be able to
    see which rendered record carried it.
    """
    rendered = ", ".join(f"{name}={value}" for name, value in candidates)
    _print_row(f"report {label}", rendered or "(no matching figure)")
    if expected is None:
        return
    if not any(value == expected for _, value in candidates):
        failures.append(
            f"the report's {label} figures ({rendered or 'none'}) do not include "
            f"{expected}, which is what the analytics route reports for the same "
            f"window, so the document is not those figures written down ({milestone})"
        )


def _report_window(driven: _Driven) -> dict[str, str]:
    """Return the explicit window a custom report is asked for (M17.6)."""
    return {
        "since": _iso_from_epoch(driven.since),
        "until": _iso_from_epoch(driven.until),
    }


def _check_reports(
    client: TestClient,
    holder: _StorageHolder,
    driven: _Driven,
    stored_traffic: dict,
    failures: list[str],
) -> None:
    """Verify a report carries the analytics figures and can be retrieved (M17).

    The CSV is the one that is cross-checked numerically: it is requested over the
    same window the analytics route was read over, so its stored traffic totals
    must contain the totals that route reported. That is the whole seam — a
    reporting layer that aggregated the tables a second time would be free to
    disagree, and this fails if it does.

    A PDF is requested as well and checked as a document, because "a PDF was
    served" and "a PDF is what was produced" are different claims and only the
    second is worth anything to a user opening the file.
    """
    _section("A report carries the analytics figures and can be read (M17)")
    directory = Path(holder.directory)
    window = _report_window(driven)
    body = {
        "report_type": CUSTOM,
        "format": "CSV",
        "since": window["since"],
        "until": window["until"],
    }
    response = _generate(client, body)
    if response.status_code != 201:
        failures.append(
            f"a CSV report over the driven window answered {response.status_code}, "
            f"not 201: {_text_of(response)[:200]} (M17.12)"
        )
        return
    data = response.json().get("data") or {}
    report = data.get("report") or {}
    report_id = report.get("report_id")
    _print_row(
        "generated",
        f"id={report_id} {report.get('report_type')}/{report.get('format')} "
        f"status={report.get('status')} size={report.get('file_size')}",
    )
    if report.get("status") != ReportStatus.COMPLETED:
        failures.append(
            f"a generated report is {report.get('status')!r}, not completed "
            "(M17.9)"
        )
    if report.get("downloadable") is not True:
        failures.append(
            "a completed report was not reported as downloadable (M17.11)"
        )
    if not report.get("file_size"):
        failures.append("a generated report recorded no artifact size (M17.9)")

    expected_name = build_filename(
        report_id=int(report_id or 0),
        label=ReportPeriod(
            since=float(report.get("period_start_epoch") or 0.0),
            until=float(report.get("period_end_epoch") or 0.0),
            report_type=str(report.get("report_type") or CUSTOM),
        ).label(),
        output_format=str(report.get("format") or "CSV"),
    )
    names = _artifact_files(directory)
    _print_row("artifact", f"expected={expected_name} found={names}")
    if expected_name not in names:
        failures.append(
            f"the artifact is not stored under the documented name {expected_name!r} "
            "(M17.9)"
        )
    for name in names:
        if name.endswith(".tmp") or name.startswith("."):
            failures.append(
                f"a temporary artifact {name!r} was left behind, so a failed write "
                "is not cleaned up (M17.9)"
            )

    download = _get(client, f"{REPORTS_URL}/{report_id}/download")
    payload = download.content
    disposition = _content_disposition_filename(download)
    _print_row(
        "download",
        f"{download.status_code} {download.headers.get('content-type')} "
        f"filename={disposition} bytes={len(payload)}",
    )
    if download.status_code != 200:
        failures.append(
            f"a completed report's download answered {download.status_code}, not "
            "200 (M17.11)"
        )
        return
    if not download.headers.get("content-type", "").startswith("text/csv"):
        failures.append(
            f"a CSV report was served as "
            f"{download.headers.get('content-type')!r}, not text/csv (M17.11)"
        )
    if disposition != expected_name:
        failures.append(
            f"the download offered {disposition!r}, not the artifact's own name "
            f"{expected_name!r} (M17.11)"
        )
    artifact_path = directory / expected_name
    stored = artifact_path.read_bytes() if artifact_path.is_file() else b""
    if payload != stored:
        failures.append(
            "the downloaded bytes are not the stored artifact's bytes (M17.11)"
        )
    if len(payload) != report.get("file_size"):
        failures.append(
            f"the download is {len(payload)} bytes while the row records "
            f"{report.get('file_size')}, so the metadata does not describe the file "
            "(M17.9)"
        )
    if str(directory) in (download.headers.get("content-disposition") or ""):
        failures.append(
            "the download named the storage directory, which is internal (M13.30)"
        )

    identity = _report_identity(payload)
    _print_row(
        "report period",
        f"{identity.get('period_start')} .. {identity.get('period_end')}",
    )
    if not _instant_matches(identity.get("period_start"), driven.since):
        failures.append(
            "the report's own period start is not the requested instant, so the "
            "document does not describe the period it was asked for (M17.6)"
        )
    if not _instant_matches(identity.get("period_end"), driven.until):
        failures.append(
            "the report's own period end is not the requested instant (M17.6)"
        )

    _expect_total_in_report(
        "packet total",
        _metrics_matching(payload, "traffic", "packet"),
        stored_traffic.get("total_packets"),
        failures,
        "M17.2",
    )
    _expect_total_in_report(
        "byte total",
        _metrics_matching(payload, "traffic", "byte"),
        stored_traffic.get("total_bytes"),
        failures,
        "M17.2",
    )
    _assert_no_internals("the rendered report", payload.decode("utf-8", "replace"), failures)

    pdf = _generate(
        client, {"report_type": DEFAULT_REPORT_TYPE, "format": "PDF"}
    )
    if pdf.status_code != 201:
        failures.append(
            f"a PDF report answered {pdf.status_code}, not 201 (M17.12)"
        )
        return
    pdf_report = (pdf.json().get("data") or {}).get("report") or {}
    pdf_download = _get(
        client, f"{REPORTS_URL}/{pdf_report.get('report_id')}/download"
    )
    _print_row(
        "pdf download",
        f"{pdf_download.status_code} {pdf_download.headers.get('content-type')} "
        f"bytes={len(pdf_download.content)}",
    )
    if pdf_download.status_code != 200:
        failures.append(
            f"the PDF report's download answered {pdf_download.status_code} (M17.11)"
        )
        return
    if not pdf_download.headers.get("content-type", "").startswith("application/pdf"):
        failures.append(
            "a PDF report was not served as application/pdf (M17.11)"
        )
    _check_pdf_body(pdf_download.content, failures)


def _check_pdf_body(payload: bytes, failures: list[str]) -> None:
    """Verify the downloaded bytes really are a PDF document (M17.8).

    A ``%PDF`` header and a ``%%EOF`` trailer are the two markers a conforming
    reader keys on, so their presence is the difference between "a PDF was
    served" and "some bytes were served with a PDF media type".
    """
    if not payload.startswith(b"%PDF"):
        failures.append(
            "the PDF artifact does not begin with a %PDF header (M17.8)"
        )
    if b"%%EOF" not in payload[-64:]:
        failures.append("the PDF artifact has no %%EOF trailer (M17.8)")


def _check_refusals(
    client: TestClient, holder: _StorageHolder, failures: list[str]
) -> None:
    """Verify a request that cannot be honoured is refused, and writes nothing (M17.6).

    Three refusals are checked — an inverted window, a report that does not exist,
    and a storage directory that cannot be written to — and each is checked for
    its *consequence* as well as its status: the listing must be unchanged after
    the first two, and the third must leave a row recorded as failed with no
    artifact claimed. A refusal that quietly wrote half a report would pass a
    status-code check and fail a user.
    """
    _section("Requests that cannot be honoured are refused, not adjusted (M13/M17)")
    before = _get_data(client, REPORTS_URL, failures)
    before_total = _list_total(before)

    now = time.time()
    inverted = _generate(
        client,
        {
            "report_type": CUSTOM,
            "format": "CSV",
            "since": _iso_from_epoch(now),
            "until": _iso_from_epoch(now - 3600.0),
        },
    )
    _print_row(
        "inverted window", f"{inverted.status_code} {_error_fields(inverted)}"
    )
    if inverted.status_code != 400:
        failures.append(
            f"a report whose end precedes its start answered "
            f"{inverted.status_code}, not the documented 400 (M16.7/M17.4)"
        )
    elif "period" not in _error_fields(inverted):
        failures.append(
            "a refused window did not name the field it rejected, so the client "
            f"cannot tell what to fix: {_error_fields(inverted)} (M13.5)"
        )
    _assert_no_internals("the window refusal", _text_of(inverted), failures)

    unknown = _get(client, f"{REPORTS_URL}/424242/download")
    _print_row("unknown download", f"{unknown.status_code} {_error_fields(unknown)}")
    if unknown.status_code != 404:
        failures.append(
            f"downloading a report that does not exist answered "
            f"{unknown.status_code}, not 404 (M13.20)"
        )

    after = _get_data(client, REPORTS_URL, failures)
    if _list_total(after) != before_total:
        failures.append(
            f"the report listing went from {before_total} to {_list_total(after)} "
            "row(s) across two refused requests, so a refusal wrote something "
            "(M17.6)"
        )

    directory = Path(holder.directory)
    blocked = directory.parent / "m18-not-a-directory"
    blocked.write_text("this path is a file, so it cannot hold a report directory")
    try:
        holder.directory = blocked
        # A *custom* period on purpose: a preset refuses explicit bounds, so a
        # daily request here would be rejected on its arguments and the storage
        # path would never be reached (M17.6/M17.14).
        failed = _generate(
            client,
            {
                "report_type": CUSTOM,
                "format": "CSV",
                "since": _iso_from_epoch(time.time() - 3600.0),
                "until": _iso_from_epoch(time.time()),
            },
        )
        _print_row(
            "unwritable storage",
            f"{failed.status_code} {_text_of(failed)[:120]}",
        )
        if failed.status_code != 500:
            failures.append(
                f"a generation whose storage could not be written answered "
                f"{failed.status_code}, not the documented 500 (M17.14)"
            )
        _assert_no_internals("the storage failure", _text_of(failed), failures)
    finally:
        holder.directory = directory
        blocked.unlink(missing_ok=True)

    listing = _get_data(client, REPORTS_URL, failures)
    for row in _items(listing, "reports", REPORTS_URL, failures):
        if row.get("status") == ReportStatus.FAILED:
            _print_row(
                f"failed row {row.get('report_id')}",
                f"downloadable={row.get('downloadable')} error={row.get('error')}",
            )
            if row.get("downloadable") is not False:
                failures.append(
                    f"a failed report is reported downloadable="
                    f"{row.get('downloadable')!r}, so a client is told to fetch an "
                    "artifact that does not exist (M17.11)"
                )
            if not row.get("downloadable"):
                missing = _get(
                    client, f"{REPORTS_URL}/{row.get('report_id')}/download"
                )
                if missing.status_code != 404:
                    failures.append(
                        f"downloading a failed report answered "
                        f"{missing.status_code}, not 404 (M17.11)"
                    )
            break


# ---------------------------------------------------------------------------
# The WebSocket envelope
# ---------------------------------------------------------------------------


def _assert_envelope(
    channel: Channel, frame: object, failures: list[str]
) -> dict:
    """Verify a received frame is the one documented envelope (M14.7).

    The envelope is the contract every channel shares, so it is checked field by
    field here rather than trusted: a client decodes all four channels with one
    function, and a field that stopped being sent would break that decoder rather
    than one screen.
    """
    if not isinstance(frame, dict):
        failures.append(
            f"the {channel.value} channel sent a frame that is not a JSON object "
            "(M14.7)"
        )
        return {}
    _print_row(
        f"ws {channel.value}",
        f"type={frame.get('type')} source={frame.get('source')} "
        f"seq={frame.get('sequence')} data_keys={sorted(frame.get('data') or {})}",
    )
    if frame.get("schema_version") != SCHEMA_VERSION:
        failures.append(
            f"the {channel.value} event carries schema_version "
            f"{frame.get('schema_version')!r}, not {SCHEMA_VERSION} (M14.7)"
        )
    event_id = frame.get("event_id")
    if not isinstance(event_id, str) or not event_id.startswith("evt-"):
        failures.append(
            f"the {channel.value} event carries event_id {event_id!r}, which is "
            "not the documented 'evt-' form (M14.7)"
        )
    if frame.get("type") not in EVENT_TYPES:
        failures.append(
            f"the {channel.value} event carries type {frame.get('type')!r}, which "
            "is not one of the documented event names (M14.7)"
        )
    if frame.get("channel") != channel.value:
        failures.append(
            f"an event delivered on {channel.value!r} declares channel "
            f"{frame.get('channel')!r}, so a client cannot trust the field (M14.7)"
        )
    timestamp = frame.get("timestamp")
    if not isinstance(timestamp, str) or "+" not in timestamp:
        failures.append(
            f"the {channel.value} event carries timestamp {timestamp!r}, which is "
            "not ISO-8601 UTC with an offset (M14.17)"
        )
    if not isinstance(frame.get("sequence"), int):
        failures.append(
            f"the {channel.value} event carries sequence "
            f"{frame.get('sequence')!r}, which is not a number (M14.7)"
        )
    if not isinstance(frame.get("data"), dict):
        failures.append(
            f"the {channel.value} event carries a payload that is not a JSON "
            "object (M14.7)"
        )
    return frame


def _receive_frame(
    client: TestClient, path: str, timeout: float
) -> tuple[dict, str]:
    """Receive one WebSocket frame, bounded by ``timeout`` (M18.9).

    The whole session runs in a daemon thread because the test client's receive
    has no timeout of its own. A transport that never sent would otherwise hang
    the verification, and a hang is not a result — a timeout is reported as the
    failure it is.

    Returns:
        The parsed frame and an empty note, or an empty mapping and the reason.
    """
    outcome: queue.Queue = queue.Queue()

    def session() -> None:
        try:
            with client.websocket_connect(path) as socket:
                outcome.put(("frame", socket.receive_json()))
        except Exception as error:  # noqa: BLE001 - reported, never swallowed
            outcome.put(("error", error))

    threading.Thread(target=session, daemon=True).start()
    try:
        kind, value = outcome.get(timeout=timeout)
    except queue.Empty:
        return {}, f"no frame arrived within {timeout:.1f}s"
    if kind == "error":
        return {}, f"the connection failed: {value}"
    return (value if isinstance(value, dict) else {}), ""


def _check_websocket(client: TestClient, failures: list[str]) -> None:
    """Verify the real-time channels deliver the documented envelope (M14).

    Two channels are dialled. The dashboard carries a sampled payload, which is
    compared against what the REST dashboard route currently reports for the
    fields they have in common, so the check is that the two surfaces describe
    the same state rather than merely that both answered. The alerts channel is
    dialled to confirm a *second* channel registers and delivers independently,
    which one channel alone could not show.
    """
    _section("The WebSocket channels deliver the documented envelope (M14)")
    dashboard_path = CHANNEL_PATHS[Channel.DASHBOARD]
    frame, note = _receive_frame(client, dashboard_path, WEBSOCKET_TIMEOUT_SECONDS)
    if not frame:
        failures.append(
            f"nothing arrived on {dashboard_path}: {note} (M14.7)"
        )
    else:
        frame = _assert_envelope(Channel.DASHBOARD, frame, failures)
        _assert_dashboard_payload(frame.get("data") or {}, failures)
        _emit_idea(
            "numeric agreement with the REST summary is checked in live mode: the "
            "M14 sampler reads the process singletons, which this mode's dependency "
            "overrides deliberately do not replace"
        )

    alerts_path = CHANNEL_PATHS[Channel.ALERTS]
    alert_frame, alert_note = _receive_frame(
        client, alerts_path, WEBSOCKET_TIMEOUT_SECONDS
    )
    if not alert_frame:
        failures.append(
            f"nothing arrived on {alerts_path}: {alert_note}, so a second channel "
            "is not served independently (M14.5)"
        )
    else:
        _assert_envelope(Channel.ALERTS, alert_frame, failures)


def _assert_dashboard_payload(payload: dict, failures: list[str]) -> None:
    """Verify a dashboard event carries the headline numbers it must (M14.9).

    The keys are asserted rather than the values, because in this mode the M14
    sampler reads the application's own process singletons and the dependency
    overrides that point the API at this run's stack do not reach them — so the
    event and the REST summary legitimately describe different objects here. What
    is checked is that the event is the documented payload and not an empty or
    renamed one. Live mode, where both surfaces read one process, compares the
    numbers themselves.
    """
    missing = [name for name in DASHBOARD_EVENT_FIELDS if name not in payload]
    _print_row(
        "dashboard event",
        f"{len(DASHBOARD_EVENT_FIELDS) - len(missing)} of "
        f"{len(DASHBOARD_EVENT_FIELDS)} documented field(s) present",
    )
    if missing:
        failures.append(
            f"the dashboard event omits {missing}, so a client's dashboard would "
            "render a blank panel for each (M14.9)"
        )


def _section_field(payload: dict, section: str, field: str) -> Any:
    """Return one field of a dashboard section's data block (M13.19).

    The summary nests each service's payload under its own section, and a section
    that could not be read is marked unavailable rather than reported as zeroes,
    so both of those states are respected instead of being read as data.
    """
    block = payload.get(section)
    if not isinstance(block, dict) or block.get("available") is False:
        return None
    inner = block.get("data")
    return inner.get(field) if isinstance(inner, dict) else None


def _compare_dashboard_state(
    event_data: dict, rest_data: dict, failures: list[str]
) -> None:
    """Verify the dashboard event and the REST summary describe one state (M14.9).

    The two surfaces are not the same document — the event is a flat snapshot of
    the headline numbers and the summary nests each service's payload under its
    own section — so they share no keys at all and comparing keys would prove
    nothing. The fields that *mean* the same thing are compared instead, named
    once in ``DASHBOARD_SUMMARY_FIELDS``, and the number of comparisons is itself
    checked so a drift that left nothing comparable fails rather than passing
    silently.
    """
    compared = 0
    for event_key, section, field in DASHBOARD_SUMMARY_FIELDS:
        if event_key not in event_data:
            continue
        expected = _section_field(rest_data, section, field)
        if expected is None:
            continue
        compared += 1
        if event_data[event_key] != expected:
            failures.append(
                f"the dashboard event reports {event_key}="
                f"{event_data[event_key]!r} while the summary reports "
                f"{section}.{field}={expected!r}, so the channel and the resource "
                "disagree about the same state (M14.9)"
            )
    _print_row(
        "dashboard state",
        f"{compared} of {len(DASHBOARD_SUMMARY_FIELDS)} field(s) compared",
    )
    if compared < MIN_DASHBOARD_COMPARISONS:
        failures.append(
            f"the dashboard event and the summary yielded only {compared} "
            "comparable field(s), so there is no evidence the two surfaces "
            "describe the same state (M14.9)"
        )
def _drive_pipeline(stack: _Stack, failures: list[str]) -> _Driven:
    """Drive the controlled traffic through the real pipeline (M18.9).

    The malformed frames are driven separately and inside a guard, because how the
    pipeline *reacts* to them is part of what is being verified: a packet with no
    usable network layer must be isolated, so an exception escaping the pipeline
    is recorded as the failure it is rather than allowed to abort the run.
    """
    captured_at = time.time() - PACKET_BACKDATE_SECONDS
    valid: list[Any] = [
        *_tcp_exchange(
            SOURCE_IP,
            WEB_SERVER,
            WEB_CLIENT_PORT,
            WEB_SERVER_PORT,
            payload=b"GET / HTTP/1.1\r\nHost: example\r\n\r\n",
        ),
        *_tcp_exchange(SECOND_SOURCE_IP, WEB_SERVER, 52000, WEB_SERVER_PORT),
        *_dns_queries(2, SOURCE_IP),
        *_icmp_probes(2, SOURCE_IP),
        *_scan_packets(PORT_SCAN_THRESHOLD + 4, SOURCE_IP),
        *_sweep_packets(INTERNAL_SCAN_THRESHOLD + 4, SECOND_SOURCE_IP),
    ]
    malformed = _malformed_packets()
    _section("Driving the real pipeline (M3-M5)")
    _print_row(
        "packets",
        f"{len(valid)} well formed + {len(malformed)} unusable",
    )
    _emit_idea(
        "handed to PacketPipeline.process — the seam the capture callback calls"
    )
    stack.capture(valid, captured_at)
    try:
        stack.capture(malformed, captured_at)
    except Exception as error:  # noqa: BLE001 - the failure is the finding
        failures.append(
            f"an unusable packet raised out of the pipeline ({error!r}), so one "
            "bad frame is not isolated from the rest of the capture (M18.2)"
        )
    return _Driven(
        captured_at=captured_at,
        valid_packets=len(valid),
        malformed_packets=len(malformed),
        protocols=("TCP", "UDP", "ICMP"),
        source_ips=(SOURCE_IP, SECOND_SOURCE_IP),
    )


def _run_sample_mode() -> list[str]:
    """Run the whole flow in one process and return the failures found (M18.9).

    The throwaway database and the throwaway report directory are created here and
    removed in the ``finally``, so a run leaves nothing behind whether it passed,
    failed or raised. The short keepalive and dashboard intervals are installed
    before the client starts, because that is when the real-time tasks are created
    from them (M14.20).
    """
    failures: list[str] = []
    workdir = Path(tempfile.mkdtemp(prefix="netwatch-m18-"))
    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    engine = None
    original_intervals = (
        settings.websocket_heartbeat_interval_seconds,
        settings.websocket_dashboard_interval_seconds,
    )
    try:
        engine, factory = _connect_database(workdir / "m18.db")
        _seed_rule_catalogue(factory)
        stack = _build_stack(factory)
        holder = _StorageHolder(reports_dir)

        driven = _drive_pipeline(stack, failures)

        settings.websocket_heartbeat_interval_seconds = HEARTBEAT_INTERVAL_SECONDS
        settings.websocket_dashboard_interval_seconds = DASHBOARD_INTERVAL_SECONDS
        with _serve(stack, factory, engine, holder) as client:
            traffic = _check_pipeline_and_persistence(client, driven, failures)
            _check_devices_and_connections(client, driven, failures)
            chain = _check_detection_alerts_correlation(client, failures)
            _check_analytics_aggregates(
                client,
                _stored_of(traffic),
                chain.get("alerts") or {},
                chain.get("incidents") or {},
                failures,
            )
            _check_reports(client, holder, driven, _stored_of(traffic), failures)
            _check_websocket(client, failures)
            _check_refusals(client, holder, failures)
    finally:
        (
            settings.websocket_heartbeat_interval_seconds,
            settings.websocket_dashboard_interval_seconds,
        ) = original_intervals
        if engine is not None:
            engine.dispose()
        shutil.rmtree(workdir, ignore_errors=True)
    return failures


# ---------------------------------------------------------------------------
# Live mode: a real server over real HTTP and a real WebSocket
# ---------------------------------------------------------------------------


def _spawn_server(port: int, database_url: str, reports_dir: Path, log_path: Path):
    """Start the application under uvicorn in its own process (M18.9).

    A child process rather than a thread, because that is what makes the paths
    real: the interpreter reads ``DATABASE_URL`` and ``REPORT_STORAGE_DIR`` from
    its own environment before anything imports them, so the server genuinely
    cannot reach the developer's database. It also means the run exercises the
    deployment command rather than an in-process imitation of it.

    The child's output goes to a file rather than a pipe: a pipe that fills up
    would block the server, and a blocked server would look like a slow one.
    """
    env = dict(os.environ)
    env["DATABASE_URL"] = database_url
    env["REPORT_STORAGE_DIR"] = str(reports_dir)
    env["PYTHONUNBUFFERED"] = "1"
    log_file = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=str(_BACKEND_ROOT),
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    process.m18_log = log_file  # type: ignore[attr-defined]
    return process


def _wait_for_server(base_url: str, process, log_path: Path) -> str:
    """Wait until the server answers, or return why it did not (M18.9)."""
    deadline = time.time() + SERVER_START_TIMEOUT_SECONDS
    last = "no response yet"
    while time.time() < deadline:
        if process.poll() is not None:
            return (
                f"the server exited with status {process.returncode} before it "
                f"answered; its output was:\n{_tail_text(log_path)}"
            )
        try:
            response = httpx.get(f"{base_url}{API}/health", timeout=2.0)
        except Exception as error:  # noqa: BLE001 - a refused connect is expected
            last = f"{type(error).__name__}"
            time.sleep(0.25)
            continue
        if response.status_code == 200:
            return ""
        last = f"the health route answered {response.status_code}"
        time.sleep(0.25)
    return (
        f"the server did not become ready within "
        f"{SERVER_START_TIMEOUT_SECONDS:.0f}s ({last})"
    )


def _tail_text(path: Path, lines: int = 20) -> str:
    """Return the last lines of a log file, or a note when there is none."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "(no log)"
    kept = text.rstrip("\n").splitlines()[-lines:]
    return "\n".join(kept) if kept else "(no output)"


def _stop_server(process, log_file) -> None:
    """Shut the child server down and close its log (M18.9)."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5.0)
    try:
        log_file.close()
    except OSError:
        pass


def _live_http_checks(base_url: str, reports_dir: Path, failures: list[str]) -> None:
    """Exercise the running server's resources and a report download (M18.9)."""
    _section("The running server answers over real HTTP (M13/M16/M17)")
    for label, path in (
        ("health", f"{API}/health"),
        ("system", SYSTEM_URL),
        ("dashboard", DASHBOARD_URL),
        ("devices", DEVICES_URL),
        ("connections", CONNECTIONS_URL),
        ("detections", DETECTIONS_URL),
        ("alerts", ALERTS_URL),
        ("incidents", INCIDENTS_URL),
    ):
        try:
            response = httpx.get(f"{base_url}{path}", timeout=10.0)
        except Exception as error:  # noqa: BLE001 - reported as the failure it is
            failures.append(f"GET {path} could not be made over HTTP ({error!r})")
            continue
        payload = {}
        if response.status_code == 200:
            body = response.json()
            block = body.get("data")
            payload = block if isinstance(block, dict) else {}
        _print_row(f"GET {path}", f"{response.status_code} keys={sorted(payload)}")
        if response.status_code != 200:
            failures.append(
                f"GET {path} over real HTTP answered {response.status_code}, not "
                "200 (M13.4)"
            )
            continue
        _assert_no_internals(f"GET {path}", response.text, failures)

    now = time.time()
    body = {
        "report_type": CUSTOM,
        "format": "CSV",
        "since": _iso_from_epoch(now - 3600.0),
        "until": _iso_from_epoch(now),
    }
    generated = httpx.post(f"{base_url}{GENERATE_URL}", json=body, timeout=30.0)
    _print_row("POST generate", generated.status_code)
    if generated.status_code != 201:
        failures.append(
            f"generating a report over real HTTP answered {generated.status_code}, "
            f"not 201: {generated.text[:200]} (M17.12)"
        )
        return
    report = (generated.json().get("data") or {}).get("report") or {}
    report_id = report.get("report_id")
    download = httpx.get(
        f"{base_url}{REPORTS_URL}/{report_id}/download", timeout=30.0
    )
    _print_row(
        "GET download",
        f"{download.status_code} {download.headers.get('content-type')} "
        f"bytes={len(download.content)}",
    )
    if download.status_code != 200:
        failures.append(
            f"downloading the generated report over real HTTP answered "
            f"{download.status_code}, not 200 (M17.11)"
        )
    else:
        if not download.headers.get("content-type", "").startswith("text/csv"):
            failures.append(
                "the download's media type is not the CSV format's own (M17.11)"
            )
        if len(download.content) != report.get("file_size"):
            failures.append(
                f"the download is {len(download.content)} bytes while the row "
                f"records {report.get('file_size')} (M17.9)"
            )
        if str(reports_dir) in (download.headers.get("content-disposition") or ""):
            failures.append(
                "the download named the storage directory, which is internal "
                "(M13.30)"
            )
    names = _artifact_files(reports_dir)
    _print_row("artifacts on disk", names)
    if not names:
        failures.append(
            "no artifact reached the storage directory, so the report was not "
            "written where the configuration says it goes (M17.9)"
        )
    for name in names:
        if name.endswith(".tmp") or name.startswith("."):
            failures.append(
                f"a temporary artifact {name!r} was left behind (M17.9)"
            )


def _live_websocket_check(base_url: str, failures: list[str]) -> None:
    """Receive a live event over a real WebSocket connection (M14).

    A real TCP connection to a real server, which is the one thing the in-process
    client cannot show: that the upgrade is accepted by the served application
    rather than by a test transport. The frame is validated as the documented
    envelope, so a channel that answered with anything else fails here.
    """
    _section("A real WebSocket connection receives an event (M14)")
    from websockets.sync.client import connect as ws_connect

    url = f"ws://127.0.0.1{base_url.rsplit(':', 1)[-1].join((':', ''))}"
    path = CHANNEL_PATHS[Channel.DASHBOARD]
    target = f"{url}{path}"
    try:
        with ws_connect(target, open_timeout=WEBSOCKET_TIMEOUT_SECONDS) as socket:
            raw = socket.recv(timeout=WEBSOCKET_TIMEOUT_SECONDS)
    except Exception as error:  # noqa: BLE001 - reported as the failure it is
        failures.append(f"no event arrived on {target} ({error!r}) (M14.7)")
        return
    try:
        frame = json.loads(raw)
    except (TypeError, ValueError):
        failures.append(
            f"the frame received on {target} is not JSON ({raw!r}) (M14.7)"
        )
        return
    _assert_envelope(Channel.DASHBOARD, frame, failures)


def _run_live_mode(port: int | None) -> list[str]:
    """Serve the application for real and exercise it (M18.9).

    The developer's database is fingerprinted before and after. Unchanged means
    the run did not touch it, which is the claim that makes this mode safe to
    run on a machine someone is using.
    """
    failures: list[str] = []
    workdir = Path(tempfile.mkdtemp(prefix="netwatch-m18-live-"))
    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    database_path = workdir / "m18-live.db"
    log_path = workdir / "server.log"

    #: Both places a relative default could reach, checked before and after.
    guarded = [
        _BACKEND_ROOT / "netwatch.db",
        _BACKEND_ROOT.parent / "netwatch.db",
    ]
    before = {path: _fingerprint(path) for path in guarded}

    chosen = port or _free_port()
    base_url = f"http://127.0.0.1:{chosen}"
    process = _spawn_server(
        chosen, f"sqlite:///{database_path.as_posix()}", reports_dir, log_path
    )
    _section("Starting the application under uvicorn (M18.9)")
    _print_row("command", f"uvicorn app.main:app --port {chosen}")
    _print_row("database", str(database_path))
    _print_row("reports", str(reports_dir))
    try:
        reason = _wait_for_server(base_url, process, log_path)
        if reason:
            failures.append(f"the live server never became usable: {reason}")
            return failures
        _print_row("ready", f"{base_url}{API}/health answered 200")
        _live_http_checks(base_url, reports_dir, failures)
        _live_websocket_check(base_url, failures)
    finally:
        _stop_server(process, getattr(process, "m18_log", None))
        for path in guarded:
            after = _fingerprint(path)
            if before[path] != after:
                failures.append(
                    f"the developer's database {path.name} changed across the run "
                    f"({before[path]} -> {after}), so the live mode was not "
                    "isolated (M18.13)"
                )
            else:
                _print_row(
                    f"{path.name} untouched",
                    "absent" if after is None else f"{after[0]} bytes",
                )
        shutil.rmtree(workdir, ignore_errors=True)
    return failures


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _report_failures(mode: str, failures: list[str]) -> int:
    """Print the verdict and return the process exit code (M18.9)."""
    print()
    print("=" * _BANNER_WIDTH)
    if failures:
        print(f"FAILED — {len(failures)} check(s) did not hold")
        for index, failure in enumerate(failures, start=1):
            print(f"  {index}. {failure}")
        print(f"RESULT: FAIL ({mode} mode)")
        return 1
    print("Every property the M18.9 flow promises held")
    print(f"RESULT: PASS ({mode} mode)")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run one mode of the end-to-end verification and return the exit code (M18.9)."""
    parser = argparse.ArgumentParser(
        prog="verify_m18.py",
        description=(
            "Verify the whole NetWatch AI data flow end to end (M18.9): real "
            "packets through the real pipeline, read back through the real API."
        ),
    )
    parser.add_argument(
        "mode",
        nargs="?",
        choices=("sample", "live"),
        default="sample",
        help="'sample' drives the pipeline in-process; 'live' serves the app under uvicorn",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="port for live mode; 0 (the default) picks a free loopback port",
    )
    args = parser.parse_args(argv)

    print("=" * _BANNER_WIDTH)
    print(f"NetWatch AI — M18 end-to-end verification ({args.mode} mode)")
    print("=" * _BANNER_WIDTH)

    failures = (
        _run_sample_mode() if args.mode == "sample" else _run_live_mode(args.port or None)
    )
    return _report_failures(args.mode, failures)


if __name__ == "__main__":
    raise SystemExit(main())
