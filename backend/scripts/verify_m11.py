"""M11 verification script — see detection findings become alerts (M11.32).

Two modes:

  sample  (default)  Push synthetic packets through a full PacketPipeline
                     (PacketProcessor -> Statistics -> Devices -> Connections ->
                     Persistence -> DetectionEngine -> AlertEngine), backing the
                     alert layer with an isolated temporary SQLite database, then
                     print every finding, every alert it produced, and the
                     evidence behind each one. No admin rights or Npcap needed.
  live               Capture real traffic through CaptureManager -> the same
                     pipeline, for a few seconds. Requires Npcap and (Windows)
                     admin.

What it verifies, against the M11 completion criteria:

  * every finding from a mapped rule becomes an alert with the mapped severity;
  * the detection confidence survives onto the alert, separately from severity;
  * the alert keeps a link back to the finding that raised it;
  * evidence is stored (rule, behavioral and, where resolvable, packet and
    connection references — never a copied packet payload);
  * a repeated observation inside the deduplication window is folded into the
    existing alert, and one outside the window is not;
  * the lifecycle accepts open -> acknowledged -> resolved and rejects a move out
    of a terminal state.

The database is a throwaway file under the OS temp directory, created and removed
by this script, so running it never touches the developer's ``netwatch.db``. The
detectors are configured with LOW thresholds so a handful of synthetic packets
demonstrates each one (M10.7); that is a lab configuration for verification, not
the shipped default.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\verify_m11.py
    & ".venv\\Scripts\\python.exe" scripts\\verify_m11.py live --interface "Wi-Fi" --seconds 5
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

# Make the backend root importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from sqlalchemy import create_engine, event  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402

from app.alerts.alert import Alert  # noqa: E402
from app.alerts.engine import AlertEngine  # noqa: E402
from app.alerts.mapping import mapping_for_rule  # noqa: E402
from app.alerts.queries import AlertQueries, AlertQuery  # noqa: E402
from app.alerts.resolvers import (  # noqa: E402
    FindingResolvers,
    ResolutionLimits,
    SessionPacketSource,
    SessionRuleSource,
)
from app.alerts.service import AlertService  # noqa: E402
from app.alerts.status import InvalidStatusTransition  # noqa: E402
from app.config.settings import Settings  # noqa: E402
from app.connections.manager import ConnectionTracker  # noqa: E402
from app.detection import (  # noqa: E402
    DetectionEngine,
    DetectionFinding,
    build_default_rules,
)
from app.devices.manager import DeviceDiscoveryManager  # noqa: E402
from app.persistence.manager import PacketPersistence  # noqa: E402
from app.services.packet_pipeline import PacketPipeline  # noqa: E402
from app.statistics.manager import TrafficStatisticsManager  # noqa: E402

_BANNER_WIDTH = 66

MAC_A = "AA:BB:CC:DD:EE:FF"
MAC_B = "22:33:44:55:66:77"

# Port-scan source sweeping a public host across distinct ports.
SCAN_SOURCE = "192.168.1.10"
SCAN_DESTINATION = "8.8.8.8"
SCAN_PORTS = [20, 21, 22, 23, 24, 25]

# SYN-flood source hammering one destination on one port.
FLOOD_SOURCE = "10.0.0.5"
FLOOD_DESTINATION = "192.168.0.99"
FLOOD_PORT = 80
FLOOD_SYNS = 25

# ICMP-flood source pinging one destination repeatedly.
ICMP_SOURCE = "10.0.0.6"
ICMP_DESTINATION = "192.168.0.100"
ICMP_PACKETS = 8

# Internal-scan source sweeping the local subnet.
SWEEP_SOURCE = "192.168.1.50"
SWEEP_DESTINATIONS = [
    "192.168.1.20",
    "192.168.1.21",
    "192.168.1.22",
    "192.168.1.23",
    "192.168.1.24",
    "192.168.1.25",
]

# Endpoints used only by the deduplication and lifecycle scenarios, kept clear of
# the capture scenario above so the two never interact.
DEDUP_SOURCE = "203.0.113.5"
DEDUP_DESTINATION = "203.0.113.9"
DEDUP_OUTSIDE_SHIFT = 400.0  # seconds; larger than the 300 s window below
DEDUP_WINDOW_SECONDS = 300.0

# Fixed reference time so the printed timestamps are stable within a run.
_BASE_TIME = time.time()

# The five detectors M10 implements and M11 must map (M11.8).
_EXPECTED_RULES = [
    "port_scan",
    "syn_flood",
    "icmp_flood",
    "internal_scan",
    "high_bandwidth",
]

# The severity each rule maps to (mirrors app.alerts.mapping, asserted here so a
# drift between the two is caught).
_EXPECTED_SEVERITY = {
    "port_scan": "high",
    "syn_flood": "critical",
    "icmp_flood": "medium",
    "internal_scan": "high",
    "high_bandwidth": "high",
}


class _FixedRatesSource:
    """A stand-in for M6 that always reports a high traffic rate (M10.12)."""

    def __init__(self, bytes_per_second: float, packets_per_second: float) -> None:
        self._bytes_per_second = bytes_per_second
        self._packets_per_second = packets_per_second

    def get_rates(self, window: str = "1s") -> tuple[float, float]:
        """Return the fixed ``(packets_per_second, bytes_per_second)``."""
        return self._packets_per_second, self._bytes_per_second


def _connect_database(db_path: Path):
    """Create (or reuse) an isolated SQLite database and a session factory.

    Foreign keys are enforced, exactly as the test harness does, so an alert's
    packet evidence must reference a packet row that really exists — which is the
    property M11.13 relies on.
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
    """Populate ``detection_rules`` so an alert's rule foreign key resolves.

    The M2 seed catalogue names the bandwidth detector ``bandwidth_abuse`` while
    M10's rule id is ``high_bandwidth``, so that one row is added here. Without a
    catalogue row an alert is still created — only its ``rule_id`` foreign key is
    left ``NULL`` (M11.18 makes that linkage best-effort) — and this keeps the
    demonstration complete rather than looking like a gap.
    """
    from app.database.seed import seed_detection_rules
    from app.models.detection_rule import DetectionRule

    session = factory()
    try:
        seed_detection_rules(session)
        existing = (
            session.query(DetectionRule)
            .filter(DetectionRule.rule_key == "high_bandwidth")
            .first()
        )
        if existing is None:
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


def _sample_packets() -> list[tuple[str, object, float]]:
    """Return labelled packets covering all five M10 detectors."""
    packets: list[tuple[str, object, float]] = []

    for index, port in enumerate(SCAN_PORTS):
        packets.append(
            (
                f"port scan     {SCAN_SOURCE}:52000 -> {SCAN_DESTINATION}:{port}",
                Ether(src=MAC_A, dst=MAC_B)
                / IP(src=SCAN_SOURCE, dst=SCAN_DESTINATION)
                / TCP(sport=52000, dport=port, flags="S"),
                _BASE_TIME + 2.00 + index * 0.01,
            )
        )

    for index in range(FLOOD_SYNS):
        packets.append(
            (
                f"syn flood     {FLOOD_SOURCE}:40000 -> "
                f"{FLOOD_DESTINATION}:{FLOOD_PORT}",
                Ether(src=MAC_A, dst=MAC_B)
                / IP(src=FLOOD_SOURCE, dst=FLOOD_DESTINATION)
                / TCP(sport=40000, dport=FLOOD_PORT, flags="S"),
                _BASE_TIME + 10.00 + index * 0.005,
            )
        )

    for index in range(ICMP_PACKETS):
        packets.append(
            (
                f"icmp flood    {ICMP_SOURCE} -> {ICMP_DESTINATION}",
                Ether(src=MAC_A, dst=MAC_B)
                / IP(src=ICMP_SOURCE, dst=ICMP_DESTINATION)
                / ICMP(),
                _BASE_TIME + 20.00 + index * 0.005,
            )
        )

    for index, destination in enumerate(SWEEP_DESTINATIONS):
        packets.append(
            (
                f"internal scan {SWEEP_SOURCE}:53000 -> {destination}:445",
                Ether(src=MAC_A, dst=MAC_B)
                / IP(src=SWEEP_SOURCE, dst=destination)
                / UDP(sport=53000, dport=445),
                _BASE_TIME + 30.00 + index * 0.01,
            )
        )

    return packets


def _build_detection_engine(devices: DeviceDiscoveryManager) -> DetectionEngine:
    """Build a detection engine with lab thresholds for every detector (M10.7)."""

    def resolve_device(ip_address: str) -> str | None:
        """Return the M8 device id owning ``ip_address``, or ``None`` (M10.4)."""
        device = devices.registry.get_by_ip(ip_address)
        return device.device_id if device is not None else None

    lab_settings = Settings(
        port_scan_unique_port_threshold=5,
        syn_flood_time_window_seconds=1.0,
        syn_flood_rate_threshold=20.0,
        icmp_flood_time_window_seconds=1.0,
        icmp_flood_rate_threshold=5.0,
        internal_scan_unique_destination_threshold=5,
        high_bandwidth_bytes_per_second_threshold=1_000_000.0,
    )
    return DetectionEngine(
        build_default_rules(lab_settings),
        rates_source=_FixedRatesSource(5_000_000.0, 1_000.0),
        device_resolver=resolve_device,
    )


def _build_alert_layer(factory) -> tuple[AlertService, AlertEngine]:
    """Build the alert service and engine wired to real M7/M9/M2 sources.

    Packet evidence resolves through the M7 packet repository, connection
    evidence through the live M9 tracker, and the rule foreign key through the M2
    catalogue — each bounded, each best-effort (M11.13-M11.15).
    """
    resolvers = FindingResolvers(
        packet_source=SessionPacketSource(factory),
        connection_source=None,
        rule_source=SessionRuleSource(factory),
        limits=ResolutionLimits(
            max_packets=5,
            packet_window_seconds=5.0,
            max_connections=5,
        ),
    )
    service = AlertService(
        session_factory=factory,
        resolvers=resolvers,
        dedup_window_seconds=DEDUP_WINDOW_SECONDS,
        max_evidence=64,
        packet_evidence_enabled=True,
    )
    return service, AlertEngine(service)


def _describe_finding(finding: DetectionFinding) -> None:
    """Print one finding with the evidence that produced it (M10.14)."""
    endpoints = f"{finding.source_ip or '*'} -> {finding.destination_ip or '*'}"
    print(f"  [{finding.rule_id:<15}] {endpoints}")
    print(f"      confidence={finding.confidence:.2f} protocol={finding.protocol or '*'}")
    for key, value in sorted(finding.evidence.items()):
        print(f"      evidence {key} = {value}")


def _describe_alert(alert: Alert, *, evidence_by_type: dict[str, int]) -> None:
    """Print one stored alert with its severity, status and evidence counts."""
    endpoints = f"{alert.source_ip or '*'} -> {alert.destination_ip or '*'}"
    print(
        f"  alert #{alert.alert_id} [{alert.rule_id:<15}] "
        f"severity={alert.severity.value:<8} confidence={alert.confidence:.2f}"
    )
    print(f"      {alert.title}: {endpoints} protocol={alert.protocol or '*'}")
    print(f"      status={alert.status.value} created_at={alert.created_at}")
    source_device = alert.source_device_id or "(unknown)"
    destination_device = alert.destination_device_id or "(unknown)"
    print(f"      devices src={source_device} dst={destination_device}")
    counts = ", ".join(f"{name}={count}" for name, count in sorted(evidence_by_type.items()))
    print(f"      evidence: {counts or '(none)'}")


# ---------------------------------------------------------------------------
# Checks (M11.32)
# ---------------------------------------------------------------------------


def _alert_id(alert: Alert) -> int:
    """Return a stored alert's primary key, which is always set for a read row."""
    if alert.alert_id is None:
        raise AssertionError("a stored alert must carry an id")
    return alert.alert_id


def _check_findings_became_alerts(
    findings: list[DetectionFinding], page, failures: list[str]
) -> None:
    """Every mapped rule that fired must have produced an alert (M11.8/M11.21)."""
    fired = {finding.rule_id for finding in findings}
    stored = {alert.rule_id for alert in page.alerts}
    for rule_id in _EXPECTED_RULES:
        if rule_id not in fired:
            failures.append(f"detector '{rule_id}' produced no finding")
        elif rule_id not in stored:
            failures.append(f"detector '{rule_id}' produced a finding but no alert")


def _check_alert_fields(page, failures: list[str]) -> None:
    """Severity is the mapped one and confidence is preserved and bounded (M11.4/M11.5)."""
    for alert in page.alerts:
        mapping = mapping_for_rule(alert.rule_id)
        if mapping is None:
            failures.append(
                f"alert {alert.alert_id} has an unmapped rule {alert.rule_id!r}"
            )
            continue
        if alert.severity != mapping.severity:
            failures.append(
                f"alert {alert.alert_id} severity {alert.severity.value!r} "
                f"is not the mapped {mapping.severity.value!r}"
            )
        documented = _EXPECTED_SEVERITY.get(alert.rule_id)
        if documented is not None and alert.severity.value != documented:
            failures.append(
                f"alert {alert.alert_id} severity {alert.severity.value!r} "
                f"is not the documented {documented!r}"
            )
        if not 0.0 <= alert.confidence <= 1.0:
            failures.append(
                f"alert {alert.alert_id} confidence {alert.confidence} "
                "is outside [0.0, 1.0]"
            )
        if alert.status.value != "open":
            failures.append(
                f"a freshly created alert {alert.alert_id} is {alert.status.value!r}"
            )


def _check_confidence_preserved(
    findings: list[DetectionFinding], page, failures: list[str]
) -> None:
    """The alert's confidence is the finding's, not a substituted value (M11.5).

    Findings are keyed by (rule, source, destination, protocol); the pipeline
    produces at most one finding per such incident, so the latest finding for an
    incident is the one whose alert was stored.
    """
    latest: dict[tuple, float] = {}
    for finding in findings:
        key = (
            finding.rule_id,
            finding.source_ip,
            finding.destination_ip,
            finding.protocol,
        )
        latest[key] = float(finding.confidence)
    for alert in page.alerts:
        key = (alert.rule_id, alert.source_ip, alert.destination_ip, alert.protocol)
        expected = latest.get(key)
        if expected is None:
            continue
        if abs(alert.confidence - expected) > 0.01:
            failures.append(
                f"alert {alert.alert_id} confidence {alert.confidence:.4f} "
                f"does not match the finding's {expected:.4f}"
            )


def _check_evidence(queries: AlertQueries, page, failures: list[str]) -> None:
    """Every alert carries rule and behavioral evidence; packet evidence references
    a real packet rather than copying one (M11.11/M11.13)."""
    saw_packet_evidence = False
    for alert in page.alerts:
        alert_id = _alert_id(alert)
        detail = queries.get_detail(alert_id)
        if detail is None:
            failures.append(f"alert {alert_id} could not be read back")
            continue
        by_type = detail.evidence_by_type
        if "rule" not in by_type:
            failures.append(f"alert {alert.alert_id} has no rule evidence")
        if "behavioral" not in by_type:
            failures.append(f"alert {alert.alert_id} has no behavioral evidence")
        if sum(by_type.values()) != alert.evidence_count:
            failures.append(
                f"alert {alert.alert_id} reports evidence_count {alert.evidence_count} "
                f"but holds {sum(by_type.values())} record(s)"
            )
        for row in detail.evidence:
            if row.evidence_type == "rule":
                data = json.loads(row.evidence_data)
                if not data.get("finding_id"):
                    failures.append(
                        f"alert {alert.alert_id} rule evidence names no finding (M11.7)"
                    )
            if row.evidence_type == "packet":
                saw_packet_evidence = True
                if row.packet_id is None:
                    failures.append(
                        f"alert {alert.alert_id} packet evidence references no packet"
                    )
                data = json.loads(row.evidence_data)
                if "payload" in data or "raw" in data:
                    failures.append(
                        f"alert {alert.alert_id} packet evidence copied a payload"
                    )
    if not saw_packet_evidence:
        failures.append(
            "no alert carried packet evidence, though packets were persisted "
            "before the findings fired (M11.13)"
        )


def _check_counters(counters, findings: int, failures: list[str]) -> None:
    """Every finding is accounted for and nothing failed (M11.26/M11.31)."""
    if counters.errors != 0:
        failures.append(f"the alert service isolated {counters.errors} error(s)")
    accounted = (
        counters.alerts_created
        + counters.duplicates_folded
        + counters.unsupported_findings
    )
    if counters.findings_seen != findings:
        failures.append(
            f"the service saw {counters.findings_seen} finding(s) but the engine "
            f"produced {findings}"
        )
    if accounted != counters.findings_seen:
        failures.append(
            f"{counters.findings_seen} finding(s) are not fully accounted for: "
            f"created={counters.alerts_created} "
            f"duplicate={counters.duplicates_folded} "
            f"unsupported={counters.unsupported_findings}"
        )


def _check_deduplication(alerts: AlertEngine, queries, failures: list[str]) -> None:
    """A repeat inside the window folds in; one outside it, or from elsewhere,
    does not (M11.9/M11.10)."""
    before = queries.summary()["total"]

    first = alerts.process_finding(_dedup_finding(0.0))
    if not first.created:
        failures.append("the first observation did not create an alert")

    repeat = alerts.process_finding(_dedup_finding(0.0))
    if not repeat.duplicate or repeat.created:
        failures.append("a repeated observation inside the window was not folded in")

    later = alerts.process_finding(_dedup_finding(DEDUP_OUTSIDE_SHIFT))
    if not later.created:
        failures.append("an observation outside the window did not create a new alert")

    elsewhere = alerts.process_finding(_dedup_finding(0.0, destination="198.51.100.7"))
    if not elsewhere.created:
        failures.append("an observation from a different destination was folded in")

    after = queries.summary()["total"]
    expected_new = 3
    if after - before != expected_new:
        failures.append(
            f"deduplication stored {after - before} new alert(s), expected {expected_new}"
        )


def _dedup_finding(offset: float, *, destination: str = DEDUP_DESTINATION) -> DetectionFinding:
    """Return a hand-built finding for the deduplication scenario.

    It names no devices, so its deduplication key is distinct from any alert the
    capture scenario produced, and the two cannot interfere.
    """
    return DetectionFinding(
        rule_id="port_scan",
        rule_name="Port Scan",
        timestamp=_BASE_TIME + offset,
        source_ip=DEDUP_SOURCE,
        destination_ip=destination,
        protocol="TCP",
        description="Possible port scan detected",
        evidence={"unique_destination_ports": 37, "unique_port_threshold": 20},
        confidence=0.7,
    )


def _check_lifecycle(service: AlertService, queries, failures: list[str]) -> None:
    """The lifecycle accepts the documented moves and rejects the rest (M11.19)."""
    open_page = queries.list_alerts(AlertQuery(statuses=("open",), limit=2))
    if not open_page.alerts:
        failures.append("no open alert was available for the lifecycle check")
        return

    alert_id = _alert_id(open_page.alerts[0])
    acknowledged = service.set_status(alert_id, "acknowledged")
    if acknowledged is None or acknowledged.status.value != "acknowledged":
        failures.append("open -> acknowledged did not apply")
    resolved = service.set_status(alert_id, "resolved")
    if resolved is None or resolved.status.value != "resolved":
        failures.append("acknowledged -> resolved did not apply")
    elif resolved.resolved_at is None:
        failures.append("resolving an alert did not record resolved_at")

    try:
        service.set_status(alert_id, "open")
        failures.append("a resolved alert was reopened without an explicit operation")
    except InvalidStatusTransition:
        pass

    if len(open_page.alerts) > 1:
        second_id = _alert_id(open_page.alerts[1])
        dismissed = service.set_status(second_id, "false_positive")
        if dismissed is None or dismissed.status.value != "false_positive":
            failures.append("open -> false_positive did not apply")


def _print_report(detection: DetectionEngine, queries: AlertQueries) -> None:
    """Print every finding, every stored alert, and the engine counters."""
    findings = detection.get_findings()
    print(f"\n--- Findings ({len(findings)}) ---")
    if not findings:
        print("  (none)")
    for finding in findings:
        _describe_finding(finding)

    page = queries.list_alerts(AlertQuery(limit=200))
    print(f"\n--- Alerts ({page.count}) ---")
    if not page.alerts:
        print("  (none)")
    for alert in page.alerts:
        detail = queries.get_detail(_alert_id(alert))
        by_type = {} if detail is None else detail.evidence_by_type
        _describe_alert(alert, evidence_by_type=by_type)


def run_sample_mode() -> int:
    """Feed synthetic packets through the whole pipeline and verify the alerts."""
    workdir = Path(tempfile.mkdtemp(prefix="netwatch_m11_"))
    db_path = workdir / "verify_m11.db"
    engine, factory = _connect_database(db_path)
    try:
        _seed_rule_catalogue(factory)

        devices = DeviceDiscoveryManager()
        detection = _build_detection_engine(devices)
        service, alerts = _build_alert_layer(factory)
        tracker = ConnectionTracker(
            device_registry=devices.registry, autostart_cleanup=False
        )
        # Connection evidence reads the live M9 tracker, which only exists once
        # it has been built, so the resolver set is completed here (M11.14).
        service.set_resolvers(
            FindingResolvers(
                packet_source=SessionPacketSource(factory),
                connection_source=tracker,
                rule_source=SessionRuleSource(factory),
                limits=ResolutionLimits(
                    max_packets=5, packet_window_seconds=5.0, max_connections=5
                ),
            )
        )
        persistence = PacketPersistence(
            session_factory=factory,
            autostart=False,
            batch_size=64,
            flush_interval=60.0,
        )
        pipeline = PacketPipeline(
            statistics=TrafficStatisticsManager(),
            devices=devices,
            persistence=persistence,
            connections=tracker,
            detection=detection,
            alerts=alerts,
        )
        queries = AlertQueries(session_factory=factory)

        print("=" * _BANNER_WIDTH)
        print("M11 SAMPLE MODE — synthetic packets, no privileges required")
        print("=" * _BANNER_WIDTH)
        print(f"database: {db_path}")

        for label, packet, captured_at in _sample_packets():
            try:
                pipeline.process(packet, captured_at=captured_at)
                # Flush after each packet so the packets that triggered a
                # detector are already persisted when the finding fires, which
                # is what lets packet evidence resolve (M11.13).
                persistence.flush()
            except Exception as exc:  # noqa: BLE001 - surface any processing failure
                print(f"\n[{label}] PROCESSING FAILED: {exc}")

        findings = detection.get_findings()
        counters = alerts.get_counters()
        _print_report(detection, queries)

        print("\n--- Alert engine counters ---")
        print(f"  findings seen     : {counters.findings_seen:,}")
        print(f"  alerts created    : {counters.alerts_created:,}")
        print(f"  duplicates folded : {counters.duplicates_folded:,}")
        print(f"  unsupported       : {counters.unsupported_findings:,}")
        print(f"  errors            : {counters.errors:,}")

        failures: list[str] = []
        page = queries.list_alerts(AlertQuery(limit=200))
        _check_findings_became_alerts(findings, page, failures)
        _check_alert_fields(page, failures)
        _check_confidence_preserved(findings, page, failures)
        _check_evidence(queries, page, failures)
        _check_counters(counters, len(findings), failures)

        print("\n--- Deduplication (M11.9/M11.10) ---")
        _check_deduplication(alerts, queries, failures)

        print("--- Lifecycle (M11.19/M11.20) ---")
        _check_lifecycle(service, queries, failures)

        summary = queries.summary()
        print(
            f"\nstored alerts: {summary['total']}  "
            f"by severity: {summary['by_severity']}  "
            f"by status: {summary['by_status']}"
        )

        print("\n" + "=" * _BANNER_WIDTH)
        if failures:
            for failure in failures:
                print(f"FAIL: {failure}")
            print("Sample mode finished with failures.")
            return 1
        print("Sample mode complete — all checks passed.")
        return 0
    finally:
        engine.dispose()
        shutil.rmtree(workdir, ignore_errors=True)


def run_live_mode(interface: str, seconds: float) -> int:
    """Capture real traffic through the alert pipeline and report the alerts."""
    from app.services.capture_manager import CaptureManager
    from app.services.capture_state import CaptureError
    from app.services.interface_manager import get_interface_manager

    interface_manager = get_interface_manager()
    try:
        interface_manager.select_interface(interface)
    except Exception as exc:  # noqa: BLE001 - report and stop
        print(f"Could not select interface '{interface}': {exc}")
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="netwatch_m11_"))
    db_path = workdir / "verify_m11_live.db"
    engine, factory = _connect_database(db_path)
    try:
        _seed_rule_catalogue(factory)

        devices = DeviceDiscoveryManager()
        detection = _build_detection_engine(devices)
        service, alerts = _build_alert_layer(factory)
        tracker = ConnectionTracker(
            device_registry=devices.registry, autostart_cleanup=False
        )
        service.set_resolvers(
            FindingResolvers(
                packet_source=SessionPacketSource(factory),
                connection_source=tracker,
                rule_source=SessionRuleSource(factory),
                limits=ResolutionLimits(
                    max_packets=5, packet_window_seconds=5.0, max_connections=5
                ),
            )
        )
        persistence = PacketPersistence(
            session_factory=factory, batch_size=64, flush_interval=1.0
        )
        pipeline = PacketPipeline(
            statistics=TrafficStatisticsManager(),
            devices=devices,
            persistence=persistence,
            connections=tracker,
            detection=detection,
            alerts=alerts,
        )
        manager = CaptureManager(interface_manager=interface_manager, pipeline=pipeline)
        try:
            manager.stop()
        except Exception:  # noqa: BLE001 - no session to stop
            pass

        print("=" * _BANNER_WIDTH)
        print(f"M11 LIVE MODE — capturing on '{interface}' for {seconds:g}s")
        print("=" * _BANNER_WIDTH)
        print(f"database: {db_path}")
        print("Generate only authorized local traffic (browse, ping a host you own).")

        try:
            manager.start()
        except CaptureError as exc:
            print(f"START FAILED: {exc.code} - {exc.message}")
            return 1

        time.sleep(seconds)
        processed = manager.get_processed_packet_count()
        detection_errors = manager.get_detection_error_count()
        alert_errors = manager.get_alert_error_count()
        manager.stop()
        # Write whatever the worker buffered so packet evidence can resolve.
        persistence.flush()

        queries = AlertQueries(session_factory=factory)
        _print_report(detection, queries)

        counters = alerts.get_counters()
        print("\n--- Capture result ---")
        print(f"  normalized ok      : {processed}")
        print(f"  detection errors   : {detection_errors}")
        print(f"  alert errors       : {alert_errors}")
        print(f"  findings raised    : {counters.findings_seen}")
        print(f"  alerts created     : {counters.alerts_created}")
        print(f"  duplicates folded  : {counters.duplicates_folded}")

        if detection_errors or alert_errors or counters.errors:
            print("\nErrors were reported; see the log above.")
            return 1
        print("\nLive mode complete.")
        return 0
    finally:
        engine.dispose()
        shutil.rmtree(workdir, ignore_errors=True)


def main() -> int:
    """Parse arguments and dispatch to the selected mode."""
    parser = argparse.ArgumentParser(
        description="Verify M11 alert generation from detection findings."
    )
    parser.add_argument(
        "mode",
        nargs="?",
        default="sample",
        choices=("sample", "live"),
        help="sample = synthetic packets (default), live = real capture",
    )
    parser.add_argument("--interface", default="Wi-Fi", help="Interface for live mode")
    parser.add_argument(
        "--seconds", type=float, default=5.0, help="Live capture duration"
    )
    args = parser.parse_args()

    if args.mode == "live":
        return run_live_mode(args.interface, args.seconds)
    return run_sample_mode()


if __name__ == "__main__":
    raise SystemExit(main())
