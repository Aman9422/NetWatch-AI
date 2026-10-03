"""M12 verification script — see related alerts become a scored incident (M12.33).

Two modes:

  sample  (default)  Create controlled M11 alerts from lab findings, feed them to
                     the real M12 CorrelationEngine, back the risk score with an
                     isolated temporary SQLite database, and print every incident,
                     the rule and reasons that grouped it, its risk score, and the
                     confidences that are deliberately kept apart. No admin rights
                     and no Npcap needed.
  live               Capture real traffic through CaptureManager -> the whole
                     pipeline with correlation enabled, for a few seconds.
                     Requires Npcap and (Windows) admin.

What it verifies, against the M12 completion criteria:

  * two related alerts (a port scan and an internal scan from one source) inside
    the window form **one** incident, and both alerts are preserved;
  * the incident records which M12.12 rule grouped it and which shared value
    justified it, as an explicit reason trail;
  * same-source, same-destination, same-device and same-connection correlation
    each work, and each is anchored on identity rather than on time;
  * events outside the correlation window do **not** join, and unrelated sources
    stay separate incidents;
  * the same alert cannot be attached to its incident twice (M12.11);
  * a correlation-derived risk score is bounded ``0..100``, deterministic, and
    documented through an explicit band;
  * the score reaches ``alerts.risk_score`` while M11's own severity, confidence
    and status are left exactly as they were (M12.10/M12.24);
  * alert confidence, correlation confidence and risk score stay three separate
    quantities (M12.16);
  * runtime state is bounded and old context expires without touching alerts
    (M12.22);
  * the reserved ML contribution is unavailable, not estimated (M12.18);
  * the lifecycle accepts the documented transitions and rejects the rest
    (M12.9).

Every finding here is synthetic and controlled: this is the M12.33 lab scenario,
not an attack. The database is a throwaway file under the OS temp directory,
created and removed by this script, so running it never touches the developer's
``netwatch.db``.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\verify_m12.py
    & ".venv\\Scripts\\python.exe" scripts\\verify_m12.py live --interface "Wi-Fi" --seconds 5
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

# Make the backend root importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from sqlalchemy import create_engine, event  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.alerts.alert import Alert  # noqa: E402
from app.alerts.engine import AlertEngine  # noqa: E402
from app.alerts.service import AlertService  # noqa: E402
from app.correlation.confidence import combine_relationships  # noqa: E402
from app.correlation.engine import CorrelationEngine  # noqa: E402
from app.correlation.event import CorrelationEvent, EventKind  # noqa: E402
from app.correlation.identity import (  # noqa: E402
    IdentityIndex,
    relationships_between,
)
from app.correlation.incident import CorrelatedIncident  # noqa: E402
from app.correlation.persistence import IncidentRiskWriter  # noqa: E402
from app.correlation.registry import (  # noqa: E402
    CorrelationOutcome,
    IncidentOrder,
    IncidentQuery,
    IncidentRegistry,
)
from app.correlation.relationship import (  # noqa: E402
    DEFAULT_ANCHOR_THRESHOLD,
    describe_relationships,
)
from app.correlation.rules import describe_rules, rule_ids  # noqa: E402
from app.correlation.status import InvalidIncidentTransition  # noqa: E402
from app.correlation.window import CorrelationWindow  # noqa: E402
from app.detection.finding import DetectionFinding  # noqa: E402
from app.risk.bands import MAX_RISK_SCORE, MIN_RISK_SCORE, RiskBand  # noqa: E402
from app.risk.contributions import ScoringBounds  # noqa: E402
from app.risk.engine import RiskScoringEngine  # noqa: E402

_BANNER_WIDTH = 66

# Fixed reference time so the printed timestamps are stable within a run.
_BASE_TIME = time.time()

# -- Correlation configuration (M12.5/M12.7) --------------------------------
# A 15-minute window with a 5-minute proximity band, and a 30-minute retention
# age for runtime context. Small, explicit and readable, which is the point: the
# script demonstrates the window rather than hiding it behind defaults.
WINDOW_SECONDS = 900.0
PROXIMITY_SECONDS = 300.0
RETENTION_SECONDS = 1800.0
MAX_INCIDENTS = 256
MAX_MEMBERS = 32
MAX_REASONS = 16
MIN_CONFIDENCE = 0.5

# -- Controlled scenario endpoints (M12.33) ---------------------------------
# Scenario 1: one source, two detectors, close in time -> one incident.
RELATED_SOURCE = "192.168.11.10"
RELATED_DESTINATION = "203.0.113.11"
RELATED_SWEEP = "192.168.11.20"
RELATED_SHIFT = 30.0  # seconds between the two observations

# Scenario 2: two unrelated sources -> two incidents. The destinations differ as
# well, so the pair shares nothing at all: neither source nor destination nor
# device nor connection. If the destination were shared they would anchor on
# ``same_destination`` and the scenario would be testing the opposite of what it
# claims.
UNRELATED_SOURCE_A = "192.168.12.20"
UNRELATED_SOURCE_B = "192.168.12.21"
UNRELATED_DESTINATION_A = "203.0.113.21"
UNRELATED_DESTINATION_B = "203.0.113.22"

# Scenario 3: the same source, far outside the window -> two incidents. Its own
# destination space, because sharing one with scenario 1 would anchor the two
# together and the pair would stop being a window test.
DISTANT_SOURCE = "192.168.13.30"
DISTANT_DESTINATION = "203.0.113.31"
DISTANT_SWEEP = "192.168.13.31"
DISTANT_SHIFT = WINDOW_SECONDS + 600.0

# Scenario 4: two alerts sharing only a destination (no device, no source).
SHARED_DESTINATION = "203.0.113.41"
SHARED_DESTINATION_SOURCE_A = "192.168.14.40"
SHARED_DESTINATION_SOURCE_B = "192.168.14.41"

# Scenario 5: two findings that reference the same M9 conversation. Findings do
# not carry one, so it is supplied to the correlation call directly (M12.3).
SHARED_CONNECTION_SOURCE = "192.168.15.50"
CONNECTION_DESTINATION_A = "203.0.113.51"
CONNECTION_DESTINATION_B = "203.0.113.52"
SHARED_CONNECTION_ID = "conn-verify-0001"

# Scenario 6: two alerts concerning the same M8 device, reached from different
# addresses — the device identity is what they share (M12.6).
SHARED_DEVICE_ID = "mac:AB:CD:EF:00:11:22"
SHARED_DEVICE_SOURCE_A = "192.168.16.60"
SHARED_DEVICE_SOURCE_B = "192.168.16.61"
DEVICE_DESTINATION_A = "203.0.113.61"
DEVICE_DESTINATION_B = "203.0.113.62"

# How many incidents the scenario set must produce: one per named scenario, plus
# the window scenario's deliberate split into two. Asserted after the scenarios
# run, so an accidental cross-scenario merge cannot pass unnoticed (M12.4).
EXPECTED_SCENARIO_INCIDENTS = 9

# The mapped rules the alert layer accepts, used for the controlled findings.
RULE_PORT_SCAN = "port_scan"
RULE_INTERNAL_SCAN = "internal_scan"
RULE_ICMP_FLOOD = "icmp_flood"

# Alert deduplication window for the alert service, so a repeated finding of one
# incident folds rather than creating a second alert (M11.9).
ALERT_DEDUP_WINDOW_SECONDS = 300.0

# -- Pipeline scenario endpoints (M12.25/M12.32) -----------------------------
# The pipeline scenario drives real packets through detection, alerting and
# correlation, so it uses its own address space: nothing it produces can then
# share an identity dimension with the controlled alerts above and change what
# those scenarios prove.
PIPELINE_SOURCE = "172.31.10.10"
PIPELINE_SCAN_TARGET = "8.8.8.8"
PIPELINE_SCAN_FIRST_PORT = 20
PIPELINE_SCAN_PORTS = 5
PIPELINE_SWEEP_PREFIX = "172.31.20"
PIPELINE_SWEEP_TARGETS = 5
PIPELINE_START = _BASE_TIME + 200.0
PIPELINE_SWEEP_SHIFT = 5.0
# Capture timestamps advance by packet *index* below, so the last sweep packet
# lands just inside the correlation window of the first — which is the point.
# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class FixedClock:
    """A clock the script drives, so retention and recency are exact (M12.22).

    Correlation expires context by age and scores recency by age. A clock the
    script advances makes both demonstrable without a real ``sleep``, and makes
    the window boundary in scenario 3 exact rather than approximate.
    """

    def __init__(self, now: float = _BASE_TIME) -> None:
        self.now = float(now)

    def __call__(self) -> float:
        """Return the current epoch seconds."""
        return self.now

    def advance(self, seconds: float) -> float:
        """Move the clock forward and return the new time."""
        self.now += float(seconds)
        return self.now


def _connect_database(db_path: Path):
    """Create an isolated SQLite database and a session factory.

    Foreign keys are enforced, as the test harness does, so an alert's evidence
    must reference a row that really exists.
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
    M10's rule id is ``high_bandwidth``; that one row is added here so the
    catalogue is complete for whichever scenario is selected.
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


def _build_alert_layer(
    factory, clock: Callable[[], float]
) -> tuple[AlertService, AlertEngine]:
    """Build the real M11 alert layer over the isolated database.

    No resolvers are supplied: this script needs alerts, not their evidence trail,
    and leaving packet/connection resolution out keeps the run fast and the output
    about correlation.
    """
    service = AlertService(
        session_factory=factory,
        resolvers=None,
        dedup_window_seconds=ALERT_DEDUP_WINDOW_SECONDS,
        max_evidence=8,
        packet_evidence_enabled=False,
        clock=clock,
    )
    return service, AlertEngine(service)


def _build_correlation_layer(
    factory, clock: Callable[[], float]
) -> tuple[CorrelationEngine, IncidentRiskWriter]:
    """Build the real correlation engine over an explicit, documented model.

    Every bound is stated rather than defaulted, so the printed configuration is
    what actually ran: the window (M12.5), the anchor threshold (M12.4/M12.6), the
    confidence floor (M12.7), the store's caps (M12.22) and the scoring bounds
    (M12.15). The risk writer is wired to the same database, so an incident's
    score reaches ``alerts.risk_score`` (M12.24).
    """
    writer = IncidentRiskWriter(factory)
    engine = CorrelationEngine(
        window=CorrelationWindow(
            seconds=WINDOW_SECONDS,
            proximity_seconds=PROXIMITY_SECONDS,
            max_span_seconds=WINDOW_SECONDS,
        ),
        registry=IncidentRegistry(
            max_incidents=MAX_INCIDENTS,
            retention_seconds=RETENTION_SECONDS,
            max_members=MAX_MEMBERS,
            max_reasons=MAX_REASONS,
            clock=clock,
        ),
        risk=RiskScoringEngine(ScoringBounds(volume_alerts=5, historical_occurrences=5)),
        anchor_threshold=DEFAULT_ANCHOR_THRESHOLD,
        min_confidence=MIN_CONFIDENCE,
        risk_persistence=writer,
        clock=clock,
    )
    return engine, writer


def _make_finding(
    rule_id: str,
    *,
    source_ip: str,
    destination_ip: str,
    protocol: str,
    timestamp: float,
    source_device_id: str | None = None,
    destination_device_id: str | None = None,
    confidence: float = 0.8,
) -> DetectionFinding:
    """Build one controlled M10 finding, as M10 would have produced it.

    These are the "controlled M10/M11 outputs" M12.32 and M12.33 ask for: a
    finding shaped exactly like a detector's, so the alert layer treats it as one
    without a detector having to fire.
    """
    return DetectionFinding(
        rule_id=rule_id,
        rule_name=rule_id.replace("_", " ").title(),
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        description=f"Controlled {rule_id} observation for M12 verification",
        evidence={"rule_id": rule_id, "source": "verify_m12"},
        confidence=confidence,
        source_device_id=source_device_id,
        destination_device_id=destination_device_id,
    )


def _create_alert(alerts: AlertEngine, finding: DetectionFinding) -> Alert:
    """Store one control-plane alert and return its runtime form (M11.7).

    Raises:
        AssertionError: If the alert layer produced no alert, which would mean the
            scenario itself is broken rather than the correlation being wrong.
    """
    outcome = alerts.process_finding(finding)
    if outcome.alert is None:
        raise AssertionError(
            f"the alert layer produced no alert for {finding.rule_id!r} "
            f"(created={outcome.created} duplicate={outcome.duplicate} "
            f"unsupported={outcome.unsupported} error={outcome.error})"
        )
    return outcome.alert


def _alert_id(alert: Alert) -> int:
    """Return a stored alert's primary key, which a read-back alert always has."""
    if alert.alert_id is None:
        raise AssertionError("a stored alert must carry an id")
    return alert.alert_id


def _stored_alert_rows(factory) -> list[object]:
    """Return every stored ``alerts`` row, newest first.

    These are the *stored* M2 rows, not the runtime alert dataclass M11 passes
    between layers. The import is local because importing the models package
    registers every table, which this script deliberately does only once it has a
    database to register them against.
    """
    from app.repositories.alert import AlertRepository

    session = factory()
    try:
        return list(AlertRepository(session).list_alerts(limit=1000, offset=0))
    finally:
        session.close()


def _stored_alert(factory, alert_id: int):
    """Return one stored ``alerts`` row, or ``None``."""
    from app.models.alert import Alert as AlertRow

    session = factory()
    try:
        return session.get(AlertRow, alert_id)
    finally:
        session.close()
# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _describe_alert(alert: Alert) -> None:
    """Print one stored M11 alert with the columns M12 must not change."""
    endpoints = f"{alert.source_ip or '*'} -> {alert.destination_ip or '*'}"
    print(
        f"  alert #{alert.alert_id} [{alert.rule_id:<14}] "
        f"severity={alert.severity.value:<8} confidence={alert.confidence:.2f}"
    )
    print(f"      {alert.title}: {endpoints} protocol={alert.protocol or '*'}")
    print(
        f"      status={alert.status.value} "
        f"devices src={alert.source_device_id or '(unknown)'} "
        f"dst={alert.destination_device_id or '(unknown)'}"
    )


def _describe_incident(incident: CorrelatedIncident) -> None:
    """Print one incident: what it grouped, why, and what it scored (M12.8).

    The three quantities M12.16 keeps apart are printed on adjacent labelled lines
    rather than combined, which is the whole point of the separation: a reader can
    see that the risk score is not the alert confidence and not the correlation
    confidence.
    """
    status = incident.normalized_status.value
    worst = incident.worst_severity()
    print(f"  incident {incident.incident_id}")
    print(f"      title={incident.title!r} status={status}")
    print(
        f"      alerts={incident.alert_count()} events={incident.event_count} "
        f"findings={len(incident.finding_ids)} "
        f"span={incident.span_seconds():.0f}s"
    )
    print(
        f"      detectors={list(incident.rule_ids)} "
        f"correlation_rules={list(incident.correlation_rule_ids)}"
    )
    if incident.alert_ids:
        print(f"      alert_ids={list(incident.alert_ids)}")
    if incident.device_ids:
        print(f"      device_ids={list(incident.device_ids)}")
    if incident.connection_ids:
        print(f"      connection_ids={list(incident.connection_ids)}")
    # The separation, made explicit on adjacent lines.
    print(
        f"      alert confidence (M11.5)        : "
        f"{incident.mean_alert_confidence():.4f}"
    )
    print(
        f"      correlation confidence (M12.7)  : "
        f"{incident.correlation_confidence:.4f}"
    )
    print(
        f"      risk score (M12.14)             : {incident.risk_score} "
        f"({incident.risk_band.value})"
    )
    if worst is not None:
        print(f"      worst member severity           : {worst.value}")
    if incident.correlation_reasons:
        print("      correlation reasons (M12.12):")
        for reason in incident.correlation_reasons:
            print(f"        - {reason}")
    else:
        print("      correlation reasons (M12.12): (none - this incident is a seed)")


def _describe_outcome(outcome: CorrelationOutcome) -> None:
    """Print what one correlation call decided, in one line (M12.25)."""
    if outcome.error:
        print(f"  {outcome.event_id:<24} ERROR: {outcome.error}")
        return
    if outcome.duplicate:
        verdict = "duplicate (already a member)"
    elif outcome.created:
        verdict = "opened a new incident"
    elif outcome.joined:
        verdict = "joined an existing incident"
    else:
        verdict = "no incident"
    print(
        f"  {outcome.event_id:<24} rule={outcome.rule_id:<14} {verdict:<28} "
        f"score={outcome.risk_score}"
    )


def _relationship_weight(entry: dict[str, object]) -> float:
    """Return a described relationship's weight as a float.

    ``describe_relationships`` returns data rather than typed objects, so the
    value arrives as ``object``; converting through ``str`` keeps the sort honest
    without an unchecked cast.
    """
    return float(str(entry["weight"]))


def _print_model() -> None:
    """Print the configured model as data (M12.5/M12.6/M12.7/M12.12/M12.27).

    The relationship strengths, the anchor threshold, the rule set and the risk
    bands are printed rather than described, so the verification states exactly
    which model it just exercised instead of referring to it in prose.
    """
    from app.risk.bands import BAND_RANGES, band_label

    print("\n--- Correlation model in use (M12.5/M12.6/M12.7) ---")
    print(
        f"  window={WINDOW_SECONDS:.0f}s proximity={PROXIMITY_SECONDS:.0f}s "
        f"retention={RETENTION_SECONDS:.0f}s"
    )
    print(
        f"  anchors at >= {DEFAULT_ANCHOR_THRESHOLD:.2f}  "
        f"joins at confidence >= {MIN_CONFIDENCE:.2f}"
    )
    print(f"  store caps: incidents={MAX_INCIDENTS} members={MAX_MEMBERS} "
          f"reasons={MAX_REASONS}")
    print("  relationships (strongest first):")
    for entry in sorted(
        describe_relationships(), key=_relationship_weight, reverse=True
    ):
        weight = _relationship_weight(entry)
        marker = "anchor" if weight >= DEFAULT_ANCHOR_THRESHOLD else "      "
        print(
            f"    {entry['kind']:<18} weight={weight:.2f} [{marker}] "
            f"{entry['description']}"
        )
    print("  correlation rules (evaluation order):")
    for entry in describe_rules():
        anchors = ", ".join(entry["anchors"])  # type: ignore[arg-type]
        detectors = ", ".join(entry["detector_pair"]) or "-"  # type: ignore[arg-type]
        print(
            f"    {entry['rule_id']:<26} anchors={anchors:<18} "
            f"detectors={detectors}"
        )
    print(f"  rule ids: {', '.join(rule_ids())}")
    print("  risk bands (M12.27 - prioritisation ranges, not attack severity):")
    for band, low, high in BAND_RANGES:
        print(f"    {low:>3}-{high:<3} {band_label(band)}")
# ---------------------------------------------------------------------------
# The identity model, demonstrated directly (M12.4/M12.6/M12.7)
# ---------------------------------------------------------------------------


def _demo_event(
    event_id: str, *, timestamp: float, source_ip: str, destination_ip: str
) -> CorrelationEvent:
    """Build a minimal correlation event for the identity demonstration."""
    return CorrelationEvent(
        event_id=event_id,
        kind=EventKind.ALERT,
        timestamp=timestamp,
        rule_id=RULE_PORT_SCAN,
        title="Identity demo",
        source_ip=source_ip,
        destination_ip=destination_ip,
    )


def _check_identity_model(window: CorrelationWindow, failures: list[str]) -> None:
    """Prove correlation is anchored on identity and never on time alone (M12.4).

    Two events that share nothing but a timestamp produce time proximity — which
    is deliberately *below* the anchor threshold — so they can never correlate.
    Two events that also share a source produce an anchoring relationship, which
    raises the confidence. That difference is what M12.4's "do not merge events
    simply because they occurred close together" means in practice, and it is
    checked here against the real relationship table rather than restated in prose.
    """
    anchor = _demo_event(
        "demo:anchor", timestamp=_BASE_TIME, source_ip="10.0.0.1", destination_ip="10.0.0.2"
    )
    same_time_only = _demo_event(
        "demo:time", timestamp=_BASE_TIME + 1.0, source_ip="10.9.9.9", destination_ip="10.9.9.8"
    )
    same_source = _demo_event(
        "demo:source", timestamp=_BASE_TIME + 2.0, source_ip="10.0.0.1", destination_ip="10.8.8.8"
    )

    # ``relationships_between`` is the pairwise comparison, and it is the only
    # entry point that adds time proximity: ``identity_relationships`` compares
    # identity dimensions alone, because the event-to-event and
    # event-to-incident paths measure proximity against different references
    # (M12.4/M12.6).
    time_only = relationships_between(anchor, same_time_only, window=window)
    if not any(item.kind.value == "time_proximity" for item in time_only):
        failures.append("two nearby events produced no time-proximity relationship")
    if any(item.is_anchor(DEFAULT_ANCHOR_THRESHOLD) for item in time_only):
        failures.append(
            "time proximity anchored a correlation, which M12.4 forbids"
        )
    time_only_confidence = combine_relationships(time_only)

    with_source = relationships_between(anchor, same_source, window=window)
    if not any(item.kind.value == "same_source" for item in with_source):
        failures.append("two events from one source produced no same-source relationship")
    if not any(item.is_anchor(DEFAULT_ANCHOR_THRESHOLD) for item in with_source):
        failures.append("the same-source relationship did not reach the anchor threshold")
    with_source_confidence = combine_relationships(with_source)

    print("\n--- Identity model (M12.4/M12.6/M12.7) ---")
    for label, relationships, confidence in (
        ("same time only  ", time_only, time_only_confidence),
        ("same source+time", with_source, with_source_confidence),
    ):
        kinds = ", ".join(sorted(item.kind.value for item in relationships))
        anchored = any(item.is_anchor(DEFAULT_ANCHOR_THRESHOLD) for item in relationships)
        print(
            f"  {label}  confidence={confidence:.4f}  "
            f"anchored={str(anchored):<5}  relationships=[{kinds}]"
        )
    if with_source_confidence <= time_only_confidence:
        failures.append(
            "an anchoring relationship did not raise the correlation confidence"
        )
    if not 0.0 <= time_only_confidence <= 1.0 or not 0.0 <= with_source_confidence <= 1.0:
        failures.append("a correlation confidence fell outside the documented 0..1")
# ---------------------------------------------------------------------------
# Scenarios (M12.33)
# ---------------------------------------------------------------------------


def _incident_holding(
    engine: CorrelationEngine, alert_ids: set[int]
) -> CorrelatedIncident | None:
    """Return the single incident holding every alert id in ``alert_ids``.

    Returns ``None`` when no incident holds them all, and the first match when
    several do — which for this script's scenarios is itself a finding, since
    every scenario is built so that at most one incident can hold the set.
    """
    for incident in engine.get_incidents():
        if alert_ids <= set(incident.alert_ids):
            return incident
    return None


def _check_score_bounds(
    incidents: list[CorrelatedIncident], failures: list[str]
) -> None:
    """Every incident's score is inside the bounded range (M12.14/M12.21).

    Checked over every incident the run produced rather than over the one the
    scenario focused on, so an unexpected incident cannot carry an out-of-range
    score unnoticed.
    """
    for incident in incidents:
        if not MIN_RISK_SCORE <= incident.risk_score <= MAX_RISK_SCORE:
            failures.append(
                f"incident {incident.incident_id} scored {incident.risk_score}, "
                f"outside {MIN_RISK_SCORE}..{MAX_RISK_SCORE}"
            )
        if not isinstance(incident.risk_band, RiskBand):
            failures.append(
                f"incident {incident.incident_id} has no documented risk band"
            )


def _scenario_related(
    alerts: AlertEngine,
    engine: CorrelationEngine,
    factory,
    failures: list[str],
) -> CorrelatedIncident | None:
    """Scenario 1 — the M12.33 headline: two related alerts, one incident.

    A port scan is followed by an internal scan from the same source inside the
    window. Expected: two alerts stored, one incident holding both, the
    ``scan_sequence`` rule attributed, the shared source in the reason trail, and
    the incident's score written onto both alert rows.
    """
    print("\n--- Scenario 1: port scan then internal scan, one source (M12.33) ---")
    first = _create_alert(
        alerts,
        _make_finding(
            RULE_PORT_SCAN,
            source_ip=RELATED_SOURCE,
            destination_ip=RELATED_DESTINATION,
            protocol="TCP",
            timestamp=_BASE_TIME,
        ),
    )
    second = _create_alert(
        alerts,
        _make_finding(
            RULE_INTERNAL_SCAN,
            source_ip=RELATED_SOURCE,
            destination_ip=RELATED_SWEEP,
            protocol="UDP",
            timestamp=_BASE_TIME + RELATED_SHIFT,
        ),
    )
    print("  two independent M11 alerts were stored:")
    _describe_alert(first)
    _describe_alert(second)

    print("  correlating both alerts:")
    outcomes = engine.correlate_alerts([first, second])
    for outcome in outcomes:
        _describe_outcome(outcome)

    alert_ids = {_alert_id(first), _alert_id(second)}
    incident = _incident_holding(engine, alert_ids)
    if incident is None:
        failures.append(
            "the two related alerts were not grouped into one incident (M12.12)"
        )
        return None

    _describe_incident(incident)

    if incident.alert_count() != 2:
        failures.append(
            f"the incident groups {incident.alert_count()} alert(s), expected 2"
        )
    if "matched:scan_sequence" not in incident.correlation_reasons:
        failures.append(
            "the scan-sequence rule was not attributed to the grouping (M12.12): "
            f"{list(incident.correlation_reasons)}"
        )
    if not any("same_source" in reason for reason in incident.correlation_reasons):
        failures.append("the shared source is missing from the reason trail")
    if incident.correlation_confidence <= 0.0:
        failures.append("a correlated incident reports no correlation confidence")
    if incident.correlation_confidence == incident.mean_alert_confidence():
        failures.append(
            "correlation confidence equals alert confidence, which M12.16 forbids"
        )
    if not {"port_scan", "internal_scan"} <= set(incident.rule_ids):
        failures.append(
            f"the incident does not name both detectors: {list(incident.rule_ids)}"
        )

    # The score reached the database (M12.24), on both member alerts.
    for alert in (first, second):
        row = _stored_alert(factory, _alert_id(alert))
        if row is None:
            failures.append(f"alert {_alert_id(alert)} disappeared from the database")
            continue
        if int(row.risk_score) != incident.risk_score:
            failures.append(
                f"stored alert {_alert_id(alert)} carries risk_score "
                f"{int(row.risk_score)}, not the incident's {incident.risk_score}"
            )
        if row.severity != alert.severity.value:
            failures.append(
                f"correlation changed alert {_alert_id(alert)}'s severity (M12.10)"
            )
        if row.status != alert.status.value:
            failures.append(
                f"correlation changed alert {_alert_id(alert)}'s status (M12.10)"
            )

    # The same alert cannot be attached twice (M12.11).
    print("  re-correlating the first alert (deduplication, M12.11):")
    again = engine.correlate_alert(first)
    _describe_outcome(again)
    if not again.duplicate:
        failures.append("re-correlating a member alert was not reported as a duplicate")
    refreshed = engine.get_incident(incident.incident_id)
    if refreshed is None or refreshed.alert_count() != 2:
        failures.append("re-correlating a member alert grew the incident (M12.11)")

    return incident


def _scenario_unrelated(
    alerts: AlertEngine, engine: CorrelationEngine, failures: list[str]
) -> None:
    """Scenario 2 — unrelated sources stay separate incidents (M12.4)."""
    print("\n--- Scenario 2: two unrelated sources ---")
    left = _create_alert(
        alerts,
        _make_finding(
            RULE_PORT_SCAN,
            source_ip=UNRELATED_SOURCE_A,
            destination_ip=UNRELATED_DESTINATION_A,
            protocol="TCP",
            timestamp=_BASE_TIME,
        ),
    )
    right = _create_alert(
        alerts,
        _make_finding(
            RULE_PORT_SCAN,
            source_ip=UNRELATED_SOURCE_B,
            destination_ip=UNRELATED_DESTINATION_B,
            protocol="TCP",
            timestamp=_BASE_TIME,
        ),
    )
    print("  correlating two alerts that share no identity dimension at all:")
    outcomes = [
        engine.correlate_alert(left),
        engine.correlate_alert(right, timestamp=_BASE_TIME),
    ]
    for outcome in outcomes:
        _describe_outcome(outcome)

    left_id, right_id = _alert_id(left), _alert_id(right)
    together = _incident_holding(engine, {left_id, right_id})
    if together is not None:
        failures.append(
            "two alerts from unrelated sources were merged into one incident (M12.4)"
        )
    for alert_id in (left_id, right_id):
        if not _incident_holding(engine, {alert_id}):
            failures.append(f"alert {alert_id} was not grouped into any incident")


def _scenario_outside_window(
    alerts: AlertEngine, engine: CorrelationEngine, failures: list[str]
) -> None:
    """Scenario 3 — the same source, but far outside the window (M12.5).

    The two observations share a source, so identity would anchor them; the
    distance is the only thing stopping the merge. That is what makes this the
    window test rather than a repeat of the unrelated-source one.
    """
    print(
        f"\n--- Scenario 3: same source, {DISTANT_SHIFT:.0f}s apart "
        f"(window {WINDOW_SECONDS:.0f}s) ---"
    )
    early = _create_alert(
        alerts,
        _make_finding(
            RULE_PORT_SCAN,
            source_ip=DISTANT_SOURCE,
            destination_ip=DISTANT_DESTINATION,
            protocol="TCP",
            timestamp=_BASE_TIME,
        ),
    )
    late = _create_alert(
        alerts,
        _make_finding(
            RULE_INTERNAL_SCAN,
            source_ip=DISTANT_SOURCE,
            destination_ip=DISTANT_SWEEP,
            protocol="UDP",
            timestamp=_BASE_TIME + DISTANT_SHIFT,
        ),
    )
    print("  correlating two alerts from one source, far apart in time:")
    for outcome in (engine.correlate_alert(early), engine.correlate_alert(late)):
        _describe_outcome(outcome)

    union = _incident_holding(engine, {_alert_id(early), _alert_id(late)})
    if union is not None:
        failures.append(
            "events outside the correlation window were merged (M12.5)"
        )
    for alert in (early, late):
        incident = _incident_holding(engine, {_alert_id(alert)})
        if incident is None:
            failures.append(
                f"alert {_alert_id(alert)} opened no incident of its own"
            )
        elif incident.correlation_confidence != 0.0:
            failures.append(
                "an incident outside the window reported a correlation confidence"
            )
def _scenario_shared_destination(
    alerts: AlertEngine, engine: CorrelationEngine, failures: list[str]
) -> None:
    """Scenario 4 — two sources, one destination (M12.6 "Same Destination")."""
    print("\n--- Scenario 4: same destination, different sources ---")
    left = _create_alert(
        alerts,
        _make_finding(
            RULE_PORT_SCAN,
            source_ip=SHARED_DESTINATION_SOURCE_A,
            destination_ip=SHARED_DESTINATION,
            protocol="TCP",
            timestamp=_BASE_TIME,
        ),
    )
    right = _create_alert(
        alerts,
        _make_finding(
            RULE_PORT_SCAN,
            source_ip=SHARED_DESTINATION_SOURCE_B,
            destination_ip=SHARED_DESTINATION,
            protocol="TCP",
            timestamp=_BASE_TIME + 5.0,
        ),
    )
    print("  correlating two alerts that share only a destination:")
    for outcome in (engine.correlate_alert(left), engine.correlate_alert(right)):
        _describe_outcome(outcome)

    incident = _incident_holding(engine, {_alert_id(left), _alert_id(right)})
    if incident is None:
        failures.append(
            "two alerts sharing a destination were not correlated (M12.6)"
        )
        return
    _describe_incident(incident)
    if "matched:same_destination_activity" not in incident.correlation_reasons:
        failures.append(
            "the same-destination rule was not attributed: "
            f"{list(incident.correlation_reasons)}"
        )
    if incident.alert_count() != 2:
        failures.append(
            f"the destination incident groups {incident.alert_count()} alert(s)"
        )


def _scenario_shared_connection(
    engine: CorrelationEngine, failures: list[str]
) -> None:
    """Scenario 5 — two findings on one M9 conversation (M12.6 "Same Connection").

    Findings carry no conversation reference, so it is supplied on the correlation
    call itself. That is the documented path for a finding whose M9 conversation a
    caller has already resolved (M12.3).
    """
    print("\n--- Scenario 5: two findings on one M9 conversation ---")
    first = _make_finding(
        RULE_PORT_SCAN,
        source_ip=SHARED_CONNECTION_SOURCE,
        destination_ip=CONNECTION_DESTINATION_A,
        protocol="TCP",
        timestamp=_BASE_TIME,
    )
    second = _make_finding(
        RULE_PORT_SCAN,
        source_ip=SHARED_CONNECTION_SOURCE,
        destination_ip=CONNECTION_DESTINATION_B,
        protocol="TCP",
        timestamp=_BASE_TIME + 3.0,
    )
    print(f"  correlating two findings that reference {SHARED_CONNECTION_ID}:")
    for outcome in (
        engine.correlate_finding(first, connection_id=SHARED_CONNECTION_ID),
        engine.correlate_finding(second, connection_id=SHARED_CONNECTION_ID),
    ):
        _describe_outcome(outcome)

    matching = [
        incident
        for incident in engine.get_incidents()
        if SHARED_CONNECTION_ID in incident.connection_ids
    ]
    if not matching:
        failures.append(
            "no incident recorded the shared conversation reference (M12.6)"
        )
        return
    if len(matching) != 1:
        failures.append(
            f"{len(matching)} incidents claim the same conversation, expected 1"
        )
    incident = matching[0]
    _describe_incident(incident)
    if "matched:same_connection" not in incident.correlation_reasons:
        failures.append(
            "the same-connection rule was not attributed: "
            f"{list(incident.correlation_reasons)}"
        )
    if len(incident.finding_ids) != 2:
        failures.append(
            f"the conversation incident holds {len(incident.finding_ids)} finding(s)"
        )
    # A findings-only incident has no alerts to stamp, so the risk write is a
    # no-op rather than an error (M12.24).
    if incident.alert_ids:
        failures.append(
            "a findings-only incident reported alert ids, which it cannot have"
        )


def _scenario_shared_device(
    alerts: AlertEngine, engine: CorrelationEngine, failures: list[str]
) -> None:
    """Scenario 6 — two alerts concerning one M8 device (M12.6 "Same Device").

    The shared identity is deliberately placed on the *destination* device while
    the source addresses differ, so the only overlapping dimension is the device.
    Had the two alerts shared a source *device* they would also anchor on
    ``same_source``, and the run would have proved a different rule.
    """
    print("\n--- Scenario 6: same affected device, different sources ---")
    left = _create_alert(
        alerts,
        _make_finding(
            RULE_PORT_SCAN,
            source_ip=SHARED_DEVICE_SOURCE_A,
            destination_ip=DEVICE_DESTINATION_A,
            protocol="TCP",
            timestamp=_BASE_TIME,
            destination_device_id=SHARED_DEVICE_ID,
        ),
    )
    right = _create_alert(
        alerts,
        _make_finding(
            RULE_PORT_SCAN,
            source_ip=SHARED_DEVICE_SOURCE_B,
            destination_ip=DEVICE_DESTINATION_B,
            protocol="TCP",
            timestamp=_BASE_TIME + 4.0,
            destination_device_id=SHARED_DEVICE_ID,
        ),
    )
    for alert in (left, right):
        if alert.destination_device_id != SHARED_DEVICE_ID:
            failures.append(
                f"alert {_alert_id(alert)} did not preserve the finding's device, "
                "so the device scenario cannot be exercised (M11.15)"
            )
            return

    print(f"  correlating two alerts concerning {SHARED_DEVICE_ID}:")
    for outcome in (engine.correlate_alert(left), engine.correlate_alert(right)):
        _describe_outcome(outcome)

    incident = _incident_holding(engine, {_alert_id(left), _alert_id(right)})
    if incident is None:
        failures.append(
            "two alerts concerning the same device were not correlated (M12.6)"
        )
        return
    _describe_incident(incident)
    if "matched:device_centric_activity" not in incident.correlation_reasons:
        failures.append(
            "the device-centric rule was not attributed: "
            f"{list(incident.correlation_reasons)}"
        )
    if SHARED_DEVICE_ID not in incident.device_ids:
        failures.append("the incident does not carry the shared device identity")


# ---------------------------------------------------------------------------
# Bounded state and lifecycle (M12.9/M12.22)
# ---------------------------------------------------------------------------


def _check_bounded_state(
    engine: CorrelationEngine, factory, clock: FixedClock, failures: list[str]
) -> None:
    """Old correlation context expires without touching the alerts (M12.22).

    The alerts referenced by the dropped incidents must still be in the database
    afterwards: M12.22 asks for the *correlation* context to be bounded, not for
    the security record to be pruned.
    """
    before_incidents = engine.count_incidents()
    before_alerts = len(_stored_alert_rows(factory))
    stats = engine.stats()
    incident_stats = stats["incidents"]
    assert isinstance(incident_stats, dict)
    max_incidents = incident_stats.get("max_incidents")

    print("\n--- Bounded state (M12.22) ---")
    print(
        f"  incidents held      : {before_incidents} "
        f"(cap {max_incidents})"
    )
    if isinstance(max_incidents, int) and before_incidents > max_incidents:
        failures.append(
            f"the registry holds {before_incidents} incidents, over its cap of "
            f"{max_incidents}"
        )

    # Move past the retention age and sweep. Scenario 3 deliberately dates an
    # observation far in the future of the others, so the sweep is measured from
    # beyond *that* observation rather than from ``_BASE_TIME``: otherwise its
    # incident would be newer than the cutoff and would survive for a reason that
    # has nothing to do with retention working.
    clock.advance(RETENTION_SECONDS + DISTANT_SHIFT + 60.0)
    expired = engine.expire_old_context()
    after_incidents = engine.count_incidents()
    after_alerts = len(_stored_alert_rows(factory))
    print(f"  expired after {RETENTION_SECONDS:.0f}s : {expired} incident(s)")
    print(f"  incidents remaining : {after_incidents}")
    print(f"  alerts before/after : {before_alerts}/{after_alerts}")

    if after_incidents != 0:
        failures.append(
            f"{after_incidents} incident(s) survived a retention sweep (M12.22)"
        )
    if after_alerts != before_alerts:
        failures.append(
            "expiring correlation context changed the stored alerts, which are "
            "M11's record and are not M12's to prune (M12.22)"
        )


def _check_lifecycle(
    engine: CorrelationEngine, incident: CorrelatedIncident | None, failures: list[str]
) -> None:
    """The incident lifecycle accepts the documented moves and no more (M12.9)."""
    from app.correlation.status import allowed_targets

    print("\n--- Incident lifecycle (M12.9) ---")
    if incident is None:
        failures.append("no incident was available for the lifecycle check")
        return

    current = incident.normalized_status.value
    print(f"  incident {incident.incident_id} starts {current}")
    print(f"  allowed targets from {current}: {list(allowed_targets(current))}")

    # Walk toward a terminal state through whichever path the table allows, so
    # the check follows the model rather than assuming one exact sequence.
    investigating = engine.set_status(incident.incident_id, "investigating")
    if investigating is None or investigating.normalized_status.value != "investigating":
        failures.append("open -> investigating did not apply")
    resolved = engine.set_status(incident.incident_id, "resolved")
    if resolved is None or resolved.normalized_status.value != "resolved":
        failures.append("investigating -> resolved did not apply")

    try:
        engine.set_status(incident.incident_id, "open")
        failures.append(
            "a resolved incident was reopened, which M12.9 does not allow"
        )
    except InvalidIncidentTransition:
        print("  resolved -> open correctly rejected (terminal state holds)")

    terminal = engine.get_incident(incident.incident_id)
    if terminal is not None:
        print(
            f"  final status        : {terminal.normalized_status.value} "
            f"(active={terminal.normalized_status.value not in ('resolved', 'dismissed')})"
        )


def _check_ml_unavailable(engine: CorrelationEngine, failures: list[str]) -> None:
    """The reserved ML contribution is unavailable, not estimated (M12.18)."""
    print("\n--- Reserved ML contribution (M12.18) ---")
    available = engine.risk.ml_available
    print(f"  ML available        : {available}")
    print("  ML contribution     : 0.0 (also tried and refused when non-zero)")
    if available:
        failures.append("ML reported as available, though M12 ships none")

    from app.risk.inputs import RiskInputs

    try:
        engine.risk.score(RiskInputs(alert_count=1, ml_contribution=0.5))
    except Exception as exc:  # noqa: BLE001 - the refusal is the expectation
        failures.append(f"a non-zero ML signal was not refused: {exc!r}")
    else:
        result = engine.risk.score(RiskInputs(alert_count=1, ml_contribution=0.5))
        if result.ok:
            failures.append("a non-zero ML contribution was accepted and scored")
        else:
            print(f"  non-zero ML signal  : refused ({result.error})")
# ---------------------------------------------------------------------------
# The pipeline scenario: M12.25's chain, exercised end to end
# ---------------------------------------------------------------------------


class _LowRatesSource:
    """A rates source that reports no traffic (M10.12).

    The bandwidth detector reads M6's rates rather than the packet stream, so
    reporting zeros keeps it quiet and the scenario about correlation.
    """

    def get_rates(self, window: str = "1s") -> tuple[float, float]:
        """Return zero packets and bytes per second."""
        return 0.0, 0.0


def _build_detection_engine(devices):
    """Build a detection engine with lab thresholds, as M10's own verifier does.

    Two thresholds are lowered so a handful of synthetic packets demonstrates a
    detector: this is a lab configuration for verification, not the shipped
    default (M10.7).
    """
    from app.config.settings import Settings
    from app.detection import DetectionEngine, build_default_rules

    def resolve_device(ip_address: str) -> str | None:
        """Return the M8 device id owning ``ip_address``, or ``None`` (M10.4)."""
        device = devices.registry.get_by_ip(ip_address)
        return device.device_id if device is not None else None

    lab_settings = Settings(
        port_scan_unique_port_threshold=PIPELINE_SCAN_PORTS,
        internal_scan_unique_destination_threshold=PIPELINE_SWEEP_TARGETS,
    )
    return DetectionEngine(
        build_default_rules(lab_settings),
        rates_source=_LowRatesSource(),
        device_resolver=resolve_device,
    )


def _scenario_pipeline(
    factory, clock: FixedClock, engine: CorrelationEngine, failures: list[str]
) -> None:
    """Run M12.25's documented chain through the real pipeline (M12.32).

    Detection finding -> alert -> correlation -> incident -> risk score, with
    every stage the application actually runs: ``PacketPipeline`` wired with the
    M10 detection engine, the M11 alert engine and this very M12 engine. The
    other scenarios drive the correlation layer directly with controlled alerts,
    which is what M12.33 specifies; this one exists to prove the layer is wired
    into the pipeline rather than merely callable from a test.

    It runs on its own source address (``172.31.x.x``) so it cannot interact with
    the controlled scenarios, and it is silent unless something goes wrong.
    """
    from app.devices.manager import DeviceDiscoveryManager
    from app.services.packet_pipeline import PacketPipeline
    from app.statistics.manager import TrafficStatisticsManager

    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether

    print("\n--- Pipeline scenario: finding -> alert -> incident (M12.25/M12.32) ---")

    devices = DeviceDiscoveryManager()
    detection = _build_detection_engine(devices)
    _, alerts = _build_alert_layer(factory, clock)
    pipeline = PacketPipeline(
        statistics=TrafficStatisticsManager(),
        devices=devices,
        detection=detection,
        alerts=alerts,
        correlation=engine,
    )

    packets: list[tuple[str, object, float]] = []
    for index, port in enumerate(range(PIPELINE_SCAN_FIRST_PORT, PIPELINE_SCAN_FIRST_PORT + PIPELINE_SCAN_PORTS)):
        packets.append(
            (
                f"port scan {PIPELINE_SOURCE}:52000 -> {PIPELINE_SCAN_TARGET}:{port}",
                Ether(src="AA:BB:CC:00:00:01", dst="22:33:44:00:00:02")
                / IP(src=PIPELINE_SOURCE, dst=PIPELINE_SCAN_TARGET)
                / TCP(sport=52000, dport=port, flags="S"),
                PIPELINE_START + index * 0.01,
            )
        )
    for index, target in enumerate(
        f"{PIPELINE_SWEEP_PREFIX}.{octet}" for octet in range(20, 20 + PIPELINE_SWEEP_TARGETS)
    ):
        packets.append(
            (
                f"internal scan {PIPELINE_SOURCE}:53000 -> {target}:445",
                Ether(src="AA:BB:CC:00:00:01", dst="22:33:44:00:00:02")
                / IP(src=PIPELINE_SOURCE, dst=target)
                / UDP(sport=53000, dport=445),
                PIPELINE_START + PIPELINE_SWEEP_SHIFT + index * 0.01,
            )
        )

    for _label, packet, captured_at in packets:
        try:
            pipeline.process(packet, captured_at=captured_at)
        except Exception as exc:  # noqa: BLE001 - surface it as a failure
            failures.append(f"the pipeline failed to process a packet: {exc!r}")
            return

    findings = detection.get_findings()
    print(f"  packets normalized : {pipeline.get_processed_count()}")
    print(f"  findings raised    : {len(findings)}")
    print(f"  detectors fired    : {sorted({finding.rule_id for finding in findings})}")
    print(
        "  correlation errors : "
        f"{pipeline.get_correlation_error_count()} "
        f"alert errors: {pipeline.get_alert_error_count()} "
        f"detection errors: {pipeline.get_detection_error_count()}"
    )

    if not findings:
        failures.append("the pipeline produced no finding from the lab packets (M10)")
        return
    if pipeline.get_correlation_error_count():
        failures.append("correlation failed inside the pipeline (M12.25)")

    incident = engine.get_incidents()
    matching = [
        candidate
        for candidate in incident
        if PIPELINE_SOURCE in candidate.identity.source_addresses
    ]
    if not matching:
        failures.append(
            "no incident was opened for the pipeline's alerts, so correlation is "
            "not wired into the capture path (M12.25)"
        )
        return
    if len(matching) != 1:
        failures.append(
            f"the pipeline's alerts opened {len(matching)} incidents, expected 1"
        )
    incident_record = matching[0]
    _describe_incident(incident_record)
    if incident_record.alert_count() < 2:
        failures.append(
            "the pipeline incident groups "
            f"{incident_record.alert_count()} alert(s), expected at least 2"
        )
    if "matched:scan_sequence" not in incident_record.correlation_reasons:
        failures.append(
            "the pipeline's two detectors were not correlated as a scan sequence: "
            f"{list(incident_record.correlation_reasons)}"
        )


def _check_scenario_separation(
    engine: CorrelationEngine, expected: int, failures: list[str]
) -> None:
    """Guard that no incident mixes two scenarios, and that there are ``expected``.

    Every scenario owns its own address space, and this is what proves the plan
    held. A shared destination *anchors* correlation (M12.6), so an address reused
    between two scenarios would merge them and each would then be demonstrating
    something about the other. Grouping incidents by the /24 their sources come
    from catches that directly rather than trusting that the addresses were chosen
    well, which is exactly the mistake the first draft of this script made.
    """
    incidents = engine.get_incidents()
    print("\n--- Scenario separation (M12.4) ---")
    print(f"  incidents produced  : {len(incidents)} (expected {expected})")
    if len(incidents) != expected:
        failures.append(
            f"the scenarios produced {len(incidents)} incident(s), expected "
            f"{expected}; two scenarios have probably merged on a shared endpoint"
        )

    # One invariant, and only one: an incident's sources must all come from a
    # single scenario subnet. Two incidents sharing a subnet is *expected* --
    # scenario 2 opens two unrelated incidents and scenario 3 splits by time --
    # so uniqueness across incidents is deliberately not asserted here.
    for incident in incidents:
        subnets = sorted(
            {
                ".".join(address.split(".")[:3])
                for address in incident.identity.source_addresses
            }
        )
        if len(subnets) > 1:
            failures.append(
                f"incident {incident.incident_id} mixes sources from {subnets}, "
                "so two scenarios were merged (M12.4)"
            )
        print(f"  {incident.incident_id:<46} sources={subnets}")


def _run_scenarios(
    factory,
    clock: FixedClock,
    alerts: AlertEngine,
    engine: CorrelationEngine,
    failures: list[str],
) -> list[CorrelatedIncident]:
    """Run every M12.33 scenario and return the incidents they produced."""
    _print_model()
    _check_identity_model(engine.window, failures)
    _scenario_pipeline(factory, clock, engine, failures)
    related = _scenario_related(alerts, engine, factory, failures)
    _scenario_unrelated(alerts, engine, failures)
    _scenario_outside_window(alerts, engine, failures)
    _scenario_shared_destination(alerts, engine, failures)
    _scenario_shared_connection(engine, failures)
    _scenario_shared_device(alerts, engine, failures)
    _check_scenario_separation(engine, EXPECTED_SCENARIO_INCIDENTS, failures)
    _check_lifecycle(engine, related, failures)
    _check_ml_unavailable(engine, failures)
    return engine.get_incidents()
# ---------------------------------------------------------------------------
# Reporting the run
# ---------------------------------------------------------------------------


def _print_incident_report(incidents: list[CorrelatedIncident]) -> None:
    """Print every incident the run produced (M12.8/M12.33)."""
    print(f"\n--- Incidents ({len(incidents)}) ---")
    if not incidents:
        print("  (none)")
        return
    for incident in sorted(incidents, key=lambda item: item.incident_id):
        _describe_incident(incident)

    print("\n--- Incidents by band (M12.27) ---")
    by_band: dict[str, int] = {}
    for incident in incidents:
        by_band[incident.risk_band.value] = by_band.get(incident.risk_band.value, 0) + 1
    for band, count in sorted(by_band.items()):
        print(f"  {band:<10} {count}")

    print("\n--- Incidents by status (M12.9) ---")
    by_status: dict[str, int] = {}
    for incident in incidents:
        key = incident.normalized_status.value
        by_status[key] = by_status.get(key, 0) + 1
    for status, count in sorted(by_status.items()):
        print(f"  {status:<14} {count}")


def _print_queries(engine: CorrelationEngine, failures: list[str]) -> None:
    """Exercise the M12.26 query surface and its determinism (M12.26).

    The queries are the read paths a future API will call, so the verification
    exercises them here rather than leaving them unproven until the REST layer
    exists. Two properties matter beyond returning a result: every page is
    *bounded*, and every ordering is *total*, so repeating a query returns the
    same sequence rather than one that depends on dictionary order.
    """
    print("\n--- Query surface (M12.26) ---")
    recent = engine.recent_incidents(limit=3)
    highest = engine.highest_risk_incidents(limit=3)
    page = engine.get_incidents(IncidentQuery(limit=2, order=IncidentOrder.CONFIDENCE))
    window = engine.incidents_in_range(since=_BASE_TIME - 60.0, limit=5)
    print(f"  recent (3)          : {[item.incident_id for item in recent]}")
    print(
        "  highest risk (3)    : "
        f"{[(item.incident_id, item.risk_score) for item in highest]}"
    )
    print(
        "  by confidence (2)   : "
        f"{[(item.incident_id, round(item.correlation_confidence, 4)) for item in page]}"
    )
    print(f"  in a time range (5) : {[item.incident_id for item in window]}")

    if len(highest) > 3 or len(page) > 2 or len(recent) > 3:
        failures.append("an incident query returned more rows than its limit (M12.26)")
    repeat = engine.highest_risk_incidents(limit=3)
    if [item.incident_id for item in repeat] != [item.incident_id for item in highest]:
        failures.append("an incident query returned a different order on repeat (M12.26)")
    counted = engine.count_incidents()
    listed = len(engine.get_incidents(IncidentQuery(limit=500)))
    if counted != listed:
        failures.append(
            f"count_incidents reported {counted} but the listing returned {listed}"
        )


def _print_stats(
    engine: CorrelationEngine, writer: IncidentRiskWriter
) -> None:
    """Print the engine, store and writer counters (M12.34)."""
    stats = engine.stats()
    print("\n--- Correlation statistics (M12.34) ---")
    print(json.dumps(stats, indent=2, default=str, sort_keys=True))
    print("--- Risk write statistics (M12.24) ---")
    print(json.dumps(writer.stats(), indent=2, sort_keys=True))


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


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------


def run_sample_mode() -> int:
    """Create controlled alerts, correlate them, and verify the result (M12.33)."""
    workdir = Path(tempfile.mkdtemp(prefix="netwatch_m12_"))
    db_path = workdir / "verify_m12.db"
    database, factory = _connect_database(db_path)
    failures: list[str] = []
    try:
        _seed_rule_catalogue(factory)
        clock = FixedClock()
        _, alerts = _build_alert_layer(factory, clock)
        engine, writer = _build_correlation_layer(factory, clock)

        print("=" * _BANNER_WIDTH)
        print("M12 SAMPLE MODE - controlled findings, no privileges required")
        print("=" * _BANNER_WIDTH)
        print(f"database: {db_path}")
        print("Every finding below is synthetic and controlled (M12.33).")
        print("No packet detector is invoked; M10's findings are supplied directly.")

        incidents = _run_scenarios(factory, clock, alerts, engine, failures)
        _check_score_bounds(incidents, failures)
        _print_incident_report(incidents)
        _print_queries(engine, failures)
        _check_bounded_state(engine, factory, clock, failures)
        _print_stats(engine, writer)
    finally:
        database.dispose()
        shutil.rmtree(workdir, ignore_errors=True)
    return _report_failures(failures, mode="sample")
def run_live_mode(interface: str, seconds: float) -> int:
    """Capture real traffic through the whole pipeline and report the incidents.

    Requires Npcap and, on Windows, administrator rights. The lab detector
    thresholds used by the sample scenario are reused here on purpose: a few
    seconds of real traffic has to be able to demonstrate a detector, and the
    point of this mode is to watch alerts become incidents on the real capture
    path, not to measure detection quality (M12.33).
    """
    from app.devices.manager import DeviceDiscoveryManager
    from app.persistence.manager import PacketPersistence
    from app.services.capture_manager import CaptureManager
    from app.services.capture_state import CaptureError
    from app.services.interface_manager import get_interface_manager
    from app.services.packet_pipeline import PacketPipeline
    from app.statistics.manager import TrafficStatisticsManager

    interface_manager = get_interface_manager()
    try:
        interface_manager.select_interface(interface)
    except Exception as exc:  # noqa: BLE001 - report and stop
        print(f"Could not select interface '{interface}': {exc}")
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="netwatch_m12_"))
    db_path = workdir / "verify_m12_live.db"
    database, factory = _connect_database(db_path)
    failures: list[str] = []
    try:
        _seed_rule_catalogue(factory)
        # The real clock in live mode: a frozen one would stop retention from
        # ever sweeping, which is the opposite of what M12.22 asks for.
        _, alerts = _build_alert_layer(factory, time.time)
        engine, writer = _build_correlation_layer(factory, time.time)

        devices = DeviceDiscoveryManager()
        detection = _build_detection_engine(devices)
        persistence = PacketPersistence(
            session_factory=factory, batch_size=64, flush_interval=1.0
        )
        pipeline = PacketPipeline(
            statistics=TrafficStatisticsManager(),
            devices=devices,
            persistence=persistence,
            detection=detection,
            alerts=alerts,
            correlation=engine,
        )
        manager = CaptureManager(interface_manager=interface_manager, pipeline=pipeline)
        try:
            manager.stop()
        except Exception:  # noqa: BLE001 - there is no session to stop
            pass

        print("=" * _BANNER_WIDTH)
        print(f"M12 LIVE MODE - capturing on '{interface}' for {seconds:g}s")
        print("=" * _BANNER_WIDTH)
        print(f"database: {db_path}")
        print("Generate only authorized local traffic (browse, or scan a host you own).")
        print("Lab detector thresholds are in use, so alerts appear quickly.")

        try:
            manager.start()
        except CaptureError as exc:
            print(f"START FAILED: {exc.code} - {exc.message}")
            return 1

        time.sleep(seconds)
        processed = manager.get_processed_packet_count()
        detection_errors = manager.get_detection_error_count()
        alert_errors = manager.get_alert_error_count()
        correlation_errors = manager.get_correlation_error_count()
        manager.stop()
        # Write whatever the worker buffered, so the stored alerts are complete.
        persistence.flush()

        incidents = engine.highest_risk_incidents(limit=50)
        _print_incident_report(incidents)
        print("\n--- Capture result (M12.25) ---")
        print(f"  normalized ok      : {processed}")
        print(f"  detection errors   : {detection_errors}")
        print(f"  alert errors       : {alert_errors}")
        print(f"  correlation errors : {correlation_errors}")
        print(f"  stored alerts      : {len(_stored_alert_rows(factory))}")
        _check_score_bounds(incidents, failures)
        _print_queries(engine, failures)
        _print_stats(engine, writer)

        if detection_errors or alert_errors or correlation_errors:
            failures.append(
                "a pipeline stage reported an error during capture, though M12.25 "
                "requires a correlation or scoring failure to be contained rather "
                "than reported at this level"
            )
    finally:
        database.dispose()
        shutil.rmtree(workdir, ignore_errors=True)
    return _report_failures(failures, mode="live")


def main() -> int:
    """Parse arguments and dispatch to the selected mode."""
    parser = argparse.ArgumentParser(
        description="Verify M12 correlation and risk scoring (M12.33)."
    )
    parser.add_argument(
        "mode",
        nargs="?",
        default="sample",
        choices=("sample", "live"),
        help="sample = controlled findings (default), live = real capture",
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
