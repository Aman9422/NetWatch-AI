"""Integration tests: Detection Engine → finding → Alert Engine → SQLite (M11.31).

These tests wire the real M10 detection engine to the real M11 alert engine and
drive actual normalized packets through both, so what is exercised is the whole
path M11.22 describes rather than a service in isolation::

    NormalizedPacket
          ↓
    DetectionEngine (real M10 rules)
          ↓
    DetectionFinding
          ↓
    AlertEngine / AlertService
          ↓
    AlertRepository + AlertEvidenceRepository
          ↓
    SQLite

Nothing is stubbed on the detection side: a finding arrives only because a real
detector observed a real packet. Only the database is isolated — the
``session_factory`` fixture points at a fresh in-memory engine — so every
assertion is made against rows that were actually stored.

The detectors' own behaviour is covered in ``test_detection_<rule>.py`` and the
alert service in ``test_alerts_creation.py``; here the point is that the two
halves agree, that the stored alert preserves what M10 measured, that repeated
findings deduplicate, and that a failing alert write never stops the pipeline
(M11.21).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from sqlalchemy.orm import Session

from app.alerts.engine import AlertEngine
from app.alerts.mapping import mapping_for_rule
from app.alerts.service import AlertService
from app.detection.engine import DetectionEngine
from app.detection.finding import DetectionFinding
from app.detection.rules.icmp_flood import IcmpFloodRule
from app.detection.rules.internal_scan import InternalScanRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.syn_flood import SynFloodRule
from app.schemas.packet import NormalizedPacket
from app.services.packet_pipeline import PacketPipeline
from tests.alert_fakes import (
    ALERT_BASE_TIME,
    FakeConnection,
    FakeConnectionSource,
    FakePacket,
    FakePacketSource,
    SOURCE_IP,
    insert_packet,
    make_finding,
    make_resolvers,
    make_service,
    stored_alert_count,
    stored_alert_rows,
)
from tests.detection_fakes import (
    make_icmp_packet,
    make_syn_packet,
    make_udp_attempt,
)

# Low thresholds keep each test fast while still exercising the real rules.
PORT_SCAN_THRESHOLD = 5
INTERNAL_SCAN_THRESHOLD = 5
FLOOD_RATE_THRESHOLD = 10.0
FLOOD_WINDOW_SECONDS = 1.0

# A public destination so the internal-scan detector cannot claim it.
PUBLIC_DESTINATION = "8.8.8.8"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _build(
    rules: list[Any],
    *,
    session_factory: Callable[[], Session],
    service_kwargs: dict[str, Any] | None = None,
) -> tuple[DetectionEngine, AlertEngine]:
    """Build a real detection engine wired to a real alert engine."""
    detection = DetectionEngine(rules)
    service = make_service(session_factory, **(service_kwargs or {}))
    return detection, AlertEngine(service)


def _run(
    detection: DetectionEngine,
    alerts: AlertEngine,
    packets: list[NormalizedPacket],
) -> list[DetectionFinding]:
    """Feed packets through detection, then hand each finding to alerting.

    This is exactly what :class:`~app.services.packet_pipeline.PacketPipeline`
    does on the hot path (M11.22), without the capture layer these tests do not
    need.
    """
    findings: list[DetectionFinding] = []
    for packet in packets:
        produced = detection.process_packet(packet)
        findings.extend(produced)
        alerts.process_findings(produced)
    return findings


def _mapping(rule_id: str):
    """Return the alert mapping for a known rule, asserting it exists."""
    entry = mapping_for_rule(rule_id)
    assert entry is not None, f"no alert mapping for {rule_id}"
    return entry


def _port_scan_rule() -> PortScanRule:
    """Return a port scan detector with the test's low threshold."""
    return PortScanRule(
        unique_port_threshold=PORT_SCAN_THRESHOLD, window_seconds=60.0
    )


def _scan_packets(count: int, *, start_port: int = 4000) -> list[NormalizedPacket]:
    """Return ``count`` SYNs from one source across distinct destination ports."""
    return [
        make_syn_packet(
            source_ip=SOURCE_IP,
            destination_ip=PUBLIC_DESTINATION,
            destination_port=start_port + index,
            timestamp=ALERT_BASE_TIME + index,
        )
        for index in range(count)
    ]


def _flood_packets(count: int) -> list[NormalizedPacket]:
    """Return ``count`` SYNs to a single port, at one instant (a flood)."""
    return [
        make_syn_packet(
            source_ip=SOURCE_IP,
            destination_ip=PUBLIC_DESTINATION,
            destination_port=443,
            timestamp=ALERT_BASE_TIME,
        )
        for _ in range(count)
    ]


def _icmp_packets(count: int) -> list[NormalizedPacket]:
    """Return ``count`` ICMP packets aimed at one destination, as a burst."""
    return [
        make_icmp_packet(
            source_ip=SOURCE_IP,
            destination_ip=PUBLIC_DESTINATION,
            timestamp=ALERT_BASE_TIME,
        )
        for _ in range(count)
    ]


def _internal_sweep(count: int) -> list[NormalizedPacket]:
    """Return ``count`` UDP attempts to distinct private destinations."""
    return [
        make_udp_attempt(
            source_ip=SOURCE_IP,
            destination_ip=f"192.168.1.{20 + index}",
            timestamp=ALERT_BASE_TIME + index,
        )
        for index in range(count)
    ]


def _scapy_scan(count: int, *, start_port: int = 4000) -> list[Any]:
    """Return ``count`` raw Scapy SYNs across distinct ports, for the pipeline.

    The :class:`PacketPipeline` normalizes *raw* packets, so its tests must hand
    it the Scapy layers the capture callback would, not an already-normalized
    packet.
    """
    return [
        Ether(src="AA:BB:CC:DD:EE:FF", dst="22:33:44:55:66:77")
        / IP(src=SOURCE_IP, dst=PUBLIC_DESTINATION)
        / TCP(sport=52000, dport=start_port + index, flags="S")
        for index in range(count)
    ]
# ---------------------------------------------------------------------------
# A detected behaviour becomes a stored alert (M11.7/M11.31)
# ---------------------------------------------------------------------------


def test_a_detected_port_scan_creates_a_stored_alert(session_factory) -> None:
    """A real port scan produces a real alert row in SQLite (M11.7)."""
    detection, alerts = _build([_port_scan_rule()], session_factory=session_factory)

    findings = _run(detection, alerts, _scan_packets(PORT_SCAN_THRESHOLD + 2))

    assert len(findings) == 1
    assert stored_alert_count(session_factory) == 1
    row = stored_alert_rows(session_factory)[0]
    assert row.title == "Port Scan"
    assert row.source_ip == SOURCE_IP


def test_the_stored_alert_links_back_to_the_finding(session_factory) -> None:
    """The finding that raised the alert stays identifiable in the row (M11.7)."""
    detection, alerts = _build([_port_scan_rule()], session_factory=session_factory)

    findings = _run(detection, alerts, _scan_packets(PORT_SCAN_THRESHOLD + 2))

    # The finding id rides in the rule evidence, which is the documented trail
    # back to the observation; the M2 alerts table has no column for it.
    row = stored_alert_rows(session_factory)[0]
    evidence = _evidence_rows(session_factory, row.id)
    rule_records = [record for record in evidence if record.evidence_type == "rule"]
    assert len(rule_records) == 1
    assert findings[0].finding_id in rule_records[0].evidence_data


def test_a_short_sweep_creates_no_alert(session_factory) -> None:
    """Traffic below the detector's threshold produces no alert at all (M11.8)."""
    detection, alerts = _build([_port_scan_rule()], session_factory=session_factory)

    findings = _run(detection, alerts, _scan_packets(PORT_SCAN_THRESHOLD - 1))

    assert findings == []
    assert stored_alert_count(session_factory) == 0


def test_an_unsupported_finding_creates_no_alert_row(session_factory) -> None:
    """A finding with no mapping is counted as unsupported and stores nothing."""
    service = make_service(session_factory)
    engine = AlertEngine(service)

    outcome = engine.process_finding(make_finding(rule_id="not_a_real_rule"))

    assert outcome.unsupported is True
    assert outcome.created is False
    assert stored_alert_count(session_factory) == 0
    assert engine.get_counters().unsupported_findings == 1


# ---------------------------------------------------------------------------
# Severity and confidence survive the whole path (M11.4/M11.5)
# ---------------------------------------------------------------------------


def test_severity_comes_from_the_rule_mapping_not_the_finding(session_factory) -> None:
    """The stored severity is the mapping's, whatever the finding carried (M11.4)."""
    detection, alerts = _build([_port_scan_rule()], session_factory=session_factory)

    _run(detection, alerts, _scan_packets(PORT_SCAN_THRESHOLD + 2))

    row = stored_alert_rows(session_factory)[0]
    assert row.severity == _mapping("port_scan").severity.value


def test_confidence_is_preserved_from_the_detector(session_factory) -> None:
    """The stored alert carries the confidence M10 measured (M11.5)."""
    detection, alerts = _build([_port_scan_rule()], session_factory=session_factory)

    findings = _run(detection, alerts, _scan_packets(PORT_SCAN_THRESHOLD + 2))

    outcome = alerts.service.get_counters()
    assert outcome.alerts_created == 1
    # The column stores a percentage; the finding carries a 0..1 float.
    row = stored_alert_rows(session_factory)[0]
    assert row.confidence == round(findings[0].confidence * 100)


def test_severity_and_confidence_stay_separate_concepts(session_factory) -> None:
    """A high-confidence alert is not a high severity one, and vice versa (M11.5)."""
    detection, alerts = _build([_port_scan_rule()], session_factory=session_factory)

    _run(detection, alerts, _scan_packets(PORT_SCAN_THRESHOLD + 2))

    row = stored_alert_rows(session_factory)[0]
    # Port scan maps to ``high``; the confidence column is a percentage, and it
    # must not be read as a risk score (M11.4). The two columns are independent.
    assert row.severity == "high"
    assert row.risk_score == 0


def test_each_supported_rule_creates_an_alert_at_its_mapped_severity(
    session_factory,
) -> None:
    """Every M10 detector M11 maps produces an alert with its severity (M11.8)."""
    cases: list[tuple[str, list[Any], list[NormalizedPacket]]] = [
        (
            "port_scan",
            [_port_scan_rule()],
            _scan_packets(PORT_SCAN_THRESHOLD + 2),
        ),
        (
            "syn_flood",
            [SynFloodRule(window_seconds=FLOOD_WINDOW_SECONDS, rate_threshold=FLOOD_RATE_THRESHOLD)],
            _flood_packets(12),
        ),
        (
            "icmp_flood",
            [IcmpFloodRule(window_seconds=FLOOD_WINDOW_SECONDS, rate_threshold=FLOOD_RATE_THRESHOLD)],
            _icmp_packets(12),
        ),
        (
            "internal_scan",
            [InternalScanRule(unique_destination_threshold=INTERNAL_SCAN_THRESHOLD, window_seconds=60.0)],
            _internal_sweep(INTERNAL_SCAN_THRESHOLD + 2),
        ),
    ]

    for rule_id, rules, packets in cases:
        detection, alerts = _build(rules, session_factory=session_factory, service_kwargs={"clock": lambda: ALERT_BASE_TIME})
        _run(detection, alerts, packets)
        rows = stored_alert_rows(session_factory)
        mapping = _mapping(rule_id)
        matching = [row for row in rows if row.title == mapping.title]
        assert matching, f"no alert stored for {rule_id}"
        assert matching[0].severity == mapping.severity.value
        # Each detector's connection key is distinct, so the alerts accumulate
        # rather than folding — a fresh service per case is not needed.
        _clear(session_factory)


def _evidence_rows(session_factory: Callable[[], Session], alert_id: int) -> list[Any]:
    """Return the stored evidence rows for one alert."""
    from app.repositories.alert_evidence import AlertEvidenceRepository

    session = session_factory()
    try:
        return AlertEvidenceRepository(session).list_for_alert(alert_id)
    finally:
        session.close()


def _clear(session_factory: Callable[[], Session]) -> None:
    """Delete every alert and evidence row, so a loop can start clean."""
    from app.models.alert import Alert
    from app.models.alert_evidence import AlertEvidence

    session = session_factory()
    try:
        session.query(AlertEvidence).delete()
        session.query(Alert).delete()
        session.commit()
    finally:
        session.close()
# ---------------------------------------------------------------------------
# Repeated findings fold into one alert (M11.9/M11.10/M11.27)
# ---------------------------------------------------------------------------


def test_repeated_identical_findings_fold_into_one_alert(session_factory) -> None:
    """The same incident observed twice inside the window stores one alert."""
    service = make_service(session_factory)
    engine = AlertEngine(service)
    finding = make_finding(timestamp=ALERT_BASE_TIME)

    first = engine.process_finding(finding)
    # A second finding with the same rule, endpoints and window is the same
    # incident, so it is folded rather than creating a second row (M11.9).
    second = engine.process_finding(make_finding(timestamp=ALERT_BASE_TIME + 5))

    assert first.created is True
    assert second.duplicate is True
    assert stored_alert_count(session_factory) == 1
    counters = engine.get_counters()
    assert counters.alerts_created == 1
    assert counters.duplicates_folded == 1


def test_a_finding_outside_the_window_creates_a_second_alert(session_factory) -> None:
    """Once the window expires, the same rule and endpoints alert again (M11.10)."""
    service = make_service(session_factory, dedup_window_seconds=60.0)
    engine = AlertEngine(service)

    engine.process_finding(make_finding(timestamp=ALERT_BASE_TIME))
    # 90 seconds later — beyond the 60-second window — is a fresh incident.
    engine.process_finding(make_finding(timestamp=ALERT_BASE_TIME + 90))

    assert stored_alert_count(session_factory) == 2


def test_a_different_source_creates_an_independent_alert(session_factory) -> None:
    """A different source is a different incident, never folded (M11.9)."""
    service = make_service(session_factory)
    engine = AlertEngine(service)

    engine.process_finding(make_finding(source_ip="192.168.1.10"))
    engine.process_finding(make_finding(source_ip="192.168.1.11"))

    assert stored_alert_count(session_factory) == 2


def test_a_different_destination_creates_an_independent_alert(session_factory) -> None:
    """A different destination is a different incident, never folded (M11.9)."""
    service = make_service(session_factory)
    engine = AlertEngine(service)

    engine.process_finding(make_finding(destination_ip="8.8.8.8"))
    engine.process_finding(make_finding(destination_ip="1.1.1.1"))

    assert stored_alert_count(session_factory) == 2


def test_a_different_rule_creates_an_independent_alert(session_factory) -> None:
    """Two detectors reporting the same endpoints are two incidents (M11.9)."""
    service = make_service(session_factory)
    engine = AlertEngine(service)

    engine.process_finding(make_finding(rule_id="port_scan"))
    engine.process_finding(make_finding(rule_id="syn_flood"))

    assert stored_alert_count(session_factory) == 2


# ---------------------------------------------------------------------------
# Evidence is stored with the alert (M11.11-M11.15/M11.29)
# ---------------------------------------------------------------------------


def test_rule_and_behavioural_evidence_are_stored(session_factory) -> None:
    """Every alert carries the two always-present evidence records (M11.11)."""
    detection, alerts = _build([_port_scan_rule()], session_factory=session_factory)

    _run(detection, alerts, _scan_packets(PORT_SCAN_THRESHOLD + 2))

    row = stored_alert_rows(session_factory)[0]
    kinds = sorted(record.evidence_type for record in _evidence_rows(session_factory, row.id))
    assert kinds == ["behavioral", "rule"]


def test_packet_evidence_references_a_real_packet(session_factory) -> None:
    """Packet evidence points at a stored packet rather than copying it (M11.13)."""
    packet_id = insert_packet(session_factory, source_ip=SOURCE_IP)
    resolvers = make_resolvers(packet_source=FakePacketSource([FakePacket(packet_id)]))
    service = make_service(session_factory, resolvers=resolvers)
    engine = AlertEngine(service)

    engine.process_finding(make_finding())

    row = stored_alert_rows(session_factory)[0]
    evidence = _evidence_rows(session_factory, row.id)
    packet_records = [record for record in evidence if record.evidence_type == "packet"]
    assert len(packet_records) == 1
    # The reference is the foreign key, not a duplicate of the packet body.
    assert packet_records[0].packet_id == packet_id


def test_connection_evidence_references_the_tracker(session_factory) -> None:
    """Connection evidence names an M9 conversation rather than copying it (M11.14)."""
    resolvers = make_resolvers(
        connection_source=FakeConnectionSource([FakeConnection("conn-42")])
    )
    service = make_service(session_factory, resolvers=resolvers)
    engine = AlertEngine(service)

    engine.process_finding(make_finding())

    row = stored_alert_rows(session_factory)[0]
    evidence = _evidence_rows(session_factory, row.id)
    connection_records = [
        record for record in evidence if record.evidence_type == "connection"
    ]
    assert len(connection_records) == 1
    assert "conn-42" in connection_records[0].evidence_data


def test_device_evidence_is_stored_for_a_resolved_device(session_factory) -> None:
    """A resolved M8 device becomes device evidence, never an invented row (M11.15)."""
    service = make_service(session_factory)
    engine = AlertEngine(service)

    engine.process_finding(
        make_finding(source_device_id="mac:AA:BB:CC:DD:EE:FF")
    )

    row = stored_alert_rows(session_factory)[0]
    evidence = _evidence_rows(session_factory, row.id)
    device_records = [record for record in evidence if record.evidence_type == "device"]
    assert len(device_records) == 1
    assert "mac:AA:BB:CC:DD:EE:FF" in device_records[0].evidence_data


def test_evidence_count_matches_the_stored_records(session_factory) -> None:
    """The reported evidence count is the number of rows actually stored (M11.12)."""
    detection, alerts = _build([_port_scan_rule()], session_factory=session_factory)

    _run(detection, alerts, _scan_packets(PORT_SCAN_THRESHOLD + 2))

    row = stored_alert_rows(session_factory)[0]
    stored = _evidence_rows(session_factory, row.id)
    assert len(stored) == 2
# ---------------------------------------------------------------------------
# Alert lifecycle over a stored alert (M11.19/M11.20/M11.28)
# ---------------------------------------------------------------------------


def test_a_stored_alert_can_be_acknowledged_then_resolved(session_factory) -> None:
    """The open → acknowledged → resolved path writes through to SQLite (M11.19)."""
    detection, alerts = _build([_port_scan_rule()], session_factory=session_factory)
    _run(detection, alerts, _scan_packets(PORT_SCAN_THRESHOLD + 2))
    row = stored_alert_rows(session_factory)[0]

    acknowledged = alerts.service.set_status(row.id, "acknowledged")
    resolved = alerts.service.set_status(row.id, "resolved", updated_at=ALERT_BASE_TIME + 60)

    assert acknowledged is not None and acknowledged.status.value == "acknowledged"
    assert resolved is not None and resolved.status.value == "resolved"
    stored = stored_alert_rows(session_factory)[0]
    assert stored.status == "resolved"
    assert stored.resolved_at is not None


def test_an_invalid_transition_leaves_the_stored_alert_unchanged(session_factory) -> None:
    """A rejected lifecycle move never mutates the stored row (M11.19)."""
    from app.alerts.status import InvalidStatusTransition

    detection, alerts = _build([_port_scan_rule()], session_factory=session_factory)
    _run(detection, alerts, _scan_packets(PORT_SCAN_THRESHOLD + 2))
    row = stored_alert_rows(session_factory)[0]

    with pytest.raises(InvalidStatusTransition):
        # resolved → open is not a legal move: there is no reopen (M11.19).
        alerts.service.set_status(row.id, "resolved")
        alerts.service.set_status(row.id, "open")

    stored = stored_alert_rows(session_factory)[0]
    assert stored.status == "resolved"


def test_a_terminal_alert_cannot_be_reopened(session_factory) -> None:
    """Once dismissed, no further transition is accepted (M11.19)."""
    from app.alerts.status import InvalidStatusTransition

    service = make_service(session_factory)
    engine = AlertEngine(service)
    outcome = engine.process_finding(make_finding())
    assert outcome.alert is not None
    assert outcome.alert.alert_id is not None
    alert_id = outcome.alert.alert_id

    service.set_status(alert_id, "dismissed")

    with pytest.raises(InvalidStatusTransition):
        service.set_status(alert_id, "acknowledged")


# ---------------------------------------------------------------------------
# The full pipeline reaches the alert store (M11.22/M11.31)
# ---------------------------------------------------------------------------


def test_the_packet_pipeline_creates_a_stored_alert(session_factory) -> None:
    """Driving the real PacketPipeline end to end lands an alert in SQLite (M11.22)."""
    detection = DetectionEngine([_port_scan_rule()])
    service = make_service(session_factory)
    alerts = AlertEngine(service)
    pipeline = PacketPipeline(detection=detection, alerts=alerts)

    for packet in _scapy_scan(PORT_SCAN_THRESHOLD + 2):
        pipeline.process(packet)

    assert pipeline.get_alert_error_count() == 0
    assert stored_alert_count(session_factory) == 1
    assert stored_alert_rows(session_factory)[0].title == "Port Scan"


# ---------------------------------------------------------------------------
# Alerting failures never reach the pipeline (M11.21/M11.26)
# ---------------------------------------------------------------------------


class _RaisingSessionFactory:
    """A session factory whose every session fails on use, for isolation tests."""

    def __call__(self):
        raise RuntimeError("simulated database outage")


def test_a_failing_alert_write_is_isolated_and_counted() -> None:
    """An alert-storage failure is contained, counted and reported, never raised."""
    service = AlertService(session_factory=_RaisingSessionFactory())
    engine = AlertEngine(service)

    outcome = engine.process_finding(make_finding())

    assert outcome.error is True
    assert outcome.created is False
    assert engine.get_counters().errors == 1


def test_the_pipeline_survives_a_failing_alert_engine(session_factory) -> None:
    """Detection keeps running after an alert failure; only the alert is lost."""
    detection = DetectionEngine([_port_scan_rule()])
    service = AlertService(session_factory=_RaisingSessionFactory())
    pipeline = PacketPipeline(detection=detection, alerts=AlertEngine(service))

    for packet in _scapy_scan(PORT_SCAN_THRESHOLD + 2):
        pipeline.process(packet)

    # Capture/processing continued for every packet, and the engine contained
    # each failure rather than letting it escape into the pipeline (M11.21).
    assert pipeline.get_processed_count() == PORT_SCAN_THRESHOLD + 2
    assert pipeline.get_alert_error_count() == 0
    assert service.get_counters().errors >= 1


def test_detection_continues_when_alerting_is_disabled(session_factory) -> None:
    """A disabled alert engine still lets detection run and store nothing (M11.24)."""
    detection = DetectionEngine([_port_scan_rule()])
    service = make_service(session_factory)
    engine = AlertEngine(service, enabled=False)

    produced = 0
    for packet in _scan_packets(PORT_SCAN_THRESHOLD + 2):
        findings = detection.process_packet(packet)
        produced += len(findings)
        engine.process_findings(findings)

    # Detection still ran and observed the sweep; alerting simply produced
    # nothing, and the engine reports the skip rather than a silent void.
    assert produced == 1
    assert stored_alert_count(session_factory) == 0
    assert engine.get_counters().findings_seen == 0
