"""Integration tests: detection → alert → correlation → risk → incident (M12.32).

These tests wire the *real* M10 detection engine, the real M11 alert engine and
the real M12 correlation engine into the real packet pipeline, and drive actual
raw packets through it, so what is exercised is the whole path M12.32 names::

    NormalizedPacket
          ↓
    DetectionEngine (real M10 rules)
          ↓
    DetectionFinding
          ↓
    AlertEngine / AlertService
          ↓
    alerts table (SQLite)
          ↓
    CorrelationEngine (real M12.12 rules)
          ↓
    CorrelatedIncident
          ↓
    RiskScoringEngine
          ↓
    risk_score written back to the alerts

Nothing on the detection or alerting side is stubbed: a finding arrives because a
real detector observed a real packet, and an alert arrives because the real M11
service stored one. Only the database is isolated — ``session_factory`` points at
a fresh in-memory engine — so every assertion is made against rows that were
actually written.

M12.32 also requires the underlying alerts to remain **accessible** after
correlation. That is the property the second half of this file is about:
correlation adds a higher-level relationship, it never consumes or rewrites the
alerts it grouped (M12.10), so the rows are still there, still queryable, and
still carry their own M11 severity and confidence beside M12's risk score.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from sqlalchemy.orm import Session

from app.alerts.engine import AlertEngine
from app.alerts.mapping import mapping_for_rule
from app.correlation.engine import CorrelationEngine
from app.correlation.persistence import IncidentRiskWriter
from app.detection.engine import DetectionEngine
from app.detection.rules.internal_scan import InternalScanRule
from app.detection.rules.port_scan import PortScanRule
from app.models.alert import Alert as AlertRow
from app.services.packet_pipeline import PacketPipeline
from tests.alert_fakes import (
    ALERT_BASE_TIME,
    OTHER_SOURCE_IP,
    SOURCE_IP,
    make_service,
    stored_alert_count,
    stored_alert_rows,
)
from tests.correlation_fakes import FixedClock, make_engine

# Low thresholds keep each test fast while still exercising the real rules.
PORT_SCAN_THRESHOLD = 5
INTERNAL_SCAN_THRESHOLD = 5

# A public destination, so the internal-scan detector cannot claim it.
PUBLIC_DESTINATION = "8.8.8.8"

# The engine's clock, and the alert service's, are pinned just after the last
# packet so the correlation window and the recency term are both deterministic.
ENGINE_NOW = ALERT_BASE_TIME + 60.0


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _port_scan_packets(
    count: int, *, source_ip: str = SOURCE_IP, start_port: int = 4000
) -> list[Any]:
    """Return ``count`` raw SYNs from one source across distinct ports (M10.8)."""
    return [
        Ether(src="AA:BB:CC:DD:EE:FF", dst="22:33:44:55:66:77")
        / IP(src=source_ip, dst=PUBLIC_DESTINATION)
        / TCP(sport=52000, dport=start_port + index, flags="S")
        for index in range(count)
    ]


def _internal_sweep_packets(count: int, *, source_ip: str = SOURCE_IP) -> list[Any]:
    """Return ``count`` raw UDP attempts to distinct private hosts (M10.9).

    Distinguished addresses rather than ports: the internal-scan detector counts
    the hosts an internal source reaches out to, which is what makes it a
    different observation from the port scan above even when the source matches.
    """
    return [
        Ether(src="AA:BB:CC:DD:EE:FF", dst="22:33:44:55:66:77")
        / IP(src=source_ip, dst=f"192.168.1.{20 + index}")
        / UDP(sport=53000, dport=53)
        for index in range(count)
    ]


def _build(
    session_factory: Callable[[], Session],
    *,
    rules: Sequence[Any] | None = None,
    correlation: CorrelationEngine | None = None,
    clock: FixedClock | None = None,
) -> tuple[PacketPipeline, IncidentRiskWriter | None]:
    """Build the real pipeline over an isolated database.

    Every layer is the production one: a real detection engine with the real
    M10 rules, a real alert service writing to the isolated database, and a real
    correlation engine scoring real incidents. The risk writer is wired to the
    same database, so the score an incident carries can be read back off the
    alert rows the pipeline stored (M12.24).
    """
    resolved_clock = clock if clock is not None else FixedClock(ENGINE_NOW)
    detection = DetectionEngine(
        list(rules)
        if rules is not None
        else [
            PortScanRule(
                unique_port_threshold=PORT_SCAN_THRESHOLD, window_seconds=60.0
            ),
            InternalScanRule(
                unique_destination_threshold=INTERNAL_SCAN_THRESHOLD,
                window_seconds=60.0,
            ),
        ]
    )
    service = make_service(session_factory, clock=lambda: ENGINE_NOW)
    alerts = AlertEngine(service)
    writer: IncidentRiskWriter | None = None
    engine = correlation
    if engine is None:
        writer = IncidentRiskWriter(session_factory)
        engine = make_engine(risk_persistence=writer, clock=resolved_clock)
    pipeline = PacketPipeline(
        detection=detection, alerts=alerts, correlation=engine
    )
    return pipeline, writer


def _drive(pipeline: PacketPipeline, packets: Sequence[Any]) -> None:
    """Feed raw packets through the pipeline at deterministic times."""
    for index, packet in enumerate(packets):
        pipeline.process(packet, ALERT_BASE_TIME + index)


def _correlated_engine(pipeline: PacketPipeline) -> CorrelationEngine:
    """Return the pipeline's correlation engine, asserting it is the real one."""
    engine = pipeline.correlation
    assert isinstance(engine, CorrelationEngine)
    return engine


def _stored_alerts(session_factory: Callable[[], Session]) -> list[AlertRow]:
    """Return every stored ``alerts`` row, newest first.

    These are the *stored* rows — the M2 model M11 writes through — not the
    runtime alert dataclass the alert engine passes between layers. Every
    property asserted of them below is about what actually reached the database.
    """
    return stored_alert_rows(session_factory)


# ---------------------------------------------------------------------------
# The whole path reaches an incident (M12.32)
# ---------------------------------------------------------------------------


def test_a_detected_port_scan_becomes_a_scored_incident(session_factory) -> None:
    """A real detector raises an alert, and correlation turns it into an incident.

    This is the M12.32 path end to end, with nothing stubbed between the wire and
    the incident.
    """
    pipeline, _ = _build(session_factory)

    _drive(pipeline, _port_scan_packets(PORT_SCAN_THRESHOLD + 2))

    assert pipeline.get_correlation_error_count() == 0
    assert pipeline.get_alert_error_count() == 0
    assert stored_alert_count(session_factory) == 1

    engine = _correlated_engine(pipeline)
    incidents = engine.get_incidents()
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.title == "Port Scan"
    # The incident points at the alert that was actually stored (M12.8/M12.10).
    stored = _stored_alerts(session_factory)
    assert incident.alert_ids == (stored[0].id,)
    assert incident.finding_ids  # the M10 finding that produced the alert
    assert incident.risk_score > 0
    # A lone alert correlates with nothing, so the *correlation* confidence is
    # zero while the alert's own evidence confidence is not (M12.16). The two are
    # deliberately different numbers, and the incident keeps both.
    assert incident.correlation_confidence == 0.0
    assert incident.mean_alert_confidence() > 0


def test_the_incident_score_is_written_onto_the_stored_alert(session_factory) -> None:
    """The risk score reaches the database through the pipeline (M12.24).

    M11 stores ``risk_score = 0`` because only M12 can produce a meaningful one;
    after the pipeline has run, the row must carry the incident's own score.
    """
    pipeline, writer = _build(session_factory)

    _drive(pipeline, _port_scan_packets(PORT_SCAN_THRESHOLD + 2))

    assert writer is not None
    assert writer.stats()["rows_written"] >= 1
    incident = _correlated_engine(pipeline).get_incidents()[0]
    stored = _stored_alerts(session_factory)
    assert stored[0].risk_score == incident.risk_score
    assert stored[0].risk_score > 0


def test_two_related_alerts_from_one_source_share_one_incident(
    session_factory,
) -> None:
    """A scan followed by follow-up activity is one incident, not two (M12.12).

    A port scan and an internal scan from the same source inside the window match
    the most specific rule in the set — ``scan_sequence`` — so they are grouped.
    Both alerts are preserved: correlation adds a relationship, it does not
    collapse the observations (M12.10).
    """
    pipeline, _ = _build(session_factory)

    _drive(pipeline, _port_scan_packets(PORT_SCAN_THRESHOLD + 2))
    _drive(pipeline, _internal_sweep_packets(INTERNAL_SCAN_THRESHOLD + 2))

    # Two independent detectors produced two independent alerts...
    assert stored_alert_count(session_factory) == 2

    engine = _correlated_engine(pipeline)
    incidents = engine.get_incidents()
    # ...and correlation grouped them into one piece of activity.
    assert len(incidents) == 1
    incident = incidents[0]
    stored_ids = {row.id for row in _stored_alerts(session_factory)}
    assert set(incident.alert_ids) == stored_ids
    assert len(incident.alert_ids) == 2

    # The rule that grouped them, and the shared value that justified it, are
    # both recorded on the incident (M12.12).
    assert any(
        reason.startswith("matched:") for reason in incident.correlation_reasons
    )
    rule_reasons = [
        reason for reason in incident.correlation_reasons if reason.startswith("matched:")
    ]
    assert rule_reasons == ["matched:scan_sequence"]
    assert any("same_source" in reason for reason in incident.correlation_reasons)
    # Both alerts contributed their detector identity to the incident.
    assert {"port_scan", "internal_scan"} <= set(incident.rule_ids)


def test_both_grouped_alerts_carry_the_incident_score(session_factory) -> None:
    """Every member alert is stamped with the one score the incident holds."""
    pipeline, writer = _build(session_factory)

    _drive(pipeline, _port_scan_packets(PORT_SCAN_THRESHOLD + 2))
    _drive(pipeline, _internal_sweep_packets(INTERNAL_SCAN_THRESHOLD + 2))

    incident = _correlated_engine(pipeline).get_incidents()[0]
    assert writer is not None
    stored = _stored_alerts(session_factory)
    assert len(stored) == 2
    assert all(row.risk_score == incident.risk_score for row in stored)
    # The two alerts were stamped separately, so the writer saw more than one row.
    assert writer.stats()["rows_written"] >= 2


# ---------------------------------------------------------------------------
# The underlying alerts stay accessible and unrevised (M12.10/M12.32)
# ---------------------------------------------------------------------------


def test_correlation_does_not_revise_what_the_alerts_recorded(session_factory) -> None:
    """Correlation adds a risk score; it does not rewrite M11's observation.

    Severity and confidence are M11's record of what was detected and are not
    correlation's to change, and the lifecycle status belongs to a human. The one
    column M12 owns is ``risk_score`` (M12.10).

    The proof is a second pass: re-scoring the incident writes its score again,
    so if correlation were touching anything besides that column, re-scoring
    would move it.
    """
    pipeline, _ = _build(session_factory)
    engine = _correlated_engine(pipeline)

    _drive(pipeline, _port_scan_packets(PORT_SCAN_THRESHOLD + 2))
    _drive(pipeline, _internal_sweep_packets(INTERNAL_SCAN_THRESHOLD + 2))

    def m11_columns() -> dict[str, tuple[str, int, str]]:
        """Return each stored alert's M11-owned columns, keyed by title."""
        return {
            row.title: (row.severity, row.confidence, row.status)
            for row in _stored_alerts(session_factory)
        }

    incident = engine.get_incidents()[0]
    before = m11_columns()
    assert set(before) == {"Port Scan", "Internal Scan"}
    # The severities are the alert mapping's own, not a level M12 chose (M11.4).
    for rule_id, title in (
        ("port_scan", "Port Scan"),
        ("internal_scan", "Internal Scan"),
    ):
        entry = mapping_for_rule(rule_id)
        assert entry is not None
        assert before[title][0] == entry.severity.value

    rescored = engine.rescore(incident.incident_id)

    assert rescored is not None
    # Nothing M11 recorded moved, and the score was written again on top of it.
    assert m11_columns() == before
    stored = _stored_alerts(session_factory)
    assert all(row.risk_score == rescored.risk_score for row in stored)
    assert all(row.status == "open" for row in stored)


def test_a_grouped_alert_is_still_queryable_in_its_own_right(session_factory) -> None:
    """Grouping does not hide an alert: it is still found by its own filters.

    M12.26's incident queries and M11.18's alert queries are different questions
    over the same rows, and answering one must not obscure the other.
    """
    pipeline, _ = _build(session_factory)
    engine = _correlated_engine(pipeline)

    _drive(pipeline, _port_scan_packets(PORT_SCAN_THRESHOLD + 2))

    incident = engine.get_incidents()[0]
    # The same alert is reachable by source, by rule and through its incident.
    assert engine.incidents_for_source(SOURCE_IP)
    assert engine.incidents_for_rule("port_scan")
    assert stored_alert_count(session_factory) == 1
    assert engine.get_incident(incident.incident_id) is not None
    # And the alert the incident holds is a real stored row, not a copy.
    assert {row.id for row in _stored_alerts(session_factory)} == set(
        incident.alert_ids
    )


# ---------------------------------------------------------------------------
# Unrelated activity is not merged (M12.4/M12.29)
# ---------------------------------------------------------------------------


def test_activity_from_a_different_source_stays_a_separate_incident(
    session_factory,
) -> None:
    """Two sources are two incidents; proximity alone never merges them (M12.4)."""
    pipeline, _ = _build(session_factory)

    _drive(pipeline, _port_scan_packets(PORT_SCAN_THRESHOLD + 2))
    _drive(
        pipeline,
        _port_scan_packets(PORT_SCAN_THRESHOLD + 2, source_ip=OTHER_SOURCE_IP),
    )

    assert stored_alert_count(session_factory) == 2
    incidents = _correlated_engine(pipeline).get_incidents()
    assert len(incidents) == 2
    # Each incident holds exactly one alert, and the two are different alerts.
    grouped = sorted(incident.alert_ids[0] for incident in incidents)
    assert len(set(grouped)) == 2


def test_correlation_is_not_reached_when_nothing_alerted(session_factory) -> None:
    """Traffic below every threshold costs no correlation work at all (M12.25).

    The pipeline only calls correlation when alerting produced something, so the
    quiet path is free rather than a wasted pass over an empty list.
    """
    counter = _CountingCorrelation()
    pipeline, _ = _build(session_factory, correlation=counter)  # type: ignore[arg-type]

    _drive(pipeline, _port_scan_packets(PORT_SCAN_THRESHOLD - 1))

    assert counter.calls == 0
    assert stored_alert_count(session_factory) == 0


# ---------------------------------------------------------------------------
# A correlation failure cannot stop capture (M12.25)
# ---------------------------------------------------------------------------


class _CountingCorrelation:
    """A correlation double that records how often it is asked to correlate."""

    def __init__(self) -> None:
        self.calls = 0
        self.alerts: list[Any] = []

    def correlate_alerts(self, alerts: Sequence[Any]) -> list[Any]:
        """Record the call and report nothing."""
        self.calls += 1
        self.alerts.extend(alerts)
        return []


class _RaisingCorrelation:
    """A correlation engine whose every call fails (M12.25)."""

    def __init__(self) -> None:
        self.calls = 0

    def correlate_alerts(self, alerts: Sequence[Any]) -> list[Any]:
        """Count the attempt, then fail."""
        self.calls += 1
        raise RuntimeError("simulated correlation failure")


def test_a_correlation_failure_is_isolated_and_counted(session_factory) -> None:
    """Correlation cannot stop capture, and the alert it was reading survives.

    The engine contains its own failures, so the pipeline counter normally stays
    zero; this proves the pipeline contains a failure that escapes it entirely,
    which M12.25 requires it to do anyway.
    """
    raising = _RaisingCorrelation()
    pipeline, _ = _build(session_factory, correlation=raising)  # type: ignore[arg-type]
    packets = _port_scan_packets(PORT_SCAN_THRESHOLD + 2)

    _drive(pipeline, packets)

    # Every packet was still processed and the alert was still stored.
    assert pipeline.get_processed_count() == len(packets)
    assert pipeline.get_correlation_error_count() == 1
    assert raising.calls == 1
    assert stored_alert_count(session_factory) == 1
    # The alert is intact — the failure cost the correlation, not the alert.
    stored = _stored_alerts(session_factory)
    assert stored[0].risk_score == 0
    assert stored[0].status == "open"


def test_a_risk_write_failure_does_not_lose_the_incident(session_factory) -> None:
    """A locked database costs the write, not the correlation or the alert.

    The writer is wired to a factory that always fails, so the incident is scored
    and held in memory while every attempt to stamp the alert rows fails. The
    alert must still be there, and the incident must still be queryable with its
    score (M12.25).
    """

    def broken_factory():
        raise RuntimeError("the database is locked")

    clock = FixedClock(ENGINE_NOW)
    engine = make_engine(
        risk_persistence=IncidentRiskWriter(broken_factory),  # type: ignore[arg-type]
        clock=clock,
    )
    pipeline, _ = _build(session_factory, correlation=engine)

    _drive(pipeline, _port_scan_packets(PORT_SCAN_THRESHOLD + 2))

    incidents = engine.get_incidents()
    assert len(incidents) == 1
    assert incidents[0].risk_score > 0
    # ``stats()`` is a heterogeneous diagnostic mapping, so the counter is
    # narrowed to the integer it is rather than compared as an opaque object.
    persist_errors = engine.stats()["persist_errors"]
    assert isinstance(persist_errors, int)
    assert persist_errors >= 1
    # The alert survived, unscored but otherwise exactly as M11 stored it.
    stored = _stored_alerts(session_factory)
    assert len(stored) == 1
    assert stored[0].risk_score == 0
    assert stored[0].severity == "high"
