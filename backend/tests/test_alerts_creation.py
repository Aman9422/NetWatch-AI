"""Tests for alert creation and the detection-to-alert mapping (M11.26).

An alert is created from an M10 finding, and these tests pin the whole
conversion: which findings create one and which do not, what title and severity
the rule's mapping assigns, that confidence is carried across from the finding
rather than invented, and that the finding, its devices and its conversations
stay identifiable on the alert and its evidence.

The database is the ``session_factory`` fixture — an in-memory engine created
and dropped per test — so nothing here touches the developer's real database.
"""

from __future__ import annotations

import pytest

from app.alerts.mapping import RULE_MAPPINGS
from app.alerts.queries import AlertQueries
from app.alerts.severity import AlertSeverity
from app.alerts.status import AlertStatus
from tests.alert_fakes import (
    DESTINATION_DEVICE_ID,
    SOURCE_DEVICE_ID,
    FakeConnection,
    FakeConnectionSource,
    make_finding,
    make_resolvers,
    make_service,
    stored_alert_count,
)

# -- which findings create alerts (M11.8) -----------------------------------


def test_supported_finding_creates_an_alert(session_factory) -> None:
    """A finding from a mapped rule creates one stored alert (M11.7)."""
    service = make_service(session_factory)
    outcome = service.process_finding(make_finding())

    assert outcome.created is True
    assert outcome.duplicate is False
    assert outcome.unsupported is False
    assert outcome.error is False
    assert outcome.alert is not None
    assert outcome.alert.alert_id is not None
    assert stored_alert_count(session_factory) == 1


def test_unsupported_finding_creates_no_alert(session_factory) -> None:
    """A rule with no alert mapping produces no alert and is not an error."""
    service = make_service(session_factory)
    outcome = service.process_finding(
        make_finding(rule_id="no_such_detector", rule_name="No Such Detector")
    )

    assert outcome.unsupported is True
    assert outcome.created is False
    assert outcome.alert is None
    assert stored_alert_count(session_factory) == 0


def test_blank_rule_id_creates_no_alert(session_factory) -> None:
    """A finding that names no rule is not alertable."""
    service = make_service(session_factory)
    outcome = service.process_finding(make_finding(rule_id=""))

    assert outcome.unsupported is True
    assert stored_alert_count(session_factory) == 0


def test_disabled_service_creates_no_alert(session_factory) -> None:
    """The master switch (M11.24) accepts a finding but raises nothing."""
    service = make_service(session_factory, enabled=False)
    outcome = service.process_finding(make_finding())

    assert outcome.created is False
    assert outcome.alert is None
    assert "disabled" in outcome.message.lower()
    assert stored_alert_count(session_factory) == 0


# -- mapping: title, severity, confidence (M11.4/M11.5/M11.8) ----------------


@pytest.mark.parametrize("rule_id", sorted(RULE_MAPPINGS))
def test_each_rule_creates_an_alert_with_its_mapped_title_and_severity(
    session_factory, rule_id: str
) -> None:
    """Every mapped detector produces the title and severity the table defines."""
    service = make_service(session_factory)
    outcome = service.process_finding(
        make_finding(rule_id=rule_id, rule_name=rule_id)
    )

    mapping = RULE_MAPPINGS[rule_id]
    assert outcome.created is True
    assert outcome.alert is not None
    assert outcome.alert.title == mapping.title
    assert outcome.alert.severity is mapping.severity


def test_syn_flood_is_critical_and_port_scan_is_high(session_factory) -> None:
    """Severity is fixed per rule, so a low-confidence flood is still critical."""
    service = make_service(session_factory)

    flood = service.process_finding(
        make_finding(rule_id="syn_flood", confidence=0.51)
    )
    scan = service.process_finding(
        make_finding(rule_id="port_scan", confidence=0.99)
    )

    assert flood.alert is not None and flood.alert.severity is AlertSeverity.CRITICAL
    assert scan.alert is not None and scan.alert.severity is AlertSeverity.HIGH


def test_confidence_is_carried_from_the_finding(session_factory) -> None:
    """The alert's confidence is what M10 measured, to the stored precision."""
    service = make_service(session_factory)
    outcome = service.process_finding(make_finding(confidence=0.92))

    assert outcome.alert is not None
    assert outcome.alert.confidence == pytest.approx(0.92)


def test_confidence_survives_the_round_trip_through_the_column(
    session_factory,
) -> None:
    """The integer-percent column reads back as the finding's confidence."""
    service = make_service(session_factory)
    outcome = service.process_finding(make_finding(confidence=0.75))
    assert outcome.alert is not None

    alerts = AlertQueries(session_factory=session_factory)
    stored = alerts.get_alert(outcome.alert.alert_id or 0)

    assert stored is not None
    assert stored.confidence == pytest.approx(0.75)


def test_alert_starts_open(session_factory) -> None:
    """A freshly created alert is open (M11.6)."""
    service = make_service(session_factory)
    outcome = service.process_finding(make_finding())

    assert outcome.alert is not None
    assert outcome.alert.status is AlertStatus.OPEN


# -- finding association (M11.7) --------------------------------------------


def test_alert_keeps_the_finding_that_raised_it(session_factory) -> None:
    """The runtime alert points back at the M10 finding (M11.7)."""
    service = make_service(session_factory)
    finding = make_finding()
    outcome = service.process_finding(finding)

    assert outcome.alert is not None
    assert outcome.alert.finding_id == finding.finding_id


def test_rule_evidence_names_the_finding(session_factory) -> None:
    """The stored rule evidence keeps the original finding identifiable (M11.7)."""
    service = make_service(session_factory)
    finding = make_finding()
    outcome = service.process_finding(finding)
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = AlertQueries(session_factory=session_factory).get_detail(
        outcome.alert.alert_id
    )
    assert detail is not None
    rule_records = [
        record for record in detail.evidence if record.evidence_type == "rule"
    ]
    assert rule_records, "an alert must carry a rule evidence record"
    assert finding.finding_id in rule_records[0].evidence_data


# -- endpoint association (M11.3) -------------------------------------------


def test_alert_records_the_endpoints_and_protocol(session_factory) -> None:
    """The alert stores the source, destination and protocol of the finding."""
    service = make_service(session_factory)
    outcome = service.process_finding(make_finding())

    assert outcome.alert is not None
    assert outcome.alert.source_ip == "192.168.1.10"
    assert outcome.alert.destination_ip == "8.8.8.8"
    assert outcome.alert.protocol == "TCP"


# -- device association (M11.15) --------------------------------------------


def test_resolved_devices_are_preserved_on_the_alert(session_factory) -> None:
    """When M8 resolved a device the association survives onto the alert (M11.15)."""
    service = make_service(session_factory)
    outcome = service.process_finding(
        make_finding(
            source_device_id=SOURCE_DEVICE_ID,
            destination_device_id=DESTINATION_DEVICE_ID,
        )
    )

    assert outcome.alert is not None
    assert outcome.alert.source_device_id == SOURCE_DEVICE_ID
    assert outcome.alert.destination_device_id == DESTINATION_DEVICE_ID


def test_unresolved_devices_are_left_empty(session_factory) -> None:
    """A finding with no device identity yields an alert with none (M11.15)."""
    service = make_service(session_factory)
    outcome = service.process_finding(make_finding())

    assert outcome.alert is not None
    assert outcome.alert.source_device_id is None
    assert outcome.alert.destination_device_id is None


# -- connection association (M11.14) ----------------------------------------


def test_related_connection_becomes_evidence(session_factory) -> None:
    """A conversation the resolver finds is attached as connection evidence."""
    connection = FakeConnection(connection_id="conn-42")
    resolvers = make_resolvers(
        connection_source=FakeConnectionSource([connection])
    )
    service = make_service(session_factory, resolvers=resolvers)
    outcome = service.process_finding(make_finding())
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = AlertQueries(session_factory=session_factory).get_detail(
        outcome.alert.alert_id
    )
    assert detail is not None
    connection_records = [
        record for record in detail.evidence if record.evidence_type == "connection"
    ]
    assert len(connection_records) == 1
    assert "conn-42" in connection_records[0].evidence_data


# -- service construction ---------------------------------------------------


def test_max_evidence_must_be_positive(session_factory) -> None:
    """A zero evidence cap is rejected at construction, not silently ignored."""
    with pytest.raises(ValueError):
        make_service(session_factory, max_evidence=0)


def test_counters_record_created_and_unsupported_findings(session_factory) -> None:
    """The service counts what it did, for the diagnostics endpoint (M11.31)."""
    service = make_service(session_factory)
    service.process_finding(make_finding())
    service.process_finding(make_finding(rule_id="nope", rule_name="Nope"))

    counters = service.get_counters()
    assert counters.findings_seen == 2
    assert counters.alerts_created == 1
    assert counters.unsupported_findings == 1
