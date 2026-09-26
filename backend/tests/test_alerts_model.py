"""Tests for the runtime alert model and the rules that define its values (M11.25).

An alert is a *conclusion*, so these tests pin the things that make it one: the
severity vocabulary (M11.4), the preserved confidence (M11.5), the lifecycle
state (M11.6), the mapping that decides a rule's severity (M11.8), the
deduplication key's shape (M11.9) and the epoch/datetime and float/percent
boundaries the runtime model crosses (M11.3).

Nothing here touches a database. ``from_record`` is exercised against a
hand-built ORM row, which is enough to prove the projection: what it reads back
out of a stored row is exactly what was written into it.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from app.alerts.alert import Alert
from app.alerts.dedup import ABSENT_COMPONENT, KEY_SEPARATOR, DeduplicationKey
from app.alerts.mapping import (
    RULE_MAPPINGS,
    SUPPORTED_RULE_IDS,
    is_alertable_rule,
    mapping_for_rule,
)
from app.alerts.persistence import confidence_to_percent, to_alert_row_values
from app.alerts.severity import (
    SEVERITY_VALUES,
    AlertSeverity,
    at_least,
    rank,
    values_at_or_above,
)
from app.alerts.status import (
    ACTIVE_STATUSES,
    STATUS_VALUES,
    TERMINAL_STATUSES,
    AlertStatus,
    is_terminal,
)
from app.alerts.timestamps import to_iso_timestamp, to_utc_datetime
from app.models.alert import Alert as AlertRow

OBSERVED_AT = datetime(2026, 1, 1, 12, 0, 0)


def make_alert(**overrides: object) -> Alert:
    """Build a valid runtime alert, overriding individual fields."""
    values: dict[str, object] = {
        "rule_id": "port_scan",
        "title": "Port Scan",
        "description": "Possible port scan detected",
        "severity": AlertSeverity.HIGH,
        "confidence": 0.9,
        "created_at": OBSERVED_AT,
    }
    values.update(overrides)
    return Alert(**values)  # type: ignore[arg-type]


def make_row(**overrides: object) -> AlertRow:
    """Build an ``alerts`` ORM row without a session, for projection tests."""
    values: dict[str, object] = {
        "id": 7,
        "rule_id": None,
        "device_id": None,
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "title": "Port Scan",
        "description": "Possible port scan detected",
        "severity": "high",
        "risk_score": 0,
        "confidence": 90,
        "status": "open",
        "correlation_key": "port_scan|192.168.1.10|8.8.8.8|TCP|-|-",
        "resolved_at": None,
        "created_at": OBSERVED_AT,
        "updated_at": OBSERVED_AT,
    }
    values.update(overrides)
    return AlertRow(**values)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Construction and required fields (M11.3)
# ---------------------------------------------------------------------------


def test_alert_accepts_the_documented_fields() -> None:
    """An alert can be built from the fields M11.3 lists."""
    alert = make_alert(
        source_ip="192.168.1.10",
        destination_ip="8.8.8.8",
        source_device_id="mac:AA:BB:CC:DD:EE:FF",
        destination_device_id=None,
        protocol="TCP",
        connection_id=None,
        finding_id="fnd-abc",
    )
    assert alert.rule_id == "port_scan"
    assert alert.severity is AlertSeverity.HIGH
    assert alert.confidence == 0.9
    assert alert.source_ip == "192.168.1.10"
    assert alert.protocol == "TCP"
    assert alert.finding_id == "fnd-abc"


def test_alert_has_no_risk_score_field() -> None:
    """Risk scoring is M12's; the model must not carry a risk field (M11.5)."""
    assert "risk_score" not in Alert.model_fields


def test_alert_id_and_evidence_count_default() -> None:
    """A freshly built alert is unpersisted and carries no evidence yet."""
    alert = make_alert()
    assert alert.alert_id is None
    assert alert.evidence_count == 0


def test_alert_is_frozen() -> None:
    """An alert is a value, so it is never mutated in place (M11.3)."""
    alert = make_alert()
    with pytest.raises(ValidationError):
        alert.severity = AlertSeverity.LOW  # type: ignore[misc]


def test_missing_rule_id_is_rejected() -> None:
    """A rule id is required: an alert with no detector is meaningless."""
    with pytest.raises(ValidationError):
        Alert(title="x", severity=AlertSeverity.HIGH)  # type: ignore[call-arg]


def test_missing_title_is_rejected() -> None:
    """A title is required so every alert is human-readable."""
    with pytest.raises(ValidationError):
        Alert(rule_id="port_scan", severity=AlertSeverity.HIGH)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Severity (M11.4)
# ---------------------------------------------------------------------------


def test_severity_values_are_the_four_levels() -> None:
    """The severity vocabulary is exactly low/medium/high/critical (M11.4)."""
    assert SEVERITY_VALUES == ("low", "medium", "high", "critical")


def test_severity_ranks_are_ordered() -> None:
    """Severity ranks rise from low to critical, with no ties."""
    ranks = [rank(value) for value in SEVERITY_VALUES]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks)


def test_at_least_compares_severities() -> None:
    """``at_least`` is inclusive of the threshold."""
    assert at_least("critical", "high") is True
    assert at_least("high", "high") is True
    assert at_least("medium", "high") is False


def test_values_at_or_above_returns_the_superset() -> None:
    """A threshold yields every severity at or above it."""
    assert values_at_or_above("high") == ("high", "critical")
    assert values_at_or_above("low") == SEVERITY_VALUES


def test_unknown_severity_is_rejected() -> None:
    """An unknown severity fails loudly rather than degrading to low (M11.4)."""
    with pytest.raises(ValueError):
        rank("catastrophic")


def test_alert_rejects_an_unknown_severity() -> None:
    """The model validates its severity against the vocabulary."""
    with pytest.raises(ValidationError):
        make_alert(severity="catastrophic")


# ---------------------------------------------------------------------------
# Confidence (M11.5)
# ---------------------------------------------------------------------------


def test_confidence_is_bounded_to_zero_and_one() -> None:
    """Confidence is a 0..1 strength, never a percentage (M11.5)."""
    with pytest.raises(ValidationError):
        make_alert(confidence=1.5)
    with pytest.raises(ValidationError):
        make_alert(confidence=-0.1)


def test_confidence_and_severity_are_separate() -> None:
    """A high severity with a low confidence is a valid, meaningful alert."""
    alert = make_alert(severity=AlertSeverity.HIGH, confidence=0.51)
    assert alert.severity is AlertSeverity.HIGH
    assert alert.confidence == 0.51


def test_confidence_to_percent_rounds_to_the_nearest_integer() -> None:
    """The M2 column stores an integer percent; rounding avoids a bias (M11.12)."""
    assert confidence_to_percent(0.923) == 92
    assert confidence_to_percent(0.926) == 93
    assert confidence_to_percent(0.0) == 0
    assert confidence_to_percent(1.0) == 100


def test_confidence_to_percent_at_the_half_is_not_always_rounded_up() -> None:
    """An exact half is resolved by ``round`` rather than always rounded up.

    ``0.925 * 100`` is ``92.4999...`` in binary floating point, so the value
    rounds down to 92. This is stated explicitly rather than left implicit: the
    percent column is lossy by design (M11.12), and a caller must not expect
    half-up rounding from it.
    """
    assert confidence_to_percent(0.925) == 92


def test_confidence_to_percent_clamps_out_of_range_values() -> None:
    """A mapping must never let a bad value reach the column's CHECK."""
    assert confidence_to_percent(2.0) == 100
    assert confidence_to_percent(-1.0) == 0


# ---------------------------------------------------------------------------
# Status (M11.6)
# ---------------------------------------------------------------------------


def test_status_values_are_the_five_states() -> None:
    """The lifecycle has exactly the five states M11.6 defines."""
    assert STATUS_VALUES == (
        "open",
        "acknowledged",
        "resolved",
        "dismissed",
        "false_positive",
    )


def test_active_and_terminal_partition_the_statuses() -> None:
    """Every status is either active or terminal, never both."""
    assert ACTIVE_STATUSES | TERMINAL_STATUSES == set(STATUS_VALUES)
    assert ACTIVE_STATUSES & TERMINAL_STATUSES == set()


def test_alert_starts_open() -> None:
    """A new alert is open and needs attention (M11.6)."""
    alert = make_alert()
    assert alert.status is AlertStatus.OPEN
    assert alert.is_open is True
    assert alert.is_terminal is False


def test_terminal_status_is_recognised() -> None:
    """A resolved alert reports itself terminal (M11.19)."""
    assert is_terminal("resolved") is True
    assert is_terminal("open") is False


# ---------------------------------------------------------------------------
# Mapping (M11.8)
# ---------------------------------------------------------------------------


def test_mapping_covers_exactly_the_implemented_detectors() -> None:
    """The table lists the five M10 detectors and nothing that does not exist."""
    assert set(SUPPORTED_RULE_IDS) == {
        "port_scan",
        "syn_flood",
        "icmp_flood",
        "internal_scan",
        "high_bandwidth",
    }


@pytest.mark.parametrize(
    ("rule_id", "title", "severity"),
    [
        ("port_scan", "Port Scan", AlertSeverity.HIGH),
        ("syn_flood", "SYN Flood", AlertSeverity.CRITICAL),
        ("icmp_flood", "ICMP Flood", AlertSeverity.MEDIUM),
        ("internal_scan", "Internal Scan", AlertSeverity.HIGH),
        ("high_bandwidth", "High Bandwidth", AlertSeverity.HIGH),
    ],
)
def test_each_rule_maps_to_its_documented_title_and_severity(
    rule_id: str, title: str, severity: AlertSeverity
) -> None:
    """The documented rule -> title/severity table is what the code implements."""
    mapping = mapping_for_rule(rule_id)
    assert mapping is not None
    assert mapping.title == title
    assert mapping.severity is severity


def test_unknown_rule_has_no_mapping() -> None:
    """An unrecognised finding is not alertable, and that is not an error (M11.8)."""
    assert mapping_for_rule("does_not_exist") is None
    assert is_alertable_rule("does_not_exist") is False


@pytest.mark.parametrize("rule_id", [None, "", "   "])
def test_absent_rule_has_no_mapping(rule_id: str | None) -> None:
    """A missing or blank rule id has no mapping."""
    assert mapping_for_rule(rule_id) is None
    assert is_alertable_rule(rule_id) is False


def test_mapping_titles_are_stable_and_distinct() -> None:
    """Titles are stable per rule, so alerts are groupable (M11.8)."""
    titles = [mapping.title for mapping in RULE_MAPPINGS.values()]
    assert len(titles) == len(set(titles))


# ---------------------------------------------------------------------------
# Deduplication key (M11.9)
# ---------------------------------------------------------------------------


def test_key_components_are_joined_in_a_documented_order() -> None:
    """The key is rule|source|destination|protocol|device|connection (M11.9)."""
    key = DeduplicationKey(
        rule_id="port_scan",
        source_ip="192.168.1.10",
        destination_ip="8.8.8.8",
        protocol="TCP",
        device_id="mac:AA:BB:CC:DD:EE:FF",
        connection_id="conn-1",
    )
    assert key.value() == KEY_SEPARATOR.join(
        ["port_scan", "192.168.1.10", "8.8.8.8", "TCP", "mac:AA:BB:CC:DD:EE:FF", "conn-1"]
    )


def test_absent_components_render_as_the_placeholder() -> None:
    """A missing component is rendered as ``-`` so the key keeps its shape."""
    key = DeduplicationKey(rule_id="port_scan")
    assert key.value() == KEY_SEPARATOR.join(
        ["port_scan", ABSENT_COMPONENT, ABSENT_COMPONENT, ABSENT_COMPONENT, ABSENT_COMPONENT, ABSENT_COMPONENT]
    )


def test_key_prefers_the_source_device() -> None:
    """When both ends resolve, the source device is the single device component."""
    from app.detection.finding import DetectionFinding

    finding = DetectionFinding(
        rule_id="port_scan",
        rule_name="Port Scan",
        timestamp=1.0,
        source_ip="192.168.1.10",
        source_device_id="mac:SRC",
        destination_device_id="mac:DST",
        description="scan",
    )
    key = DeduplicationKey.from_finding(finding)
    assert key.components()["device_id"] == "mac:SRC"


def test_finding_without_a_rule_cannot_be_deduplicated() -> None:
    """A key for a finding with no rule is a programming error, not a fallback."""
    from app.detection.finding import DetectionFinding

    finding = DetectionFinding(
        rule_id="", rule_name="x", timestamp=1.0, description="x"
    )
    with pytest.raises(ValueError):
        DeduplicationKey.from_finding(finding)


# ---------------------------------------------------------------------------
# from_record projection (M11.3)
# ---------------------------------------------------------------------------


def test_from_record_recovers_the_detector_from_the_key() -> None:
    """The string rule id travels in the key when the row has no rule column."""
    alert = Alert.from_record(make_row(), evidence_count=3)
    assert alert.rule_id == "port_scan"
    assert alert.protocol == "TCP"
    assert alert.connection_id is None
    assert alert.evidence_count == 3


def test_from_record_restores_confidence_as_a_fraction() -> None:
    """An integer percent column reads back as the 0..1 confidence (M11.5)."""
    alert = Alert.from_record(make_row(confidence=92))
    assert alert.confidence == pytest.approx(0.92)


@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        ("open", AlertStatus.OPEN),
        ("acknowledged", AlertStatus.ACKNOWLEDGED),
        ("new", AlertStatus.OPEN),
        ("investigating", AlertStatus.ACKNOWLEDGED),
        ("resolved", AlertStatus.RESOLVED),
        ("dismissed", AlertStatus.DISMISSED),
        ("false_positive", AlertStatus.FALSE_POSITIVE),
    ],
)
def test_from_record_translates_legacy_status_names(
    stored: str, expected: AlertStatus
) -> None:
    """A pre-M11 row stays readable through the runtime translation (M11.6)."""
    alert = Alert.from_record(make_row(status=stored))
    assert alert.status is expected


def test_from_record_without_a_key_has_no_rule_id() -> None:
    """A row with no correlation key reports no detector rather than guessing."""
    alert = Alert.from_record(make_row(correlation_key=None))
    assert alert.rule_id == ""
    assert alert.protocol is None
    assert alert.connection_id is None


def test_from_record_reports_zero_evidence_when_uncounted() -> None:
    """An uncounted alert reports zero evidence, never a guess (M11.12)."""
    alert = Alert.from_record(make_row())
    assert alert.evidence_count == 0


# ---------------------------------------------------------------------------
# Persistence mapping (M11.3/M11.12)
# ---------------------------------------------------------------------------


def test_to_row_values_writes_an_explicit_risk_score_of_zero() -> None:
    """M11 does not score risk; the column is written as a deliberate 0 (M11.4)."""
    values = to_alert_row_values(make_alert())
    assert values["risk_score"] == 0


def test_to_row_values_writes_no_device_row() -> None:
    """M8 owns devices, so M11 invents no device foreign key (M11.15)."""
    values = to_alert_row_values(make_alert())
    assert values["device_id"] is None


def test_to_row_values_dates_the_alert_to_the_observation() -> None:
    """created_at/updated_at come from the observation, not the write (M11.3)."""
    values = to_alert_row_values(make_alert())
    assert values["created_at"] == OBSERVED_AT
    assert values["updated_at"] == OBSERVED_AT


def test_to_row_values_keeps_the_severity_and_status() -> None:
    """The stored strings are the model's own severity and status values."""
    values = to_alert_row_values(make_alert())
    assert values["severity"] == "high"
    assert values["status"] == "open"


def test_rule_row_id_is_passed_through_when_resolved() -> None:
    """The catalogue foreign key is whatever the caller resolved (M11.18)."""
    values = to_alert_row_values(make_alert(), rule_row_id=42)
    assert values["rule_id"] == 42


# ---------------------------------------------------------------------------
# Timestamp helpers (M11.3)
# ---------------------------------------------------------------------------


def test_epoch_round_trips_through_the_stored_datetime() -> None:
    """Epoch seconds -> naive UTC -> ISO-8601 is stable and lossless."""
    epoch = 1_767_268_800.0  # 2026-01-01T12:00:00Z
    stored = to_utc_datetime(epoch)
    assert stored == OBSERVED_AT
    assert to_iso_timestamp(stored) == "2026-01-01T12:00:00+00:00"


def test_iso_timestamp_of_none_is_none() -> None:
    """A missing timestamp stays missing on the wire."""
    assert to_iso_timestamp(None) is None
