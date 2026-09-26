"""Tests for the alert lifecycle and its validation (M11.28).

The lifecycle is only meaningful if it is *enforced*: an alert that can be talked
back out of ``resolved`` has no lifecycle at all (M11.19). These tests walk every
allowed edge, every rejected edge, and the two things a transition has to record
— ``updated_at`` always, and ``resolved_at`` when the move ends the alert
(M11.20).

Both the service path (``AlertService.set_status``) and the model path
(``Alert.with_status``) are exercised, because the service delegates its
validation to the model and a gap in either would be a gap in the guarantee.
"""

from __future__ import annotations

import pytest

from app.alerts.alert import Alert
from app.alerts.queries import AlertQueries
from app.alerts.severity import AlertSeverity
from app.alerts.status import (
    AlertStatus,
    InvalidStatusTransition,
    allowed_targets,
    is_terminal,
    is_valid_transition,
    validate_transition,
)
from app.alerts.timestamps import to_utc_datetime
from tests.alert_fakes import ALERT_BASE_TIME, make_finding, make_service

LATER = ALERT_BASE_TIME + 60.0


def _create_alert(service, *, timestamp: float = ALERT_BASE_TIME) -> int:
    """Create one alert and return its id."""
    outcome = service.process_finding(make_finding(timestamp=timestamp))
    assert outcome.created is True
    assert outcome.alert is not None
    assert outcome.alert.alert_id is not None
    return outcome.alert.alert_id


def _runtime_alert(**overrides: object) -> Alert:
    """Build a runtime alert of a given status, for the pure transition cases."""
    values: dict[str, object] = {
        "rule_id": "port_scan",
        "title": "Port Scan",
        "severity": AlertSeverity.HIGH,
        "status": AlertStatus.OPEN,
    }
    values.update(overrides)
    return Alert(**values)  # type: ignore[arg-type]


def _status_of(session_factory, alert_id: int) -> AlertStatus:
    """Return the stored status of an alert."""
    stored = AlertQueries(session_factory=session_factory).get_alert(alert_id)
    assert stored is not None
    return stored.status


# -- allowed transitions (M11.19) -------------------------------------------


@pytest.mark.parametrize(
    ("start", "target"),
    [
        ("open", "acknowledged"),
        ("open", "resolved"),
        ("open", "dismissed"),
        ("open", "false_positive"),
    ],
)
def test_moves_out_of_open_are_allowed(
    session_factory, start: str, target: str
) -> None:
    """Every documented move out of ``open`` succeeds and is stored."""
    service = make_service(session_factory)
    alert_id = _create_alert(service)
    assert _status_of(session_factory, alert_id) is AlertStatus.OPEN

    updated = service.set_status(alert_id, target, updated_at=LATER)

    assert updated is not None
    assert updated.status is AlertStatus(target)
    assert _status_of(session_factory, alert_id) is AlertStatus(target)


@pytest.mark.parametrize(
    ("target"),
    ["resolved", "dismissed", "false_positive"],
)
def test_moves_out_of_acknowledged_are_allowed(
    session_factory, target: str
) -> None:
    """An acknowledged alert may be resolved, dismissed or marked false positive."""
    service = make_service(session_factory)
    alert_id = _create_alert(service)
    service.set_status(alert_id, "acknowledged", updated_at=LATER)

    updated = service.set_status(alert_id, target, updated_at=LATER + 1.0)

    assert updated is not None
    assert updated.status is AlertStatus(target)


def test_reacknowledging_is_a_no_op(session_factory) -> None:
    """Moving to the state an alert is already in changes nothing and is allowed."""
    service = make_service(session_factory)
    alert_id = _create_alert(service)
    service.set_status(alert_id, "acknowledged", updated_at=LATER)

    again = service.set_status(alert_id, "acknowledged", updated_at=LATER + 5.0)

    assert again is not None
    assert again.status is AlertStatus.ACKNOWLEDGED


# -- rejected transitions (M11.19) ------------------------------------------


@pytest.mark.parametrize(
    ("start", "target"),
    [
        ("resolved", "open"),
        ("resolved", "acknowledged"),
        ("resolved", "dismissed"),
        ("dismissed", "open"),
        ("dismissed", "acknowledged"),
        ("false_positive", "open"),
        ("false_positive", "resolved"),
    ],
)
def test_moves_out_of_a_terminal_state_are_rejected(
    session_factory, start: str, target: str
) -> None:
    """A closed alert cannot be reopened through the transition endpoint."""
    service = make_service(session_factory)
    alert_id = _create_alert(service)
    service.set_status(alert_id, start, updated_at=LATER)

    with pytest.raises(InvalidStatusTransition):
        service.set_status(alert_id, target, updated_at=LATER + 1.0)

    assert _status_of(session_factory, alert_id) is AlertStatus(start)


def test_a_rejected_transition_leaves_the_alert_untouched(session_factory) -> None:
    """Validation happens before the write, so a refused move changes nothing."""
    service = make_service(session_factory)
    alert_id = _create_alert(service)
    resolved = service.set_status(alert_id, "resolved", updated_at=LATER)
    assert resolved is not None and resolved.updated_at is not None
    stamp = resolved.updated_at

    with pytest.raises(InvalidStatusTransition):
        service.set_status(alert_id, "open", updated_at=LATER + 100.0)

    stored = AlertQueries(session_factory=session_factory).get_alert(alert_id)
    assert stored is not None
    assert stored.status is AlertStatus.RESOLVED
    assert stored.updated_at == stamp


def test_unknown_target_status_is_rejected(session_factory) -> None:
    """A status outside the five states is a ValueError, not a silent store."""
    service = make_service(session_factory)
    alert_id = _create_alert(service)

    with pytest.raises(ValueError):
        service.set_status(alert_id, "closed")


def test_set_status_on_a_missing_alert_returns_none(session_factory) -> None:
    """Moving a non-existent alert reports "not found" rather than raising."""
    service = make_service(session_factory)
    assert service.set_status(9999, "acknowledged") is None


# -- what a transition records (M11.20) -------------------------------------


def test_transition_stamps_updated_at(session_factory) -> None:
    """``updated_at`` is set from the supplied clock reading."""
    service = make_service(session_factory)
    alert_id = _create_alert(service)

    updated = service.set_status(alert_id, "acknowledged", updated_at=LATER)

    assert updated is not None
    # Compared as the naive-UTC datetime the column stores, not through
    # ``.timestamp()`` — which would read a naive value in the local timezone.
    assert updated.updated_at == to_utc_datetime(LATER)


def test_terminal_transition_stamps_resolved_at(session_factory) -> None:
    """A terminal move fills ``resolved_at`` from the same reading (M11.20)."""
    service = make_service(session_factory)
    alert_id = _create_alert(service)

    resolved = service.set_status(alert_id, "resolved", updated_at=LATER)

    assert resolved is not None
    assert resolved.resolved_at == to_utc_datetime(LATER)


def test_non_terminal_transition_leaves_resolved_at_unset(session_factory) -> None:
    """An acknowledged alert is not resolved, so ``resolved_at`` stays empty."""
    service = make_service(session_factory)
    alert_id = _create_alert(service)

    acked = service.set_status(alert_id, "acknowledged", updated_at=LATER)

    assert acked is not None
    assert acked.resolved_at is None


def test_terminal_status_is_reported_terminal(session_factory) -> None:
    """After a terminal move the alert reports itself terminal."""
    service = make_service(session_factory)
    alert_id = _create_alert(service)

    service.set_status(alert_id, "dismissed", updated_at=LATER)

    stored = AlertQueries(session_factory=session_factory).get_alert(alert_id)
    assert stored is not None
    assert stored.is_terminal is True
    assert stored.is_open is False


# -- the pure transition table (M11.19) -------------------------------------


def test_allowed_targets_are_ordered_and_complete() -> None:
    """``allowed_targets`` lists the reachable states in lifecycle order."""
    assert allowed_targets("open") == (
        "acknowledged",
        "resolved",
        "dismissed",
        "false_positive",
    )
    assert allowed_targets("acknowledged") == (
        "resolved",
        "dismissed",
        "false_positive",
    )
    assert allowed_targets("resolved") == ()


def test_is_terminal_matches_the_terminal_set() -> None:
    """Only resolved, dismissed and false_positive are terminal."""
    assert is_terminal("open") is False
    assert is_terminal("acknowledged") is False
    assert is_terminal("resolved") is True
    assert is_terminal("dismissed") is True
    assert is_terminal("false_positive") is True


def test_is_valid_transition_accepts_the_table_and_same_state() -> None:
    """A table edge and a same-state move are both valid; a closed move is not."""
    assert is_valid_transition("open", "resolved") is True
    assert is_valid_transition("open", "open") is True
    assert is_valid_transition("resolved", "open") is False


def test_validate_transition_reports_no_op_without_raising() -> None:
    """A same-state move validates as a no-op (``False``) rather than an error."""
    assert validate_transition(AlertStatus.OPEN, "open") is False
    assert validate_transition(AlertStatus.OPEN, "resolved") is True


def test_alert_with_status_validates_the_move() -> None:
    """The model's own copy constructor enforces the same table."""
    alert = _runtime_alert()

    moved = alert.with_status("resolved")

    assert moved.status is AlertStatus.RESOLVED
    with pytest.raises(InvalidStatusTransition):
        moved.with_status("open")


def test_alert_with_status_sets_resolved_at_for_a_terminal_state() -> None:
    """A terminal copy records when it closed."""
    alert = _runtime_alert()
    stamp = to_utc_datetime(LATER)

    moved = alert.with_status("resolved", updated_at=stamp)

    assert moved.resolved_at == stamp
    assert moved.updated_at == stamp
