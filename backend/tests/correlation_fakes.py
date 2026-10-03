"""Shared builders and doubles for the M12 correlation tests.

Correlation is reached from two directions — an M10 finding and an M11 alert —
and every test needs the same few things: a deterministic clock, a valid alert, a
valid event, and an engine wired to an isolated database. They live here so each
test file states only what is *different* about the behaviour it exercises.

Reusing :func:`tests.alert_fakes.make_finding` rather than copying it is
deliberate: the M12 tests are meant to consume the *real* M10 finding shape, and a
second private copy of it could drift away from the first.
"""

from __future__ import annotations

from typing import Any

from app.alerts.alert import Alert
from app.alerts.severity import AlertSeverity
from app.alerts.timestamps import to_utc_datetime
from app.correlation.engine import CorrelationEngine
from app.correlation.event import CorrelationEvent, EventKind, from_alert
from app.correlation.registry import IncidentRegistry
from app.correlation.window import CorrelationWindow
from app.risk.contributions import ScoringBounds
from app.risk.engine import RiskScoringEngine
from tests.alert_fakes import (  # noqa: F401 - re-exported for the M12 tests
    ALERT_BASE_TIME,
    DESTINATION_DEVICE_ID,
    DESTINATION_IP,
    OTHER_DESTINATION_IP,
    OTHER_SOURCE_IP,
    SOURCE_DEVICE_ID,
    SOURCE_IP,
    make_finding,
)

#: A fixed observation time, so every M12 test is deterministic.
CORRELATION_BASE_TIME = ALERT_BASE_TIME

#: A second source address and a second device, for "unrelated activity" tests.
THIRD_SOURCE_IP = "192.168.1.77"
THIRD_DEVICE_ID = "mac:99:99:99:99:99:99"

#: A connection reference, so `same_connection` can be exercised.
CONNECTION_ID = "conn-0001"
OTHER_CONNECTION_ID = "conn-0002"


class FixedClock:
    """A clock the test drives, so retention and recency are exact.

    Correlation expires context by age and scores recency by age, and both would
    otherwise need a real ``sleep`` to exercise. A clock the test advances makes
    the boundary exact — which is what the M12.29 boundary tests require.
    """

    def __init__(self, now: float = CORRELATION_BASE_TIME) -> None:
        self.now = float(now)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> float:
        """Move the clock forward by ``seconds`` and return the new time."""
        self.now += float(seconds)
        return self.now

    def set(self, value: float) -> None:
        """Set the clock to an absolute time."""
        self.now = float(value)


def make_alert(**overrides: Any) -> Alert:
    """Build a valid M11 alert, overriding individual fields.

    Defaults describe a high-severity port scan from one source to one
    destination, with both endpoints resolved to M8 devices — the shape most
    correlation tests want, because it gives every identity dimension a value.
    """
    values: dict[str, Any] = {
        "alert_id": 1,
        "rule_id": "port_scan",
        "title": "Port Scan",
        "description": "Possible port scan detected",
        "severity": AlertSeverity.HIGH,
        "confidence": 0.8,
        "created_at": to_utc_datetime(CORRELATION_BASE_TIME),
        "updated_at": to_utc_datetime(CORRELATION_BASE_TIME),
        "source_ip": SOURCE_IP,
        "destination_ip": DESTINATION_IP,
        "source_device_id": SOURCE_DEVICE_ID,
        "destination_device_id": DESTINATION_DEVICE_ID,
        "protocol": "TCP",
        "finding_id": "fnd-1",
        "correlation_key": "port_scan|192.168.1.10|8.8.8.8|-|-|-|-",
    }
    values.update(overrides)
    return Alert(**values)


def make_event(
    *, kind: EventKind = EventKind.ALERT, **overrides: Any
) -> CorrelationEvent:
    """Build a normalized correlation event, overriding individual fields."""
    values: dict[str, Any] = {
        "event_id": "alert:1",
        "kind": kind,
        "timestamp": CORRELATION_BASE_TIME,
        "rule_id": "port_scan",
        "title": "Port Scan",
        "description": "Possible port scan detected",
        "severity": AlertSeverity.HIGH if kind is EventKind.ALERT else None,
        "confidence": 0.8,
        "source_ip": SOURCE_IP,
        "destination_ip": DESTINATION_IP,
        "source_device_id": SOURCE_DEVICE_ID,
        "destination_device_id": DESTINATION_DEVICE_ID,
        "protocol": "TCP",
        "connection_id": None,
        "alert_id": 1 if kind is EventKind.ALERT else None,
        "finding_id": "fnd-1" if kind is EventKind.FINDING else None,
        "correlation_key": None,
    }
    values.update(overrides)
    return CorrelationEvent(**values)


def event_from_alert(alert: Alert, *, timestamp: float | None = None) -> CorrelationEvent:
    """Normalize an alert through the production converter."""
    return from_alert(alert, timestamp=timestamp)


def make_registry(
    clock: FixedClock | None = None,
    *,
    max_incidents: int = 1024,
    retention_seconds: float = 3600.0,
    seen_event_capacity: int = 4096,
    max_members: int = 64,
    max_reasons: int = 16,
) -> IncidentRegistry:
    """Build an incident store driven by a deterministic clock."""
    return IncidentRegistry(
        max_incidents=max_incidents,
        retention_seconds=retention_seconds,
        seen_event_capacity=seen_event_capacity,
        max_members=max_members,
        max_reasons=max_reasons,
        clock=clock if clock is not None else FixedClock(),
    )


def make_window(
    *,
    seconds: float = 900.0,
    proximity_seconds: float = 300.0,
    max_span_seconds: float | None = None,
) -> CorrelationWindow:
    """Build a bounded correlation window with explicit bounds."""
    return CorrelationWindow(
        seconds=seconds,
        proximity_seconds=proximity_seconds,
        max_span_seconds=max_span_seconds,
    )


def make_engine(
    *,
    clock: FixedClock | None = None,
    window: CorrelationWindow | None = None,
    registry: IncidentRegistry | None = None,
    risk: RiskScoringEngine | None = None,
    anchor_threshold: float = 0.55,
    min_confidence: float = 0.5,
    risk_persistence: Any | None = None,
    enabled: bool = True,
) -> CorrelationEngine:
    """Build a correlation engine over deterministic collaborators.

    The scorer is given bounds that keep the volume term meaningful for the small
    incidents the tests build, so a two-alert incident is not scored as if it
    were a single alert.
    """
    resolved_clock = clock if clock is not None else FixedClock()
    return CorrelationEngine(
        window=window if window is not None else make_window(),
        registry=registry if registry is not None else make_registry(resolved_clock),
        risk=(
            risk
            if risk is not None
            else RiskScoringEngine(ScoringBounds(volume_alerts=5))
        ),
        anchor_threshold=anchor_threshold,
        min_confidence=min_confidence,
        risk_persistence=risk_persistence,
        enabled=enabled,
        clock=resolved_clock,
    )


__all__ = [
    "ALERT_BASE_TIME",
    "CONNECTION_ID",
    "CORRELATION_BASE_TIME",
    "DESTINATION_DEVICE_ID",
    "DESTINATION_IP",
    "FixedClock",
    "OTHER_CONNECTION_ID",
    "OTHER_DESTINATION_IP",
    "OTHER_SOURCE_IP",
    "SOURCE_DEVICE_ID",
    "SOURCE_IP",
    "THIRD_DEVICE_ID",
    "THIRD_SOURCE_IP",
    "event_from_alert",
    "make_alert",
    "make_engine",
    "make_event",
    "make_finding",
    "make_registry",
    "make_window",
]
