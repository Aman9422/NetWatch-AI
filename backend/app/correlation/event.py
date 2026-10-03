"""The normalized correlation input (M12.3).

A correlation engine should not have to know that findings and alerts are
different shapes. It should be handed one thing — an *event* — and reason about
that. This module is that one thing.

M12.3 lists what a correlation event may carry, and the list is deliberately
narrow:

* the originating ``DetectionFinding`` or ``Alert``, by identifier
* connection, device and packet *references*
* a timestamp
* structured metadata

and it is equally explicit about what it may **not** carry: "Do not copy complete
packet data into the correlation layer." A correlation event therefore holds
identities, addresses, a protocol and a confidence — not payloads, not byte
counts, not packet rows. A packet is referenced by the finding that saw it, and
the finding is referenced by id, so the trail back to the raw observation stays
walkable without the correlation layer holding a copy of it.

One conversion is worth calling out. A detection finding is timed in **epoch
seconds** while an alert is timed in a **naive UTC datetime** (M11.3).
Correlation thinks in one timeline, so both are normalised to epoch seconds here,
through the M11 converters rather than by a second, private implementation of the
same arithmetic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from app.alerts.severity import AlertSeverity, from_value
from app.alerts.timestamps import to_epoch_seconds
from app.risk.inputs import bounded_confidence

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from app.alerts.alert import Alert
    from app.detection.finding import DetectionFinding

#: Prefix identifying an event that came from a detection finding.
FINDING_EVENT_PREFIX = "fnd:"

#: Prefix identifying an event that came from an alert.
ALERT_EVENT_PREFIX = "alert:"


class EventKind(str, Enum):
    """Where a correlation event came from (M12.3)."""

    FINDING = "finding"
    ALERT = "alert"


@dataclass(frozen=True)
class CorrelationEvent:
    """One normalized thing that can be correlated (M12.3).

    Attributes:
        event_id: Stable identity of the event, used for deduplication (M12.11).
            ``fnd:<finding_id>`` for a finding and ``alert:<alert_id>`` for a
            persisted alert.
        kind: Whether this came from a finding or an alert.
        timestamp: Observation time in epoch seconds. Both source types are
            converted onto this one timeline.
        rule_id: The detector's string rule id, e.g. ``port_scan``.
        title: Short human-readable label, used to title a new incident.
        description: The source's own account of what it observed.
        severity: Alert severity. ``None`` for a finding: M10 findings carry no
            severity by design, and correlation must not invent one (M12.15).
        confidence: The source's own evidence confidence in ``[0, 1]`` — alert or
            finding confidence, never a risk score (M12.16).
        source_ip / destination_ip: The endpoints the event concerns.
        source_device_id / destination_device_id: M8 device identities, when the
            addresses resolved to a known device.
        protocol: Transport protocol concerned.
        connection_id: M9 conversation reference, when one was resolved. A
            finding does not carry one, so it is present here only when the
            caller supplied it.
        alert_id: Database primary key of the originating alert, when there is
            one.
        finding_id: The M10 finding this event descends from.
        correlation_key: The M11 deduplication key the alert was raised under, so
            a correlation reason can name the exact incident the alert belonged
            to.
        metadata: Supplementary string facts, for reasons and diagnostics. Not a
            place for packet data (M12.3).
    """

    event_id: str
    kind: EventKind
    timestamp: float
    rule_id: str
    title: str = ""
    description: str = ""
    severity: AlertSeverity | str | None = None
    confidence: float = 0.0
    source_ip: str | None = None
    destination_ip: str | None = None
    source_device_id: str | None = None
    destination_device_id: str | None = None
    protocol: str | None = None
    connection_id: str | None = None
    alert_id: int | None = None
    finding_id: str | None = None
    correlation_key: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Reject an unusable identity and validate a supplied severity.

        Raises:
            ValueError: If ``event_id`` or ``rule_id`` is empty, or if
                ``severity`` is set but is not one of the four alert levels.
                Both are needed for deduplication and for correlation reasons,
                and a blank one would silently produce key mismatches rather
                than an error.
        """
        if not str(self.event_id).strip():
            raise ValueError("A correlation event must have an event_id")
        if not str(self.rule_id).strip():
            raise ValueError("A correlation event must name a rule")
        if self.severity is not None:
            from_value(self.severity)

    # -- derived views ------------------------------------------------------

    @property
    def normalized_confidence(self) -> float:
        """Return the confidence clamped to ``[0, 1]`` (M12.16/M12.21)."""
        return bounded_confidence(self.confidence)

    @property
    def normalized_severity(self) -> AlertSeverity | None:
        """Return the severity as an enum, or ``None`` for a finding."""
        if self.severity is None:
            return None
        return from_value(self.severity)

    def device_ids(self) -> frozenset[str]:
        """Return the device identities this event resolved, at either end."""
        return frozenset(
            device
            for device in (self.source_device_id, self.destination_device_id)
            if device
        )

    def source_identity(self) -> str | None:
        """Return the most specific source identity available.

        A resolved device identity is preferred over the raw address: two
        addresses belonging to one device are one actor, and correlating them by
        device is the point of M12.6's ``same_source``. The address is the
        fallback, so an event with no resolved device is still groupable.
        """
        return self.source_device_id or self.source_ip

    def destination_identity(self) -> str | None:
        """Return the most specific destination identity available."""
        return self.destination_device_id or self.destination_ip

    @property
    def is_alert(self) -> bool:
        """Return True when this event came from an alert."""
        return self.kind is EventKind.ALERT

    @property
    def is_finding(self) -> bool:
        """Return True when this event came from a detection finding."""
        return self.kind is EventKind.FINDING

    def sort_key(self) -> tuple[float, str]:
        """Return a deterministic ordering key: by time, then by identity."""
        return (float(self.timestamp), str(self.event_id))

    def reason_label(self) -> str:
        """Return a short label naming this event, for incident reasons."""
        return f"{self.kind.value}:{self.rule_id}"


def finding_event_id(finding_id: str) -> str:
    """Return the event id for a detection finding identifier."""
    return f"{FINDING_EVENT_PREFIX}{finding_id}"


def alert_event_id(alert_id: int) -> str:
    """Return the event id for a persisted alert identifier."""
    return f"{ALERT_EVENT_PREFIX}{int(alert_id)}"


def _fallback_alert_event_id(
    *, rule_id: str, timestamp: float, finding_id: str | None
) -> str:
    """Return an event id for an alert that has not been persisted.

    A runtime alert built by a caller or a test may have no database id yet.
    Falling back to its finding keeps the identity stable across a re-run, and
    the final fallback — rule and timestamp — is deterministic rather than
    random, so two identical observations still deduplicate (M12.11).
    """
    if finding_id:
        return f"{ALERT_EVENT_PREFIX}{finding_id}"
    return f"{ALERT_EVENT_PREFIX}{rule_id}@{float(timestamp):.6f}"


def from_finding(
    finding: "DetectionFinding",
    *,
    connection_id: str | None = None,
) -> CorrelationEvent:
    """Build a correlation event from an M10 finding (M12.3).

    Args:
        finding: The detection finding to normalise.
        connection_id: An optional M9 conversation reference. M10 findings carry
            no connection — exactly as M11's deduplication key notes — so this
            is supplied only when the caller resolved one for the finding.

    Returns:
        The normalized event. Severity is ``None``: a finding states confidence
        and evidence, never severity, and correlation does not invent one.
    """
    return CorrelationEvent(
        event_id=finding_event_id(str(finding.finding_id)),
        kind=EventKind.FINDING,
        timestamp=float(finding.timestamp),
        rule_id=str(finding.rule_id),
        title=str(finding.rule_name or finding.rule_id),
        description=str(finding.description or ""),
        severity=None,
        confidence=float(finding.confidence),
        source_ip=finding.source_ip,
        destination_ip=finding.destination_ip,
        source_device_id=finding.source_device_id,
        destination_device_id=finding.destination_device_id,
        protocol=finding.protocol,
        connection_id=connection_id,
        alert_id=None,
        finding_id=str(finding.finding_id),
        correlation_key=None,
    )


def from_alert(
    alert: "Alert",
    *,
    timestamp: float | None = None,
) -> CorrelationEvent:
    """Build a correlation event from an M11 alert (M12.3).

    Args:
        alert: The runtime alert to normalise.
        timestamp: Epoch seconds to date the event. Defaults to the alert's own
            ``created_at``, converted from the naive UTC datetime M11 stores.

    Raises:
        ValueError: If the event cannot be timed — the alert has no
            ``created_at`` and none was supplied. Correlation is fundamentally
            about time, so an untimed event is a caller error rather than
            something to guess at. The engine catches this per event, so a
            single unusable alert cannot stop alert processing (M12.25).
    """
    if timestamp is None:
        observed = to_epoch_seconds(alert.created_at)
    else:
        observed = float(timestamp)
    if observed is None:
        raise ValueError(
            "Cannot correlate an alert without an observation time "
            "(created_at is unset and no timestamp was supplied)"
        )

    alert_id = alert.alert_id
    event_id = (
        alert_event_id(int(alert_id))
        if alert_id is not None
        else _fallback_alert_event_id(
            rule_id=str(alert.rule_id),
            timestamp=observed,
            finding_id=alert.finding_id,
        )
    )

    return CorrelationEvent(
        event_id=event_id,
        kind=EventKind.ALERT,
        timestamp=observed,
        rule_id=str(alert.rule_id),
        title=str(alert.title or alert.rule_id),
        description=str(alert.description or ""),
        severity=alert.severity,
        confidence=float(alert.confidence),
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        source_device_id=alert.source_device_id,
        destination_device_id=alert.destination_device_id,
        protocol=alert.protocol,
        connection_id=alert.connection_id,
        alert_id=int(alert_id) if alert_id is not None else None,
        finding_id=alert.finding_id,
        correlation_key=alert.correlation_key,
    )


__all__ = [
    "ALERT_EVENT_PREFIX",
    "CorrelationEvent",
    "EventKind",
    "FINDING_EVENT_PREFIX",
    "alert_event_id",
    "finding_event_id",
    "from_alert",
    "from_finding",
]
