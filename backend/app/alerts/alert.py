"""The runtime alert: the normalized representation the rest of M11 works on (M11.3).

An alert is a *conclusion*, not an observation. Where an M10 finding says "this
is what the packets showed", an alert says "this behaviour is worth a human's
attention, at this severity, and here is why". The difference shows in the
fields: severity, confidence, lifecycle status, the endpoints the incident
concerns, and a link back to the finding that justified it.

Everything here is a **value**: the model is frozen, so an alert is never
mutated in place. A lifecycle change produces an updated copy through
:meth:`Alert.with_status`, which is what keeps the validation in
:mod:`app.alerts.status` from being bypassed by an assignment.

Three deliberate properties (M11.3, M11.5, M11.12):

* **``evidence_count`` is derived, never assigned by a detector.** It is the
  number of evidence rows the alert actually has, and the service computes it
  from the persisted evidence. A detector cannot inflate it.
* **``confidence`` is a 0..1 float**, the value M10 measured, and it is stored
  *separately* from severity. It is rounded to the integer percent the M2 column
  holds only at the persistence boundary.
* **``risk_score`` does not exist here.** Risk needs the historical context M12
  owns; M11 states severity and confidence and nothing more.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from app.alerts.severity import AlertSeverity
from app.alerts.status import (
    AlertStatus,
    from_stored_value,
    from_value,
    is_terminal,
    validate_transition,
)

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from app.models.alert import Alert as AlertRow

#: Separator and absent-value marker of the deduplication key (M11.9). Repeated
#: here rather than imported so this module has no dependency on the key builder.
_KEY_SEPARATOR = "|"
_ABSENT_COMPONENT = "-"


class Alert(BaseModel):
    """One alert, as the engine and the API model it (M11.3).

    Attributes:
        rule_id: Stable detector identifier the alert came from, e.g.
            ``port_scan``. This is the *string* rule id a finding carries, not
            the ``detection_rules`` foreign key.
        title: Short alert title, taken from the rule's mapping (M11.8).
        description: The detector's own account of what it observed.
        severity: How serious the behaviour is (M11.4). Fixed per rule.
        confidence: 0..1 strength of the evidence (M11.5), from the finding.
        status: Lifecycle state (M11.6).
        alert_id: Database primary key. ``None`` until the alert is persisted.
        created_at: When the underlying behaviour was observed, as naive UTC.
        updated_at: When the alert was last modified, as naive UTC.
        resolved_at: When the alert reached a terminal state, as naive UTC
            (M11.20). ``None`` while it is still open or acknowledged.
        source_ip / destination_ip: The endpoints the incident concerns.
        source_device_id / destination_device_id: M8 device identities, when the
            addresses resolved to a known device.
        protocol: Transport protocol the observation concerns.
        connection_id: M9 conversation reference, when one was resolved.
        finding_id: The M10 finding that raised this alert (M11.7) — the trail
            back to the raw observation.
        evidence_count: How many evidence records the alert carries (M11.12).
        correlation_key: The deduplication key this alert was raised under
            (M11.9), which is what makes a later observation find it again.
    """

    model_config = ConfigDict(frozen=True)

    rule_id: str
    title: str
    description: str = ""
    severity: AlertSeverity
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    status: AlertStatus = AlertStatus.OPEN

    alert_id: int | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    resolved_at: datetime | None = None

    source_ip: str | None = None
    destination_ip: str | None = None
    source_device_id: str | None = None
    destination_device_id: str | None = None
    protocol: str | None = None
    connection_id: str | None = None
    finding_id: str | None = None
    evidence_count: int = Field(default=0, ge=0)
    correlation_key: str | None = None

    @property
    def is_open(self) -> bool:
        """Return True while the alert still needs attention (M11.6)."""
        return self.status is AlertStatus.OPEN

    @property
    def is_terminal(self) -> bool:
        """Return True once no further lifecycle move is possible (M11.19)."""
        return is_terminal(self.status)

    def with_status(
        self, status: AlertStatus | str, *, updated_at: datetime | None = None
    ) -> "Alert":
        """Return a copy of this alert in a new lifecycle state (M11.19).

        Raises:
            ValueError: If ``status`` is not one of the five M11 states.
            InvalidStatusTransition: If the move is not allowed. The check lives
                in :mod:`app.alerts.status`, so the transition table is applied
                in exactly one place whether the caller goes through the service
                or builds a copy directly.
        """
        target = from_value(status)
        validate_transition(self.status, target)
        update: dict[str, object] = {"status": target}
        if updated_at is not None:
            update["updated_at"] = updated_at
            if is_terminal(target):
                # A terminal state is the moment the alert was closed, so the
                # M2 ``resolved_at`` column is filled from the same clock
                # reading as ``updated_at`` (M11.20).
                update["resolved_at"] = updated_at
        return self.model_copy(update=update)

    def with_evidence_count(self, evidence_count: int) -> "Alert":
        """Return a copy carrying a freshly counted evidence total (M11.12)."""
        return self.model_copy(update={"evidence_count": max(int(evidence_count), 0)})

    @classmethod
    def from_record(
        cls,
        record: "AlertRow",
        *,
        evidence_count: int | None = None,
    ) -> "Alert":
        """Build the runtime alert from a persisted ``alerts`` row.

        Args:
            record: The ORM row.
            evidence_count: Number of evidence rows, when the caller already
                counted them. ``None`` means "not counted", and the model reports
                ``0`` rather than guessing.

        Returns:
            The runtime representation of the row. The status passes through the
            M11 translation, so a legacy M2 value is read as its M11 equivalent
            (M11.6), and ``confidence`` comes back as the 0..1 float the column's
            integer percent represents.
        """
        return cls(
            alert_id=record.id,
            rule_id=_component(record.correlation_key, 0) or "",
            title=record.title,
            description=record.description or "",
            severity=AlertSeverity(record.severity),
            confidence=int(record.confidence or 0) / 100.0,
            status=from_stored_value(record.status),
            created_at=record.created_at,
            updated_at=record.updated_at,
            resolved_at=record.resolved_at,
            source_ip=record.source_ip,
            destination_ip=record.destination_ip,
            protocol=_component(record.correlation_key, 3),
            connection_id=_component(record.correlation_key, 5),
            evidence_count=max(int(evidence_count or 0), 0),
            correlation_key=record.correlation_key,
        )


def _component(correlation_key: str | None, index: int) -> str | None:
    """Return one component of a stored deduplication key, or ``None``.

    The key is the deduplication key (M11.9), joined in a fixed order, so the
    detector rule id is its leading component and the protocol and connection
    follow at known positions. Reading them back is how a persisted row recovers
    facts the M2 ``alerts`` table has no dedicated column for — the key is the
    record of them, and this is the single place that decodes it.

    Returns ``None`` for a missing key, a component index the key is too short to
    have, or a component rendered as ``-`` (the key builder's marker for an
    unknown value).
    """
    if not correlation_key:
        return None
    parts = correlation_key.split(_KEY_SEPARATOR)
    if index >= len(parts):
        return None
    value = parts[index]
    return None if value == _ABSENT_COMPONENT else value
