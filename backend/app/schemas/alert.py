"""Read-only wire schemas for alerts (M11.18).

These models are how M11 exposes alerts over the API. The runtime representation
is :class:`app.alerts.alert.Alert`; this is its serializable projection plus its
evidence.

Two deliberate choices about how values cross the wire:

* **confidence is a 0..1 float**, not the integer percent the column stores. The
  column's percentage is a storage detail of the M2 schema; exposing it as 92
  rather than 0.92 would invite a client to read it as a risk score, which M11.5
  explicitly says it is not.
* **timestamps are ISO-8601 UTC**, matching devices, connections and findings, so
  every milestone's API renders time the same way.

There is **no risk field here**. Risk scoring belongs to M12 and M11 has no
opinion about it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from app.alerts.severity import AlertSeverity
from app.alerts.status import AlertStatus

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.alerts.alert import Alert
    from app.models.alert_evidence import AlertEvidence

#: JSON value an evidence document may decode to.
EvidenceValue = int | float | str | bool | None | dict[str, object] | list[object]


def to_iso_timestamp(value: datetime | None) -> str | None:
    """Render a naive-UTC datetime as an ISO-8601 UTC string, or ``None``.

    Alert rows store naive UTC datetimes, so the timezone is attached here rather
    than assumed by the client. This is the mirror of
    :func:`app.alerts.timestamps.to_epoch_seconds`.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


class AlertEvidenceView(BaseModel):
    """Serializable snapshot of one evidence record (M11.11).

    ``data`` is the parsed evidence document rather than the raw JSON string, so
    a client reads fields directly instead of parsing text itself. ``packet_id``
    is surfaced separately because it is a *reference* a client can follow
    (M11.13), not merely a field inside the document.
    """

    evidence_type: str
    packet_id: int | None = Field(
        default=None, description="Referenced packets.id, for packet evidence"
    )
    created_at: str | None = Field(default=None, description="ISO-8601 UTC")
    data: dict[str, EvidenceValue] = Field(default_factory=dict)

    @classmethod
    def from_record(cls, record: "AlertEvidence") -> "AlertEvidenceView":
        """Project an evidence row onto the wire model.

        A document that will not parse is returned as an empty mapping rather
        than raising: one malformed evidence row must not make an entire alert
        unreadable, which would hide the alert itself.
        """
        try:
            parsed = json.loads(record.evidence_data)
        except (TypeError, ValueError):
            parsed = None
        return cls(
            evidence_type=str(record.evidence_type),
            packet_id=record.packet_id,
            created_at=to_iso_timestamp(record.created_at),
            data=parsed if isinstance(parsed, dict) else {},
        )


class AlertView(BaseModel):
    """Serializable snapshot of one alert (M11.3/M11.18)."""

    alert_id: int
    rule_id: str = Field(
        description="Stable detector identifier, recovered from the deduplication key"
    )
    title: str
    description: str = ""
    severity: AlertSeverity
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Evidence strength (M11.5). Never a risk score.",
    )
    status: AlertStatus
    created_at: str | None = Field(default=None, description="ISO-8601 UTC")
    updated_at: str | None = Field(default=None, description="ISO-8601 UTC")
    resolved_at: str | None = Field(default=None, description="ISO-8601 UTC")
    source_ip: str | None = None
    destination_ip: str | None = None
    source_device_id: str | None = None
    destination_device_id: str | None = None
    protocol: str | None = None
    connection_id: str | None = None
    finding_id: str | None = Field(
        default=None, description="The M10 finding that raised this alert (M11.7)"
    )
    evidence_count: int = 0
    correlation_key: str | None = Field(
        default=None, description="The deduplication key of this incident (M11.9)"
    )

    @classmethod
    def from_alert(cls, alert: "Alert") -> "AlertView":
        """Project a runtime alert onto this wire model."""
        return cls(
            alert_id=int(alert.alert_id or 0),
            rule_id=alert.rule_id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity,
            confidence=alert.confidence,
            status=alert.status,
            created_at=to_iso_timestamp(alert.created_at),
            updated_at=to_iso_timestamp(alert.updated_at),
            resolved_at=to_iso_timestamp(alert.resolved_at),
            source_ip=alert.source_ip,
            destination_ip=alert.destination_ip,
            source_device_id=alert.source_device_id,
            destination_device_id=alert.destination_device_id,
            protocol=alert.protocol,
            connection_id=alert.connection_id,
            finding_id=alert.finding_id,
            evidence_count=alert.evidence_count,
            correlation_key=alert.correlation_key,
        )


class AlertListData(BaseModel):
    """Payload of the alert-collection endpoint (M11.18).

    ``total`` is the number of alerts matching the filters, not the size of this
    page, so a client can page through the whole result set.
    """

    count: int = 0
    total: int = 0
    limit: int = 100
    offset: int = 0
    alerts: list[AlertView] = Field(default_factory=list)


class AlertDetailData(BaseModel):
    """Payload of the alert-detail endpoint (M11.18)."""

    alert: AlertView
    evidence: list[AlertEvidenceView] = Field(default_factory=list)
    evidence_by_type: dict[str, int] = Field(
        default_factory=dict,
        description="Evidence count per type, so an alert can be described at a glance",
    )


class AlertLifecycleRequest(BaseModel):
    """Body of the alert lifecycle endpoint (M11.19).

    Only the target status is accepted. The transition itself is validated
    against the lifecycle table in ``app.alerts.status`` — this model deliberately
    cannot express an *invalid* move as a distinct outcome, because doing so
    would duplicate the validation the agent of record already performs.
    """

    status: AlertStatus = Field(description="The lifecycle state to move to")


class AlertDiagnosticsData(BaseModel):
    """Payload of the alert diagnostics endpoint (M11.31)."""

    enabled: bool = True
    findings_seen: int = 0
    alerts_created: int = 0
    duplicates_folded: int = 0
    unsupported_findings: int = 0
    errors: int = 0
    transitions: int = 0
    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
