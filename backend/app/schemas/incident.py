"""Read-only wire schemas for correlated incidents (M13.15/M13.27).

M12 already owns the serialization: ``CorrelatedIncident.as_dict()`` is the
detail shape and ``.summary()`` is the listing shape (M12.26). These models exist
so that shape is *declared* rather than implied, which is what lets FastAPI put
it in ``/openapi.json`` (M13.27) and what makes a missing or renamed field a
type error instead of a silent change in the JSON a client receives.

They therefore carry every field the M12 mappings produce and validate an
incident by way of them, rather than re-deriving any value. Three numbers stay
separate and are spelled out as such (M12.16):

* ``correlation_confidence`` — how strongly the events were judged related;
* ``alert_confidence`` — the mean of the member alerts' own evidence strengths;
* ``risk_score`` — the bounded ``0..100`` prioritisation metric, with
  ``risk_band`` its documented display band.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field, field_validator

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.correlation.incident import CorrelatedIncident


def as_iso_utc(value: str | None) -> str | None:
    """Render an ISO-8601 timestamp with an explicit UTC offset (M13.26).

    M12 serialises its datetimes with ``to_utc_datetime(...).isoformat()``, and
    that value is intentionally *naive* — it is what a SQLite ``DateTime`` column
    round-trips, which is what M12's own tests compare against (M12.26). It is
    the right internal form and the wrong wire form: ``2026-01-01T12:00:00`` does
    not tell an HTTP client which zone it is in, so two clients on two machines
    could read the same instant differently.

    A naive value is therefore read as UTC and re-rendered with the offset, giving
    the one documented format the rest of the M13 API already uses. The
    conversion happens here, at the boundary, so M12's serialization is left
    exactly as it is (M13.26). A value that cannot be parsed is passed through
    unchanged rather than discarded — losing a timestamp would be worse than
    formatting it oddly, and it cannot happen for a value M12 produced.
    """
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.isoformat()


class IncidentSummaryView(BaseModel):
    """One incident as a listing row (M12.26/M13.15).

    Carries the facts an operator scans — identity, lifecycle, counts, the two
    confidences and the score — without the member lists, which are what the
    detail view is for.
    """

    incident_id: str
    title: str = ""
    status: str = "open"
    start_time: float = 0.0
    last_seen: float = 0.0
    event_count: int = 0
    alert_count: int = 0
    finding_count: int = 0
    device_ids: list[str] = Field(default_factory=list)
    correlation_confidence: float = 0.0
    alert_confidence: float = 0.0
    severity: str | None = Field(
        default=None, description="Worst member severity, or None when unmeasured"
    )
    risk_score: int = 0
    risk_band: str = "minimal"

    @classmethod
    def from_incident(cls, incident: "CorrelatedIncident") -> "IncidentSummaryView":
        """Project an incident's summary mapping onto this model."""
        return cls.model_validate(incident.summary())


class IncidentView(BaseModel):
    """One incident with its full membership (M12.26/M13.15).

    Timestamps are present twice on purpose: as epoch seconds, which is what M12
    reasons in, and as ISO-8601 UTC strings, which is what a client displays
    (M13.26).
    """

    incident_id: str
    title: str = ""
    status: str = "open"
    created_at: float = 0.0
    updated_at: float = 0.0
    start_time: float = 0.0
    last_seen: float = 0.0
    created_at_iso: str | None = None
    updated_at_iso: str | None = None
    start_time_iso: str | None = None
    last_seen_iso: str | None = None
    span_seconds: float = 0.0
    event_count: int = 0
    dropped_events: int = Field(
        default=0,
        description="Events counted but not retained because a membership cap was reached (M12.22)",
    )
    alert_ids: list[int] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    device_ids: list[str] = Field(default_factory=list)
    connection_ids: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    correlation_rule_ids: list[str] = Field(default_factory=list)
    correlation_reasons: list[str] = Field(default_factory=list)
    correlation_confidence: float = 0.0
    alert_confidence: float = 0.0
    severity: str | None = None
    risk_score: int = 0
    risk_band: str = "minimal"

    @field_validator(
        "created_at_iso", "updated_at_iso", "start_time_iso", "last_seen_iso"
    )
    @classmethod
    def _timestamps_are_utc(cls, value: str | None) -> str | None:
        """Give every incident timestamp an explicit UTC offset (M13.26)."""
        return as_iso_utc(value)

    @classmethod
    def from_incident(cls, incident: "CorrelatedIncident") -> "IncidentView":
        """Project an incident's full mapping onto this model."""
        return cls.model_validate(incident.as_dict())


class IncidentListData(BaseModel):
    """Payload of the incident collection endpoints (M13.15/M13.24)."""

    count: int = 0
    limit: int | None = None
    offset: int = 0
    total: int | None = Field(
        default=None, description="Items matching overall, when countable"
    )
    has_more: bool | None = None
    incidents: list[IncidentSummaryView] = Field(default_factory=list)


__all__ = ["IncidentListData", "IncidentSummaryView", "IncidentView", "as_iso_utc"]
