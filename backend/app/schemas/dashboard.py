"""Read-only wire schemas for the consolidated dashboard (M13.19).

The dashboard is one request that answers "what is happening right now?" from the
services that already hold the answers. Each block here is therefore a *summary
of an existing service's state*, never a new computation: the traffic block is
the M6 snapshot, the device block counts M8's registry, and so on.

Two deliberate properties:

* **Every section is always present.** A section whose service could not be read
  is reported as ``available: false`` with a safe reason; a section whose service
  returned nothing is reported as available and holding zeroes. A client
  therefore renders a fixed layout *and* can tell "nothing happened" apart from
  "this could not be read", which are different facts (M13.19/M13.29).
* **The counts are counts, not scores.** ``devices`` has no risk field and
  ``connections`` has no severity field, because M8 and M9 do not produce them.
  Only the alert and incident blocks carry severity and risk, and those values
  come straight from M11 and M12 rather than being recomputed here.
"""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

from app.schemas.detection import DetectionFindingView

#: The payload type a dashboard section wraps.
DataT = TypeVar("DataT")


class DashboardCapture(BaseModel):
    """Capture state as the dashboard reports it (M13.19)."""

    running: bool = False
    status: str = "unknown"
    interface: str | None = None
    packet_count: int = Field(default=0, description="Packets seen this session")


class DashboardTraffic(BaseModel):
    """The M6 traffic snapshot, reduced to what a summary needs (M13.19)."""

    total_packets: int = 0
    total_bytes: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    bits_per_second: float = 0.0
    protocol_count: int = Field(
        default=0, description="Distinct protocols observed so far"
    )


class DashboardDevices(BaseModel):
    """Device counts from the M8 registry (M13.19).

    ``by_status`` is keyed by the M8 activity state and always names every state,
    so a client can render a fixed set of rows without checking for absences.
    """

    total: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)


class DashboardConnections(BaseModel):
    """Connection counts from the M9 tracker (M13.19)."""

    active: int = 0
    historical: int = 0
    tracked: int = Field(default=0, description="Active plus retired conversations")


class DashboardAlerts(BaseModel):
    """Alert counts from the M11 store (M13.19).

    ``open`` counts the states M11 defines as still needing attention
    (:data:`app.alerts.status.ACTIVE_STATUSES`), so a legacy stored status is
    reported in ``by_status`` without being miscounted as open.
    """

    total: int = 0
    open: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)


class DashboardIncidents(BaseModel):
    """Incident counts and the worst current score (M13.19).

    ``highest_risk_score`` is read from the riskiest incident the engine holds
    rather than recomputed, so it cannot disagree with what
    ``GET /api/v1/incidents?order=risk`` reports (M12.13).
    """

    total: int = 0
    active: int = 0
    highest_risk_score: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)


class DashboardDetections(BaseModel):
    """Retained finding count and the most recent findings (M13.19).

    ``recent`` is bounded by the request, and the findings are the M10 wire views
    rather than a new shape, so a client can read them with the same model it uses
    for ``GET /api/v1/detections``.
    """

    retained: int = 0
    recent: list[DetectionFindingView] = Field(default_factory=list)


class DashboardSection(BaseModel, Generic[DataT]):
    """One independently-readable block of the dashboard summary (M13.19/M13.29).

    Each dashboard section is read from its own service, so each can fail on its
    own. Wrapping the block is what lets one unavailable service leave the rest of
    the summary intact — the per-section isolation M13.29 asks for, so a
    device-registry problem cannot hide the alert counts.

    ``error`` is a short, safe sentence *naming the section*, never the
    exception's own text: a driver message can name a path or a host, and none of
    that belongs in a response body (M13.5/M13.30).
    """

    available: bool = True
    error: str | None = Field(
        default=None,
        description="Why the section is unavailable; never an internal detail",
    )
    data: DataT | None = None


class DashboardSummaryData(BaseModel):
    """Everything the dashboard summary endpoint returns (M13.19).

    Every section is present and independently available. ``unavailable_sections``
    names the ones that failed in a single place, so a client can check one field
    rather than walking every section.
    """

    generated_at: str = Field(description="ISO-8601 UTC instant of this response")
    unavailable_sections: list[str] = Field(
        default_factory=list, description="Sections that could not be read"
    )
    capture: DashboardSection[DashboardCapture]
    traffic: DashboardSection[DashboardTraffic]
    devices: DashboardSection[DashboardDevices]
    connections: DashboardSection[DashboardConnections]
    alerts: DashboardSection[DashboardAlerts]
    incidents: DashboardSection[DashboardIncidents]
    detections: DashboardSection[DashboardDetections]


__all__ = [
    "DashboardAlerts",
    "DashboardCapture",
    "DashboardConnections",
    "DashboardDetections",
    "DashboardDevices",
    "DashboardIncidents",
    "DashboardSection",
    "DashboardSummaryData",
    "DashboardTraffic",
    "DataT",
]
