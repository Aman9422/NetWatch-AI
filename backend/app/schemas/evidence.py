"""Wire schemas for alert evidence (M13.14).

M11.13 stores evidence as a *reference* to the underlying resource — a packet
id, a conversation id, a device id — rather than a copy of the resource itself.
These models keep that discipline: an evidence record exposes its type, its
reference and its own JSON document, and never inlines the packet or the
connection it points at.

The standalone ``GET /evidence/{evidence_id}`` needs one thing the per-alert
listing does not: the identifier of the record itself, and the alert that owns
it, so a client holding a reference can navigate in both directions. That is what
:class:`EvidenceDetailData` adds over :class:`~app.schemas.alert.AlertEvidenceView`.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.alert import AlertEvidenceView


class EvidenceListData(BaseModel):
    """Payload of ``GET /alerts/{alert_id}/evidence`` (M13.14)."""

    alert_id: int = Field(description="The alert the evidence belongs to")
    count: int = 0
    evidence: list[AlertEvidenceView] = Field(default_factory=list)


class EvidenceDetailData(BaseModel):
    """Payload of ``GET /evidence/{evidence_id}`` (M13.14)."""

    evidence_id: int = Field(description="Stable identifier of the evidence row")
    alert_id: int = Field(
        description="The alert this evidence supports, so the reference is navigable"
    )
    evidence: AlertEvidenceView


__all__ = ["EvidenceDetailData", "EvidenceListData"]
