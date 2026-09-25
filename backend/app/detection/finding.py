"""Normalized detection finding (M10.5, M10.14, M10.15).

A finding is *one observation produced by one detector*. It is deliberately not
an alert: there is no severity, no risk score, no false-positive state and no
lifecycle here. Severity and lifecycle belong to the M11 alert engine, and risk
scoring to M12 — a finding carries only what a detector actually observed.

Every finding must be explainable (M10.14), so :attr:`DetectionFinding.evidence`
holds the measured numbers and the threshold they were compared against, and
:attr:`DetectionFinding.metadata` holds supplementary facts. Values are never
invented: a detector records only what the packets and statistics showed.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field

from app.schemas.detection import DetectionFindingView

# A JSON-scalar value: the only shape an evidence or metadata value may take.
EvidenceValue = int | float | str | bool

# Prefix used for generated finding ids, so they are recognisable in logs.
_FINDING_ID_PREFIX = "fnd-"

# Confidence given to a finding whose measurement only just met its threshold.
MIN_CONFIDENCE = 0.5


def new_finding_id() -> str:
    """Return a unique, opaque finding identifier.

    A finding is an *observation*, not a stable entity: the same behaviour seen
    twice legitimately produces two findings. An opaque unique id therefore
    describes it better than a value derived from its content, which a later
    milestone could mistake for a deduplication key.
    """
    return f"{_FINDING_ID_PREFIX}{uuid.uuid4().hex}"


def threshold_confidence(
    measured: float, threshold: float, *, floor: float = MIN_CONFIDENCE
) -> float:
    """Return how strongly ``measured`` satisfies ``threshold`` (M10.15).

    The result is bounded to ``[floor, 1.0]``: a value exactly at the threshold
    scores ``floor`` (the evidence is present, but only just) and a value at or
    beyond twice the threshold scores ``1.0``. This states how strongly the
    detector's own evidence supports its rule condition — it is explicitly *not*
    a risk score, which M12 owns and which needs context a detector has not got.
    """
    if threshold <= 0:
        return 1.0
    if measured <= threshold:
        return floor
    excess = (measured - threshold) / threshold
    return min(1.0, floor + (1.0 - floor) * min(1.0, excess))


class DetectionFinding(BaseModel):
    """A single structured observation produced by a detector (M10.5)."""

    finding_id: str = Field(
        default_factory=new_finding_id, description="Unique finding identifier"
    )
    rule_id: str = Field(description="Stable detector identifier, e.g. 'port_scan'")
    rule_name: str = Field(description="Human-readable detector name")
    timestamp: float = Field(ge=0, description="Observation time, epoch seconds")
    source_ip: str | None = Field(
        default=None, description="Source address, when one was observed"
    )
    destination_ip: str | None = Field(default=None)
    source_device_id: str | None = Field(
        default=None, description="M8 device identity, when the address is known"
    )
    destination_device_id: str | None = Field(default=None)
    protocol: str | None = Field(
        default=None, description="Transport protocol the observation concerns"
    )
    description: str = Field(
        description="Descriptive wording such as 'Possible port scan detected'"
    )
    evidence: dict[str, EvidenceValue] = Field(
        default_factory=dict,
        description="Measured values and the thresholds they were compared against",
    )
    confidence: float = Field(
        default=MIN_CONFIDENCE,
        ge=0.0,
        le=1.0,
        description="How strongly the evidence supports the rule condition (M10.15)",
    )
    metadata: dict[str, EvidenceValue] = Field(
        default_factory=dict, description="Supplementary observed facts"
    )

    def with_devices(
        self, *, source_device_id: str | None, destination_device_id: str | None
    ) -> "DetectionFinding":
        """Return a copy carrying resolved device associations (M10.4).

        Device association is enrichment, exactly as it is in M9: a ``None``
        never overwrites a value the detector already set, and an unresolved
        address stays unknown rather than being invented.
        """
        return self.model_copy(
            update={
                "source_device_id": self.source_device_id or source_device_id,
                "destination_device_id": (
                    self.destination_device_id or destination_device_id
                ),
            }
        )

    def to_view(self) -> DetectionFindingView:
        """Build the read-only API projection of this finding (M10.22)."""
        return DetectionFindingView.from_finding(self)
