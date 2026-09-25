"""Read-only wire schemas for detection findings (M10.5, M10.22).

These models describe how M10 exposes detection output. The runtime finding
built by a detector is ``app.detection.finding.DetectionFinding``; these
schemas are its serializable projections.

This is *not* an alert contract. A detection finding is an observation, so no
severity, risk score, assignment or lifecycle field exists here — those belong
to the M11 alert engine and the M12 correlation/risk layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

# The epoch → ISO-8601 UTC rule is shared with the M9 connection schemas, so a
# timestamp is rendered identically across the API.
from app.schemas.connection import to_iso_timestamp

if TYPE_CHECKING:
    from app.detection.finding import DetectionFinding, EvidenceValue
else:
    # Imported lazily at runtime to avoid a schemas ⇄ detection import cycle:
    # the finding model imports these view schemas to project itself.
    EvidenceValue = int | float | str | bool


class DetectionFindingView(BaseModel):
    """Serializable snapshot of one detection finding (M10.5/M10.22)."""

    finding_id: str
    rule_id: str = Field(description="Stable detector identifier")
    rule_name: str = Field(description="Human-readable detector name")
    timestamp: str | None = Field(default=None, description="ISO-8601 UTC")
    source_ip: str | None = None
    destination_ip: str | None = None
    source_device_id: str | None = None
    destination_device_id: str | None = None
    protocol: str | None = None
    description: str
    evidence: dict[str, EvidenceValue] = Field(default_factory=dict)
    confidence: float = Field(default=0.0, description="Evidence strength (M10.15)")
    metadata: dict[str, EvidenceValue] = Field(default_factory=dict)

    @classmethod
    def from_finding(cls, finding: "DetectionFinding") -> "DetectionFindingView":
        """Project a runtime finding onto this wire model."""
        return cls(
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            rule_name=finding.rule_name,
            timestamp=to_iso_timestamp(finding.timestamp),
            source_ip=finding.source_ip,
            destination_ip=finding.destination_ip,
            source_device_id=finding.source_device_id,
            destination_device_id=finding.destination_device_id,
            protocol=finding.protocol,
            description=finding.description,
            evidence=dict(finding.evidence),
            confidence=finding.confidence,
            metadata=dict(finding.metadata),
        )


class DetectionFindingListData(BaseModel):
    """Payload of the detection-findings collection endpoint."""

    count: int = 0
    findings: list[DetectionFindingView] = Field(default_factory=list)


class DetectionRuleView(BaseModel):
    """Serializable description of one registered detector (M10.22)."""

    rule_id: str
    rule_name: str
    description: str = ""
    enabled: bool = True
    window_seconds: float | None = Field(
        default=None, description="Detection window the rule reasons over (M10.13)"
    )
    state_size: int = Field(
        default=0, description="Subjects currently held in bounded detector state"
    )


class DetectionRuleListData(BaseModel):
    """Payload of the detection-rules endpoint."""

    count: int = 0
    rules: list[DetectionRuleView] = Field(default_factory=list)


class DetectionDiagnostics(BaseModel):
    """Execution diagnostics for the detection engine (M10.6/M10.17)."""

    evaluations: int = 0
    findings: int = 0
    errors: int = 0
    enabled_rules: int = 0
    registered_rules: int = 0
    retained_findings: int = 0
