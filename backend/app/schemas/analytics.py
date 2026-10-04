"""Read-only wire schemas for the analytics API (M13.18).

Analytics is a *derived view* over services that already exist, and the schemas
say so: the traffic and protocol blocks reuse the M6 models directly, and the
ranked blocks carry an entry model per resource rather than a generic one.

That last choice is deliberate. M6's ``TopEntry`` is a ``key`` plus two totals,
which is all a statistics ranking needs because the key *is* the label. An
analytics ranking is asked "which device?" or "which conversation?", and a bare
key would force a client to make a second request per row to find out. So a ranked
device carries its identity, addresses and status, and a ranked conversation
carries its endpoints — both read from the record the registry already produced.

**No block here is a score.** The device and connection entries carry traffic
totals, not risk; only the threats block carries severity and risk, and those come
from M11 and M12 (M13.18).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.statistics import DirectionStat, ProtocolStat, TopEntry


class RankedDevice(BaseModel):
    """One device in a traffic ranking (M13.18).

    The identity fields are copied from the M8 device view for this request, so a
    client can render a ranking row without resolving the id again.
    """

    device_id: str
    mac_address: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    hostname: str | None = None
    status: str = Field(default="unknown", description="M8 activity state")
    packets: int = 0
    bytes: int = 0


class RankedConnection(BaseModel):
    """One conversation in a traffic ranking (M13.18)."""

    connection_id: str
    protocol: str
    source_ip: str
    source_port: int | None = None
    destination_ip: str
    destination_port: int | None = None
    state: str = Field(default="unknown", description="M9 observed state")
    packets: int = 0
    bytes: int = 0


class AnalyticsTraffic(BaseModel):
    """Traffic analytics: live totals, derived ratios and leading talkers (M13.18).

    ``average_packet_bytes`` and the protocol share are *derived from* the M6
    snapshot rather than recomputed from packets — arithmetic on a value a service
    already produced, not a second implementation of how that value is built.
    ``stored_packet_count`` comes from the packet table, so the live view and what
    has been persisted are both present (M13.18).
    """

    total_packets: int = 0
    total_bytes: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    bits_per_second: float = 0.0
    average_packet_bytes: float = Field(
        default=0.0, description="total_bytes / total_packets, 0 when no packets seen"
    )
    stored_packet_count: int = Field(
        default=0, description="Rows currently in the packet table"
    )
    protocol_count: int = 0
    directions: list[DirectionStat] = Field(default_factory=list)
    protocols: list[ProtocolStat] = Field(default_factory=list)
    top_sources: list[TopEntry] = Field(default_factory=list)
    top_destinations: list[TopEntry] = Field(default_factory=list)
    top_ports: list[TopEntry] = Field(default_factory=list)


class AnalyticsProtocols(BaseModel):
    """Protocol analytics with the totals the shares are relative to (M13.18)."""

    count: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    rank_by: str = Field(default="packets", description="Metric the list is ordered by")
    protocols: list[ProtocolStat] = Field(default_factory=list)


class AnalyticsDevices(BaseModel):
    """Device analytics: totals by state and a bounded traffic ranking (M13.18)."""

    total: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    rank_by: str = Field(default="packets", description="packets or bytes")
    top: list[RankedDevice] = Field(default_factory=list)


class AnalyticsConnections(BaseModel):
    """Connection analytics: tracker counters and a bounded traffic ranking (M13.18)."""

    active: int = 0
    historical: int = 0
    tracked: int = Field(default=0, description="Active plus retired conversations")
    rank_by: str = Field(default="bytes", description="Metric the ranking is ordered by")
    top: list[RankedConnection] = Field(default_factory=list)


class ThreatRuleStat(BaseModel):
    """Per-detector execution counters behind the threat totals (M13.18/M10.31).

    These are the M10 counters read as they are. They count *evaluations and
    findings*, which is what a detector did — not a severity, because a finding
    has none (M10.5).
    """

    rule_id: str
    rule_name: str = ""
    enabled: bool = True
    evaluations: int = 0
    findings: int = 0
    errors: int = 0


class AnalyticsThreats(BaseModel):
    """Threat analytics assembled from M11, M10 and M12 (M13.18).

    Three distinct notions of "how bad" stay distinct: alert ``severity`` is M11's
    evidence-based judgement, ``incidents_by_risk_band`` is M12's bounded
    prioritisation metric, and the finding counters are M10's raw observations with
    no judgement attached at all. A client can read all three without one
    masquerading as another (M12.16).
    """

    alerts_total: int = 0
    alerts_open: int = Field(
        default=0, description="Alerts in a state that still needs attention"
    )
    alerts_by_severity: dict[str, int] = Field(default_factory=dict)
    alerts_by_status: dict[str, int] = Field(default_factory=dict)

    findings_retained: int = Field(
        default=0, description="Findings currently in the bounded M10 history"
    )
    detections_evaluated: int = 0
    detections_findings: int = 0
    detections_errors: int = 0
    rules: list[ThreatRuleStat] = Field(default_factory=list)

    incidents_total: int = 0
    incidents_active: int = 0
    incidents_by_status: dict[str, int] = Field(default_factory=dict)
    incidents_by_risk_band: dict[str, int] = Field(default_factory=dict)
    highest_risk_score: int = 0


__all__ = [
    "AnalyticsConnections",
    "AnalyticsDevices",
    "AnalyticsProtocols",
    "AnalyticsThreats",
    "AnalyticsTraffic",
    "RankedConnection",
    "RankedDevice",
    "ThreatRuleStat",
]
