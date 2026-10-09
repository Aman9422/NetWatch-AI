"""Read-only wire schemas for the analytics API (M13.18, extended by M16).

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

M16 adds three things and changes nothing that was already here.

**A period.** Every response now carries the resolved
:class:`AnalyticsPeriod` its database-derived block was read over, so a client
never has to guess which window a number describes (M16.7).

**Persisted blocks.** ``stored`` (and ``windowed`` for devices) carry figures read
from SQLite within that period. They are *availability sections*
(:class:`AnalyticsSection`): always present, with ``available: false`` and a safe
sentence when the read failed. An available section holding zeroes is the honest
answer for "nothing is stored"; an unavailable one means the question could not be
asked at all (M16.8). The two are never conflated, and a value the store cannot
know is ``null`` rather than ``0``.

**Optionality with meaning.** ``float | None`` is used only where the underlying
value genuinely may not exist — an average over zero packets, a duration over
conversations that have not ended. Every such field is documented at its
definition. A field that is always known is never nullable.

Nothing here is recomputed by the client. Percentages, rates and averages arrive
calculated, because the numerator and denominator both live in the backend.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.analytics.metrics import RankMetric
from app.schemas.statistics import DirectionStat, ProtocolStat, TopEntry

#: A JSON count map, used wherever a breakdown's key set is a vocabulary the
#: owning milestone defines (severities, statuses, bands, ranges).
CountMap = dict[str, int]


class AnalyticsPeriod(BaseModel):
    """The window a response's database-derived block was read over (M16.7).

    ``since`` is inclusive and ``until`` exclusive, matching M13.26. ``defaulted``
    says whether the caller named the bounds or the one-hour default was applied:
    a client that sent nothing gets told so, rather than being left to infer it
    from timestamps it did not ask for.

    ``buckets`` is how many series points ``bucket_seconds`` produces for this
    window, and ``max_buckets`` is the ceiling that chose the bucket — reported so
    the relationship between a window's length and its resolution is visible
    rather than mysterious.
    """

    since: str = Field(description="Inclusive lower bound, ISO-8601 UTC")
    until: str = Field(description="Exclusive upper bound, ISO-8601 UTC")
    seconds: float = Field(default=0.0, description="Window length in seconds")
    bucket_seconds: int = Field(default=0, description="Series resolution")
    buckets: int = Field(default=0, description="Series points this window lists")
    max_buckets: int = Field(default=0, description="Ceiling that chose the bucket")
    defaulted: bool = Field(
        default=False, description="True when no bounds were sent"
    )


class SeriesPoint(BaseModel):
    """One traffic time bucket (M16.2).

    A bucket with zero packets means the store holds no packet in that interval.
    That is a statement about the persisted data, not a claim that no traffic
    occurred: capture may have been stopped. The distinction is why this is a
    *stored* series and is named as one.
    """

    start: str = Field(description="Bucket start, ISO-8601 UTC")
    packets: int = 0
    bytes: int = 0


class ConnectionSeriesPoint(BaseModel):
    """One conversation-count time bucket (M16.5)."""

    start: str = Field(description="Bucket start, ISO-8601 UTC")
    connections: int = 0


class AlertSeriesPoint(BaseModel):
    """One alert-count time bucket (M16.6)."""

    start: str = Field(description="Bucket start, ISO-8601 UTC")
    alerts: int = 0


class DurationStats(BaseModel):
    """Observed conversation lifetimes over the ones that ended (M16.5).

    ``samples`` is reported beside the statistics because they describe only the
    conversations that have an ``end_time``. A conversation still running has no
    lifetime yet, so it is excluded rather than counted as zero, and ``samples``
    is how a client knows how much of the window the statistics cover.

    Every statistic is ``None`` when ``samples`` is ``0``: no observation exists,
    and ``0.0`` would be a claim that a conversation lasted no time at all.
    """

    samples: int = 0
    min_seconds: float | None = None
    mean_seconds: float | None = None
    max_seconds: float | None = None


class ThreatRuleCount(BaseModel):
    """How many stored alerts one detector raised in the period (M16.6).

    ``rule_key`` is the detector's string rule id (M11.9), not the
    ``detection_rules`` foreign key, which is empty whenever the catalogue holds
    no row for the detector.
    """

    rule_key: str
    alerts: int = 0


class FindingRuleCount(BaseModel):
    """How many retained findings one detector produced in the period (M16.6)."""

    rule_id: str
    rule_name: str = ""
    findings: int = 0


class FindingsSummary(BaseModel):
    """The windowed view of the M10 findings still held in memory (M16.6).

    Distinct from the ``rules`` block on the same response, and the distinction is
    worth stating: ``rules`` is M10's own per-detector *execution* counters —
    evaluations, findings and errors since the process started — while this is the
    observations that are still retained *and* fall inside the period. One is a
    lifetime tally of what the engine did; the other is what it observed in a
    window.

    ``mean_confidence`` is ``None`` when the period holds no finding, and a
    finding's ``0.0..1.0`` confidence is scaled to ``0..100`` only to place it in
    the project's one documented 0-100 tiling for
    :attr:`by_confidence_range` (M12.27/M16.6).
    """

    retained: int = Field(
        default=0, description="Findings currently in M10's bounded history"
    )
    in_window: int = Field(default=0, description="Retained findings inside the period")
    mean_confidence: float | None = Field(
        default=None, description="Mean confidence of those findings, or null"
    )
    by_confidence_range: CountMap = Field(default_factory=dict)
    by_rule: list[FindingRuleCount] = Field(default_factory=list)


class IncidentLinkage(BaseModel):
    """Alert-to-incident references M12 already holds (M16.6).

    An incident names the alerts it grouped (``CorrelatedIncident.alert_ids``), so
    this reports the relationship rather than deriving one. ``alerts_in_incidents``
    counts *distinct* alert ids across all incidents, so an alert that two
    incidents reference is counted once — it is a count of alerts, not of links.
    """

    incidents_total: int = 0
    incidents_with_alerts: int = 0
    alerts_in_incidents: int = 0


class StoredTrafficData(BaseModel):
    """Traffic read from the ``packets`` table inside the period (M16.2).

    ``stored_packet_count`` is the one figure here that is *not* scoped to the
    period: it is M13's unwindowed row count, read in the same guarded block as
    the windowed totals so that a packet table which cannot be read is reported
    as an unavailable section instead of failing the whole request (M16.8). The
    M13 top-level field of the same name mirrors it and is ``0`` only when this
    section is itself unavailable — which its own ``available`` flag states, so
    nothing is silently turned into zero.
    """

    total_packets: int = 0
    total_bytes: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    average_packet_bytes: float | None = Field(
        default=None, description="Null when the period holds no packet"
    )
    first_timestamp: str | None = Field(
        default=None, description="Oldest stored packet, or null when empty"
    )
    last_timestamp: str | None = Field(
        default=None, description="Newest stored packet, or null when empty"
    )
    distinct_protocols: int = 0
    packets_without_source_port: int = Field(
        default=0, description="Stored packets carrying no source port (ICMP, ARP)"
    )
    packets_without_destination_port: int = Field(
        default=0, description="Stored packets carrying no destination port"
    )
    stored_packet_count: int = Field(
        default=0, description="Rows in the packet table, the M13 unwindowed count"
    )
    series: list[SeriesPoint] = Field(default_factory=list)
    top_sources: list[TopEntry] = Field(default_factory=list)
    top_destinations: list[TopEntry] = Field(default_factory=list)
    top_ports: list[TopEntry] = Field(default_factory=list)
    protocols: list[ProtocolStat] = Field(default_factory=list)


class StoredProtocolsData(BaseModel):
    """Protocol breakdown from the ``packets`` table inside the period (M16.3).

    ``percentage`` on each entry is a share of ``total_packets`` — the whole
    population the window selected — not of the returned rows. When
    ``distinct_protocols`` exceeds ``count`` the list was truncated to the
    ranking's limit, ``truncated`` is true, and the shares deliberately do not sum
    to 100: they are shares of the window, and the window was not truncated.
    """

    count: int = Field(default=0, description="Protocols returned in this list")
    distinct_protocols: int = 0
    truncated: bool = False
    total_packets: int = 0
    total_bytes: int = 0
    rank_by: RankMetric = "packets"
    protocols: list[ProtocolStat] = Field(default_factory=list)


class DeviceWindowData(BaseModel):
    """Devices seen inside the period, from the M8 registry (M16.4).

    The window filters on a device's ``last_seen``: a device is listed when it was
    observed at least once inside the period. The registry itself holds no history,
    so these are the *current* records that fall in the window rather than a
    reconstruction of what was observed then — see the M16 limitations.

    No risk score appears here, because M8 computes none (M13.10). Network-level
    identity, and its limitation on routed traffic, are unchanged from M15: a
    device id can be the next hop rather than the remote host.
    """

    total: int = 0
    by_status: CountMap = Field(default_factory=dict)
    rank_by: RankMetric = "packets"
    top: list["RankedDevice"] = Field(default_factory=list)


class StoredConnectionsData(BaseModel):
    """Conversations read from the ``connections`` table (M16.5).

    The window selects conversations whose ``start_time`` falls inside it, which
    is M9's own rule for the same filter. ``active`` counts the stored rows still
    marked ``active`` — conversations M9 has not retired — and is a different
    figure from the live tracker counter reported at the top of the response.
    """

    total: int = 0
    active: int = 0
    first_timestamp: str | None = None
    last_timestamp: str | None = None
    by_protocol: CountMap = Field(default_factory=dict)
    by_status: CountMap = Field(default_factory=dict)
    duration: DurationStats = Field(default_factory=DurationStats)
    series: list[ConnectionSeriesPoint] = Field(default_factory=list)
    top_sources: list[TopEntry] = Field(default_factory=list)
    top_destinations: list[TopEntry] = Field(default_factory=list)


class StoredAlertsData(BaseModel):
    """Alerts read from the ``alerts`` table inside the period (M16.6).

    Every vocabulary here is named in full even when it holds no rows, so a client
    renders fixed rows rather than discovering a missing key. The three notions of
    "how bad" stay in three fields: ``by_severity`` is M11's judgement,
    ``by_confidence_range`` is how strongly M11 believed its evidence, and
    ``by_risk_band`` is M12's prioritisation metric.

    Note on ``by_risk_band``: M11 writes ``risk_score = 0`` and leaves it there
    until M12 correlates the alert, so an alert no incident has reached is banded
    ``minimal``. That is the truthful reading of its stored score, but it means
    "not yet scored", not "assessed as minimal". The live incident block is where a
    scored judgement is reported.
    """

    total: int = 0
    without_rule_key: int = Field(
        default=0, description="Alerts carrying no correlation key, so unranked"
    )
    first_timestamp: str | None = None
    last_timestamp: str | None = None
    by_severity: CountMap = Field(default_factory=dict)
    by_status: CountMap = Field(default_factory=dict)
    by_risk_band: CountMap = Field(default_factory=dict)
    by_confidence_range: CountMap = Field(default_factory=dict)
    rules: list[ThreatRuleCount] = Field(default_factory=list)
    series: list[AlertSeriesPoint] = Field(default_factory=list)


class AnalyticsSection(BaseModel):
    """Availability of one database-derived analytics block (M16.8).

    Every section is always present, so a client renders a fixed layout. ``data``
    is ``None`` exactly when ``available`` is False, and ``error`` is then a single
    safe sentence that names no table, column, query or exception (M13.30). An
    available section whose numbers are all zero means the store holds nothing in
    the period — a different answer from "the question could not be asked", which
    is why the two are separate fields rather than one nullable payload.
    """

    available: bool = True
    error: str | None = Field(
        default=None, description="A safe sentence when unavailable, else null"
    )


class TrafficSection(AnalyticsSection):
    """Persisted traffic for the period (M16.2)."""

    data: StoredTrafficData | None = None


class ProtocolsSection(AnalyticsSection):
    """Persisted protocol breakdown for the period (M16.3)."""

    data: StoredProtocolsData | None = None


class DeviceWindowSection(AnalyticsSection):
    """Devices observed inside the period (M16.4)."""

    data: DeviceWindowData | None = None


class ConnectionsSection(AnalyticsSection):
    """Persisted conversations for the period (M16.5)."""

    data: StoredConnectionsData | None = None


class AlertsSection(AnalyticsSection):
    """Persisted alerts for the period (M16.6)."""

    data: StoredAlertsData | None = None


class RankedDevice(BaseModel):
    """One device in a traffic ranking (M13.18, extended by M16.4).

    The identity fields are copied from the M8 device view for this request, so a
    client can render a ranking row without resolving the id again. ``first_seen``
    and ``last_seen`` are the registry's own observation bounds, added by M16.4;
    both are ``None`` for a record the registry has not dated, rather than epoch 0.
    """

    device_id: str
    mac_address: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    hostname: str | None = None
    status: str = Field(default="unknown", description="M8 activity state")
    first_seen: str | None = Field(
        default=None, description="ISO-8601 UTC, when M8 observed it"
    )
    last_seen: str | None = Field(
        default=None, description="ISO-8601 UTC, when M8 last observed it"
    )
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
    """Traffic analytics: live totals, derived ratios and persisted traffic (M16.2).

    The first block is M13's unchanged live view of the M6 snapshot.
    ``average_packet_bytes`` and the protocol share are *derived from* that
    snapshot rather than recomputed from packets, and ``stored_packet_count`` comes
    from the packet table so the live view and what has been persisted are both
    present.

    ``stored`` is M16's addition: the same questions asked of the persisted packet
    table, over an explicit ``period``. The two are deliberately different figures
    — live counters reset with the process, stored rows do not — which is exactly
    why both are reported instead of one standing in for the other.
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

    period: AnalyticsPeriod = Field(
        default_factory=lambda: AnalyticsPeriod(since="", until="")
    )
    stored: TrafficSection = Field(default_factory=TrafficSection)


class AnalyticsProtocols(BaseModel):
    """Protocol analytics: the live distribution and the persisted one (M16.3).

    The top-level block is M13's: the M6 manager's own protocol entries, ordered by
    the requested metric. ``stored`` is M16's windowed breakdown of the packet
    table, with percentages taken against that window's total packet count so the
    shares and the population they describe come from the same selection.
    """

    count: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    rank_by: RankMetric = Field(
        default="packets", description="Metric the list is ordered by"
    )
    protocols: list[ProtocolStat] = Field(default_factory=list)

    period: AnalyticsPeriod = Field(
        default_factory=lambda: AnalyticsPeriod(since="", until="")
    )
    stored: ProtocolsSection = Field(default_factory=ProtocolsSection)


class AnalyticsDevices(BaseModel):
    """Device analytics: the registry totals and the windowed view (M16.4).

    ``total``, ``by_status`` and ``top`` are M13's view of the whole M8 registry.
    ``windowed`` is M16's: the same shape restricted to devices whose ``last_seen``
    falls inside the period. Neither carries a risk score, because M8 computes
    none, and neither claims to identify a remote host behind a routed next hop.
    """

    total: int = 0
    by_status: CountMap = Field(default_factory=dict)
    rank_by: RankMetric = Field(default="packets", description="packets or bytes")
    top: list[RankedDevice] = Field(default_factory=list)

    period: AnalyticsPeriod = Field(
        default_factory=lambda: AnalyticsPeriod(since="", until="")
    )
    windowed: DeviceWindowSection = Field(default_factory=DeviceWindowSection)


class AnalyticsConnections(BaseModel):
    """Connection analytics: live tracker counters and stored conversations (M16.5).

    ``active``, ``historical`` and ``tracked`` are M9's own live counters, so they
    agree with ``/connections``. ``top`` ranks tracked conversations — including
    retired ones, because the busiest conversation of a session is often one that
    has already closed.

    ``stored`` is M16's windowed read of the ``connections`` table, which is a
    different population: rows M9 has written for conversations that *began* in the
    period, whether or not they are still tracked. Neither side scores risk.
    """

    active: int = 0
    historical: int = 0
    tracked: int = Field(default=0, description="Active plus retired conversations")
    rank_by: RankMetric = Field(
        default="bytes", description="Metric the ranking is ordered by"
    )
    top: list[RankedConnection] = Field(default_factory=list)

    period: AnalyticsPeriod = Field(
        default_factory=lambda: AnalyticsPeriod(since="", until="")
    )
    stored: ConnectionsSection = Field(default_factory=ConnectionsSection)


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
    """Threat analytics assembled from M11, M10 and M12 (M13.18, extended by M16.6).

    Three layers are reported side by side and kept distinct, because collapsing
    them would invent a single "threat" number that no milestone produces:

    * M10's findings — what the detectors *observed*, with no judgement;
    * M11's alerts by severity and status — the evidence-based judgement;
    * M12's incidents by lifecycle state and risk band — the bounded
      prioritisation metric.

    M16 adds a fourth, orthogonal view rather than a fourth judgement: ``stored``
    is the same M11 alert table read over an explicit ``period``, so a client can
    ask "how did alerts break down in this window" instead of only "what is stored
    now". ``findings`` window-sums the retained M10 observations, and
    ``incident_links`` reports the alert-to-incident references M12 already holds.

    No field here is a second risk score. ``incidents_by_risk_band`` and the
    stored alerts' ``by_risk_band`` both read M12's persisted score, banded by the
    one table M12 defines.
    """

    alerts_total: int = 0
    alerts_open: int = Field(
        default=0, description="Alerts in a state that still needs attention"
    )
    alerts_by_severity: CountMap = Field(default_factory=dict)
    alerts_by_status: CountMap = Field(default_factory=dict)

    findings_retained: int = Field(
        default=0, description="Findings currently in the bounded M10 history"
    )
    detections_evaluated: int = 0
    detections_findings: int = 0
    detections_errors: int = 0
    rules: list[ThreatRuleStat] = Field(default_factory=list)

    incidents_total: int = 0
    incidents_active: int = 0
    incidents_by_status: CountMap = Field(default_factory=dict)
    incidents_by_risk_band: CountMap = Field(default_factory=dict)
    highest_risk_score: int = 0

    period: AnalyticsPeriod = Field(
        default_factory=lambda: AnalyticsPeriod(since="", until="")
    )
    stored: AlertsSection = Field(default_factory=AlertsSection)
    findings: FindingsSummary = Field(default_factory=FindingsSummary)
    incident_links: IncidentLinkage = Field(default_factory=IncidentLinkage)


# ``DeviceWindowData`` names ``RankedDevice`` as a forward reference, because the
# ranked-entry models are declared below the aggregate that holds them. Resolving
# it here, once the name exists, is what makes the reference concrete rather than
# leaving Pydantic to raise on first use.
DeviceWindowData.model_rebuild()

__all__ = [
    "AlertSeriesPoint",
    "AlertsSection",
    "AnalyticsConnections",
    "AnalyticsDevices",
    "AnalyticsPeriod",
    "AnalyticsProtocols",
    "AnalyticsSection",
    "AnalyticsThreats",
    "AnalyticsTraffic",
    "ConnectionSeriesPoint",
    "ConnectionsSection",
    "CountMap",
    "DeviceWindowData",
    "DeviceWindowSection",
    "DurationStats",
    "FindingRuleCount",
    "FindingsSummary",
    "IncidentLinkage",
    "ProtocolsSection",
    "RankedConnection",
    "RankedDevice",
    "SeriesPoint",
    "StoredAlertsData",
    "StoredConnectionsData",
    "StoredProtocolsData",
    "StoredTrafficData",
    "ThreatRuleCount",
    "ThreatRuleStat",
    "TrafficSection",
]
