/**
 * Analytics and dashboard models (M15.6).
 *
 * Analytics is a *derived view* over services that already exist, and these types
 * say so: nothing here is a score the frontend may recompute. The device and
 * connection rankings carry traffic totals rather than risk (`app/schemas/analytics.py`),
 * and the only block with severity or risk is the threats block — whose values
 * come straight from M11 and M12 (M13.18).
 *
 * The dashboard is the seventh-service aggregate. Two of its properties shape
 * these types:
 *
 * * **Every section is always present**, so a client renders a fixed layout. A
 *   section whose service could not be read is reported as `available: false`
 *   with a safe reason; a section holding nothing is available and full of
 *   zeroes. `null` data with `available: true` is therefore a real combination
 *   rather than an oversight (M13.19/M13.29).
 * * **A dashboard WS event is not the summary.** `/ws/dashboard` sends a small
 *   bounded projection (nine numbers), while `GET /dashboard/summary` is the
 *   full aggregate. They are separate types so a page cannot mistake one for the
 *   other (M14.9).
 */

import type { RankMetric, TopEntry, DirectionStat, ProtocolStat } from './traffic'

/** One device in a traffic ranking (M13.18, extended by M16.4). */
export interface RankedDevice {
  readonly device_id: string
  readonly mac_address: string | null
  readonly ip_addresses: readonly string[]
  readonly hostname: string | null
  /** M8 activity state, not a security verdict. */
  readonly status: string
  /**
   * When M8 first and last observed it, ISO-8601 UTC, or `null`.
   *
   * `null` is not epoch zero: it is a record the registry has not dated. The
   * registry keeps no history, so a device id can also be a routed next hop
   * rather than the remote host (M16.4/M15.20).
   */
  readonly first_seen: string | null
  readonly last_seen: string | null
  readonly packets: number
  readonly bytes: number
}

/** One conversation in a traffic ranking (M13.18). */
export interface RankedConnection {
  readonly connection_id: string
  readonly protocol: string
  readonly source_ip: string
  readonly source_port: number | null
  readonly destination_ip: string
  readonly destination_port: number | null
  /** M9 observed state, not a security verdict. */
  readonly state: string
  readonly packets: number
  readonly bytes: number
}

/** `GET /api/v1/analytics/traffic` (M13.18). */
export interface AnalyticsTraffic {
  readonly total_packets: number
  readonly total_bytes: number
  readonly packets_per_second: number
  readonly bytes_per_second: number
  readonly bits_per_second: number
  /** `total_bytes / total_packets`, computed by the backend. */
  readonly average_packet_bytes: number
  /** Rows currently in the packet table. */
  readonly stored_packet_count: number
  readonly protocol_count: number
  readonly directions: readonly DirectionStat[]
  readonly protocols: readonly ProtocolStat[]
  readonly top_sources: readonly TopEntry[]
  readonly top_destinations: readonly TopEntry[]
  readonly top_ports: readonly TopEntry[]

  /** The window the persisted block was read over (M16.7). */
  readonly period: AnalyticsPeriod
  /** The same questions asked of the packet table, over `period` (M16.2). */
  readonly stored: AnalyticsSection<StoredTrafficData>
}

/** `GET /api/v1/analytics/protocols` (M13.18, extended by M16.3). */
export interface AnalyticsProtocols {
  readonly count: number
  readonly total_packets: number
  readonly total_bytes: number
  readonly rank_by: RankMetric
  readonly protocols: readonly ProtocolStat[]

  readonly period: AnalyticsPeriod
  readonly stored: AnalyticsSection<StoredProtocolsData>
}

/** `GET /api/v1/analytics/devices` (M13.18, extended by M16.4). */
export interface AnalyticsDevices {
  readonly total: number
  readonly by_status: Readonly<Record<string, number>>
  readonly rank_by: RankMetric
  readonly top: readonly RankedDevice[]

  readonly period: AnalyticsPeriod
  /**
   * The same M8 views restricted to devices last seen inside `period`.
   *
   * A section because a client renders it on its own, but it reads no table: it
   * re-filters the in-process registry, so it cannot fail on a database the way
   * the other four blocks can.
   */
  readonly windowed: AnalyticsSection<DeviceWindowData>
}

/** `GET /api/v1/analytics/connections` (M13.18, extended by M16.5). */
export interface AnalyticsConnections {
  readonly active: number
  readonly historical: number
  readonly tracked: number
  readonly rank_by: RankMetric
  readonly top: readonly RankedConnection[]

  readonly period: AnalyticsPeriod
  readonly stored: AnalyticsSection<StoredConnectionsData>
}

/** Per-detector execution counters (M13.18/M10.31). */
export interface ThreatRuleStat {
  readonly rule_id: string
  readonly rule_name: string
  readonly enabled: boolean
  readonly evaluations: number
  readonly findings: number
  readonly errors: number
}

/** `GET /api/v1/analytics/threats` (M13.18). */
export interface AnalyticsThreats {
  readonly alerts_total: number
  readonly alerts_open: number
  readonly alerts_by_severity: Readonly<Record<string, number>>
  readonly alerts_by_status: Readonly<Record<string, number>>

  readonly findings_retained: number
  readonly detections_evaluated: number
  readonly detections_findings: number
  readonly detections_errors: number
  readonly rules: readonly ThreatRuleStat[]

  readonly incidents_total: number
  readonly incidents_active: number
  readonly incidents_by_status: Readonly<Record<string, number>>
  readonly incidents_by_risk_band: Readonly<Record<string, number>>
  readonly highest_risk_score: number

  readonly period: AnalyticsPeriod
  readonly stored: AnalyticsSection<StoredAlertsData>
  /** The retained M10 observations, summed over `period` (M16.6). */
  readonly findings: FindingsSummary
  /** The alert-to-incident references M12 already holds (M16.6). */
  readonly incident_links: IncidentLinkage
}

// ── Dashboard (M13.19/M14.9) ────────────────────────────────────────────────

/** Capture state as the dashboard reports it (M13.19). */
export interface DashboardCapture {
  readonly running: boolean
  readonly status: string
  readonly interface: string | null
  readonly packet_count: number
}

/** The M6 snapshot, reduced to what a summary needs (M13.19). */
export interface DashboardTraffic {
  readonly total_packets: number
  readonly total_bytes: number
  readonly packets_per_second: number
  readonly bytes_per_second: number
  readonly bits_per_second: number
  readonly protocol_count: number
}

/** Device counts from the M8 registry (M13.19). */
export interface DashboardDevices {
  readonly total: number
  readonly by_status: Readonly<Record<string, number>>
}

/** Connection counts from the M9 tracker (M13.19). */
export interface DashboardConnections {
  readonly active: number
  readonly historical: number
  readonly tracked: number
}

/** Alert counts from the M11 store (M13.19). */
export interface DashboardAlerts {
  readonly total: number
  /** The states M11 marks as still needing attention. */
  readonly open: number
  readonly by_severity: Readonly<Record<string, number>>
  readonly by_status: Readonly<Record<string, number>>
}

/** Incident counts and the worst current score (M13.19). */
export interface DashboardIncidents {
  readonly total: number
  readonly active: number
  readonly highest_risk_score: number
  readonly by_status: Readonly<Record<string, number>>
}

/** Retained finding count and the most recent findings (M13.19). */
export interface DashboardDetections {
  readonly retained: number
  readonly recent: readonly import('./security').DetectionFinding[]
}

/**
 * One independently-readable dashboard block (M13.19/M13.29).
 *
 * `data` is nullable while `available` is `true` only in the theoretical case
 * where a builder returned nothing; in practice an available section holds a
 * payload and an unavailable one holds `null` plus a safe `error` sentence that
 * names the section and never exposes an internal detail.
 */
export interface DashboardSection<T> {
  readonly available: boolean
  /** Why the section is unavailable; never an internal detail. */
  readonly error: string | null
  readonly data: T | null
}

/** Everything `GET /api/v1/dashboard/summary` returns (M13.19). */
export interface DashboardSummary {
  /** ISO-8601 UTC instant of the response. */
  readonly generated_at: string
  /** Names the sections that could not be read. */
  readonly unavailable_sections: readonly string[]
  readonly capture: DashboardSection<DashboardCapture>
  readonly traffic: DashboardSection<DashboardTraffic>
  readonly devices: DashboardSection<DashboardDevices>
  readonly connections: DashboardSection<DashboardConnections>
  readonly alerts: DashboardSection<DashboardAlerts>
  readonly incidents: DashboardSection<DashboardIncidents>
  readonly detections: DashboardSection<DashboardDetections>
}

/** The section names a dashboard summary may report as unavailable. */
export type DashboardSectionName = keyof Pick<
  DashboardSummary,
  | 'capture'
  | 'traffic'
  | 'devices'
  | 'connections'
  | 'alerts'
  | 'incidents'
  | 'detections'
>

/**
 * The `dashboard.updated` payload (M14.9).
 *
 * Nine scalars, sampled once per tick. It is *not* the summary: it carries no
 * severity breakdown, no per-state counts and no findings, because a live tick
 * must stay small. A page needing more refreshes from REST (M15.30).
 */
export interface DashboardUpdateEvent {
  readonly capture_running: boolean
  readonly interface: string | null
  readonly packet_count: number
  readonly packets_per_second: number
  readonly bytes_per_second: number
  readonly device_count: number
  readonly active_connections: number
  readonly open_alerts: number
  readonly active_incidents: number
}

/** The metrics a analytics ranking endpoint may be ordered by. */
export type AnalyticsRank = RankMetric

// ── M16: the window and the persisted blocks ───────────────────────────────

/**
 * The window a response's database-derived block was read over (M16.7).
 *
 * Every analytics response now carries one, so a client never has to guess which
 * window a number describes. `since` is inclusive and `until` exclusive, matching
 * M13.26: the half-open convention means two adjacent windows never both claim
 * the same instant.
 *
 * `defaulted` says whether the caller named the bounds or the one-hour default
 * was applied, so a page can say "last hour" honestly instead of inferring it
 * from timestamps it never sent. `buckets` is how many series points
 * `bucket_seconds` produces, and `max_buckets` the ceiling that chose the bucket
 * — reported together so the resolution is visibly a consequence of the window's
 * length rather than a mystery.
 */
export interface AnalyticsPeriod {
  readonly since: string
  readonly until: string
  readonly seconds: number
  readonly bucket_seconds: number
  readonly buckets: number
  readonly max_buckets: number
  readonly defaulted: boolean
}

/**
 * One database-derived analytics block (M16.8).
 *
 * Always present, so a page renders a fixed layout. `available: false` means the
 * question could not be asked — a locked file, a full disk — and `data` is then
 * `null` with a safe `error` sentence that names no table, query or exception.
 * An *available* section holding zeroes is the different, honest answer for
 * "the store holds nothing in this window".
 *
 * The distinction is why this is not `T | null`: a nullable payload alone could
 * not tell "nothing stored" apart from "could not read", and a page that treated
 * the second as the first would report a measurement it never took.
 *
 * Structurally identical to {@link DashboardSection}, which reports the same
 * thing for the dashboard's own blocks; they are kept as separate names because
 * the two endpoints describe different sections.
 */
export interface AnalyticsSection<T> {
  readonly available: boolean
  readonly error: string | null
  readonly data: T | null
}

/**
 * One traffic time bucket (M16.2).
 *
 * A bucket with zero packets means the store holds no packet in that interval.
 * That is a statement about the persisted data, not a claim that no traffic
 * occurred — capture may have been stopped — which is why this is a *stored*
 * series and named as one.
 */
export interface SeriesPoint {
  readonly start: string
  readonly packets: number
  readonly bytes: number
}

/** One conversation-count time bucket (M16.5). */
export interface ConnectionSeriesPoint {
  readonly start: string
  readonly connections: number
}

/** One alert-count time bucket (M16.6). */
export interface AlertSeriesPoint {
  readonly start: string
  readonly alerts: number
}

/**
 * Observed conversation lifetimes over the ones that ended (M16.5).
 *
 * `samples` is reported beside the statistics because they describe only the
 * conversations carrying an `end_time`. A conversation still running has no
 * lifetime yet, so it is excluded rather than counted as zero, and `samples` is
 * how a page knows how much of the window the statistics cover.
 *
 * Every statistic is `null` when `samples` is `0`: no observation exists, and
 * `0.0` would claim a conversation lasted no time at all.
 */
export interface DurationStats {
  readonly samples: number
  readonly min_seconds: number | null
  readonly mean_seconds: number | null
  readonly max_seconds: number | null
}

/** How many stored alerts one detector raised in the window (M16.6). */
export interface ThreatRuleCount {
  /** The detector's string rule id (M11.9), not its catalogue foreign key. */
  readonly rule_key: string
  readonly alerts: number
}

/** How many retained findings one detector produced in the window (M16.6). */
export interface FindingRuleCount {
  readonly rule_id: string
  readonly rule_name: string
  readonly findings: number
}

/**
 * The windowed view of the M10 findings still held in memory (M16.6).
 *
 * Distinct from {@link AnalyticsThreats.rules}, and the distinction matters:
 * `rules` is M10's per-detector *execution* counters since the process started,
 * while this is the observations still retained *and* inside the window. One is
 * a lifetime tally of what the engine did; the other, what it saw.
 *
 * `mean_confidence` is `null` when the window holds no finding. A finding's
 * `0.0..1.0` confidence is scaled to `0..100` only to place it in the project's
 * one documented 0-100 tiling for `by_confidence_range` (M12.27).
 */
export interface FindingsSummary {
  /** Findings currently in M10's bounded history. */
  readonly retained: number
  readonly in_window: number
  readonly mean_confidence: number | null
  readonly by_confidence_range: Readonly<Record<string, number>>
  readonly by_rule: readonly FindingRuleCount[]
}

/**
 * Alert-to-incident references M12 already holds (M16.6).
 *
 * An incident names the alerts it grouped, so this reports that relationship
 * rather than deriving one. `alerts_in_incidents` counts *distinct* alert ids
 * across all incidents, so an alert two incidents reference is counted once: it
 * is a count of alerts, not of links.
 */
export interface IncidentLinkage {
  readonly incidents_total: number
  readonly incidents_with_alerts: number
  readonly alerts_in_incidents: number
}

/**
 * Traffic read from the `packets` table inside the window (M16.2).
 *
 * `stored_packet_count` is the one field here that is *not* scoped to the
 * window: it is the unwindowed row count M13 has always reported, read in the
 * same guarded block as the windowed totals. The top-level
 * {@link AnalyticsTraffic.stored_packet_count} mirrors it, and is `0` only when
 * this section is itself unavailable — which its `available` flag states, so
 * nothing is silently turned into a zero.
 *
 * `average_packet_bytes`, `first_timestamp` and `last_timestamp` are `null` for
 * an empty window: no stored packet means no size and no instant was observed,
 * and `0` would claim a packet of no length at epoch 1970.
 */
export interface StoredTrafficData {
  readonly total_packets: number
  readonly total_bytes: number
  readonly packets_per_second: number
  readonly bytes_per_second: number
  readonly average_packet_bytes: number | null
  readonly first_timestamp: string | null
  readonly last_timestamp: string | null
  readonly distinct_protocols: number
  /** Stored packets carrying no source port — ICMP and ARP genuinely do not. */
  readonly packets_without_source_port: number
  readonly packets_without_destination_port: number
  readonly stored_packet_count: number
  readonly series: readonly SeriesPoint[]
  readonly top_sources: readonly TopEntry[]
  readonly top_destinations: readonly TopEntry[]
  readonly top_ports: readonly TopEntry[]
  readonly protocols: readonly ProtocolStat[]
}

/**
 * Protocol breakdown from the `packets` table inside the window (M16.3).
 *
 * Each entry's `percentage` is a share of `total_packets` — the whole population
 * the window selected — not of the returned rows. When `distinct_protocols`
 * exceeds `count` the list was cut to the ranking's limit, `truncated` is true,
 * and the shares deliberately do not sum to `100`: they are shares of the
 * window, and the window was not truncated.
 */
export interface StoredProtocolsData {
  readonly count: number
  readonly distinct_protocols: number
  readonly truncated: boolean
  readonly total_packets: number
  readonly total_bytes: number
  readonly rank_by: RankMetric
  readonly protocols: readonly ProtocolStat[]
}

/**
 * Devices seen inside the window, from the M8 registry (M16.4).
 *
 * The window filters on a device's `last_seen`, and the registry holds no
 * history: these are the *current* records that fall in the window, not a
 * reconstruction of what was observed then. No risk score appears, because M8
 * computes none, and the routed-traffic limitation on device identity is
 * unchanged — a device id can be a next hop rather than the remote host.
 */
export interface DeviceWindowData {
  readonly total: number
  readonly by_status: Readonly<Record<string, number>>
  readonly rank_by: RankMetric
  readonly top: readonly RankedDevice[]
}

/**
 * Conversations read from the `connections` table (M16.5).
 *
 * The window selects conversations whose `start_time` falls inside it — M9's own
 * rule for the same filter. `active` counts stored rows still marked `active`,
 * which is a different figure from the live tracker counter at the top of the
 * response.
 *
 * `duration` describes only the conversations that ended, and `by_protocol` is
 * *not* zero-filled: a protocol no conversation used is simply absent, whereas
 * `by_status` names every state M9 can write.
 */
export interface StoredConnectionsData {
  readonly total: number
  readonly active: number
  readonly first_timestamp: string | null
  readonly last_timestamp: string | null
  readonly by_protocol: Readonly<Record<string, number>>
  readonly by_status: Readonly<Record<string, number>>
  readonly duration: DurationStats
  readonly series: readonly ConnectionSeriesPoint[]
  readonly top_sources: readonly TopEntry[]
  readonly top_destinations: readonly TopEntry[]
}

/**
 * Alerts read from the `alerts` table inside the window (M16.6).
 *
 * Every vocabulary is named in full even when it holds no rows, so a page
 * renders fixed rows rather than discovering a missing key. The three notions of
 * "how bad" stay in three fields: `by_severity` is M11's judgement,
 * `by_confidence_range` is how strongly M11 believed its evidence, and
 * `by_risk_band` is M12's prioritisation metric.
 *
 * One caveat on `by_risk_band`: M11 writes `risk_score = 0` and leaves it until
 * M12 correlates the alert, so an alert no incident has reached is banded
 * `minimal`. That is the truthful reading of its stored score, but it means "not
 * yet scored" rather than "assessed as minimal". The live incident block is
 * where a scored judgement is reported.
 *
 * `without_rule_key` counts alerts carrying no correlation key, so they appear
 * in no entry of `rules` — reported separately so the ranking's coverage is
 * visible rather than silently short.
 */
export interface StoredAlertsData {
  readonly total: number
  readonly without_rule_key: number
  readonly first_timestamp: string | null
  readonly last_timestamp: string | null
  readonly by_severity: Readonly<Record<string, number>>
  readonly by_status: Readonly<Record<string, number>>
  readonly by_risk_band: Readonly<Record<string, number>>
  readonly by_confidence_range: Readonly<Record<string, number>>
  readonly rules: readonly ThreatRuleCount[]
  readonly series: readonly AlertSeriesPoint[]
}
