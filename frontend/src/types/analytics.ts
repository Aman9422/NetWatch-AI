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

/** One device in a traffic ranking (M13.18). */
export interface RankedDevice {
  readonly device_id: string
  readonly mac_address: string | null
  readonly ip_addresses: readonly string[]
  readonly hostname: string | null
  /** M8 activity state, not a security verdict. */
  readonly status: string
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
}

/** `GET /api/v1/analytics/protocols` (M13.18). */
export interface AnalyticsProtocols {
  readonly count: number
  readonly total_packets: number
  readonly total_bytes: number
  readonly rank_by: RankMetric
  readonly protocols: readonly ProtocolStat[]
}

/** `GET /api/v1/analytics/devices` (M13.18). */
export interface AnalyticsDevices {
  readonly total: number
  readonly by_status: Readonly<Record<string, number>>
  readonly rank_by: RankMetric
  readonly top: readonly RankedDevice[]
}

/** `GET /api/v1/analytics/connections` (M13.18). */
export interface AnalyticsConnections {
  readonly active: number
  readonly historical: number
  readonly tracked: number
  readonly rank_by: RankMetric
  readonly top: readonly RankedConnection[]
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
