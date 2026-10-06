/**
 * Detection, alert, evidence and incident models (M15.6).
 *
 * The single most important thing this module encodes is that **three separate
 * "how bad" numbers exist and none of them is the others** (M12.16):
 *
 * * `severity` — M11's four-level judgement of how serious the *behaviour* is;
 * * `confidence` — M11's evidence strength for one alert, a `0..1` float that is
 *   deliberately *not* a percentage and *not* a risk score;
 * * `risk_score` — M12's bounded `0..100` prioritisation metric, with
 *   `risk_band` its documented display band.
 *
 * An incident additionally carries `correlation_confidence` (how strongly the
 * events were judged related) beside `alert_confidence` (the mean of its member
 * alerts' own evidence strengths). The UI must keep all three visually separate
 * (M15.17) and must never render one in the other's place.
 *
 * A **finding is not an alert** (M15.20). Findings have no severity, no lifecycle
 * and no risk — they are M10's raw observations — so they are modelled separately
 * rather than as a "pre-alert".
 */

import type { PageMeta } from './api'

// ── Detection findings (M10) ────────────────────────────────────────────────

/** A scalar an evidence document may hold. */
export type EvidenceValue = string | number | boolean | null

/**
 * One detection finding (M10.5) — an observation, never a verdict.
 *
 * The nullable fields are declared **optional as well as nullable**, and that is
 * not over-caution: `app/api/v1/detections.py` serialises the listing with
 * `model_dump(exclude_none=True)`, so an unset address or timestamp is *absent*
 * from the JSON rather than present as `null`. A model declaring them required
 * would type them as `string | null` while the value is really `undefined`, which
 * is exactly the kind of lie that turns into `undefined` on screen.
 */
export interface DetectionFinding {
  readonly finding_id: string
  readonly rule_id: string
  readonly rule_name: string
  /** ISO-8601 UTC. Absent when the detector recorded no instant. */
  readonly timestamp?: string | null
  readonly source_ip?: string | null
  readonly destination_ip?: string | null
  readonly source_device_id?: string | null
  readonly destination_device_id?: string | null
  readonly protocol?: string | null
  readonly description: string
  readonly evidence: Readonly<Record<string, EvidenceValue>>
  /** Evidence strength, `0..1`. Never a risk score. */
  readonly confidence: number
  readonly metadata: Readonly<Record<string, EvidenceValue>>
}

/** Payload of `GET /api/v1/detections` (M13.12/M13.24). */
export interface DetectionFindingPage extends PageMeta {
  readonly total: number
  readonly findings: readonly DetectionFinding[]
}

/** Execution counters behind the detector table (M10.6/M10.17). */
export interface DetectionDiagnostics {
  readonly evaluations: number
  readonly findings: number
  readonly errors: number
  readonly enabled_rules: number
  readonly registered_rules: number
  readonly retained_findings: number
}

/** One registered detector (M10.22). */
export interface DetectionRule {
  readonly rule_id: string
  readonly rule_name: string
  readonly description: string
  readonly enabled: boolean
  readonly window_seconds: number | null
  readonly state_size: number
}

/** Payload of `GET /api/v1/detections/rules`. */
export interface DetectionRuleList {
  readonly count: number
  readonly rules: readonly DetectionRule[]
  readonly diagnostics: DetectionDiagnostics
}

/** Filters accepted by `GET /api/v1/detections`. */
export interface DetectionQuery {
  readonly rule_id?: string
  readonly source_ip?: string
  readonly destination_ip?: string
  readonly device_id?: string
  /** ISO-8601 UTC, inclusive. */
  readonly since?: string
  /** ISO-8601 UTC, exclusive. */
  readonly until?: string
  readonly limit?: number
  readonly offset?: number
}

// ── Alerts (M11) ────────────────────────────────────────────────────────────

/** The four alert severity levels, ordered `low` → `critical` (M11.4). */
export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical'

/** The five alert lifecycle states (M11.6). */
export type AlertStatus =
  | 'open'
  | 'acknowledged'
  | 'resolved'
  | 'dismissed'
  | 'false_positive'

/** States that still need attention (`app/alerts/status.ACTIVE_STATUSES`). */
export const ACTIVE_ALERT_STATUSES: readonly AlertStatus[] = ['open', 'acknowledged']

/** States nothing may follow (`app/alerts/status.TERMINAL_STATUSES`). */
export const TERMINAL_ALERT_STATUSES: readonly AlertStatus[] = [
  'resolved',
  'dismissed',
  'false_positive',
]

/**
 * The lifecycle moves `app/alerts/status.VALID_TRANSITIONS` allows.
 *
 * Present so the UI can *offer* only reachable actions. The backend remains the
 * authority — this table exists to avoid showing a button that is guaranteed to
 * be refused, not to replace the validation the server performs (M15.15).
 */
export const ALERT_TRANSITIONS: Readonly<Record<AlertStatus, readonly AlertStatus[]>> = {
  open: ['acknowledged', 'resolved', 'dismissed', 'false_positive'],
  acknowledged: ['resolved', 'dismissed', 'false_positive'],
  resolved: [],
  dismissed: [],
  false_positive: [],
}

/** The named lifecycle endpoints M13.13 serves, keyed by target state. */
export type AlertLifecycleAction =
  | 'acknowledge'
  | 'resolve'
  | 'dismiss'
  | 'false-positive'

/** One alert (M11.3). */
export interface Alert {
  readonly alert_id: number
  /** The detector's stable rule id, recovered from the dedup key. */
  readonly rule_id: string
  readonly title: string
  readonly description: string
  readonly severity: AlertSeverity
  /** Evidence strength, `0..1`. Never a risk score. */
  readonly confidence: number
  readonly status: AlertStatus
  /** ISO-8601 UTC. */
  readonly created_at: string | null
  readonly updated_at: string | null
  readonly resolved_at: string | null
  readonly source_ip: string | null
  readonly destination_ip: string | null
  readonly source_device_id: string | null
  readonly destination_device_id: string | null
  readonly protocol: string | null
  readonly connection_id: string | null
  /** The M10 finding that raised this alert (M11.7). */
  readonly finding_id: string | null
  readonly evidence_count: number
  readonly correlation_key: string | null
}

/** Payload of `GET /api/v1/alerts` (M11.18/M13.24). */
export interface AlertPage {
  readonly count: number
  /** The match count, not the page size. */
  readonly total: number
  readonly limit?: number | null
  readonly offset: number
  readonly has_more?: boolean | null
  readonly alerts: readonly Alert[]
}

/** One evidence record attached to an alert (M11.11). */
export interface AlertEvidence {
  readonly evidence_type: string
  /** A *reference* to a packet row, when this is packet evidence. */
  readonly packet_id: number | null
  /** ISO-8601 UTC. */
  readonly created_at: string | null
  readonly data: Readonly<Record<string, EvidenceValue>>
}

/** Payload of `GET /api/v1/alerts/{id}` (M11.18). */
export interface AlertDetail {
  readonly alert: Alert
  readonly evidence: readonly AlertEvidence[]
  readonly evidence_by_type: Readonly<Record<string, number>>
}

/** Counts by severity and status (M11.18). */
export interface AlertSummary {
  readonly total: number
  readonly by_severity: Readonly<Record<string, number>>
  readonly by_status: Readonly<Record<string, number>>
}

/** The alert engine's execution counters (M11.31). */
export interface AlertDiagnostics extends AlertSummary {
  readonly enabled: boolean
  readonly findings_seen: number
  readonly alerts_created: number
  readonly duplicates_folded: number
  readonly unsupported_findings: number
  readonly errors: number
  readonly transitions: number
}

/** Filters accepted by `GET /api/v1/alerts`. */
export interface AlertQuery {
  readonly severity?: AlertSeverity
  readonly min_severity?: AlertSeverity
  readonly status?: readonly AlertStatus[]
  readonly rule_id?: number
  readonly rule_key?: string
  readonly source_ip?: string
  readonly destination_ip?: string
  /** ISO-8601 UTC, inclusive. */
  readonly since?: string
  /** ISO-8601 UTC, exclusive. */
  readonly until?: string
  readonly limit?: number
  readonly offset?: number
}

/** Body of `POST /api/v1/alerts/{id}/status` (M11.19). */
export interface AlertLifecycleRequest {
  readonly status: AlertStatus
}

// ── Evidence (M13.14) ───────────────────────────────────────────────────────

/** Payload of `GET /api/v1/alerts/{alert_id}/evidence`. */
export interface EvidenceList {
  readonly alert_id: number
  readonly count: number
  readonly evidence: readonly AlertEvidence[]
}

/** Payload of `GET /api/v1/evidence/{evidence_id}`. */
export interface EvidenceDetail {
  readonly evidence_id: number
  /** The alert this evidence supports, so a reference is navigable both ways. */
  readonly alert_id: number
  readonly evidence: AlertEvidence
}

/** The evidence kinds a caller may filter by (M11.11). */
export type EvidenceType = 'rule' | 'behavioral' | 'packet' | 'connection' | 'device'
// ── Incidents (M12) ─────────────────────────────────────────────────────────

/** The four correlated-incident states (M12.9). */
export type IncidentStatus = 'open' | 'investigating' | 'resolved' | 'dismissed'

/** States that still accept newly correlated events (M12.26). */
export const ACTIVE_INCIDENT_STATUSES: readonly IncidentStatus[] = [
  'open',
  'investigating',
]

/**
 * The incident lifecycle moves `app/correlation/status.VALID_TRANSITIONS` allows.
 *
 * Mirrors {@link ALERT_TRANSITIONS} deliberately: an operator who has learned one
 * lifecycle already knows the other. As with alerts, the server validates; this
 * table only decides which actions to offer (M15.19).
 */
export const INCIDENT_TRANSITIONS: Readonly<
  Record<IncidentStatus, readonly IncidentStatus[]>
> = {
  open: ['investigating', 'resolved', 'dismissed'],
  investigating: ['resolved', 'dismissed'],
  resolved: [],
  dismissed: [],
}

/** The three named incident lifecycle endpoints M13.15 serves. */
export type IncidentLifecycleAction = 'investigate' | 'resolve' | 'dismiss'

/**
 * One incident as a listing row (M12.26).
 *
 * Carries both confidences and the score; the member lists are what the detail
 * view adds. Timestamps are epoch seconds here, because that is what M12 reasons
 * in — the ISO-8601 forms arrive only on the detail view.
 */
export interface IncidentSummary {
  readonly incident_id: string
  readonly title: string
  readonly status: string
  /** Epoch seconds. */
  readonly start_time: number
  /** Epoch seconds. */
  readonly last_seen: number
  readonly event_count: number
  readonly alert_count: number
  readonly finding_count: number
  readonly device_ids: readonly string[]
  /** How strongly the events were judged related, `0..1` (M12.16). */
  readonly correlation_confidence: number
  /** The mean of the member alerts' own evidence strengths, `0..1` (M12.16). */
  readonly alert_confidence: number
  /** Worst member severity, or `null` when unmeasured. */
  readonly severity: string | null
  /** The bounded `0..100` prioritisation metric (M12.14). */
  readonly risk_score: number
  readonly risk_band: string
}

/**
 * One incident with its full membership (M12.26).
 *
 * Timestamps are present twice on purpose: epoch seconds, which M12 reasons in,
 * and ISO-8601 UTC strings, which a client displays (M13.26).
 */
export interface Incident extends IncidentSummary {
  /** Epoch seconds. */
  readonly created_at: number
  readonly updated_at: number
  readonly created_at_iso: string | null
  readonly updated_at_iso: string | null
  readonly start_time_iso: string | null
  readonly last_seen_iso: string | null
  readonly span_seconds: number
  /** Events counted but not retained because a membership cap was reached. */
  readonly dropped_events: number
  readonly alert_ids: readonly number[]
  readonly finding_ids: readonly string[]
  readonly connection_ids: readonly string[]
  readonly rule_ids: readonly string[]
  readonly correlation_rule_ids: readonly string[]
  /** Human-readable reasons the events were judged related (M12.6). */
  readonly correlation_reasons: readonly string[]
}

/** Payload of the incident collection endpoints (M13.15/M13.24). */
export interface IncidentPage {
  readonly count: number
  readonly limit?: number | null
  readonly offset: number
  readonly total?: number | null
  readonly has_more?: boolean | null
  readonly incidents: readonly IncidentSummary[]
}

/** The order an incident listing may be requested in (M13.15). */
export type IncidentOrder = 'recent' | 'risk'

/** Filters accepted by `GET /api/v1/incidents`. */
export interface IncidentQuery {
  readonly status?: IncidentStatus
  readonly active_only?: boolean
  readonly source?: string
  readonly device_id?: string
  readonly connection_id?: string
  readonly rule_id?: string
  readonly correlation_rule_id?: string
  readonly min_risk_score?: number
  readonly max_risk_score?: number
  readonly min_confidence?: number
  /** ISO-8601 UTC. */
  readonly since?: string
  /** ISO-8601 UTC. */
  readonly until?: string
  readonly order?: IncidentOrder
  readonly limit?: number
  readonly offset?: number
}

// ── Risk bands (M12.27) ─────────────────────────────────────────────────────

/** The four documented display bands for a risk score (M12.27). */
export type RiskBand = 'minimal' | 'low' | 'moderate' | 'high'

/**
 * The inclusive bounds each band covers, tiling `0..100`.
 *
 * Read from `app/risk/bands.BAND_RANGES`. Defined here so a chart axis or a
 * legend can be labelled without the frontend inventing its own thresholds —
 * which would let the UI and the API disagree about what "moderate" means.
 */
export const RISK_BAND_RANGES: Readonly<Record<RiskBand, readonly [number, number]>> = {
  minimal: [0, 24],
  low: [25, 49],
  moderate: [50, 74],
  high: [75, 100],
}

/** The band a score falls in, clamped to `0..100` first (M12.27). */
export function riskBandFor(score: number): RiskBand {
  const bounded = Math.max(0, Math.min(100, Math.round(score)))
  if (bounded >= 75) return 'high'
  if (bounded >= 50) return 'moderate'
  if (bounded >= 25) return 'low'
  return 'minimal'
}

/** Severity order, least serious first (M11.4). */
export const ALERT_SEVERITY_ORDER: readonly AlertSeverity[] = [
  'low',
  'medium',
  'high',
  'critical',
]

/** Return the rank of a severity, `1` (low) to `4` (critical). */
export function severityRank(severity: AlertSeverity): number {
  return ALERT_SEVERITY_ORDER.indexOf(severity) + 1
}
