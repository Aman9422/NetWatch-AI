/**
 * System, settings, report and notification models (M15.6).
 *
 * Three deliberate absences, each of which a page must not paper over:
 *
 * * **The database is described by dialect, never by URL.** `app/schemas/system.py`
 *   withholds the connection string because it is a path or a credential-bearing
 *   DSN, and M13.30 forbids returning either. There is no field here to leak one.
 * * **A report exposes metadata, never a location.** `file_path` is absent from
 *   every model, structurally (`app/schemas/report.py`). M17 owns generation, so
 *   there is no "download" the API could honour (M15.22).
 * * **A notification has no delivery state.** The base application has no
 *   external notification integration, so no `sent`, `channel` or `delivered_at`
 *   exists — a field implying otherwise would claim a subsystem that does not
 *   exist (M13.23).
 */

import type { PageMeta } from './api'

// ── System (M13.22) ─────────────────────────────────────────────────────────

/** Whether one pipeline stage is switched on and attached (M13.22). */
export interface ServiceState {
  readonly name: string
  /** The configuration switch. */
  readonly enabled: boolean
  /** Whether the running pipeline actually holds it, when known. */
  readonly attached: boolean | null
}

/** Reachability and flavour of the database — never its URL (M13.22). */
export interface DatabaseState {
  readonly reachable: boolean
  /** Engine family, e.g. `sqlite`. */
  readonly dialect: string
}

/** Capture state as the system endpoints report it (M13.22). */
export interface SystemCaptureState {
  readonly running: boolean
  readonly status: string
  readonly interface: string | null
  readonly packet_count: number
  readonly processed_packet_count: number
  readonly error_counts: Readonly<Record<string, number>>
}

/** Basic runtime facts about the process (M13.22). */
export interface RuntimeMetrics {
  /** `null` when startup was never recorded — which is not "zero seconds". */
  readonly uptime_seconds: number | null
  /** ISO-8601 UTC. */
  readonly started_at: string | null
  /** ISO-8601 UTC instant of the response. */
  readonly generated_at: string
  readonly python_version: string
  readonly pid: number
}

/** Application identity and environment (M13.22). */
export interface SystemInfo {
  readonly app_name: string
  readonly app_version: string
  readonly environment: string
  readonly api_version: string
  readonly timezone: string
  readonly platform: string
  readonly database_dialect: string
  readonly registered_route_count: number | null
  readonly docs_url: string | null
  readonly openapi_url: string | null
}

/** The verdict of one health probe (M13.22). */
export interface HealthCheck {
  readonly name: string
  readonly ok: boolean
  /** A short, safe sentence naming which dependency failed. */
  readonly detail: string
}

/** `GET /api/v1/system/health` (M13.22). */
export interface SystemHealth {
  /** `healthy` when every probe passed, `degraded` otherwise. */
  readonly status: string
  readonly checks: readonly HealthCheck[]
}

/** `GET /api/v1/system/status` — process, database and pipeline in one view. */
export interface SystemStatus {
  readonly status: string
  readonly info: SystemInfo
  readonly capture: SystemCaptureState
  readonly database: DatabaseState
  readonly services: readonly ServiceState[]
  readonly runtime: RuntimeMetrics
}

// ── Settings (M13.21) ───────────────────────────────────────────────────────

/** A setting's decoded value. */
export type SettingValue =
  | string
  | number
  | boolean
  | Readonly<Record<string, unknown>>
  | readonly unknown[]
  | null

/** One readable setting (M13.21). */
export interface Setting {
  readonly key: string
  readonly value: SettingValue
  readonly data_type: string
  /** Whether `PUT /settings` will accept this key. */
  readonly mutable: boolean
  /** ISO-8601 UTC. */
  readonly updated_at: string | null
}

/** `GET /api/v1/settings` (M13.21). */
export interface SettingList {
  readonly count: number
  readonly settings: readonly Setting[]
  /** Every key `PUT /settings` accepts, in a stable order. */
  readonly mutable_keys: readonly string[]
  /** How many stored keys are withheld as internal-only. */
  readonly internal_key_count: number
}

/** Body of `PUT /api/v1/settings` (M13.21). */
export interface SettingUpdateRequest {
  readonly values: Readonly<Record<string, string | number | boolean>>
}

/** Payload returned by `PUT /api/v1/settings` (M13.21). */
export interface SettingUpdateResult {
  readonly updated: readonly Setting[]
  /**
   * True because stored settings are applied at application startup rather than
   * to the running process. The UI must state this rather than implying the
   * change took effect (M15.23).
   */
  readonly restart_required: boolean
}

// ── Reports (M13.20) ────────────────────────────────────────────────────────

/** One stored report's metadata (M13.20). Never its file location. */
export interface Report {
  readonly report_id: number
  readonly name: string
  readonly report_type: string
  readonly format: string
  readonly generated_by: number | null
  /** ISO-8601 UTC. */
  readonly generated_at: string | null
  /** The same instant in epoch seconds (M13.26). */
  readonly generated_at_epoch: number | null
}

/** `GET /api/v1/reports` (M13.20). */
export interface ReportList {
  readonly count: number
  readonly total: number
  readonly limit?: number | null
  readonly offset: number
  readonly has_more?: boolean | null
  readonly reports: readonly Report[]
}

// ── Notifications (M13.23) ──────────────────────────────────────────────────

/** One stored notification (M13.23). No delivery state exists. */
export interface Notification {
  readonly notification_id: number
  readonly user_id: number | null
  readonly title: string
  readonly message: string
  readonly notification_type: string
  readonly is_read: boolean
  /** ISO-8601 UTC. */
  readonly created_at: string | null
  readonly created_at_epoch: number | null
}

/** `GET /api/v1/notifications` (M13.23). */
export interface NotificationList extends PageMeta {
  readonly total: number
  readonly notifications: readonly Notification[]
}

/** `GET /api/v1/notifications` filters. */
export interface NotificationQuery {
  readonly unread_only?: boolean
  readonly limit?: number
  readonly offset?: number
}

// ── Baselines (M13) ─────────────────────────────────────────────────────────

/**
 * One device's observed baseline.
 *
 * Modelled loosely because M13 exposes this endpoint without documenting a strict
 * schema; the page that renders it reads named fields and tolerates a missing one
 * rather than asserting a shape the backend never promised.
 */
export interface Baseline {
  readonly device_id: string
  readonly [key: string]: unknown
}
