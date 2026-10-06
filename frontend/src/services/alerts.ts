/**
 * Alert service (M11, M15.14–M15.16).
 *
 * An alert is M11's judgement: a severity, an evidence-strength `confidence`, a
 * lifecycle state and references to the evidence that supports it. This module
 * reads them and moves them, and does nothing else.
 *
 * **Lifecycle rules are not implemented here.** Which moves are legal is
 * `app/alerts/status.VALID_TRANSITIONS`, and every write below posts to an
 * endpoint that validates against that table and answers `409 INVALID_TRANSITION`
 * for a move it refuses (M15.15). The frontend may *offer* only reachable actions
 * — `ALERT_TRANSITIONS` in `@/types` mirrors the table for that purpose — but it
 * must never decide the outcome. A rejected transition is reported to the user,
 * not routed around.
 *
 * Two spellings of the same move exist server-side: the named routes
 * (`/acknowledge`, `/resolve`, …) and the body-carrying `POST /{id}/status`. Both
 * delegate to one transition table, so this module uses the named routes for the
 * four button actions and keeps `setAlertStatus` for a caller that already has a
 * target state.
 */

import { apiGet, apiPost } from './client'
import { AlertPaths } from './endpoints'
import { withPageWindow, type PageWindow } from './query'
import type {
  Alert,
  AlertDetail,
  AlertDiagnostics,
  AlertLifecycleAction,
  AlertPage,
  AlertQuery,
  AlertStatus,
  AlertSummary,
  EvidenceList,
  EvidenceType,
} from '@/types'

/** `GET /api/v1/alerts` — stored alerts, newest first (M11.18). */
export function fetchAlerts(
  query: AlertQuery = {},
  window?: PageWindow,
  signal?: AbortSignal,
): Promise<AlertPage> {
  // The alert listing is the one collection whose page window is carried as
  // plain `limit`/`offset` rather than through the shared helper, because its
  // own maximum is `alert_max_page_size` and it accepts no unbounded request.
  return apiGet<AlertPage>(AlertPaths.list, withPageWindow(query, window), { signal })
}

/** `GET /api/v1/alerts/{alert_id}` — one alert with its evidence (M11.18). */
export function fetchAlert(alertId: number, signal?: AbortSignal): Promise<AlertDetail> {
  return apiGet<AlertDetail>(AlertPaths.detail(alertId), undefined, { signal })
}

/**
 * `GET /api/v1/alerts/summary` — counts by severity and status.
 *
 * Every severity is reported even at zero, so a client renders fixed rows rather
 * than treating a missing key as "none".
 */
export function fetchAlertSummary(signal?: AbortSignal): Promise<AlertSummary> {
  return apiGet<AlertSummary>(AlertPaths.summary, undefined, { signal })
}

/**
 * `GET /api/v1/alerts/diagnostics` — the alert engine's process-wide counters.
 *
 * These describe the *engine* (findings seen, alerts created, duplicates folded)
 * beside the stored totals, which is why they are a separate model from the
 * summary rather than a superset of it.
 */
export function fetchAlertDiagnostics(signal?: AbortSignal): Promise<AlertDiagnostics> {
  return apiGet<AlertDiagnostics>(AlertPaths.diagnostics, undefined, { signal })
}

/**
 * `GET /api/v1/alerts/{alert_id}/evidence` — one alert's evidence (M15.16).
 *
 * Each record is a *reference* — a packet id, a connection id, a device id — plus
 * a small document describing why. Nothing here inlines the referenced packet,
 * and the caller must not go looking for a payload that was deliberately never
 * stored (M11.13).
 *
 * A missing alert is a `404` rather than an empty list, so "this alert has no
 * evidence of that kind" and "there is no such alert" stay distinguishable.
 */
export function fetchAlertEvidence(
  alertId: number,
  evidenceType?: EvidenceType,
  signal?: AbortSignal,
): Promise<EvidenceList> {
  return apiGet<EvidenceList>(
    AlertPaths.evidence(alertId),
    evidenceType === undefined ? undefined : { evidence_type: evidenceType },
    { signal },
  )
}

/** The path builder for each named lifecycle endpoint (M13.13). */
const LIFECYCLE_PATHS: Readonly<Record<AlertLifecycleAction, (alertId: number) => string>> = {
  acknowledge: AlertPaths.acknowledge,
  resolve: AlertPaths.resolve,
  dismiss: AlertPaths.dismiss,
  'false-positive': AlertPaths.falsePositive,
}

/**
 * Apply one named lifecycle action and return the updated alert.
 *
 * The named endpoints carry no body, which is why this is a `POST` with nothing
 * in it: the target state is the route. A refusal arrives as a `409` whose
 * `userMessage` already explains that the move is not allowed from the alert's
 * current state, so the caller renders the error rather than guessing at it.
 */
export function applyAlertLifecycle(
  alertId: number,
  action: AlertLifecycleAction,
  signal?: AbortSignal,
): Promise<Alert> {
  return apiPost<Alert>(LIFECYCLE_PATHS[action](alertId), { signal })
}

/**
 * `POST /api/v1/alerts/{alert_id}/status` — move an alert to a chosen state.
 *
 * A move to the state the alert is already in is accepted as a no-op by the
 * backend, so a double click is harmless. Any other illegal move is a `409` and
 * leaves the stored alert untouched.
 */
export function setAlertStatus(
  alertId: number,
  status: AlertStatus,
  signal?: AbortSignal,
): Promise<Alert> {
  return apiPost<Alert>(AlertPaths.status(alertId), { body: { status }, signal })
}
