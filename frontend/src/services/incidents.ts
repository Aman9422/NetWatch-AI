/**
 * Incident service (M12, M15.17–M15.19).
 *
 * An incident is what several related events add up to. It carries **three
 * numbers that must never be conflated** (M12.16):
 *
 * * `risk_score` / `risk_band` — the bounded `0..100` prioritisation metric;
 * * `correlation_confidence` — how strongly the events were judged related;
 * * `alert_confidence` — the mean of the member alerts' own evidence strengths.
 *
 * None of them is computed here. `risk_score` is written onto the incident by M12's
 * scoring engine through `with_risk`, and this module reads it as stored — a
 * second implementation would disagree with the alert rows it was written onto
 * (M12.24/M15.17).
 *
 * **Lifecycle rules are not implemented here either.** `investigate`, `resolve`
 * and `dismiss` all delegate to `app/correlation/status.VALID_TRANSITIONS`; an
 * illegal move is a `409` and the caller shows it rather than working around it
 * (M15.19). There is deliberately no "reopen": reopening would edit a conclusion
 * that was already recorded.
 *
 * Timestamps arrive in two forms on purpose — epoch seconds, which M12 reasons
 * in, and ISO-8601 UTC strings, which a client displays. The detail view carries
 * both; the summary carries epoch only.
 */

import { apiGet, apiPost } from './client'
import { IncidentPaths } from './endpoints'
import { withPageWindow, type PageWindow } from './query'
import type {
  Incident,
  IncidentLifecycleAction,
  IncidentPage,
  IncidentQuery,
} from '@/types'

/**
 * `GET /api/v1/incidents` — correlated incidents matching the filters (M13.15).
 *
 * `since`/`until` select an incident whose `[start_time, last_seen]` extent
 * *overlaps* the window, so an incident that began earlier but was still active
 * inside the range is included. Both are ISO-8601; the backend converts them to
 * the epoch seconds M12 reasons in.
 */
export function fetchIncidents(
  query: IncidentQuery = {},
  window?: PageWindow,
  signal?: AbortSignal,
): Promise<IncidentPage> {
  return apiGet<IncidentPage>(
    IncidentPaths.list,
    withPageWindow(query, window),
    { signal },
  )
}

/**
 * `GET /api/v1/incidents/open` — the incidents still needing attention, riskiest
 * first.
 *
 * "Open" is the backend's own `ACTIVE_STATUSES` — `open` and `investigating` —
 * which is the same definition the `active_only` filter uses, so the two views
 * cannot disagree.
 */
export function fetchOpenIncidents(
  window?: PageWindow,
  signal?: AbortSignal,
): Promise<IncidentPage> {
  return apiGet<IncidentPage>(IncidentPaths.open, withPageWindow({}, window), { signal })
}

/**
 * `GET /api/v1/incidents/{incident_id}` — one incident with its full membership.
 *
 * Adds what the listing omits: every member alert, finding, device and connection
 * reference, the correlation reason trail explaining *why* the events were judged
 * related, and the ISO-8601 forms of every timestamp.
 */
export function fetchIncident(
  incidentId: string,
  signal?: AbortSignal,
): Promise<Incident> {
  return apiGet<Incident>(IncidentPaths.detail(incidentId), undefined, { signal })
}

/** The path builder for each named incident lifecycle endpoint (M13.16). */
const LIFECYCLE_PATHS: Readonly<
  Record<IncidentLifecycleAction, (incidentId: string) => string>
> = {
  investigate: IncidentPaths.investigate,
  resolve: IncidentPaths.resolve,
  dismiss: IncidentPaths.dismiss,
}

/**
 * Apply one incident lifecycle action and return the updated incident.
 *
 * A refused move — an illegal transition, or any move out of a terminal state —
 * answers `409 INVALID_TRANSITION` and leaves the incident untouched. The caller
 * renders that refusal; it must not assume the move succeeded.
 */
export function applyIncidentLifecycle(
  incidentId: string,
  action: IncidentLifecycleAction,
  signal?: AbortSignal,
): Promise<Incident> {
  return apiPost<Incident>(LIFECYCLE_PATHS[action](incidentId), { signal })
}
