/**
 * Detection service (M10, M15.20).
 *
 * A finding is an **observation**, not a verdict: no severity, no lifecycle, no
 * risk. This service therefore exposes only reads, because M10 offers nothing
 * else — the single `POST` it publishes clears in-memory state for verification
 * rather than changing a finding.
 *
 * The distinction the UI must keep (M15.20): a finding and an alert are different
 * things, and the findings list is not "alerts that have not been triaged". Only
 * some findings raise an alert, and which ones is M11's decision.
 *
 * Two endpoints resolve to `404` for reasons that are not errors: a finding that
 * has aged out of the engine's bounded history (M10.19) is no longer retained,
 * and that is the honest answer rather than an empty object.
 */

import { apiGet, apiPost } from './client'
import { DetectionPaths } from './endpoints'
import { withPageWindow, type PageWindow } from './query'
import type {
  DetectionDiagnostics,
  DetectionFinding,
  DetectionFindingPage,
  DetectionQuery,
  DetectionRuleList,
} from '@/types'

/** `GET /api/v1/detections` — retained findings, newest first (M13.12). */
export function fetchDetections(
  query: DetectionQuery = {},
  window?: PageWindow,
  signal?: AbortSignal,
): Promise<DetectionFindingPage> {
  return apiGet<DetectionFindingPage>(
    DetectionPaths.list,
    withPageWindow(query, window),
    { signal },
  )
}

/**
 * `GET /api/v1/detections/{finding_id}` — one retained finding.
 *
 * An id that has aged out of the retention cap answers `404`, which the caller
 * renders as "no longer retained" rather than as a failed request.
 */
export function fetchDetection(
  findingId: string,
  signal?: AbortSignal,
): Promise<DetectionFinding> {
  return apiGet<DetectionFinding>(
    DetectionPaths.detail(findingId),
    undefined,
    { signal },
  )
}

/**
 * `GET /api/v1/detections/rules` — every registered detector, plus diagnostics.
 *
 * Diagnostics ride along because "which detectors exist" and "are they actually
 * being evaluated" are two halves of one question; reading them separately would
 * describe two different instants.
 */
export function fetchDetectionRules(signal?: AbortSignal): Promise<DetectionRuleList> {
  return apiGet<DetectionRuleList>(DetectionPaths.rules, undefined, { signal })
}

/**
 * `POST /api/v1/detections/reset` — discard retained findings and counters.
 *
 * The M10.22 development helper. It clears in-memory observation state only and
 * turns no detector on or off, so it is safe against a development backend.
 */
export function resetDetections(signal?: AbortSignal): Promise<DetectionDiagnostics> {
  return apiPost<DetectionDiagnostics>(DetectionPaths.reset, { signal })
}
