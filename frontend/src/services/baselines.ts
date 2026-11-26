/**
 * Behavioural baseline service (M21.10).
 *
 * Three calls over the M21 engine, and the same restraint as `devices.ts`: nothing
 * returned here is a verdict. A baseline is a statistical description of behaviour
 * a device has already been observed producing, and every payload carries the
 * backend's own `disclaimer` sentence saying so (M21.7).
 *
 * * `fetchBaselines` — a page of learnt baselines, optionally narrowed to one
 *   learning state. A device that has been discovered but has not yet completed an
 *   aggregation window has no baseline and is **absent from this listing** rather
 *   than present with zeroes (M21.7). The page says so instead of rendering a
 *   fabricated row.
 * * `fetchBaseline` — one device's profile plus the bounded set of observation
 *   windows it was calculated from.
 * * `resetBaseline` — discard one device's windows and profile so learning
 *   restarts. It touches the two M21 tables and nothing else (M21.10).
 *
 * `resetBaseline` answers `200` even when there was nothing to delete, so its
 * result always says what actually happened in `windows_deleted` and
 * `profile_deleted` rather than leaving the caller to infer it from a status code.
 */

import { apiGet, apiPost } from './client'
import { BaselinePaths } from './endpoints'
import { withPageWindow, type PageWindow } from './query'
import type {
  Baseline,
  BaselinePage,
  BaselineQuery,
  BaselineResetResult,
} from '@/types'

/**
 * `GET /api/v1/baselines` — a page of learnt baselines (M21.10).
 *
 * `total` is present because the engine can count its profiles, so a caller may
 * render "showing 20 of 43" without a second request.
 */
export function fetchBaselines(
  query: BaselineQuery = {},
  window?: PageWindow,
  signal?: AbortSignal,
): Promise<BaselinePage> {
  return apiGet<BaselinePage>(BaselinePaths.list, withPageWindow(query, window), {
    signal,
  })
}

/**
 * `GET /api/v1/baselines/{device_key}` — one device's baseline (M21.10).
 *
 * The detail response carries `recent_windows`, which the listing does not: the
 * samples exist to show what the profile was calculated from.
 *
 * A device with no baseline yet answers `404`. That is a real answer rather than a
 * fault — the device has been discovered but has produced no complete observation
 * window — and the page renders it as "nothing observed yet" rather than as a
 * failed request.
 */
export function fetchBaseline(
  deviceKey: string,
  signal?: AbortSignal,
): Promise<Baseline> {
  return apiGet<Baseline>(BaselinePaths.detail(deviceKey), undefined, { signal })
}

/**
 * `POST /api/v1/baselines/{device_key}/reset` — re-learn this device (M21.10).
 *
 * No body: the device key in the path is the whole request. The operation deletes
 * only this device's observation windows and profile, so packets, devices, alerts,
 * incidents, connections and reports are unaffected — which the returned `message`
 * states explicitly.
 */
export function resetBaseline(deviceKey: string): Promise<BaselineResetResult> {
  return apiPost<BaselineResetResult>(BaselinePaths.reset(deviceKey))
}
