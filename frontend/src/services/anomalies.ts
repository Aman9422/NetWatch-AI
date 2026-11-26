/**
 * ML anomaly detection service (M22.12).
 *
 * Five calls over the M22 engine, and the restraint of `baselines.ts` applies
 * with more force here: an anomaly is a *deviation from learned behaviour*, not a
 * verdict of malice, and nothing returned here is a probability.
 *
 * * `fetchAnomalies` — a page of evaluated windows, newest first, with counted
 *   totals for the page tiles.
 * * `fetchAnomaly` — one verdict with its per-feature comparison against M21's
 *   profile. The comparison is a *statistic*, not model feature attribution.
 * * `fetchAnomalyModels` / `fetchAnomalyModel` — per-device model lifecycle. A
 *   device still collecting history is present in `collecting_data`, deliberately:
 *   "no model yet" must never look like "no anomalies".
 * * `retrainAnomalyModel` — a controlled retraining. It answers `200` whether or
 *   not a model was produced, so the caller reads `trained`.
 *
 * `decision_score` is the raw `IsolationForest.decision_function` output. Lower is
 * more unusual. It is not a probability, not a calibrated confidence, and not
 * comparable between two devices' models — every payload says so in
 * `decision_score_note`.
 */

import { apiGet, apiPost } from './client'
import { AnomalyPaths } from './endpoints'
import { withPageWindow, type PageWindow } from './query'
import type {
  AnomalyModel,
  AnomalyModelPage,
  AnomalyModelQuery,
  AnomalyPage,
  AnomalyQuery,
  AnomalyResult,
  AnomalyRetrainResult,
} from '@/types'

/**
 * `GET /api/v1/anomalies` — a page of evaluated observation windows (M22.12).
 *
 * Filters combine with AND, and the window (device, time range, classification)
 * narrows the listing without changing its ordering.
 */
export function fetchAnomalies(
  query: AnomalyQuery = {},
  window?: PageWindow,
  signal?: AbortSignal,
): Promise<AnomalyPage> {
  return apiGet<AnomalyPage>(AnomalyPaths.list, withPageWindow(query, window), {
    signal,
  })
}

/**
 * `GET /api/v1/anomalies/{evaluation_id}` — one verdict (M22.12).
 *
 * The detail response carries `feature_context`, which the listing does not: the
 * context exists so an operator can see *how* the window differed from the
 * baseline, not to attribute the prediction to a feature.
 *
 * An unknown id answers `404`; the page renders that as "this result no longer
 * exists" rather than as a failed request, because retention may have removed it.
 */
export function fetchAnomaly(
  evaluationId: number,
  signal?: AbortSignal,
): Promise<AnomalyResult> {
  return apiGet<AnomalyResult>(AnomalyPaths.detail(evaluationId), undefined, {
    signal,
  })
}

/**
 * `GET /api/v1/anomalies/models` — every device's model lifecycle (M22.12).
 *
 * A device in `collecting_data` appears here. Omitting it would make an unready
 * device indistinguishable from one that was never observed.
 */
export function fetchAnomalyModels(
  query: AnomalyModelQuery = {},
  window?: PageWindow,
  signal?: AbortSignal,
): Promise<AnomalyModelPage> {
  return apiGet<AnomalyModelPage>(
    AnomalyPaths.models,
    withPageWindow(query, window),
    { signal },
  )
}

/**
 * `GET /api/v1/anomalies/models/{device_key}` — one device's model (M22.12).
 *
 * Answers `404` when the device has no model row at all, which is a real answer
 * for a device that has produced no completed observation window.
 */
export function fetchAnomalyModel(
  deviceKey: string,
  signal?: AbortSignal,
): Promise<AnomalyModel> {
  return apiGet<AnomalyModel>(AnomalyPaths.model(deviceKey), undefined, {
    signal,
  })
}

/**
 * `POST /api/v1/anomalies/models/{device_key}/retrain` — force a training pass.
 *
 * No body: the device key in the path is the whole request. The response always
 * describes the outcome — trained, refused, or failed with the previous model
 * retained — so the caller reads `trained` rather than inferring it from the
 * status code. M21's behavioural history is never modified by a retrain.
 */
export function retrainAnomalyModel(
  deviceKey: string,
): Promise<AnomalyRetrainResult> {
  return apiPost<AnomalyRetrainResult>(AnomalyPaths.retrain(deviceKey))
}
