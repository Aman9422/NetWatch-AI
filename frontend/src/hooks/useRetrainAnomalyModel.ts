/**
 * Manual anomaly-model retraining (M22.12/M22.13).
 *
 * A thin wrapper over `useAction`, like `useResetBaseline`: the retrain is a plain
 * POST whose outcome the backend describes, so all it needs is the shared write
 * primitive's progress, failure and result tracking.
 *
 * Two properties the caller must honour, and this hook does not hide them:
 *
 * * **`run` resolves with a discriminated result.** A caller handles the failure
 *   branch to read the value, so a refused retrain can never be reported as having
 *   happened (M15.15).
 * * **A `200` does not mean a model was trained.** The endpoint answers `200` for a
 *   refusal too — too little history, a pass already running — so the confirmation
 *   reads `trained` and `message` rather than the status code.
 */

import { useAction } from './useAction'
import type { ActionResource } from './useAction'
import { retrainAnomalyModel } from '@/services'
import type { AnomalyRetrainResult } from '@/types'

/** What {@link useRetrainAnomalyModel} returns: an action taking one device key. */
export type RetrainAnomalyModelResource = ActionResource<
  readonly [deviceKey: string],
  AnomalyRetrainResult
>

/**
 * Force a training pass for one device.
 *
 * The returned `run` takes the device key, so one hook instance serves any row on
 * the page. The operation reads the device's retained observation windows and
 * writes one model row; M21's behavioural history is never modified.
 */
export function useRetrainAnomalyModel(): RetrainAnomalyModelResource {
  return useAction(async (deviceKey: string) => retrainAnomalyModel(deviceKey))
}
