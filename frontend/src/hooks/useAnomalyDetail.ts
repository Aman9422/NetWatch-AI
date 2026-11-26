/**
 * One evaluated window, with its feature context (M22.13).
 *
 * A detail read rather than a second listing call, because the backend's detail
 * response carries `feature_context` and the listing deliberately does not: the
 * context is nine rows of per-feature comparison and belongs beside one verdict,
 * not multiplied across a page of them.
 *
 * A `404` is a real answer here — retention removes evaluations after thirty days
 * by default — so the page renders it as "this result is no longer recorded"
 * rather than as a failure. This hook reports the error; the page decides the
 * wording.
 */

import { fetchAnomaly } from '@/services'
import { useAsyncResource } from './useAsyncResource'
import type { AsyncResource } from './useAsyncResource'
import type { AnomalyResult } from '@/types'

/** What {@link useAnomalyDetail} returns. */
export type AnomalyDetailResource = AsyncResource<AnomalyResult>

/**
 * Read one anomaly result by identifier.
 *
 * @param evaluationId The id, or `null` to request nothing.
 */
export function useAnomalyDetail(
  evaluationId: number | null,
): AnomalyDetailResource {
  return useAsyncResource(
    (signal) =>
      evaluationId === null
        ? Promise.reject(new Error('no evaluation id'))
        : fetchAnomaly(evaluationId, signal),
    [evaluationId],
    { enabled: evaluationId !== null },
  )
}
