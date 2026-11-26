/**
 * One device's anomaly-model lifecycle (M22.12/M22.13).
 *
 * The model listing already carries every device's row, so this hook exists for
 * the one case the listing cannot serve: a device-level detail view opened from a
 * row that is on *another* page, or from a deep link. Re-reading the single row is
 * cheaper and more current than scanning the pages already in memory.
 *
 * A `404` is a real answer, not a fault: a device that has produced no completed
 * observation window has no model row, and the page says so rather than showing an
 * error. This hook reports the error; the page decides the wording.
 */

import { fetchAnomalyModel } from '@/services'
import { useAsyncResource } from './useAsyncResource'
import type { AsyncResource } from './useAsyncResource'
import type { AnomalyModel } from '@/types'

/** What {@link useAnomalyModel} returns. */
export type AnomalyModelDetailResource = AsyncResource<AnomalyModel>

/**
 * Read one device's model lifecycle.
 *
 * @param deviceKey The M8 identity, or `null` to request nothing.
 */
export function useAnomalyModel(
  deviceKey: string | null,
): AnomalyModelDetailResource {
  return useAsyncResource(
    (signal) =>
      deviceKey === null
        ? Promise.reject(new Error('no device key'))
        : fetchAnomalyModel(deviceKey, signal),
    [deviceKey],
    { enabled: deviceKey !== null },
  )
}
