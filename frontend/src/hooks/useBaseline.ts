/**
 * One device's behavioural baseline (M21.11).
 *
 * The detail read, separate from the listing because it is a different resource
 * with a different shape: `recent_windows` is present here and absent from the
 * listing, and the engine bounds it (`MAX_DETAIL_WINDOWS`, M21.10).
 *
 * **A `404` is not a failure.** A device can be listed as discovered by M8 and
 * still have no baseline, because the engine writes nothing until an aggregation
 * window has something to record. The hook therefore separates "the engine says
 * this device has no baseline" from "the request failed", and the page renders the
 * first as an answer and the second as a fault. Collapsing them would tell an
 * operator the API was broken when it had answered correctly (M21.7).
 */

import { fetchBaseline } from '@/services'
import type { ApiError } from '@/services'
import type { Baseline } from '@/types'
import { useAsyncResource } from './useAsyncResource'

/** What {@link useBaseline} returns. */
export interface BaselineDetailResource {
  readonly baseline: Baseline | null
  readonly error: ApiError | null
  /** A failure that left nothing to show — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  /**
   * True when the engine answered `404`: this device has no baseline yet.
   *
   * Distinct from `blockingError` on purpose. "Nothing has been observed for this
   * device yet" is a correct answer about a real device; it is not a failed
   * request, and the page must not offer a retry for it as though one would help
   * — only further capture will produce a baseline (M21.7).
   */
  readonly isNotLearnt: boolean
  readonly reload: () => void
}

/** The loader rejection used only if a null key ever reaches the request. */
const NO_DEVICE_KEY = 'No device key supplied'

/**
 * Read one device's baseline.
 *
 * @param deviceKey The stable M8 identity, e.g. `mac:aa:bb:cc:dd:ee:ff`.
 * @param enabled When False nothing is requested.
 */
export function useBaseline(
  deviceKey: string | null,
  enabled = true,
): BaselineDetailResource {
  const resource = useAsyncResource(
    (signal) => {
      // The guard is inside the loader as well as in `enabled`, so a caller that
      // forgets the flag cannot turn a null key into the string "null" in a path.
      if (deviceKey === null) return Promise.reject(new Error(NO_DEVICE_KEY))
      return fetchBaseline(deviceKey, signal)
    },
    [deviceKey],
    { enabled: enabled && deviceKey !== null },
  )

  const isNotLearnt = resource.error?.kind === 'not_found'

  return {
    baseline: resource.data,
    error: resource.error,
    // A 404 is a real answer, so it must not be presented as a blocking failure.
    blockingError: isNotLearnt ? null : resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isNotLearnt,
    reload: resource.reload,
  }
}
