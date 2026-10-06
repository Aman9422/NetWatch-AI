/**
 * One retained finding (M15.20).
 *
 * `GET /detections/{finding_id}` exists beside the listing because M10's finding
 * history is **bounded**: a finding that was on screen a moment ago can age out of
 * the retention cap, and the endpoint's honest answer for it is `404`
 * (`FINDING_NOT_FOUND`), not an empty record (M10.19). This hook keeps that case
 * distinguishable so a page can say "no longer retained" rather than "the request
 * failed" — the same distinction the alerts detail makes for a deleted alert.
 *
 * A finding is not an alert (M15.20): nothing here reads a severity, a lifecycle or
 * a risk score, because M10 produces none. What it produces is an observation with
 * an evidence document, and that is all this returns.
 */

import { fetchDetection } from '@/services'
import type { ApiError } from '@/services'
import type { DetectionFinding } from '@/types'
import { useAsyncResource } from './useAsyncResource'

/** What {@link useDetection} returns. */
export interface DetectionDetailResource {
  /** The finding, or `null` while loading or once it has aged out. */
  readonly finding: DetectionFinding | null
  /**
   * True when the engine answered `404`.
   *
   * "No longer retained" rather than "not found": findings are kept in a bounded
   * history, so an id that was valid can stop being valid without anything having
   * gone wrong.
   */
  readonly isAgedOut: boolean
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  /** True when `findingId` is `null`, so nothing was requested. */
  readonly isIdle: boolean
  readonly reload: () => void
}

/**
 * Read one retained finding.
 *
 * @param findingId The finding to read, or `null` for none.
 * @param options Whether to run.
 */
export function useDetection(
  findingId: string | null,
  options: { readonly enabled?: boolean } = {},
): DetectionDetailResource {
  const { enabled = true } = options
  const active = enabled && findingId !== null

  const resource = useAsyncResource(
    (signal) => fetchDetection(findingId as string, signal),
    [findingId],
    { enabled: active },
  )

  return {
    finding: resource.data,
    isAgedOut: resource.error?.kind === 'not_found',
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    isIdle: !active,
    reload: resource.reload,
  }
}
