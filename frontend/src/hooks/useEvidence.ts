/**
 * One evidence record in its own right (M15.16).
 *
 * `GET /evidence/{id}` returns a record **together with the alert that owns it**,
 * which is what makes an evidence reference navigable both ways: a page holding an
 * id can name its alert instead of searching every alert for a match.
 *
 * A pruned record, or an id that never existed, answers `404` rather than an empty
 * object — "this reference is no longer resolvable" and "this evidence has no
 * content" are different statements and only one of them is true. The hook
 * surfaces that as {@link EvidenceResource.isNotFound}.
 *
 * Evidence is a **reference, never a copy** (M11.13): the record names a packet,
 * connection or device id plus a small document. Nothing here fetches a payload,
 * because M7 stores none and M13 exposes none.
 */

import { fetchEvidence } from '@/services'
import type { ApiError } from '@/services'
import type { AlertEvidence, EvidenceDetail } from '@/types'
import { useAsyncResource } from './useAsyncResource'

/** What {@link useEvidence} returns. */
export interface EvidenceResource {
  /** The evidence record, or `null` while loading or when the id is unknown. */
  readonly evidence: AlertEvidence | null
  /** The alert this evidence supports, so the reference is navigable back. */
  readonly alertId: number | null
  /** True when the record is a `404` — pruned, or never present. */
  readonly isNotFound: boolean
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  /** True when `evidenceId` is `null`, so nothing was requested. */
  readonly isIdle: boolean
  readonly reload: () => void
}

/**
 * Read one evidence record and its owning alert.
 *
 * @param evidenceId The record to read, or `null` for none.
 * @param options Whether to run.
 */
export function useEvidence(
  evidenceId: number | null,
  options: { readonly enabled?: boolean } = {},
): EvidenceResource {
  const { enabled = true } = options
  const active = enabled && evidenceId !== null

  const resource = useAsyncResource(
    (signal) => fetchEvidence(evidenceId as number, signal),
    [evidenceId],
    { enabled: active },
  )

  const detail: EvidenceDetail | null = resource.data

  return {
    evidence: detail?.evidence ?? null,
    alertId: detail?.alert_id ?? null,
    isNotFound: resource.error?.kind === 'not_found',
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    isIdle: !active,
    reload: resource.reload,
  }
}
