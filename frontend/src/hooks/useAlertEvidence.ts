/**
 * One alert's evidence, optionally filtered by kind (M15.16).
 *
 * `GET /alerts/{alert_id}/evidence` exists beside the alert detail because a page
 * often wants one kind — the packet references, or the device references — without
 * the rest. Filtering is the backend's, so the returned list is exactly the match
 * set for the requested kind rather than a client-side narrowing of everything.
 *
 * A missing alert is a `404`, never an empty list, so "this alert has no evidence
 * of that kind" and "there is no such alert" stay distinguishable (M11.18).
 *
 * Evidence is a **reference**: each record names a packet, connection or device id
 * plus a small document. Nothing here fetches a payload, because M7 stores none
 * and M13 exposes none (M11.13).
 */

import { fetchAlertEvidence } from '@/services'
import type { ApiError } from '@/services'
import type { AlertEvidence, EvidenceList, EvidenceType } from '@/types'
import { useAsyncResource } from './useAsyncResource'

/** What {@link useAlertEvidence} returns. */
export interface AlertEvidenceResource {
  readonly evidence: readonly AlertEvidence[]
  /** How many records the backend counted, or `null` before the first read. */
  readonly count: number | null
  /** True when the alert exists but has no evidence of the requested kind. */
  readonly isEmpty: boolean
  /** True when the alert itself does not exist. */
  readonly isNotFound: boolean
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  /** True when `alertId` is `null`, so nothing was requested. */
  readonly isIdle: boolean
  readonly reload: () => void
}

/**
 * Read one alert's evidence.
 *
 * @param alertId The alert whose evidence to read, or `null` for none.
 * @param evidenceType An optional kind to restrict the listing to.
 * @param options Whether to run.
 */
export function useAlertEvidence(
  alertId: number | null,
  evidenceType?: EvidenceType,
  options: { readonly enabled?: boolean } = {},
): AlertEvidenceResource {
  const { enabled = true } = options
  const active = enabled && alertId !== null

  const resource = useAsyncResource(
    (signal) => fetchAlertEvidence(alertId as number, evidenceType, signal),
    [alertId, evidenceType ?? null],
    {
      enabled: active,
      isEmpty: (list: EvidenceList) => list.evidence.length === 0,
    },
  )

  const isNotFound = resource.error?.kind === 'not_found'

  return {
    evidence: resource.data?.evidence ?? [],
    count: resource.data?.count ?? null,
    isEmpty: resource.data !== null && resource.data.evidence.length === 0,
    isNotFound,
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    isIdle: !active,
    reload: resource.reload,
  }
}

/** The evidence kinds a page may offer as a filter, in a stable order. */
export const EVIDENCE_TYPE_ORDER: readonly EvidenceType[] = [
  'rule',
  'behavioral',
  'packet',
  'connection',
  'device',
]

/** True when `value` is one of the five documented evidence kinds. */
export function isEvidenceType(value: unknown): value is EvidenceType {
  return (
    typeof value === 'string' &&
    (EVIDENCE_TYPE_ORDER as readonly string[]).includes(value)
  )
}
