/**
 * ML anomaly results (M22.13).
 *
 * A plain REST listing, like `useBaselines`: the M22 engine publishes no WebSocket
 * channel, and an evaluation happens once per completed observation window — sixty
 * seconds by default — which is slower than an operator reads a page. An explicit
 * refresh is the honest cadence (M15.34).
 *
 * **An empty page is not "all clear".** An empty list means no window has been
 * evaluated, which is what a freshly started backend returns for the first hundred
 * windows of every device. The page states that; this hook only reports the shape.
 *
 * The summary counts come from the same response, so the page's tiles and its rows
 * can never disagree about which set of results they describe.
 */

import { useMemo } from 'react'
import { fetchAnomalies } from '@/services'
import type { ApiError, PageWindow } from '@/services'
import type { AnomalyPage, AnomalyQuery, AnomalyResult, AnomalySummary } from '@/types'
import { useAsyncResource } from './useAsyncResource'

/** Options for {@link useAnomalies}. */
export interface AnomalyListOptions {
  /** Filters to apply. May be built inline; it is compared by value. */
  readonly query?: AnomalyQuery
  /** Page window. Compared by value, like the filter. */
  readonly window?: PageWindow
  /** When False nothing is requested. */
  readonly enabled?: boolean
}

/** What {@link useAnomalies} returns. */
export interface AnomalyListResource {
  readonly anomalies: readonly AnomalyResult[]
  /** The full page, for its `total`, `has_more` and `summary`. */
  readonly page: AnomalyPage | null
  /** Counted totals from the backend, so the tiles are not derived from one page. */
  readonly summary: AnomalySummary | null
  /** The sentence stating that an anomaly is not proof of malicious activity. */
  readonly disclaimer: string | null
  /** The true match count, when the engine could count it. */
  readonly total: number | null
  /** True when a further page exists. */
  readonly hasMore: boolean
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  /** True while a reload is in flight over existing content. */
  readonly isRefreshing: boolean
  /** True when the backend answered with no evaluated windows at all. */
  readonly isEmpty: boolean
  readonly reload: () => void
}

/** The empty summary a page shows before the first response arrives. */
const EMPTY_SUMMARY: AnomalySummary = {
  evaluations: 0,
  anomalies: 0,
  affected_devices: 0,
  scored: 0,
  skipped: 0,
}

/**
 * Read evaluated observation windows.
 *
 * @param options Filters, page window, and whether to read at all.
 */
export function useAnomalies(
  options: AnomalyListOptions = {},
): AnomalyListResource {
  const { query, window, enabled = true } = options

  // Serialised so an inline object literal does not restart the request on every
  // render. Key order is fixed by constructing the key from the known fields.
  const cacheKey = useMemo(
    () =>
      JSON.stringify({
        deviceKey: query?.device_key ?? null,
        isAnomaly: query?.is_anomaly ?? null,
        status: query?.status ?? null,
        since: query?.since ?? null,
        until: query?.until ?? null,
        limit: window?.limit ?? null,
        offset: window?.offset ?? null,
      }),
    [query, window],
  )

  const resource = useAsyncResource(
    (signal) => fetchAnomalies(query ?? {}, window, signal),
    [cacheKey],
    {
      enabled,
      isEmpty: (page: AnomalyPage) => page.anomalies.length === 0,
    },
  )

  return {
    anomalies: resource.data?.anomalies ?? [],
    page: resource.data,
    summary: resource.data?.summary ?? (resource.data ? EMPTY_SUMMARY : null),
    disclaimer: resource.data?.disclaimer ?? null,
    total: resource.data?.total ?? null,
    hasMore: resource.data?.has_more === true,
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    isEmpty: resource.data !== null && resource.data.anomalies.length === 0,
    reload: resource.reload,
  }
}
