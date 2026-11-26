/**
 * Per-device behavioural baselines (M21.11).
 *
 * A plain REST listing, like `useDevices`: the M21 engine publishes no WebSocket
 * channel, so there is nothing to subscribe to and no polling to justify. A
 * baseline changes when an aggregation window closes — sixty seconds by default —
 * which is slower than an operator reads a page, so an explicit refresh is the
 * honest cadence (M15.34).
 *
 * **A device with no baseline is absent, not zero.** The engine only writes a
 * window once it has observations to put in it, so a device discovered seconds ago
 * has no profile and does not appear here. That absence is the truthful answer and
 * the page states it; fabricating a row of zeroes would present "no observations"
 * as "no traffic", which M21.7 forbids.
 *
 * The filter is keyed by its **serialised form**, not its object identity, for the
 * same reason `useDevices` does it: a page naturally builds `{ learning_state }`
 * inline, which is a new object on every render.
 */

import { useMemo } from 'react'
import { fetchBaselines } from '@/services'
import type { ApiError, PageWindow } from '@/services'
import type { Baseline, BaselinePage, BaselineQuery } from '@/types'
import { useAsyncResource } from './useAsyncResource'

/** Options for {@link useBaselines}. */
export interface BaselineListOptions {
  /** Filters to apply. May be built inline; it is compared by value. */
  readonly query?: BaselineQuery
  /** Page window. Compared by value, like the filter. */
  readonly window?: PageWindow
  /** When False nothing is requested. */
  readonly enabled?: boolean
}

/** What {@link useBaselines} returns. */
export interface BaselineListResource {
  readonly baselines: readonly Baseline[]
  /** The full page, for its `total` and `has_more`. */
  readonly page: BaselinePage | null
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
  /** True when the engine answered with no learnt baselines. */
  readonly isEmpty: boolean
  readonly reload: () => void
}

/**
 * Read the learnt baselines.
 *
 * @param options Filters, page window, and whether to read at all.
 */
export function useBaselines(
  options: BaselineListOptions = {},
): BaselineListResource {
  const { query, window, enabled = true } = options

  // Serialised so an inline object literal does not restart the request on every
  // render. Key order is fixed by constructing the key from the known fields.
  const cacheKey = useMemo(
    () =>
      JSON.stringify({
        learningState: query?.learning_state ?? null,
        limit: window?.limit ?? null,
        offset: window?.offset ?? null,
      }),
    [query, window],
  )

  const resource = useAsyncResource(
    (signal) => fetchBaselines(query ?? {}, window, signal),
    [cacheKey],
    {
      enabled,
      isEmpty: (page: BaselinePage) => page.baselines.length === 0,
    },
  )

  return {
    baselines: resource.data?.baselines ?? [],
    page: resource.data,
    total: resource.data?.total ?? null,
    hasMore: resource.data?.has_more === true,
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    isEmpty: resource.data !== null && resource.data.baselines.length === 0,
    reload: resource.reload,
  }
}
