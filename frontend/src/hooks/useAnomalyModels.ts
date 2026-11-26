/**
 * Per-device anomaly model lifecycles (M22.13).
 *
 * A plain REST listing like `useAnomalies`. The important property is what it does
 * *not* do: it never filters out a device that has no usable model. A device in
 * `collecting_data` is a real answer to "which devices have models", and hiding it
 * would make an unmonitored device look like one that was never observed — or,
 * worse, like one that is being checked and finding nothing.
 *
 * The filter is compared by its serialised form, not its object identity, so a
 * page may build `{ state }` inline.
 */

import { useMemo } from 'react'
import { fetchAnomalyModels } from '@/services'
import type { ApiError, PageWindow } from '@/services'
import type { AnomalyModel, AnomalyModelPage, AnomalyModelQuery } from '@/types'
import { useAsyncResource } from './useAsyncResource'

/** Options for {@link useAnomalyModels}. */
export interface AnomalyModelListOptions {
  /** Filters to apply. May be built inline; it is compared by value. */
  readonly query?: AnomalyModelQuery
  /** Page window. Compared by value, like the filter. */
  readonly window?: PageWindow
  /** When False nothing is requested. */
  readonly enabled?: boolean
}

/** What {@link useAnomalyModels} returns. */
export interface AnomalyModelListResource {
  readonly models: readonly AnomalyModel[]
  readonly page: AnomalyModelPage | null
  readonly total: number | null
  readonly hasMore: boolean
  /** The sentence stating that an anomaly is not proof of malicious activity. */
  readonly disclaimer: string | null
  /** How many of the loaded models can actually score a window. */
  readonly readyCount: number
  /** How many loaded models are still collecting history. */
  readonly collectingCount: number
  readonly error: ApiError | null
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  readonly isEmpty: boolean
  readonly reload: () => void
}

/**
 * Read per-device model lifecycles.
 *
 * @param options Filters, page window, and whether to read at all.
 */
export function useAnomalyModels(
  options: AnomalyModelListOptions = {},
): AnomalyModelListResource {
  const { query, window, enabled = true } = options

  const cacheKey = useMemo(
    () =>
      JSON.stringify({
        state: query?.state ?? null,
        limit: window?.limit ?? null,
        offset: window?.offset ?? null,
      }),
    [query, window],
  )

  const resource = useAsyncResource(
    (signal) => fetchAnomalyModels(query ?? {}, window, signal),
    [cacheKey],
    {
      enabled,
      isEmpty: (page: AnomalyModelPage) => page.models.length === 0,
    },
  )

  const models = resource.data?.models ?? []
  return {
    models,
    page: resource.data,
    total: resource.data?.total ?? null,
    hasMore: resource.data?.has_more === true,
    disclaimer: resource.data?.disclaimer ?? null,
    readyCount: models.filter(model => model.ready).length,
    collectingCount: models.filter(
      model => model.state === 'collecting_data',
    ).length,
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    isEmpty: resource.data !== null && resource.data.models.length === 0,
    reload: resource.reload,
  }
}
