/**
 * Tracked conversations (M15.13).
 *
 * M9 tracks conversations and never judges them, so nothing here reads a severity
 * or a risk figure — there is none to read. `state` and `active` are the
 * **tracker's own** view, derived from its expiry window, and the frontend must
 * not recompute either: a second opinion in React would disagree with the tracker
 * the moment a timeout fired on the server (M15.13).
 *
 * The endpoint is chosen by the filter rather than by a client-side flag.
 * `GET /connections/active` is a distinct route precisely so the "active" figure
 * a page shows is the backend's answer rather than a filter this client applied
 * (M13.11) — so `activeOnly` switches the request, not the result.
 *
 * `expire` is exposed because the endpoint exists as an M9.22 verification
 * helper. Using it forces the sweep the tracker would perform on its own timer;
 * the page offers it as a development action and must not imply it schedules
 * expiry.
 */

import { useCallback, useMemo } from 'react'
import { expireConnections, fetchActiveConnections, fetchConnections } from '@/services'
import type { ApiError, PageWindow } from '@/services'
import type { Connection, ConnectionPage, ConnectionQuery, ExpireResult } from '@/types'
import { useAction } from './useAction'
import { useAsyncResource } from './useAsyncResource'

/** Options for {@link useConnections}. */
export interface ConnectionListOptions {
  /** Filters to apply. Compared by value, so it may be built inline. */
  readonly query?: ConnectionQuery
  /** Page window. Compared by value. */
  readonly window?: PageWindow
  /**
   * Use `GET /connections/active` instead of the filtered listing.
   *
   * A separate request rather than a client-side filter, so the count shown is
   * the tracker's own.
   */
  readonly activeOnly?: boolean
  readonly enabled?: boolean
}

/** What {@link useConnections} returns. */
export interface ConnectionListResource {
  readonly connections: readonly Connection[]
  readonly page: ConnectionPage | null
  /** The true match count, when the tracker could count it. */
  readonly total: number | null
  readonly hasMore: boolean
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  /** True when the tracker answered with no conversations. */
  readonly isEmpty: boolean
  readonly reload: () => void
  /** True while a forced expiry sweep is in flight. */
  readonly isExpiring: boolean
  /**
   * Force the tracker's expiry sweep, then re-read the listing.
   *
   * Resolves `null` on success or the refusal. The listing is reloaded because
   * the sweep changes which conversations are still tracked, and only the tracker
   * knows the new state.
   */
  readonly expire: () => Promise<ApiError | null>
  /** The result of the last successful sweep, when there was one. */
  readonly lastExpiry: ExpireResult | null
}

/**
 * Read the connection tracker.
 *
 * @param options Filters, page window, endpoint choice, and whether to read.
 */
export function useConnections(
  options: ConnectionListOptions = {},
): ConnectionListResource {
  const { query, window, activeOnly = false, enabled = true } = options

  const cacheKey = useMemo(
    () =>
      JSON.stringify({
        endpoint: activeOnly ? 'active' : 'list',
        protocol: query?.protocol ?? null,
        source_ip: query?.source_ip ?? null,
        destination_ip: query?.destination_ip ?? null,
        source_port: query?.source_port ?? null,
        destination_port: query?.destination_port ?? null,
        device_id: query?.device_id ?? null,
        state: query?.state ?? null,
        active_only: query?.active_only ?? null,
        limit: window?.limit ?? null,
        offset: window?.offset ?? null,
      }),
    [activeOnly, query, window],
  )

  const resource = useAsyncResource(
    (signal) =>
      activeOnly
        ? fetchActiveConnections(window, signal)
        : fetchConnections(query ?? {}, window, signal),
    [cacheKey],
    {
      enabled,
      isEmpty: (page: ConnectionPage) => page.connections.length === 0,
    },
  )

  const expireAction = useAction(expireConnections)
  const { reload } = resource

  const expire = useCallback(async (): Promise<ApiError | null> => {
    const outcome = await expireAction.run()
    if (!outcome.ok) return outcome.error
    reload()
    return null
  }, [expireAction, reload])

  return {
    connections: resource.data?.connections ?? [],
    page: resource.data,
    total: resource.data?.total ?? null,
    hasMore: resource.data?.has_more === true,
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    isEmpty: resource.data !== null && resource.data.connections.length === 0,
    reload,
    isExpiring: expireAction.isRunning,
    expire,
    lastExpiry: expireAction.result,
  }
}
