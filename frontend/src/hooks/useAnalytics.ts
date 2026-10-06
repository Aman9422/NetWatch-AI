/**
 * The analytics view (M15.21).
 *
 * Analytics is five independent derived views — traffic, protocols, devices,
 * connections, threats — and they are loaded together so a page renders once,
 * but they are **not** loaded atomically. {@link fetchAnalyticsBundle} keeps a
 * failure per section, and this hook surfaces it rather than collapsing five
 * answers into one pass/fail: a page shows the four blocks that answered and
 * names the one that did not, instead of blanking the whole screen because one
 * endpoint was unavailable.
 *
 * Nothing here derives a figure. Each number comes from the endpoint whose owning
 * service computed it, and the rankings carry **traffic totals rather than risk**
 * (M8/M9 score nothing), so the page must not render them as verdicts (M15.21).
 *
 * Analytics has no WebSocket channel, so there is no live path: the data is read
 * and refreshed explicitly (M15.34).
 */

import { useMemo } from 'react'
import { DEFAULT_ANALYTICS_LIMIT, fetchAnalyticsBundle } from '@/services'
import type { AnalyticsBundle, ApiError } from '@/services'
import type { RankMetric } from '@/types'
import { useAsyncResource } from './useAsyncResource'

/** Options for {@link useAnalytics}. */
export interface AnalyticsOptions {
  /** Which ranking metric to sort every ranked block by. Defaults `packets`. */
  readonly by?: RankMetric
  /** How many entries each ranked block asks for. Defaults to the service's own. */
  readonly limit?: number
  readonly enabled?: boolean
}

/** What {@link useAnalytics} returns. */
export interface AnalyticsResource {
  /** Every block, each independently present or `null`. `null` until first load. */
  readonly bundle: AnalyticsBundle | null
  /** The sections that failed, with a renderable sentence each. */
  readonly failures: AnalyticsBundle['failures']
  /** True when no section failed and no section is `null`. */
  readonly isComplete: boolean
  /**
   * A total failure — every section missing through one error.
   *
   * Distinct from a partial failure: `error` being set with no bundle at all is
   * "analytics is unavailable", whereas a bundle with `failures` is "these blocks
   * are unavailable".
   */
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  /** True when every section answered and all of them are empty. */
  readonly isEmpty: boolean
  readonly reload: () => void
}

/**
 * Load every analytics block concurrently, isolating failures.
 *
 * @param options Ranking metric, entry count, and whether to read at all.
 */
export function useAnalytics(options: AnalyticsOptions = {}): AnalyticsResource {
  const { by, limit, enabled = true } = options

  const resolvedLimit = limit ?? DEFAULT_ANALYTICS_LIMIT

  const resource = useAsyncResource(
    (signal) => fetchAnalyticsBundle({ by, limit: resolvedLimit, signal }),
    [by ?? null, resolvedLimit],
    { enabled },
  )

  const bundle = resource.data
  const failures = bundle?.failures ?? []

  // The bundle carries failures in-band rather than throwing, so a partially
  // broken view still resolves successfully. `isComplete` is the one place that
  // reconciles the two: no sections missing and none failed.
  const isComplete = useMemo(() => {
    if (bundle === null) return false
    if (bundle.failures.length > 0) return false
    return (
      bundle.traffic !== null &&
      bundle.protocols !== null &&
      bundle.devices !== null &&
      bundle.connections !== null &&
      bundle.threats !== null
    )
  }, [bundle])

  const isEmpty = useMemo(() => {
    if (bundle === null) return false
    // "Empty" only when every present block reported zero: a traffic block of
    // zeroes is the honest answer for an idle interface, and a page must say so
    // rather than render nothing.
    const trafficIdle = bundle.traffic === null || bundle.traffic.total_packets === 0
    const devicesIdle = bundle.devices === null || bundle.devices.top.length === 0
    const connectionsIdle =
      bundle.connections === null || bundle.connections.top.length === 0
    return trafficIdle && devicesIdle && connectionsIdle
  }, [bundle])

  return {
    bundle,
    failures,
    isComplete,
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    isEmpty,
    reload: resource.reload,
  }
}
