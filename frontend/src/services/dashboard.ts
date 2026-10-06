/**
 * Dashboard and statistics service (M13.19, M6).
 *
 * `fetchDashboardSummary` is the one aggregate request the dashboard page makes on
 * load. Everything on the page that is a *counter* comes from it, and nothing is
 * recomputed client-side (M15.9): the backend already knows the packet rate, the
 * device count and the open-alert count, and a second implementation in React
 * would disagree with it the moment either changed.
 *
 * Live movement comes from `/ws/dashboard` instead. The split is deliberate — REST
 * for current state, WebSocket for updates (M15.30).
 */

import { apiGet } from './client'
import { DashboardPaths, StatisticsPaths } from './endpoints'
import type {
  DashboardSummary,
  ProtocolStat,
  StatisticsWindow,
  TopEntry,
  TopTalkers,
  TrafficSnapshot,
} from '@/types'

/** How many recent findings the summary carries by default (M13.19). */
export const DEFAULT_RECENT_FINDINGS = 5

/** Largest number of recent findings the summary may carry (M13.19). */
export const MAX_RECENT_FINDINGS = 50

/**
 * `GET /api/v1/dashboard/summary` — the consolidated summary (M13.19).
 *
 * Every section is present, and each reports `available` independently, so one
 * unavailable service leaves the rest renderable (M13.29).
 */
export function fetchDashboardSummary(
  options: { readonly recentLimit?: number; readonly signal?: AbortSignal } = {},
): Promise<DashboardSummary> {
  return apiGet<DashboardSummary>(
    DashboardPaths.summary,
    { recent_limit: options.recentLimit ?? DEFAULT_RECENT_FINDINGS },
    { signal: options.signal },
  )
}

/**
 * `GET /api/v1/statistics/traffic` — the M6 point-in-time snapshot.
 *
 * `window` selects the rate the snapshot reports: `1s`, `10s` or `60s`.
 */
export function fetchTrafficSnapshot(
  options: {
    readonly window?: StatisticsWindow
    readonly signal?: AbortSignal
  } = {},
): Promise<TrafficSnapshot> {
  return apiGet<TrafficSnapshot>(
    StatisticsPaths.traffic,
    { window: options.window ?? '1s' },
    { signal: options.signal },
  )
}

/**
 * `GET /api/v1/statistics/protocols` — the complete protocol distribution.
 *
 * Resolves to a **bare list**, not a counted object. `app/api/v1/statistics.py`
 * renders the manager's own distribution, which is deliberately complete rather
 * than a page, so there is no window and no total to report. The counted form
 * belongs to `GET /api/v1/analytics/protocols`, which *is* a ranking — two
 * different questions, two different shapes.
 */
export function fetchProtocolStatistics(
  signal?: AbortSignal,
): Promise<readonly ProtocolStat[]> {
  return apiGet<readonly ProtocolStat[]>(StatisticsPaths.protocols, undefined, { signal })
}

/** `GET /api/v1/statistics/ports` — ranked ports for one direction. */
export function fetchTopPorts(
  options: {
    readonly limit?: number
    readonly by?: 'packets' | 'bytes'
    readonly direction?: 'source' | 'destination'
    readonly signal?: AbortSignal
  } = {},
): Promise<readonly TopEntry[]> {
  return apiGet<readonly TopEntry[]>(
    StatisticsPaths.ports,
    {
      limit: options.limit ?? 10,
      by: options.by ?? 'packets',
      direction: options.direction ?? 'destination',
    },
    { signal: options.signal },
  )
}

/** `GET /api/v1/statistics/top-talkers` — busiest sources and destinations. */
export function fetchTopTalkers(
  options: {
    readonly limit?: number
    readonly by?: 'packets' | 'bytes'
    readonly signal?: AbortSignal
  } = {},
): Promise<TopTalkers> {
  return apiGet<TopTalkers>(
    StatisticsPaths.topTalkers,
    { limit: options.limit ?? 10, by: options.by ?? 'packets' },
    { signal: options.signal },
  )
}
