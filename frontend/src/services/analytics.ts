/**
 * Analytics service (M13.18, M15.21).
 *
 * Analytics is a *derived view* over services that already exist. Nothing here
 * computes a metric: every figure is read from the object that owns it, and the
 * page must not re-derive one. In particular the device and connection rankings
 * carry traffic totals rather than risk — M8 and M9 do not score anything — so
 * the UI must not present them as verdicts (M15.21).
 *
 * The five endpoints are independent, and {@link fetchAnalyticsBundle} loads them
 * concurrently while keeping a failure **per section**. That mirrors the
 * dashboard summary's design (M13.29): one unavailable block leaves the other
 * four renderable, and the page can say which one is missing instead of showing
 * an empty screen.
 */

import { apiGet } from './client'
import { AnalyticsPaths } from './endpoints'
import { toQueryParams } from './query'
import { toUserMessage } from './errors'
import type {
  AnalyticsConnections,
  AnalyticsDevices,
  AnalyticsProtocols,
  AnalyticsThreats,
  AnalyticsTraffic,
  RankMetric,
  StatisticsWindow,
} from '@/types'

/** How many ranked entries an analytics request asks for by default. */
export const DEFAULT_ANALYTICS_LIMIT = 10

/**
 * `GET /api/v1/analytics/traffic` — totals, derived ratios and leading talkers.
 *
 * Reads one M6 snapshot, so the totals, the rates and the protocol list all
 * describe the same instant. `window` only selects which per-second figure is
 * reported; `1s` is the snapshot's own live rate.
 */
export function fetchAnalyticsTraffic(
  options: {
    readonly window?: StatisticsWindow
    readonly limit?: number
    readonly by?: RankMetric
    readonly signal?: AbortSignal
  } = {},
): Promise<AnalyticsTraffic> {
  return apiGet<AnalyticsTraffic>(
    AnalyticsPaths.traffic,
    {
      window: options.window ?? '1s',
      limit: options.limit ?? DEFAULT_ANALYTICS_LIMIT,
      by: options.by ?? 'packets',
    },
    { signal: options.signal },
  )
}

/**
 * `GET /api/v1/analytics/protocols` — the protocol breakdown as a ranking.
 *
 * Distinct from `GET /api/v1/statistics/protocols`, which answers with a bare
 * distribution: this one is ordered by a chosen metric and states which one.
 */
export function fetchAnalyticsProtocols(
  options: { readonly by?: RankMetric; readonly signal?: AbortSignal } = {},
): Promise<AnalyticsProtocols> {
  return apiGet<AnalyticsProtocols>(
    AnalyticsPaths.protocols,
    { by: options.by ?? 'packets' },
    { signal: options.signal },
  )
}

/** `GET /api/v1/analytics/devices` — totals by activity state and a ranking. */
export function fetchAnalyticsDevices(
  options: {
    readonly by?: RankMetric
    readonly limit?: number
    readonly signal?: AbortSignal
  } = {},
): Promise<AnalyticsDevices> {
  return apiGet<AnalyticsDevices>(
    AnalyticsPaths.devices,
    {
      by: options.by ?? 'packets',
      limit: options.limit ?? DEFAULT_ANALYTICS_LIMIT,
    },
    { signal: options.signal },
  )
}

/**
 * `GET /api/v1/analytics/connections` — tracker counters and a ranking.
 *
 * The ranking deliberately includes retired conversations, because the busiest
 * conversation of a session is frequently one that has already closed.
 */
export function fetchAnalyticsConnections(
  options: {
    readonly by?: RankMetric
    readonly limit?: number
    readonly signal?: AbortSignal
  } = {},
): Promise<AnalyticsConnections> {
  return apiGet<AnalyticsConnections>(
    AnalyticsPaths.connections,
    {
      by: options.by ?? 'bytes',
      limit: options.limit ?? DEFAULT_ANALYTICS_LIMIT,
    },
    { signal: options.signal },
  )
}

/**
 * `GET /api/v1/analytics/threats` — findings, alerts and incidents side by side.
 *
 * Three layers that must stay distinct: M10's observations, M11's evidence-based
 * judgement, and M12's bounded prioritisation. Collapsing them would invent a
 * single "threat" number no milestone produces.
 */
export function fetchAnalyticsThreats(signal?: AbortSignal): Promise<AnalyticsThreats> {
  return apiGet<AnalyticsThreats>(AnalyticsPaths.threats, undefined, { signal })
}

/** One section of the analytics page that could not be read. */
export interface AnalyticsSectionFailure {
  /** The section's own name, so the page can say which block is missing. */
  readonly section: string
  /** A sentence safe to render; never a backend stack trace. */
  readonly message: string
}

/**
 * Every analytics block, each independently present or independently missing.
 *
 * A field is `null` exactly when its section failed, and `failures` names why.
 * The page renders the four that answered and a placeholder for the one that did
 * not, rather than one error for the whole view.
 */
export interface AnalyticsBundle {
  readonly traffic: AnalyticsTraffic | null
  readonly protocols: AnalyticsProtocols | null
  readonly devices: AnalyticsDevices | null
  readonly connections: AnalyticsConnections | null
  readonly threats: AnalyticsThreats | null
  readonly failures: readonly AnalyticsSectionFailure[]
}

/** Options accepted by {@link fetchAnalyticsBundle}. */
export interface AnalyticsBundleOptions {
  readonly limit?: number
  readonly by?: RankMetric
  readonly signal?: AbortSignal
}

/**
 * Load all five analytics blocks concurrently, isolating any failure.
 *
 * `Promise.allSettled` rather than `Promise.all` is the whole point: one broken
 * section must not blank the four that answered. The signal is passed to every
 * request, so unmounting the page aborts all five.
 */
export async function fetchAnalyticsBundle(
  options: AnalyticsBundleOptions = {},
): Promise<AnalyticsBundle> {
  const { limit, by, signal } = options
  const [traffic, protocols, devices, connections, threats] = await Promise.allSettled([
    fetchAnalyticsTraffic({ limit, by, signal }),
    fetchAnalyticsProtocols({ by, signal }),
    fetchAnalyticsDevices({ limit, by, signal }),
    fetchAnalyticsConnections({ limit, by, signal }),
    fetchAnalyticsThreats(signal),
  ])

  const failures: AnalyticsSectionFailure[] = []
  const record = (section: string, result: PromiseSettledResult<unknown>): void => {
    if (result.status === 'rejected') {
      failures.push({ section, message: toUserMessage(result.reason) })
    }
  }
  record('traffic', traffic)
  record('protocols', protocols)
  record('devices', devices)
  record('connections', connections)
  record('threats', threats)

  return {
    traffic: traffic.status === 'fulfilled' ? traffic.value : null,
    protocols: protocols.status === 'fulfilled' ? protocols.value : null,
    devices: devices.status === 'fulfilled' ? devices.value : null,
    connections: connections.status === 'fulfilled' ? connections.value : null,
    threats: threats.status === 'fulfilled' ? threats.value : null,
    failures,
  }
}

/** Serialise an analytics ranking filter, for a caller building its own request. */
export function analyticsQueryParams(filter: {
  readonly by?: RankMetric
  readonly limit?: number
}): ReturnType<typeof toQueryParams> {
  return toQueryParams(filter)
}
