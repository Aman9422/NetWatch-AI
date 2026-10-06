/**
 * The dashboard's data (M15.9/M15.30/M15.34).
 *
 * One REST read for current state, one WebSocket subscription for movement, and
 * a pure selector that combines them. The split follows M15.30 exactly:
 *
 *     GET /dashboard/summary  →  what is true now
 *     /ws/dashboard           →  what changed since
 *
 * Three consequences worth stating, because each is a decision a reader would
 * otherwise wonder about:
 *
 * * **A reconnect re-reads REST rather than replaying events.** M14 keeps no
 *   per-client buffer, so an outage leaves a hole in the stream that cannot be
 *   filled from the events themselves. On reconnect the hook reloads the summary
 *   and then carries on live (M15.27).
 * * **There is no polling here.** The dashboard channel exists precisely so this
 *   page does not need one: every scalar it shows is in the tick, and the
 *   breakdowns it shows beyond those come from the summary and change slowly
 *   enough that a reconnect-triggered refresh is the right cadence (M15.34).
 * * **The live payload replaces the REST scalars it covers, and nothing else.**
 *   `metrics` is where that happens, and it is computed outside React so a test
 *   can assert it without a socket.
 */

import { useState } from 'react'
import { DEFAULT_RECENT_FINDINGS, fetchDashboardSummary } from '@/services'
import { isDashboardEvent } from '@/types'
import type { ConnectionPhase, DashboardSummary, DashboardUpdateEvent } from '@/types'
import type { ApiError } from '@/services'
import {
  dashboardMetrics,
  unavailableSections,
  type DashboardMetrics,
  type UnavailableSection,
} from '@/lib/dashboard'
import { useAsyncResource } from './useAsyncResource'
import { useChannelEvents } from './useChannelEvents'

/** Options for {@link useDashboard}. */
export interface DashboardOptions {
  /** How many recent findings to include. Bounded by the backend (M13.19). */
  readonly recentLimit?: number
}

/** What {@link useDashboard} returns. */
export interface DashboardResource {
  /** The summary as last read from REST, or `null` before it arrives. */
  readonly summary: DashboardSummary | null
  /** The most recent live tick, or `null` if none has arrived. */
  readonly live: DashboardUpdateEvent | null
  /** The nine scalars, sourced from the tick where it carries them. */
  readonly metrics: DashboardMetrics
  /** Sections the backend could not read, with its own reasons. */
  readonly unavailable: readonly UnavailableSection[]
  /** The REST failure, when the summary could not be read. */
  readonly error: ApiError | null
  /** The REST failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  /** True while a reload is in flight after content was already shown. */
  readonly isRefreshing: boolean
  /** Read the summary again. */
  readonly reload: () => void
  readonly phase: ConnectionPhase
  readonly isConnected: boolean
  readonly lastEventAt: number | null
}

/**
 * Load and maintain the dashboard.
 *
 * @param options How many recent findings the summary should carry.
 */
export function useDashboard(options: DashboardOptions = {}): DashboardResource {
  const recentLimit = options.recentLimit ?? DEFAULT_RECENT_FINDINGS
  const [live, setLive] = useState<DashboardUpdateEvent | null>(null)

  const resource = useAsyncResource(
    (signal) => fetchDashboardSummary({ recentLimit, signal }),
    [recentLimit],
  )
  const { reload } = resource

  const channel = useChannelEvents({
    channel: 'dashboard',
    onEvent: (event) => {
      if (!isDashboardEvent(event)) return
      // The payload is the nine-scalar projection, not the summary (M14.9), so
      // it is stored as what it is rather than merged into the summary object.
      setLive(event.data)
    },
    onReconnect: () => {
      // The hole a reconnect leaves cannot be reconstructed from the events we
      // missed, so current state is re-read and the live stream resumes on top.
      setLive(null)
      reload()
    },
  })

  return {
    summary: resource.data,
    live,
    metrics: dashboardMetrics(resource.data, live),
    unavailable: unavailableSections(resource.data),
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    reload,
    phase: channel.phase,
    isConnected: channel.isConnected,
    lastEventAt: channel.lastEventAt,
  }
}
