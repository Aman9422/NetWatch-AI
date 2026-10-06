/**
 * Process, database and pipeline status (M15.24).
 *
 * Three REST angles on the running process — consolidated status, per-dependency
 * health, and identity — plus the `/ws/system` channel, which announces that a
 * *system* fact changed: capture started or stopped, the database became
 * reachable or not, a service changed state (M14.11).
 *
 * How the two combine is the whole design. This hook does **not** patch the REST
 * status in place for each event. It re-reads the consolidated status when a
 * system event arrives. The reason is that the events carry a *subset* of the
 * status — `capture.stop ped` has no `processed_packet_count`, `service.status`
 * names one service where the status carries the whole list — and a partial
 * client-side merge would leave the untouched fields showing whatever they held
 * before, which is a freshness claim the data cannot support. The evidence is the
 * M15.30 rule: REST is the source for current state, WebSockets are the signal
 * that it changed. System events are state changes, not a stream, so re-reading
 * on each is both correct and cheap.
 *
 * Nothing here is a frontend health metric. The frontend does not probe the
 * backend; it renders the verdicts the backend computed (M15.24). The last
 * capture and service events are exposed as transient facts a page can show as a
 * banner, because they carry a reason REST cannot reconstruct.
 */

import { useCallback, useState } from 'react'
import {
  fetchSystemHealth,
  fetchSystemInfo,
  fetchSystemStatus,
  isSystemHealthy,
} from '@/services'
import type { ApiError } from '@/services'
import {
  isCaptureEvent,
  isDatabaseStatusEvent,
  isServiceStatusEvent,
} from '@/types'
import type {
  CaptureEventData,
  ConnectionPhase,
  DatabaseStatusEventData,
  ServerEvent,
  ServiceStatusEventData,
  SystemHealth,
  SystemInfo,
  SystemStatus,
} from '@/types'
import { useAsyncResource } from './useAsyncResource'
import { useChannelEvents } from './useChannelEvents'

/** What {@link useSystemStatus} returns. */
export interface SystemResource {
  /** The consolidated view; `null` until the first read succeeds. */
  readonly status: SystemStatus | null
  /** Per-dependency verdicts; `null` until read, or if that endpoint failed. */
  readonly health: SystemHealth | null
  /** Application identity; `null` until read, or if that endpoint failed. */
  readonly info: SystemInfo | null
  /**
   * The aggregate verdict, or `null` before health is known.
   *
   * A named value rather than a comparison at each call site, because "degraded"
   * and "unknown" must not render the same way.
   */
  readonly isHealthy: boolean | null
  /** The status read's failure, if any. */
  readonly error: ApiError | null
  /** The status failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly healthError: ApiError | null
  readonly infoError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  readonly reload: () => void
  /** Where the system channel currently stands. */
  readonly isConnected: boolean
  readonly phase: ConnectionPhase
  readonly lastEventAt: number | null
  /** The most recent capture event, for a banner; `null` before any. */
  readonly lastCaptureEvent: CaptureEventData | null
  /** The most recent database event, for a banner. */
  readonly lastDatabaseEvent: DatabaseStatusEventData | null
  /** The most recent service event, for a banner. */
  readonly lastServiceEvent: ServiceStatusEventData | null
}

/**
 * Read the running process and follow its system events.
 *
 * @param options Whether to read and subscribe at all.
 */
export function useSystemStatus(
  options: { readonly enabled?: boolean } = {},
): SystemResource {
  const { enabled = true } = options

  const statusResource = useAsyncResource((signal) => fetchSystemStatus(signal), [], {
    enabled,
  })
  const healthResource = useAsyncResource((signal) => fetchSystemHealth(signal), [], {
    enabled,
  })
  const infoResource = useAsyncResource((signal) => fetchSystemInfo(signal), [], {
    enabled,
  })

  const [lastCaptureEvent, setLastCaptureEvent] = useState<CaptureEventData | null>(null)
  const [lastDatabaseEvent, setLastDatabaseEvent] = useState<DatabaseStatusEventData | null>(
    null,
  )
  const [lastServiceEvent, setLastServiceEvent] = useState<ServiceStatusEventData | null>(
    null,
  )

  const { reload: reloadStatus } = statusResource
  const { reload: reloadHealth } = healthResource
  const { reload: reloadInfo } = infoResource

  const refreshAll = useCallback(() => {
    reloadStatus()
    reloadHealth()
  }, [reloadStatus, reloadHealth])

  const channel = useChannelEvents({
    channel: 'system',
    enabled,
    onEvent: (event: ServerEvent) => {
      // The event itself is a signal, not the data. Each known system event
      // records its payload for a banner and refreshes the consolidated status,
      // whose answer is the backend's rather than a merge of this event's fields.
      // The guards narrow the payload, so no cast is needed and an event of an
      // unexpected shape is ignored rather than half-applied.
      if (isCaptureEvent(event)) {
        setLastCaptureEvent(event.data)
        refreshAll()
        return
      }
      if (isDatabaseStatusEvent(event)) {
        setLastDatabaseEvent(event.data)
        refreshAll()
        return
      }
      if (isServiceStatusEvent(event)) {
        setLastServiceEvent(event.data)
        refreshAll()
        return
      }
      // Anything else on this channel — a `ping`/`pong` or a refusal — is handled
      // below the hook and ignored here.
    },
    onReconnect: () => {
      // M14 keeps no replay buffer, so the state accumulated across the outage is
      // not trustworthy: REST is re-read for the current truth and the transient
      // banners are cleared (M15.27).
      setLastCaptureEvent(null)
      setLastDatabaseEvent(null)
      setLastServiceEvent(null)
      reloadStatus()
      reloadHealth()
      reloadInfo()
    },
  })

  const health = healthResource.data

  return {
    status: statusResource.data,
    health,
    info: infoResource.data,
    isHealthy: health === null ? null : isSystemHealthy(health),
    error: statusResource.error,
    blockingError: statusResource.blockingError,
    healthError: healthResource.error,
    infoError: infoResource.error,
    isLoading:
      statusResource.isLoading || healthResource.isLoading || infoResource.isLoading,
    isInitialLoading:
      statusResource.isInitialLoading ||
      healthResource.isInitialLoading ||
      infoResource.isInitialLoading,
    isRefreshing:
      (statusResource.isLoading && !statusResource.isInitialLoading) ||
      (healthResource.isLoading && !healthResource.isInitialLoading) ||
      (infoResource.isLoading && !infoResource.isInitialLoading),
    reload: reloadStatus,
    isConnected: channel.isConnected,
    phase: channel.phase,
    lastEventAt: channel.lastEventAt,
    lastCaptureEvent,
    lastDatabaseEvent,
    lastServiceEvent,
  }
}
