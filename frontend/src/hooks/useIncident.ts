/**
 * One correlated incident in full (M15.17/M15.18).
 *
 * The listing hook (`useIncidents`) carries only the summary. This hook reads
 * `GET /incidents/{id}`, which adds what the summary omits: the member alert,
 * finding, device and connection references, the correlation *reason trail*, and
 * the ISO-8601 forms of every timestamp.
 *
 * Live updates arrive on the **alerts** channel (M14.12), and an `incident.*`
 * event whose id matches the incident on screen triggers a re-read rather than a
 * client-side patch. The reason is the same as the listing's: the event carries
 * the summary, not the membership, so patching would leave stale member lists
 * beside a fresh status. Re-reading the detail is the only way the whole view is
 * one consistent snapshot.
 *
 * The three numbers — `risk_score`, `correlation_confidence` and
 * `alert_confidence` — are read as stored and must stay visually separate; nothing
 * here recomputes or reorders them (M15.17).
 */

import { useCallback } from 'react'
import { fetchIncident } from '@/services'
import type { ApiError } from '@/services'
import { isIncidentEvent } from '@/types'
import type { ConnectionPhase, Incident, IncidentSummary } from '@/types'
import { useAsyncResource } from './useAsyncResource'
import { useChannelEvents } from './useChannelEvents'

/** What {@link useIncident} returns. */
export interface IncidentDetailResource {
  /** The incident, or `null` while loading or when the id is unknown. */
  readonly incident: Incident | null
  /**
   * True when the incident is a `404`.
   *
   * Distinguished from a general failure so the page can say "no such incident"
   * rather than "something went wrong" — the two are different facts.
   */
  readonly isNotFound: boolean
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  /** True when `incidentId` is `null`, so nothing was requested. */
  readonly isIdle: boolean
  readonly reload: () => void
  readonly isConnected: boolean
  readonly phase: ConnectionPhase
}

/**
 * Read one incident and keep it current.
 *
 * @param incidentId The incident to read, or `null` for none.
 * @param options Whether to run.
 */
export function useIncident(
  incidentId: string | null,
  options: { readonly enabled?: boolean } = {},
): IncidentDetailResource {
  const { enabled = true } = options
  const active = enabled && incidentId !== null

  const resource = useAsyncResource(
    (signal) => fetchIncident(incidentId as string, signal),
    [incidentId],
    { enabled: active },
  )

  const { reload } = resource

  const channel = useChannelEvents({
    channel: 'alerts',
    enabled: active,
    onEvent: (event) => {
      // Only an incident event naming this incident is relevant. The payload is a
      // summary rather than the detail, so it points at the change but is not
      // applied — the re-read is what makes the membership and the timestamps
      // consistent with the new status (M15.18).
      if (!isIncidentEvent(event)) return
      const summary: IncidentSummary = event.data
      if (summary.incident_id !== incidentId) return
      reload()
    },
    onReconnect: () => {
      // No replay buffer, so the detail is re-read rather than trusted across the
      // outage (M15.27).
      reload()
    },
  })

  const isNotFound = resource.error?.kind === 'not_found'

  const reloadStable = useCallback(() => reload(), [reload])

  return {
    incident: resource.data,
    isNotFound,
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    isIdle: !active,
    reload: reloadStable,
    isConnected: channel.isConnected,
    phase: channel.phase,
  }
}
