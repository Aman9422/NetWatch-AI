/**
 * One alert in full (M15.14/M15.16).
 *
 * `GET /alerts/{id}` is a superset of a listing row: the same alert plus its
 * evidence records and a per-type tally. This hook reads it and keeps it current.
 *
 * Live updates arrive on the **alerts** channel (M14.10). An event naming the
 * alert on screen is applied **in place** — its payload is the same wire view the
 * detail carries for the alert itself — but the evidence is not in the event, so a
 * lifecycle event also triggers a re-read when the evidence tally could have
 * changed. The distinction is deliberate: a status change updates the header
 * immediately from the event, and the re-read reconciles the evidence beside it.
 *
 * Evidence is a **reference, never a copy** (M11.13): each record names a packet,
 * connection or device id. Nothing here fetches a payload, because M7 stores none
 * and M13 exposes none (M15.16).
 */

import { useCallback, useState } from 'react'
import { fetchAlert } from '@/services'
import type { ApiError } from '@/services'
import { isAlertEvent } from '@/types'
import type { Alert, AlertDetail, AlertEvidence, ConnectionPhase } from '@/types'
import { useAsyncResource } from './useAsyncResource'
import { useChannelEvents } from './useChannelEvents'

/** What {@link useAlertDetail} returns. */
export interface AlertDetailResource {
  /** The alert, or `null` while loading or when the id is unknown. */
  readonly alert: Alert | null
  /** The evidence records attached to the alert, newest first as served. */
  readonly evidence: readonly AlertEvidence[]
  /** Counts per evidence kind, straight from the response. */
  readonly evidenceByType: Readonly<Record<string, number>>
  /** True when the alert is a `404`, distinguished from a general failure. */
  readonly isNotFound: boolean
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  /** True when `alertId` is `null`, so nothing was requested. */
  readonly isIdle: boolean
  readonly reload: () => void
  readonly isConnected: boolean
  readonly phase: ConnectionPhase
}

/**
 * Read one alert with its evidence, and keep it current.
 *
 * @param alertId The alert to read, or `null` for none.
 * @param options Whether to run.
 */
export function useAlertDetail(
  alertId: number | null,
  options: { readonly enabled?: boolean } = {},
): AlertDetailResource {
  const { enabled = true } = options
  const active = enabled && alertId !== null

  const resource = useAsyncResource(
    (signal) => fetchAlert(alertId as number, signal),
    [alertId],
    { enabled: active },
  )

  // A live event for this alert is applied to the header immediately, while the
  // evidence — which the event does not carry — is reconciled by a re-read.
  const [liveAlert, setLiveAlert] = useState<Alert | null>(null)

  const { reload } = resource

  const channel = useChannelEvents({
    channel: 'alerts',
    enabled: active,
    onEvent: (event) => {
      if (!isAlertEvent(event)) return
      if (event.data.alert_id !== alertId) return
      setLiveAlert(event.data)
      // The evidence tally may have moved with the status, so the detail is
      // re-read; the header already shows the event's value meanwhile.
      reload()
    },
    onReconnect: () => {
      // No replay buffer, so a header patched from an event is dropped and the
      // detail is re-read for the current truth (M15.27).
      setLiveAlert(null)
      reload()
    },
  })

  const detail: AlertDetail | null = resource.data
  // A live update wins over the loaded alert, because it is more recent than the
  // request that produced the detail; the re-read then supersedes both.
  const alert: Alert | null = liveAlert ?? detail?.alert ?? null

  const reloadStable = useCallback(() => reload(), [reload])

  return {
    alert,
    evidence: detail?.evidence ?? [],
    evidenceByType: detail?.evidence_by_type ?? {},
    isNotFound: resource.error?.kind === 'not_found',
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
