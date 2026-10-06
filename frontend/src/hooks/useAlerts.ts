/**
 * Alerts: listing, live updates and lifecycle (M15.14/M15.15).
 *
 * Three mechanisms meet here, and keeping them distinct is the point:
 *
 * * `GET /alerts` is the **listing** for whatever filter the page is showing;
 * * `/ws/alerts` delivers `alert.created` and the five lifecycle events, whose
 *   payload is the same wire view the listing serves — so a row can be **replaced
 *   in place** rather than appended as a duplicate (M15.14);
 * * the named lifecycle routes move an alert and answer with the updated row.
 *
 * How live events meet the listing is a deliberate choice. An update to an alert
 * *already on screen* replaces that row. A **new** alert is not inserted into a
 * filtered, paginated listing, because deciding whether it belongs there would
 * mean re-implementing the backend's filter and its ordering in React. Instead it
 * is collected in {@link AlertListResource.pendingNew}, and the page offers the
 * operator a refresh — which is honest, because the backend definition of "the
 * next page of this filter" is not something the client can reproduce.
 *
 * **No transition rule is implemented here.** Which moves are legal is M11's
 * `VALID_TRANSITIONS`; the page uses `ALERT_TRANSITIONS` only to decide which
 * buttons to offer, and a refused move comes back as a `409` that is reported
 * rather than worked around (M15.15).
 */

import { useCallback, useMemo, useState } from 'react'
import {
  applyAlertLifecycle,
  fetchAlertSummary,
  fetchAlerts,
} from '@/services'
import type { ApiError, PageWindow } from '@/services'
import { EventType, isAlertEvent } from '@/types'
import type {
  Alert,
  AlertLifecycleAction,
  AlertPage,
  AlertQuery,
  AlertSummary,
  ConnectionPhase,
} from '@/types'
import { useAction } from './useAction'
import { useAsyncResource } from './useAsyncResource'
import { useBoundedKeyedList } from './useBoundedList'
import { useChannelEvents } from './useChannelEvents'

/** How many live-alert rows are remembered per kind. */
export const LIVE_ALERT_CAPACITY = 200

/** The identity of an alert row. */
export function alertKey(alert: Alert): string {
  return String(alert.alert_id)
}

/** Options for {@link useAlerts}. */
export interface AlertListOptions {
  /** Filters to apply. Compared by value, so it may be built inline. */
  readonly query?: AlertQuery
  /** Page window. Compared by value. */
  readonly window?: PageWindow
  /** Whether to read the severity/status counts as well. Defaults True. */
  readonly withSummary?: boolean
  readonly enabled?: boolean
}

/** What {@link useAlerts} returns. */
export interface AlertListResource {
  /** The listing, with live updates to its own rows applied in place. */
  readonly alerts: readonly Alert[]
  /**
   * Alerts created on the wire that the current listing does not contain.
   *
   * Never merged in: whether one belongs in this filtered page is the backend's
   * answer, so the page offers a refresh instead of guessing.
   */
  readonly pendingNew: readonly Alert[]
  readonly page: AlertPage | null
  readonly summary: AlertSummary | null
  readonly total: number | null
  readonly hasMore: boolean
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  /** True when the listing answered with no alerts. */
  readonly isEmpty: boolean
  readonly reload: () => void
  readonly isConnected: boolean
  readonly phase: ConnectionPhase
  readonly lastEventAt: number | null
  /** True while a lifecycle move is in flight. */
  readonly isTransitioning: boolean
  /** The last refused lifecycle move, for an inline message. */
  readonly actionError: ApiError | null
  /**
   * Move one alert through its lifecycle.
   *
   * Resolves `null` on success or the refusal. On success the returned row is
   * applied immediately, so the table does not wait for the matching event.
   */
  readonly transition: (
    alertId: number,
    action: AlertLifecycleAction,
  ) => Promise<ApiError | null>
}

/**
 * Read alerts and follow their lifecycle.
 *
 * @param options Filters, page window, whether to read counts, and whether to run.
 */
export function useAlerts(options: AlertListOptions = {}): AlertListResource {
  const { query, window, withSummary = true, enabled = true } = options

  const cacheKey = useMemo(
    () =>
      JSON.stringify({
        severity: query?.severity ?? null,
        min_severity: query?.min_severity ?? null,
        status: query?.status ?? null,
        rule_id: query?.rule_id ?? null,
        rule_key: query?.rule_key ?? null,
        source_ip: query?.source_ip ?? null,
        destination_ip: query?.destination_ip ?? null,
        since: query?.since ?? null,
        until: query?.until ?? null,
        limit: window?.limit ?? null,
        offset: window?.offset ?? null,
      }),
    [query, window],
  )

  const resource = useAsyncResource(
    (signal) => fetchAlerts(query ?? {}, window, signal),
    [cacheKey],
    { enabled, isEmpty: (page: AlertPage) => page.alerts.length === 0 },
  )

  const summary = useAsyncResource(
    (signal) => fetchAlertSummary(signal),
    [],
    { enabled: enabled && withSummary },
  )

  // Updated rows and created rows are tracked apart, because they are used
  // differently: one replaces a row, the other becomes a "new alert" notice.
  const updated = useBoundedKeyedList<Alert>(LIVE_ALERT_CAPACITY, alertKey)
  const created = useBoundedKeyedList<Alert>(LIVE_ALERT_CAPACITY, alertKey)
  // A bump forces a re-render after a live write, since the lists themselves are
  // mutable collections rather than state this hook owns.
  const [liveVersion, setLiveVersion] = useState(0)

  const { reload } = resource
  const { reload: reloadSummary } = summary

  const channel = useChannelEvents({
    channel: 'alerts',
    enabled,
    onEvent: (event) => {
      if (!isAlertEvent(event)) return
      const alert = event.data
      if (event.type === EventType.ALERT_CREATED) created.upsert(alert)
      else updated.upsert(alert)
      setLiveVersion((version) => version + 1)
    },
    onReconnect: () => {
      // Both live collections are dropped: REST is about to be authoritative
      // again, and keeping the old rows would let a stale update outlive the
      // listing it was applied to (M15.27).
      updated.clear()
      created.clear()
      setLiveVersion((version) => version + 1)
      reload()
      reloadSummary()
    },
  })

  const transitionAction = useAction(applyAlertLifecycle)

  const transition = useCallback(
    async (alertId: number, action: AlertLifecycleAction): Promise<ApiError | null> => {
      const outcome = await transitionAction.run(alertId, action)
      if (!outcome.ok) return outcome.error
      // The response is the updated row, so it is applied straight away rather
      // than waiting for the matching WebSocket event to arrive.
      updated.upsert(outcome.value)
      setLiveVersion((version) => version + 1)
      reloadSummary()
      return null
    },
    [transitionAction, updated, reloadSummary],
  )

  const pageAlerts = resource.data?.alerts ?? []
  const updatedById = useMemo(() => {
    void liveVersion
    const map = new Map<string, Alert>()
    for (const alert of updated.items) map.set(alertKey(alert), alert)
    return map
  }, [updated.items, liveVersion])

  const alerts = useMemo(
    () => pageAlerts.map((alert) => updatedById.get(alertKey(alert)) ?? alert),
    [pageAlerts, updatedById],
  )

  const pendingNew = useMemo(() => {
    void liveVersion
    const listedIds = new Set(pageAlerts.map(alertKey))
    return created.items.filter((alert) => !listedIds.has(alertKey(alert)))
  }, [created.items, pageAlerts, liveVersion])

  return {
    alerts,
    pendingNew,
    page: resource.data,
    summary: summary.data,
    total: resource.data?.total ?? null,
    hasMore: resource.data?.has_more === true,
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    isEmpty: resource.data !== null && resource.data.alerts.length === 0,
    reload,
    isConnected: channel.isConnected,
    phase: channel.phase,
    lastEventAt: channel.lastEventAt,
    isTransitioning: transitionAction.isRunning,
    actionError: transitionAction.error,
    transition,
  }
}
