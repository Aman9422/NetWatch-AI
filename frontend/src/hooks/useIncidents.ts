/**
 * Correlated incidents (M15.17/M15.18/M15.19).
 *
 * An incident is what several related events add up to, and it carries **three
 * numbers that mean different things and must not be conflated** (M12.16):
 *
 * * `risk_score` with its `risk_band` — the bounded `0..100` prioritisation;
 * * `correlation_confidence` — how strongly the events were judged related;
 * * `alert_confidence` — the mean evidence strength of the member alerts.
 *
 * All three are read as stored. None is recomputed here, and the page must keep
 * them visually distinct: rendering one in another's place would be the most
 * damaging display error this milestone could make (M15.17).
 *
 * Live updates arrive on the **alerts** channel, not a channel of their own
 * (M14.12), and their payload is the incident *summary* rather than the detail
 * view — an event announces that something changed, and the member lists remain
 * the detail endpoint's business. A live event for an incident already on screen
 * replaces that row; a newly created one is offered behind
 * {@link IncidentListResource.pendingNew} rather than inserted into a filtered
 * listing.
 *
 * Lifecycle moves are delegated: `investigate`, `resolve` and `dismiss` are
 * validated by M12's transition table, and a refusal is a `409` that is shown
 * rather than routed around (M15.19).
 */

import { useCallback, useMemo, useState } from 'react'
import { applyIncidentLifecycle, fetchIncidents, fetchOpenIncidents } from '@/services'
import type { ApiError, PageWindow } from '@/services'
import { EventType, isIncidentEvent } from '@/types'
import type {
  ConnectionPhase,
  IncidentLifecycleAction,
  IncidentPage,
  IncidentQuery,
  IncidentSummary,
} from '@/types'
import { useAction } from './useAction'
import { useAsyncResource } from './useAsyncResource'
import { useBoundedKeyedList } from './useBoundedList'
import { useChannelEvents } from './useChannelEvents'

/** How many live incident rows are remembered per kind. */
export const LIVE_INCIDENT_CAPACITY = 200

/**
 * The identity of an incident.
 *
 * Taken from the event envelope rather than the payload, because the summary's
 * `incident_id` is the same value and the envelope is guaranteed present on every
 * event.
 */
export function incidentKey(incident: IncidentSummary): string {
  return incident.incident_id
}

/** Options for {@link useIncidents}. */
export interface IncidentListOptions {
  /** Filters to apply. Compared by value, so it may be built inline. */
  readonly query?: IncidentQuery
  /** Page window. Compared by value. */
  readonly window?: PageWindow
  /**
   * Use `GET /incidents/open` instead of the filtered listing.
   *
   * The backend's own `ACTIVE_STATUSES`, so the "open" figure shown is its answer
   * rather than a filter this client applied.
   */
  readonly openOnly?: boolean
  readonly enabled?: boolean
}

/** What {@link useIncidents} returns. */
export interface IncidentListResource {
  /** The listing, with live updates to its own rows applied in place. */
  readonly incidents: readonly IncidentSummary[]
  /** Incidents created on the wire that this listing does not contain. */
  readonly pendingNew: readonly IncidentSummary[]
  readonly page: IncidentPage | null
  readonly total: number | null
  readonly hasMore: boolean
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  /** True when the listing answered with no incidents. */
  readonly isEmpty: boolean
  readonly reload: () => void
  readonly isConnected: boolean
  readonly phase: ConnectionPhase
  readonly lastEventAt: number | null
  /** True while a lifecycle move is in flight. */
  readonly isTransitioning: boolean
  /** The last refused move, for an inline message. */
  readonly actionError: ApiError | null
  /**
   * Move one incident through its lifecycle.
   *
   * Resolves `null` on success or the refusal. The returned incident is applied
   * immediately so the row does not wait for the matching event.
   */
  readonly transition: (
    incidentId: string,
    action: IncidentLifecycleAction,
  ) => Promise<ApiError | null>
}

/**
 * Read correlated incidents.
 *
 * @param options Filters, page window, endpoint choice, and whether to run.
 */
export function useIncidents(
  options: IncidentListOptions = {},
): IncidentListResource {
  const { query, window, openOnly = false, enabled = true } = options

  const cacheKey = useMemo(
    () =>
      JSON.stringify({
        endpoint: openOnly ? 'open' : 'list',
        status: query?.status ?? null,
        active_only: query?.active_only ?? null,
        source: query?.source ?? null,
        device_id: query?.device_id ?? null,
        connection_id: query?.connection_id ?? null,
        rule_id: query?.rule_id ?? null,
        correlation_rule_id: query?.correlation_rule_id ?? null,
        min_risk_score: query?.min_risk_score ?? null,
        max_risk_score: query?.max_risk_score ?? null,
        min_confidence: query?.min_confidence ?? null,
        since: query?.since ?? null,
        until: query?.until ?? null,
        order: query?.order ?? null,
        limit: window?.limit ?? null,
        offset: window?.offset ?? null,
      }),
    [openOnly, query, window],
  )

  const resource = useAsyncResource(
    (signal) =>
      openOnly
        ? fetchOpenIncidents(window, signal)
        : fetchIncidents(query ?? {}, window, signal),
    [cacheKey],
    { enabled, isEmpty: (page: IncidentPage) => page.incidents.length === 0 },
  )

  // Updated and created rows are tracked apart: one replaces a row, the other
  // becomes a "new incident" notice the operator can pull in with a refresh.
  const updated = useBoundedKeyedList<IncidentSummary>(
    LIVE_INCIDENT_CAPACITY,
    incidentKey,
  )
  const created = useBoundedKeyedList<IncidentSummary>(
    LIVE_INCIDENT_CAPACITY,
    incidentKey,
  )
  const [liveVersion, setLiveVersion] = useState(0)

  const { reload } = resource

  const channel = useChannelEvents({
    channel: 'alerts',
    enabled,
    onEvent: (event) => {
      if (!isIncidentEvent(event)) return
      const incident = event.data
      if (event.type === EventType.INCIDENT_CREATED) created.upsert(incident)
      else updated.upsert(incident)
      setLiveVersion((version) => version + 1)
    },
    onReconnect: () => {
      // Dropped, because REST is about to be authoritative again — a live patch
      // kept across an outage could outlive the state it was applied to.
      updated.clear()
      created.clear()
      setLiveVersion((version) => version + 1)
      reload()
    },
  })

  const transitionAction = useAction(applyIncidentLifecycle)

  const transition = useCallback(
    async (
      incidentId: string,
      action: IncidentLifecycleAction,
    ): Promise<ApiError | null> => {
      const outcome = await transitionAction.run(incidentId, action)
      if (!outcome.ok) return outcome.error
      // The detail response is a superset of the summary, so it satisfies the
      // listing row's fields and can be applied directly.
      updated.upsert(outcome.value)
      setLiveVersion((version) => version + 1)
      return null
    },
    [transitionAction, updated],
  )

  const pageIncidents = resource.data?.incidents ?? []

  const updatedById = useMemo(() => {
    void liveVersion
    const map = new Map<string, IncidentSummary>()
    for (const incident of updated.items) map.set(incidentKey(incident), incident)
    return map
  }, [updated.items, liveVersion])

  const incidents = useMemo(
    () =>
      pageIncidents.map(
        (incident) => updatedById.get(incidentKey(incident)) ?? incident,
      ),
    [pageIncidents, updatedById],
  )

  const pendingNew = useMemo(() => {
    void liveVersion
    const listedIds = new Set(pageIncidents.map(incidentKey))
    return created.items.filter((incident) => !listedIds.has(incidentKey(incident)))
  }, [created.items, pageIncidents, liveVersion])

  return {
    incidents,
    pendingNew,
    page: resource.data,
    total: resource.data?.total ?? null,
    hasMore: resource.data?.has_more === true,
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    isEmpty: resource.data !== null && resource.data.incidents.length === 0,
    reload,
    isConnected: channel.isConnected,
    phase: channel.phase,
    lastEventAt: channel.lastEventAt,
    isTransitioning: transitionAction.isRunning,
    actionError: transitionAction.error,
    transition,
  }
}
