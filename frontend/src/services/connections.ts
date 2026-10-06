/**
 * Connection service (M9, M15.13).
 *
 * A connection is an M9 *conversation*: an identity derived from the five-tuple,
 * plus counters for how much each side sent. It carries no severity and no risk,
 * because M9 tracks and never judges — the page that renders one must not add a
 * verdict (M15.13).
 *
 * **The frontend does not track connections.** `active` and `state` are the
 * backend's own view of whether a conversation is still being seen, derived from
 * its expiry window (M9.10/M9.11). Recomputing either in React would produce a
 * second answer that disagreed with the tracker as soon as a timeout fired.
 */

import { apiGet, apiPost } from './client'
import { ConnectionPaths } from './endpoints'
import { withPageWindow, type PageWindow } from './query'
import type { Connection, ConnectionPage, ConnectionQuery, ExpireResult } from '@/types'

/**
 * `GET /api/v1/connections` — tracked conversations, active and historical.
 *
 * `total` is present because the tracker can count its rows, so a listing can
 * show how much of the whole it is displaying.
 */
export function fetchConnections(
  query: ConnectionQuery = {},
  window?: PageWindow,
  signal?: AbortSignal,
): Promise<ConnectionPage> {
  return apiGet<ConnectionPage>(
    ConnectionPaths.list,
    withPageWindow(query, window),
    { signal },
  )
}

/**
 * `GET /api/v1/connections/active` — only conversations still being tracked.
 *
 * A separate endpoint rather than `?active_only=true`, so the "active" figure a
 * page shows is the backend's own answer rather than a filter the client applied.
 */
export function fetchActiveConnections(
  window?: PageWindow,
  signal?: AbortSignal,
): Promise<ConnectionPage> {
  return apiGet<ConnectionPage>(
    ConnectionPaths.active,
    withPageWindow({}, window),
    { signal },
  )
}

/**
 * `GET /api/v1/connections/{connection_id}` — one conversation.
 *
 * The id contains `|`, `:` and `.` (`TCP|10.0.0.1:52134|1.1.1.1:443`), so the
 * path builder encodes it as a single segment.
 */
export function fetchConnection(
  connectionId: string,
  signal?: AbortSignal,
): Promise<Connection> {
  return apiGet<Connection>(ConnectionPaths.detail(connectionId), undefined, { signal })
}

/**
 * `POST /api/v1/connections/expire` — the M9.22 development helper.
 *
 * Forces the expiry sweep that a running tracker performs on its own timer, so an
 * operator can watch `active` become `historical` without waiting. It is exposed
 * because the endpoint exists, not because the UI needs to schedule expiry
 * itself — it must not.
 */
export function expireConnections(signal?: AbortSignal): Promise<ExpireResult> {
  return apiPost<ExpireResult>(ConnectionPaths.expire, { signal })
}
