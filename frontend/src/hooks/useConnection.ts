/**
 * One tracked conversation (M15.13).
 *
 * `GET /connections/{id}` reads a single conversation by its deterministic id, and
 * the tracker can answer `404` for one it has already retired — a conversation
 * expires on M9's own timer, independently of anything the client is doing, so a
 * row that was listed a moment ago can be gone by the time it is opened. That case
 * is kept distinct so a page says "no longer tracked" rather than "the request
 * failed" (M9.10).
 *
 * Nothing here judges the conversation. A connection has no severity and no risk
 * score — M9 tracks, it does not score — so the only state this reads is the
 * tracker's own `state` and `active` flag, which the frontend must not recompute
 * (M15.13).
 */

import { fetchConnection } from '@/services'
import type { ApiError } from '@/services'
import type { Connection } from '@/types'
import { useAsyncResource } from './useAsyncResource'

/** What {@link useConnection} returns. */
export interface ConnectionDetailResource {
  /** The conversation, or `null` while loading or once it has been retired. */
  readonly connection: Connection | null
  /**
   * True when the tracker answered `404`.
   *
   * "No longer tracked" rather than "not found": M9 retires conversations on its
   * expiry window, so an id that was valid stops being valid without anything
   * having gone wrong.
   */
  readonly isRetired: boolean
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  /** True when `connectionId` is `null`, so nothing was requested. */
  readonly isIdle: boolean
  readonly reload: () => void
}

/**
 * Read one tracked conversation.
 *
 * @param connectionId The conversation to read, or `null` for none.
 * @param options Whether to run.
 */
export function useConnection(
  connectionId: string | null,
  options: { readonly enabled?: boolean } = {},
): ConnectionDetailResource {
  const { enabled = true } = options
  const active = enabled && connectionId !== null

  const resource = useAsyncResource(
    (signal) => fetchConnection(connectionId as string, signal),
    [connectionId],
    { enabled: active },
  )

  return {
    connection: resource.data,
    isRetired: resource.error?.kind === 'not_found',
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    isIdle: !active,
    reload: resource.reload,
  }
}
