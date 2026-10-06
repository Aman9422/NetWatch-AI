/**
 * Stored notifications (M15.25).
 *
 * Read-only, and that is the whole truth about this subsystem: the base
 * application has **no external delivery integration**, so nothing is emailed,
 * pushed or posted anywhere, and a page must not imply a notification was "sent"
 * or "delivered". There is no delivery state in these models because there is no
 * delivery.
 *
 * There is also deliberately **no mark-as-read verb** — M13.23 offers no write,
 * and adding one on the client would imply a read/unread workflow the rest of the
 * application does not participate in. This hook exposes `is_read` as stored and
 * offers no control that pretends otherwise.
 *
 * There is no WebSocket channel for notifications either (M14 defines four, none
 * of them notifications), so a page refreshes explicitly (M15.34).
 */

import { useMemo } from 'react'
import { fetchNotifications, fetchUnreadCount } from '@/services'
import type { ApiError, PageWindow } from '@/services'
import type { Notification, NotificationList, NotificationQuery } from '@/types'
import { useAsyncResource } from './useAsyncResource'

/** Options for {@link useNotifications}. */
export interface NotificationOptions {
  /** Filters to apply. Compared by value, so it may be built inline. */
  readonly query?: NotificationQuery
  /** Page window. Compared by value. */
  readonly window?: PageWindow
  /**
   * Whether to read the unread total as well. Defaults True.
   *
   * The count is the backend's own tally under the `unread_only` filter rather
   * than a client-side count of whatever page is loaded, so a badge is correct
   * even when only one notification is on screen.
   */
  readonly withUnreadCount?: boolean
  readonly enabled?: boolean
}

/** What {@link useNotifications} returns. */
export interface NotificationResource {
  readonly notifications: readonly Notification[]
  readonly page: NotificationList | null
  /** The true match count across every page, or `null` when uncountable. */
  readonly total: number | null
  readonly hasMore: boolean
  /** How many unread notifications exist, or `null` when that cannot be known. */
  readonly unreadCount: number | null
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  /** A failure of the count read, kept separate from the listing's failure. */
  readonly unreadError: ApiError | null
  /** The count-read failure that is blocking the view, if any. */
  readonly unreadBlockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  /** True when the store holds no notification for this filter. */
  readonly isEmpty: boolean
  readonly reload: () => void
}

/**
 * Read stored notifications and, optionally, the unread total.
 *
 * @param options Filters, page window, whether to count, and whether to read.
 */
export function useNotifications(
  options: NotificationOptions = {},
): NotificationResource {
  const { query, window, withUnreadCount = true, enabled = true } = options

  const cacheKey = useMemo(
    () =>
      JSON.stringify({
        unread_only: query?.unread_only ?? null,
        limit: window?.limit ?? null,
        offset: window?.offset ?? null,
      }),
    [query, window],
  )

  const resource = useAsyncResource(
    (signal) => fetchNotifications(query ?? {}, window, signal),
    [cacheKey],
    { enabled, isEmpty: (page: NotificationList) => page.notifications.length === 0 },
  )

  const unread = useAsyncResource((signal) => fetchUnreadCount(signal), [], {
    enabled: enabled && withUnreadCount,
  })

  const page = resource.data

  return {
    notifications: page?.notifications ?? [],
    page,
    total: page?.total ?? null,
    hasMore: page?.has_more === true,
    unreadCount: unread.data,
    error: resource.error,
    blockingError: resource.blockingError,
    unreadError: unread.error,
    unreadBlockingError: unread.blockingError,
    isLoading: resource.isLoading || unread.isLoading,
    isInitialLoading: resource.isInitialLoading || unread.isInitialLoading,
    isRefreshing:
      (resource.isLoading && !resource.isInitialLoading) ||
      (unread.isLoading && !unread.isInitialLoading),
    isEmpty: page !== null && page.notifications.length === 0,
    reload: resource.reload,
  }
}
