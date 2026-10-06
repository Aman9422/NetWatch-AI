/**
 * Notification service (M13.23, M15.25).
 *
 * Read-only over the `notifications` table, and that is the whole truth about
 * this subsystem: the base application has **no external delivery integration**.
 * Nothing is emailed, pushed or posted anywhere, so a page must not imply that a
 * notification was "sent" or "delivered" (M15.25). There is no delivery state in
 * these models because there is no delivery.
 *
 * There is also **no mark-as-read verb**, deliberately. Changing `is_read` would
 * be a write M13.23 does not offer, and adding one on the client would imply a
 * read/unread workflow the rest of the application does not participate in. The
 * UI shows `is_read` as stored and offers no control that pretends otherwise.
 *
 * Ordering is `created_at DESC, id DESC`, so two notifications sharing a
 * timestamp still come back in a stable order and a page cannot repeat or skip a
 * row.
 */

import { apiGet } from './client'
import { NotificationPaths } from './endpoints'
import { withPageWindow, type PageWindow } from './query'
import type { Notification, NotificationList, NotificationQuery } from '@/types'

/**
 * `GET /api/v1/notifications` — stored notifications, newest first.
 *
 * `count` is this page's size and `total` the size of the whole match set, both
 * computed over the same filter, so the two cannot disagree.
 */
export function fetchNotifications(
  query: NotificationQuery = {},
  window?: PageWindow,
  signal?: AbortSignal,
): Promise<NotificationList> {
  return apiGet<NotificationList>(
    NotificationPaths.list,
    withPageWindow(query, window),
    { signal },
  )
}

/**
 * `GET /api/v1/notifications/{notification_id}` — one stored notification.
 *
 * Resolves to a `404` for an id that does not exist, which the caller renders as
 * "not found" rather than as an empty record.
 */
export function fetchNotification(
  notificationId: number,
  signal?: AbortSignal,
): Promise<Notification> {
  return apiGet<Notification>(
    NotificationPaths.detail(notificationId),
    undefined,
    { signal },
  )
}

/**
 * How many unread notifications exist, or `null` when that cannot be known.
 *
 * Reads `total` under the `unread_only` filter, which is the backend's own count
 * rather than a client-side tally of the page it happens to hold. It returns
 * `null` when the count is absent rather than reporting `0`, because "no unread
 * notifications" and "the store cannot count" are different answers and only one
 * of them should clear a badge.
 */
export async function fetchUnreadCount(signal?: AbortSignal): Promise<number | null> {
  const page = await fetchNotifications({ unread_only: true, limit: 1 }, undefined, signal)
  return typeof page.total === 'number' ? page.total : null
}
