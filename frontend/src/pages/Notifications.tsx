/**
 * Notifications — stored records, read-only, with no delivery implied (M15.25).
 *
 * This page did not exist before M15. It is small on purpose, because the
 * subsystem is small and saying so is the milestone:
 *
 * * **Nothing is delivered.** The base application has no email, push or webhook
 *   integration, so no field reports a channel, a destination or a delivery time,
 *   and this page claims none. A notification here is a **row that was stored**,
 *   and the copy says exactly that.
 * * **There is no mark-as-read.** M13.23 offers no write for `is_read`, so the
 *   page shows the flag as stored and offers no control that would imply a
 *   read/unread workflow the rest of the application does not take part in.
 *   Rows are labelled "read"/"unread" as *stored state*, never as something the
 *   operator can change here.
 * * **The unread figure is the backend's tally.** It is read under the
 *   `unread_only` filter rather than counted from whatever page is loaded, so it
 *   is correct even when one notification is on screen. When the count cannot be
 *   known it renders as unknown rather than as zero, because "none unread" and
 *   "the store cannot count" are different answers and only one should clear a
 *   badge.
 *
 * There is no WebSocket channel for notifications (M14 defines four, none of them
 * this), so the listing is read and refreshed explicitly (M15.34).
 */

import { useMemo, useState } from 'react'
import {
  Bell, BellOff, CheckCircle2, Circle, Clock, Info, Inbox, RefreshCw,
} from 'lucide-react'
import { AsyncSection, EmptyState, RefreshFailureBanner, Spinner } from '@/components/AsyncState'
import { useAsyncResource, useNotifications } from '@/hooks'
import { DEFAULT_PAGE_LIMIT, fetchNotification } from '@/services'
import { C, tint } from '@/lib/tokens'
import {
  UNKNOWN_TEXT, formatCount, formatEpochRelative, formatTimestamp,
} from '@/lib/format'
import type { Notification } from '@/types'

/** How many notifications one page shows. */
const PAGE_SIZE = DEFAULT_PAGE_LIMIT

/**
 * The colour for a stored notification type.
 *
 * The backend stores whatever string a writer supplied, so this maps the ones the
 * application produces and falls back to a neutral shade — it never assumes a
 * closed set, because no model declares one.
 */
const TYPE_COLORS: Readonly<Record<string, string>> = {
  alert: C.danger,
  warning: C.warning,
  incident: C.orange,
  info: C.info,
  system: C.purple,
  success: C.success,
}

/** A readable label for a stored type. */
function typeLabel(value: string): string {
  if (value === '') return 'unspecified'
  const spaced = value.replace(/_/g, ' ')
  return spaced.charAt(0).toUpperCase() + spaced.slice(1)
}

/** The colour for a stored type, falling back to a neutral shade. */
function typeColor(value: string): string {
  return TYPE_COLORS[value.toLowerCase()] ?? C.muted
}

/** The stored read state, as a small labelled indicator. */
function ReadState({ isRead }: { isRead: boolean }) {
  const color = isRead ? C.dim : C.accent
  return (
    <span className="flex items-center gap-1.5 text-xs whitespace-nowrap" style={{ color }}
      title={isRead
        ? 'Stored as read. This subsystem offers no write to change it.'
        : 'Stored as unread. This subsystem offers no write to change it.'}>
      {isRead
        ? <CheckCircle2 size={11} />
        : <Circle size={11} />}
      {isRead ? 'read' : 'unread'}
    </span>
  )
}

/** One notification in full, read from `GET /notifications/{id}`. */
function NotificationDetailPanel({ notificationId, fallback, onBack }: {
  notificationId: number
  fallback: Notification | null
  onBack: () => void
}) {
  const resource = useAsyncResource(
    (signal) => fetchNotification(notificationId, signal),
    [notificationId],
  )
  const notification = resource.data ?? fallback
  const color = notification === null ? C.muted : typeColor(notification.notification_type)

  return (
    <div className="space-y-4 fade-in-up">
      <button onClick={onBack}
        className="flex items-center gap-2 text-sm font-medium transition-colors"
        style={{ color: C.muted }}
        onMouseEnter={e => (e.currentTarget.style.color = C.accent)}
        onMouseLeave={e => (e.currentTarget.style.color = C.muted)}>
        ← Back to Notifications
      </button>

      {notification === null && resource.error !== null && (
        <div className="rounded-2xl border" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <AsyncSection isInitialLoading={false} error={resource.blockingError} isEmpty={false}
            onRetry={resource.reload} minHeight={200}>
            <span />
          </AsyncSection>
        </div>
      )}

      {notification === null && resource.isInitialLoading && (
        <div className="rounded-2xl border" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="flex items-center justify-center gap-3 py-16">
            <Spinner size={18} />
            <span className="text-xs" style={{ color: C.faint }}>Loading notification…</span>
          </div>
        </div>
      )}

      {notification !== null && (
        <>
          <div className="rounded-2xl border p-6" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-2xl flex-shrink-0" style={{ backgroundColor: tint(color, 0.1) }}>
                <Bell size={22} style={{ color }} />
              </div>
              <div className="min-w-0 flex-1">
                <h2 className="text-base font-bold text-white break-words">{notification.title}</h2>
                <div className="flex items-center gap-3 flex-wrap mt-2">
                  <span className="text-xs font-semibold px-2.5 py-1 rounded-full"
                    style={{ backgroundColor: tint(color, 0.12), color }}>
                    {typeLabel(notification.notification_type)}
                  </span>
                  <ReadState isRead={notification.is_read} />
                  <span className="mono text-xs" style={{ color: C.faint }}>
                    #{notification.notification_id}
                  </span>
                </div>
              </div>
            </div>

            <p className="text-sm mt-5 whitespace-pre-wrap break-words" style={{ color: C.text }}>
              {notification.message === '' ? UNKNOWN_TEXT : notification.message}
            </p>

            <div className="grid grid-cols-3 gap-4 mt-6 pt-6 border-t" style={{ borderColor: C.border }}>
              <div>
                <div className="flex items-center gap-1.5 text-xs mb-1" style={{ color: C.faint }}>
                  <Clock size={11} /> Stored at
                </div>
                <div className="text-sm font-semibold text-white">
                  {formatTimestamp(notification.created_at)}
                </div>
              </div>
              <div>
                <div className="flex items-center gap-1.5 text-xs mb-1" style={{ color: C.faint }}>
                  <Clock size={11} /> Age
                </div>
                <div className="text-sm font-semibold text-white">
                  {formatEpochRelative(notification.created_at_epoch)}
                </div>
              </div>
              <div>
                <div className="text-xs mb-1" style={{ color: C.faint }}>Addressed to</div>
                <div className="text-sm font-semibold text-white mono">
                  {notification.user_id === null ? UNKNOWN_TEXT : `user ${notification.user_id}`}
                </div>
              </div>
            </div>
          </div>

          {resource.error !== null && (
            <RefreshFailureBanner error={resource.error} onRetry={resource.reload} />
          )}
        </>
      )}
    </div>
  )
}

/** One row of the notification list. Read state as stored, and no action. */
function NotificationRow({ notification, onOpen }: {
  notification: Notification
  onOpen: () => void
}) {
  const color = typeColor(notification.notification_type)
  return (
    <tr onClick={onOpen}
      className="border-b transition-all duration-150 cursor-pointer align-top"
      style={{ borderColor: '#1a2744' }}
      onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)')}
      onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
      <td className="pl-5 py-3 pr-4">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-xl flex-shrink-0" style={{ backgroundColor: tint(color, 0.08) }}>
            <Bell size={14} style={{ color }} />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-white truncate max-w-[320px]"
                title={notification.title}>
                {notification.title}
              </span>
              {!notification.is_read && (
                <span className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                  style={{ backgroundColor: C.accent }} title="Stored as unread" />
              )}
            </div>
            <p className="text-xs mt-0.5 line-clamp-2 max-w-[440px]" style={{ color: C.muted }}>
              {notification.message === '' ? UNKNOWN_TEXT : notification.message}
            </p>
          </div>
        </div>
      </td>
      <td className="py-3 pr-4">
        <span className="text-xs font-medium px-2 py-0.5 rounded-full whitespace-nowrap"
          style={{ backgroundColor: tint(color, 0.12), color }}>
          {typeLabel(notification.notification_type)}
        </span>
      </td>
      <td className="py-3 pr-4">
        <ReadState isRead={notification.is_read} />
      </td>
      <td className="py-3 pr-5 text-xs whitespace-nowrap" style={{ color: C.muted }}>
        {formatEpochRelative(notification.created_at_epoch)}
      </td>
    </tr>
  )
}
// ─── Page ────────────────────────────────────────────────────────────────────

export default function Notifications() {
  const [selected, setSelected] = useState<Notification | null>(null)
  const [unreadOnly, setUnreadOnly] = useState(false)
  const [offset, setOffset] = useState(0)

  const query = useMemo(
    () => (unreadOnly ? { unread_only: true } : {}),
    [unreadOnly],
  )
  const window = useMemo(() => ({ limit: PAGE_SIZE, offset }), [offset])

  // The unread figure comes from the listing's own `unread_only` read, which the
  // hook performs beside the page request — so it describes the whole store even
  // when this page holds one row.
  const resource = useNotifications({ query, window })

  if (selected !== null) {
    return (
      <NotificationDetailPanel
        notificationId={selected.notification_id}
        fallback={selected}
        onBack={() => setSelected(null)}
      />
    )
  }

  const notifications = resource.notifications
  const unread = resource.unreadCount

  return (
    <div className="space-y-4">
      {/* What this is, and the two things it is not. */}
      <div className="rounded-2xl border p-5" style={{ backgroundColor: C.card, borderColor: C.border }}>
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1.5">
              <Bell size={15} style={{ color: C.accent }} />
              <h1 className="text-sm font-semibold text-white">Notifications</h1>
            </div>
            <p className="text-xs max-w-2xl" style={{ color: C.muted }}>
              Stored notification records, newest first. A row here is something the application
              <span className="font-semibold text-white"> wrote to its own store</span> — it is not a
              message that was sent anywhere.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {unread === null ? (
              <span className="px-2.5 py-1 rounded-full text-xs font-semibold"
                style={{ backgroundColor: tint(C.dim, 0.12), color: C.dim }}>
                unread count unknown
              </span>
            ) : (
              <span className="px-2.5 py-1 rounded-full text-xs font-semibold"
                style={{
                  backgroundColor: tint(unread > 0 ? C.accent : C.dim, 0.12),
                  color: unread > 0 ? C.accent : C.dim,
                }}>
                {formatCount(unread)} unread
              </span>
            )}
            <button onClick={resource.reload} disabled={resource.isLoading}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border disabled:opacity-50"
              style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
              <RefreshCw size={12} className={resource.isLoading ? 'animate-spin' : undefined} />
              Refresh
            </button>
          </div>
        </div>
      </div>

      {/* The absence of a delivery subsystem, stated rather than implied. */}
      <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl border"
        style={{ backgroundColor: tint(C.info, 0.06), borderColor: tint(C.info, 0.25) }}>
        <Info size={13} style={{ color: C.info, flexShrink: 0, marginTop: 1 }} />
        <p className="text-xs" style={{ color: C.muted }}>
          This base application has no email, push or webhook integration, so nothing is delivered
          and no delivery state exists. There is also no mark-as-read: the API offers no write, so
          "read" and "unread" below are the <span className="font-semibold text-white">stored</span>
          {' '}values and cannot be changed from this page.
        </p>
      </div>

      {resource.unreadError !== null && (
        <p className="text-xs px-1" style={{ color: C.faint }}>
          The unread tally could not be read
          {resource.unreadError.userMessage === '' ? '' : `: ${resource.unreadError.userMessage}`}
          {' '}— shown as unknown rather than as zero, because an uncountable store is not an empty one.
        </p>
      )}

      {/* Filters — the one filter the endpoint accepts. */}
      <div className="flex items-center gap-2 flex-wrap">
        <button type="button"
          onClick={() => { setUnreadOnly(!unreadOnly); setOffset(0) }}
          className="px-3 py-2 rounded-xl text-xs font-medium border"
          style={{
            backgroundColor: unreadOnly ? tint(C.accent, 0.14) : C.card,
            borderColor: unreadOnly ? C.accent : C.border,
            color: unreadOnly ? C.accent : C.muted,
          }}>
          {unreadOnly ? 'Showing unread only' : 'Show unread only'}
        </button>
        <span className="text-xs ml-auto" style={{ color: C.faint }}>
          Filtering is done by the backend under <span className="mono">unread_only</span>, so the
          counts below describe the whole match set rather than the rows on screen.
        </span>
      </div>

      {resource.error !== null && notifications.length > 0 && (
        <RefreshFailureBanner error={resource.error} onRetry={resource.reload} />
      )}

      <div className="rounded-2xl border overflow-hidden"
        style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: C.border }}>
          <div>
            <h2 className="text-sm font-semibold text-white">
              {unreadOnly ? 'Unread notifications' : 'Stored notifications'}
            </h2>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>
              {notifications.length} loaded
              {resource.total === null ? '' : ` of ${formatCount(resource.total)} matching`}
              {` · rows ${offset + 1}–${offset + notifications.length}`}
            </p>
          </div>
          <span className="text-xs" style={{ color: C.faint }}>Read-only — no action is offered</span>
        </div>

        <AsyncSection
          isInitialLoading={resource.isInitialLoading}
          error={resource.blockingError}
          isEmpty={false}
          loadingLabel="Loading notifications…"
          errorTitle="Unable to load notifications"
          onRetry={resource.reload}
          minHeight={240}
        >
          {notifications.length === 0 ? (
            <EmptyState
              title={unreadOnly ? 'Nothing unread' : 'No notifications stored'}
              hint={unreadOnly
                ? 'Every stored notification is marked read. Nothing has been written since.'
                : 'Nothing has been written to the notification store yet. Alerts and incidents are recorded in their own sections rather than here.'}
              icon={unreadOnly ? <BellOff size={28} /> : <Inbox size={28} />}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b" style={{ borderColor: C.border }}>
                    <th className="text-left pl-5 py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Notification</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Type</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Stored state</th>
                    <th className="text-left py-2.5 pr-5 text-xs font-medium" style={{ color: C.dim }}>Stored</th>
                  </tr>
                </thead>
                <tbody>
                  {notifications.map(notification => (
                    <NotificationRow
                      key={notification.notification_id}
                      notification={notification}
                      onOpen={() => setSelected(notification)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AsyncSection>

        <div className="flex items-center justify-between px-5 py-3 border-t" style={{ borderColor: C.border }}>
          <button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            disabled={offset === 0 || resource.isLoading}
            className="px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            Previous
          </button>
          <span className="text-xs" style={{ color: C.faint }}>
            {offset === 0 && !resource.hasMore ? 'All matching notifications' : `Offset ${offset}`}
          </span>
          <button onClick={() => setOffset(offset + PAGE_SIZE)}
            disabled={!resource.hasMore || resource.isLoading}
            className="px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            Next
          </button>
        </div>
      </div>

      <p className="text-xs px-1" style={{ color: C.faint }}>
        Selecting a row reads that notification's own record. A value of {UNKNOWN_TEXT} means the
        backend stored nothing for that field — an unfilled recipient, for instance, is not the same
        as a notification addressed to nobody.
      </p>
    </div>
  )
}
