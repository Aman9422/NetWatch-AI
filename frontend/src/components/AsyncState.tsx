/**
 * The four data states, rendered once (M15.8).
 *
 * Every data-driven page must be able to show *loading*, *success*, *empty* and
 * *error*, and the failure mode this module exists to prevent is a blank screen
 * when a request fails. A page composes `AsyncSection` (or the individual panels)
 * so the four states look the same everywhere and no page invents a fifth.
 *
 * Two distinctions the components keep, because collapsing either would mislead:
 *
 * * **"loading" and "refreshing" are different.** {@link AsyncSection} shows a
 *   spinner only when there is nothing to display yet (`isInitialLoading`); a
 *   refresh over existing content keeps that content on screen. Blanking a table
 *   on every refresh is the flicker this avoids.
 * * **"empty" and "unavailable" are different.** A section that answered with no
 *   rows is empty; a section whose request failed is an error. Only the second
 *   offers a retry, and only when the failure is one a retry could fix
 *   (`ApiError.isRetryable`).
 *
 * The error panel renders `ApiError.userMessage`, which is always a sentence this
 * application produced — a backend stack trace never reaches a screen (M15.7).
 */

import type { ReactNode } from 'react'
import { AlertTriangle, Inbox, RefreshCw, WifiOff } from 'lucide-react'
import type { ApiError } from '@/services'
import { C } from '@/lib/tokens'

/** A small spinning icon, in the shade the design uses for a busy control. */
export function Spinner({ size = 16, color = C.accent }: { size?: number; color?: string }) {
  return <RefreshCw size={size} className="animate-spin" style={{ color }} />
}

/** A centred busy panel, for a section with nothing to show yet. */
export function LoadingState({
  label = 'Loading…',
  minHeight = 160,
}: {
  label?: string
  minHeight?: number
}) {
  return (
    <div
      className="flex flex-col items-center justify-center gap-3"
      style={{ minHeight }}
    >
      <Spinner size={20} />
      <p className="text-xs" style={{ color: C.faint }}>
        {label}
      </p>
    </div>
  )
}

/** A centred empty panel, for a section that answered with no rows. */
export function EmptyState({
  title,
  hint,
  icon,
  minHeight = 160,
}: {
  title: string
  hint?: string
  icon?: ReactNode
  minHeight?: number
}) {
  return (
    <div
      className="flex flex-col items-center justify-center gap-3 text-center px-6"
      style={{ minHeight }}
    >
      <div style={{ color: C.border }}>{icon ?? <Inbox size={28} />}</div>
      <p className="text-sm font-medium text-white">{title}</p>
      {hint && (
        <p className="text-xs max-w-sm" style={{ color: C.faint }}>
          {hint}
        </p>
      )}
    </div>
  )
}

/** A centred error panel, with a retry only when a retry could help. */
export function ErrorState({
  error,
  title = 'Unable to load',
  onRetry,
  minHeight = 160,
}: {
  error: ApiError
  title?: string
  onRetry?: () => void
  minHeight?: number
}) {
  // A network failure reads differently from a server fault, and the icon says
  // which without the operator having to parse the sentence.
  const isNetwork = error.kind === 'network' || error.kind === 'timeout'
  return (
    <div
      className="flex flex-col items-center justify-center gap-3 text-center px-6"
      style={{ minHeight }}
    >
      <div style={{ color: C.danger }}>
        {isNetwork ? <WifiOff size={26} /> : <AlertTriangle size={26} />}
      </div>
      <p className="text-sm font-medium text-white">{title}</p>
      <p className="text-xs max-w-md" style={{ color: C.muted }}>
        {error.userMessage}
      </p>
      {error.fieldDetails.length > 0 && (
        <ul className="text-xs space-y-0.5" style={{ color: C.faint }}>
          {error.fieldDetails.map((detail) => (
            <li key={detail} className="mono">
              {detail}
            </li>
          ))}
        </ul>
      )}
      {onRetry && error.isRetryable && (
        <button
          onClick={onRetry}
          className="mt-1 flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold"
          style={{ backgroundColor: `${C.accent}15`, color: C.accent }}
        >
          <RefreshCw size={12} /> Retry
        </button>
      )}
      {onRetry && !error.isRetryable && (
        <button
          onClick={onRetry}
          className="mt-1 flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border"
          style={{ borderColor: C.border, color: C.muted }}
        >
          <RefreshCw size={12} /> Reload
        </button>
      )}
    </div>
  )
}

/**
 * A section the backend reported it could not read (M13.29).
 *
 * Not an {@link ErrorState}, because no request from this client failed and there
 * is nothing here to retry; and not an {@link EmptyState} either, because "no rows"
 * and "could not be asked" are different facts. It carries the backend's own
 * sentence, which already names the dependency that failed.
 */
export function UnavailableState({
  reason,
  minHeight = 160,
}: {
  reason: string
  minHeight?: number
}) {
  return (
    <div
      className="flex flex-col items-center justify-center gap-3 text-center px-6"
      style={{ minHeight }}
    >
      <div style={{ color: C.warning }}>
        <AlertTriangle size={26} />
      </div>
      <p className="text-sm font-medium text-white">This section could not be read</p>
      <p className="text-xs max-w-md" style={{ color: C.muted }}>
        {reason}
      </p>
    </div>
  )
}

/**
 * A slim "the last refresh failed" strip.
 *
 * Shown above content that is already on screen when a *reload* fails, so the
 * operator learns the data may be stale without losing what they were reading.
 */
export function RefreshFailureBanner({
  error,
  onRetry,
}: {
  error: ApiError
  onRetry?: () => void
}) {
  return (
    <div
      className="flex items-center gap-2 px-3 py-2 rounded-xl border text-xs"
      style={{
        backgroundColor: 'rgba(239,68,68,0.08)',
        borderColor: 'rgba(239,68,68,0.25)',
        color: C.danger,
      }}
    >
      <AlertTriangle size={12} style={{ flexShrink: 0 }} />
      <span className="flex-1" style={{ color: C.muted }}>
        {error.userMessage} The data below may be out of date.
      </span>
      {onRetry && (
        <button
          onClick={onRetry}
          className="font-semibold flex items-center gap-1"
          style={{ color: C.danger }}
        >
          <RefreshCw size={11} /> Retry
        </button>
      )}
    </div>
  )
}

/** What {@link AsyncSection} needs to choose a state. */
export interface AsyncSectionState {
  readonly isInitialLoading: boolean
  readonly error: ApiError | null
  readonly isEmpty: boolean
}

/** Options for {@link AsyncSection}. */
export interface AsyncSectionProps extends AsyncSectionState {
  readonly children: ReactNode
  /** Shown during the first load. */
  readonly loadingLabel?: string
  /** Shown when the section answered with no rows. */
  readonly emptyTitle?: string
  readonly emptyHint?: string
  readonly emptyIcon?: ReactNode
  /** Shown when the request failed and there is nothing to display. */
  readonly errorTitle?: string
  readonly onRetry?: () => void
  readonly minHeight?: number
  /**
   * The backend's own reason this section could not be read, when it said so.
   *
   * Distinct from `isEmpty`: a section the summary reported as unavailable has no
   * rows to show, and rendering "no alerts recorded" for it would state a calm
   * absence where the truth is that nothing could be read (M13.29/M15.8).
   */
  readonly unavailableReason?: string | null
}

/**
 * Render one of loading, error, unavailable, empty or the content, in that order.
 *
 * The order is the fix for the blank screen (M15.8): a section with no data and a
 * failure shows the failure, never nothing. When content exists, it is rendered
 * even if a *later* refresh failed — the page shows a
 * {@link RefreshFailureBanner} for that case instead of replacing good data.
 *
 * `unavailableReason` sits between error and empty because those are three
 * different facts: a request this client made and lost, a section the backend
 * named as unreadable, and a section that answered with no rows. Only the first is
 * this client's to retry, and none of them is the others.
 */
export function AsyncSection({
  isInitialLoading,
  error,
  isEmpty,
  children,
  loadingLabel,
  emptyTitle = 'Nothing to show',
  emptyHint,
  emptyIcon,
  errorTitle,
  onRetry,
  minHeight,
  unavailableReason = null,
}: AsyncSectionProps) {
  if (isInitialLoading) return <LoadingState label={loadingLabel} minHeight={minHeight} />
  if (error !== null) {
    return (
      <ErrorState error={error} title={errorTitle} onRetry={onRetry} minHeight={minHeight} />
    )
  }
  if (unavailableReason !== null) {
    return <UnavailableState reason={unavailableReason} minHeight={minHeight} />
  }
  if (isEmpty) {
    return <EmptyState title={emptyTitle} hint={emptyHint} icon={emptyIcon} minHeight={minHeight} />
  }
  return <>{children}</>
}
