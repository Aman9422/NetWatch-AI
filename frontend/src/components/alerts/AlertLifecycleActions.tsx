/**
 * The alert lifecycle controls (M15.15).
 *
 * Which buttons appear is decided by {@link ALERT_TRANSITIONS}, the frontend's
 * copy of M11's transition table — but that copy decides **what to offer**, never
 * **what is allowed**. The backend validates every move, and a refusal is a `409`
 * that this component displays rather than works around. Implementing the rule
 * here as well would mean two authorities that could disagree, and the one the
 * operator would be reading is the wrong one.
 *
 * Terminal states therefore render an explicit "no further transitions" note
 * instead of an empty row of controls: an alert that is resolved stays resolved,
 * and saying so is more useful than showing nothing.
 */

import { AlarmCheck, CheckCheck, EyeOff, ShieldQuestion, Loader2 } from 'lucide-react'
import { ALERT_TRANSITIONS } from '@/types'
import type { Alert, AlertLifecycleAction, AlertStatus } from '@/types'
import type { ApiError } from '@/services'
import { C, tint } from '@/lib/tokens'

/** How each target state is presented as a button. */
interface ActionPresentation {
  readonly action: AlertLifecycleAction
  readonly label: string
  readonly icon: React.ElementType
  readonly color: string
  /** A line describing what the move means, shown beside the controls. */
  readonly hint: string
}

/** The presentation for each state an alert may move to. */
const ACTION_PRESENTATION: Readonly<Record<AlertStatus, ActionPresentation | null>> = {
  open: null,
  acknowledged: {
    action: 'acknowledge',
    label: 'Acknowledge',
    icon: AlarmCheck,
    color: C.info,
    hint: 'Marks the alert as seen and being worked on.',
  },
  resolved: {
    action: 'resolve',
    label: 'Resolve',
    icon: CheckCheck,
    color: C.success,
    hint: 'Closes the alert as dealt with.',
  },
  dismissed: {
    action: 'dismiss',
    label: 'Dismiss',
    icon: EyeOff,
    color: C.dim,
    hint: 'Closes the alert without action.',
  },
  false_positive: {
    action: 'false-positive',
    label: 'False positive',
    icon: ShieldQuestion,
    color: C.purple,
    hint: 'Records the detection as incorrect.',
  },
}

/** What {@link AlertLifecycleActions} takes. */
export interface AlertLifecycleActionsProps {
  readonly alert: Alert
  readonly onTransition: (action: AlertLifecycleAction) => void
  readonly isTransitioning: boolean
  /** The last refused move, shown inline until the next attempt. */
  readonly actionError: ApiError | null
}

/**
 * Render the lifecycle buttons an alert's current state allows.
 *
 * The state changes are optimistic in appearance only: the row itself is replaced
 * from the response, so the badge beside these controls is the backend's own
 * answer for the alert, not a local guess about what the click did.
 */
export function AlertLifecycleActions({
  alert,
  onTransition,
  isTransitioning,
  actionError,
}: AlertLifecycleActionsProps) {
  const reachable = ALERT_TRANSITIONS[alert.status] ?? []
  const actions = reachable
    .map(status => ACTION_PRESENTATION[status])
    .filter((entry): entry is ActionPresentation => entry !== null)

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        {actions.length === 0 ? (
          <p className="text-xs" style={{ color: C.faint }}>
            This alert is in a terminal state — <span className="capitalize">{alert.status.replace('_', ' ')}</span> —
            so no further transition is possible.
          </p>
        ) : (
          actions.map(entry => {
            const Icon = entry.icon
            return (
              <button key={entry.action}
                onClick={() => onTransition(entry.action)}
                disabled={isTransitioning}
                title={entry.hint}
                className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold disabled:opacity-50"
                style={{ backgroundColor: tint(entry.color, 0.12), color: entry.color }}>
                {isTransitioning
                  ? <Loader2 size={14} className="animate-spin" />
                  : <Icon size={14} />}
                {entry.label}
              </button>
            )
          })
        )}
      </div>

      {actionError !== null && (
        <div className="flex items-start gap-2 px-3 py-2 rounded-xl border text-xs"
          style={{
            backgroundColor: 'rgba(239,68,68,0.08)',
            borderColor: 'rgba(239,68,68,0.25)',
            color: C.muted,
          }}>
          <ShieldQuestion size={13} style={{ color: C.danger, flexShrink: 0, marginTop: 1 }} />
          <span>
            <span className="font-semibold" style={{ color: C.danger }}>
              {actionError.kind === 'conflict' ? 'Transition refused. ' : 'Could not update. '}
            </span>
            {actionError.userMessage}
          </span>
        </div>
      )}

      {actions.length > 0 && (
        <p className="text-xs" style={{ color: C.faint }}>
          The backend validates every transition; a move it refuses leaves the alert unchanged.
        </p>
      )}
    </div>
  )
}
