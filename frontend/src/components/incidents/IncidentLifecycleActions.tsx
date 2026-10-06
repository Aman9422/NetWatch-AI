/**
 * The incident lifecycle controls (M15.19).
 *
 * An incident moves `open → investigating → resolved | dismissed`, and which
 * moves are offered comes from {@link INCIDENT_TRANSITIONS}. As with alerts, that
 * table is a **UI convenience, not the rule**: M12's transition table is the
 * authority, a refused move is a `409`, and this component reports the refusal
 * instead of hiding it. The two tables are deliberately kept in step so the UI
 * does not offer a button the server is certain to reject.
 *
 * `IncidentSummary.status` is typed as a plain string because the API serialises
 * it that way. It is therefore narrowed through {@link isIncidentStatus} before
 * the transition table is consulted — an unrecognised status renders "no
 * transitions offered" rather than indexing into the table with a value it does
 * not contain and offering a move the backend never declared.
 */

import { Search, CheckCheck, EyeOff, Loader2, ShieldQuestion } from 'lucide-react'
import { INCIDENT_TRANSITIONS } from '@/types'
import type { IncidentLifecycleAction, IncidentStatus } from '@/types'
import type { ApiError } from '@/services'
import { C, tint } from '@/lib/tokens'

/** True when `value` is one of the four documented incident states. */
export function isIncidentStatus(value: string): value is IncidentStatus {
  return (
    value === 'open' || value === 'investigating' ||
    value === 'resolved' || value === 'dismissed'
  )
}

/** How each target state is presented as a button. */
interface ActionPresentation {
  readonly action: IncidentLifecycleAction
  readonly label: string
  readonly icon: React.ElementType
  readonly color: string
  readonly hint: string
}

/** The presentation for each state an incident may move to. */
const ACTION_PRESENTATION: Readonly<Record<IncidentStatus, ActionPresentation | null>> = {
  open: null,
  investigating: {
    action: 'investigate',
    label: 'Investigate',
    icon: Search,
    color: C.warning,
    hint: 'Marks the incident as under active investigation.',
  },
  resolved: {
    action: 'resolve',
    label: 'Resolve',
    icon: CheckCheck,
    color: C.success,
    hint: 'Closes the incident as dealt with.',
  },
  dismissed: {
    action: 'dismiss',
    label: 'Dismiss',
    icon: EyeOff,
    color: C.dim,
    hint: 'Closes the incident without action.',
  },
}

/** What {@link IncidentLifecycleActions} takes. */
export interface IncidentLifecycleActionsProps {
  /** The incident's current status, as the backend reported it. */
  readonly status: string
  readonly onTransition: (action: IncidentLifecycleAction) => void
  readonly isTransitioning: boolean
  readonly actionError: ApiError | null
}

/**
 * Render the lifecycle buttons an incident's current state allows.
 */
export function IncidentLifecycleActions({
  status,
  onTransition,
  isTransitioning,
  actionError,
}: IncidentLifecycleActionsProps) {
  const known = isIncidentStatus(status)
  const reachable = known ? INCIDENT_TRANSITIONS[status] : []
  const actions = reachable
    .map(target => ACTION_PRESENTATION[target])
    .filter((entry): entry is ActionPresentation => entry !== null)

  return (
    <div className="space-y-3">
      {!known && (
        <p className="text-xs" style={{ color: C.warning }}>
          The backend reported a status this console does not recognise
          (<span className="mono">{status}</span>), so no transition is offered rather than
          guessing which one would apply.
        </p>
      )}

      <div className="flex items-center gap-2 flex-wrap">
        {known && actions.length === 0 ? (
          <p className="text-xs" style={{ color: C.faint }}>
            This incident is in a terminal state —{' '}
            <span className="capitalize">{status}</span> — so no further transition is possible.
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
          The backend validates every transition; a move it refuses leaves the incident unchanged.
        </p>
      )}
    </div>
  )
}
