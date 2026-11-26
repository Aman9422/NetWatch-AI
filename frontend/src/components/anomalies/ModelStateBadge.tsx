/**
 * An anomaly model's lifecycle state as a badge (M22.13).
 *
 * The badge exists to stop one specific misreading: **`collecting_data` rendered
 * as healthy.** A device with no trained model is not being checked, and a page
 * that showed it in green — or omitted it — would tell an operator that a device's
 * traffic had been examined and found unremarkable when in truth nothing examined
 * it at all.
 *
 * So the colour comes from the shared palette rather than being chosen here, and
 * `collecting_data` maps to a neutral grey rather than to `success`. The backend's
 * own `state_description` is the tooltip, because it shipped with the state and
 * says in words what the badge cannot.
 */

import { C, tint } from '@/lib/tokens'
import { ANOMALY_STATE_COLORS, modelStateLabel } from '@/lib/anomaly'
import type { AnomalyModelState } from '@/types'

interface Props {
  /** One of the six lifecycle states. */
  readonly state: AnomalyModelState
  /** The backend's sentence describing the state, shown as a tooltip. */
  readonly description?: string | null
  /** The backend's short label, preferred over the local mapping when present. */
  readonly label?: string | null
  /** Render smaller, for a table row. */
  readonly compact?: boolean
}

export default function ModelStateBadge({
  state,
  description,
  label,
  compact = false,
}: Props) {
  const color = ANOMALY_STATE_COLORS[state] ?? C.muted
  return (
    <span
      className={`flex items-center gap-1.5 font-medium w-fit whitespace-nowrap ${
        compact ? 'text-[11px]' : 'text-xs'
      } px-2 py-0.5 rounded-full`}
      title={description ?? label ?? modelStateLabel(state)}
      style={{ backgroundColor: tint(color, 0.12), color }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />
      {label ?? modelStateLabel(state)}
    </span>
  )
}
