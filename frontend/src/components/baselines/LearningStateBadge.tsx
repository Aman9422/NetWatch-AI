/**
 * A baseline's learning state as a badge (M21.11).
 *
 * The badge reports *maturity*, and its label must never read as a judgement.
 * `established` says the profile has enough observation windows to be worth
 * reading; it does not say the device is healthy, normal or safe, and M21 has no
 * mechanism that could make such a claim (`app/baselines/states.py`).
 *
 * The colour comes from the shared palette rather than being chosen here, so the
 * same state looks the same on every surface that shows it.
 */

import { C, LEARNING_STATE_COLORS, tint } from '@/lib/tokens'
import { learningStateHint, learningStateLabel } from '@/lib/baseline'

interface Props {
  /** `learning`, `provisional` or `established`. */
  readonly state: string
  /** The backend's own sentence describing the state, shown as a tooltip. */
  readonly description?: string | null
  /** Render smaller, for a table row. */
  readonly compact?: boolean
}

export default function LearningStateBadge({
  state,
  description,
  compact = false,
}: Props) {
  const color = LEARNING_STATE_COLORS[state] ?? C.muted

  return (
    <span
      className={`flex items-center gap-1.5 font-medium w-fit whitespace-nowrap ${
        compact ? 'text-[11px]' : 'text-xs'
      } px-2 py-0.5 rounded-full`}
      // The backend's explanation wins because it shipped with the state; the
      // local hint is the fallback for a payload that omitted it.
      title={description ?? learningStateHint(state)}
      style={{ backgroundColor: tint(color, 0.12), color }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />
      {learningStateLabel(state)}
    </span>
  )
}
