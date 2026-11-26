/**
 * The per-feature context beside one anomaly verdict (M22.9/M22.13).
 *
 * This table is the investigation aid, and its honesty depends on one distinction
 * being visible on screen rather than only in a comment:
 *
 * **These are baseline statistics, not model attribution.** Each row compares the
 * window's observed value against M21's profile median for that feature — the
 * difference and how many scaled MADs it is. Isolation Forest does not report which
 * feature caused a prediction, so nothing here is labelled a cause. The header says
 * so, because a reader who sees "packets per window +240%" will otherwise assume
 * the model used it.
 *
 * Two further facts the row must not hide:
 *
 * * **Missing** — the feature was absent from the window (M21 stores
 *   `new_connections` as NULL when it cannot be measured). It is modelled with an
 *   explicit imputation, and the row says the value was absent rather than showing
 *   a zero.
 * * **Truncated** — a cardinality hit its cap, so the recorded value is a floor.
 *   It is marked rather than presented as an exact count.
 */

import { Info } from 'lucide-react'
import { C } from '@/lib/tokens'
import { formatCount, UNKNOWN_TEXT } from '@/lib/format'
import { formatDeviationMads, formatDifference } from '@/lib/anomaly'
import type { FeatureContext } from '@/types'

interface Props {
  /** The context rows the detail endpoint returned. */
  readonly context: readonly FeatureContext[]
}

/** Render a value with the truncation and missing markers the row carries. */
function valueCell(
  value: number | null,
  missing: boolean,
  truncated: boolean,
): React.ReactNode {
  if (missing) {
    return <span style={{ color: C.warning }}>not measured</span>
  }
  const rendered = value === null ? UNKNOWN_TEXT : formatCount(value)
  return (
    <span className="mono">
      {rendered}
      {truncated && (
        <span
          className="ml-1 text-[10px] font-semibold"
          title="This cardinality hit its configured cap, so the value is a lower bound rather than an exact count."
          style={{ color: C.warning }}>
          ≥
        </span>
      )}
    </span>
  )
}

export default function FeatureContextTable({ context }: Props) {
  if (context.length === 0) {
    return (
      <p className="text-xs px-4 py-6 text-center" style={{ color: C.faint }}>
        No feature context was recorded for this window. The window may have been
        evaluated before a baseline profile existed, or the evaluation may have been
        skipped.
      </p>
    )
  }

  return (
    <div>
      <div
        className="flex items-start gap-2 px-4 py-2.5 text-[11px] border-b"
        style={{ borderColor: C.border, backgroundColor: C.panel, color: C.faint }}>
        <Info size={12} style={{ flexShrink: 0, marginTop: 1 }} />
        <span>
          These are comparisons against the device's statistical baseline, not
          an explanation of the model's decision. The Isolation Forest reports
          that the window is unusual; it does not report which feature made it so.
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b" style={{ borderColor: C.border }}>
              <th className="text-left pl-4 py-2 pr-3 text-xs font-medium"
                style={{ color: C.dim }}>Feature</th>
              <th className="text-right py-2 pr-3 text-xs font-medium"
                style={{ color: C.dim }}>Observed</th>
              <th className="text-right py-2 pr-3 text-xs font-medium"
                style={{ color: C.dim }}>Baseline median</th>
              <th className="text-right py-2 pr-3 text-xs font-medium"
                style={{ color: C.dim }}>Difference</th>
              <th className="text-right py-2 pr-4 text-xs font-medium"
                style={{ color: C.dim }}>Deviation</th>
            </tr>
          </thead>
          <tbody>
            {context.map(entry => (
              <tr key={entry.feature} className="border-b" style={{ borderColor: '#1a2744' }}>
                <td className="pl-4 py-2 pr-3 text-xs" style={{ color: C.muted }}>
                  {entry.label}
                </td>
                <td className="py-2 pr-3 text-xs text-right" style={{ color: C.text }}>
                  {valueCell(entry.observed, entry.missing, entry.truncated)}
                </td>
                <td className="py-2 pr-3 text-xs text-right mono" style={{ color: C.faint }}>
                  {entry.baseline_median === null
                    ? UNKNOWN_TEXT
                    : formatCount(entry.baseline_median)}
                </td>
                <td className="py-2 pr-3 text-xs text-right mono"
                  style={{ color: entry.far_from_centre ? C.warning : C.muted }}>
                  {formatDifference(entry.difference)}
                </td>
                <td className="py-2 pr-4 text-xs text-right mono"
                  style={{ color: entry.far_from_centre ? C.warning : C.faint }}>
                  {formatDeviationMads(entry.deviation_mads)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
