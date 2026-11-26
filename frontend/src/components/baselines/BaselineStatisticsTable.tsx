/**
 * A baseline's statistical profile (M21.11).
 *
 * One row per feature the engine could calculate, with the location and robust
 * dispersion measures side by side. Four decisions here are deliberate:
 *
 * * **Nothing is re-derived.** Every figure is read from `baseline.statistics`;
 *   the page never recomputes a mean from the recent windows, because that would
 *   be a second implementation of the M21.6 statistics and it would disagree with
 *   the backend the moment the sample set changed (M15.9).
 * * **A truncated feature says so.** A peer or port cardinality that hit the
 *   engine's cap is a *floor*, and the row marks it rather than presenting a
 *   capped number as exact (M21.6).
 * * **MAD is shown beside σ, not instead of it.** A profile built from a device
 *   with one busy window has a stdev that says "highly variable" and a MAD that
 *   says "mostly steady"; only both together describe it honestly (M21.6).
 * * **Bytes are formatted as bytes.** A byte *count* mean is a magnitude, so it
 *   reads in KB/MB; a packet mean stays a plain number.
 */

import { formatBytes } from '@/lib/format'
import { C, tint } from '@/lib/tokens'
import { formatStatistic, isTruncated } from '@/lib/baseline'
import type { FeatureStatistics } from '@/types'

interface Props {
  readonly statistics: readonly FeatureStatistics[]
}

/** Render one statistic, choosing byte formatting for a byte feature. */
function statistic(feature: FeatureStatistics, value: number): string {
  if (feature.feature === 'byte_count') return formatBytes(value)
  return formatStatistic(value)
}

export default function BaselineStatisticsTable({ statistics }: Props) {
  if (statistics.length === 0) {
    return (
      <div className="px-5 py-8 text-center">
        <p className="text-sm font-medium text-white">No profile yet</p>
        <p className="text-xs mt-1 max-w-md mx-auto" style={{ color: C.faint }}>
          The engine publishes statistics once it has observation windows to summarise. A device
          still in the learning state has none, so there is nothing here to read.
        </p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b" style={{ borderColor: C.border }}>
            <th className="text-left pl-5 py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>
              Feature
            </th>
            <th className="text-right py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>
              Samples
            </th>
            <th className="text-right py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>
              Median
            </th>
            <th className="text-right py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>
              Mean
            </th>
            <th className="text-right py-2.5 pr-4 text-xs font-medium"
              title="Median absolute deviation — unshifted, so it is on the same scale as the values"
              style={{ color: C.dim }}>
              MAD
            </th>
            <th className="text-right py-2.5 pr-4 text-xs font-medium"
              title="MAD × 1.4826 — a robust estimate of the standard deviation"
              style={{ color: C.dim }}>
              MAD σ
            </th>
            <th className="text-right py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>
              Std dev
            </th>
            <th className="text-right py-2.5 pr-4 text-xs font-medium"
              title="The 95th percentile of the observed values"
              style={{ color: C.dim }}>
              P95
            </th>
            <th className="text-right py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>
              Min
            </th>
            <th className="text-right py-2.5 pr-5 text-xs font-medium" style={{ color: C.dim }}>
              Max
            </th>
          </tr>
        </thead>
        <tbody>
          {statistics.map(entry => (
            <tr key={entry.feature} className="border-b" style={{ borderColor: '#1a2744' }}>
              <td className="pl-5 py-2.5 pr-4">
                <div className="text-xs font-medium text-white">{entry.label}</div>
                <div className="mono text-[11px]" style={{ color: C.faint }}>
                  {entry.feature}
                </div>
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right" style={{ color: C.muted }}>
                {formatStatistic(entry.count)}
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right text-white">
                {statistic(entry, entry.median)}
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right" style={{ color: C.muted }}>
                {statistic(entry, entry.mean)}
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right" style={{ color: C.muted }}>
                {statistic(entry, entry.mad)}
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right" style={{ color: C.muted }}>
                {statistic(entry, entry.mad_scaled)}
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right" style={{ color: C.faint }}>
                {statistic(entry, entry.stdev)}
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right" style={{ color: C.muted }}>
                {statistic(entry, entry.p95)}
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right" style={{ color: C.faint }}>
                {statistic(entry, entry.min)}
              </td>
              <td className="py-2.5 pr-5 mono text-xs text-right" style={{ color: C.faint }}>
                {statistic(entry, entry.max)}
                {isTruncated(entry) && (
                  <span className="ml-1.5 text-[10px] font-semibold px-1.5 py-0.5 rounded-full"
                    title="A contributing window hit the peer or port cap, so this figure is a floor rather than an exact count."
                    style={{ backgroundColor: tint(C.warning, 0.14), color: C.warning }}>
                    ≥
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
