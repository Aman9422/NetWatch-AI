/**
 * An incident's three judgement figures (M15.17).
 *
 * An incident carries three numbers that are all "how bad" in some sense and are
 * nonetheless **not interchangeable** (M12.16):
 *
 * * `risk_score` — M12's bounded `0..100` prioritisation metric, with `risk_band`
 *   its documented display band;
 * * `correlation_confidence` — how strongly the correlation engine judged the
 *   member events to be *related* to each other;
 * * `alert_confidence` — the mean of the member alerts' own **evidence** strength.
 *
 * `alert_confidence` says nothing about whether the events belong together, and
 * `correlation_confidence` says nothing about how strong the evidence is; a page
 * that rendered one where the other belonged would be telling an operator that
 * weak evidence was strongly corroborated, or the reverse. They are therefore
 * given different units, different labels, different shapes and their own
 * explanatory line, and no caller may merge them into a single score.
 *
 * The risk score is drawn as a wide bar with its band named, the two confidences
 * as narrower bars. The score is *not* re-banded here: `risk_band` arrives from
 * the backend and is used as given, so the UI cannot disagree with the API about
 * what "moderate" means (M12.27).
 */

import { Gauge, GitBranch, Activity } from 'lucide-react'
import { C, tint, RISK_BAND_COLORS } from '@/lib/tokens'
import { formatConfidence, formatRiskScore } from '@/lib/format'

/** What {@link IncidentMetrics} takes. */
export interface IncidentMetricsProps {
  /** The `0..100` prioritisation metric (M12.14). */
  readonly riskScore: number
  /** The backend's display band for that score (M12.27). */
  readonly riskBand: string
  /** How strongly the events were judged related, `0..1`. */
  readonly correlationConfidence: number
  /** The mean evidence strength of the member alerts, `0..1`. */
  readonly alertConfidence: number
}

/** A labelled bar, used for both confidences. */
function ConfidenceBar({ label, hint, value, color, icon }: {
  label: string
  hint: string
  value: number
  color: string
  icon: React.ReactNode
}) {
  const bounded = Math.max(0, Math.min(1, value))
  return (
    <div>
      <div className="flex items-center justify-between gap-3 mb-1.5">
        <span className="flex items-center gap-1.5 text-xs font-medium" style={{ color: C.muted }}>
          <span style={{ color }}>{icon}</span>
          {label}
        </span>
        <span className="mono text-xs font-semibold" style={{ color }}>{formatConfidence(value)}</span>
      </div>
      <div className="h-2 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
        <div className="h-full rounded-full transition-all duration-500"
          style={{ width: `${Math.round(bounded * 100)}%`, backgroundColor: color }} />
      </div>
      <p className="text-xs mt-1.5" style={{ color: C.faint }}>{hint}</p>
    </div>
  )
}

/**
 * Render the risk score and the two confidences as three separate readings.
 */
export function IncidentMetrics({
  riskScore,
  riskBand,
  correlationConfidence,
  alertConfidence,
}: IncidentMetricsProps) {
  const bandColor = RISK_BAND_COLORS[riskBand] ?? C.muted
  const boundedScore = Math.max(0, Math.min(100, riskScore))

  return (
    <div className="space-y-4">
      {/* The prioritisation score, alone in its own block with its band named */}
      <div className="rounded-xl border p-4"
        style={{ backgroundColor: C.panel, borderColor: tint(bandColor, 0.3) }}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <span className="flex items-center gap-1.5 text-xs font-medium" style={{ color: C.muted }}>
              <Gauge size={12} style={{ color: bandColor }} />
              Risk score
            </span>
            <p className="text-xs mt-1" style={{ color: C.faint }}>
              M12's prioritisation of this incident, 0–100.
            </p>
          </div>
          <div className="text-right flex-shrink-0">
            <div className="mono text-3xl font-bold leading-none" style={{ color: bandColor }}>
              {formatRiskScore(riskScore)}
            </div>
            <div className="text-xs font-semibold capitalize mt-1" style={{ color: bandColor }}>
              {riskBand} band
            </div>
          </div>
        </div>
        <div className="h-2 rounded-full overflow-hidden mt-3" style={{ backgroundColor: C.card }}>
          <div className="h-full rounded-full transition-all duration-500"
            style={{ width: `${Math.round(boundedScore)}%`, backgroundColor: bandColor }} />
        </div>
      </div>

      {/* The two confidences, side by side and explicitly distinct from the score */}
      <div className="grid grid-cols-2 gap-4">
        <ConfidenceBar
          label="Correlation confidence"
          hint="How strongly M12 judged the member events to be related."
          value={correlationConfidence}
          color={C.purple}
          icon={<GitBranch size={12} />}
        />
        <ConfidenceBar
          label="Alert confidence"
          hint="The mean evidence strength of the member alerts — not a measure of relatedness."
          value={alertConfidence}
          color={C.info}
          icon={<Activity size={12} />}
        />
      </div>

      <p className="text-xs" style={{ color: C.faint }}>
        These three are separate readings, not parts of one score: a high correlation
        confidence says the events belong together, and a high alert confidence says the
        evidence behind them is strong. Neither is the risk score.
      </p>
    </div>
  )
}
