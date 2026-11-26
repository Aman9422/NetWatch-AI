/**
 * One anomaly verdict, in full (M22.13).
 *
 * The panel keeps two numbers visually and textually separate, because collapsing
 * them is the mistake this milestone most needs to avoid:
 *
 * * **The model decision** — `decision_score` and the classification. This is the
 *   Isolation Forest output, labelled as a raw score and explicitly *not* a
 *   probability.
 * * **The baseline comparison** — the per-feature table, which is a statistic about
 *   the window and says nothing about why the model reacted.
 *
 * It also refuses to render a skipped evaluation as if it were a verdict. A window
 * the engine could not score has no decision at all, and the panel says which
 * condition prevented one instead of showing a blank score beside a green tick.
 */

import { ArrowLeft, BellRing, Brain, ShieldQuestion } from 'lucide-react'
import { AsyncSection } from '@/components/AsyncState'
import { useAnomalyDetail } from '@/hooks'
import { C, tint } from '@/lib/tokens'
import { formatCount, formatRelative, formatTimestamp, UNKNOWN_TEXT } from '@/lib/format'
import {
  anomalyIdentityKind,
  formatDecisionScore,
  hasVerdict,
  skipReasonLabel,
  statusLabel,
} from '@/lib/anomaly'
import FeatureContextTable from './FeatureContextTable'
import type { AnomalyResult } from '@/types'

interface Props {
  /** The verdict to display. */
  readonly anomaly: AnomalyResult
  /** Return to the list. */
  readonly onBack: () => void
}

/** One labelled field in the summary grid. */
function Field({ label, value, title }: {
  label: string
  value: React.ReactNode
  title?: string
}) {
  return (
    <div title={title}>
      <div className="text-[10px] font-semibold uppercase tracking-wider"
        style={{ color: C.dim }}>{label}</div>
      <div className="text-xs mt-0.5 wrap-break-word" style={{ color: C.muted }}>{value}</div>
    </div>
  )
}

export default function AnomalyDetailPanel({ anomaly, onBack }: Props) {
  // The listing row carries no feature context, so the detail is read again with
  // it. The row is shown immediately so the header is never blank.
  const detail = useAnomalyDetail(anomaly.evaluation_id)
  const full = detail.data ?? anomaly
  const verdict = hasVerdict(full)
  const kind = anomalyIdentityKind(full.device_key)
  const accent = verdict && full.is_anomaly ? C.warning : C.accent

  return (
    <div className="space-y-4">
      <button onClick={onBack}
        className="flex items-center gap-1.5 text-xs font-medium"
        style={{ color: C.muted }}>
        <ArrowLeft size={12} /> Back to anomaly results
      </button>

      <div className="rounded-2xl border p-5"
        style={{ backgroundColor: C.card, borderColor: C.border }}>
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="mono text-sm font-semibold text-white break-all">
                {full.device_key}
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold"
                style={{
                  backgroundColor: tint(kind === 'mac' ? C.accent : C.warning, 0.12),
                  color: kind === 'mac' ? C.accent : C.warning,
                }}>
                {kind === 'mac' ? 'MAC' : 'IP'}
              </span>
            </div>
            <p className="text-xs mt-1" style={{ color: C.faint }}>
              Observation window starting {formatTimestamp(full.window_start)} ·{' '}
              {full.window_seconds}s
            </p>
          </div>

          <div className="text-right">
            <div className="text-[10px] font-semibold uppercase tracking-wider"
              style={{ color: C.dim }}>
              Isolation Forest decision
            </div>
            <div className="text-xl font-bold mono leading-none mt-1"
              style={{ color: verdict ? accent : C.faint }}>
              {formatDecisionScore(full.decision_score)}
            </div>
            <div className="text-[11px] mt-1" style={{ color: C.faint }}>
              {statusLabel(full.status)}
              {verdict && (full.is_anomaly ? ' · flagged as unusual' : ' · within learned range')}
            </div>
          </div>
        </div>

        {!verdict && (
          <div className="mt-4 flex items-start gap-2 px-3 py-2.5 rounded-xl border text-xs"
            style={{
              backgroundColor: tint(C.warning, 0.08),
              borderColor: tint(C.warning, 0.25),
              color: C.muted,
            }}>
            <ShieldQuestion size={13} style={{ color: C.warning, flexShrink: 0, marginTop: 1 }} />
            <span>
              <span className="font-semibold" style={{ color: C.text }}>
                This window was not evaluated.
              </span>{' '}
              {skipReasonLabel(full.skip_reason)}
              {' '}The absence of a verdict here is not evidence that the traffic was normal.
            </span>
          </div>
        )}

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-5 pt-4 border-t"
          style={{ borderColor: C.border }}>
          <Field label="Algorithm" value={full.algorithm} />
          <Field label="Model version"
            value={full.model_version === 0 ? 'no model' : `v${full.model_version}`}
            title={full.model_trained_at
              ? `Trained ${formatTimestamp(full.model_trained_at)}`
              : 'No model was involved in this row'} />
          <Field label="Training samples"
            value={full.training_sample_count === 0
              ? UNKNOWN_TEXT
              : formatCount(full.training_sample_count)} />
          <Field label="Recorded" value={formatRelative(full.created_at)} />
        </div>
      </div>

      <div className="rounded-2xl border overflow-hidden"
        style={{ backgroundColor: C.card, borderColor: C.border }}>
        <div className="flex items-center gap-2 px-4 py-3 border-b"
          style={{ borderColor: C.border }}>
          <Brain size={14} style={{ color: C.purple }} />
          <h2 className="text-sm font-semibold text-white">Feature context</h2>
          <span className="text-[11px]" style={{ color: C.faint }}>
            observed value vs. learned baseline
          </span>
        </div>
        <AsyncSection
          isInitialLoading={detail.isInitialLoading}
          error={detail.blockingError}
          isEmpty={false}
          loadingLabel="Loading feature context…"
          errorTitle="Unable to load this result"
          onRetry={detail.reload}
          minHeight={140}
        >
          <FeatureContextTable context={full.feature_context} />
        </AsyncSection>
      </div>

      <div className="flex flex-wrap items-center gap-3 px-4 py-3 rounded-xl border text-xs"
        style={{ backgroundColor: C.panel, borderColor: C.border, color: C.faint }}>
        <BellRing size={12} style={{ flexShrink: 0 }} />
        <span>
          {full.alert_id === null
            ? 'No alert was raised for this window. A finding is only created when the model classifies a window as anomalous and an alert path is available.'
            : `This verdict produced alert #${full.alert_id}. The alert carries the same decision score and is processed by the existing alert lifecycle.`}
        </span>
      </div>

      <div className="px-4 py-3 rounded-xl border text-xs"
        style={{ backgroundColor: C.panel, borderColor: C.border, color: C.muted }}>
        {full.disclaimer}
      </div>
      <p className="text-[11px] px-1" style={{ color: C.dim }}>
        {full.decision_score_note}
      </p>
    </div>
  )
}
