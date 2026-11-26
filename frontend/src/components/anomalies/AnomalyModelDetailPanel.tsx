/**
 * One device's model lifecycle, in full (M22.13).
 *
 * The model table shows a row per device; this panel is the drill-down the
 * milestone asks for, and it exists because a single state badge cannot answer the
 * questions an operator actually has about a device that is not being checked:
 *
 * * **How far along is it?** `training_sample_count` against
 *   `min_training_windows`, as a number of windows still needed — not a
 *   reassuringly-round percentage that would read as progress towards "healthy".
 * * **What is it learning from?** The feature list the model was fitted on, so a
 *   device whose history is too sparse for most features is visible as such.
 * * **When did it last look?** `last_evaluated_at`, distinct from `trained_at`,
 *   because a model can be trained and then never consulted.
 * * **Is a refresh due?** `windows_since_training`.
 *
 * The one thing this panel must never do is present `collecting_data` as a normal,
 * healthy state. It is a normal *stage*, but the device is not being evaluated, and
 * the panel says so in words beside the badge.
 */

import { ArrowLeft, Brain, CalendarClock, ListChecks, TriangleAlert } from 'lucide-react'
import { AsyncSection } from '@/components/AsyncState'
import { useAnomalyModel } from '@/hooks'
import { C, tint } from '@/lib/tokens'
import { formatCount, formatRelative, formatTimestamp, UNKNOWN_TEXT } from '@/lib/format'
import { anomalyIdentityKind } from '@/lib/anomaly'
import ModelStateBadge from './ModelStateBadge'
import type { AnomalyModel } from '@/types'

interface Props {
  /** The device whose model is being inspected. */
  readonly deviceKey: string
  /** The row already on screen, so the header renders before the read completes. */
  readonly fallback?: AnomalyModel | null
  /** Return to the previous view. */
  readonly onBack: () => void
  /** Ask the page to confirm and run a retrain for this device. */
  readonly onRequestRetrain: (model: AnomalyModel) => void
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

export default function AnomalyModelDetailPanel({
  deviceKey,
  fallback = null,
  onBack,
  onRequestRetrain,
}: Props) {
  const detail = useAnomalyModel(deviceKey)
  const model = detail.data ?? fallback
  const kind = anomalyIdentityKind(deviceKey)

  // A device with no model row is a real answer: nothing has completed a window
  // for it yet. Retention can also remove a model row, so a 404 is explained
  // rather than reported as a fault.
  const missing = detail.blockingError?.kind === 'not_found'

  if (missing) {
    return (
      <div className="space-y-4">
        <button onClick={onBack}
          className="flex items-center gap-1.5 text-xs font-medium"
          style={{ color: C.muted }}>
          <ArrowLeft size={12} /> Back to device models
        </button>
        <div className="rounded-2xl border px-5 py-8 text-center"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <p className="text-sm font-medium text-white">No model for this device</p>
          <p className="text-xs mt-1 max-w-md mx-auto" style={{ color: C.faint }}>
            No completed observation window has been recorded for this device yet, so
            no model exists and nothing is being evaluated. This is not a report that
            the device's traffic is normal.
          </p>
        </div>
      </div>
    )
  }

  const remaining = model === null
    ? 0
    : Math.max(0, model.min_training_windows - model.training_sample_count)
  const collecting = model !== null && model.state === 'collecting_data'

  return (
    <div className="space-y-4">
      <button onClick={onBack}
        className="flex items-center gap-1.5 text-xs font-medium"
        style={{ color: C.muted }}>
        <ArrowLeft size={12} /> Back to device models
      </button>

      <div className="rounded-2xl border p-5"
        style={{ backgroundColor: C.card, borderColor: C.border }}>
        {model === null ? (
          <AsyncSection
            isInitialLoading={detail.isInitialLoading}
            error={detail.blockingError}
            isEmpty={false}
            loadingLabel="Loading model lifecycle…"
            errorTitle="Unable to load this model"
            onRetry={detail.reload}
            minHeight={140}
          >
            <div />
          </AsyncSection>
        ) : (
          <>
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="mono text-sm font-semibold text-white break-all">
                    {model.device_key}
                  </span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold"
                    style={{
                      backgroundColor: tint(kind === 'mac' ? C.accent : C.warning, 0.12),
                      color: kind === 'mac' ? C.accent : C.warning,
                    }}>
                    {kind === 'mac' ? 'MAC' : 'IP'}
                  </span>
                  <ModelStateBadge
                    state={model.state}
                    label={model.state_label}
                    description={model.state_description}
                  />
                </div>
                <p className="text-xs mt-1.5 max-w-lg" style={{ color: C.faint }}>
                  {model.state_description}
                </p>
              </div>

              <button
                onClick={() => onRequestRetrain(model)}
                className="px-3 py-1.5 rounded-xl text-xs font-semibold shrink-0"
                style={{ backgroundColor: tint(C.accent, 0.12), color: C.accent }}>
                Retrain
              </button>
            </div>

            {collecting && (
              <div className="mt-4 flex items-start gap-2 px-3 py-2.5 rounded-xl border text-xs"
                style={{
                  backgroundColor: tint(C.warning, 0.08),
                  borderColor: tint(C.warning, 0.25),
                  color: C.muted,
                }}>
                <TriangleAlert size={13}
                  style={{ color: C.warning, flexShrink: 0, marginTop: 1 }} />
                <span>
                  <span className="font-semibold" style={{ color: C.text }}>
                    This device is not being evaluated.
                  </span>{' '}
                  {remaining > 0
                    ? `${formatCount(remaining)} more observation window(s) are needed before a model can be trained.`
                    : 'A model has not been trained for this device yet.'}
                  {' '}No window has a verdict, which is not the same as every window
                  being normal.
                </span>
              </div>
            )}

            {model.last_error !== null && (
              <div className="mt-3 flex items-start gap-2 px-3 py-2.5 rounded-xl border text-xs"
                style={{
                  backgroundColor: 'rgba(239,68,68,0.08)',
                  borderColor: 'rgba(239,68,68,0.25)',
                  color: C.muted,
                }}>
                <TriangleAlert size={13}
                  style={{ color: C.danger, flexShrink: 0, marginTop: 1 }} />
                <span>
                  <span className="font-semibold" style={{ color: C.text }}>
                    The last training pass reported:
                  </span>{' '}
                  {model.last_error}
                </span>
              </div>
            )}

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-5 pt-4 border-t"
              style={{ borderColor: C.border }}>
              <Field label="Algorithm" value={model.algorithm} />
              <Field label="Model version"
                value={model.model_version === 0 ? 'no model' : `v${model.model_version}`} />
              <Field label="Training samples"
                value={model.training_sample_count === 0
                  ? UNKNOWN_TEXT
                  : formatCount(model.training_sample_count)}
                title={`${formatCount(model.training_window_count)} window(s) available`} />
              <Field label="Minimum required" value={formatCount(model.min_training_windows)} />
              <Field label="Last trained"
                value={model.trained_at === null
                  ? UNKNOWN_TEXT
                  : formatRelative(model.trained_at)}
                title={model.trained_at === null ? undefined : formatTimestamp(model.trained_at)} />
              <Field label="Last evaluated"
                value={formatRelative(model.last_evaluated_at)}
                title={model.last_evaluated_at === null
                  ? undefined
                  : formatTimestamp(model.last_evaluated_at)} />
              <Field label="Windows since training"
                value={formatCount(model.windows_since_training)} />
              <Field label="Contamination"
                value={model.contamination === null
                  ? UNKNOWN_TEXT
                  : model.contamination.toFixed(3)}
                title="The proportion of the training set the model expects to be unusual" />
            </div>
          </>
        )}
      </div>

      {model !== null && (
        <>
          <div className="rounded-2xl border overflow-hidden"
            style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="flex items-center gap-2 px-4 py-3 border-b"
              style={{ borderColor: C.border }}>
              <ListChecks size={14} style={{ color: C.purple }} />
              <h2 className="text-sm font-semibold text-white">Features this model uses</h2>
              <span className="text-[11px]" style={{ color: C.faint }}>
                schema v{model.feature_schema_version}
              </span>
            </div>
            {model.feature_names.length === 0 ? (
              <p className="text-xs px-4 py-6 text-center" style={{ color: C.faint }}>
                No features have been selected yet. A feature is included once enough of
                the device's history carries a usable value for it.
              </p>
            ) : (
              <div className="flex flex-wrap gap-1.5 px-4 py-3">
                {model.feature_names.map(name => (
                  <span key={name} className="mono text-[11px] px-2 py-0.5 rounded-full"
                    style={{ backgroundColor: tint(C.accent, 0.1), color: C.muted }}>
                    {name}
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-3 px-4 py-3 rounded-xl border text-xs"
            style={{ backgroundColor: C.panel, borderColor: C.border, color: C.faint }}>
            <CalendarClock size={12} style={{ flexShrink: 0 }} />
            <span>
              {model.ready
                ? 'This model can score new completed windows. It is retrained periodically from the device\'s retained observation windows.'
                : 'This model cannot score a window in its current state, so completed windows for this device have no verdict.'}
            </span>
          </div>

          <div className="flex items-start gap-2 px-4 py-3 rounded-xl border text-xs"
            style={{ backgroundColor: C.panel, borderColor: C.border, color: C.muted }}>
            <Brain size={12} style={{ flexShrink: 0, marginTop: 1 }} />
            <span>{model.disclaimer}</span>
          </div>
        </>
      )}
    </div>
  )
}
