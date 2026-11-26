/**
 * The per-device model table (M22.13).
 *
 * The table's job is to answer "is this device actually being checked?" honestly.
 * Two things follow from that:
 *
 * * **A device with no model is a row, not an omission.** `collecting_data` is a
 *   real lifecycle state, and hiding it would make an unmonitored device
 *   indistinguishable from one that was never observed — or, worse, from one that
 *   is being checked and finding nothing.
 * * **Retraining is an explicit, confirmed action.** Each row offers it, the page
 *   asks for confirmation, and the result is reported from the payload's `trained`
 *   field rather than from the HTTP status.
 */

import { RefreshCw, RotateCw } from 'lucide-react'
import { C } from '@/lib/tokens'
import { formatCount, formatRelative, UNKNOWN_TEXT } from '@/lib/format'
import { anomalyIdentityKind } from '@/lib/anomaly'
import ModelStateBadge from './ModelStateBadge'
import type { AnomalyModel } from '@/types'

interface Props {
  readonly models: readonly AnomalyModel[]
  /** Ask the page to confirm and run a retrain for this device. */
  readonly onRequestRetrain: (model: AnomalyModel) => void
  /** Open this device's full lifecycle view. */
  readonly onOpenModel: (model: AnomalyModel) => void
  /** The device currently mid-retrain, so its button shows a busy state. */
  readonly retrainingDeviceKey: string | null
  /** True while any retrain is in flight, which blocks a second one. */
  readonly isRetraining: boolean
}

export default function AnomalyModelsTable({
  models,
  onRequestRetrain,
  onOpenModel,
  retrainingDeviceKey,
  isRetraining,
}: Props) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b" style={{ borderColor: C.border }}>
            <th className="text-left pl-5 py-2.5 pr-4 text-xs font-medium"
              style={{ color: C.dim }}>Device</th>
            <th className="text-left py-2.5 pr-4 text-xs font-medium"
              style={{ color: C.dim }}>Model state</th>
            <th className="text-right py-2.5 pr-4 text-xs font-medium"
              title="Historical observation windows the current model was trained on"
              style={{ color: C.dim }}>Training samples</th>
            <th className="text-left py-2.5 pr-4 text-xs font-medium"
              style={{ color: C.dim }}>Last trained</th>
            <th className="text-left py-2.5 pr-4 text-xs font-medium"
              style={{ color: C.dim }}>Last evaluated</th>
            <th className="text-right py-2.5 pr-5 text-xs font-medium"
              style={{ color: C.dim }}>Action</th>
          </tr>
        </thead>
        <tbody>
          {models.map(model => {
            const kind = anomalyIdentityKind(model.device_key)
            const busy = isRetraining && retrainingDeviceKey === model.device_key
            // A device below its minimum is not "nearly ready": the remaining
            // window count is the honest figure, and it only applies while the
            // model is still collecting.
            const remaining = Math.max(
              0,
              model.min_training_windows - model.training_sample_count,
            )
            return (
              <tr key={model.device_key} className="border-b cursor-pointer"
                style={{ borderColor: '#1a2744' }}
                onClick={() => onOpenModel(model)}
                onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)')}
                onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
                <td className="pl-5 py-3 pr-4">
                  <div className="flex items-center gap-2">
                    <span className="mono text-xs font-semibold text-white break-all">
                      {model.device_key}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold shrink-0"
                      style={{
                        backgroundColor: `${kind === 'mac' ? C.accent : C.warning}1f`,
                        color: kind === 'mac' ? C.accent : C.warning,
                      }}>
                      {kind === 'mac' ? 'MAC' : 'IP'}
                    </span>
                  </div>
                  {model.state === 'collecting_data' && remaining > 0 && (
                    <div className="text-[11px] mt-0.5" style={{ color: C.faint }}>
                      {formatCount(remaining)} more window(s) needed
                    </div>
                  )}
                  {model.last_error !== null && (
                    <div className="text-[11px] mt-0.5" style={{ color: C.danger }}>
                      {model.last_error}
                    </div>
                  )}
                </td>
                <td className="py-3 pr-4">
                  <ModelStateBadge
                    state={model.state}
                    label={model.state_label}
                    description={model.state_description}
                    compact
                  />
                </td>
                <td className="py-3 pr-4 mono text-xs text-right text-white">
                  {formatCount(model.training_sample_count)}
                  <div className="text-[10px] font-normal" style={{ color: C.faint }}>
                    of {formatCount(model.training_window_count)} available
                  </div>
                </td>
                <td className="py-3 pr-4 text-xs" style={{ color: C.muted }}>
                  {model.model_version === 0
                    ? UNKNOWN_TEXT
                    : formatRelative(model.trained_at)}
                </td>
                <td className="py-3 pr-4 text-xs" style={{ color: C.muted }}>
                  {formatRelative(model.last_evaluated_at)}
                </td>
                <td className="py-3 pr-5 text-right">
                  <button
                    onClick={event => {
                      // The row itself opens the detail view, so the retrain
                      // button must not also trigger that navigation.
                      event.stopPropagation()
                      onRequestRetrain(model)
                    }}
                    disabled={isRetraining}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-medium border disabled:opacity-40"
                    title="Run a training pass from this device's retained observation windows"
                    style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
                    {busy
                      ? <RefreshCw size={10} className="animate-spin" />
                      : <RotateCw size={10} />}
                    Retrain
                  </button>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
