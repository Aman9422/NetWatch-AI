/**
 * Confirmation before a manual retrain (M22.13).
 *
 * A retrain replaces the device's working model with a newly fitted one, so it is
 * asked for explicitly rather than fired from a table cell. The dialog states what
 * the operation does *and* what it does not touch, because the second half is the
 * part an operator needs: M21's behavioural history, packets, alerts and incidents
 * are untouched.
 */

import { RefreshCw, RotateCw } from 'lucide-react'
import { C } from '@/lib/tokens'
import { formatCount } from '@/lib/format'
import type { AnomalyModel } from '@/types'

interface Props {
  readonly model: AnomalyModel
  readonly isRetraining: boolean
  readonly onCancel: () => void
  readonly onConfirm: () => void
}

export default function RetrainDialog({
  model,
  isRetraining,
  onCancel,
  onConfirm,
}: Props) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ backgroundColor: 'rgba(2,6,23,0.75)' }}
      role="dialog" aria-modal="true" aria-labelledby="retrain-title">
      <div className="w-full max-w-md rounded-2xl border p-5"
        style={{ backgroundColor: C.card, borderColor: C.border }}>
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-xl shrink-0"
            style={{ backgroundColor: `${C.accent}15`, color: C.accent }}>
            <RotateCw size={16} />
          </div>
          <div className="min-w-0">
            <h2 id="retrain-title" className="text-sm font-semibold text-white">
              Retrain this device's anomaly model?
            </h2>
            <p className="text-xs mt-1 break-all mono" style={{ color: C.muted }}>
              {model.device_key}
            </p>
          </div>
        </div>

        <p className="text-xs mt-4" style={{ color: C.muted }}>
          A new Isolation Forest will be fitted from this device's retained
          observation windows
          {model.min_training_windows > 0 && (
            <> — at least {formatCount(model.min_training_windows)} are required</>
          )}.
          The previous model is kept if the pass fails, and it is replaced only when
          a new one trains successfully.
        </p>
        <p className="text-xs mt-2" style={{ color: C.faint }}>
          Behavioural history, packets, alerts and incidents are not modified. No
          device is blocked or quarantined.
        </p>

        <div className="flex items-center justify-end gap-2 mt-5">
          <button onClick={onCancel} disabled={isRetraining}
            className="px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            Cancel
          </button>
          <button onClick={onConfirm} disabled={isRetraining}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold disabled:opacity-60"
            style={{ backgroundColor: `${C.accent}20`, color: C.accent }}>
            {isRetraining
              ? <RefreshCw size={12} className="animate-spin" />
              : <RotateCw size={12} />}
            {isRetraining ? 'Training…' : 'Retrain'}
          </button>
        </div>
      </div>
    </div>
  )
}
