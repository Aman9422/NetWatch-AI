/**
 * The baseline reset confirmation (M21.11).
 *
 * A reset throws away everything the engine has learnt about one device, so it
 * asks first. Two things the dialog is careful to say:
 *
 * * **What is deleted, and what is not.** Only the device's observation windows
 *   and its profile are removed; packets, devices, alerts, incidents, connections
 *   and reports are untouched. An operator who feared a reset would erase their
 *   incident history would not use it (`app/api/v1/baselines.py`).
 * * **What happens next.** The device returns to `learning` and the profile is
 *   rebuilt from the next observed packet onwards — so the immediate consequence
 *   is that the device has *no* baseline, not a zeroed one.
 *
 * The confirm button stays disabled while the request is in flight, and the
 * backdrop cannot dismiss the dialog during that window: a second reset or a
 * half-closed dialog mid-write is not a state worth allowing.
 */

import { AlertTriangle, RotateCcw } from 'lucide-react'
import { C, tint } from '@/lib/tokens'
import { identityLabel } from '@/lib/baseline'
import type { Baseline } from '@/types'

interface Props {
  /** The baseline whose history would be deleted. */
  readonly baseline: Baseline
  readonly isResetting: boolean
  readonly onCancel: () => void
  readonly onConfirm: () => void
}

export default function BaselineResetDialog({
  baseline,
  isResetting,
  onCancel,
  onConfirm,
}: Props) {
  const identity = identityLabel(baseline.device_key, baseline.identity_kind)
  const windowNoun = baseline.sample_count === 1 ? 'window' : 'windows'

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ backgroundColor: 'rgba(2,6,23,0.75)' }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="baseline-reset-title"
      onClick={() => {
        if (!isResetting) onCancel()
      }}>
      <div
        className="w-full max-w-lg rounded-2xl border p-6"
        style={{ backgroundColor: C.card, borderColor: C.border }}
        // Clicks inside must not reach the backdrop's dismiss handler.
        onClick={event => event.stopPropagation()}>
        <div className="flex items-start gap-3">
          <div className="p-2.5 rounded-xl shrink-0"
            style={{ backgroundColor: tint(C.warning, 0.1), color: C.warning }}>
            <AlertTriangle size={18} />
          </div>
          <div className="min-w-0">
            <h2 id="baseline-reset-title" className="text-sm font-semibold text-white">
              Reset this device&rsquo;s baseline?
            </h2>
            <p className="mono text-xs mt-1 break-all" style={{ color: C.accent }}>
              {identity}
            </p>
          </div>
        </div>

        <div className="mt-4 space-y-2 text-xs" style={{ color: C.muted }}>
          <p>
            This deletes all {baseline.sample_count} observation {windowNoun} and the statistical
            profile the engine calculated from them.
          </p>
          <p>
            No packet, device, alert, incident, connection or report record is affected. Only this
            device&rsquo;s behavioural history is removed.
          </p>
          <p>
            The device returns to{' '}
            <span className="font-medium" style={{ color: C.text }}>learning</span> and a new
            profile is built from the next observed packet. Until then it has no baseline at all —
            not a baseline of zeroes.
          </p>
        </div>

        <div className="flex items-center justify-end gap-2 mt-6">
          <button onClick={onCancel} disabled={isResetting}
            className="px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            Cancel
          </button>
          <button onClick={onConfirm} disabled={isResetting}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold disabled:opacity-50"
            style={{ backgroundColor: tint(C.danger, 0.14), color: C.danger }}>
            <RotateCcw size={12} className={isResetting ? 'animate-spin' : undefined} />
            {isResetting ? 'Resetting…' : 'Reset baseline'}
          </button>
        </div>
      </div>
    </div>
  )
}
