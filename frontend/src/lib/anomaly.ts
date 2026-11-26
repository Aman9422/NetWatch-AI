/**
 * Presentation helpers for ML anomaly results (M22.13).
 *
 * Kept out of the page for the same reason `lib/baseline.ts` exists: the labels,
 * the ordering and the formatting decisions are used by more than one component
 * (the listing, the detail panel and the model table), and a page that re-invented
 * them would eventually disagree with itself about what `collecting_data` means.
 *
 * The one rule everything here follows: **never turn "no verdict" into "normal".**
 * A `skipped` result means no model could evaluate the window, and this module says
 * so in words rather than letting a blank score read as a clean report.
 */

import type { AnomalyModelState, AnomalyResult, AnomalyStatus } from '@/types'
import { C } from './tokens'
import { UNKNOWN_TEXT } from './format'

/** Every model state, in the order a reader should scan them. */
export const ANOMALY_STATE_ORDER: readonly AnomalyModelState[] = [
  'ready',
  'stale',
  'training',
  'collecting_data',
  'failed',
  'disabled',
]

/**
 * A colour per model state.
 *
 * `collecting_data` is deliberately neutral rather than green: it is a normal
 * stage of learning, but it is *not* a working detector, and colouring it like
 * `ready` would present an unmonitored device as a healthy one.
 */
export const ANOMALY_STATE_COLORS: Readonly<Record<AnomalyModelState, string>> = {
  ready: C.success,
  stale: C.warning,
  training: C.info,
  collecting_data: C.faint,
  failed: C.danger,
  disabled: C.dim,
}

/** A colour per evaluation status. */
export const ANOMALY_STATUS_COLORS: Readonly<Record<AnomalyStatus, string>> = {
  scored: C.accent,
  skipped: C.faint,
  failed: C.danger,
}

/** Short badge text for a model state, used when a payload supplies none. */
export function modelStateLabel(state: AnomalyModelState): string {
  switch (state) {
    case 'ready':
      return 'Ready'
    case 'stale':
      return 'Stale'
    case 'training':
      return 'Training'
    case 'collecting_data':
      return 'Collecting data'
    case 'failed':
      return 'Failed'
    case 'disabled':
      return 'Disabled'
  }
}

/** A short phrase for an evaluation status. */
export function statusLabel(status: AnomalyStatus): string {
  switch (status) {
    case 'scored':
      return 'Scored'
    case 'skipped':
      return 'Not evaluated'
    case 'failed':
      return 'Failed'
  }
}

/**
 * The plain-English reason a window was not evaluated.
 *
 * The backend stores a stable code rather than prose (`skip_reason`), so the
 * wording lives here. An unknown code is reported as itself rather than hidden:
 * a future skip reason should be visible, not silently rendered as "unknown".
 */
export function skipReasonLabel(reason: string | null): string {
  switch (reason) {
    case null:
      return ''
    case 'insufficient_training_data':
      return 'Not enough historical observation windows have accumulated to train a model for this device.'
    case 'insufficient_features':
      return 'Too many behavioural features are unavailable for this device to train a model.'
    case 'model_unavailable':
      return 'No model was available for this device when the window was evaluated.'
    case 'model_failed':
      return 'The model failed, so this window could not be evaluated.'
    case 'scoring_failed':
      return 'The model raised an error while scoring this window.'
    case 'disabled':
      return 'ML anomaly detection is switched off by configuration.'
    default:
      return reason
  }
}

/**
 * Format a raw decision score.
 *
 * Four decimal places, because the useful differences between two Isolation
 * Forest scores are small — but the value is still a raw model output, and the
 * caller must label it as such. This function deliberately does **not** convert it
 * to a percentage: doing so would imply a calibration the model does not have.
 */
export function formatDecisionScore(score: number | null | undefined): string {
  if (typeof score !== 'number' || !Number.isFinite(score)) return UNKNOWN_TEXT
  return score.toFixed(4)
}

/** A signed difference against the baseline median, for the context table. */
export function formatDifference(value: number | null | undefined): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return UNKNOWN_TEXT
  const rounded =
    Math.abs(value) >= 100 ? Math.round(value) : Number(value.toFixed(2))
  return rounded > 0 ? `+${rounded.toLocaleString()}` : rounded.toLocaleString()
}

/** The deviation in scaled MADs, e.g. `+12.4σ`. */
export function formatDeviationMads(value: number | null | undefined): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return UNKNOWN_TEXT
  return `${value > 0 ? '+' : ''}${value.toFixed(1)}σ`
}

/**
 * Whether a result carries an actual verdict.
 *
 * `skipped` and `failed` rows are *not* verdicts, and every caller that decides
 * how to present a row should branch on this rather than on `is_anomaly` alone —
 * a skipped row has `is_anomaly: false` and would otherwise read as "normal".
 */
export function hasVerdict(result: AnomalyResult): boolean {
  return result.status === 'scored' && result.decision_score !== null
}

/** The identity kind of a device key, for the badge beside it. */
export function anomalyIdentityKind(deviceKey: string): 'mac' | 'ip' {
  return deviceKey.startsWith('mac:') ? 'mac' : 'ip'
}

/** The identity shown in a cell, or a dash when absent. */
export function anomalyIdentity(deviceKey: string | null | undefined): string {
  return deviceKey ? deviceKey : UNKNOWN_TEXT
}
