/**
 * Baseline presentation helpers (M21.11).
 *
 * Pure functions so the page and its components agree on what a baseline says, and
 * so the wording can be tested without rendering anything.
 *
 * Three rules run through this module:
 *
 * * **A state label states maturity, not safety.** `established` is described as
 *   "enough samples to describe", never as "normal" or "safe" — M21 has no notion
 *   of normal-versus-abnormal, and a label implying one would be the anomaly
 *   verdict the milestone does not produce (M21.7).
 * * **A truncated figure says it is a floor.** A peer or port cardinality that hit
 *   the engine's cap is not an exact count, and presenting it as one would
 *   understate a device's reach (M21.6).
 * * **A statistic that could not be calculated is unknown, never zero.** The
 *   backend omits a feature with no samples rather than sending `0`, and a page
 *   that rendered a missing mean as `0` would report an idle device that was never
 *   observed (`@/lib/format`).
 */

import { UNKNOWN_TEXT, formatCount } from './format'
import type { LearningState, FeatureStatistics } from '@/types'

/** The order the learning states mature in, for filters and sorting. */
export const LEARNING_STATE_ORDER: readonly LearningState[] = [
  'learning',
  'provisional',
  'established',
]

/** A short human label for a learning state. */
export function learningStateLabel(state: string): string {
  switch (state) {
    case 'learning':
      return 'Learning'
    case 'provisional':
      return 'Provisional'
    case 'established':
      return 'Established'
    default:
      // An unknown state is shown as it arrived rather than mapped to a known one:
      // a later milestone that adds a state should look unfamiliar, not mature.
      return state === '' ? UNKNOWN_TEXT : state
  }
}

/** One sentence on what a state means, for a row's tooltip. */
export function learningStateHint(state: string): string {
  switch (state) {
    case 'learning':
      return 'Too few observation windows to describe behaviour yet. No profile is published.'
    case 'provisional':
      return 'The minimum sample count has been reached, but the profile is still developing.'
    case 'established':
      return 'Enough observation windows have been collected for a mature profile. This describes past behaviour; it is not a safety verdict.'
    default:
      return 'This learning state is not one this build recognises.'
  }
}

/**
 * How a device identity is displayed.
 *
 * A MAC identity survives an IP change, which is why M8 prefers it; the `ip:`
 * fallback is labelled as the weaker identity it is, so an operator reading the
 * page knows the baseline may not follow the physical device (M21.4).
 */
export function identityLabel(deviceKey: string, identityKind: string): string {
  if (identityKind === 'mac') return deviceKey.replace(/^mac:/, '')
  if (identityKind === 'ip') return deviceKey.replace(/^ip:/, '')
  return deviceKey
}

/** The addresses observed for a device, or an explicit absence. */
export function addressLabel(addresses: readonly string[]): string {
  return addresses.length === 0 ? UNKNOWN_TEXT : addresses.join(', ')
}

/**
 * Format one statistic for display.
 *
 * A whole number is grouped; a fractional one keeps a single decimal, which is the
 * most precision a mean or a percentile of small counts can mean.
 */
export function formatStatistic(value: number): string {
  if (!Number.isFinite(value)) return UNKNOWN_TEXT
  if (Number.isInteger(value)) return formatCount(value)
  return value.toFixed(1)
}

/**
 * Describe how many samples shaped a profile.
 *
 * The phrase names the *windows*, not the packets: a sample is one aggregated
 * interval, and calling it anything else would overstate how much raw traffic the
 * profile was built from (M21.5).
 */
export function formatSampleCount(baseline: {
  readonly sample_count: number
  readonly statistics_sample_count: number
}): string {
  const samples = baseline.sample_count
  const noun = samples === 1 ? 'window' : 'windows'
  if (baseline.statistics_sample_count === samples) {
    return `${formatCount(samples)} ${noun}`
  }
  // The statistics are calculated over a bounded set of the most recent samples,
  // so the two numbers genuinely differ and both are worth stating.
  return `${formatCount(samples)} ${noun} · ${formatCount(baseline.statistics_sample_count)} in profile`
}

/** Describe an aggregation interval in seconds. */
export function formatWindowSeconds(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return UNKNOWN_TEXT
  if (seconds < 60) return `${formatStatistic(seconds)}s`
  const minutes = seconds / 60
  if (minutes < 60) return `${formatStatistic(minutes)} min`
  return `${formatStatistic(minutes / 60)} h`
}

/**
 * True when a statistics entry's figures are floors rather than exact counts.
 *
 * Kept as a named predicate rather than read inline, because the reason a figure
 * is a floor — a peer or port cap — is a fact the UI must state rather than hide
 * (M21.6).
 */
export function isTruncated(statistics: FeatureStatistics): boolean {
  return statistics.truncated
}
