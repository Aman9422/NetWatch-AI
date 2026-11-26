/**
 * Behavioural baseline models (M21.11).
 *
 * A baseline is a *description* of behaviour a device has already been observed
 * producing. Three absences in this module are deliberate and must not be "fixed"
 * by a page:
 *
 * * **No score.** There is no risk, anomaly, confidence or suspicion field, and
 *   the backend produces none (`app/schemas/baseline.py`). M21 learns and
 *   describes; M22 is the milestone that will compare a window to a profile.
 *   Inventing a number here would present an anomaly verdict the engine never
 *   issued.
 * * **No peers or ports.** A profile reports *how many* distinct peers and
 *   destination ports a device normally uses, never which ones. The API stores
 *   cardinalities, not address sets (M21.8), so there is nothing to display even
 *   if a page wanted to.
 * * **No inbound/outbound split.** Attribution is by packet sender, and on a
 *   routed path this capture cannot determine direction reliably, so M21.4's
 *   optional direction metrics are documented as unsupported rather than guessed.
 *
 * `learning_state` is a maturity observation, not a verdict: `established` means
 * "watched for a while", never "safe".
 */

/** How mature a device's behavioural profile is (M21.7). */
export type LearningState = 'learning' | 'provisional' | 'established'

/** The statistical summary of one behavioural feature (M21.6). */
export interface FeatureStatistics {
  /** Stable feature name, e.g. `packet_count`. */
  readonly feature: string
  /** Human label the backend supplies, so a page need not map feature names. */
  readonly label: string
  /** How many observation windows carried a value for this feature. */
  readonly count: number
  readonly mean: number
  readonly median: number
  /** Median absolute deviation, unscaled. */
  readonly mad: number
  /** `mad * 1.4826`, a robust standard-deviation estimate. */
  readonly mad_scaled: number
  readonly stdev: number
  readonly p95: number
  readonly min: number
  readonly max: number
  /** True when a contributing window hit a peer or port cap (a floor, not exact). */
  readonly truncated: boolean
}

/** One aggregated observation window (M21.10). */
export interface BaselineWindow {
  /** ISO-8601 UTC. */
  readonly window_start: string
  readonly window_seconds: number
  readonly packet_count: number
  readonly byte_count: number
  readonly tcp_packets: number
  readonly udp_packets: number
  readonly icmp_packets: number
  readonly dns_packets: number
  readonly unique_peers: number
  readonly unique_destination_ports: number
  /** `null` when the feature could not be measured for this window. */
  readonly new_connections: number | null
  readonly peers_truncated: boolean
  readonly ports_truncated: boolean
}

/** One device's learnt behavioural baseline (M21.10). */
export interface Baseline {
  /** Stable M8 identity: `mac:...` or `ip:...`. */
  readonly device_key: string
  /** `mac` (hardware, survives an IP change) or `ip` (the weaker fallback). */
  readonly identity_kind: string
  readonly mac_address: string | null
  readonly ip_addresses: readonly string[]
  readonly learning_state: LearningState
  /** One sentence explaining the state, supplied by the backend (M21.7). */
  readonly state_description: string
  /** How many observation windows shaped this profile; maturity derives from it. */
  readonly sample_count: number
  /** How many recent windows the statistics describe. */
  readonly statistics_sample_count: number
  /** The aggregation interval the samples cover, in seconds. */
  readonly window_seconds: number
  /** ISO-8601 UTC. */
  readonly first_observed_at: string | null
  /** ISO-8601 UTC. */
  readonly last_observed_at: string | null
  /** Empty while `learning`, because no profile is published yet. */
  readonly statistics: readonly FeatureStatistics[]
  /** Present on the detail response only; the listing carries none. */
  readonly recent_windows: readonly BaselineWindow[]
  /** The sentence stating that a baseline is not an anomaly verdict. */
  readonly disclaimer: string
}

/** Payload of `GET /api/v1/baselines` (M21.10/M13.24). */
export interface BaselinePage {
  readonly count: number
  readonly limit?: number | null
  readonly offset: number
  readonly total?: number | null
  readonly has_more?: boolean | null
  readonly baselines: readonly Baseline[]
}

/** Filters accepted by `GET /api/v1/baselines`. */
export interface BaselineQuery {
  readonly learning_state?: LearningState
  readonly limit?: number
  readonly offset?: number
}

/** Payload of `POST /api/v1/baselines/{device_key}/reset` (M21.10). */
export interface BaselineResetResult {
  readonly device_key: string
  readonly windows_deleted: number
  readonly profile_deleted: boolean
  /** Always true: a reset always returns the device to `learning`. */
  readonly learning_restarted: boolean
  /** A sentence naming what was and was not touched. */
  readonly message: string
}
