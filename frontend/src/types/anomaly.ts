/**
 * ML anomaly result models (M22.13).
 *
 * An anomaly is a *deviation from previously observed behaviour*, produced by a
 * locally fitted Isolation Forest. Three absences are deliberate and must not be
 * "fixed" by a page:
 *
 * * **No probability.** `decision_score` is the raw
 *   `IsolationForest.decision_function` output — lower is more unusual — and it
 *   is neither a probability nor a calibrated confidence. There is no
 *   `confidence`/`probability`/`likelihood` field anywhere in this module, and
 *   the backend produces none. Rendering the score as "95% malicious" would be an
 *   invention this milestone forbids.
 * * **No feature attribution.** `feature_context` compares an observed value
 *   against M21's statistical profile (median, difference, scaled MADs). Isolation
 *   Forest does not report which feature caused a prediction, so nothing here
 *   claims it does; the comparison is a statistic, not a reason.
 * * **No verdict of malice.** `disclaimer` travels with every payload, and the
 *   page must show it: an anomaly is not confirmation of malicious activity.
 *
 * `status: 'skipped'` is not a clean bill of health. It means *no verdict was
 * issued* — typically because there is not yet enough history to train a model —
 * and a page that rendered it as "normal" would report the absence of evidence as
 * evidence of normality.
 */

/** The model lifecycle vocabulary (mirrors `app.anomaly_detection.states`). */
export type AnomalyModelState =
  | 'collecting_data'
  | 'training'
  | 'ready'
  | 'stale'
  | 'failed'
  | 'disabled'

/** How one evaluated window resolved. */
export type AnomalyStatus = 'scored' | 'skipped' | 'failed'

/** One feature's observed value beside M21's baseline statistics (M22.9). */
export interface FeatureContext {
  /** Stable feature name, e.g. `packet_count`. */
  readonly feature: string
  /** Human label the backend supplies, so a page need not map feature names. */
  readonly label: string
  /** The value observed in the evaluated window, when measurable. */
  readonly observed: number | null
  /** M21's profile median for this feature, when a profile exists. */
  readonly baseline_median: number | null
  /** `observed - baseline_median`. A comparison, never an attribution. */
  readonly difference: number | null
  /** The difference in scaled MADs, when it is non-zero. */
  readonly deviation_mads: number | null
  /** True when the deviation exceeds the documented reporting threshold. */
  readonly far_from_centre: boolean
  /** True when the feature was absent from the window. */
  readonly missing: boolean
  /** True when a cardinality hit a cap, so the value is a floor. */
  readonly truncated: boolean
}

/** One evaluated observation window (M22.12). */
export interface AnomalyResult {
  readonly evaluation_id: number
  /** Stable M8 identity: `mac:...` or `ip:...`. */
  readonly device_key: string
  /** ISO-8601 UTC start of the evaluated window. */
  readonly window_start: string
  readonly window_seconds: number
  readonly algorithm: string
  /** `0` when no model was involved because this row is a skip or a failure. */
  readonly model_version: number
  readonly model_trained_at: string | null
  readonly training_sample_count: number
  readonly contamination: number | null
  /** Raw decision-function output. Lower is more unusual; **not** a probability. */
  readonly decision_score: number | null
  readonly is_anomaly: boolean
  readonly status: AnomalyStatus
  readonly skip_reason: string | null
  readonly feature_context: readonly FeatureContext[]
  readonly alert_id: number | null
  readonly created_at: string | null
  /** The sentence explaining what the score is, and is not. */
  readonly decision_score_note: string
  readonly disclaimer: string
}

/** Counted totals for the page tiles (M22.13). */
export interface AnomalySummary {
  readonly evaluations: number
  readonly anomalies: number
  readonly affected_devices: number
  readonly scored: number
  readonly skipped: number
}

/** Payload of `GET /api/v1/anomalies` (M13.24). */
export interface AnomalyPage {
  readonly count: number
  readonly limit?: number | null
  readonly offset: number
  readonly total?: number | null
  readonly has_more?: boolean | null
  readonly anomalies: readonly AnomalyResult[]
  readonly summary: AnomalySummary
  readonly disclaimer: string
}

/** One device's model lifecycle (M22.12). */
export interface AnomalyModel {
  readonly device_key: string
  readonly identity_kind: string
  readonly algorithm: string
  readonly state: AnomalyModelState
  /** Short badge text, e.g. "Collecting data". */
  readonly state_label: string
  /** One sentence explaining the state; never reads as a clean bill of health. */
  readonly state_description: string
  readonly model_version: number
  readonly feature_names: readonly string[]
  readonly feature_schema_version: number
  readonly training_sample_count: number
  readonly training_window_count: number
  readonly min_training_windows: number
  readonly contamination: number | null
  readonly trained_at: string | null
  readonly last_evaluated_at: string | null
  readonly windows_since_training: number
  /** True only when this model can actually score a window. */
  readonly ready: boolean
  readonly last_error: string | null
  readonly disclaimer: string
}

/** Payload of `GET /api/v1/anomalies/models` (M22.12). */
export interface AnomalyModelPage {
  readonly count: number
  readonly limit?: number | null
  readonly offset: number
  readonly total?: number | null
  readonly has_more?: boolean | null
  readonly models: readonly AnomalyModel[]
  readonly disclaimer: string
}

/** Payload of `POST /api/v1/anomalies/models/{device_key}/retrain` (M22.12). */
export interface AnomalyRetrainResult {
  readonly device_key: string
  /** Always true: the request reached the training path. */
  readonly requested: boolean
  /** Whether a new model was produced. Read this, not the HTTP status. */
  readonly trained: boolean
  readonly state: AnomalyModelState
  readonly state_description: string
  readonly model_version: number
  readonly training_sample_count: number
  /** True when a failed pass kept the previous working model. */
  readonly previous_model_retained: boolean
  readonly reason: string | null
  readonly message: string
  readonly disclaimer: string
}

/** Filters accepted by `GET /api/v1/anomalies`. */
export interface AnomalyQuery {
  readonly device_key?: string
  readonly is_anomaly?: boolean
  readonly status?: AnomalyStatus
  /** Inclusive ISO-8601 lower bound on window start. */
  readonly since?: string
  /** Exclusive ISO-8601 upper bound on window start. */
  readonly until?: string
  readonly limit?: number
  readonly offset?: number
}

/** Filters accepted by `GET /api/v1/anomalies/models`. */
export interface AnomalyModelQuery {
  readonly state?: AnomalyModelState
  readonly limit?: number
  readonly offset?: number
}
