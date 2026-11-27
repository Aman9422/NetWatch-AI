/**
 * Local LLM models (M23.11).
 *
 * Four things are deliberate here, and a page must not "fix" any of them:
 *
 * * **A state, not an error.** `disabled` and `unreachable` are ordinary
 *   conditions of a development machine. The status endpoint answers `200` with
 *   one of these words, so a page renders a badge and a sentence rather than an
 *   error banner — and "switched off" stays distinguishable from "broken".
 * * **No verdict.** Nothing here is a security judgement. The test endpoint
 *   returns text a model produced, and `disclaimer` travels with every payload
 *   saying so.
 * * **No model or host in a request.** `AiTestRequest` is a prompt and nothing
 *   else, so a browser cannot choose which model runs or where it is reached.
 * * **`ai_enabled` is not this.** The database setting of that name on the
 *   Settings page is a different, older switch which the LLM runtime does not
 *   read. `enabled` here mirrors `llm_enabled`.
 */

/** The four states a local LLM integration can be in (mirrors `app.ai.health`). */
export type AiState = 'disabled' | 'unreachable' | 'model_missing' | 'ready'

/** Payload of `GET /api/v1/ai/status` (M23.9). */
export interface AiStatus {
  /** Whether `llm_enabled` is true. The authoritative switch for this runtime. */
  readonly enabled: boolean
  /** The configured runtime, e.g. `ollama`. */
  readonly provider: string
  /** The configured model, blank when none is selected. */
  readonly model: string
  readonly state: AiState
  /** Short badge text, e.g. "Runtime unreachable". */
  readonly state_label: string
  /** One sentence explaining the state and what to do about it. */
  readonly state_description: string
  /** Whether the runtime answered the health probe. */
  readonly runtime_reachable: boolean
  /** Whether the configured model is installed. */
  readonly model_available: boolean
  /** The runtime's version string, when it reported one. */
  readonly runtime_version: string
  /** How many models the runtime reports, when reachable. */
  readonly installed_model_count: number
  /** A safe sentence for the page. Never a provider error, URL or path. */
  readonly message: string
  /**
   * The probe budget this answer was produced under, in seconds.
   *
   * Reported because it explains the answer: `unreachable` after three seconds and
   * `unreachable` after sixty are different facts about the configuration, and an
   * operator seeing the number knows which one they are looking at.
   */
  readonly health_timeout_seconds: number
  /** The sentence stating what model output is and is not. */
  readonly disclaimer: string
}

/** One installed model, as the runtime reports it (M23.8). */
export interface AiModel {
  /** The identifier to name in `LLM_MODEL`. */
  readonly name: string
  /** e.g. `3.2B`, when reported. */
  readonly parameter_size: string
  /** e.g. `Q4_K_M`, when reported. */
  readonly quantization: string
  /** On-disk size in bytes, when reported. */
  readonly size_bytes: number
  /** e.g. `llama`, when reported. */
  readonly family: string
}

/** Payload of `GET /api/v1/ai/models` (M23.8). */
export interface AiModelList {
  readonly count: number
  /** The model named in configuration, so a page can mark it. */
  readonly configured_model: string
  /** Whether that model is among `models`. */
  readonly configured_model_installed: boolean
  readonly models: readonly AiModel[]
  readonly disclaimer: string
}

/**
 * Body of `POST /api/v1/ai/test` (M23.9).
 *
 * A prompt and nothing else. There is deliberately no `model`, `base_url`,
 * `timeout` or `temperature` field: adding one would let a browser choose what
 * runs and where.
 */
export interface AiTestRequest {
  readonly prompt: string
}

/** Payload of `POST /api/v1/ai/test` (M23.9). */
export interface AiTestResult {
  /** How long the accepted prompt was, so the page can confirm what was sent. */
  readonly requested_prompt_chars: number
  /** The model's reply. Untrusted text — rendered, never executed. */
  readonly response: string
  readonly model: string
  readonly provider: string
  readonly prompt_tokens: number
  readonly output_tokens: number
  /** Wall time the runtime spent, when reported. */
  readonly duration_ms: number
  /** `stop` for a finished reply, `length` when the output budget cut it off. */
  readonly done_reason: string
  readonly disclaimer: string
}

/** Every state, in the order a page presents them. */
export const AI_STATES: readonly AiState[] = [
  'disabled',
  'unreachable',
  'model_missing',
  'ready',
]

/** Return whether `value` is a known state. */
export function isAiState(value: string): value is AiState {
  return (AI_STATES as readonly string[]).includes(value)
}

/** Return whether the state permits a generation attempt. */
export function isAiReady(state: AiState): boolean {
  return state === 'ready'
}
