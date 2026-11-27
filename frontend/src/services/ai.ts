/**
 * Local LLM service (M23.11).
 *
 * Three calls, and the shape of each is the point:
 *
 * * `fetchAiStatus` — a read that **always succeeds** with one of four states.
 *   `disabled` and `unreachable` are conditions, not failures, so the page renders a
 *   badge and a sentence rather than an error banner.
 * * `fetchAiModels` — a passthrough of the runtime's own inventory. Nothing cached,
 *   nothing curated, because a curated list would be a claim about what is installed.
 * * `testAiGeneration` — a bounded prompt, and the model's reply as **untrusted
 *   text**.
 *
 * `testAiGeneration` passes an explicit timeout. The client's default is 15 seconds;
 * a cold model load was measured at ~9 seconds on the reference machine, so a
 * 60-second backend budget behind a 15-second browser budget would abort the request
 * while the model was still loading and report a timeout for work that was about to
 * succeed. The override is per call rather than global, so no other page inherits a
 * longer wait.
 */

import { apiGet, apiPost } from './client'
import { AiPaths } from './endpoints'
import type { AiModelList, AiStatus, AiTestResult } from '@/types'

/**
 * How long a test generation may take before the browser gives up.
 *
 * 90 seconds: the backend's own budget is 60, so a request that outlives it should
 * fail with the backend's sentence rather than the client's aborted-request one. The
 * margin is larger than the backend's so the *server* decides what a timeout means,
 * which is the only side that knows how long the model needed.
 */
export const AI_TEST_TIMEOUT_MS = 90_000

/**
 * `GET /api/v1/ai/status` — whether local AI is usable (M23.9).
 *
 * Resolves in every non-transport case, including disabled and unreachable: the
 * backend answers those with `200` and a state. Only a genuine transport failure
 * reaches the caller as an `ApiError`.
 */
export function fetchAiStatus(signal?: AbortSignal): Promise<AiStatus> {
  return apiGet<AiStatus>(AiPaths.status, undefined, { signal })
}

/**
 * `GET /api/v1/ai/models` — the models actually installed (M23.8).
 *
 * Answers `503` when the feature is disabled or the runtime is unreachable, so a
 * caller must read that as "cannot list" rather than "no models installed". The page
 * keeps the status call's state to tell the two apart.
 */
export function fetchAiModels(signal?: AbortSignal): Promise<AiModelList> {
  return apiGet<AiModelList>(AiPaths.models, undefined, { signal })
}

/**
 * `POST /api/v1/ai/test` — send a bounded prompt to the configured model (M23.9).
 *
 * The body is a prompt and nothing else: there is no way to name a model or a host
 * from here, which keeps "a client cannot choose what runs" a property of the type
 * rather than a convention.
 *
 * The reply is untrusted text. It is returned as a string and rendered; it is never
 * evaluated, never executed and never written to a detection or alert record.
 */
export function testAiGeneration(
  prompt: string,
  signal?: AbortSignal,
): Promise<AiTestResult> {
  return apiPost<AiTestResult>(AiPaths.test, {
    body: { prompt },
    timeoutMs: AI_TEST_TIMEOUT_MS,
    signal,
  })
}
