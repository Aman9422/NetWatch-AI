/**
 * Operator-triggered test generation (M23.11).
 *
 * A thin wrapper over `useAction`, like `useRetrainAnomalyModel`: a generation is a
 * plain POST whose outcome the backend describes, so all this needs is the shared
 * write primitive's progress, failure and result tracking.
 *
 * Three properties the caller must honour, and this hook does not hide them:
 *
 * * **`run` resolves with a discriminated result.** A caller handles the failure
 *   branch to read the value, so a refused generation can never be reported as
 *   having happened (M15.15).
 * * **A `503` is not one thing.** It covers "disabled", "runtime unreachable",
 *   "model missing" and "generation timed out", and the page distinguishes them by
 *   the `field` on the error rather than by the status code.
 * * **The result is text, not a verdict.** `AiTestResult.disclaimer` says so, and the
 *   page renders it rather than treating the reply as an answer about the network.
 */

import { useAction } from './useAction'
import type { ActionResource } from './useAction'
import { testAiGeneration } from '@/services'
import type { AiTestResult } from '@/types'

/** What {@link useAiTest} returns: an action taking one prompt. */
export type AiTestResource = ActionResource<
  readonly [prompt: string],
  AiTestResult
>

/**
 * Send a bounded prompt to the configured model.
 *
 * The returned `run` takes only the prompt. There is no way to pass a model, a host
 * or a timeout through it, which mirrors the request schema: what runs is decided by
 * configuration, never by the caller.
 */
export function useAiTest(): AiTestResource {
  return useAction(async (prompt: string) => testAiGeneration(prompt))
}
