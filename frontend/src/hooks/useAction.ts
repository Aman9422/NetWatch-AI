/**
 * The write primitive (M15.15/M15.19/M15.23).
 *
 * Every mutating call in this application — an alert transition, an incident
 * transition, a settings save, starting capture — goes through this hook, so the
 * three things a write must always do are done once rather than per button:
 *
 * * **Report a refusal instead of assuming success.** `run` resolves with a
 *   discriminated {@link ActionResult}, so a caller must handle the failure branch
 *   to read the value. That is deliberate: a `409 INVALID_TRANSITION` means the
 *   backend's transition table refused the move and the stored resource is
 *   unchanged, which is exactly the outcome a caller must not paper over
 *   (M15.15/M15.19).
 * * **Never update state after unmount.** A transition that resolves after the
 *   operator navigated away sets nothing; the request itself is still allowed to
 *   complete, because a lifecycle move is not something to cancel halfway.
 * * **Expose the raw `ApiError`.** A page branches on `kind` — a `conflict` is
 *   explained by the backend's own sentence, a `not_implemented` needs an
 *   "unavailable" panel — and only converts it to text at render time.
 *
 * Overlapping calls are prevented rather than queued: two clicks on "resolve"
 * would send the same transition twice, and while the second is a documented
 * no-op server-side, a double request is still two requests. `isRunning` is
 * exposed so a button can disable itself, and `run` refuses re-entry.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, toApiError } from '@/services'

/** The outcome of one write. The failure branch must be handled to read a value. */
export type ActionResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: ApiError }

/** What {@link useAction} returns. */
export interface ActionResource<TArgs extends readonly unknown[], TResult> {
  /** True while a call is in flight. */
  readonly isRunning: boolean
  /** The last failure, or `null`. Cleared when a later call starts. */
  readonly error: ApiError | null
  /** The last successful value, or `null`. */
  readonly result: TResult | null
  /**
   * Perform the action.
   *
   * Returns the outcome; it never rejects, so a click handler cannot produce an
   * unhandled rejection. A call made while one is already running resolves with
   * that call's refusal rather than starting a second request.
   */
  readonly run: (...args: TArgs) => Promise<ActionResult<TResult>>
  /** Forget the last result and error, e.g. when a dialog closes. */
  readonly reset: () => void
}

/**
 * Run a write and track its progress, its failure and its result.
 *
 * @param action The request. Receives whatever the caller passes to `run`.
 */
export function useAction<TArgs extends readonly unknown[], TResult>(
  action: (...args: TArgs) => Promise<TResult>,
): ActionResource<TArgs, TResult> {
  const [isRunning, setIsRunning] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)
  const [result, setResult] = useState<TResult | null>(null)

  const actionRef = useRef(action)
  actionRef.current = action
  const runningRef = useRef(false)
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  const run = useCallback(async (...args: TArgs): Promise<ActionResult<TResult>> => {
    if (runningRef.current) {
      // Re-entry is refused rather than queued: the caller asked twice for the
      // same state change, and the second request would only repeat the first.
      const refusal = new ApiError({
        kind: 'conflict',
        message: 'That action is already in progress.',
      })
      return { ok: false, error: refusal }
    }
    runningRef.current = true
    setIsRunning(true)
    setError(null)
    try {
      const value = await actionRef.current(...args)
      if (mountedRef.current) setResult(value)
      return { ok: true, value }
    } catch (cause) {
      const failure = toApiError(cause)
      if (mountedRef.current) setError(failure)
      return { ok: false, error: failure }
    } finally {
      runningRef.current = false
      if (mountedRef.current) setIsRunning(false)
    }
  }, [])

  const reset = useCallback(() => {
    setError(null)
    setResult(null)
  }, [])

  return { isRunning, error, result, run, reset }
}
