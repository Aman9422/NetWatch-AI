/**
 * The REST loading primitive (M15.8/M15.32).
 *
 * Every page-level REST read in the application goes through this hook, so the
 * four states M15.8 requires — loading, success, empty, error — are produced the
 * same way everywhere and no page reimplements them.
 *
 * Four decisions are load-bearing:
 *
 * * **A refresh does not blank the view.** `isLoading` is true during any request,
 *   but `isInitialLoading` is true only while there is nothing to show yet. A page
 *   uses the first to render a subtle busy state and the second to decide between
 *   a spinner and its content, which is the difference between a calm refresh and
 *   a flicker.
 * * **A stale response never wins.** Each request carries an id; a resolution whose
 *   id is no longer current is discarded. Without this, a fast first request that
 *   resolves after a slow second one would overwrite fresh data with older data —
 *   the classic race when a user changes a filter twice quickly.
 * * **Unmounting aborts the request.** The `AbortSignal` is passed to the service,
 *   so navigating away cancels the fetch rather than leaving it to resolve into a
 *   component that no longer exists.
 * * **The error is an `ApiError`, not a string.** A page branches on `kind`
 *   (`not_implemented` needs a different panel from `network`), and only converts
 *   it to a sentence with `userMessage` at the point of rendering.
 *
 * Data is deliberately **not** cached or shared across hooks. M15.32 asks for the
 * smallest state strategy that works, and a query cache would be a large library
 * solving a problem this application does not have: each page reads its own
 * resource, and live change arrives over WebSocket rather than from a second
 * component asking the same question.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { toApiError } from '@/services'
import type { ApiError } from '@/services'

/** What {@link useAsyncResource} returns. */
export interface AsyncResource<T> {
  /** The last successful value, or `null` when none has arrived. */
  readonly data: T | null
  /** The last failure, or `null`. Cleared when a retry succeeds. */
  readonly error: ApiError | null
  /**
   * The failure that is actually blocking the view.
   *
   * `error` is every failure; this is the subset that leaves the page with
   * nothing to show in its place. Once a payload has arrived, a later failure
   * does **not** erase it — the page renders the payload beside a
   * `RefreshFailureBanner`, which is what M15.8 asks for and what a failed
   * refresh must never turn into a blank screen.
   *
   * It is derived here rather than left to each page because ten pages made this
   * choice independently and most of them got it wrong, passing `error` straight
   * to `AsyncSection` and so wiping good rows the moment a refresh failed. The
   * rule is one line and belongs in one place.
   */
  readonly blockingError: ApiError | null
  /** True while any request is in flight. */
  readonly isLoading: boolean
  /** True only while the first request is in flight and there is nothing to show. */
  readonly isInitialLoading: boolean
  /** True when the last request finished successfully. */
  readonly isSuccess: boolean
  /**
   * True when the last request succeeded and returned nothing to display.
   *
   * The predicate is supplied by the caller because "empty" is resource-specific:
   * a page of zero devices is empty, but a dashboard summary full of zeroes is
   * not.
   */
  readonly isEmpty: boolean
  /** Run the loader again. Stable, so it can be a dependency or a click handler. */
  readonly reload: () => void
}

/** Options accepted by {@link useAsyncResource}. */
export interface AsyncResourceOptions<T> {
  /** When False the loader is not run — for a tab that is not open, or a dialog. */
  readonly enabled?: boolean
  /** Decide whether a successful value counts as empty. Defaults to never. */
  readonly isEmpty?: (data: T) => boolean
}

/**
 * Run an async loader and track its four states.
 *
 * @param loader Performs the request. Receives an `AbortSignal` it must pass to
 *   the service, so unmounting cancels the work.
 * @param deps What the loader depends on. The request re-runs when these change,
 *   exactly like `useEffect`.
 * @param options Whether to run at all, and how to recognise an empty result.
 */
export function useAsyncResource<T>(
  loader: (signal: AbortSignal) => Promise<T>,
  deps: readonly unknown[],
  options: AsyncResourceOptions<T> = {},
): AsyncResource<T> {
  const enabled = options.enabled ?? true
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const [isLoading, setIsLoading] = useState(enabled)
  const [hasLoaded, setHasLoaded] = useState(false)
  const [reloadToken, setReloadToken] = useState(0)

  // The loader is read from a ref so a caller that passes an inline arrow
  // function — which most of them do — does not restart the request on every
  // render. `deps` is the only thing that decides when to re-run.
  const loaderRef = useRef(loader)
  loaderRef.current = loader

  // The id of the most recent request. A resolution whose id is behind this one
  // is discarded, which is what stops a slow response from overwriting a fast one.
  const requestIdRef = useRef(0)
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  useEffect(() => {
    if (!enabled) return
    const requestId = ++requestIdRef.current
    const controller = new AbortController()
    setIsLoading(true)
    setError(null)

    void (async () => {
      try {
        const result = await loaderRef.current(controller.signal)
        if (requestId !== requestIdRef.current || !mountedRef.current) return
        setData(result)
        setError(null)
        setHasLoaded(true)
      } catch (cause) {
        // An abort is this hook's own doing — a dependency change or an unmount —
        // so it is not a failure to report. Any other throw is.
        if (controller.signal.aborted) return
        if (requestId !== requestIdRef.current || !mountedRef.current) return
        setError(toApiError(cause))
        setHasLoaded(true)
      } finally {
        if (requestId === requestIdRef.current && mountedRef.current) setIsLoading(false)
      }
    })()

    return () => controller.abort()
    // `deps` is intentionally spread: the caller owns the dependency list, exactly
    // as with `useEffect`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, reloadToken, ...deps])

  const reload = useCallback(() => {
    setReloadToken((token) => token + 1)
  }, [])

  const isEmpty =
    data !== null && options.isEmpty !== undefined ? options.isEmpty(data) : false

  return {
    data,
    error,
    // Blocking only when the failure left nothing behind: a payload that has
    // already arrived survives a later failed refresh, and the page shows a
    // staleness banner for that case instead of replacing what was on screen.
    blockingError: error !== null && data === null ? error : null,
    isLoading,
    isInitialLoading: isLoading && !hasLoaded,
    isSuccess: data !== null && error === null,
    isEmpty,
    reload,
  }
}
