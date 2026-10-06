/**
 * The REST loading primitive (M15.8/M15.32).
 *
 * Four of the behaviours here are the reason this hook exists rather than a
 * `useEffect` in each page, and each is a real defect when it is missing:
 *
 * * a refresh must not blank the view (`isInitialLoading` is false once something
 *   has been shown, even while a reload is in flight);
 * * a stale response must not win the race against a newer one;
 * * unmounting must abort the request rather than let it resolve into a component
 *   that no longer exists;
 * * the failure must be an `ApiError`, because a page branches on `kind`.
 *
 * A deferred promise is used rather than a resolved one wherever the *order* of
 * resolution is what is being asserted — a resolved promise settles before the
 * test can observe the in-flight state at all.
 */

import { act, renderHook, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ApiError, NETWORK_MESSAGE } from '@/services'
import { useAsyncResource } from '@/hooks'

/** A promise whose settlement the test decides. */
interface Deferred<T> {
  readonly promise: Promise<T>
  readonly resolve: (value: T) => void
  readonly reject: (reason: unknown) => void
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

/** An abort rejection shaped the way `networkError` recognises one. */
function abortError(): Error {
  const error = new Error('aborted')
  error.name = 'AbortError'
  return error
}

describe('useAsyncResource on success', () => {
  it('starts in the initial-loading state', () => {
    const pending = deferred<string>()
    const { result } = renderHook(() => useAsyncResource(() => pending.promise, []))
    expect(result.current.isLoading).toBe(true)
    expect(result.current.isInitialLoading).toBe(true)
    expect(result.current.data).toBeNull()
    expect(result.current.error).toBeNull()
  })

  it('exposes the value once the loader settles', async () => {
    const { result } = renderHook(() => useAsyncResource(() => Promise.resolve('devices'), []))
    await waitFor(() => {
      expect(result.current.data).toBe('devices')
    })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.isInitialLoading).toBe(false)
    expect(result.current.isSuccess).toBe(true)
    expect(result.current.error).toBeNull()
  })

  it('passes an abort signal to the loader, so the service can cancel the request', async () => {
    // Without this the hook could not cancel anything, and a slow request would
    // resolve into a component the user has already navigated away from.
    const seen: AbortSignal[] = []
    const { result } = renderHook(() =>
      useAsyncResource((signal) => {
        seen.push(signal)
        return Promise.resolve('ok')
      }, []),
    )
    await waitFor(() => {
      expect(result.current.data).toBe('ok')
    })
    expect(seen).toHaveLength(1)
    expect(seen[0]).toBeInstanceOf(AbortSignal)
  })

  it('counts a successful empty result as empty only when told how', () => {
    const { result } = renderHook(() =>
      useAsyncResource(() => Promise.resolve<string[]>([]), [], {
        isEmpty: (rows) => rows.length === 0,
      }),
    )
    // Before the request settles there is nothing to judge, so it is not "empty".
    expect(result.current.isEmpty).toBe(false)
  })

  it('reports an empty payload with the caller\'s predicate', async () => {
    const { result } = renderHook(() =>
      useAsyncResource(() => Promise.resolve<string[]>([]), [], {
        isEmpty: (rows) => rows.length === 0,
      }),
    )
    await waitFor(() => {
      expect(result.current.isEmpty).toBe(true)
    })
  })

  it('does not call a full payload empty', async () => {
    const { result } = renderHook(() =>
      useAsyncResource(() => Promise.resolve(['a']), [], {
        isEmpty: (rows) => rows.length === 0,
      }),
    )
    await waitFor(() => {
      expect(result.current.isEmpty).toBe(false)
    })
  })

  it('never calls a payload empty when no predicate was given', async () => {
    // The default matters: a dashboard summary of zeroes is a valid summary, not
    // an empty page, and only the caller knows which it holds.
    const { result } = renderHook(() => useAsyncResource(() => Promise.resolve(0), []))
    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })
    expect(result.current.isEmpty).toBe(false)
  })
})

describe('useAsyncResource on failure', () => {
  it('reports an ApiError with its kind preserved', async () => {
    const failure = new ApiError({ kind: 'not_implemented' })
    const { result } = renderHook(() => useAsyncResource(() => Promise.reject(failure), []))
    await waitFor(() => {
      expect(result.current.error).not.toBeNull()
    })
    expect(result.current.error?.kind).toBe('not_implemented')
    expect(result.current.error?.isRetryable).toBe(false)
  })

  it('coerces a non-ApiError throw so a page never has to narrow', async () => {
    const { result } = renderHook(() =>
      useAsyncResource(() => Promise.reject(new TypeError('fetch failed')), []),
    )
    await waitFor(() => {
      expect(result.current.error).not.toBeNull()
    })
    expect(result.current.error).toBeInstanceOf(ApiError)
    expect(result.current.error?.kind).toBe('unknown')
  })

  it('clears the error when a retry succeeds', async () => {
    let shouldFail = true
    const { result } = renderHook(() =>
      useAsyncResource(
        () => (shouldFail ? Promise.reject(new ApiError({ kind: 'network' })) : Promise.resolve('ok')),
        [],
      ),
    )
    await waitFor(() => {
      expect(result.current.error).not.toBeNull()
    })
    shouldFail = false
    act(() => {
      result.current.reload()
    })
    await waitFor(() => {
      expect(result.current.data).toBe('ok')
    })
    expect(result.current.error).toBeNull()
  })

  it('does not report a failure it caused itself by aborting', async () => {
    // A dependency change aborts the previous request. That abort must not surface
    // as an error, or every filter change would flash a failure.
    const requests: Deferred<string>[] = []
    const { result, rerender } = renderHook(
      ({ id }: { id: number }) =>
        useAsyncResource(() => {
          const request = deferred<string>()
          requests.push(request)
          return request.promise
        }, [id]),
      { initialProps: { id: 1 } },
    )

    rerender({ id: 2 })
    await act(async () => {
      requests[0]?.reject(abortError())
    })
    expect(result.current.error).toBeNull()
  })

  it('does not clear data that is already on screen when a refresh fails', async () => {
    // The operator keeps reading what they had; the page shows a staleness banner
    // rather than replacing good rows with an error panel (M15.8).
    let shouldFail = false
    const { result } = renderHook(() =>
      useAsyncResource(
        () => (shouldFail ? Promise.reject(new ApiError({ kind: 'network' })) : Promise.resolve('rows')),
        [],
      ),
    )
    await waitFor(() => {
      expect(result.current.data).toBe('rows')
    })
    shouldFail = true
    act(() => {
      result.current.reload()
    })
    await waitFor(() => {
      expect(result.current.error).not.toBeNull()
    })
    expect(result.current.data).toBe('rows')
    expect(result.current.error?.userMessage).toBe(NETWORK_MESSAGE)
  })
})

describe('useAsyncResource lifecycle', () => {
  it('re-runs when a dependency changes', async () => {
    const loader = vi.fn((id: number) => Promise.resolve(`value ${id}`))
    const { result, rerender } = renderHook(
      ({ id }: { id: number }) => useAsyncResource(() => loader(id), [id]),
      { initialProps: { id: 1 } },
    )
    await waitFor(() => {
      expect(result.current.data).toBe('value 1')
    })
    rerender({ id: 2 })
    await waitFor(() => {
      expect(result.current.data).toBe('value 2')
    })
    expect(loader).toHaveBeenCalledTimes(2)
  })

  it('re-runs on an explicit reload', async () => {
    const loader = vi.fn(() => Promise.resolve('value'))
    const { result } = renderHook(() => useAsyncResource(loader, []))
    await waitFor(() => {
      expect(result.current.data).toBe('value')
    })
    act(() => {
      result.current.reload()
    })
    await waitFor(() => {
      expect(loader).toHaveBeenCalledTimes(2)
    })
  })

  it('runs nothing at all while disabled', () => {
    const loader = vi.fn(() => Promise.resolve('value'))
    const { result } = renderHook(() => useAsyncResource(loader, [], { enabled: false }))
    expect(loader).not.toHaveBeenCalled()
    expect(result.current.isLoading).toBe(false)
    expect(result.current.isInitialLoading).toBe(false)
    expect(result.current.data).toBeNull()
  })

  it('starts loading when it becomes enabled', async () => {
    const loader = vi.fn(() => Promise.resolve('value'))
    const { result, rerender } = renderHook(
      ({ enabled }: { enabled: boolean }) => useAsyncResource(loader, [], { enabled }),
      { initialProps: { enabled: false } },
    )
    rerender({ enabled: true })
    await waitFor(() => {
      expect(result.current.data).toBe('value')
    })
    expect(loader).toHaveBeenCalledTimes(1)
  })

  it('discards a response that arrived after a newer one', async () => {
    // The classic race: a user changes a filter twice quickly, the first request is
    // slow, and it resolves last. Without the request-id guard it would overwrite
    // the fresh page with an older one.
    const requests: Deferred<string>[] = []
    const { result, rerender } = renderHook(
      ({ id }: { id: number }) =>
        useAsyncResource(() => {
          const request = deferred<string>()
          requests.push(request)
          return request.promise
        }, [id]),
      { initialProps: { id: 1 } },
    )

    rerender({ id: 2 })
    expect(requests).toHaveLength(2)

    // The newer request settles first, then the older one.
    await act(async () => {
      requests[1]?.resolve('newer')
    })
    await act(async () => {
      requests[0]?.resolve('older')
    })

    expect(result.current.data).toBe('newer')
  })

  it('aborts the in-flight request when the component unmounts', async () => {
    const signals: AbortSignal[] = []
    const { unmount } = renderHook(() =>
      useAsyncResource((signal) => {
        signals.push(signal)
        return deferred<string>().promise
      }, []),
    )
    expect(signals[0]?.aborted).toBe(false)
    unmount()
    expect(signals[0]?.aborted).toBe(true)
  })

  it('aborts the previous request when the dependencies change', async () => {
    const signals: AbortSignal[] = []
    const { rerender } = renderHook(
      ({ id }: { id: number }) =>
        useAsyncResource((signal) => {
          signals.push(signal)
          return deferred<string>().promise
        }, [id]),
      { initialProps: { id: 1 } },
    )
    rerender({ id: 2 })
    expect(signals).toHaveLength(2)
    expect(signals[0]?.aborted).toBe(true)
    expect(signals[1]?.aborted).toBe(false)
  })

  it('does not re-run when only the loader identity changes', async () => {
    // A page almost always passes an inline arrow, which is a new function every
    // render. Treating that as a dependency would restart the request forever.
    const loader = vi.fn(() => Promise.resolve('value'))
    const { result, rerender } = renderHook(
      ({ extra }: { extra: number }) => useAsyncResource(() => loader(), [extra]),
      { initialProps: { extra: 1 } },
    )
    await waitFor(() => {
      expect(result.current.data).toBe('value')
    })
    rerender({ extra: 1 })
    rerender({ extra: 1 })
    expect(loader).toHaveBeenCalledTimes(1)
  })
})
