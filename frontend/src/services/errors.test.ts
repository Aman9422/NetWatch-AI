/**
 * The API error model (M15.7).
 *
 * `client.test.ts` covers the error model *through* the client, which is how the
 * application uses it. This file covers the parts that have no request attached to
 * them — the status-to-kind map, the sentence chooser, and the two invariants a
 * page depends on:
 *
 * * `userMessage` is always a sentence this module produced, never the backend's
 *   raw text and never a `fetch` rejection;
 * * `isRetryable` and `isUserFixable` are mutually exclusive answers to "what
 *   should this screen offer?", so a page never shows both a retry button and a
 *   "fix your input" hint for the same failure.
 */

import { describe, expect, it } from 'vitest'
import {
  ApiError,
  GENERIC_MESSAGE,
  NETWORK_MESSAGE,
  NOT_IMPLEMENTED_MESSAGE,
  TIMEOUT_MESSAGE,
  isApiError,
  kindForStatus,
  malformedResponseError,
  messageFor,
  messageForKind,
  networkError,
  toApiError,
  toUserMessage,
} from '@/services'

/** An abort the way each environment reports one. */
function abortLike(name: 'AbortError' | 'Error'): Error {
  const error = new Error('aborted')
  error.name = name
  return error
}

describe('kindForStatus', () => {
  it.each([
    [400, 'validation'],
    [422, 'validation'],
    [404, 'not_found'],
    [409, 'conflict'],
    [500, 'server'],
    [501, 'not_implemented'],
    [503, 'unavailable'],
  ] as const)('maps %i to %s', (status, kind) => {
    expect(kindForStatus(status)).toBe(kind)
  })

  it('treats 502 as a server failure rather than as "unavailable"', () => {
    // Only 503 means "the dependency is switched off", which is the one a page
    // words differently; a 502 from a proxy is an ordinary server fault.
    expect(kindForStatus(502)).toBe('server')
  })

  it('falls back to validation for an undocumented 4xx', () => {
    // A method the route does not serve is the caller's mistake, so offering a
    // retry would be wrong.
    expect(kindForStatus(405)).toBe('validation')
  })

  it('reports a 3xx as unknown rather than inventing a kind', () => {
    expect(kindForStatus(302)).toBe('unknown')
  })
})

describe('messageFor', () => {
  it('prefers a conflict code over the status, because one status covers several problems', () => {
    expect(messageFor(409, 'INVALID_TRANSITION')).toContain('not allowed from the current state')
    expect(messageFor(409, 'IMMUTABLE_SETTING')).toContain('read-only')
    expect(messageFor(409, 'INVALID_LIFECYCLE')).toContain('not a valid lifecycle state')
  })

  it('uses a validation code sentence when one is known', () => {
    expect(messageFor(400, 'INVALID_FILTER')).toContain('filter value was rejected')
  })

  it('maps FEATURE_NOT_IMPLEMENTED to the milestone-boundary sentence', () => {
    expect(messageFor(501, 'FEATURE_NOT_IMPLEMENTED')).toBe(NOT_IMPLEMENTED_MESSAGE)
  })

  it('ignores an unknown code and falls back to the status', () => {
    expect(messageFor(404, 'SOMETHING_NEW')).toBe(messageForKind('not_found'))
  })

  it('falls back to the status when no code arrived', () => {
    expect(messageFor(503)).toBe(messageForKind('unavailable'))
  })
})

describe('messageForKind', () => {
  it('never returns an empty sentence, for any kind', () => {
    const kinds = [
      'network',
      'timeout',
      'validation',
      'not_found',
      'conflict',
      'not_implemented',
      'server',
      'unavailable',
      'unknown',
    ] as const
    for (const kind of kinds) {
      expect(messageForKind(kind).length).toBeGreaterThan(0)
    }
  })

  it('names the backend and the base URL for a network failure', () => {
    // The most common first-run problem is a backend that is not running, so this
    // sentence has to say what to check.
    expect(messageForKind('network')).toBe(NETWORK_MESSAGE)
    expect(NETWORK_MESSAGE).toContain('API base URL')
  })
})

describe('networkError', () => {
  it('reports an abort as a timeout', () => {
    expect(networkError(abortLike('AbortError')).kind).toBe('timeout')
  })

  it('reports any other rejection as a network failure', () => {
    expect(networkError(new TypeError('fetch failed')).kind).toBe('network')
  })

  it('keeps the original cause for the console', () => {
    const cause = new TypeError('fetch failed')
    expect(networkError(cause).cause).toBe(cause)
  })

  it('tolerates a thrown non-object', () => {
    // A rejection value is whatever was thrown, and it is not required to be an
    // Error; reading `.name` off a string must not itself throw.
    expect(networkError('boom').kind).toBe('network')
  })
})

describe('malformedResponseError', () => {
  it('reports a shape the client does not recognise as unknown', () => {
    const error = malformedResponseError(200, { nope: true })
    expect(error.kind).toBe('unknown')
    expect(error.status).toBe(200)
  })

  it('does not claim the request failed at the server', () => {
    expect(malformedResponseError(200).isRetryable).toBe(false)
  })
})

describe('ApiError', () => {
  it('prefers the backend sentence over the generic one', () => {
    const error = new ApiError({ kind: 'validation', message: 'Filter "status" is not valid.' })
    expect(error.userMessage).toBe('Filter "status" is not valid.')
  })

  it('substitutes a kind sentence when the constructor was given none', () => {
    expect(new ApiError({ kind: 'timeout' }).userMessage).toBe(TIMEOUT_MESSAGE)
  })

  it('does not leak the generic sentence when a more specific one exists for the kind', () => {
    // `new ApiError` defaults `message` to the generic text; that default must not
    // shadow the per-kind sentence, or every failure would read identically.
    const error = new ApiError({ kind: 'unavailable' })
    expect(error.message).toBe(GENERIC_MESSAGE)
    expect(error.userMessage).toBe(messageForKind('unavailable'))
    expect(error.userMessage).not.toBe(GENERIC_MESSAGE)
  })

  it('offers a retry exactly for the failures a retry can fix', () => {
    for (const kind of ['network', 'timeout', 'server', 'unavailable'] as const) {
      expect(new ApiError({ kind }).isRetryable).toBe(true)
    }
    for (const kind of ['validation', 'not_found', 'conflict', 'not_implemented'] as const) {
      expect(new ApiError({ kind }).isRetryable).toBe(false)
    }
  })

  it('marks the two input-driven kinds as the user\'s to fix', () => {
    expect(new ApiError({ kind: 'validation' }).isUserFixable).toBe(true)
    expect(new ApiError({ kind: 'conflict' }).isUserFixable).toBe(true)
  })

  it('does not offer both a retry and an input hint for the same failure', () => {
    // A screen renders one of the two, so an error where both were true would give
    // the operator contradictory advice.
    for (const kind of [
      'network',
      'timeout',
      'validation',
      'not_found',
      'conflict',
      'not_implemented',
      'server',
      'unavailable',
      'unknown',
    ] as const) {
      const error = new ApiError({ kind })
      expect(error.isRetryable && error.isUserFixable).toBe(false)
    }
  })

  it('fixes a milestone gap as neither retryable nor the user\'s fault', () => {
    const error = new ApiError({ kind: 'not_implemented' })
    expect(error.isRetryable).toBe(false)
    expect(error.isUserFixable).toBe(false)
  })

  it('formats field details as "field: code"', () => {
    const error = new ApiError({
      kind: 'validation',
      fields: [
        { field: 'limit', code: 'INVALID_FILTER' },
        { field: 'status', code: 'INVALID_FILTER' },
      ],
    })
    expect(error.fieldDetails).toEqual(['limit: INVALID_FILTER', 'status: INVALID_FILTER'])
  })

  it('shows only the code when the failure names no field', () => {
    const error = new ApiError({
      kind: 'validation',
      fields: [{ field: '', code: 'INVALID_REQUEST' }],
    })
    expect(error.fieldDetails).toEqual(['INVALID_REQUEST'])
  })

  it('reports no field details rather than `undefined` when there are none', () => {
    expect(new ApiError({ kind: 'server' }).fieldDetails).toEqual([])
  })

  it('is an Error, so an unhandled rejection still prints a stack', () => {
    const error = new ApiError({ kind: 'server' })
    expect(error).toBeInstanceOf(Error)
    expect(error.name).toBe('ApiError')
    expect(typeof error.stack).toBe('string')
  })
})

describe('isApiError', () => {
  it('accepts an ApiError', () => {
    expect(isApiError(new ApiError({ kind: 'server' }))).toBe(true)
  })

  it('rejects a plain Error', () => {
    expect(isApiError(new Error('boom'))).toBe(false)
  })

  it('rejects a non-object', () => {
    expect(isApiError('boom')).toBe(false)
    expect(isApiError(null)).toBe(false)
  })
})

describe('toApiError', () => {
  it('returns the same ApiError instance', () => {
    const original = new ApiError({ kind: 'conflict' })
    expect(toApiError(original)).toBe(original)
  })

  it('wraps anything else so a component never has to narrow', () => {
    const wrapped = toApiError({ nope: true })
    expect(wrapped).toBeInstanceOf(ApiError)
    expect(wrapped.kind).toBe('unknown')
    expect(wrapped.cause).toEqual({ nope: true })
  })
})

describe('toUserMessage', () => {
  it('renders an ApiError\'s own sentence', () => {
    expect(toUserMessage(new ApiError({ kind: 'timeout' }))).toBe(TIMEOUT_MESSAGE)
  })

  it('falls back to the generic sentence for a non-API value', () => {
    // The fallback must not render the value itself: a thrown string could be a
    // URL, and a thrown object would render as "[object Object]".
    expect(toUserMessage('http://127.0.0.1:8000/api/v1/devices')).toBe(GENERIC_MESSAGE)
    expect(toUserMessage({ detail: 'traceback' })).toBe(GENERIC_MESSAGE)
  })
})
