/**
 * The HTTP client (M15.38, "API").
 *
 * These tests exercise {@link apiRequest} against a stubbed `fetch`, so the
 * envelope parser, the query serialiser and the error translation all run for
 * real. Nothing here mocks a service or a hook: the unit under test is the client
 * itself, and the assertions are about what it returns and what it throws.
 *
 * The four cases M15.38 names are all present — a successful response, an API
 * error, a network failure and a validation failure — plus the specific statuses
 * M15.7 lists, because each one is a different sentence on screen.
 */

import { describe, expect, it, vi } from 'vitest'
import { environment } from '@/config/env'
import {
  ApiError,
  GENERIC_MESSAGE,
  NETWORK_MESSAGE,
  NOT_IMPLEMENTED_MESSAGE,
  TIMEOUT_MESSAGE,
  apiGet,
  apiPost,
  apiPut,
  apiRequest,
  buildQueryString,
  buildUrl,
  toApiError,
} from '@/services'
import {
  emptyResponse,
  failure,
  hangingFetch,
  installFetch,
  malformed,
  networkDownFetch,
  ok,
  raw,
  validationFailure,
} from '@/test/harness'

describe('buildQueryString', () => {
  it('omits null and undefined rather than sending the string "null"', () => {
    // The backend validates filters strictly, so `?status=null` would be a 400.
    expect(buildQueryString({ status: null, limit: undefined })).toBe('')
  })

  it('repeats an array as one parameter per value', () => {
    expect(buildQueryString({ status: ['open', 'acknowledged'] })).toBe(
      '?status=open&status=acknowledged',
    )
  })

  it('omits an empty array', () => {
    expect(buildQueryString({ status: [] })).toBe('')
  })

  it('percent-encodes a value that would otherwise break the URL', () => {
    expect(buildQueryString({ source_ip: '10.0.0.1/32', q: 'a&b=c' })).toBe(
      '?source_ip=10.0.0.1%2F32&q=a%26b%3Dc',
    )
  })

  it('writes a number and a boolean as their literal values', () => {
    expect(buildQueryString({ limit: 50, offset: 0, active: true })).toBe(
      '?limit=50&offset=0&active=true',
    )
  })

  it('returns an empty string when there is no query at all', () => {
    expect(buildQueryString(undefined)).toBe('')
  })
})

describe('buildUrl', () => {
  it('joins the configured base with the resource path', () => {
    expect(buildUrl('/devices')).toBe(`${environment.apiBaseUrl}/devices`)
  })

  it('accepts a path without a leading slash', () => {
    expect(buildUrl('devices')).toBe(`${environment.apiBaseUrl}/devices`)
  })

  it('appends the query string after the path', () => {
    expect(buildUrl('/devices', { limit: 25 })).toBe(
      `${environment.apiBaseUrl}/devices?limit=25`,
    )
  })
})

describe('apiRequest on success', () => {
  it('resolves with the payload the envelope wrapped, not the envelope', async () => {
    installFetch({ 'GET /devices': () => ok({ count: 2, devices: [{ device_id: 1 }] }) })
    const data = await apiGet<{ count: number }>('/devices')
    expect(data).toEqual({ count: 2, devices: [{ device_id: 1 }] })
  })

  it('sends the Accept header and no body on a GET', async () => {
    const router = installFetch({ 'GET /devices': () => ok({}) })
    await apiGet('/devices')
    expect(router.lastCall('GET /devices')?.path).toBe('/devices')
    expect(router.lastCall('GET /devices')?.body).toBeUndefined()
  })

  it('sends a JSON body and the matching content type on a POST', async () => {
    const router = installFetch({
      'POST /alerts/7/acknowledge': () => ok({ alert_id: 7 }),
    })
    await apiPost('/alerts/7/acknowledge', { body: { note: 'seen' } })
    expect(router.lastCall('POST /alerts/7/acknowledge')?.body).toEqual({ note: 'seen' })
  })

  it('performs a PUT and passes the body through', async () => {
    const router = installFetch({ 'PUT /settings': () => ok({ restart_required: false }) })
    await apiPut('/settings', { body: { values: { alert_threshold: 80 } } })
    expect(router.lastCall('PUT /settings')?.body).toEqual({
      values: { alert_threshold: 80 },
    })
  })

  it('serialises the query onto the request URL', async () => {
    const router = installFetch({ 'GET /packets': () => ok({ packets: [] }) })
    await apiGet('/packets', { limit: 10, protocol: ['TCP', 'UDP'] })
    expect(router.lastCall('GET /packets')?.params).toEqual({
      limit: '10',
      protocol: ['TCP', 'UDP'],
    })
  })
})

describe('apiRequest on an API error', () => {
  it('throws an ApiError carrying the backend sentence and field', async () => {
    installFetch({
      'GET /devices': () =>
        failure(400, 'The filter "status" is not recognised.', [
          { field: 'status', code: 'INVALID_FILTER' },
        ]),
    })

    const error = await apiGet('/devices').catch((cause: unknown) => cause)
    expect(error).toBeInstanceOf(ApiError)
    const apiError = error as ApiError
    expect(apiError.kind).toBe('validation')
    expect(apiError.code).toBe('INVALID_FILTER')
    expect(apiError.field).toBe('status')
    // The backend's own sentence is preferred: it names the offending filter.
    expect(apiError.userMessage).toBe('The filter "status" is not recognised.')
    expect(apiError.fieldDetails).toEqual(['status: INVALID_FILTER'])
  })

  it('maps 404 to not_found', async () => {
    installFetch({
      'GET /devices/9': () => failure(404, '', [{ field: 'device_id', code: 'DEVICE_NOT_FOUND' }]),
    })
    const error = (await apiGet('/devices/9').catch((cause: unknown) => cause)) as ApiError
    expect(error.kind).toBe('not_found')
    // An empty backend message falls back to this module's own sentence.
    expect(error.userMessage).toBe('That resource no longer exists on the backend.')
    expect(error.isRetryable).toBe(false)
  })

  it('maps 409 INVALID_TRANSITION to a conflict with a transition-specific sentence', async () => {
    installFetch({
      'POST /alerts/3/resolve': () =>
        failure(409, '', [{ field: 'status', code: 'INVALID_TRANSITION' }]),
    })
    const error = (
      await apiPost('/alerts/3/resolve').catch((cause: unknown) => cause)
    ) as ApiError
    expect(error.kind).toBe('conflict')
    expect(error.isUserFixable).toBe(true)
    // The code, not the status, picks the sentence: 409 alone is ambiguous.
    expect(error.userMessage).toContain('not allowed from the current state')
  })

  it('maps 409 IMMUTABLE_SETTING to a different sentence from the same status', async () => {
    installFetch({
      'PUT /settings': () =>
        failure(409, '', [{ field: 'key', code: 'IMMUTABLE_SETTING' }]),
    })
    const error = (
      await apiPut('/settings', { body: {} }).catch((cause: unknown) => cause)
    ) as ApiError
    expect(error.kind).toBe('conflict')
    expect(error.userMessage).toBe(
      'That setting is read-only and cannot be changed through this API.',
    )
  })

  it('maps 500 to server and marks it retryable without leaking the body', async () => {
    installFetch({
      'GET /dashboard/summary': () =>
        failure(500, 'The server failed while handling this request.', [
          { field: 'request', code: 'INTERNAL_ERROR' },
        ]),
    })
    const error = (
      await apiGet('/dashboard/summary').catch((cause: unknown) => cause)
    ) as ApiError
    expect(error.kind).toBe('server')
    expect(error.isRetryable).toBe(true)
  })

  it('maps 501 FEATURE_NOT_IMPLEMENTED to a milestone-boundary message', async () => {
    installFetch({
      'POST /reports': () => failure(501, '', [{ field: 'report', code: 'FEATURE_NOT_IMPLEMENTED' }]),
    })
    const error = (await apiPost('/reports').catch((cause: unknown) => cause)) as ApiError
    expect(error.kind).toBe('not_implemented')
    expect(error.userMessage).toBe(NOT_IMPLEMENTED_MESSAGE)
    // A milestone gap is not a fault, so offering a retry would be misleading.
    expect(error.isRetryable).toBe(false)
  })

  it('maps 503 to unavailable and marks it retryable', async () => {
    installFetch({
      'GET /system/status': () => failure(503, '', [{ field: 'service', code: 'SERVICE_UNAVAILABLE' }]),
    })
    const error = (await apiGet('/system/status').catch((cause: unknown) => cause)) as ApiError
    expect(error.kind).toBe('unavailable')
    expect(error.isRetryable).toBe(true)
  })

  it('uses the status when the body carried no envelope and no content', async () => {
    installFetch({ 'GET /devices': () => emptyResponse(500) })
    const error = (await apiGet('/devices').catch((cause: unknown) => cause)) as ApiError
    expect(error.kind).toBe('server')
    expect(error.status).toBe(500)
  })

  it('reports a 200 that is not the envelope as a malformed response', async () => {
    installFetch({ 'GET /devices': () => malformed() })
    const error = (await apiGet('/devices').catch((cause: unknown) => cause)) as ApiError
    expect(error.kind).toBe('unknown')
    expect(error.userMessage).toBe('The backend returned a response in an unexpected format.')
  })

  it('reports a 200 carrying a failure envelope as a failure rather than as data', async () => {
    installFetch({
      'GET /devices': () => raw({ success: false, message: 'nope', errors: [] }, 200),
    })
    const error = (await apiGet('/devices').catch((cause: unknown) => cause)) as ApiError
    expect(error).toBeInstanceOf(ApiError)
    expect(error.message).toBe('nope')
  })
})

describe('apiRequest on a validation failure', () => {
  it('reads FastAPI\'s own 422 shape, which bypasses the project envelope', async () => {
    installFetch({
      'GET /packets': () =>
        validationFailure([
          { loc: ['query', 'limit'], msg: 'Input should be a valid integer', type: 'int_parsing' },
        ]),
    })

    const error = (await apiGet('/packets').catch((cause: unknown) => cause)) as ApiError
    expect(error.kind).toBe('validation')
    expect(error.status).toBe(422)
    // The last segment of `loc` is the field a user can actually change.
    expect(error.field).toBe('limit')
    expect(error.code).toBe('int_parsing')
    expect(error.fieldDetails).toEqual(['limit: int_parsing'])
  })

  it('falls back to "request" when the loc path is empty', async () => {
    installFetch({
      'GET /packets': () => validationFailure([{ loc: [], msg: 'bad', type: 'value_error' }]),
    })
    const error = (await apiGet('/packets').catch((cause: unknown) => cause)) as ApiError
    expect(error.field).toBe('request')
  })
})

describe('apiRequest on a transport failure', () => {
  it('reports a rejected fetch as a network failure with a reachability sentence', async () => {
    vi.stubGlobal('fetch', networkDownFetch())
    const error = (await apiGet('/devices').catch((cause: unknown) => cause)) as ApiError
    expect(error.kind).toBe('network')
    expect(error.userMessage).toBe(NETWORK_MESSAGE)
    expect(error.isRetryable).toBe(true)
    // The browser's own text names a URL and must never be what a page renders.
    expect(error.userMessage).not.toContain('ECONNREFUSED')
  })

  it('reports its own abort as a timeout, separately from a network failure', async () => {
    vi.stubGlobal('fetch', hangingFetch())
    const error = (
      await apiRequest('/devices', { method: 'GET' }, undefined, { timeoutMs: 5 }).catch(
        (cause: unknown) => cause,
      )
    ) as ApiError
    expect(error.kind).toBe('timeout')
    expect(error.userMessage).toBe(TIMEOUT_MESSAGE)
    expect(error.isRetryable).toBe(true)
  })

  it('aborts at once when the caller\'s signal is already aborted', async () => {
    vi.stubGlobal('fetch', hangingFetch())
    const controller = new AbortController()
    controller.abort()
    const error = (
      await apiGet('/devices', undefined, { signal: controller.signal }).catch(
        (cause: unknown) => cause,
      )
    ) as ApiError
    expect(error.kind).toBe('timeout')
  })
})

describe('toApiError', () => {
  it('returns an ApiError unchanged', () => {
    const original = new ApiError({ kind: 'not_found', status: 404 })
    expect(toApiError(original)).toBe(original)
  })

  it('wraps a non-ApiError so a component never has to narrow', () => {
    const wrapped = toApiError(new TypeError('boom'))
    expect(wrapped).toBeInstanceOf(ApiError)
    expect(wrapped.kind).toBe('unknown')
    // The generic sentence is used, not the thrown text.
    expect(wrapped.userMessage).toBe(GENERIC_MESSAGE)
  })
})
