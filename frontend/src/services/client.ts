/**
 * The shared HTTP client (M15.5).
 *
 * Every REST call in the application goes through {@link apiRequest}. That is the
 * whole point of the module: the base URL, the envelope, the error translation
 * and the timeout are decided once, so a page cannot get one of them wrong and no
 * page repeats the response parsing.
 *
 * The client understands all three shapes the backend can answer with:
 *
 * 1. the project envelope, `{ success: true, message, data }` (M13.4);
 * 2. the project error envelope, `{ success: false, message, errors }` (M13.4);
 * 3. FastAPI's own `422 { detail: [...] }`, which the backend deliberately leaves
 *    outside the envelope because the per-field detail is the point of the status
 *    (`app/api/common/errors.py`).
 *
 * Anything else is reported as a malformed response rather than guessed at.
 *
 * **Timeouts are client-side only and always distinguishable.** A request that
 * outlives its budget is aborted, and the abort is reported as a `timeout` rather
 * than as a generic network failure, because the two need different wording and
 * one of them is retryable.
 */

import { environment } from '@/config/env'
import {
  isApiSuccess,
  isValidationErrorBody,
  type ApiEnvelope,
  type ApiFailure,
  type ApiFieldError,
} from '@/types'
import {
  ApiError,
  GENERIC_MESSAGE,
  kindForStatus,
  malformedResponseError,
  messageFor,
  networkError,
} from './errors'

/** A query value the client can serialise. */
export type QueryValue =
  | string
  | number
  | boolean
  | null
  | undefined
  | readonly (string | number)[]

/** Query parameters for one request. */
export type QueryParams = Readonly<Record<string, QueryValue>>

/** Options accepted by {@link apiRequest}. */
export interface RequestOptions {
  /** Caller-supplied abort signal, e.g. from a component unmounting. */
  readonly signal?: AbortSignal
  /** Override the configured timeout for this one request. */
  readonly timeoutMs?: number
}

/** Options for a request that carries a body. */
export interface BodyRequestOptions extends RequestOptions {
  /** Value serialised as JSON. `undefined` sends no body. */
  readonly body?: unknown
}

/**
 * Serialise query parameters into a `?a=1&b=2` string.
 *
 * Three rules, each of which prevents a real bug:
 *
 * * a `null` or `undefined` value is **omitted**, not sent as the string
 *   `"null"` — the backend validates filters strictly and would reject it
 *   (M13.25);
 * * an empty array is omitted for the same reason;
 * * an array is repeated as `?status=open&status=acknowledged`, which is the form
 *   FastAPI's `list[str]` parameters read.
 *
 * Values are `encodeURIComponent`-ed, so an address in a filter cannot break the
 * URL.
 */
export function buildQueryString(query: QueryParams | undefined): string {
  if (!query) return ''
  const parts: string[] = []
  for (const [key, value] of Object.entries(query)) {
    if (value === null || value === undefined) continue
    if (Array.isArray(value)) {
      for (const entry of value) {
        if (entry === null || entry === undefined) continue
        parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(entry))}`)
      }
      continue
    }
    parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`)
  }
  return parts.length === 0 ? '' : `?${parts.join('&')}`
}

/**
 * Join the configured base URL with a resource path.
 *
 * `path` is expected to begin `/` (`/devices`, `/alerts/1`). A path with a
 * trailing slash is left alone so a caller can deliberately target one.
 */
export function buildUrl(path: string, query?: QueryParams): string {
  const suffix = path.startsWith('/') ? path : `/${path}`
  return `${environment.apiBaseUrl}${suffix}${buildQueryString(query)}`
}

/** Turn one entry of FastAPI's `422` detail list into a field error. */
function fieldErrorFromValidation(detail: {
  readonly loc: readonly (string | number)[]
  readonly msg: string
  readonly type: string
}): ApiFieldError {
  // `loc` is a path such as `["query", "limit"]`. The last segment is the field
  // the user can actually change, and the rest is FastAPI's own bookkeeping.
  const last = detail.loc.length > 0 ? detail.loc[detail.loc.length - 1] : 'request'
  return { field: String(last), code: detail.type || 'INVALID_REQUEST' }
}

/** Build the error for an unrecognised response body. */
function errorFromUnexpectedBody(status: number, body: unknown): ApiError {
  return new ApiError({
    kind: kindForStatus(status),
    status,
    message: messageFor(status),
    cause: body,
  })
}

/**
 * Translate a failed response into an {@link ApiError}.
 *
 * The backend's `message` is preserved because it is the only text that names the
 * field that failed, and its `errors` list becomes {@link ApiError.fieldDetails}
 * so a form can point at the offending input.
 */
function errorFromFailureResponse(status: number, failure: ApiFailure): ApiError {
  const first = failure.errors[0]
  return new ApiError({
    kind: kindForStatus(status),
    status,
    code: first?.code,
    field: first?.field,
    fields: failure.errors,
    // The envelope's message is already a safe human sentence and is more
    // specific than anything this client could compose, so it is used as-is.
    message: failure.message || messageFor(status, first?.code),
  })
}

/** Build the error for a failure whose body could not be read at all. */
function errorFromEmptyFailure(status: number): ApiError {
  return new ApiError({
    kind: kindForStatus(status),
    status,
    message: messageFor(status),
  })
}

/** Read a response body as JSON without throwing on an empty or non-JSON body. */
async function readJson(response: Response): Promise<unknown> {
  const text = await response.text()
  if (text.trim() === '') return undefined
  try {
    return JSON.parse(text) as unknown
  } catch {
    return undefined
  }
}

/** Return True when `value` looks like the project's error envelope. */
function isFailureEnvelope(value: unknown): value is ApiFailure {
  if (typeof value !== 'object' || value === null) return false
  const candidate = value as { success?: unknown; errors?: unknown }
  return candidate.success === false && Array.isArray(candidate.errors)
}

/**
 * Perform one API request and return its `data`.
 *
 * Resolves with the payload the envelope wrapped, or rejects with an
 * {@link ApiError}. It never rejects with a raw `TypeError` from `fetch`, and it
 * never resolves with an error envelope.
 *
 * @param path Resource path beginning `/`, e.g. `/devices`.
 * @param init Standard `RequestInit` fields this client sets itself.
 * @param query Query parameters, already typed.
 * @param options Timeout and abort signal.
 */
export async function apiRequest<T>(
  path: string,
  init: { method: string; body?: unknown },
  query?: QueryParams,
  options: RequestOptions = {},
): Promise<T> {
  const url = buildUrl(path, query)
  const controller = new AbortController()
  const timeoutMs = options.timeoutMs ?? environment.requestTimeoutMs
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  const externalSignal = options.signal

  const onExternalAbort = (): void => controller.abort()
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort()
    else externalSignal.addEventListener('abort', onExternalAbort)
  }

  let response: Response
  try {
    const headers: Record<string, string> = { Accept: 'application/json' }
    if (init.body !== undefined) headers['Content-Type'] = 'application/json'
    response = await fetch(url, {
      method: init.method,
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      signal: controller.signal,
    })
  } catch (cause) {
    throw networkError(cause)
  } finally {
    clearTimeout(timer)
    externalSignal?.removeEventListener('abort', onExternalAbort)
  }

  const body = await readJson(response)

  if (!response.ok) {
    // A 422 from FastAPI's own validation handler is the one failure that does
    // not use the project envelope, so it is recognised by its shape.
    if (isValidationErrorBody(body)) {
      const fields = body.detail.map(fieldErrorFromValidation)
      throw new ApiError({
        kind: 'validation',
        status: response.status,
        code: fields[0]?.code ?? 'INVALID_REQUEST',
        field: fields[0]?.field,
        fields,
        message:
          'The backend rejected this request’s parameters. Adjust the highlighted values and try again.',
      })
    }
    if (isFailureEnvelope(body)) {
      throw errorFromFailureResponse(response.status, body)
    }
    if (body === undefined) {
      throw errorFromEmptyFailure(response.status)
    }
    throw errorFromUnexpectedBody(response.status, body)
  }

  if (!isApiSuccess<T>(body as ApiEnvelope<T>)) {
    if (isFailureEnvelope(body)) {
      // A 200 carrying a failure envelope should not happen; reporting it as a
      // failure is still better than returning `undefined` as if it succeeded.
      throw errorFromFailureResponse(200, body)
    }
    throw malformedResponseError(response.status, body)
  }

  return (body as { data: T }).data
}

/** Perform a GET and return its `data`. */
export function apiGet<T>(
  path: string,
  query?: QueryParams,
  options?: RequestOptions,
): Promise<T> {
  return apiRequest<T>(path, { method: 'GET' }, query, options)
}

/** Perform a POST, optionally with a JSON body, and return its `data`. */
export function apiPost<T>(
  path: string,
  options: { body?: unknown; query?: QueryParams; signal?: AbortSignal } = {},
): Promise<T> {
  return apiRequest<T>(
    path,
    { method: 'POST', body: options.body },
    options.query,
    { signal: options.signal },
  )
}

/** Perform a PUT with a JSON body and return its `data`. */
export function apiPut<T>(
  path: string,
  options: { body?: unknown; query?: QueryParams; signal?: AbortSignal } = {},
): Promise<T> {
  return apiRequest<T>(
    path,
    { method: 'PUT', body: options.body },
    options.query,
    { signal: options.signal },
  )
}

/** The timeout the client applies when none is configured. */
export const CLIENT_FALLBACK_MESSAGE = GENERIC_MESSAGE
