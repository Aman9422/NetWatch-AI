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

/**
 * Translate a failed response into an {@link ApiError}, reading its body.
 *
 * Shared by every request this client makes — the JSON ones and the file ones —
 * so a download's `404` is classified and worded exactly like a JSON call's, and
 * a caller never has to care which kind of request it made.
 *
 * The order matters, because the three shapes are told apart by content rather
 * than by status: FastAPI's own `422` detail list is recognised first (it is the
 * one failure the backend deliberately leaves outside the envelope), then the
 * project's error envelope, then a body that could not be read at all, and
 * anything else is reported as unexpected rather than guessed at.
 */
async function errorForFailedResponse(response: Response): Promise<ApiError> {
  const body = await readJson(response)
  // A 422 from FastAPI's own validation handler is the one failure that does
  // not use the project envelope, so it is recognised by its shape.
  if (isValidationErrorBody(body)) {
    const fields = body.detail.map(fieldErrorFromValidation)
    return new ApiError({
      kind: 'validation',
      status: response.status,
      code: fields[0]?.code ?? 'INVALID_REQUEST',
      field: fields[0]?.field,
      fields,
      message:
        'The backend rejected this request’s parameters. Adjust the highlighted values and try again.',
    })
  }
  if (isFailureEnvelope(body)) return errorFromFailureResponse(response.status, body)
  if (body === undefined) return errorFromEmptyFailure(response.status)
  return errorFromUnexpectedBody(response.status, body)
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

  if (!response.ok) throw await errorForFailedResponse(response)

  const body = await readJson(response)

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

/**
 * Options for a write.
 *
 * `timeoutMs` is accepted here because one write is genuinely slower than the
 * rest: generating a report runs several aggregate queries and renders a document
 * (M17.12), so it is given a longer budget than the fifteen seconds a read gets
 * rather than being allowed to time out mid-render.
 */
export interface WriteRequestOptions extends RequestOptions {
  /** Value serialised as JSON. `undefined` sends no body. */
  readonly body?: unknown
  /** Query parameters for this request. */
  readonly query?: QueryParams
}

/** Perform a POST, optionally with a JSON body, and return its `data`. */
export function apiPost<T>(
  path: string,
  options: WriteRequestOptions = {},
): Promise<T> {
  return apiRequest<T>(
    path,
    { method: 'POST', body: options.body },
    options.query,
    { signal: options.signal, timeoutMs: options.timeoutMs },
  )
}

/** Perform a PUT with a JSON body and return its `data`. */
export function apiPut<T>(
  path: string,
  options: WriteRequestOptions = {},
): Promise<T> {
  return apiRequest<T>(
    path,
    { method: 'PUT', body: options.body },
    options.query,
    { signal: options.signal, timeoutMs: options.timeoutMs },
  )
}

// ── Files ────────────────────────────────────────────────────────────────────

/** A file the backend served, ready to be handed to the browser (M17.11). */
export interface DownloadedFile {
  /** The artifact's bytes. */
  readonly blob: Blob
  /**
   * The filename the backend declared, or {@link FALLBACK_DOWNLOAD_NAME}.
   *
   * It comes from `Content-Disposition` and is the artifact's *own* name, which
   * the reporting layer has already reduced to `[A-Za-z0-9-]` — so it is safe to
   * write to a filesystem and, deliberately, it is not the server's path.
   */
  readonly filename: string
  /** The media type the backend served, e.g. `application/pdf`. */
  readonly contentType: string
}

/** What a download is named when the backend declared no usable filename. */
export const FALLBACK_DOWNLOAD_NAME = 'download'

/** What an untyped download is labelled as. */
export const DEFAULT_BINARY_MEDIA_TYPE = 'application/octet-stream'

/**
 * Read a filename out of a `Content-Disposition` header.
 *
 * Both forms a server may send are understood: the plain `filename="..."` and the
 * RFC 5987 `filename*=UTF-8''...` extension, which wins when the two disagree
 * because it is the only one that can carry a non-ASCII name. Surrounding quotes
 * are stripped, and a name that is blank afterwards is treated as absent — a
 * malformed header yields `null` so the caller falls back to a known name rather
 * than saving a file called `""`.
 */
export function filenameFromDisposition(header: string | null): string | null {
  if (header === null || header === '') return null

  const extended = /filename\*\s*=\s*([^;]+)/i.exec(header)
  if (extended?.[1] !== undefined) {
    // `UTF-8''name` — the charset and language come first, separated by `''`.
    const raw = extended[1].trim().replace(/^["']|["']$/g, '')
    const separator = raw.indexOf("''")
    const encoded = separator === -1 ? raw : raw.slice(separator + 2)
    try {
      const decoded = decodeURIComponent(encoded).trim()
      if (decoded !== '') return decoded
    } catch {
      // A malformed percent-escape is no reason to fail a download that otherwise
      // succeeded; fall through to the plain form below.
    }
  }

  const plain = /filename\s*=\s*([^;]+)/i.exec(header)
  if (plain?.[1] === undefined) return null
  const name = plain[1].trim().replace(/^["']|["']$/g, '').trim()
  return name === '' ? null : name
}

/**
 * Perform a GET for a file and return it rather than the envelope's `data`.
 *
 * A few endpoints serve a document instead of JSON (M17.11), and unwrapping one
 * into `data` would be meaningless: the payload *is* the response. Everything
 * else is shared with {@link apiRequest} — the base URL, the timeout, the abort
 * signal and the error translation — so a download's `404` reaches the caller as
 * the same {@link ApiError} a JSON call's would, and a page needs no second error
 * path.
 *
 * The body is deliberately not parsed. A file's bytes are opaque to this module;
 * only the headers are read, and what to do with the bytes is the browser's
 * problem rather than the transport's.
 *
 * @param path Resource path beginning `/`, e.g. `/reports/7/download`.
 * @param options Timeout and abort signal.
 */
export async function apiDownload(
  path: string,
  options: RequestOptions = {},
): Promise<DownloadedFile> {
  const url = buildUrl(path)
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
    response = await fetch(url, {
      method: 'GET',
      // Anything is acceptable: the endpoint declares what it serves, and asking
      // for JSON here would be a promise the route cannot keep.
      headers: { Accept: '*/*' },
      signal: controller.signal,
    })
  } catch (cause) {
    throw networkError(cause)
  } finally {
    clearTimeout(timer)
    externalSignal?.removeEventListener('abort', onExternalAbort)
  }

  if (!response.ok) throw await errorForFailedResponse(response)

  const contentType = response.headers.get('content-type') ?? DEFAULT_BINARY_MEDIA_TYPE
  const filename =
    filenameFromDisposition(response.headers.get('content-disposition')) ??
    FALLBACK_DOWNLOAD_NAME
  return { blob: await response.blob(), filename, contentType }
}

/** The timeout the client applies when none is configured. */
export const CLIENT_FALLBACK_MESSAGE = GENERIC_MESSAGE
