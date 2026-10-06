/**
 * The frontend's API error model (M15.7).
 *
 * One error type for every way a request can fail, so a page never has to know
 * whether a failure came from `fetch`, from an HTTP status, or from an error
 * envelope. A page asks an {@link ApiError} for its `kind` and its `userMessage`
 * and renders those.
 *
 * Two rules this module exists to enforce:
 *
 * * **A backend stack trace never reaches a screen.** The backend already refuses
 *   to send one (M13.30) — a `500` body carries a constant sentence. But a
 *   `fetch` rejection can carry the browser's own text, which names a URL, and
 *   that must not be rendered either. {@link ApiError.userMessage} is therefore
 *   always a sentence this module produced; the raw cause is kept for the console
 *   and never displayed.
 * * **Every documented status maps to a distinct message.** A `409` on an alert
 *   transition and a `409` on an immutable setting are different problems for the
 *   operator even though they share a status, which is why the *code* — not just
 *   the status — decides the message when one is present.
 */

import type { ApiFieldError } from '@/types'

/**
 * How a request failed, at the level a page cares about.
 *
 * Deliberately coarse: a page branches on "can I show the user their mistake?" or
 * "should I offer a retry?", not on the difference between a 502 and a 503.
 */
export type ApiErrorKind =
  /** The request never reached the server (`fetch` rejected). */
  | 'network'
  /** The request was aborted by our own timeout. */
  | 'timeout'
  /** A request parameter or body was rejected (400, 422). */
  | 'validation'
  /** The resource does not exist (404). */
  | 'not_found'
  /** The request conflicts with current state (409). */
  | 'conflict'
  /** The endpoint exists but this milestone does not implement it (501). */
  | 'not_implemented'
  /** The server failed (5xx other than 501 and 503). */
  | 'server'
  /** A dependency is switched off or unreachable (503). */
  | 'unavailable'
  /** Anything else, including a response that was not in the documented shape. */
  | 'unknown'

/** Formats one field-level failure as `field: code` for a details list. */
function describeField(error: ApiFieldError): string {
  return error.field ? `${error.field}: ${error.code}` : error.code
}

/** Map an HTTP status onto the kind a page branches on. */
export function kindForStatus(status: number): ApiErrorKind {
  if (status === 400 || status === 422) return 'validation'
  if (status === 404) return 'not_found'
  if (status === 409) return 'conflict'
  if (status === 501) return 'not_implemented'
  if (status === 503) return 'unavailable'
  if (status >= 500) return 'server'
  if (status >= 400) return 'validation'
  return 'unknown'
}

/** The message shown when the failure cannot be described more precisely. */
export const GENERIC_MESSAGE = 'The request could not be completed.'

/** The message shown when the server cannot be reached at all. */
export const NETWORK_MESSAGE =
  'Cannot reach the NetWatch backend. Check that it is running and that the API base URL is correct.'

/** The message shown when the request outlived the configured timeout. */
export const TIMEOUT_MESSAGE =
  'The NetWatch backend did not respond in time. It may still be starting up.'

/** The message shown for `501`, which is a milestone boundary and not a fault. */
export const NOT_IMPLEMENTED_MESSAGE =
  'This feature is not implemented in the current backend. It is owned by a later milestone.'

/**
 * Messages for conflict codes, which are the ones a page must word precisely.
 *
 * A `409` is almost always the result of an action the *transition tables* refuse,
 * so the message says what was refused rather than "conflict". The backend's own
 * sentence is more specific still and is preferred when it arrives — this table is
 * the fallback for when it does not.
 */
const CONFLICT_MESSAGES: Readonly<Record<string, string>> = {
  INVALID_TRANSITION:
    'That lifecycle change is not allowed from the current state. Reloading will show the actions that are.',
  INVALID_LIFECYCLE: 'That is not a valid lifecycle state.',
  IMMUTABLE_SETTING: 'That setting is read-only and cannot be changed through this API.',
  CONFLICT: 'The request conflicts with the current state of the resource.',
}

/** Messages for validation codes. */
const VALIDATION_MESSAGES: Readonly<Record<string, string>> = {
  INVALID_FILTER: 'A filter value was rejected. Adjust the filters and try again.',
  INVALID_REQUEST: 'The request was not understood by the backend.',
  INVALID_SETTING: 'A setting value was rejected by the backend.',
}

/**
 * Compare an abort reason without depending on `DOMException` being defined.
 *
 * The abort reason is a `DOMException` with `name === 'AbortError'` in a browser
 * and a plain `Error` in a test environment, so the name is compared rather than
 * the constructor.
 */
function isAbortError(cause: unknown): boolean {
  return (
    typeof cause === 'object' &&
    cause !== null &&
    'name' in cause &&
    (cause as { name?: unknown }).name === 'AbortError'
  )
}

/** Options accepted when constructing an {@link ApiError}. */
export interface ApiErrorOptions {
  readonly kind: ApiErrorKind
  readonly status?: number
  readonly code?: string
  readonly field?: string
  readonly fields?: readonly ApiFieldError[]
  readonly message?: string
  readonly cause?: unknown
}

/**
 * One failed API request.
 *
 * `message` is always a sentence safe to render; `cause` is always the raw
 * failure, for the console only. Keeping both is what lets a page show something
 * useful while a developer still sees the real reason.
 */
export class ApiError extends Error {
  /** How the request failed, at the level a page branches on. */
  readonly kind: ApiErrorKind
  /** The HTTP status, when a response was received. */
  readonly status: number | undefined
  /** The machine-readable code from the envelope, when one was present. */
  readonly code: string | undefined
  /** Which field failed, when the backend named one. */
  readonly field: string | undefined
  /** Every field-level failure, when the backend named more than one. */
  readonly fields: readonly ApiFieldError[]
  /** The raw failure, for the console. Never rendered. */
  readonly cause: unknown

  constructor(options: ApiErrorOptions) {
    super(options.message ?? GENERIC_MESSAGE)
    this.name = 'ApiError'
    this.kind = options.kind
    this.status = options.status
    this.code = options.code
    this.field = options.field
    this.fields = options.fields ?? []
    this.cause = options.cause
  }

  /** True when retrying the same request could plausibly succeed. */
  get isRetryable(): boolean {
    return (
      this.kind === 'network' ||
      this.kind === 'timeout' ||
      this.kind === 'server' ||
      this.kind === 'unavailable'
    )
  }

  /** True when the failure is the caller's own input and needs no retry button. */
  get isUserFixable(): boolean {
    return this.kind === 'validation' || this.kind === 'conflict'
  }

  /**
   * The sentence to render.
   *
   * The backend's own `message` is used when it was supplied, because it names
   * the field that failed more precisely than a generic sentence can — the backend
   * is the only party that knows *which* filter was rejected. Only when no
   * message arrived does the kind decide.
   */
  get userMessage(): string {
    if (this.message && this.message !== GENERIC_MESSAGE) return this.message
    return messageForKind(this.kind)
  }

  /** Every field-level failure as `field: code`, for a details list. */
  get fieldDetails(): readonly string[] {
    return this.fields.map(describeField)
  }
}

/** The default sentence for a kind, used when the backend supplied none. */
export function messageForKind(kind: ApiErrorKind): string {
  switch (kind) {
    case 'network':
      return NETWORK_MESSAGE
    case 'timeout':
      return TIMEOUT_MESSAGE
    case 'validation':
      return 'The backend rejected part of this request. Check the values and try again.'
    case 'not_found':
      return 'That resource no longer exists on the backend.'
    case 'conflict':
      return CONFLICT_MESSAGES.CONFLICT ?? GENERIC_MESSAGE
    case 'not_implemented':
      return NOT_IMPLEMENTED_MESSAGE
    case 'server':
      return 'The NetWatch backend failed while handling this request. Nothing was changed.'
    case 'unavailable':
      return 'The NetWatch backend is temporarily unavailable.'
    default:
      return GENERIC_MESSAGE
  }
}

/**
 * Choose the most specific sentence for a status and an optional code.
 *
 * The code wins over the status when it is one this module knows: a
 * `409 INVALID_TRANSITION` and a `409 IMMUTABLE_SETTING` are the same status and
 * different problems, and only the code distinguishes them.
 */
export function messageFor(status: number, code?: string): string {
  if (code && CONFLICT_MESSAGES[code]) return CONFLICT_MESSAGES[code]
  if (code && VALIDATION_MESSAGES[code]) return VALIDATION_MESSAGES[code]
  if (code === 'FEATURE_NOT_IMPLEMENTED') return NOT_IMPLEMENTED_MESSAGE
  return messageForKind(kindForStatus(status))
}

/** Build the error for a request that never reached the server. */
export function networkError(cause: unknown): ApiError {
  return new ApiError({
    kind: isAbortError(cause) ? 'timeout' : 'network',
    cause,
  })
}

/** Build the error for a response that was not in the documented shape. */
export function malformedResponseError(status: number, cause?: unknown): ApiError {
  return new ApiError({
    kind: 'unknown',
    status,
    message: 'The backend returned a response in an unexpected format.',
    cause,
  })
}

/** Return True when `value` is an {@link ApiError}. */
export function isApiError(value: unknown): value is ApiError {
  return value instanceof ApiError
}

/**
 * Coerce any thrown value into an {@link ApiError}.
 *
 * Every service already rejects with an `ApiError`, so in a correctly wired call
 * this returns its argument unchanged. It exists for the two places where that
 * cannot be assumed — a hook whose `catch` sees whatever a promise rejected with,
 * and a call site bug such as a misspelled function — and its purpose is to keep
 * one invariant: **the error a component receives is always an `ApiError`**, so
 * no component has to narrow before it branches on `kind`.
 *
 * `cause` is preserved, because the console still wants the original.
 */
export function toApiError(value: unknown): ApiError {
  if (isApiError(value)) return value
  return new ApiError({ kind: 'unknown', cause: value })
}

/**
 * Return a renderable sentence for any thrown value.
 *
 * The fallback exists because a component's `catch` may receive something that is
 * not an `ApiError` — a bug in a render path, or a rejection from a non-API
 * promise. It must still show *something*, and it must not show the raw value.
 */
export function toUserMessage(value: unknown): string {
  if (isApiError(value)) return value.userMessage
  return GENERIC_MESSAGE
}
