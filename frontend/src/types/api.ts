/**
 * The shared REST contract: the response envelope, the error model and the
 * pagination block (M15.5/M15.6/M15.7).
 *
 * Every M13 endpoint answers with one of exactly two shapes, and both are
 * described here so no service or page has to restate them:
 *
 *     { "success": true,  "message": "...", "data": {...} }
 *     { "success": false, "message": "...", "errors": [{ "field", "code" }] }
 *
 * One important exception lives in this module too. FastAPI renders its *own*
 * request-validation failures as `422 { "detail": [...] }` rather than through the
 * project envelope (see `app/api/common/errors.py`), so {@link ValidationDetail}
 * models that third shape. A client that only knew about two shapes would show
 * "unexpected response" for the single most common client-side mistake — a
 * malformed query parameter.
 */

/** The `data` of a successful response. */
export interface ApiSuccess<T> {
  readonly success: true
  readonly message: string
  readonly data: T
}

/** One field-level failure inside an error envelope. */
export interface ApiFieldError {
  /** Which request field or validation rule failed. */
  readonly field: string
  /** A stable, machine-readable code. Branch on this, not on `message`. */
  readonly code: string
}

/** A failure rendered in the project envelope. */
export interface ApiFailure {
  readonly success: false
  readonly message: string
  readonly errors: readonly ApiFieldError[]
}

/** The two shapes a NetWatch API response can take. */
export type ApiEnvelope<T> = ApiSuccess<T> | ApiFailure

/** One entry of FastAPI's own `422` request-validation body. */
export interface ValidationDetail {
  readonly loc: readonly (string | number)[]
  readonly msg: string
  readonly type: string
}

/** The body FastAPI returns for a `422` that bypassed the project envelope. */
export interface ValidationErrorBody {
  readonly detail: readonly ValidationDetail[]
}

/**
 * The machine-readable error codes this frontend branches on.
 *
 * Mirrors `app/api/common/envelope.py:ErrorCode`, minus the codes no screen reads.
 * The rule for inclusion is "does this change what is rendered, or how a failure
 * is worded?" — a refused capture needs its own sentence and an adapter that is
 * down needs its own control state, while a generic status covers the rest.
 *
 * The **spelling is the backend's**, character for character, because the code is
 * what a page branches on: a typo here would not fail loudly, it would quietly
 * fall through to the generic message.
 */
export const ErrorCode = {
  /** The request itself was malformed (400). */
  INVALID_REQUEST: 'INVALID_REQUEST',
  /** A query filter could not be honoured; `field` names it (400). */
  INVALID_FILTER: 'INVALID_FILTER',
  /** A generic "no such resource" (404). */
  NOT_FOUND: 'NOT_FOUND',
  /** The request conflicts with current state, e.g. an illegal transition (409). */
  CONFLICT: 'CONFLICT',
  /** An alert lifecycle move the transition table forbids (409). */
  INVALID_TRANSITION: 'INVALID_TRANSITION',
  /** A value that is not a lifecycle state at all (400). */
  INVALID_LIFECYCLE: 'INVALID_LIFECYCLE',
  /** A settings value that failed its own declaration (400). */
  INVALID_SETTING: 'INVALID_SETTING',
  /** A readable but non-writable setting key (409). */
  IMMUTABLE_SETTING: 'IMMUTABLE_SETTING',
  /** Exposed but not implemented by this milestone (501). */
  FEATURE_NOT_IMPLEMENTED: 'FEATURE_NOT_IMPLEMENTED',
  /** A dependency that is switched off or unreachable (503). */
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
  /** An unanticipated server failure, rendered opaquely (500). */
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  /** A method the route does not serve (405). */
  METHOD_NOT_ALLOWED: 'METHOD_NOT_ALLOWED',

  // ── A resource that has gone ──────────────────────────────────────────────
  // Spelled per resource, because the sentence a page shows differs by resource:
  // a finding older than M10's retention cap is "no longer retained", while a
  // device that has been forgotten is simply "no longer known".

  PACKET_NOT_FOUND: 'PACKET_NOT_FOUND',
  DEVICE_NOT_FOUND: 'DEVICE_NOT_FOUND',
  CONNECTION_NOT_FOUND: 'CONNECTION_NOT_FOUND',
  /** A finding that has aged out of M10's bounded history (M10.19). */
  FINDING_NOT_FOUND: 'FINDING_NOT_FOUND',
  ALERT_NOT_FOUND: 'ALERT_NOT_FOUND',
  EVIDENCE_NOT_FOUND: 'EVIDENCE_NOT_FOUND',
  INCIDENT_NOT_FOUND: 'INCIDENT_NOT_FOUND',
  REPORT_NOT_FOUND: 'REPORT_NOT_FOUND',
  NOTIFICATION_NOT_FOUND: 'NOTIFICATION_NOT_FOUND',
  SETTING_NOT_FOUND: 'SETTING_NOT_FOUND',

  // ── Capture and interfaces (M4/M13.6/M13.7) ──────────────────────────────

  /** A start was refused because a session is already running (409). */
  CAPTURE_ALREADY_RUNNING: 'CAPTURE_ALREADY_RUNNING',
  /** A stop was refused because no session is running (409). */
  CAPTURE_NOT_RUNNING: 'CAPTURE_NOT_RUNNING',
  /** A start was refused because no interface has been chosen (409). */
  CAPTURE_NO_INTERFACE: 'CAPTURE_NO_INTERFACE',
  CAPTURE_START_FAILED: 'CAPTURE_START_FAILED',
  CAPTURE_STOP_FAILED: 'CAPTURE_STOP_FAILED',
  /** No interface chosen yet — a precondition to fix, not a missing row (M13.6). */
  NO_INTERFACE_SELECTED: 'NO_INTERFACE_SELECTED',
  INTERFACE_NOT_FOUND: 'INTERFACE_NOT_FOUND',
  /** The adapter exists but is down, so capture cannot use it (M13.7). */
  INTERFACE_UNAVAILABLE: 'INTERFACE_UNAVAILABLE',
  EMPTY_INTERFACE_NAME: 'EMPTY_INTERFACE_NAME',
} as const

/** One of the codes in {@link ErrorCode}. */
export type ErrorCodeValue = (typeof ErrorCode)[keyof typeof ErrorCode]

/**
 * The pagination block carried by every collection payload (M13.24).
 *
 * `limit` is `null` on the endpoints that do not use the shared window (the M11
 * alert listing is the one such payload), and `total`/`has_more` are absent where
 * the store cannot count without materialising the match set. Both absences are
 * meaningful rather than missing values, so both are optional and neither is
 * defaulted here — a client that assumed `total = 0` would render "no results"
 * for a page that simply cannot be counted.
 */
export interface PageMeta {
  /** How many items this page holds. */
  readonly count: number
  /** Maximum items the page was allowed to hold. */
  readonly limit?: number | null
  /** Items skipped before this page. */
  readonly offset: number
  /** Items matching overall, when the store can count them. */
  readonly total?: number | null
  /** Whether a further page may hold more items. */
  readonly has_more?: boolean | null
}

/** A collection payload: its page block plus its rows under a resource key. */
export type Paged<TKey extends string, TRow> = PageMeta & {
  readonly [K in TKey]: readonly TRow[]
}

/** Narrow an unknown envelope to its success branch. */
export function isApiSuccess<T>(envelope: ApiEnvelope<T>): envelope is ApiSuccess<T> {
  return envelope.success === true
}

/**
 * Return True when `value` looks like a `422` request-validation body.
 *
 * Used by the HTTP client to tell FastAPI's own validation shape apart from the
 * project envelope, so a malformed query parameter is reported as a field error
 * rather than as an unknown response.
 */
export function isValidationErrorBody(value: unknown): value is ValidationErrorBody {
  if (typeof value !== 'object' || value === null) return false
  const detail = (value as { detail?: unknown }).detail
  return Array.isArray(detail)
}
