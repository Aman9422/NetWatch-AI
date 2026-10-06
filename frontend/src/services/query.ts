/**
 * Filter serialisation helpers (M15.4).
 *
 * Every list endpoint takes the same kind of input: a typed filter object whose
 * fields are all optional, where "absent" means "no filter". The client's
 * `QueryParams` is a `Record`, and a TypeScript `interface` is deliberately *not*
 * assignable to a `Record` — it has no implicit index signature — so a typed
 * filter cannot be handed to the client directly.
 *
 * That is a feature rather than an obstacle: it forces this one conversion to
 * happen in one place, and that place is where the two rules that make filters
 * safe are enforced:
 *
 * * **Absent means absent.** An `undefined` or `null` field is dropped, never
 *   serialised as the string `"null"`. The backend validates filters strictly
 *   (M13.25), so sending one would turn "no filter" into a `400`.
 * * **Only scalars survive.** A value of an unexpected shape is dropped rather
 *   than coerced. A filter that silently became `"[object Object]"` would be a
 *   `400` at best and a wrong result set at worst.
 */

import type { QueryParams, QueryValue } from './client'

/** The default page size a listing request asks for. */
export const DEFAULT_PAGE_LIMIT = 50

/** The largest page size the backend accepts, kept in step with M13.24. */
export const MAX_PAGE_LIMIT = 200

/** A page window: how many rows, and how many to skip. */
export interface PageWindow {
  readonly limit?: number
  readonly offset?: number
}

/** Return True when `value` can be serialised as a scalar query value. */
function isScalar(value: unknown): value is string | number | boolean {
  return (
    typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
  )
}

/**
 * Return True when `value` may appear in a *repeated* query parameter.
 *
 * Narrower than {@link isScalar}: `QueryValue` allows an array only of
 * `string | number`, because a repeated parameter is how the backend reads a
 * `list[str]` filter and no such filter is a list of booleans. Accepting one here
 * would build `?flag=true&flag=false`, which the backend does not declare.
 */
function isArrayScalar(value: unknown): value is string | number {
  return typeof value === 'string' || typeof value === 'number'
}

/**
 * Convert a typed filter object into the client's `QueryParams`.
 *
 * An array field is expanded and each surviving entry is kept, which is how the
 * alert listing's repeated `status` parameter is expressed. An array whose
 * entries are all non-scalars is dropped entirely rather than sent empty.
 */
export function toQueryParams(source: object): QueryParams {
  const result: Record<string, QueryValue> = {}
  for (const [key, value] of Object.entries(source as Record<string, unknown>)) {
    if (value === undefined || value === null) continue
    if (isScalar(value)) {
      result[key] = value
      continue
    }
    if (Array.isArray(value)) {
      const scalars = value.filter(isArrayScalar)
      if (scalars.length > 0) result[key] = scalars
      continue
    }
    // Anything else — a nested object, a function — is not a filter the backend
    // understands, so it is omitted rather than coerced into nonsense.
  }
  return result
}

/**
 * Bound a requested page size to what the backend accepts.
 *
 * A limit above {@link MAX_PAGE_LIMIT} is clamped rather than rejected: the
 * caller asked for "as much as possible", and the backend's own ceiling is the
 * honest answer. A limit that is missing, non-finite or not positive falls back
 * to {@link DEFAULT_PAGE_LIMIT}, because a page size of `0` would render an empty
 * screen that looks like "no data" when nothing had been fetched.
 */
export function clampLimit(value: number | undefined, fallback = DEFAULT_PAGE_LIMIT): number {
  if (value === undefined || !Number.isFinite(value) || value < 1) return fallback
  return Math.min(Math.round(value), MAX_PAGE_LIMIT)
}

/** Bound an offset to a non-negative whole number. */
export function clampOffset(value: number | undefined): number {
  if (value === undefined || !Number.isFinite(value) || value < 0) return 0
  return Math.round(value)
}

/** Merge a page window into a filter object as serialised parameters. */
export function withPageWindow(
  filter: object,
  window: PageWindow | undefined,
): QueryParams {
  return {
    ...toQueryParams(filter),
    limit: clampLimit(window?.limit),
    offset: clampOffset(window?.offset),
  }
}
