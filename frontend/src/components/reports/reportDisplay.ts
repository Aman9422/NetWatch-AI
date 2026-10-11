/**
 * Presentation helpers for the report surface (M17).
 *
 * Two jobs, both of which exist because a report's *period* is the fact a reader
 * must be able to trust and the fact a browser will misread if left alone:
 *
 * * **Instants are rendered in UTC, never in the viewer's locale.** Every bound a
 *   report carries is a UTC calendar instant — a daily report covers a UTC day —
 *   so rendering one through `toLocaleString` would show the same stored report at
 *   two different addresses and, worse, might make a whole-day period look like it
 *   spans two. {@link formatUtcInstant} prints the stored instant and says `UTC`.
 * * **A date the operator picks is a UTC calendar day.** The custom form takes
 *   `YYYY-MM-DD`, and {@link utcDayStartIso} / {@link utcDayAfterIso} turn it into
 *   the ISO-8601 UTC bounds the API expects (M13.26). The end is converted to the
 *   *following* midnight because a reporting period is half-open (M17.5): the
 *   operator names the last day they want included, and the conversion to an
 *   exclusive bound happens here, once, rather than at each call site.
 *
 * Both conversions refuse an input the calendar does not have rather than
 * letting `Date` roll it over: `2026-02-31` is not a day, and silently reading it
 * as the 3rd of March would produce a report for a period nobody asked about.
 */

import { UNKNOWN_TEXT } from '@/lib/format'

/** A `YYYY-MM-DD` date, the only shape the custom form accepts. */
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/

/** Milliseconds in one UTC calendar day. */
const DAY_MS = 86_400_000

/**
 * Render a stored instant as its UTC calendar form, e.g. `2026-10-09 00:00 UTC`.
 *
 * The stored value is what is printed — not a local-time translation of it —
 * because the periods being compared are UTC calendar periods (M17.5).
 */
export function formatUtcInstant(iso: string | null | undefined): string {
  if (!iso) return UNKNOWN_TEXT
  const parsed = Date.parse(iso)
  if (Number.isNaN(parsed)) return UNKNOWN_TEXT
  return `${new Date(parsed).toISOString().slice(0, 16).replace('T', ' ')} UTC`
}

/**
 * Render a half-open reporting period as `start → end`.
 *
 * Both bounds are shown, because a reader comparing two daily reports needs to
 * see that they do not overlap, and the end is the *exclusive* bound the store
 * actually holds rather than a rounded-off inclusive one.
 */
export function formatReportPeriod(
  start: string | null | undefined,
  end: string | null | undefined,
): string {
  if (!start || !end) return UNKNOWN_TEXT
  return `${formatUtcInstant(start)} → ${formatUtcInstant(end)}`
}

/** Parse a `YYYY-MM-DD` day into the epoch milliseconds of its UTC midnight. */
function utcDayStartMs(value: string): number | null {
  if (!ISO_DATE.test(value)) return null
  const parsed = Date.parse(`${value}T00:00:00Z`)
  if (Number.isNaN(parsed)) return null
  // A day the calendar does not have rolls over, so the round trip is the check.
  return new Date(parsed).toISOString().slice(0, 10) === value ? parsed : null
}

/** Render epoch milliseconds as an ISO-8601 UTC string with an explicit offset. */
function isoUtc(ms: number): string {
  return new Date(ms).toISOString().replace('.000Z', '+00:00')
}

/**
 * The inclusive lower bound of one UTC calendar day, as ISO-8601 UTC.
 *
 * Returns `null` for anything that is not a real `YYYY-MM-DD` day, so a caller
 * refuses the request itself rather than sending a bound the backend would have
 * to reject.
 */
export function utcDayStartIso(value: string): string | null {
  const ms = utcDayStartMs(value)
  return ms === null ? null : isoUtc(ms)
}

/**
 * The exclusive bound that *includes* one whole UTC calendar day.
 *
 * The day after the given one at midnight UTC — which is what makes a period
 * `[start, day-after)` cover the operator's chosen last day exactly once.
 */
export function utcDayAfterIso(value: string): string | null {
  const ms = utcDayStartMs(value)
  return ms === null ? null : isoUtc(ms + DAY_MS)
}

/** The shape a custom report's bounds were resolved into, or why they were not. */
export interface CustomBounds {
  readonly since: string | null
  readonly until: string | null
  /** A sentence naming what is wrong, or `null` when the bounds are usable. */
  readonly problem: string | null
}

/**
 * Resolve the custom form's two days into the bounds the API expects.
 *
 * The check lives here rather than only in the backend because a missing or
 * backwards pair is something the operator can see and fix without a round trip —
 * and the backend would refuse it anyway (M17.6). A value the calendar cannot
 * represent is refused with the same kind of sentence, so the form never sends a
 * request it already knows will fail.
 */
export function resolveCustomBounds(from: string, to: string): CustomBounds {
  if (from === '' || to === '') {
    return {
      since: null,
      until: null,
      problem: 'A custom report needs both a first and a last day.',
    }
  }
  const since = utcDayStartIso(from)
  const until = utcDayAfterIso(to)
  if (since === null || until === null) {
    return {
      since: null,
      until: null,
      problem: 'Both days must be real calendar dates in YYYY-MM-DD form.',
    }
  }
  if (Date.parse(until) <= Date.parse(since)) {
    return {
      since: null,
      until: null,
      problem: 'The last day must not be before the first day.',
    }
  }
  return { since, until, problem: null }
}
