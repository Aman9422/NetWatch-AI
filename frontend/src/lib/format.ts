/**
 * Display formatting (M15.6).
 *
 * Every number and instant an operator reads is formatted here, so two pages
 * cannot disagree about what a byte count looks like — and, more importantly, so
 * a value the backend did not supply is rendered as **unknown** rather than as a
 * zero. That distinction runs through the whole milestone: `null` means "the
 * backend did not report this", `0` means "it reported none", and a formatter
 * that collapsed the two would turn an unavailable service into a calm report of
 * nothing happening.
 *
 * Timestamps arrive in two forms and both are handled explicitly:
 *
 * * ISO-8601 UTC strings, which M13.26 emits for anything a client displays;
 * * epoch **seconds**, which is what M12 reasons in and what a few payloads
 *   (incidents, reports, notifications) carry beside the ISO form.
 *
 * Nothing here parses a naive timestamp as local time: `Date.parse` on an ISO
 * string without a zone is treated as UTC by the specification, and every instant
 * this API sends is either zoned or epoch, so a displayed time is always the
 * operator's own wall clock derived from a known instant.
 */

/** What a missing value renders as. One constant, so no page invents another. */
export const UNKNOWN_TEXT = '—'

/** Timestamp of an instant, in the viewer's locale. */
export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return UNKNOWN_TEXT
  const parsed = Date.parse(iso)
  if (Number.isNaN(parsed)) return UNKNOWN_TEXT
  return new Date(parsed).toLocaleString()
}

/** Timestamp of an epoch-seconds instant, in the viewer's locale. */
export function formatEpochSeconds(epochSeconds: number | null | undefined): string {
  if (typeof epochSeconds !== 'number' || !Number.isFinite(epochSeconds)) {
    return UNKNOWN_TEXT
  }
  return new Date(epochSeconds * 1000).toLocaleString()
}

/** Just the time of day — for a dense table where the date is known from context. */
export function formatTimeOfDay(iso: string | null | undefined): string {
  if (!iso) return UNKNOWN_TEXT
  const parsed = Date.parse(iso)
  if (Number.isNaN(parsed)) return UNKNOWN_TEXT
  return new Date(parsed).toLocaleTimeString()
}

/**
 * How long ago an instant was, from an ISO string.
 *
 * `now` is injectable so a test asserts a stable answer instead of racing the
 * clock.
 */
export function formatRelative(
  iso: string | null | undefined,
  now: number = Date.now(),
): string {
  if (!iso) return UNKNOWN_TEXT
  const parsed = Date.parse(iso)
  if (Number.isNaN(parsed)) return UNKNOWN_TEXT
  return formatElapsed((now - parsed) / 1000)
}

/** How long ago an epoch-seconds instant was. */
export function formatEpochRelative(
  epochSeconds: number | null | undefined,
  now: number = Date.now(),
): string {
  if (typeof epochSeconds !== 'number' || !Number.isFinite(epochSeconds)) {
    return UNKNOWN_TEXT
  }
  return formatElapsed(now / 1000 - epochSeconds)
}

/**
 * Render an elapsed duration in seconds as a short phrase.
 *
 * A negative delta is reported as "just now" rather than as a negative age: clock
 * skew between the browser and the backend is real, and "-3s ago" is noise.
 */
export function formatElapsed(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 1) return 'just now'
  if (seconds < 60) return `${Math.floor(seconds)}s ago`
  const minutes = seconds / 60
  if (minutes < 60) return `${Math.floor(minutes)}m ago`
  const hours = minutes / 60
  if (hours < 24) return `${Math.floor(hours)}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

/**
 * Render a duration in seconds as `1h 04m`-style text.
 *
 * `null` renders as unknown, because M13.22 reports `uptime_seconds: null` when
 * startup was never recorded — which is not the same as being up for zero
 * seconds, and must not be displayed as one.
 */
export function formatDurationSeconds(seconds: number | null | undefined): string {
  if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds < 0) {
    return UNKNOWN_TEXT
  }
  const whole = Math.floor(seconds)
  const days = Math.floor(whole / 86_400)
  const hours = Math.floor((whole % 86_400) / 3_600)
  const minutes = Math.floor((whole % 3_600) / 60)
  const secs = whole % 60
  if (days > 0) return `${days}d ${String(hours).padStart(2, '0')}h`
  if (hours > 0) return `${hours}h ${String(minutes).padStart(2, '0')}m`
  if (minutes > 0) return `${minutes}m ${String(secs).padStart(2, '0')}s`
  return `${secs}s`
}

/** A whole number with thousands separators. */
export function formatCount(value: number | null | undefined): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return UNKNOWN_TEXT
  return Math.round(value).toLocaleString()
}

/** Byte size in binary units, e.g. `1.4 MB`. */
export function formatBytes(bytes: number | null | undefined): string {
  if (typeof bytes !== 'number' || !Number.isFinite(bytes)) return UNKNOWN_TEXT
  return formatScaled(bytes, ['B', 'KB', 'MB', 'GB', 'TB', 'PB'], 1024)
}

/** A per-second count of items, e.g. `1.2 K/s`. */
export function formatItemsPerSecond(rate: number | null | undefined): string {
  if (typeof rate !== 'number' || !Number.isFinite(rate)) return UNKNOWN_TEXT
  return `${formatScaled(rate, ['', 'K', 'M', 'G'], 1000)}/s`
}

/** A per-second size, e.g. `848 KB/s`. */
export function formatBytesPerSecond(rate: number | null | undefined): string {
  if (typeof rate !== 'number' || !Number.isFinite(rate)) return UNKNOWN_TEXT
  const scaled = formatScaled(rate, ['B', 'KB', 'MB', 'GB', 'TB'], 1024)
  return `${scaled}/s`
}

/** A bit rate in decimal units, e.g. `6.8 Mbps` — the unit a link is sold in. */
export function formatBitsPerSecond(bits: number | null | undefined): string {
  if (typeof bits !== 'number' || !Number.isFinite(bits)) return UNKNOWN_TEXT
  if (bits < 1000) return `${Math.round(bits)} bps`
  const units = ['Kbps', 'Mbps', 'Gbps', 'Tbps']
  let value = bits / 1000
  let index = 0
  while (value >= 1000 && index < units.length - 1) {
    value /= 1000
    index += 1
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[index]}`
}

/**
 * A `0..100` percentage the backend already computed.
 *
 * The value is not re-derived: M6 supplies `percentage`, and dividing counts in
 * React would be the second implementation M15.9 forbids.
 */
export function formatPercentage(value: number | null | undefined): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return UNKNOWN_TEXT
  return `${value.toFixed(value < 10 ? 1 : 0)}%`
}

/**
 * A `0..1` confidence as a percentage.
 *
 * Documented as a ratio throughout, so the conversion happens once, here, rather
 * than at each call site — where a page could accidentally render `0.72` as
 * "0.72%" or `72%` for `72`.
 */
export function formatConfidence(value: number | null | undefined): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return UNKNOWN_TEXT
  const bounded = Math.max(0, Math.min(1, value))
  return `${Math.round(bounded * 100)}%`
}

/** A bounded `0..100` risk score, with no unit. */
export function formatRiskScore(value: number | null | undefined): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return UNKNOWN_TEXT
  const bounded = Math.max(0, Math.min(100, value))
  return String(Math.round(bounded))
}

/** Scale `value` down through `units`, keeping one decimal below ten. */
function formatScaled(value: number, units: readonly string[], base: number): string {
  const negative = value < 0
  let scaled = Math.abs(value)
  let index = 0
  while (scaled >= base && index < units.length - 1) {
    scaled /= base
    index += 1
  }
  const rendered = index === 0 && Number.isInteger(scaled)
    ? String(scaled)
    : scaled.toFixed(scaled < 10 ? 1 : 0)
  const unit = units[index]
  const body = unit === '' ? rendered : `${rendered} ${unit}`
  return negative ? `-${body}` : body
}

/** A short, human label for a record title, truncating rather than overflowing. */
export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text
  return `${text.slice(0, Math.max(0, maxLength - 1))}…`
}

/** Join a host and a port the way an operator reads an endpoint. */
export function formatEndpoint(ip: string | null, port: number | null): string {
  if (!ip) return UNKNOWN_TEXT
  return port === null || port === undefined ? ip : `${ip}:${port}`
}
