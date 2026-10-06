/**
 * Frontend runtime configuration (M15.3).
 *
 * Vite inlines `import.meta.env` at build time, so the values here are read once
 * and never change while the bundle is running. This module exists so that fact
 * is expressed in exactly one place: every other module asks for a URL instead of
 * touching `import.meta.env`, which means a typo in a variable name is caught in
 * one function rather than scattering `undefined` through the application.
 *
 * Two rules the defaults encode:
 *
 * * **A missing variable is not an error.** The documented local-development
 *   defaults are applied, so `npm run dev` against a backend on the documented
 *   port works with no `.env` file at all. Failing hard on a missing variable
 *   would make the app unstartable for the most common local case.
 * * **A trailing slash is removed.** Every service joins a base URL with a path
 *   beginning `/`, so a base URL that ends in `/` would produce `//` and a path
 *   the backend does not route.
 *
 * No secret may ever be read here: every `VITE_*` value is public (M15.37).
 */

/** The public configuration one running frontend instance uses. */
export interface FrontendEnvironment {
  /** Base URL of the versioned REST API, without a trailing slash. */
  readonly apiBaseUrl: string
  /** Base URL of the real-time channels, without a trailing slash. */
  readonly wsBaseUrl: string
  /** Milliseconds before a REST request is aborted. */
  readonly requestTimeoutMs: number
}

/** Where the backend serves the versioned REST API in local development. */
export const DEFAULT_API_BASE_URL = 'http://127.0.0.1:8000/api/v1'

/** Where the backend serves the WebSocket channels in local development. */
export const DEFAULT_WS_BASE_URL = 'ws://127.0.0.1:8000'

/** How long a REST request may take before it is aborted. */
export const DEFAULT_REQUEST_TIMEOUT_MS = 15_000

/** Lowest timeout accepted, so a mistyped `0` cannot abort every request. */
export const MIN_REQUEST_TIMEOUT_MS = 1_000

/** The `import.meta.env` keys this module understands. */
export interface EnvironmentSource {
  readonly VITE_API_BASE_URL?: string
  readonly VITE_WS_BASE_URL?: string
  readonly VITE_API_TIMEOUT_MS?: string
}

/** Remove every trailing `/` so joined paths never contain `//`. */
export function stripTrailingSlashes(value: string): string {
  return value.replace(/\/+$/, '')
}

/** Return `value` when it is a non-blank string, otherwise `undefined`. */
function nonBlank(value: string | undefined): string | undefined {
  if (typeof value !== 'string') return undefined
  const trimmed = value.trim()
  return trimmed === '' ? undefined : trimmed
}

/**
 * Parse the configured request timeout.
 *
 * A value that is missing, non-numeric, or below {@link MIN_REQUEST_TIMEOUT_MS}
 * falls back to the default rather than being honoured. A timeout of `0` would
 * abort every request the instant it was issued, which is never what the operator
 * meant, and reporting it as a startup error would be less useful than using the
 * documented default.
 */
export function parseRequestTimeout(raw: string | undefined): number {
  const text = nonBlank(raw)
  if (text === undefined) return DEFAULT_REQUEST_TIMEOUT_MS
  const parsed = Number(text)
  if (!Number.isFinite(parsed) || parsed < MIN_REQUEST_TIMEOUT_MS) {
    return DEFAULT_REQUEST_TIMEOUT_MS
  }
  return Math.round(parsed)
}

/**
 * Resolve the configuration from an environment source.
 *
 * Exported separately from {@link environment} so a test can drive it from a
 * literal object instead of mutating `import.meta.env`.
 */
export function readEnvironment(source: EnvironmentSource): FrontendEnvironment {
  const api = nonBlank(source.VITE_API_BASE_URL) ?? DEFAULT_API_BASE_URL
  const ws = nonBlank(source.VITE_WS_BASE_URL) ?? DEFAULT_WS_BASE_URL
  return {
    apiBaseUrl: stripTrailingSlashes(api),
    wsBaseUrl: stripTrailingSlashes(ws),
    requestTimeoutMs: parseRequestTimeout(source.VITE_API_TIMEOUT_MS),
  }
}

/** The configuration this running bundle uses. */
export const environment: FrontendEnvironment = readEnvironment(import.meta.env)

/**
 * Return the absolute URL of one WebSocket channel path.
 *
 * The path is supplied by the caller (`/ws/dashboard`, `/ws/packets`, …) so the
 * channel vocabulary lives in the WebSocket service rather than here.
 */
export function webSocketUrl(path: string): string {
  const suffix = path.startsWith('/') ? path : `/${path}`
  return `${environment.wsBaseUrl}${suffix}`
}
