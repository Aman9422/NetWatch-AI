/**
 * The runtime configuration (M15.3).
 *
 * Small module, high blast radius: every request URL in the application is built
 * from `environment.apiBaseUrl`, and every channel URL from `environment.wsBaseUrl`.
 * A trailing slash here would produce `//devices` on every call, so the rules that
 * strip it and the fallbacks that keep a misconfigured value from making the app
 * unstartable are worth pinning down.
 *
 * `readEnvironment` and `parseRequestTimeout` are tested through their arguments
 * rather than by mutating `import.meta.env`: they were exported precisely so a
 * test does not have to reach into module state that Vite inlines at build time.
 */

import { describe, expect, it } from 'vitest'
import {
  DEFAULT_API_BASE_URL,
  DEFAULT_REQUEST_TIMEOUT_MS,
  DEFAULT_WS_BASE_URL,
  MIN_REQUEST_TIMEOUT_MS,
  environment,
  parseRequestTimeout,
  readEnvironment,
  stripTrailingSlashes,
  webSocketUrl,
} from '@/config/env'

describe('stripTrailingSlashes', () => {
  it('removes a single trailing slash', () => {
    expect(stripTrailingSlashes('http://127.0.0.1:8000/')).toBe('http://127.0.0.1:8000')
  })

  it('removes several, because a doubled slash is the bug being prevented', () => {
    expect(stripTrailingSlashes('http://127.0.0.1:8000///')).toBe('http://127.0.0.1:8000')
  })

  it('leaves a URL with no trailing slash alone', () => {
    expect(stripTrailingSlashes('http://127.0.0.1:8000/api/v1')).toBe(
      'http://127.0.0.1:8000/api/v1',
    )
  })
})

describe('readEnvironment', () => {
  it('falls back to the documented local defaults when nothing is configured', () => {
    // The common case: a developer runs `npm run dev` with no `.env` file, and the
    // documented backend port has to work.
    const resolved = readEnvironment({})
    expect(resolved.apiBaseUrl).toBe(DEFAULT_API_BASE_URL)
    expect(resolved.wsBaseUrl).toBe(DEFAULT_WS_BASE_URL)
    expect(resolved.requestTimeoutMs).toBe(DEFAULT_REQUEST_TIMEOUT_MS)
  })

  it('uses a configured API base URL', () => {
    expect(readEnvironment({ VITE_API_BASE_URL: 'http://10.0.0.5:9000/api/v1' }).apiBaseUrl).toBe(
      'http://10.0.0.5:9000/api/v1',
    )
  })

  it('strips a trailing slash from both base URLs', () => {
    const resolved = readEnvironment({
      VITE_API_BASE_URL: 'http://10.0.0.5:9000/api/v1/',
      VITE_WS_BASE_URL: 'ws://10.0.0.5:9000/',
    })
    expect(resolved.apiBaseUrl).toBe('http://10.0.0.5:9000/api/v1')
    expect(resolved.wsBaseUrl).toBe('ws://10.0.0.5:9000')
  })

  it('treats a blank variable as absent rather than as an empty base URL', () => {
    // An empty string would produce relative URLs (`/devices`) that resolve against
    // the Vite dev server instead of the backend, which is far harder to diagnose
    // than falling back to the documented port.
    const resolved = readEnvironment({ VITE_API_BASE_URL: '   ', VITE_WS_BASE_URL: '' })
    expect(resolved.apiBaseUrl).toBe(DEFAULT_API_BASE_URL)
    expect(resolved.wsBaseUrl).toBe(DEFAULT_WS_BASE_URL)
  })
})

describe('parseRequestTimeout', () => {
  it('reads a valid timeout', () => {
    expect(parseRequestTimeout('5000')).toBe(5000)
  })

  it('rounds a fractional value to a whole millisecond', () => {
    expect(parseRequestTimeout('2500.6')).toBe(2501)
  })

  it('falls back on a missing value', () => {
    expect(parseRequestTimeout(undefined)).toBe(DEFAULT_REQUEST_TIMEOUT_MS)
  })

  it('falls back on a non-numeric value instead of producing NaN', () => {
    // `setTimeout(fn, NaN)` fires immediately, so a typo here would abort every
    // request the instant it was issued rather than failing visibly.
    expect(parseRequestTimeout('soon')).toBe(DEFAULT_REQUEST_TIMEOUT_MS)
  })

  it('falls back on zero, which would abort every request immediately', () => {
    expect(parseRequestTimeout('0')).toBe(DEFAULT_REQUEST_TIMEOUT_MS)
  })

  it('falls back on a negative value', () => {
    expect(parseRequestTimeout('-1')).toBe(DEFAULT_REQUEST_TIMEOUT_MS)
  })

  it('refuses a value below the documented minimum', () => {
    expect(parseRequestTimeout(String(MIN_REQUEST_TIMEOUT_MS - 1))).toBe(
      DEFAULT_REQUEST_TIMEOUT_MS,
    )
  })

  it('accepts a value exactly at the minimum', () => {
    expect(parseRequestTimeout(String(MIN_REQUEST_TIMEOUT_MS))).toBe(MIN_REQUEST_TIMEOUT_MS)
  })
})

describe('the resolved environment', () => {
  it('is usable even with no test-time configuration', () => {
    // The suite relies on this: the harness strips the base URL from a request to
    // produce the relative path a route is keyed by, so `environment` must be
    // resolved (not `undefined`) whenever a test runs.
    expect(environment.apiBaseUrl).toMatch(/^https?:\/\//)
    expect(environment.wsBaseUrl).toMatch(/^wss?:\/\//)
    expect(environment.requestTimeoutMs).toBeGreaterThan(0)
  })
})

describe('webSocketUrl', () => {
  it('joins the configured WebSocket base with a channel path', () => {
    expect(webSocketUrl('/ws/packets')).toBe(`${environment.wsBaseUrl}/ws/packets`)
  })

  it('adds the leading slash when the caller omitted it', () => {
    expect(webSocketUrl('ws/alerts')).toBe(`${environment.wsBaseUrl}/ws/alerts`)
  })
})
