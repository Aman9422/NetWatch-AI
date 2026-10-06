/**
 * The test harness (M15.38).
 *
 * The tests in this suite are deliberately written against the *real* client
 * stack — a page renders, its hook runs, the hook calls a service, the service
 * calls {@link apiRequest}, and `apiRequest` calls `fetch`. Only the two edges are
 * replaced: `fetch` (this file's router) and `WebSocket` (this file's
 * {@link MockWebSocket}). Everything between them is the code under test.
 *
 * That choice is the point. A suite that mocked the *services* would pass while
 * the envelope parser, the query serialiser, the error translation and the
 * bounded-state hooks were all broken, because none of them would run. Mocking at
 * the wire is what makes these tests evidence about the application.
 *
 * Nothing here is exported from the application: `src/test` is not reachable from
 * `App`, and `vite build` never sees it.
 */

import { vi } from 'vitest'
import { environment } from '@/config/env'
import { channelHub } from '@/services'

export { channelHub }

// ── Response builders ────────────────────────────────────────────────────────

/** The `message` the backend sends on success when a test does not care what it says. */
export const OK_MESSAGE = 'OK'

/** A `Response` carrying a successful project envelope (M13.4). */
export function ok<T>(data: T, message: string = OK_MESSAGE): Response {
  return jsonResponse({ success: true, message, data }, 200)
}

/** A `Response` carrying a bare value with no envelope, for malformed-shape tests. */
export function raw(body: unknown, status = 200): Response {
  return jsonResponse(body, status)
}

/** A `Response` carrying the project's error envelope (M13.4). */
export function failure(
  status: number,
  message: string,
  errors: readonly { field: string; code: string }[] = [],
): Response {
  return jsonResponse({ success: false, message, errors }, status)
}

/** A `Response` carrying FastAPI's own `422` body, which bypasses the envelope. */
export function validationFailure(
  details: readonly { loc: readonly (string | number)[]; msg: string; type: string }[],
): Response {
  return jsonResponse({ detail: details }, 422)
}

/** A `Response` with no body at all, e.g. a bare `500` from a proxy. */
export function emptyResponse(status: number): Response {
  return new Response('', { status })
}

/** A `200` carrying something that is neither branch of the envelope. */
export function malformed(status = 200): Response {
  return jsonResponse({ unexpected: true }, status)
}

/** Encode a body as JSON with the headers the client expects. */
function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

/**
 * A fetch that rejects the way a browser does when nothing is listening.
 *
 * `TypeError` rather than a bare `Error`, because that is what `fetch` throws and
 * the client distinguishes a network failure from an abort by the error's `name`.
 */
export function networkDownFetch(): typeof fetch {
  const stub = (): Promise<Response> =>
    Promise.reject(new TypeError('fetch failed: ECONNREFUSED'))
  return stub as unknown as typeof fetch
}

/**
 * A fetch that never answers, so the client's own timeout fires.
 *
 * The promise settles only when the request is aborted, which is exactly the
 * shape of a hung backend: the client must abort it itself rather than wait.
 */
export function hangingFetch(): typeof fetch {
  const stub = (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> =>
    new Promise<Response>((_resolve, reject) => {
      // `RequestInit.signal` is `AbortSignal | null | undefined`, so an explicit
      // `null` is treated exactly like an absent signal: nothing can abort this
      // request, and it simply never settles.
      const signal: AbortSignal | null = init?.signal ?? null
      if (signal === null) return
      const abort = (): void => {
        reject(Object.assign(new Error('The operation was aborted.'), { name: 'AbortError' }))
      }
      if (signal.aborted) abort()
      else signal.addEventListener('abort', abort)
    })
  return stub as unknown as typeof fetch
}

// ── The router ───────────────────────────────────────────────────────────────

/** One request the router saw, after the base URL was stripped. */
export interface RoutedCall {
  /** The method, always upper case. */
  readonly method: string
  /** The path *relative to the API base*, e.g. `/devices` or `/alerts/7`. */
  readonly path: string
  /** The query string without its leading `?`, or `''`. */
  readonly query: string
  /** The parsed query, with repeated keys collected into arrays. */
  readonly params: Readonly<Record<string, string | string[]>>
  /** The decoded JSON body, when one was sent. */
  readonly body: unknown
  /** The URL as the service built it. */
  readonly url: string
}

/** What a route handler is given. */
export type RouteResult = Response | Promise<Response>

/** A route handler. */
export type RouteHandler = (call: RoutedCall) => RouteResult

/** Routes keyed by `"METHOD /path"`, with `*` accepted for either part. */
export type RouteTable = Readonly<Record<string, RouteHandler>>

/**
 * A handle on an installed router.
 *
 * `calls` is every request the application made, in order, which is how a test
 * asserts *what was asked for* rather than only what came back — the check that
 * catches a service building the wrong URL while still parsing the right shape.
 */
export interface FetchRouter {
  readonly calls: readonly RoutedCall[]
  /** How many requests matched a given `"METHOD /path"` key. */
  countOf(key: string): number
  /** The last call matching a key, or `undefined`. */
  lastCall(key: string): RoutedCall | undefined
}

/** Strip the configured API base from a request URL, leaving the service path. */
function relativePath(url: URL): string {
  let base = ''
  try {
    base = new URL(environment.apiBaseUrl).pathname.replace(/\/+$/, '')
  } catch {
    base = ''
  }
  const path = url.pathname
  if (base !== '' && path.startsWith(base)) return path.slice(base.length) || '/'
  return path
}

/** Collect a query string into a record, keeping repeated keys as arrays. */
function collectParams(search: URLSearchParams): Record<string, string | string[]> {
  const params: Record<string, string | string[]> = {}
  for (const key of new Set(search.keys())) {
    const all = search.getAll(key)
    params[key] = all.length === 1 ? all[0]! : all
  }
  return params
}

/** Normalise a route key into its method and path parts. */
function splitKey(key: string): { method: string; path: string } {
  const space = key.indexOf(' ')
  if (space === -1) return { method: '*', path: key }
  return { method: key.slice(0, space).toUpperCase(), path: key.slice(space + 1) }
}

/**
 * Return True when a route key matches a call.
 *
 * A path may end in `*` to match a prefix, which is what lets one route cover
 * `/alerts/{id}/evidence` without enumerating ids. An exact match always wins over
 * a prefix match, so a specific route can override a broader one.
 */
function keyMatches(key: string, call: RoutedCall): boolean {
  const { method, path } = splitKey(key)
  if (method !== '*' && method !== call.method) return false
  if (path === '*' || path === '/*') return true
  if (path.endsWith('*')) return call.path.startsWith(path.slice(0, -1))
  return call.path === path
}

/**
 * Install a fetch that answers from `routes`.
 *
 * An unmatched request **fails the test** rather than returning a 404: a service
 * that asks for an endpoint the test did not describe is a bug in the test or in
 * the service, and either way the failure should be immediate and named.
 */
export function installFetch(routes: RouteTable): FetchRouter {
  const calls: RoutedCall[] = []

  const handler = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const rawUrl =
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const url = new URL(rawUrl)
    const method = (init?.method ?? 'GET').toUpperCase()
    let body: unknown
    if (typeof init?.body === 'string' && init.body !== '') {
      try {
        body = JSON.parse(init.body) as unknown
      } catch {
        body = init.body
      }
    }

    const call: RoutedCall = {
      method,
      path: relativePath(url),
      query: url.search.replace(/^\?/, ''),
      params: collectParams(url.searchParams),
      body,
      url: rawUrl,
    }
    calls.push(call)

    // Exact keys first, then prefixes, then the catch-all. The order is what lets
    // `GET /alerts/7` win over `GET /alerts*`.
    const keys = Object.keys(routes)
    const exact = keys.filter((key) => !key.includes('*') && keyMatches(key, call))
    const wildcard = keys.filter((key) => key.includes('*') && keyMatches(key, call))
    const handlerForKey = exact[0] ?? wildcard[0]

    if (handlerForKey === undefined) {
      throw new Error(
        `No test route for ${method} ${call.path}${call.query === '' ? '' : `?${call.query}`}. ` +
          `Describe it in installFetch({ '${method} ${call.path}': ... }).`,
      )
    }
    return routes[handlerForKey]!(call)
  }

  vi.stubGlobal('fetch', vi.fn(handler))

  return {
    calls,
    countOf(key: string): number {
      return calls.filter((call) => keyMatches(key, call)).length
    },
    lastCall(key: string): RoutedCall | undefined {
      const matches = calls.filter((call) => keyMatches(key, call))
      return matches[matches.length - 1]
    },
  }
}
// ── The WebSocket fake ───────────────────────────────────────────────────────

/**
 * A controllable stand-in for a browser `WebSocket`.
 *
 * The real object is driven by a server this suite does not run, and it has no
 * way to be told "now open" or "now deliver this frame". This class has those as
 * methods, so a test causes each transition explicitly and asserts on the result —
 * which is the only way to test reconnection, backoff and deduplication
 * deterministically.
 *
 * It is a plain object with the same shape as `WebSocket` rather than a subclass,
 * because `ChannelSocket` only ever calls `send`, `close` and assigns the four
 * handler properties; implementing the full interface would be inventing surface
 * no code under test touches.
 */
export class MockWebSocket {
  /** Matches the browser's own constants, which `ChannelSocket` compares against. */
  static readonly CONNECTING = 0
  static readonly OPEN = 1
  static readonly CLOSING = 2
  static readonly CLOSED = 3

  readonly url: string
  readyState: number = MockWebSocket.CONNECTING
  /** Every frame this socket was asked to send, in order (`ChannelSocket.send`). */
  readonly sent: string[] = []
  /** Every close it was asked to perform, for asserting an idempotent teardown. */
  readonly closeRequests: { code: number; reason: string }[] = []

  onopen: ((event: Event) => void) | null = null
  onmessage: ((event: MessageEvent<unknown>) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  onclose: ((event: CloseEvent) => void) | null = null

  constructor(url: string) {
    this.url = url
  }

  // ── The surface `ChannelSocket` uses ───────────────────────────────────────

  send(data: string): void {
    this.sent.push(data)
  }

  close(code = 1000, reason = ''): void {
    this.closeRequests.push({ code, reason })
    const wasOpen = this.readyState === MockWebSocket.OPEN
    this.readyState = MockWebSocket.CLOSED
    // `ChannelSocket.close` detaches the handlers before calling this, so a
    // client-initiated close fires nothing. A server-initiated close goes through
    // `serverClose` instead.
    if (wasOpen && this.onclose !== null) {
      this.onclose({ code, reason } as CloseEvent)
    }
  }

  // ── Test controls ──────────────────────────────────────────────────────────

  /** Complete the handshake: the socket becomes OPEN and `onopen` fires. */
  open(): void {
    this.readyState = MockWebSocket.OPEN
    this.onopen?.(new Event('open'))
  }

  /** Deliver one frame. An object is serialised, so a test passes an event. */
  emit(payload: unknown): void {
    const data = typeof payload === 'string' ? payload : JSON.stringify(payload)
    this.onmessage?.({ data } as MessageEvent<unknown>)
  }

  /** Deliver a frame of a non-string type, which the client must refuse. */
  emitNonText(): void {
    this.onmessage?.({ data: 1234 } as MessageEvent<unknown>)
  }

  /**
   * The server dropped the connection.
   *
   * `code` decides whether the client retries: `1006` (abnormal) is retried, while
   * `1000` (normal) and `1005` (no code) are treated as a deliberate end.
   */
  serverClose(code = 1006, reason = ''): void {
    this.readyState = MockWebSocket.CLOSED
    this.onclose?.({ code, reason } as CloseEvent)
  }

  /** A transport error. The client ignores it and waits for the close. */
  error(): void {
    this.onerror?.(new Event('error'))
  }
}

/** A socket factory plus the sockets it produced. */
export interface SocketHarness {
  /** Every socket created, in creation order. */
  readonly sockets: MockWebSocket[]
  /** The most recently created socket. Throws when none exists yet. */
  latest(): MockWebSocket
  /** How many sockets have been created — the count a reconnect test asserts on. */
  readonly count: number
  /** The factory to hand to `ChannelSocket` or `ChannelHub.subscribe`. */
  readonly factory: (url: string) => WebSocket
}

/**
 * Build a socket factory a test can drive.
 *
 * The factory is what `ChannelSocket` calls instead of `new WebSocket(url)`, so a
 * test never touches the global constructor and two channels cannot interfere.
 */
export function createSocketHarness(): SocketHarness {
  const sockets: MockWebSocket[] = []
  const factory = (url: string): WebSocket => {
    const socket = new MockWebSocket(url)
    sockets.push(socket)
    return socket as unknown as WebSocket
  }
  return {
    sockets,
    factory,
    latest(): MockWebSocket {
      const socket = sockets[sockets.length - 1]
      if (socket === undefined) throw new Error('No socket has been created yet.')
      return socket
    },
    get count(): number {
      return sockets.length
    },
  }
}

// ── Event frames ─────────────────────────────────────────────────────────────

/** The fields a test supplies when building an event frame. */
export interface FrameOptions {
  readonly type: string
  readonly channel?: string
  readonly data?: Record<string, unknown>
  /** Defaults to a counter, so consecutive frames are distinct by default. */
  readonly event_id?: string
  readonly sequence?: number
  readonly schema_version?: number
  readonly timestamp?: string
  readonly source?: string
}

let frameCounter = 0

/** The next default event id. Reset by {@link resetFrames}. */
function nextEventId(): string {
  frameCounter += 1
  return `evt-${frameCounter}`
}

/** Reset the frame counter, so an event id is predictable across a test. */
export function resetFrames(): void {
  frameCounter = 0
}

/**
 * Build one envelope as the server would send it, already JSON-encoded.
 *
 * The defaults match `app/websockets/event.py`: schema version 1, an ISO timestamp
 * and a distinct `event_id`. A test overrides only the field it is about.
 */
export function eventFrame(options: FrameOptions): string {
  return JSON.stringify({
    schema_version: options.schema_version ?? 1,
    event_id: options.event_id ?? nextEventId(),
    type: options.type,
    channel: options.channel ?? 'alerts',
    timestamp: options.timestamp ?? new Date().toISOString(),
    source: options.source ?? 'system',
    sequence: options.sequence ?? frameCounter,
    data: options.data ?? {},
  })
}

/** The same envelope as an object, for a test that wants to mutate a copy. */
export function eventObject(options: FrameOptions): Record<string, unknown> {
  return JSON.parse(eventFrame(options)) as Record<string, unknown>
}

/** A `packet.observed` frame carrying one normalized packet (M14.8). */
export function packetFrame(data: Record<string, unknown>, eventId?: string): string {
  return eventFrame({
    type: 'packet.observed',
    channel: 'packets',
    source: 'pipeline.packets',
    data,
    ...(eventId === undefined ? {} : { event_id: eventId }),
  })
}

/** A keepalive `ping` frame, which the client must answer with a `pong`. */
export function pingFrame(nonce?: string): string {
  return eventFrame({
    type: 'ping',
    channel: 'system',
    source: 'system',
    data: nonce === undefined ? {} : { nonce },
  })
}

/** An `error` frame: the server refusing a frame this client sent (M14.23). */
export function refusalFrame(reason = 'unknown frame', field = 'type'): string {
  return eventFrame({
    type: 'error',
    channel: 'system',
    source: 'system',
    data: { reason, field },
  })
}
