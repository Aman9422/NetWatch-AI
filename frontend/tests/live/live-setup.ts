/**
 * Setup for the live-backend run (M15.39).
 *
 * This is deliberately **not** `src/test/setup.ts`. That file exists to make the
 * unit suite deterministic and installs a fake `WebSocket` that speaks nothing;
 * running it here would defeat the purpose of this run, because a page under it
 * could never receive a real event. What is supplied here is only what the
 * environment genuinely lacks:
 *
 * * `@testing-library/jest-dom`'s matchers, so a page test can say
 *   `toBeInTheDocument` rather than reading `textContent`;
 * * `matchMedia` and `ResizeObserver`, which Recharts calls on mount and jsdom
 *   does not implement;
 * * `scrollTo`, which newer jsdom defines only as a throwing stub;
 * * **in a DOM environment only**, an inert `WebSocket` — see below.
 *
 * Nothing here replaces `fetch`. The real `fetch` is what makes this run evidence
 * about the backend.
 *
 * ## The socket, and why it is split by environment
 *
 * The run is divided by what each file can honestly prove:
 *
 * * **`node`-environment files use the runtime's own `WebSocket`.** The ambient
 *   global there is the real client, so `websocket.test.ts` opens real
 *   connections, receives real frames and asserts on real payloads. Nothing is
 *   installed for those files, which is why this setup file leaves the global
 *   alone whenever there is no `window`.
 * * **DOM files get the inert socket instead.** A real socket under vitest's jsdom
 *   fails in the harness rather than in the application: the runtime builds the
 *   `open` event from the ambient `Event` class, the jsdom environment has
 *   replaced that class with its own, and the runtime's `EventTarget` rejects an
 *   event from a foreign realm before any listener runs. The connection itself
 *   succeeds and `message` frames arrive — only `open` is refused, as an
 *   **unhandled** error that would fail this run for a reason that has nothing to
 *   do with the code under test.
 *
 * A repair was written and then deleted on the evidence: overriding
 * `dispatchEvent` — on the prototype, and then as an **own property of the
 * instance** — was never called, while the same socket's `readyState` reached `1`,
 * proving the failing dispatch bypasses the instance. A DOM file therefore cannot
 * use the real socket cleanly, and the honest split is the one above: the page
 * tests exercise real REST through real pages, and the real socket is exercised
 * where it can be.
 */

import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, beforeEach } from 'vitest'
import { channelHub } from '@/services'
import { installInertWebSocket } from './inert-socket'

// ── The socket each environment gets ─────────────────────────────────────────

/**
 * True when this file is running under jsdom rather than under the `node`
 * environment. The presence of a `window` is the whole test: the application only
 * touches `window` in a browser, and the environment that provides one is the
 * environment with the `Event` realm clash.
 */
const hasDom = typeof window !== 'undefined'

beforeEach(() => {
  // A page reaching the socket through the hub's default factory
  // (`new WebSocket(url)`) must not open a connection it cannot close cleanly. In
  // a DOM file the inert socket is what prevents that; in a `node` file the real
  // constructor is deliberately left in place.
  if (hasDom) installInertWebSocket()
})

// ── The DOM APIs jsdom does not implement ────────────────────────────────────

/** A `MediaQueryList` that reports "no match" and never notifies. */
function mediaQueryListStub(query: string): MediaQueryList {
  return {
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  } as unknown as MediaQueryList
}

if (hasDom && typeof window.matchMedia !== 'function') {
  window.matchMedia = mediaQueryListStub as typeof window.matchMedia
}

/** A no-op observer, for the components that only need the constructor. */
class NoopObserver {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
  takeRecords(): [] {
    return []
  }
}

if (typeof globalThis.ResizeObserver === 'undefined') {
  globalThis.ResizeObserver = NoopObserver as unknown as typeof ResizeObserver
}

if (typeof globalThis.IntersectionObserver === 'undefined') {
  globalThis.IntersectionObserver = NoopObserver as unknown as typeof IntersectionObserver
}

if (hasDom) {
  window.scrollTo = (() => {}) as typeof window.scrollTo
}

// ── Teardown ─────────────────────────────────────────────────────────────────

afterEach(() => {
  // A socket is process-wide state: a test that subscribes and does not release
  // would leave the next test sharing a connection it did not open, which is the
  // one way these tests could leak into each other. Every connection in the `node`
  // files is a real one, so leaving it open would also leave the backend holding a
  // client — and, for the dashboard channel, sampling six services a second for an
  // audience that no longer exists.
  if (hasDom) cleanup()
  channelHub.closeAll()
})
