/**
 * Test environment setup (M15.38).
 *
 * Three things and nothing else, because a setup file that does real work is a
 * setup file whose failures are impossible to attribute:
 *
 * 1. **The jest-dom matchers.** Registered through `@testing-library/jest-dom/vitest`
 *    so `toBeInTheDocument` and friends augment `expect` rather than being
 *    hand-rolled per test. Importing it here (a file inside `src`) is also what puts
 *    the matcher types into the TypeScript program, since `tsconfig.json` narrows
 *    `types` to `["node"]`.
 * 2. **DOM APIs jsdom does not implement.** jsdom is a document implementation, not
 *    a browser: `matchMedia`, `ResizeObserver` and `IntersectionObserver` are all
 *    absent, and Recharts calls the first two on mount. Without them any page test
 *    that renders a chart throws for a reason that has nothing to do with the page.
 *    The stubs are deliberately inert — they report "desktop", never fire a resize —
 *    so a test cannot accidentally depend on a layout event it did not cause.
 * 3. **Cleanup between tests**, which must be explicit because `globals` is off and
 *    Testing Library's automatic cleanup only registers when globals exist.
 *
 * `fetch` is deliberately **not** stubbed here. Each test installs the response it
 * expects through the router in `./harness`, which makes an unexpected network call
 * a visible missing stub rather than a silent request to a server that is not there.
 */

import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, vi } from 'vitest'
import { channelHub } from './harness'

afterEach(() => {
  cleanup()
  // Every socket is process-wide state, so a test that subscribes leaves the hub
  // holding an entry the next test would share. Closing it here keeps one test's
  // channel from being observed as open by the next.
  channelHub.closeAll()
  // `vi.stubGlobal` is how the router installs `fetch`; without this the stub from
  // one test would answer the next test's request with the wrong payload.
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

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

if (typeof window !== 'undefined' && typeof window.matchMedia !== 'function') {
  window.matchMedia = mediaQueryListStub as typeof window.matchMedia
}

/** A no-op observer, for the components that only need the constructor to exist. */
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

// jsdom defines `scrollTo` only as a stub that throws "not implemented" in newer
// versions; the pages scroll their own containers on mount.
if (typeof window !== 'undefined') {
  window.scrollTo = (() => {}) as typeof window.scrollTo
}
