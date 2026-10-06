/**
 * The live-backend integration configuration (M15.39).
 *
 * A **third** config, next to `vite.config.ts` and `vitest.config.ts`, because
 * this run tests something the other two deliberately cannot: the real
 * application against a real FastAPI backend on `127.0.0.1:8000`.
 *
 * The difference from the unit run is not cosmetic, it is the whole point:
 *
 * * **Nothing is stubbed.** The unit suites replace `fetch` with a router and
 *   `WebSocket` with a controllable fake, which is what makes them deterministic
 *   and what also means they can pass while the backend's actual envelope,
 *   actual field names or actual event payloads have drifted. Here the real
 *   `fetch`, the real `WebSocket` and the real backend are used, so a drift
 *   fails this run and only this run.
 * * **It is excluded from the unit run** (`vitest.config.ts` excludes
 *   `tests/live/**`) and is never part of `npm test`. A machine with no backend
 *   must still be able to run the unit suite; running this one there would fail
 *   for a reason that is not a defect in the code.
 * * **It is slower and less certain by nature.** Real sockets, real timers and a
 *   real capture pipeline mean the timeouts are generous and one test waits for
 *   an event the backend publishes on its own schedule.
 *
 * There is no setup file that installs a fake. The only thing `live-setup.ts`
 * does is supply the Node built-in `WebSocket` where jsdom does not define one —
 * the same category of shim as the unit setup's `ResizeObserver`, and not a stub
 * of the protocol: the connection it makes is real.
 */

import { fileURLToPath } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

/** Where the backend is expected to be listening, for the failure message. */
const EXPECTED_BACKEND = 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  test: {
    name: 'live-backend',
    // The same pool choice as the unit config, for the same Windows reason: the
    // project path contains a space, and the forks pool never hands a file to a
    // worker there.
    pool: 'threads',
    // jsdom by default so a page can be rendered. The files that talk to the
    // backend without a DOM opt out with a `@vitest-environment node` docblock.
    environment: 'jsdom',
    setupFiles: ['./tests/live/live-setup.ts'],
    include: ['tests/live/**/*.test.{ts,tsx}'],
    // A real backend is involved, so nothing here may be mocked behind the test's
    // back: no stub is inherited from the unit setup, and none is installed here.
    restoreMocks: true,
    clearMocks: true,
    unstubEnvs: true,
    unstubGlobals: true,
    // Generous, because these are real requests to a local server, and one test
    // waits for an event the backend publishes on its own heartbeat.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // One file at a time keeps the socket count and the capture state legible
    // while a human reads the output.
    fileParallelism: false,
    // Printed so a failing run names where it was pointed rather than leaving the
    // reader to guess which port was tried.
    env: {
      LIVE_BACKEND_EXPECTED_AT: EXPECTED_BACKEND,
    },
  },
})
