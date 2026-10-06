/**
 * The unit-test configuration (M15.38).
 *
 * A **separate** config from `vite.config.ts` on purpose. The application config
 * loads the Figma Make plugins and `./.figma/make/site.json`, which exist to shape
 * a *deployed page* — document tags, an error-overlay replay, a stories registry.
 * None of that belongs in a test run, and importing it would make the test suite
 * depend on a generated file that a fresh clone may not have. Only what the tests
 * genuinely need is repeated here: JSX, the `@` alias, and jsdom.
 *
 * `globals` is left off. Every test imports `describe`, `it` and `expect` from
 * `vitest` explicitly, so a test file that is read on its own says where its
 * assertions come from rather than relying on ambient names the TypeScript
 * configuration would also have to declare.
 */

import { fileURLToPath } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // `fileURLToPath` rather than `__dirname`: this file is ESM (`type: module`),
      // and on Windows the URL pathname form would keep a leading slash.
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  test: {
    // `threads` is pinned rather than left to the default `forks` pool. On Windows
    // with a space in the project path (`…/Projets/NetWatch AI/frontend`) the forks
    // pool never hands a file to a worker — every run sits on `[queued]` until it is
    // killed — while the worker-thread pool starts and runs the suite in seconds.
    pool: 'threads',
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    // Component tests render trees; utilities and services need no DOM. Both are
    // `.test.ts`/`.test.tsx` under `src`, so one pattern covers the suite.
    include: ['src/**/*.test.{ts,tsx}'],
    // The live-backend suite is a different run with a different environment, and
    // it must never be picked up here: it would fail on a machine with no backend.
    exclude: ['node_modules/**', 'dist/**', 'tests/live/**'],
    restoreMocks: true,
    clearMocks: true,
    unstubEnvs: true,
    unstubGlobals: true,
    // A test that reaches for the network is a bug; making that explicit turns a
    // surprise 5-second timeout into an immediate failure.
    testTimeout: 10_000,
    hookTimeout: 10_000,
  },
})
