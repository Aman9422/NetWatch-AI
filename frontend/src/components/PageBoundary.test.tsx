/**
 * The lazy-route boundary (M19.8).
 *
 * Code splitting gives the page area a failure mode the eager shell did not have:
 * a chunk that never arrives. These tests assert the two properties the boundary
 * exists for, and the one it must not break:
 *
 * * a page that throws while rendering is reported inside the page area — the
 *   shell stays mounted, so the operator can still navigate;
 * * the reported message is the application's own sentence, never the thrown
 *   error's text, because a chunk failure must not put internal detail on screen
 *   (M15.7);
 * * opening a different route retries, so a broken page is not permanent.
 *
 * A component that throws on first render stands in for the failed dynamic
 * import: React cannot distinguish them, because both surface as a render error
 * below the boundary.
 */

import type { ReactElement } from 'react'
import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { LazyPage, PageBoundary } from '@/components/PageBoundary'

/** A page that always throws, standing in for a chunk that never loaded. */
function BrokenPage(): never {
  throw new Error('Failed to fetch dynamically imported module')
}

/** The text a chunk failure is reported with. */
const FAILURE_TITLE = 'This page could not be loaded'

describe('PageBoundary', () => {
  it('reports a failed page inside the page area and keeps the shell mounted', () => {
    // `console.error` is React's own complaint about a caught error; silenced so
    // the expected failure does not read as a real one in the test output.
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})

    render(
      <div>
        <nav>Sidebar</nav>
        <LazyPage resetKey="dashboard">
          <BrokenPage />
        </LazyPage>
      </div>,
    )

    expect(screen.getByText(FAILURE_TITLE)).toBeInTheDocument()
    // The shell around the page area is untouched: the boundary is inside it.
    expect(screen.getByText('Sidebar')).toBeInTheDocument()
    // And there is something to do about it.
    expect(screen.getByRole('button', { name: /reload/i })).toBeInTheDocument()

    consoleError.mockRestore()
  })

  it('does not put the thrown error’s text on screen', () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})

    render(
      <LazyPage resetKey="reports">
        <BrokenPage />
      </LazyPage>,
    )

    // The sentence is the application's, and the internal message stays internal.
    expect(screen.queryByText(/Failed to fetch dynamically imported module/)).toBeNull()
    expect(screen.getByText(/Reloading fetches it again/)).toBeInTheDocument()

    consoleError.mockRestore()
  })

  it('calls the reload handler it was given', () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
    const onReload = vi.fn()

    render(
      <PageBoundary resetKey="alerts" onReload={onReload}>
        <BrokenPage />
      </PageBoundary>,
    )
    screen.getByRole('button', { name: /reload/i }).click()

    expect(onReload).toHaveBeenCalledTimes(1)

    consoleError.mockRestore()
  })

  it('retries when a different route is opened', () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
    let shouldThrow = true

    /** A page that throws until the test says otherwise. */
    function SometimesBroken(): ReactElement {
      if (shouldThrow) throw new Error('Failed to fetch dynamically imported module')
      return <p>Reports content</p>
    }

    const { rerender } = render(
      <LazyPage resetKey="reports">
        <SometimesBroken />
      </LazyPage>,
    )
    expect(screen.getByText(FAILURE_TITLE)).toBeInTheDocument()

    // Opening another route, then returning, gives the page a second attempt.
    shouldThrow = false
    rerender(
      <LazyPage resetKey="system">
        <SometimesBroken />
      </LazyPage>,
    )

    expect(screen.queryByText(FAILURE_TITLE)).toBeNull()
    expect(screen.getByText('Reports content')).toBeInTheDocument()

    consoleError.mockRestore()
  })
})
