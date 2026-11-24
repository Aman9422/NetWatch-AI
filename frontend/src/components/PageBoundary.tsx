/**
 * The boundary a lazily loaded page sits behind (M19.8).
 *
 * Splitting the routes into chunks is what keeps the entry bundle small, but it
 * buys that with a failure mode the eager shell did not have: a chunk request can
 * fail — a deploy replaced the hashed file, a flaky link dropped the request, a
 * proxy refused it. React surfaces that as a render-time error from the dynamic
 * import, and with no boundary above it the whole application unmounts to a blank
 * page.
 *
 * So this module adds the two things a lazy route needs and nothing else:
 *
 * * a {@link LoadingState} while the chunk is in flight, so a slow route reads as
 *   busy rather than as an empty screen;
 * * an error boundary that keeps the shell — the sidebar and the navbar — usable
 *   and reports the failure in the page area, with a reload the operator can
 *   perform. The message is fixed text: a chunk load failure has no operator-facing
 *   sentence behind it worth printing, and a stack trace on screen is exactly what
 *   M15.7 forbids.
 *
 * `resetKey` is the route name. A failed chunk stays failed until the boundary is
 * told the attempted page changed, otherwise navigating away from the broken route
 * and back would show the stale error without retrying the import.
 */

import { Component, Suspense, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'
import { LoadingState } from './AsyncState'
import { C } from '@/lib/tokens'

/** What a caller supplies to {@link PageBoundary}. */
export interface PageBoundaryProps {
  readonly children: ReactNode
  /**
   * Identifier of the page being rendered. Changing it clears a previous failure
   * so the new page's chunk is requested.
   */
  readonly resetKey: string
  /** How to reload. Defaults to a full page load, which re-requests every chunk. */
  readonly onReload?: () => void
}

/** The one fact the boundary tracks. */
interface PageBoundaryState {
  readonly failed: boolean
}

/** What a failed chunk load tells the operator. */
const CHUNK_FAILURE_TITLE = 'This page could not be loaded'
const CHUNK_FAILURE_DETAIL =
  'The page’s code did not arrive. Reloading fetches it again.'

/** The page area's error panel, drawn in the application's own design. */
function ChunkFailure({
  onReload,
  minHeight,
}: {
  onReload: () => void
  minHeight: number
}) {
  return (
    <div
      className="flex flex-col items-center justify-center gap-3 text-center px-6"
      style={{ minHeight }}
    >
      <div style={{ color: C.danger }}>
        <AlertTriangle size={26} />
      </div>
      <p className="text-sm font-medium text-white">{CHUNK_FAILURE_TITLE}</p>
      <p className="text-xs max-w-md" style={{ color: C.muted }}>
        {CHUNK_FAILURE_DETAIL}
      </p>
      <button
        onClick={onReload}
        className="mt-1 flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold"
        style={{ backgroundColor: `${C.accent}15`, color: C.accent }}
      >
        <RefreshCw size={12} /> Reload
      </button>
    </div>
  )
}

/**
 * Keeps a failed page from taking the shell down with it.
 *
 * Only a render-time failure below this boundary is caught, which is the shape a
 * failed `import()` takes. An error in an event handler or a rejected promise is
 * still the page's own to report, as it was before this boundary existed.
 */
export class PageBoundary extends Component<PageBoundaryProps, PageBoundaryState> {
  state: PageBoundaryState = { failed: false }

  static getDerivedStateFromError(): PageBoundaryState {
    return { failed: true }
  }

  componentDidUpdate(previous: PageBoundaryProps): void {
    // A different route deserves a fresh attempt at its own chunk.
    if (previous.resetKey !== this.props.resetKey && this.state.failed) {
      this.setState({ failed: false })
    }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // The console is for the developer; a chunk failure carries no data worth
    // sending to the backend, and nothing here is shown to the operator.
    console.error('A page failed to render (M19.8):', error, info.componentStack)
  }

  render(): ReactNode {
    if (this.state.failed) {
      return (
        <ChunkFailure
          onReload={this.props.onReload ?? (() => window.location.reload())}
          minHeight={320}
        />
      )
    }
    return this.props.children
  }
}

/**
 * One lazy route: busy while its chunk loads, recoverable if it never arrives.
 *
 * The `Suspense` boundary is inside the page area rather than around the whole
 * application, so a route that is still loading never hides the sidebar or the
 * navbar the operator navigates with.
 */
export function LazyPage({
  resetKey,
  children,
  onReload,
}: {
  resetKey: string
  children: ReactNode
  onReload?: () => void
}) {
  return (
    <PageBoundary resetKey={resetKey} onReload={onReload}>
      <Suspense fallback={<LoadingState label="Loading page…" minHeight={320} />}>
        {children}
      </Suspense>
    </PageBoundary>
  )
}

export default LazyPage
