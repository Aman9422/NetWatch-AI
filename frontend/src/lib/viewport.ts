/**
 * Viewport helpers for the shell (M15.35).
 *
 * The rail is a fixed 272px column, and the page column is what is left of the
 * window. On a phone that leaves the page a few dozen pixels wide — narrower than
 * any card on any page, so every page paints over itself. The rail can already be
 * collapsed from the navbar's menu button; all that was missing is a narrow
 * viewport *starting* collapsed (M16.15).
 *
 * `matchMedia` is the test: both test environments install an inert
 * `MediaQueryList` that reports "no match", so under jsdom this module reports
 * "wide" whatever the viewport, and the shell behaves exactly as it did before.
 * The `typeof` guards cover a runtime that has no `matchMedia` at all.
 */

/** Below this width the rail costs the page more than it gives it. */
export const NARROW_VIEWPORT_QUERY = '(max-width: 767px)'

/** True when the viewport is currently narrow. Unknown environments report "wide". */
export function isNarrowViewport(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false
  return window.matchMedia(NARROW_VIEWPORT_QUERY).matches
}

/**
 * Call `onNarrow` whenever the viewport *becomes* narrow — a phone rotating to
 * portrait, or a desktop window dragged small. Widening deliberately does not call
 * back: reopening the rail after the user closed it would undo their click.
 *
 * Returns the unsubscribe function, so a caller can return it from `useEffect`.
 */
export function onEnterNarrowViewport(onNarrow: () => void): () => void {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return () => {}
  const list = window.matchMedia(NARROW_VIEWPORT_QUERY)
  const handleChange = (event: MediaQueryListEvent): void => {
    if (event.matches) onNarrow()
  }
  list.addEventListener('change', handleChange)
  return () => list.removeEventListener('change', handleChange)
}
