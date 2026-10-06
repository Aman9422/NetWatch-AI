/**
 * The four data states (M15.8, M15.38 "Components").
 *
 * M15.8 states the requirement as "do not leave blank screens when an API fails",
 * so the assertions here are mostly about *precedence*: which state a section picks
 * when more than one could apply. That is where a blank screen comes from — a
 * component that renders nothing because two conditions were true at once and
 * neither branch was reached.
 *
 * The error panel's sentences come from the real `ApiError`, so the check that a
 * backend sentence reaches the screen is a check about the actual error model
 * rather than about a hand-written string.
 */

import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ApiError, GENERIC_MESSAGE, NETWORK_MESSAGE } from '@/services'
import {
  AsyncSection,
  EmptyState,
  ErrorState,
  LoadingState,
  RefreshFailureBanner,
  Spinner,
} from '@/components/AsyncState'

/** A retryable failure: the backend could not be reached. */
const networkError = new ApiError({ kind: 'network' })

/** A failure a retry cannot fix: the lifecycle transition was refused. */
const conflictError = new ApiError({
  kind: 'conflict',
  message: 'That lifecycle change is not allowed from the current state.',
})

describe('LoadingState', () => {
  it('shows the label it was given', () => {
    render(<LoadingState label="Loading devices…" />)
    expect(screen.getByText('Loading devices…')).toBeInTheDocument()
  })

  it('falls back to a generic busy label', () => {
    render(<LoadingState />)
    expect(screen.getByText('Loading…')).toBeInTheDocument()
  })
})

describe('Spinner', () => {
  it('renders a spinning icon rather than an emoji', () => {
    // The interface convention is an icon-library glyph, never an emoji standing
    // in for a control.
    const { container } = render(<Spinner />)
    const svg = container.querySelector('svg')
    expect(svg).not.toBeNull()
    expect(svg?.getAttribute('class')).toContain('animate-spin')
  })
})

describe('EmptyState', () => {
  it('shows a title and an optional hint', () => {
    render(<EmptyState title="No devices observed" hint="Start capture to see devices." />)
    expect(screen.getByText('No devices observed')).toBeInTheDocument()
    expect(screen.getByText('Start capture to see devices.')).toBeInTheDocument()
  })

  it('works without a hint', () => {
    render(<EmptyState title="No alerts" />)
    expect(screen.getByText('No alerts')).toBeInTheDocument()
  })
})

describe('ErrorState', () => {
  it('renders the error model\'s own sentence, not the raw failure', () => {
    render(<ErrorState error={networkError} />)
    expect(screen.getByText(NETWORK_MESSAGE)).toBeInTheDocument()
  })

  it('offers a retry when a retry could help', () => {
    const onRetry = vi.fn()
    render(<ErrorState error={networkError} onRetry={onRetry} />)
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('offers a reload, not a retry, when the failure is not retryable', () => {
    // A retry cannot fix a refused transition, so the control says what it does.
    render(<ErrorState error={conflictError} onRetry={vi.fn()} />)
    expect(screen.getByRole('button', { name: /reload/i })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^retry$/i })).toBeNull()
  })

  it('offers no control when the caller supplied no handler', () => {
    render(<ErrorState error={networkError} />)
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('lists the field-level failures when the backend named any', () => {
    const error = new ApiError({
      kind: 'validation',
      message: 'A filter value was rejected.',
      fields: [
        { field: 'limit', code: 'INVALID_FILTER' },
        { field: 'status', code: 'INVALID_FILTER' },
      ],
    })
    render(<ErrorState error={error} />)
    expect(screen.getByText('limit: INVALID_FILTER')).toBeInTheDocument()
    expect(screen.getByText('status: INVALID_FILTER')).toBeInTheDocument()
  })

  it('renders no list when there were no field-level failures', () => {
    const { container } = render(<ErrorState error={networkError} />)
    expect(container.querySelectorAll('li')).toHaveLength(0)
  })

  it('uses the caller\'s title so the section names what failed', () => {
    render(<ErrorState error={networkError} title="Unable to load devices" />)
    expect(screen.getByText('Unable to load devices')).toBeInTheDocument()
  })
})

describe('RefreshFailureBanner', () => {
  it('says the data below may be stale, because the rows are still on screen', () => {
    render(<RefreshFailureBanner error={networkError} />)
    const text = screen.getByText(/may be out of date/i)
    expect(text.textContent).toContain(NETWORK_MESSAGE)
  })

  it('offers a retry when the caller supplied one', () => {
    const onRetry = vi.fn()
    render(<RefreshFailureBanner error={networkError} onRetry={onRetry} />)
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('shows a warning icon rather than an emoji', () => {
    const { container } = render(<RefreshFailureBanner error={networkError} />)
    expect(container.querySelector('svg')).not.toBeNull()
  })
})

describe('AsyncSection precedence', () => {
  const child = <p>the rows</p>

  it('renders the content on success', () => {
    render(
      <AsyncSection isInitialLoading={false} error={null} isEmpty={false}>
        {child}
      </AsyncSection>,
    )
    expect(screen.getByText('the rows')).toBeInTheDocument()
  })

  it('renders the loading panel on a first load, and not the content', () => {
    render(
      <AsyncSection
        isInitialLoading
        error={null}
        isEmpty={false}
        loadingLabel="Loading packets…"
      >
        {child}
      </AsyncSection>,
    )
    expect(screen.getByText('Loading packets…')).toBeInTheDocument()
    expect(screen.queryByText('the rows')).toBeNull()
  })

  it('prefers loading over a stale error while the first request is in flight', () => {
    // A reload after a failure clears the error and sets loading again; showing the
    // old failure during that moment would make the retry look broken.
    render(
      <AsyncSection
        isInitialLoading
        error={networkError}
        isEmpty
        loadingLabel="Loading devices…"
      >
        {child}
      </AsyncSection>,
    )
    expect(screen.getByText('Loading devices…')).toBeInTheDocument()
    expect(screen.queryByText(NETWORK_MESSAGE)).toBeNull()
  })

  it('prefers the error over empty, so a failure is never reported as "nothing here"', () => {
    // This is the blank-screen bug in its other form: a section that has no rows
    // *because* the request failed must not say "no devices observed".
    render(
      <AsyncSection
        isInitialLoading={false}
        error={networkError}
        isEmpty
        emptyTitle="No devices observed"
      >
        {child}
      </AsyncSection>,
    )
    expect(screen.getByText(NETWORK_MESSAGE)).toBeInTheDocument()
    expect(screen.queryByText('No devices observed')).toBeNull()
  })

  it('renders the empty panel when the request succeeded with no rows', () => {
    render(
      <AsyncSection
        isInitialLoading={false}
        error={null}
        isEmpty
        emptyTitle="No alerts"
        emptyHint="Nothing has been detected yet."
      >
        {child}
      </AsyncSection>,
    )
    expect(screen.getByText('No alerts')).toBeInTheDocument()
    expect(screen.getByText('Nothing has been detected yet.')).toBeInTheDocument()
    expect(screen.queryByText('the rows')).toBeNull()
  })

  it('passes the retry handler through to the error panel', () => {
    const onRetry = vi.fn()
    render(
      <AsyncSection
        isInitialLoading={false}
        error={networkError}
        isEmpty={false}
        onRetry={onRetry}
      >
        {child}
      </AsyncSection>,
    )
    screen.getByRole('button', { name: /retry/i }).click()
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('uses the caller\'s error title', () => {
    render(
      <AsyncSection
        isInitialLoading={false}
        error={networkError}
        isEmpty={false}
        errorTitle="Unable to load alerts"
      >
        {child}
      </AsyncSection>,
    )
    expect(screen.getByText('Unable to load alerts')).toBeInTheDocument()
  })

  it('never renders nothing, whichever combination of flags it is given', () => {
    // The single invariant M15.8 asks for. Every combination is enumerated rather
    // than sampled, because the failure mode is one specific combination.
    const flags = [true, false]
    for (const isInitialLoading of flags) {
      for (const hasError of flags) {
        for (const isEmpty of flags) {
          const { container, unmount } = render(
            <AsyncSection
              isInitialLoading={isInitialLoading}
              error={hasError ? networkError : null}
              isEmpty={isEmpty}
            >
              {child}
            </AsyncSection>,
          )
          expect(container.textContent?.trim()).not.toBe('')
          unmount()
        }
      }
    }
  })

  it('reports a generic sentence rather than an empty panel for an unknown failure', () => {
    const unknown = new ApiError({ kind: 'unknown' })
    render(
      <AsyncSection isInitialLoading={false} error={unknown} isEmpty={false}>
        {child}
      </AsyncSection>,
    )
    expect(screen.getByText(GENERIC_MESSAGE)).toBeInTheDocument()
  })
})
