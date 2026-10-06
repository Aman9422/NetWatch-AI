/**
 * Reports — stored metadata only (M15.22, M15.38 "Pages").
 *
 * This page is where M15.22 is most easily got wrong, so the tests check the
 * *absences* as carefully as the render:
 *
 * * **No report is ever offered as a file.** The row action opens details, not a
 *   download, and no control on the page promises one — the API carries no
 *   location for a file to point at.
 * * **A `501` is not a failure.** Generation is M17's, so the control exists only
 *   so the refusal can be *shown*; the refusal must render as "not available yet"
 *   and toast as information, never as a red error with a retry.
 *
 * As in the Devices suite, the requests are asserted on the wire as well as the
 * rendering, because a page that paints plausible metadata from a payload it never
 * asked for would otherwise pass.
 */

import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { DEFAULT_PAGE_LIMIT, NETWORK_MESSAGE } from '@/services'
import { UNKNOWN_TEXT } from '@/lib/format'
import type { Report, ReportList } from '@/types'
import Reports from '@/pages/Reports'
import { failure, installFetch, networkDownFetch, ok, type RoutedCall } from '@/test/harness'

/** One report as M13.20 reports it, with everything settable for a given case. */
function report(overrides: Partial<Report> = {}): Report {
  return {
    report_id: 7,
    name: 'Weekly traffic summary',
    report_type: 'traffic',
    format: 'PDF',
    generated_by: 3,
    generated_at: '2026-01-01T10:00:00+00:00',
    // Now, so the age column reads "just now" whatever the wall clock says.
    generated_at_epoch: Date.now() / 1000,
    ...overrides,
  }
}

/** A page of report metadata as the listing endpoint answers. */
function reportList(
  reports: readonly Report[],
  overrides: Partial<ReportList> = {},
): ReportList {
  return {
    count: reports.length,
    total: reports.length,
    limit: DEFAULT_PAGE_LIMIT,
    offset: 0,
    has_more: false,
    reports,
    ...overrides,
  }
}

/** Render the page with a toast recorder. */
function renderPage() {
  const showToast = vi.fn()
  const view = render(<Reports showToast={showToast} />)
  return { ...view, showToast }
}

describe('Reports requesting', () => {
  it('asks for one page of stored metadata with the configured window', async () => {
    const router = installFetch({ 'GET /reports': () => ok(reportList([report()])) })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(1)
    })
    const call = router.lastCall('GET /reports')
    expect(call?.params['limit']).toBe(String(DEFAULT_PAGE_LIMIT))
    expect(call?.params['offset']).toBe('0')
  })

  it('sends no type or format filter while none has been applied', async () => {
    // The inputs are free text and only reach the backend on submit; typing alone
    // must not narrow the request.
    const router = installFetch({ 'GET /reports': () => ok(reportList([report()])) })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(1)
    })
    fireEvent.change(screen.getByPlaceholderText(/exact report type/i), {
      target: { value: 'traffic' },
    })
    expect(router.countOf('GET /reports')).toBe(1)
    expect(router.lastCall('GET /reports')?.params['report_type']).toBeUndefined()
  })

  it('sends the applied filters to the backend and restarts the window', async () => {
    // M13.20 filters by exact stored value server-side, so applying one must be a
    // request rather than a narrowing of the loaded page.
    const router = installFetch({ 'GET /reports': () => ok(reportList([report()])) })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(1)
    })

    fireEvent.change(screen.getByPlaceholderText(/exact report type/i), {
      target: { value: 'traffic' },
    })
    fireEvent.change(screen.getByPlaceholderText(/exact format/i), {
      target: { value: 'PDF' },
    })
    const form = screen.getByPlaceholderText(/exact report type/i).closest('form')
    expect(form).not.toBeNull()
    fireEvent.submit(form as HTMLFormElement)

    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(2)
    })
    const call = router.lastCall('GET /reports')
    expect(call?.params['report_type']).toBe('traffic')
    expect(call?.params['format']).toBe('PDF')
    // The window restarts, so the operator does not land on page 3 of a new filter.
    expect(call?.params['offset']).toBe('0')
  })
})

describe('Reports rendering', () => {
  it('renders the stored fields of a real report', async () => {
    installFetch({ 'GET /reports': () => ok(reportList([report()])) })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })
    expect(screen.getByText('traffic')).toBeInTheDocument()
    expect(screen.getByText('PDF')).toBeInTheDocument()
    expect(screen.getByText('#7')).toBeInTheDocument()
    // The age column, derived from the epoch form M13.26 sends.
    expect(screen.getByText('just now')).toBeInTheDocument()
  })

  it('offers no download, because the API carries no file to download', async () => {
    // M15.22: the honest state is "metadata only". A download control would be a
    // promise no endpoint can keep.
    installFetch({ 'GET /reports': () => ok(reportList([report()])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })
    expect(screen.queryByRole('button', { name: /download/i })).toBeNull()
    expect(screen.queryByText(/download/i)).toBeNull()
    expect(screen.getByText(/no file is served/i)).toBeInTheDocument()
  })

  it('counts the loaded page and names the stored total separately', async () => {
    // Showing the page count as the total would misreport a paged listing.
    installFetch({
      'GET /reports': () => ok(reportList([report()], { total: 137 })),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/of 137 matching/i)).toBeInTheDocument()
    })
    expect(screen.getByText(/rows 1–1/)).toBeInTheDocument()
  })

  it('renders the unknown marker for a field the backend recorded nothing for', async () => {
    // A blank cell reads as a rendering bug; the marker reads as an answer. The
    // row shows two fields that can be unrecorded, so both are checked.
    installFetch({
      'GET /reports': () =>
        ok(reportList([report({ report_type: '', format: '', generated_at_epoch: null })])),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })
    expect(screen.getAllByText(UNKNOWN_TEXT).length).toBeGreaterThanOrEqual(2)
  })
})

describe('Reports loading, empty and error states', () => {
  it('shows a busy panel while the first request is in flight', () => {
    installFetch({ 'GET /reports': () => new Promise<Response>(() => {}) })
    renderPage()
    expect(screen.getByText('Loading report metadata…')).toBeInTheDocument()
  })

  it('shows the empty state and explains why nothing is stored', async () => {
    installFetch({ 'GET /reports': () => ok(reportList([])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('No reports stored')).toBeInTheDocument()
    })
    expect(screen.getByText(/owned by a later milestone/i)).toBeInTheDocument()
  })

  it('says the filter matched nothing rather than claiming nothing is stored', async () => {
    const router = installFetch({
      'GET /reports': (call: RoutedCall) =>
        ok(reportList(call.params['report_type'] === 'traffic' ? [] : [report()])),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    const form = screen.getByPlaceholderText(/exact report type/i).closest('form')
    fireEvent.change(screen.getByPlaceholderText(/exact report type/i), {
      target: { value: 'traffic' },
    })
    fireEvent.submit(form as HTMLFormElement)

    await waitFor(() => {
      expect(screen.getByText('No reports match the filter')).toBeInTheDocument()
    })
    expect(screen.queryByText('No reports stored')).toBeNull()
    expect(router.countOf('GET /reports')).toBe(2)
  })

  it('shows a usable error panel when the backend cannot be reached', async () => {
    vi.stubGlobal('fetch', networkDownFetch())
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Unable to load reports')).toBeInTheDocument()
    })
    expect(screen.getByText(NETWORK_MESSAGE)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('does not report a failed request as an empty store', async () => {
    vi.stubGlobal('fetch', networkDownFetch())
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Unable to load reports')).toBeInTheDocument()
    })
    expect(screen.queryByText('No reports stored')).toBeNull()
  })

  it('re-requests the listing when the operator retries', async () => {
    let failNext = true
    const router = installFetch({
      'GET /reports': () => {
        if (failNext) {
          failNext = false
          return failure(503, '', [{ field: 'service', code: 'SERVICE_UNAVAILABLE' }])
        }
        return ok(reportList([report()]))
      },
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /retry/i }))

    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })
    expect(router.countOf('GET /reports')).toBe(2)
  })

  it('keeps the loaded rows and warns they may be stale when a refresh fails', async () => {
    let failNext = false
    installFetch({
      'GET /reports': () =>
        failNext
          ? failure(500, 'The server failed while handling this request.', [
              { field: 'request', code: 'INTERNAL_ERROR' },
            ])
          : ok(reportList([report()])),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    failNext = true
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }))

    await waitFor(() => {
      expect(screen.getByText(/may be out of date/i)).toBeInTheDocument()
    })
    expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
  })
})

describe('Reports generation refusal (M15.22)', () => {
  /** The `501` body the backend returns for an unbuilt feature. */
  const refusal = () =>
    failure(501, 'Report generation is not implemented.', [
      { field: 'report', code: 'FEATURE_NOT_IMPLEMENTED' },
    ])

  it('shows the backend refusal as "not available yet", not as a fault', async () => {
    installFetch({
      'GET /reports': () => ok(reportList([])),
      'POST /reports/generate': refusal,
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('No reports stored')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /request generation/i }))

    await waitFor(() => {
      expect(screen.getByText('Report generation is not available yet')).toBeInTheDocument()
    })
    // It names the milestone boundary and the backend's own answer.
    expect(screen.getByText(/The backend answered 501/)).toBeInTheDocument()
    // A phrase unique to this panel: both the page header and the empty-state
    // hint mention the milestone, so the assertion is scoped to the refusal's own
    // sentence about what it will not do.
    expect(
      screen.getByText(/stored metadata only and produces no file/i),
    ).toBeInTheDocument()
  })

  it('does not render the refusal as a failure with a retry', async () => {
    // A milestone that has not been built is not an error, so a red retry panel
    // would tell the operator the application is broken.
    installFetch({
      'GET /reports': () => ok(reportList([])),
      'POST /reports/generate': refusal,
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('No reports stored')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /request generation/i }))

    await waitFor(() => {
      expect(screen.getByText('Report generation is not available yet')).toBeInTheDocument()
    })
    expect(screen.queryByText(/Generation request failed/i)).toBeNull()
  })

  it('reports the refusal through a toast as information', async () => {
    installFetch({
      'GET /reports': () => ok(reportList([])),
      'POST /reports/generate': refusal,
    })
    const { showToast } = renderPage()
    await waitFor(() => {
      expect(screen.getByText('No reports stored')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /request generation/i }))

    await waitFor(() => {
      expect(showToast).toHaveBeenCalledWith(
        'Report generation is not available yet — it is owned by a later milestone',
        'info',
      )
    })
  })
})

describe('Reports detail and paging', () => {
  it('opens a report’s own metadata and returns to the listing', async () => {
    const router = installFetch({
      'GET /reports': () => ok(reportList([report()])),
      'GET /reports/7': () =>
        ok(report({ name: 'Weekly traffic summary', generated_by: null, format: 'CSV' })),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    const row = screen.getByText('Weekly traffic summary').closest('tr')
    expect(row).not.toBeNull()
    fireEvent.click(row as HTMLElement)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /back to reports/i })).toBeInTheDocument()
    })
    // The detail read is the record's own endpoint, not a re-read of the listing.
    expect(router.countOf('GET /reports/7')).toBe(1)
    await waitFor(() => {
      expect(screen.getByText('CSV')).toBeInTheDocument()
    })
    expect(screen.getByText(/does not return the file's location/i)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /back to reports/i }))
    await waitFor(() => {
      expect(screen.getByText('Stored reports')).toBeInTheDocument()
    })
  })

  it('keeps the row’s metadata on screen when the detail request fails', async () => {
    // The listing row already carried the metadata, so a failed re-read must not
    // blank the panel (M15.8).
    installFetch({
      'GET /reports': () => ok(reportList([report()])),
      'GET /reports/7': () =>
        failure(500, 'The server failed while handling this request.', [
          { field: 'request', code: 'INTERNAL_ERROR' },
        ]),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Weekly traffic summary').closest('tr') as HTMLElement)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /back to reports/i })).toBeInTheDocument()
    })
    expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    expect(screen.queryByText('Unable to load this report')).toBeNull()
  })

  it('offers no next page when the store reported no more rows', async () => {
    installFetch({ 'GET /reports': () => ok(reportList([report()], { has_more: false })) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('All matching reports')).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: /next/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /previous/i })).toBeDisabled()
  })

  it('pages forward by the page size when more rows exist', async () => {
    const router = installFetch({
      'GET /reports': (call: RoutedCall) =>
        call.params['offset'] === '0'
          ? ok(reportList([report()], { has_more: true, total: 120 }))
          : ok(
              reportList([report({ report_id: 8, name: 'Monthly summary' })], {
                offset: DEFAULT_PAGE_LIMIT,
                has_more: false,
                total: 120,
              }),
            ),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /next/i })).toBeEnabled()
    })

    fireEvent.click(screen.getByRole('button', { name: /next/i }))

    await waitFor(() => {
      expect(screen.getByText('Monthly summary')).toBeInTheDocument()
    })
    expect(router.lastCall('GET /reports')?.params['offset']).toBe(String(DEFAULT_PAGE_LIMIT))
  })
})
