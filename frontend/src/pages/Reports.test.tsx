/**
 * Reports — generate, list and download (M15.22, M15.38 "Pages", completed by M17).
 *
 * The M15 version of this suite asserted the page's *absences*, because that was
 * the honest state of the feature: no file could be downloaded and generation
 * could only be refused. M17 built both, so the absences are gone and the
 * assertions are now about behaviour that has to actually work:
 *
 * * **A download happens, with the backend's own filename.** The bytes are checked
 *   to have reached the browser, not merely that a request went out — a page that
 *   fetched a file and dropped it would otherwise pass.
 * * **A download is offered only where the store holds a file.** `downloadable` is
 *   what decides, so a row the backend says has no artifact gets a disabled
 *   control rather than a hopeful one.
 * * **Generation sends the documented defaults, and only what was chosen.** A
 *   preset and bounds are mutually exclusive (M17.6), and the custom pair is
 *   converted to half-open UTC bounds, which is checked on the wire.
 *
 * As in the rest of this suite, requests are asserted on the wire as well as the
 * rendering, because a page that paints plausible metadata from a payload it never
 * asked for would otherwise pass.
 */

import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { DEFAULT_PAGE_LIMIT, NETWORK_MESSAGE } from '@/services'
import { UNKNOWN_TEXT } from '@/lib/format'
import type { GeneratedReport, Report, ReportList } from '@/types'
import Reports from '@/pages/Reports'
import {
  CUSTOM_FROM_LABEL,
  CUSTOM_TO_LABEL,
} from '@/components/reports/GenerationForm'
import { failure, installFetch, ok } from '@/test/harness'

/** One report as M17.9 reports it, with everything settable for a given case. */
function report(overrides: Partial<Report> = {}): Report {
  return {
    report_id: 7,
    name: 'Weekly traffic summary',
    report_type: 'daily',
    format: 'PDF',
    generated_by: 3,
    generated_at: '2026-10-10T09:00:00+00:00',
    // Now, so the age column reads "just now" whatever the wall clock says.
    generated_at_epoch: Date.now() / 1000,
    period_start: '2026-10-09T00:00:00+00:00',
    period_end: '2026-10-10T00:00:00+00:00',
    period_start_epoch: Date.UTC(2026, 9, 9) / 1000,
    period_end_epoch: Date.UTC(2026, 9, 10) / 1000,
    status: 'completed',
    file_size: 20_480,
    error: null,
    downloadable: true,
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

/** One generated report, as `POST /reports/generate` answers (M17.12). */
function generated(overrides: Partial<Report> = {}, metrics = true): GeneratedReport {
  return {
    report: report(overrides),
    summary: metrics
      ? [
          { label: 'Total packets stored', value: '1,234' },
          { label: 'Total bytes stored', value: '2.4 MB' },
        ]
      : [],
  }
}

/** A file response, as the download route serves one (M17.11). */
function fileResponse(
  body = 'PDFBYTES',
  filename = 'netwatch-report-000007-daily-2026-10-09.pdf',
): Response {
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${filename}"`,
    },
  })
}

/** The object-URL and anchor-click surface jsdom does not implement. */
interface SaveHarness {
  readonly createObjectURL: ReturnType<typeof vi.fn>
  readonly clickedAnchors: HTMLAnchorElement[]
}

/**
 * Make `saveBlob` able to run in a test, and record what it handed over.
 *
 * jsdom has no download manager, so `URL.createObjectURL` is absent and clicking an
 * anchor with a `blob:` href would attempt a navigation it cannot perform. Both are
 * supplied here: the URL factory records the blob, and the click is captured so the
 * `download` attribute — the backend's filename — can be asserted.
 */
function installSaveHarness(): SaveHarness {
  const createObjectURL = vi.fn((_blob: Blob) => 'blob:netwatch-test')
  const revokeObjectURL = vi.fn((_url: string) => {})
  Object.defineProperty(URL, 'createObjectURL', {
    value: createObjectURL,
    configurable: true,
    writable: true,
  })
  Object.defineProperty(URL, 'revokeObjectURL', {
    value: revokeObjectURL,
    configurable: true,
    writable: true,
  })

  const clickedAnchors: HTMLAnchorElement[] = []
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
    this: HTMLAnchorElement,
  ) {
    clickedAnchors.push(this)
  })

  return { createObjectURL, clickedAnchors }
}

/**
 * Undo {@link installSaveHarness}, so no other suite inherits the stubs.
 *
 * `createObjectURL` is removed, because that is exactly what makes `canSaveFiles()`
 * false again — the honest answer for a runner with no download manager.
 * `revokeObjectURL` is left as a no-op instead, because `saveBlob` releases its
 * object URL on a one-second timer: deleting the method would turn that late
 * callback into a thrown `TypeError`, raised long after the test that caused it had
 * finished and in whatever test happened to be running.
 */
function removeSaveHarness(): void {
  Reflect.deleteProperty(URL, 'createObjectURL')
  Object.defineProperty(URL, 'revokeObjectURL', {
    value: () => {},
    configurable: true,
    writable: true,
  })
}

/** Render the page with a toast recorder. */
function renderPage() {
  const showToast = vi.fn()
  const view = render(<Reports showToast={showToast} />)
  return { ...view, showToast }
}

/** The generation form, found by the button that submits it. */
function generationForm(): HTMLFormElement {
  const form = screen
    .getByRole('button', { name: /generate report/i })
    .closest('form')
  if (form === null) throw new Error('the generation form was not rendered')
  return form as HTMLFormElement
}

/** The filters form, found by one of its own inputs. */
function filterForm(): HTMLFormElement {
  const form = screen.getByPlaceholderText(/exact report type/i).closest('form')
  if (form === null) throw new Error('the filter form was not rendered')
  return form as HTMLFormElement
}

afterEach(removeSaveHarness)

describe('Reports listing requests', () => {
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
    const router = installFetch({ 'GET /reports': () => ok(reportList([report()])) })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(1)
    })
    fireEvent.change(screen.getByPlaceholderText(/exact report type/i), {
      target: { value: 'daily' },
    })
    expect(router.countOf('GET /reports')).toBe(1)
    expect(router.lastCall('GET /reports')?.params['report_type']).toBeUndefined()
  })

  it('sends the applied filters to the backend and restarts the window', async () => {
    const router = installFetch({ 'GET /reports': () => ok(reportList([report()])) })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(1)
    })

    fireEvent.change(screen.getByPlaceholderText(/exact report type/i), {
      target: { value: 'daily' },
    })
    fireEvent.change(screen.getByPlaceholderText(/exact format/i), {
      target: { value: 'PDF' },
    })
    fireEvent.submit(filterForm())

    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(2)
    })
    const call = router.lastCall('GET /reports')
    expect(call?.params['report_type']).toBe('daily')
    expect(call?.params['format']).toBe('PDF')
    expect(call?.params['offset']).toBe('0')
  })
})

describe('Reports rendering', () => {
  it('renders the stored fields of a generated report, including its period', async () => {
    installFetch({ 'GET /reports': () => ok(reportList([report()])) })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })
    // Scoped to the table, because the generation form above also renders the word
    // `PDF` — as the format choice, which is a different fact from the format a
    // stored row holds. An unscoped query would match both and prove neither.
    const table = within(screen.getByRole('table'))
    expect(table.getByText('daily')).toBeInTheDocument()
    expect(table.getByText('PDF')).toBeInTheDocument()
    expect(table.getByText('#7')).toBeInTheDocument()
    expect(table.getByText('completed')).toBeInTheDocument()
    // The half-open period, both bounds, in UTC and not in the viewer's locale: a
    // UTC day rendered through the local clock could look like it spans two dates,
    // and two consecutive daily reports would then appear to overlap.
    expect(
      table.getByText('2026-10-09 00:00 UTC → 2026-10-10 00:00 UTC'),
    ).toBeInTheDocument()
    expect(table.getByText('20 KB')).toBeInTheDocument()
    expect(table.getByText('just now')).toBeInTheDocument()
    // A row offers a way to fetch the artifact, and says which report it means.
    expect(table.getByLabelText('Download report 7')).toBeEnabled()
  })

  it('renders the unknown marker for a field the backend recorded nothing for', async () => {
    // A pre-M17 row has no period and no size; blank cells read as a rendering bug,
    // the marker reads as an answer.
    installFetch({
      'GET /reports': () =>
        ok(
          reportList([
            report({
              report_type: '',
              format: '',
              generated_at_epoch: null,
              period_start: null,
              period_end: null,
              file_size: null,
              status: '',
            }),
          ]),
        ),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })
    expect(screen.getAllByText(UNKNOWN_TEXT).length).toBeGreaterThanOrEqual(3)
    expect(screen.getByText('state not recorded')).toBeInTheDocument()
  })

  it('counts the loaded page and names the stored total separately', async () => {
    installFetch({ 'GET /reports': () => ok(reportList([report()], { total: 137 })) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/of 137 matching/i)).toBeInTheDocument()
    })
    expect(screen.getByText(/rows 1–1/)).toBeInTheDocument()
  })
})

describe('Reports downloading (M17.11)', () => {
  it('offers a download only for a row the backend reports as downloadable', async () => {
    installFetch({
      'GET /reports': () =>
        ok(
          reportList([
            report({ report_id: 7, name: 'Downloadable', downloadable: true }),
            report({
              report_id: 8,
              name: 'File removed',
              status: 'completed',
              downloadable: false,
            }),
          ]),
        ),
    })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Downloadable')).toBeInTheDocument()
    })
    expect(screen.getByLabelText('Download report 7')).toBeEnabled()
    // A `completed` row with a missing file must not offer a control whose next
    // request would be a 404.
    expect(screen.getByLabelText('Download report 8')).toBeDisabled()
  })

  it('fetches the artifact by id and hands the browser the backend filename', async () => {
    const save = installSaveHarness()
    const router = installFetch({
      'GET /reports': () => ok(reportList([report()])),
      'GET /reports/7/download': () => fileResponse('PDFBYTES'),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByLabelText('Download report 7'))

    await waitFor(() => {
      expect(router.countOf('GET /reports/7/download')).toBe(1)
    })
    await waitFor(() => {
      expect(save.createObjectURL).toHaveBeenCalledTimes(1)
    })

    // The bytes, not just the request: a page that fetched a file and dropped it
    // would otherwise pass this test.
    const blob = save.createObjectURL.mock.calls[0]?.[0] as Blob
    expect(await blob.text()).toBe('PDFBYTES')
    // And the artifact's own name, which is what stops two daily reports from
    // overwriting each other in the operator's downloads folder.
    expect(save.clickedAnchors[0]?.download).toBe(
      'netwatch-report-000007-daily-2026-10-09.pdf',
    )
  })

  it('reports a refusal and saves nothing when the artifact is gone', async () => {
    const save = installSaveHarness()
    const router = installFetch({
      'GET /reports': () => ok(reportList([report()])),
      'GET /reports/7/download': () =>
        failure(404, 'The report file is not available for download', [
          { field: 'report_id', code: 'REPORT_NOT_FOUND' },
        ]),
    })
    const { showToast } = renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByLabelText('Download report 7'))

    await waitFor(() => {
      expect(router.countOf('GET /reports/7/download')).toBe(1)
    })
    await waitFor(() => {
      expect(showToast).toHaveBeenCalledWith(
        'The report file is not available for download',
        'error',
      )
    })
    expect(save.createObjectURL).not.toHaveBeenCalled()
    // The listing is untouched: a failed download is not a failed page.
    expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
  })

  it('names the report being fetched while the download is in flight', async () => {
    installSaveHarness()
    // A queue rather than a bare `let`: the resolver is assigned inside the promise
    // executor, which TypeScript's flow analysis does not follow, so a plain
    // variable would still be narrowed to `null` at the call below.
    const pending: Array<() => void> = []
    installFetch({
      'GET /reports': () => ok(reportList([report()])),
      'GET /reports/7/download': () =>
        new Promise<Response>((resolve) => {
          pending.push(() => resolve(fileResponse()))
        }),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByLabelText('Download report 7'))

    await waitFor(() => {
      expect(screen.getByText(/Fetching report #7/)).toBeInTheDocument()
    })

    const settle = pending[0]
    if (settle === undefined) throw new Error('the download was never awaited')
    settle()
    // The header names the report only while its bytes are in flight; a busy state
    // that never cleared would otherwise leave the listing claiming a fetch that
    // had finished.
    await waitFor(() => {
      expect(
        screen.getByText(/Download is offered only where the store holds a file/),
      ).toBeInTheDocument()
    })
  })
})
describe('Reports generation (M17.4–M17.6, M17.12)', () => {
  it('sends the documented defaults when nothing was chosen', async () => {
    const router = installFetch({
      'GET /reports': () => ok(reportList([])),
      'POST /reports/generate': () => ok(generated()),
    })
    const { showToast } = renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(1)
    })

    fireEvent.submit(generationForm())

    await waitFor(() => {
      expect(router.countOf('POST /reports/generate')).toBe(1)
    })
    // The backend's own defaults, stated rather than left implicit: the previous
    // completed UTC day, as a PDF. What the form sends is therefore checkable, and
    // a default that changed server-side would show up here rather than as a
    // surprise in a downloaded file.
    expect(router.lastCall('POST /reports/generate')?.body).toEqual({
      report_type: 'daily',
      format: 'PDF',
    })
    await waitFor(() => {
      expect(showToast).toHaveBeenCalledWith('Report generated and stored', 'success')
    })
  })

  it('sends the weekly preset with no bounds of its own', async () => {
    const router = installFetch({
      'GET /reports': () => ok(reportList([])),
      'POST /reports/generate': () => ok(generated()),
    })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(1)
    })

    fireEvent.click(screen.getByRole('button', { name: 'Previous week' }))
    fireEvent.submit(generationForm())

    await waitFor(() => {
      expect(router.countOf('POST /reports/generate')).toBe(1)
    })
    // A preset derives its period from the UTC calendar, so it carries no bounds:
    // the two are mutually exclusive and the backend refuses a request that is both
    // (M17.6). Sending one anyway would be a request built to be rejected.
    expect(router.lastCall('POST /reports/generate')?.body).toEqual({
      report_type: 'weekly',
      format: 'PDF',
    })
  })

  it('sends CSV when CSV was chosen', async () => {
    const router = installFetch({
      'GET /reports': () => ok(reportList([])),
      'POST /reports/generate': () => ok(generated({ format: 'CSV' })),
    })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(1)
    })

    fireEvent.click(screen.getByRole('button', { name: 'CSV' }))
    fireEvent.submit(generationForm())

    await waitFor(() => {
      expect(router.countOf('POST /reports/generate')).toBe(1)
    })
    expect(router.lastCall('POST /reports/generate')?.body).toEqual({
      report_type: 'daily',
      format: 'CSV',
    })
  })

  it('reveals the custom days only for a custom period', async () => {
    installFetch({ 'GET /reports': () => ok(reportList([])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/No reports stored/)).toBeInTheDocument()
    })

    // A preset has no days to name, so the fields are not merely empty — they are
    // absent, which is what makes "preset or bounds, never both" visible.
    expect(screen.queryByLabelText(CUSTOM_FROM_LABEL)).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Custom range' }))
    expect(screen.getByLabelText(CUSTOM_FROM_LABEL)).toBeInTheDocument()
    expect(screen.getByLabelText(CUSTOM_TO_LABEL)).toBeInTheDocument()
  })

  it('refuses a half-named period without asking the backend', async () => {
    const router = installFetch({
      'GET /reports': () => ok(reportList([])),
      'POST /reports/generate': () => ok(generated()),
    })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(1)
    })

    fireEvent.click(screen.getByRole('button', { name: 'Custom range' }))
    fireEvent.submit(generationForm())

    expect(
      await screen.findByText('A custom report needs both a first and a last day.'),
    ).toBeInTheDocument()
    // Nothing was asked of the backend. The form can see this itself, and a round
    // trip to be told what it already knows is not a validation strategy — though
    // the backend's own refusal is still what decides when a request is sent.
    expect(router.countOf('POST /reports/generate')).toBe(0)
  })

  it('turns the chosen inclusive days into half-open UTC bounds', async () => {
    const router = installFetch({
      'GET /reports': () => ok(reportList([])),
      'POST /reports/generate': () => ok(generated({ report_type: 'custom' })),
    })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(1)
    })

    fireEvent.click(screen.getByRole('button', { name: 'Custom range' }))
    fireEvent.change(screen.getByLabelText(CUSTOM_FROM_LABEL), {
      target: { value: '2026-10-01' },
    })
    fireEvent.change(screen.getByLabelText(CUSTOM_TO_LABEL), {
      target: { value: '2026-10-03' },
    })
    fireEvent.change(screen.getByPlaceholderText(/defaults to the period/i), {
      target: { value: '  October review  ' },
    })
    fireEvent.submit(generationForm())

    await waitFor(() => {
      expect(router.countOf('POST /reports/generate')).toBe(1)
    })
    // The operator names the last day they want *included*, so its exclusive bound
    // is the following midnight: two consecutive custom reports then cannot count
    // the same record twice (M17.5). The title is trimmed, because a trailing space
    // is not part of a name.
    expect(router.lastCall('POST /reports/generate')?.body).toEqual({
      report_type: 'custom',
      format: 'PDF',
      since: '2026-10-01T00:00:00+00:00',
      until: '2026-10-04T00:00:00+00:00',
      title: 'October review',
    })
  })

  it('renders the figures the artifact opens with, without a download', async () => {
    installFetch({
      'GET /reports': () => ok(reportList([])),
      'POST /reports/generate': () => ok(generated()),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/No reports stored/)).toBeInTheDocument()
    })

    fireEvent.submit(generationForm())

    await waitFor(() => {
      expect(screen.getByText('Report generated')).toBeInTheDocument()
    })
    // The stored metadata and the report's own opening figures, from the same
    // assembly — so the summary on screen and the one printed inside the file
    // cannot disagree (M17.12).
    expect(screen.getByText(/Stored as report #7/)).toBeInTheDocument()
    expect(screen.getByText('The figures this report opens with')).toBeInTheDocument()
    expect(screen.getByText('Total packets stored')).toBeInTheDocument()
    expect(screen.getByText('1,234')).toBeInTheDocument()
    expect(screen.getByText('Total bytes stored')).toBeInTheDocument()
    expect(screen.getByText('2.4 MB')).toBeInTheDocument()
  })

  it('renders a refused request as the backend sentence and writes nothing', async () => {
    const router = installFetch({
      'GET /reports': () => ok(reportList([])),
      'POST /reports/generate': () =>
        failure(400, 'The format must be one of PDF, CSV.', [
          { field: 'format', code: 'INVALID_FORMAT' },
        ]),
    })
    const { showToast } = renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(1)
    })

    fireEvent.submit(generationForm())

    await waitFor(() => {
      expect(screen.getByText('The backend refused that request')).toBeInTheDocument()
    })
    // The backend's own sentence, because it is the only text that names the field
    // that failed.
    expect(screen.getByText('The format must be one of PDF, CSV.')).toBeInTheDocument()
    expect(screen.getByText('format: INVALID_FORMAT')).toBeInTheDocument()
    expect(screen.queryByText('Report generated')).toBeNull()
    // A 400 is the caller's own input, so it is reported as information rather than
    // as a fault: nothing was written and nothing broke.
    expect(showToast).toHaveBeenCalledWith('The format must be one of PDF, CSV.', 'info')
    // A refused request produced no row, so the listing is not re-read.
    expect(router.countOf('GET /reports')).toBe(1)
  })

  it('renders a failure as a row the store kept and marked failed', async () => {
    installFetch({
      'GET /reports': () => ok(reportList([])),
      'POST /reports/generate': () =>
        failure(500, 'The report could not be generated.'),
    })
    const { showToast } = renderPage()
    await waitFor(() => {
      expect(screen.getByText(/No reports stored/)).toBeInTheDocument()
    })

    fireEvent.submit(generationForm())

    await waitFor(() => {
      expect(screen.getByText('Generation failed')).toBeInTheDocument()
    })
    // Different from a refusal, and the panel says which: a 500 was attempted and
    // left a row behind rather than being rejected before anything happened.
    expect(
      screen.getByText(/recorded as a failed report with no file/),
    ).toBeInTheDocument()
    expect(showToast).toHaveBeenCalledWith('The report could not be generated.', 'error')
  })

  it('re-reads the listing so the new row appears without a manual refresh', async () => {
    let listingReads = 0
    const router = installFetch({
      'GET /reports': () => {
        listingReads += 1
        return ok(
          listingReads === 1 ? reportList([]) : reportList([report({ name: 'Daily report 2026-10-09' })]),
        )
      },
      'POST /reports/generate': () => ok(generated()),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/No reports stored/)).toBeInTheDocument()
    })

    fireEvent.submit(generationForm())

    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(2)
    })
    // The row comes from the store's answer and not from the request: generation is
    // never optimistic, because a row the store does not hold would put a download
    // control on screen for an artifact that does not exist.
    await waitFor(() => {
      expect(screen.getByText('Daily report 2026-10-09')).toBeInTheDocument()
    })
  })

  it('dismisses the summary without dismissing the stored report', async () => {
    installFetch({
      'GET /reports': () => ok(reportList([report()])),
      'POST /reports/generate': () => ok(generated()),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    fireEvent.submit(generationForm())
    await waitFor(() => {
      expect(screen.getByText('Report generated')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /dismiss this summary/i }))

    expect(screen.queryByText('Report generated')).toBeNull()
    // Dismissing is about the panel, not about the report: the row is unchanged.
    expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
  })

  it('keeps the form usable while a generation is in flight and names the wait', async () => {
    const pending: Array<() => void> = []
    installFetch({
      'GET /reports': () => ok(reportList([])),
      'POST /reports/generate': () =>
        new Promise<Response>((resolve) => {
          pending.push(() => resolve(ok(generated())))
        }),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/No reports stored/)).toBeInTheDocument()
    })

    fireEvent.submit(generationForm())

    // The submit control reports the wait and refuses a second request, so a double
    // click cannot ask for the same report twice.
    const submit = await screen.findByRole('button', { name: /generating/i })
    expect(submit).toBeDisabled()

    const settle = pending[0]
    if (settle === undefined) throw new Error('the generation was never awaited')
    settle()
    await waitFor(() => {
      expect(screen.getByText('Report generated')).toBeInTheDocument()
    })
  })
})
describe('Reports states (M15.8)', () => {
  it('shows a loading panel while the first page is in flight', async () => {
    const pending: Array<() => void> = []
    installFetch({
      'GET /reports': () =>
        new Promise<Response>((resolve) => {
          pending.push(() => resolve(ok(reportList([report()]))))
        }),
    })
    renderPage()

    // The panel names what is being waited for rather than showing a bare spinner:
    // "loading" and "the store holds nothing" must never look the same (M15.8).
    expect(screen.getByText('Loading report metadata…')).toBeInTheDocument()

    const settle = pending[0]
    if (settle === undefined) throw new Error('the listing was never awaited')
    settle()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })
  })

  it('distinguishes an empty store from a filter that matched nothing', async () => {
    const router = installFetch({ 'GET /reports': () => ok(reportList([])) })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('No reports stored')).toBeInTheDocument()
    })
    expect(
      screen.getByText(/Nothing has been generated yet/),
    ).toBeInTheDocument()

    fireEvent.change(screen.getByPlaceholderText(/exact report type/i), {
      target: { value: 'weekly' },
    })
    fireEvent.submit(filterForm())

    await waitFor(() => {
      expect(screen.getByText('No reports match the filter')).toBeInTheDocument()
    })
    // The two empties are different facts — nothing exists, versus nothing matched —
    // and the second one says how to get back to everything.
    expect(
      screen.getByText(/Clear them to see everything recorded/),
    ).toBeInTheDocument()
    expect(router.lastCall('GET /reports')?.params['report_type']).toBe('weekly')

    fireEvent.click(screen.getByRole('button', { name: 'Clear' }))

    await waitFor(() => {
      expect(screen.getByText('No reports stored')).toBeInTheDocument()
    })
    expect(router.lastCall('GET /reports')?.params['report_type']).toBeUndefined()
  })

  it('renders an unreachable backend as an error with a retry, never as an empty store', async () => {
    installFetch({
      'GET /reports': () => {
        throw new TypeError('fetch failed: ECONNREFUSED')
      },
    })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Unable to load reports')).toBeInTheDocument()
    })
    expect(screen.getByText(NETWORK_MESSAGE)).toBeInTheDocument()
    // A transport failure is retryable, so the offer is made; an empty store would
    // have said "No reports stored" and offered nothing.
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
    expect(screen.queryByText('No reports stored')).toBeNull()
  })

  it('recovers when the retry succeeds', async () => {
    let attempt = 0
    const router = installFetch({
      'GET /reports': () => {
        attempt += 1
        if (attempt === 1) throw new TypeError('fetch failed: ECONNREFUSED')
        return ok(reportList([report()]))
      },
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Unable to load reports')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /retry/i }))

    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })
    expect(router.countOf('GET /reports')).toBe(2)
  })

  it('keeps the rows on screen when a refresh fails', async () => {
    let attempt = 0
    const router = installFetch({
      'GET /reports': () => {
        attempt += 1
        if (attempt === 1) return ok(reportList([report()]))
        throw new TypeError('fetch failed: ECONNREFUSED')
      },
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /refresh/i }))

    await waitFor(() => {
      expect(screen.getByText(/may be out of date/i)).toBeInTheDocument()
    })
    expect(router.countOf('GET /reports')).toBe(2)
    // The failed refresh is reported *beside* the rows rather than replacing them:
    // blanking a table on a failed reload is the flicker M15.8 forbids.
    expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    expect(screen.queryByText('Unable to load reports')).toBeNull()
  })

  it('pages with the same window size and moves the offset', async () => {
    const router = installFetch({
      'GET /reports': () => ok(reportList([report()], { has_more: true, total: 137 })),
    })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(1)
    })

    expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))

    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(2)
    })
    expect(router.lastCall('GET /reports')?.params['limit']).toBe(String(DEFAULT_PAGE_LIMIT))
    expect(router.lastCall('GET /reports')?.params['offset']).toBe(String(DEFAULT_PAGE_LIMIT))
    expect(screen.getByText('Offset 50')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Previous' }))

    await waitFor(() => {
      expect(router.countOf('GET /reports')).toBe(3)
    })
    expect(router.lastCall('GET /reports')?.params['offset']).toBe('0')
  })

  it('offers no further page when the store says there is none', async () => {
    installFetch({ 'GET /reports': () => ok(reportList([report()], { has_more: false })) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    // Driven by the backend's own `has_more`, not by "the page came back full":
    // a store holding exactly one page must not offer a next one.
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
    expect(screen.getByText('All matching reports')).toBeInTheDocument()
  })
})
describe('Report detail (M13.20, extended by M17)', () => {
  it('reads the record itself rather than reusing the row that was clicked', async () => {
    const router = installFetch({
      'GET /reports': () => ok(reportList([report()])),
      'GET /reports/7': () =>
        ok(report({ name: 'Weekly traffic summary (regenerated)' })),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Weekly traffic summary'))

    await waitFor(() => {
      expect(router.countOf('GET /reports/7')).toBe(1)
    })
    // A listing is a snapshot and the record is the store's own answer, which is
    // why the panel re-reads instead of reusing the row.
    expect(
      await screen.findByText('Weekly traffic summary (regenerated)'),
    ).toBeInTheDocument()
  })

  it('shows the period, the size, who produced it and whether a file is present', async () => {
    installFetch({
      'GET /reports': () => ok(reportList([report()])),
      'GET /reports/7': () => ok(report()),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Weekly traffic summary'))

    expect(await screen.findByText('Period start (inclusive)')).toBeInTheDocument()
    expect(screen.getByText('Period end (exclusive)')).toBeInTheDocument()
    expect(screen.getByText('Produced by')).toBeInTheDocument()
    expect(screen.getByText('user 3')).toBeInTheDocument()
    expect(screen.getByText('20 KB')).toBeInTheDocument()
    // Both the half-open range and each bound, because a reader comparing two daily
    // reports needs to see that the periods do not overlap.
    expect(
      screen.getByText('2026-10-09 00:00 UTC → 2026-10-10 00:00 UTC'),
    ).toBeInTheDocument()
    expect(screen.getByText('available to download')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Download' })).toBeEnabled()
  })

  it('says plainly when there is no artifact, and why it failed', async () => {
    installFetch({
      'GET /reports': () =>
        ok(
          reportList([
            report({
              status: 'failed',
              file_size: null,
              error: 'The PDF renderer refused the report content.',
              downloadable: false,
            }),
          ]),
        ),
      'GET /reports/7': () => ok(report()),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Weekly traffic summary'))

    expect(await screen.findByText('not available')).toBeInTheDocument()
    // The failed row now reports the fresh record, which is `completed` and
    // downloadable: the panel states the store's answer, not the clicked row's.
    expect(screen.getByRole('button', { name: 'Download' })).toBeEnabled()
  })

  it('renders the sentence the store recorded for a failed generation', async () => {
    const failed = report({
      status: 'failed',
      file_size: null,
      error: 'The PDF renderer refused the report content.',
      downloadable: false,
    })
    installFetch({
      'GET /reports': () => ok(reportList([failed])),
      'GET /reports/7': () => ok(failed),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Weekly traffic summary'))

    // "It failed" without saying why is not an answer an operator can act on, so
    // the store's own sentence is shown as-is.
    expect(
      await screen.findByText('The PDF renderer refused the report content.'),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Download' })).toBeDisabled()
  })

  it('keeps the clicked row’s metadata when the re-read fails', async () => {
    installFetch({
      'GET /reports': () => ok(reportList([report()])),
      'GET /reports/7': () =>
        failure(404, 'That report is not stored.', [
          { field: 'report_id', code: 'REPORT_NOT_FOUND' },
        ]),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Weekly traffic summary'))

    // A failed re-read is not a blank panel: the operator keeps the metadata they
    // already had rather than losing it to a 404 (M15.8).
    await waitFor(() => {
      expect(screen.getByText('Period start (inclusive)')).toBeInTheDocument()
    })
    expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    expect(
      screen.getByText('2026-10-09 00:00 UTC → 2026-10-10 00:00 UTC'),
    ).toBeInTheDocument()
    // The fallback is not an error: nothing failed from the operator's point of
    // view, so no error panel is drawn over the metadata that did arrive.
    expect(screen.queryByText('Unable to load this report')).toBeNull()
  })

  it('goes back to the listing', async () => {
    installFetch({
      'GET /reports': () => ok(reportList([report()])),
      'GET /reports/7': () => ok(report()),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Weekly traffic summary'))
    await screen.findByText('Period start (inclusive)')

    fireEvent.click(screen.getByRole('button', { name: /back to reports/i }))

    expect(screen.getByText('Stored reports')).toBeInTheDocument()
    expect(screen.queryByText('Period start (inclusive)')).toBeNull()
  })

  it('downloads from the panel under the name the backend declared', async () => {
    const save = installSaveHarness()
    const router = installFetch({
      'GET /reports': () => ok(reportList([report()])),
      'GET /reports/7': () => ok(report()),
      'GET /reports/7/download': () => fileResponse('PANELBYTES'),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Weekly traffic summary')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('Weekly traffic summary'))
    await screen.findByText('Period start (inclusive)')

    fireEvent.click(screen.getByRole('button', { name: 'Download' }))

    await waitFor(() => {
      expect(router.countOf('GET /reports/7/download')).toBe(1)
    })
    await waitFor(() => {
      expect(save.createObjectURL).toHaveBeenCalledTimes(1)
    })
    const blob = save.createObjectURL.mock.calls[0]?.[0] as Blob
    expect(await blob.text()).toBe('PANELBYTES')
    expect(save.clickedAnchors[0]?.download).toBe(
      'netwatch-report-000007-daily-2026-10-09.pdf',
    )
  })
})
