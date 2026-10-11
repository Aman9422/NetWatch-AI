/**
 * Reports — generate, list and download (M15.22, completed by M17).
 *
 * The page this replaces could only *describe* reports. M13 exposed metadata and
 * nothing else: no artifact could be downloaded, and generation answered
 * `501 FEATURE_NOT_IMPLEMENTED`, so the page offered a control whose only possible
 * outcome was a refusal — deliberately, because M15.22 forbids inventing the file.
 * M17 built the writer, so all three things now exist and the page does all three:
 *
 * * **Generate.** One form covering daily, weekly and custom (M17.4/M17.6). The
 *   preset and the bounds are mutually exclusive and the form never sends both,
 *   because the backend refuses a request that tries to be.
 * * **Read.** The stored listing, unchanged in shape from M13.20 but now carrying
 *   the period, the artifact size and the generation state a report needs to be
 *   told apart from its neighbours.
 * * **Download.** Offered *only* for a row the backend reports as downloadable
 *   (M17.11). The file is fetched by the report's id and saved under the name the
 *   backend declared, so a client never learns — or needs — a directory (M13.30).
 *
 * What the page still does not do is guess. A generation that failed is rendered
 * as a failed report with the store's own sentence; a refusal is rendered as the
 * backend's sentence naming the field to change; a download the backend says is
 * unavailable is a disabled control, not a hopeful click.
 *
 * Reports publish no WebSocket channel, so nothing here is live: the listing is
 * read, refreshed and re-read after a generation (M15.34).
 */

import { useMemo, useState } from 'react'
import { FileText, RefreshCw, Search } from 'lucide-react'
import { AsyncSection, EmptyState, RefreshFailureBanner } from '@/components/AsyncState'
import { useReports } from '@/hooks'
import { DEFAULT_PAGE_LIMIT } from '@/services'
import { C, tint } from '@/lib/tokens'
import { UNKNOWN_TEXT, formatCount } from '@/lib/format'
import { GenerationForm } from '@/components/reports/GenerationForm'
import { GenerationRefusal, GenerationSuccess } from '@/components/reports/GenerationOutcome'
import { ReportDetailPanel } from '@/components/reports/ReportDetailPanel'
import { ReportRow } from '@/components/reports/ReportRow'
import type { Report, ReportGenerationRequest } from '@/types'
import type { ToastMsg } from '../App'

/** How many reports one page shows. */
const PAGE_SIZE = DEFAULT_PAGE_LIMIT

interface Props {
  showToast: (msg: string, type?: ToastMsg['type']) => void
}

export default function Reports({ showToast }: Props) {
  const [selected, setSelected] = useState<Report | null>(null)
  const [typeInput, setTypeInput] = useState('')
  const [formatInput, setFormatInput] = useState('')
  const [appliedType, setAppliedType] = useState('')
  const [appliedFormat, setAppliedFormat] = useState('')
  const [offset, setOffset] = useState(0)

  // Filtering is by *exact stored value* (M13.20), so the inputs are free text
  // rather than a dropdown of guessed values: offering a list of types this
  // client invented would invite a filter that matches nothing.
  const query = useMemo(() => {
    const built: { report_type?: string; format?: string } = {}
    if (appliedType !== '') built.report_type = appliedType
    if (appliedFormat !== '') built.format = appliedFormat
    return built
  }, [appliedType, appliedFormat])

  const window = useMemo(() => ({ limit: PAGE_SIZE, offset }), [offset])
  const resource = useReports({ query, window })

  const requestGeneration = (request: ReportGenerationRequest): void => {
    void resource.generate(request).then((failure) => {
      if (failure === null) {
        showToast('Report generated and stored', 'success')
        return
      }
      // A refused request is the operator's own input, so it is reported as
      // information rather than as a fault — nothing was written, nothing broke.
      showToast(
        failure.userMessage,
        failure.kind === 'validation' ? 'info' : 'error',
      )
    })
  }

  const requestDownload = (reportId: number): void => {
    void resource.download(reportId).then((failure) => {
      showToast(
        failure === null ? `Report ${reportId} saved` : failure.userMessage,
        failure === null ? 'success' : 'error',
      )
    })
  }

  if (selected !== null) {
    return (
      <ReportDetailPanel
        reportId={selected.report_id}
        fallback={selected}
        onBack={() => setSelected(null)}
        onDownload={requestDownload}
        isDownloading={resource.downloadingId === selected.report_id}
        downloadError={resource.downloadError}
      />
    )
  }

  const reports = resource.reports
  const isFiltered = appliedType !== '' || appliedFormat !== ''

  const applyFilters = (): void => {
    setAppliedType(typeInput.trim())
    setAppliedFormat(formatInput.trim())
    setOffset(0)
  }

  const clearFilters = (): void => {
    setTypeInput('')
    setFormatInput('')
    setAppliedType('')
    setAppliedFormat('')
    setOffset(0)
  }

  return (
    <div className="space-y-4">
      {/* What this page is, and what it now can do. */}
      <div className="rounded-2xl border p-5" style={{ backgroundColor: C.card, borderColor: C.border }}>
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1.5">
              <FileText size={15} style={{ color: C.accent }} />
              <h1 className="text-sm font-semibold text-white">Reports</h1>
            </div>
            <p className="text-xs max-w-2xl" style={{ color: C.muted }}>
              Generate a report over a bounded period and read or download what the
              store holds. A report is written once and kept: the listing below is
              the store&rsquo;s own record of every report produced, with the period it
              covers and whether its file is still available.
            </p>
          </div>
          <button
            type="button"
            onClick={resource.reload}
            disabled={resource.isLoading}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border disabled:opacity-50 shrink-0"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}
          >
            <RefreshCw size={12} className={resource.isLoading ? 'animate-spin' : undefined} />
            Refresh
          </button>
        </div>
      </div>

      <GenerationForm isSubmitting={resource.isGenerating} onSubmit={requestGeneration} />

      {resource.generationError !== null && (
        <GenerationRefusal error={resource.generationError} />
      )}

      {resource.generationError === null && resource.generated !== null && (
        <div className="space-y-2">
          <GenerationSuccess
            generated={resource.generated}
            onDownload={requestDownload}
            isDownloading={resource.downloadingId === resource.generated.report.report_id}
            downloadError={resource.downloadError}
          />
          <button
            type="button"
            onClick={resource.clearGenerated}
            className="text-xs font-medium px-1"
            style={{ color: C.faint }}
          >
            Dismiss this summary
          </button>
        </div>
      )}

      {/* Filters — exact stored values. */}
      <form
        className="flex items-center gap-2 flex-wrap"
        onSubmit={(event) => {
          event.preventDefault()
          applyFilters()
        }}
      >
        <div
          className="flex items-center gap-2 px-3 py-2 rounded-xl border min-w-45"
          style={{ backgroundColor: C.card, borderColor: C.border }}
        >
          <Search size={12} style={{ color: C.faint }} />
          <input
            value={typeInput}
            onChange={(event) => setTypeInput(event.target.value)}
            placeholder="Exact report type…"
            className="bg-transparent text-xs flex-1"
            style={{ color: C.text, outline: 'none' }}
          />
        </div>
        <div
          className="flex items-center gap-2 px-3 py-2 rounded-xl border min-w-40"
          style={{ backgroundColor: C.card, borderColor: C.border }}
        >
          <Search size={12} style={{ color: C.faint }} />
          <input
            value={formatInput}
            onChange={(event) => setFormatInput(event.target.value)}
            placeholder="Exact format…"
            className="bg-transparent text-xs flex-1"
            style={{ color: C.text, outline: 'none' }}
          />
        </div>
        <button
          type="submit"
          className="px-3 py-2 rounded-xl text-xs font-medium border"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}
        >
          Apply
        </button>
        {isFiltered && (
          <button
            type="button"
            onClick={clearFilters}
            className="px-3 py-2 rounded-xl text-xs font-medium border"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}
          >
            Clear
          </button>
        )}
        <span className="text-xs ml-auto" style={{ color: C.faint }}>
          Filters match stored values exactly, so an unrecognised value selects nothing.
        </span>
      </form>

      {resource.error !== null && reports.length > 0 && (
        <RefreshFailureBanner error={resource.error} onRetry={resource.reload} />
      )}

      <div
        className="rounded-2xl border overflow-hidden"
        style={{
          backgroundColor: C.card,
          borderColor: C.border,
          boxShadow: '0 4px 24px rgba(0,0,0,0.2)',
        }}
      >
        <div
          className="flex items-center justify-between px-5 py-4 border-b"
          style={{ borderColor: C.border }}
        >
          <div>
            <h2 className="text-sm font-semibold text-white">Stored reports</h2>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>
              {reports.length} loaded
              {resource.total === null ? '' : ` of ${formatCount(resource.total)} matching`}
              {` · rows ${offset + 1}–${offset + reports.length}`}
            </p>
          </div>
          <span className="text-xs" style={{ color: C.faint }}>
            {resource.downloadingId === null
              ? 'Download is offered only where the store holds a file'
              : `Fetching report #${resource.downloadingId}…`}
          </span>
        </div>

        <AsyncSection
          isInitialLoading={resource.isInitialLoading}
          error={resource.blockingError}
          isEmpty={false}
          loadingLabel="Loading report metadata…"
          errorTitle="Unable to load reports"
          onRetry={resource.reload}
          minHeight={240}
        >
          {reports.length === 0 ? (
            <EmptyState
              title={isFiltered ? 'No reports match the filter' : 'No reports stored'}
              hint={
                isFiltered
                  ? 'Filters match stored values exactly. Clear them to see everything recorded.'
                  : 'Nothing has been generated yet. Use the form above to produce one.'
              }
              icon={isFiltered ? <Search size={28} /> : <FileText size={28} />}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b" style={{ borderColor: C.border }}>
                    <th className="text-left pl-5 py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>
                      Report
                    </th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>
                      Type
                    </th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>
                      Format
                    </th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>
                      Period (half-open)
                    </th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>
                      Generated
                    </th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>
                      Size
                    </th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>
                      Status
                    </th>
                    <th className="text-right py-2.5 pr-5 text-xs font-medium" style={{ color: C.dim }}>
                      File
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {reports.map((report) => (
                    <ReportRow
                      key={report.report_id}
                      report={report}
                      onOpen={() => setSelected(report)}
                      onDownload={requestDownload}
                      isDownloading={resource.downloadingId === report.report_id}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AsyncSection>

        <div
          className="flex items-center justify-between px-5 py-3 border-t"
          style={{ borderColor: C.border }}
        >
          <button
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            disabled={offset === 0 || resource.isLoading}
            className="px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}
          >
            Previous
          </button>
          <span className="text-xs" style={{ color: C.faint }}>
            {offset === 0 && !resource.hasMore ? 'All matching reports' : `Offset ${offset}`}
          </span>
          <button
            onClick={() => setOffset(offset + PAGE_SIZE)}
            disabled={!resource.hasMore || resource.isLoading}
            className="px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}
          >
            Next
          </button>
        </div>
      </div>

      <p className="text-xs px-1" style={{ color: C.faint }}>
        Selecting a row reads that report&rsquo;s own metadata record. A value of {UNKNOWN_TEXT} means
        the backend recorded nothing for that field — a report produced before this
        instance was started has no recorded period or size.
      </p>
    </div>
  )
}
