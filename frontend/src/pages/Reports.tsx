/**
 * Reports — stored metadata, and an honest statement that generation does not
 * exist yet (M15.22).
 *
 * The page this replaces was fabricated end to end: a six-row history with dates,
 * sizes and a `failed` status that no table held; a "live preview" of KPIs, a
 * traffic chart, a severity breakdown and a MITRE-attributed event list, none of
 * which any endpoint returns; and three export buttons that waited 1.4 seconds
 * and then toasted about a file that was never produced. M15.22 forbids exactly
 * that, so all of it is removed rather than re-pointed at real data (M15.31).
 *
 * What M13 actually exposes is **metadata**: `GET /reports` and
 * `GET /reports/{id}` describe reports that exist — name, type, format, who
 * produced them and when. Two consequences shape this page:
 *
 * * **There is nothing to download.** No model carries a location
 *   (`app/schemas/report.py` withholds `file_path`, M13.30), so no control on this
 *   page offers a file. The row action is *details*, not *download*.
 * * **Generation refuses, and the page says so.** `POST /reports/generate`
 *   answers `501 FEATURE_NOT_IMPLEMENTED`; M17 owns the writer. The control is
 *   therefore offered so the refusal can be *shown* — an "unavailable until a
 *   later milestone" state, deliberately distinct from a red failure, because a
 *   milestone that has not been built yet is not an error.
 *
 * Reports publish no WebSocket channel, so the listing is read and refreshed
 * explicitly (M15.34).
 */

import { useMemo, useState } from 'react'
import {
  AlertTriangle, CalendarClock, Clock, FileText, RefreshCw, Search, User,
} from 'lucide-react'
import { AsyncSection, EmptyState, RefreshFailureBanner, Spinner } from '@/components/AsyncState'
import { useAsyncResource, useReports } from '@/hooks'
import { DEFAULT_PAGE_LIMIT, fetchReport } from '@/services'
import { C, tint } from '@/lib/tokens'
import {
  UNKNOWN_TEXT, formatCount, formatElapsed, formatEpochRelative, formatTimestamp,
} from '@/lib/format'
import type { Report } from '@/types'
import type { ToastMsg } from '../App'

/** How many reports one page shows. */
const PAGE_SIZE = DEFAULT_PAGE_LIMIT

/** One labelled value in the detail panel. */
function MetaField({ label, value, mono = false, icon }: {
  label: string
  value: string
  mono?: boolean
  icon?: React.ReactNode
}) {
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-1.5 text-xs mb-1" style={{ color: C.faint }}>
        {icon}
        {label}
      </div>
      <div className={`text-sm font-semibold text-white ${mono ? 'mono' : ''} wrap-break-word`}>
        {value}
      </div>
    </div>
  )
}

/**
 * The generation refusal, rendered as "not built yet" rather than as a fault.
 *
 * A `not_implemented` answer is the backend stating that a later milestone owns
 * this feature. Colouring it red would tell an operator the application is broken
 * when it is simply incomplete, so the two cases render differently and the
 * refusal carries the backend's own sentence (M15.22).
 */
function GenerationOutcome({ error, onRetry }: {
  error: import('@/services').ApiError
  onRetry: () => void
}) {
  const isUnavailable = error.kind === 'not_implemented'
  const color = isUnavailable ? C.info : C.danger
  return (
    <div className="rounded-2xl border p-4 flex items-start gap-3"
      style={{ backgroundColor: tint(color, 0.06), borderColor: tint(color, 0.25) }}>
      <div className="p-2 rounded-xl shrink-0" style={{ backgroundColor: tint(color, 0.12) }}>
        {isUnavailable
          ? <CalendarClock size={16} style={{ color }} />
          : <AlertTriangle size={16} style={{ color }} />}
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold" style={{ color }}>
          {isUnavailable ? 'Report generation is not available yet' : 'Generation request failed'}
        </p>
        <p className="text-xs mt-1" style={{ color: C.muted }}>{error.userMessage}</p>
        {isUnavailable && (
          <p className="text-xs mt-1.5" style={{ color: C.faint }}>
            The backend answered {error.status ?? 501}
            {error.code === undefined ? '' : ` (${error.code})`} because no report writer exists
            in this milestone. Report generation is owned by a later milestone, so this page shows
            stored metadata only and produces no file.
          </p>
        )}
      </div>
      {!isUnavailable && (
        <button onClick={onRetry} className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold shrink-0"
          style={{ backgroundColor: tint(color, 0.15), color }}>
          <RefreshCw size={11} /> Retry
        </button>
      )}
    </div>
  )
}

/** One stored report's metadata in full, read from `GET /reports/{id}`. */
function ReportDetailPanel({ reportId, fallback, onBack }: {
  reportId: number
  fallback: Report | null
  onBack: () => void
}) {
  const resource = useAsyncResource(
    (signal) => fetchReport(reportId, signal),
    [reportId],
  )
  const report = resource.data ?? fallback

  return (
    <div className="space-y-4 fade-in-up">
      <button onClick={onBack}
        className="flex items-center gap-2 text-sm font-medium transition-colors"
        style={{ color: C.muted }}
        onMouseEnter={e => (e.currentTarget.style.color = C.accent)}
        onMouseLeave={e => (e.currentTarget.style.color = C.muted)}>
        ← Back to Reports
      </button>

      {resource.blockingError !== null && report === null && (
        <div className="rounded-2xl border" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <AsyncSection isInitialLoading={false} error={resource.blockingError} isEmpty={false}
            errorTitle="Unable to load this report" onRetry={resource.reload} minHeight={200}>
            <span />
          </AsyncSection>
        </div>
      )}

      {report === null && resource.isInitialLoading && (
        <div className="rounded-2xl border" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="flex items-center justify-center gap-3 py-16">
            <Spinner size={18} />
            <span className="text-xs" style={{ color: C.faint }}>Loading report…</span>
          </div>
        </div>
      )}

      {report !== null && (
        <>
          <div className="rounded-2xl border p-6" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-2xl shrink-0" style={{ backgroundColor: tint(C.accent, 0.1) }}>
                <FileText size={24} style={{ color: C.accent }} />
              </div>
              <div className="min-w-0 flex-1">
                <h2 className="text-base font-bold text-white wrap-break-word">{report.name}</h2>
                <div className="flex items-center gap-2 flex-wrap mt-2">
                  <span className="text-xs font-semibold px-2.5 py-1 rounded-full capitalize"
                    style={{ backgroundColor: tint(C.purple, 0.12), color: C.purple }}>
                    {report.report_type === '' ? 'type not recorded' : report.report_type}
                  </span>
                  <span className="mono text-xs px-2 py-0.5 rounded-full"
                    style={{ backgroundColor: tint(C.info, 0.12), color: C.info }}>
                    {report.format === '' ? 'format not recorded' : report.format}
                  </span>
                  <span className="mono text-xs" style={{ color: C.faint }}>
                    #{report.report_id}
                  </span>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-4 mt-6 pt-6 border-t" style={{ borderColor: C.border }}>
              <MetaField label="Generated at" value={formatTimestamp(report.generated_at)}
                icon={<Clock size={11} />} />
              <MetaField label="Age"
                value={formatEpochRelative(report.generated_at_epoch)}
                icon={<Clock size={11} />} />
              <MetaField label="Produced by"
                value={report.generated_by === null ? UNKNOWN_TEXT : `user ${report.generated_by}`}
                mono={report.generated_by !== null} icon={<User size={11} />} />
              <MetaField label="Stored type" value={report.report_type === '' ? UNKNOWN_TEXT : report.report_type}
                mono />
            </div>
          </div>

          <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl border text-xs"
            style={{ backgroundColor: C.panel, borderColor: C.border, color: C.muted }}>
            <FileText size={13} style={{ color: C.faint, flexShrink: 0, marginTop: 1 }} />
            <span>
              These are the stored details for this report, and they are all M13 exposes. The
              backend does not return the file's location, and no report writer exists in this
              milestone, so there is no file for this page to link to or download.
            </span>
          </div>
        </>
      )}
    </div>
  )
}

/** One row of the report listing. Metadata only — no size, status or download. */
function ReportRow({ report, onOpen }: { report: Report; onOpen: () => void }) {
  const ageSeconds = report.generated_at_epoch === null
    ? null
    : Date.now() / 1000 - report.generated_at_epoch
  return (
    <tr onClick={onOpen}
      className="border-b transition-all duration-150 cursor-pointer align-middle"
      style={{ borderColor: '#1a2744' }}
      onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)')}
      onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
      <td className="pl-5 py-3 pr-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl shrink-0" style={{ backgroundColor: tint(C.accent, 0.08) }}>
            <FileText size={14} style={{ color: C.accent }} />
          </div>
          <div className="min-w-0">
            <div className="text-xs font-semibold text-white truncate max-w-70" title={report.name}>
              {report.name}
            </div>
            <div className="mono text-xs mt-0.5" style={{ color: C.faint }}>#{report.report_id}</div>
          </div>
        </div>
      </td>
      <td className="py-3 pr-4">
        <span className="text-xs font-medium capitalize px-2 py-0.5 rounded-full whitespace-nowrap"
          style={{
            backgroundColor: tint(C.purple, 0.12),
            color: C.purple,
          }}>
          {report.report_type === '' ? UNKNOWN_TEXT : report.report_type}
        </span>
      </td>
      <td className="py-3 pr-4">
        <span className="mono text-xs px-2 py-0.5 rounded-full whitespace-nowrap"
          style={{ backgroundColor: tint(C.info, 0.12), color: C.info }}>
          {report.format === '' ? UNKNOWN_TEXT : report.format}
        </span>
      </td>
      <td className="py-3 pr-4 text-xs whitespace-nowrap" style={{ color: C.muted }}>
        {formatTimestamp(report.generated_at)}
      </td>
      <td className="py-3 pr-5 text-xs whitespace-nowrap" style={{ color: C.faint }}>
        {ageSeconds === null ? UNKNOWN_TEXT : formatElapsed(ageSeconds)}
      </td>
    </tr>
  )
}
// ─── Page ────────────────────────────────────────────────────────────────────

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

  if (selected !== null) {
    return (
      <ReportDetailPanel
        reportId={selected.report_id}
        fallback={selected}
        onBack={() => setSelected(null)}
      />
    )
  }

  const reports = resource.reports
  const isFiltered = appliedType !== '' || appliedFormat !== ''

  const applyFilters = () => {
    setAppliedType(typeInput.trim())
    setAppliedFormat(formatInput.trim())
    setOffset(0)
  }

  const clearFilters = () => {
    setTypeInput('')
    setFormatInput('')
    setAppliedType('')
    setAppliedFormat('')
    setOffset(0)
  }

  const requestGeneration = () => {
    void resource.generate().then(failure => {
      // A `501` is the expected answer in this milestone, so it is reported as
      // information rather than as a failure. The panel below carries the detail;
      // the toast only confirms the request went out and came back.
      if (failure === null) {
        showToast('Generation request returned without a refusal', 'info')
        return
      }
      showToast(
        failure.kind === 'not_implemented'
          ? 'Report generation is not available yet — it is owned by a later milestone'
          : failure.userMessage,
        failure.kind === 'not_implemented' ? 'info' : 'error',
      )
    })
  }

  return (
    <div className="space-y-4">
      {/* What this page is, and what it deliberately is not. */}
      <div className="rounded-2xl border p-5" style={{ backgroundColor: C.card, borderColor: C.border }}>
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1.5">
              <FileText size={15} style={{ color: C.accent }} />
              <h1 className="text-sm font-semibold text-white">Reports</h1>
            </div>
            <p className="text-xs max-w-2xl" style={{ color: C.muted }}>
              Stored report <span className="font-semibold text-white">metadata</span> — name, type,
              format, who produced it and when. A report is described here, never served: the API
              returns no file location, and no report writer exists in this milestone.
            </p>
          </div>
          <button
            onClick={requestGeneration}
            disabled={resource.isGenerating}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border disabled:opacity-50 shrink-0"
            style={{
              borderColor: tint(C.info, 0.4),
              color: C.info,
              backgroundColor: tint(C.info, 0.06),
            }}
            title="Asks the backend to generate a report. No report writer exists yet, so the request is refused — this control exists so that refusal can be shown.">
            <RefreshCw size={12} className={resource.isGenerating ? 'animate-spin' : undefined} />
            {resource.isGenerating ? 'Requesting…' : 'Request generation'}
          </button>
        </div>
      </div>

      {resource.generationError !== null && (
        <GenerationOutcome error={resource.generationError} onRetry={requestGeneration} />
      )}

      {/* Filters — exact stored values. */}
      <form className="flex items-center gap-2 flex-wrap"
        onSubmit={event => { event.preventDefault(); applyFilters() }}>
        <div className="flex items-center gap-2 px-3 py-2 rounded-xl border min-w-45"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <Search size={12} style={{ color: C.faint }} />
          <input value={typeInput} onChange={e => setTypeInput(e.target.value)}
            placeholder="Exact report type…"
            className="bg-transparent text-xs flex-1"
            style={{ color: C.text, outline: 'none' }} />
        </div>
        <div className="flex items-center gap-2 px-3 py-2 rounded-xl border min-w-40"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <Search size={12} style={{ color: C.faint }} />
          <input value={formatInput} onChange={e => setFormatInput(e.target.value)}
            placeholder="Exact format…"
            className="bg-transparent text-xs flex-1"
            style={{ color: C.text, outline: 'none' }} />
        </div>
        <button type="submit"
          className="px-3 py-2 rounded-xl text-xs font-medium border"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
          Apply
        </button>
        {isFiltered && (
          <button type="button" onClick={clearFilters}
            className="px-3 py-2 rounded-xl text-xs font-medium border"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
            Clear
          </button>
        )}
        <button type="button" onClick={resource.reload} disabled={resource.isLoading}
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
          <RefreshCw size={12} className={resource.isLoading ? 'animate-spin' : undefined} /> Refresh
        </button>
        <span className="text-xs ml-auto" style={{ color: C.faint }}>
          Filters match stored values exactly, so an unrecognised value selects nothing.
        </span>
      </form>

      {resource.error !== null && reports.length > 0 && (
        <RefreshFailureBanner error={resource.error} onRetry={resource.reload} />
      )}

      <div className="rounded-2xl border overflow-hidden"
        style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: C.border }}>
          <div>
            <h2 className="text-sm font-semibold text-white">Stored reports</h2>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>
              {reports.length} loaded
              {resource.total === null ? '' : ` of ${formatCount(resource.total)} matching`}
              {` · rows ${offset + 1}–${offset + reports.length}`}
            </p>
          </div>
          <span className="text-xs" style={{ color: C.faint }}>
            Metadata only — no file is served
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
              hint={isFiltered
                ? 'Filters match stored values exactly. Clear them to see everything recorded.'
                : 'Report generation is owned by a later milestone, so nothing has been recorded yet.'}
              icon={isFiltered ? <Search size={28} /> : <FileText size={28} />}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b" style={{ borderColor: C.border }}>
                    <th className="text-left pl-5 py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Report</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Type</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Format</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Generated at</th>
                    <th className="text-left py-2.5 pr-5 text-xs font-medium" style={{ color: C.dim }}>Age</th>
                  </tr>
                </thead>
                <tbody>
                  {reports.map(report => (
                    <ReportRow key={report.report_id} report={report}
                      onOpen={() => setSelected(report)} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AsyncSection>

        <div className="flex items-center justify-between px-5 py-3 border-t" style={{ borderColor: C.border }}>
          <button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            disabled={offset === 0 || resource.isLoading}
            className="px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            Previous
          </button>
          <span className="text-xs" style={{ color: C.faint }}>
            {offset === 0 && !resource.hasMore ? 'All matching reports' : `Offset ${offset}`}
          </span>
          <button onClick={() => setOffset(offset + PAGE_SIZE)}
            disabled={!resource.hasMore || resource.isLoading}
            className="px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            Next
          </button>
        </div>
      </div>

      <p className="text-xs px-1" style={{ color: C.faint }}>
        Selecting a row reads that report's own metadata record. A value of {UNKNOWN_TEXT} means the
        backend recorded nothing for that field — a report produced before this instance was
        started, for instance, has no recorded producer.
      </p>
    </div>
  )
}
