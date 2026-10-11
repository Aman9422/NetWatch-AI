/**
 * What a generation request produced (M17.12/M17.14).
 *
 * Two outcomes, and the difference between them is the point of the panel:
 *
 * * **A report was generated.** The stored metadata is shown with the summary
 *   block the artifact itself opens with, so an operator can read what the report
 *   *says* — its period, its headline figures — without downloading the file it
 *   just asked for. Both come from the same assembly, so what is shown here and
 *   what is printed inside the document cannot disagree (M17.12).
 * * **The request was refused.** The backend's own sentence is rendered as-is,
 *   because it is the only text that names the field that failed. A `400` here is
 *   the backend doing its job — a `DOCX` request, a custom report with half a
 *   period — so it is reported as a refused request rather than as a broken
 *   application, and no retry button is offered for something a retry cannot fix.
 *
 * A `500` is different again and is worded as a failure: the generation was
 * attempted and did not finish, so the report exists in the store marked `failed`
 * with no file. The panel says so and points at the row rather than implying the
 * attempt left no trace.
 */

import { AlertTriangle, CalendarClock, CheckCircle2, FileText, XCircle } from 'lucide-react'
import type { ApiError } from '@/services'
import { C, tint } from '@/lib/tokens'
import { formatBytes } from '@/lib/format'
import type { GeneratedReport } from '@/types'
import { formatReportPeriod } from './reportDisplay'
import { ReportStatusBadge } from './ReportStatusBadge'

/** A heading and a body line for one outcome, so the shapes stay consistent. */
function OutcomeHeader({
  color,
  title,
  detail,
  icon,
}: {
  color: string
  title: string
  detail: string
  icon: React.ReactNode
}) {
  return (
    <div className="flex items-start gap-3">
      <div className="p-2 rounded-xl shrink-0" style={{ backgroundColor: tint(color, 0.12) }}>
        {icon}
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold" style={{ color }}>
          {title}
        </p>
        <p className="text-xs mt-1" style={{ color: C.muted }}>
          {detail}
        </p>
      </div>
    </div>
  )
}

/**
 * One request that was refused, drawn as the refusal it is.
 *
 * The distinction the panel keeps is between "the backend said no to what I asked
 * for" (`400`, the caller's own input, fixable here) and "the generation was
 * attempted and failed" (`500`, a fault that left a `failed` row behind). Colour
 * and wording follow that split; neither case claims the other's meaning.
 */
export function GenerationRefusal({ error }: { error: ApiError }) {
  const isRefusal = error.kind === 'validation'
  const isMissing = error.kind === 'not_found'
  const color = isRefusal ? C.warning : C.danger
  const title = isRefusal
    ? 'The backend refused that request'
    : isMissing
      ? 'Nothing was generated'
      : 'Generation failed'

  const detail = isRefusal
    ? 'Nothing was created or stored — the request was rejected before any file was written. The message above names the value to change.'
    : isMissing
      ? 'The backend could not produce the report.'
      : 'The attempt was recorded as a failed report with no file. It appears in the listing below marked failed.'

  return (
    <div
      className="rounded-2xl border p-4"
      style={{ backgroundColor: tint(color, 0.06), borderColor: tint(color, 0.25) }}
      role="status"
    >
      <OutcomeHeader
        color={color}
        title={title}
        detail={detail}
        icon={isRefusal ? <AlertTriangle size={16} style={{ color }} /> : <XCircle size={16} style={{ color }} />}
      />
      <p className="text-xs mt-3 pl-11 wrap-break-word" style={{ color: C.text }}>
        {error.userMessage}
      </p>
      {error.fieldDetails.length > 0 && (
        <ul className="text-xs mt-2 pl-11 space-y-0.5 mono" style={{ color: C.faint }}>
          {error.fieldDetails.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

/**
 * One report that was generated, with the figures it opens with.
 *
 * The summary is rendered exactly as the backend supplied it: the labels and the
 * already-formatted values, in the backend's order. Re-formatting a number here
 * would be a second implementation of the report's own arithmetic (M15.9).
 */
export function GenerationSuccess({
  generated,
  onDownload,
  isDownloading,
  downloadError,
}: {
  generated: GeneratedReport
  onDownload: (reportId: number) => void
  isDownloading: boolean
  downloadError: ApiError | null
}) {
  const report = generated.report

  return (
    <div
      className="rounded-2xl border p-4 space-y-3"
      style={{ backgroundColor: tint(C.success, 0.05), borderColor: tint(C.success, 0.25) }}
      role="status"
    >
      <OutcomeHeader
        color={C.success}
        title="Report generated"
        detail={`Stored as report #${report.report_id}. Its period is ${formatReportPeriod(
          report.period_start,
          report.period_end,
        )}.`}
        icon={<CheckCircle2 size={16} style={{ color: C.success }} />}
      />

      <div className="flex items-center gap-3 flex-wrap pl-11">
        <ReportStatusBadge status={report.status} />
        <span className="text-xs" style={{ color: C.faint }}>
          {report.format === '' ? 'format not recorded' : report.format}
        </span>
        <span className="text-xs" style={{ color: C.faint }}>
          {report.file_size === null
            ? 'size not recorded'
            : formatBytes(report.file_size)}
        </span>
        <button
          type="button"
          onClick={() => onDownload(report.report_id)}
          disabled={!report.downloadable || isDownloading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold disabled:opacity-50"
          style={{ backgroundColor: tint(C.accent, 0.15), color: C.accent }}
          title={
            report.downloadable
              ? 'Fetch the artifact and save it with the name the backend gave it.'
              : 'The backend reports no artifact for this row, so there is nothing to fetch.'
          }
        >
          <FileText size={12} />
          {isDownloading ? 'Preparing…' : 'Download'}
        </button>
      </div>

      {downloadError !== null && (
        <p className="text-xs pl-11" style={{ color: C.danger }}>
          {downloadError.userMessage}
        </p>
      )}

      {generated.summary.length > 0 && (
        <div className="pl-11">
          <p className="text-xs mb-2 flex items-center gap-1.5" style={{ color: C.faint }}>
            <CalendarClock size={11} />
            The figures this report opens with
          </p>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-2">
            {generated.summary.map((metric) => (
              <div key={metric.label} className="min-w-0">
                <div className="text-xs" style={{ color: C.faint }}>
                  {metric.label}
                </div>
                <div className="text-sm font-semibold text-white wrap-break-word">
                  {metric.value}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
