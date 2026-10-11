/**
 * One stored report, as a listing row (M13.20, extended by M17).
 *
 * The row states what the store holds — period, size, generation state — and
 * offers a download *only when the backend said one would succeed*. That
 * conditional is the whole reason `downloadable` exists on the wire: a `completed`
 * row whose file was deleted by hand must not present a control whose next request
 * would be a `404`.
 *
 * The download control stops its click from reaching the row, because the row's own
 * click opens the detail panel. Without that, asking for the file would also
 * navigate — two actions from one gesture, and the wrong one first.
 *
 * Every cell clips rather than overflowing, so a long report name or a long period
 * cannot push the table wider than its container.
 */

import { Download, FileText, Loader2 } from 'lucide-react'
import { C, tint } from '@/lib/tokens'
import { UNKNOWN_TEXT, formatBytes, formatElapsed, formatTimestamp } from '@/lib/format'
import type { Report } from '@/types'
import { formatReportPeriod } from './reportDisplay'
import { ReportStatusBadge } from './ReportStatusBadge'

export interface ReportRowProps {
  readonly report: Report
  /** Open this report's detail panel. */
  readonly onOpen: () => void
  /** Fetch and save this report's artifact. */
  readonly onDownload: (reportId: number) => void
  /** True while *this* report's artifact is being fetched. */
  readonly isDownloading: boolean
}

export function ReportRow({ report, onOpen, onDownload, isDownloading }: ReportRowProps) {
  const ageSeconds =
    report.generated_at_epoch === null ? null : Date.now() / 1000 - report.generated_at_epoch

  return (
    <tr
      className="border-b transition-all duration-150 align-middle"
      style={{ borderColor: '#1a2744' }}
      onMouseEnter={(event) => (event.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)')}
      onMouseLeave={(event) => (event.currentTarget.style.backgroundColor = 'transparent')}
    >
      <td className="pl-5 py-3 pr-4">
        <button
          type="button"
          onClick={onOpen}
          className="flex items-center gap-3 text-left w-full"
          title="Open this report's stored metadata"
        >
          <div className="p-2 rounded-xl shrink-0" style={{ backgroundColor: tint(C.accent, 0.08) }}>
            <FileText size={14} style={{ color: C.accent }} />
          </div>
          <div className="min-w-0">
            <div className="text-xs font-semibold text-white truncate max-w-70" title={report.name}>
              {report.name}
            </div>
            <div className="mono text-xs mt-0.5" style={{ color: C.faint }}>
              #{report.report_id}
            </div>
          </div>
        </button>
      </td>
      <td className="py-3 pr-4">
        <span
          className="text-xs font-medium capitalize px-2 py-0.5 rounded-full whitespace-nowrap"
          style={{ backgroundColor: tint(C.purple, 0.12), color: C.purple }}
        >
          {report.report_type === '' ? UNKNOWN_TEXT : report.report_type}
        </span>
      </td>
      <td className="py-3 pr-4">
        <span
          className="mono text-xs px-2 py-0.5 rounded-full whitespace-nowrap"
          style={{ backgroundColor: tint(C.info, 0.12), color: C.info }}
        >
          {report.format === '' ? UNKNOWN_TEXT : report.format}
        </span>
      </td>
      <td className="py-3 pr-4 text-xs whitespace-nowrap" style={{ color: C.muted }}>
        {formatReportPeriod(report.period_start, report.period_end)}
      </td>
      <td className="py-3 pr-4 text-xs whitespace-nowrap" style={{ color: C.muted }}>
        {formatTimestamp(report.generated_at)}
        <span className="ml-2" style={{ color: C.faint }}>
          {ageSeconds === null ? UNKNOWN_TEXT : formatElapsed(ageSeconds)}
        </span>
      </td>
      <td className="py-3 pr-4 text-xs whitespace-nowrap" style={{ color: C.muted }}>
        {report.file_size === null ? UNKNOWN_TEXT : formatBytes(report.file_size)}
      </td>
      <td className="py-3 pr-4">
        <ReportStatusBadge status={report.status} />
      </td>
      <td className="py-3 pr-5 text-right">
        <button
          type="button"
          onClick={(event) => {
            // The row's name cell opens the detail panel; a download must not do
            // that too, and the click is stopped before it can bubble.
            event.stopPropagation()
            onDownload(report.report_id)
          }}
          disabled={!report.downloadable || isDownloading}
          aria-label={`Download report ${report.report_id}`}
          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap"
          style={{
            borderColor: report.downloadable ? tint(C.accent, 0.4) : C.border,
            color: report.downloadable ? C.accent : C.dim,
            backgroundColor: report.downloadable ? tint(C.accent, 0.08) : 'transparent',
          }}
          title={
            report.downloadable
              ? 'Fetch the artifact and save it with the name the backend gave it.'
              : 'The backend holds no downloadable artifact for this report.'
          }
        >
          {isDownloading ? (
            <Loader2 size={11} className="animate-spin" />
          ) : (
            <Download size={11} />
          )}
          {isDownloading ? 'Preparing…' : 'Download'}
        </button>
      </td>
    </tr>
  )
}
