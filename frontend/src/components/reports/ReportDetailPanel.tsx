/**
 * One stored report, in full (M13.20, extended by M17).
 *
 * The panel reads the record's own endpoint rather than reusing the row that was
 * clicked, because the two can genuinely differ: a listing page is a snapshot, and
 * by the time a row is opened the report may have been regenerated, or its file
 * removed. The row's copy is kept as a fallback, though, so a failed re-read leaves
 * the operator with the metadata they already had rather than a blank panel
 * (M15.8).
 *
 * The download control appears here as well as on the row, disabled unless the
 * backend reports an artifact — including the two ways a report has none: it was
 * never completed, or its file is gone. A `failed` generation also shows the safe
 * sentence the store recorded, because "it failed" without saying why is not an
 * answer an operator can act on.
 */

import { Clock, Download, FileText, Loader2, User } from 'lucide-react'
import { AsyncSection, Spinner } from '@/components/AsyncState'
import { useAsyncResource } from '@/hooks'
import { fetchReport } from '@/services'
import type { ApiError } from '@/services'
import { C, tint } from '@/lib/tokens'
import {
  UNKNOWN_TEXT,
  formatBytes,
  formatEpochRelative,
  formatTimestamp,
} from '@/lib/format'
import type { Report } from '@/types'
import { formatReportPeriod, formatUtcInstant } from './reportDisplay'
import { ReportStatusBadge } from './ReportStatusBadge'

/** One labelled value in the detail grid. */
function MetaField({
  label,
  value,
  mono = false,
  icon,
}: {
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

export interface ReportDetailPanelProps {
  readonly reportId: number
  /** The row that was clicked, shown until — or unless — the re-read arrives. */
  readonly fallback: Report | null
  readonly onBack: () => void
  readonly onDownload: (reportId: number) => void
  readonly isDownloading: boolean
  readonly downloadError: ApiError | null
}

export function ReportDetailPanel({
  reportId,
  fallback,
  onBack,
  onDownload,
  isDownloading,
  downloadError,
}: ReportDetailPanelProps) {
  const resource = useAsyncResource(
    (signal) => fetchReport(reportId, signal),
    [reportId],
  )
  const report = resource.data ?? fallback

  return (
    <div className="space-y-4 fade-in-up">
      <button
        onClick={onBack}
        className="flex items-center gap-2 text-sm font-medium transition-colors"
        style={{ color: C.muted }}
        onMouseEnter={(event) => (event.currentTarget.style.color = C.accent)}
        onMouseLeave={(event) => (event.currentTarget.style.color = C.muted)}
      >
        ← Back to Reports
      </button>

      {resource.blockingError !== null && report === null && (
        <div className="rounded-2xl border" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <AsyncSection
            isInitialLoading={false}
            error={resource.blockingError}
            isEmpty={false}
            errorTitle="Unable to load this report"
            onRetry={resource.reload}
            minHeight={200}
          >
            <span />
          </AsyncSection>
        </div>
      )}

      {report === null && resource.isInitialLoading && (
        <div className="rounded-2xl border" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="flex items-center justify-center gap-3 py-16">
            <Spinner size={18} />
            <span className="text-xs" style={{ color: C.faint }}>
              Loading report…
            </span>
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
                  <span
                    className="text-xs font-semibold px-2.5 py-1 rounded-full capitalize"
                    style={{ backgroundColor: tint(C.purple, 0.12), color: C.purple }}
                  >
                    {report.report_type === '' ? 'type not recorded' : report.report_type}
                  </span>
                  <span
                    className="mono text-xs px-2 py-0.5 rounded-full"
                    style={{ backgroundColor: tint(C.info, 0.12), color: C.info }}
                  >
                    {report.format === '' ? 'format not recorded' : report.format}
                  </span>
                  <ReportStatusBadge status={report.status} />
                  <span className="mono text-xs" style={{ color: C.faint }}>
                    #{report.report_id}
                  </span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => onDownload(report.report_id)}
                disabled={!report.downloadable || isDownloading}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold disabled:opacity-50 shrink-0"
                style={{ backgroundColor: tint(C.accent, 0.15), color: C.accent }}
                title={
                  report.downloadable
                    ? 'Fetch the artifact and save it with the name the backend gave it.'
                    : 'The backend holds no downloadable artifact for this report.'
                }
              >
                {isDownloading ? <Loader2 size={12} className="animate-spin" /> : <Download size={12} />}
                {isDownloading ? 'Preparing…' : 'Download'}
              </button>
            </div>

            {downloadError !== null && (
              <p className="text-xs mt-4" style={{ color: C.danger }}>
                {downloadError.userMessage}
              </p>
            )}

            {report.status === 'failed' && report.error !== null && (
              <p
                className="text-xs mt-4 px-3 py-2 rounded-xl border"
                style={{
                  backgroundColor: tint(C.danger, 0.06),
                  borderColor: tint(C.danger, 0.25),
                  color: C.muted,
                }}
              >
                {report.error}
              </p>
            )}

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 pt-6 border-t" style={{ borderColor: C.border }}>
              <MetaField
                label="Period"
                value={formatReportPeriod(report.period_start, report.period_end)}
                icon={<Clock size={11} />}
              />
              <MetaField
                label="Period start (inclusive)"
                value={formatUtcInstant(report.period_start)}
                mono
              />
              <MetaField
                label="Period end (exclusive)"
                value={formatUtcInstant(report.period_end)}
                mono
              />
              <MetaField
                label="Artifact size"
                value={report.file_size === null ? UNKNOWN_TEXT : formatBytes(report.file_size)}
              />
              <MetaField
                label="Generated at"
                value={formatTimestamp(report.generated_at)}
                icon={<Clock size={11} />}
              />
              <MetaField
                label="Age"
                value={formatEpochRelative(report.generated_at_epoch)}
                icon={<Clock size={11} />}
              />
              <MetaField
                label="Produced by"
                value={report.generated_by === null ? UNKNOWN_TEXT : `user ${report.generated_by}`}
                mono={report.generated_by !== null}
                icon={<User size={11} />}
              />
              <MetaField
                label="Artifact"
                value={report.downloadable ? 'available to download' : 'not available'}
              />
            </div>
          </div>

          <div
            className="flex items-start gap-2.5 px-4 py-3 rounded-xl border text-xs"
            style={{ backgroundColor: C.panel, borderColor: C.border, color: C.muted }}
          >
            <FileText size={13} style={{ color: C.faint, flexShrink: 0, marginTop: 1 }} />
            <span>
              These are the stored details for this report. The backend does not
              return the file&rsquo;s location — only whether an artifact is present —
              so a download is fetched by this report&rsquo;s id and saved under the name
              the backend gave it, which is {report.downloadable ? 'available now' : 'not present'}.
            </span>
          </div>
        </>
      )}
    </div>
  )
}
