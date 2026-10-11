/**
 * Report service (M13.20, generation and download added by M17).
 *
 * Four surfaces over one subsystem, and the split between them is the point:
 *
 * * `GET /reports` and `GET /reports/{id}` describe reports — name, type, format,
 *   the period covered, who produced them, when, and whether their artifact can
 *   actually be served.
 * * `POST /reports/generate` produces one. It is a write: it creates a metadata
 *   row *and* a file, so it answers `201` with the stored metadata plus the
 *   summary block the artifact opens with.
 * * `GET /reports/{id}/download` serves the file itself.
 *
 * **No response carries a location.** `file_path` is omitted from every wire model
 * (`app/schemas/report.py`), because it is an internal filesystem path and M13.30
 * forbids exposing one. The artifact is fetched by the report's *id*, through the
 * download route, so a client can obtain the file without ever learning — or
 * needing — the directory it lives in. That is why {@link downloadReport} returns
 * bytes rather than a URL for a page to link to.
 *
 * **One request shape covers daily, weekly and custom.** A preset derives its
 * period from the UTC calendar and a custom report names its own bounds; the two
 * are mutually exclusive and the backend refuses a request that tries to be both
 * rather than quietly preferring one (M17.6). The service therefore sends exactly
 * what the caller supplied and lets the backend own the vocabulary — the same
 * division of responsibility the rest of this layer keeps.
 */

import { apiDownload, apiGet, apiPost } from './client'
import type { DownloadedFile } from './client'
import { ReportPaths } from './endpoints'
import { withPageWindow, type PageWindow } from './query'
import type {
  GeneratedReport,
  Report,
  ReportGenerationRequest,
  ReportList,
} from '@/types'

/**
 * How long a generation request may take.
 *
 * Longer than the fifteen seconds a read gets, because generation is not a read:
 * it resolves a period, runs several aggregate queries through the M16 analytics
 * service and renders a document (M17.12). Timing it out mid-render would abandon
 * work the backend has already started, and the stored row would be left
 * describing a file that was never finished — so the budget is generous rather
 * than tight.
 */
export const GENERATION_TIMEOUT_MS = 60_000

/** Filters accepted by `GET /api/v1/reports`. */
export interface ReportQuery {
  /** Exact stored type, e.g. `traffic`. */
  readonly report_type?: string
  /** Stored format, folded to upper case by the backend, e.g. `PDF`. */
  readonly format?: string
}

/**
 * `GET /api/v1/reports` — stored report metadata, newest first.
 *
 * Filtering is by exact stored value. An unrecognised filter selects nothing
 * rather than being translated into a known one — which is the truthful answer
 * for a value the store does not hold.
 */
export function fetchReports(
  query: ReportQuery = {},
  window?: PageWindow,
  signal?: AbortSignal,
): Promise<ReportList> {
  return apiGet<ReportList>(ReportPaths.list, withPageWindow(query, window), { signal })
}

/** `GET /api/v1/reports/{report_id}` — one stored report's metadata, or a `404`. */
export function fetchReport(reportId: number, signal?: AbortSignal): Promise<Report> {
  return apiGet<Report>(ReportPaths.detail(reportId), undefined, { signal })
}

/**
 * `POST /api/v1/reports/generate` — produce a report and record it (M17.12).
 *
 * The body is optional all the way down: an empty request produces the *previous
 * completed UTC day* as a PDF, because those are the layer's documented defaults.
 * A refusal — an unsupported type or format, a custom report with half a period,
 * a preset given bounds — arrives as a `400` naming the field that failed, so the
 * caller renders the backend's own sentence rather than a guess at what was
 * wrong.
 *
 * Nothing is sent for a field the caller did not supply: an explicit `null` would
 * be a value, and the backend validates strictly (M13.25).
 *
 * @param request The preset, the format, an optional title and the bounds a custom
 *   period needs. Every field is optional.
 * @param signal Abort signal, e.g. from a component unmounting.
 */
export function generateReport(
  request: ReportGenerationRequest = {},
  signal?: AbortSignal,
): Promise<GeneratedReport> {
  const body: Record<string, string | number> = {}
  if (request.report_type !== undefined) body.report_type = request.report_type
  if (request.format !== undefined) body.format = request.format
  if (request.title !== undefined) body.title = request.title
  if (request.generated_by !== undefined) body.generated_by = request.generated_by
  if (request.since !== undefined) body.since = request.since
  if (request.until !== undefined) body.until = request.until

  return apiPost<GeneratedReport>(ReportPaths.generate, {
    body,
    signal,
    timeoutMs: GENERATION_TIMEOUT_MS,
  })
}

/**
 * `GET /api/v1/reports/{report_id}/download` — fetch a stored artifact (M17.11).
 *
 * The response is the file itself rather than the standard envelope, so it is
 * returned as bytes with the name and media type the backend declared. A report
 * whose row exists but whose artifact does not is a `404` with the same sentence
 * whether the file was never written, was removed by hand, or is outside the
 * storage directory — all three are "not available", and none of them names a
 * path (M13.30).
 *
 * A row reports this outcome in advance through its `downloadable` field, so a
 * page can offer the control only when it would succeed; this function is what
 * happens when it is followed through.
 */
export function downloadReport(
  reportId: number,
  signal?: AbortSignal,
): Promise<DownloadedFile> {
  return apiDownload(ReportPaths.download(reportId), { signal })
}
