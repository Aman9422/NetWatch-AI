/**
 * Report service (M13.20, M15.22).
 *
 * Read-only over the `reports` table, which stores report **metadata**. There is
 * no report writer in this application, so this module deliberately exposes no
 * "generate" or "download" helper that could imply one:
 *
 * * `POST /reports/generate` answers `501 FEATURE_NOT_IMPLEMENTED`, and
 *   {@link requestReportGeneration} exists only so a page can *show* that
 *   refusal. It never resolves with a report.
 * * No response carries a file location. `file_path` is omitted from every wire
 *   model (`app/schemas/report.py`), because it is an internal filesystem path
 *   and M13.30 forbids exposing one.
 *
 * The UI must not fabricate a downloadable report (M15.22): M17 owns report
 * generation, and until it exists the honest answer is "not available yet".
 */

import { apiGet, apiPost } from './client'
import { ReportPaths } from './endpoints'
import { withPageWindow, type PageWindow } from './query'
import type { Report, ReportList } from '@/types'

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
 * `POST /api/v1/reports/generate` — always refuses in this milestone.
 *
 * Kept as a named function rather than omitted so a page can offer the control
 * and then render the backend's own `501` sentence. It rejects with an
 * {@link import('./errors').ApiError} whose `kind` is `not_implemented`, so the
 * caller can render an "unavailable until a later milestone" state instead of a
 * generic failure.
 */
export function requestReportGeneration(signal?: AbortSignal): Promise<never> {
  return apiPost<never>(ReportPaths.generate, { signal })
}
