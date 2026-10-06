/**
 * Stored report metadata (M15.22).
 *
 * This hook reads and nothing else, and that restraint is the point. There is no
 * report writer in this application, so it deliberately does **not** offer a
 * "generate" or "download" that could imply one:
 *
 * * {@link ReportResource.generate} posts to `POST /reports/generate` **only so
 *   the refusal can be shown**. It never resolves with a report; the backend
 *   answers `501 FEATURE_NOT_IMPLEMENTED`, and the page renders "not available
 *   until a later milestone" rather than a fake file.
 * * No model carries a location, so {@link ReportResource.reports} cannot leak a
 *   filesystem path (`app/schemas/report.py`), and nothing here invents one.
 *
 * M17 owns report generation. Until it exists the honest answer is "unavailable",
 * which is exactly what this hook lets a page say.
 */

import { useCallback, useMemo } from 'react'
import { requestReportGeneration, fetchReports } from '@/services'
import type { ApiError, PageWindow, ReportQuery } from '@/services'
import type { Report, ReportList } from '@/types'
import { useAction } from './useAction'
import { useAsyncResource } from './useAsyncResource'

/** Options for {@link useReports}. */
export interface ReportOptions {
  /** Filters to apply. Compared by value, so it may be built inline. */
  readonly query?: ReportQuery
  /** Page window. Compared by value. */
  readonly window?: PageWindow
  readonly enabled?: boolean
}

/** What {@link useReports} returns. */
export interface ReportResource {
  readonly reports: readonly Report[]
  readonly page: ReportList | null
  /** The true match count across every page, or `null` when uncountable. */
  readonly total: number | null
  readonly hasMore: boolean
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  /** True when the store holds no report for this filter. */
  readonly isEmpty: boolean
  readonly reload: () => void
  /** True while the generation request is in flight. */
  readonly isGenerating: boolean
  /**
   * The last generation refusal, or `null`.
   *
   * Expected to be a `not_implemented` error — M17 owns generation — so the page
   * reads `kind` and renders an "unavailable" state rather than a red failure.
   */
  readonly generationError: ApiError | null
  /** Ask the backend to generate a report. Always refuses in this milestone. */
  readonly generate: () => Promise<ApiError | null>
}

/**
 * Read stored report metadata.
 *
 * @param options Filters, page window, and whether to read at all.
 */
export function useReports(options: ReportOptions = {}): ReportResource {
  const { query, window, enabled = true } = options

  const cacheKey = useMemo(
    () =>
      JSON.stringify({
        report_type: query?.report_type ?? null,
        format: query?.format ?? null,
        limit: window?.limit ?? null,
        offset: window?.offset ?? null,
      }),
    [query, window],
  )

  const resource = useAsyncResource(
    (signal) => fetchReports(query ?? {}, window, signal),
    [cacheKey],
    { enabled, isEmpty: (page: ReportList) => page.reports.length === 0 },
  )

  const generateAction = useAction(requestReportGeneration)

  const generate = useCallback(async (): Promise<ApiError | null> => {
    const outcome = await generateAction.run()
    // `requestReportGeneration` is typed `Promise<never>`, so a success branch
    // cannot occur — the call always throws a `501`. The refusal is returned for
    // the page to render; there is no report to hand back.
    return outcome.ok ? null : outcome.error
  }, [generateAction])

  return {
    reports: resource.data?.reports ?? [],
    page: resource.data,
    total: resource.data?.total ?? null,
    hasMore: resource.data?.has_more === true,
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    isEmpty: resource.data !== null && resource.data.reports.length === 0,
    reload: resource.reload,
    isGenerating: generateAction.isRunning,
    generationError: generateAction.error,
    generate,
  }
}
