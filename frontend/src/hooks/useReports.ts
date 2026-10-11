/**
 * Reports: the stored listing, generation and artifact download (M15.22, M17).
 *
 * This hook is three things over one resource, and each is kept distinct because
 * they fail differently:
 *
 * * {@link ReportResource.reports} is the **read** — a page of stored metadata.
 * * {@link ReportResource.generate} is a **write** that creates a row *and* a
 *   file (M17.12). It resolves with the outcome rather than throwing, so the page
 *   must handle the refusal branch to read a value; a `400` naming a bad format
 *   is the backend doing its job, not an exception. On success the listing is
 *   reloaded, because a report the store now holds is a row the page should show.
 * * {@link ReportResource.download} is a **read of a file**, and it is the only
 *   call in this application that ends with the browser saving something. The
 *   bytes and the filename both come from the backend — nothing here invents a
 *   name, and nothing here knows a path (M13.30).
 *
 * **Generation is never optimistic.** Nothing is added to the list until the
 * backend confirms it: a report that failed to render is a row marked `failed`
 * with no file (M17.9), and guessing at one would put a download link on screen
 * for an artifact that does not exist.
 *
 * Reports publish no WebSocket channel, so the listing is read and refreshed
 * explicitly (M15.34).
 */

import { useCallback, useMemo, useState } from 'react'
import { downloadReport, fetchReports, generateReport } from '@/services'
import type { ApiError, PageWindow } from '@/services'
import { saveBlob } from '@/lib/download'
import type { GeneratedReport, Report, ReportGenerationRequest, ReportList } from '@/types'
import { useAction } from './useAction'
import { useAsyncResource } from './useAsyncResource'

/** Options for {@link useReports}. */
export interface ReportOptions {
  /** Filters to apply. Compared by value, so it may be built inline. */
  readonly query?: ReportQueryShape
  /** Page window. Compared by value. */
  readonly window?: PageWindow
  readonly enabled?: boolean
}

/** The filter fields this hook reads, structurally identical to `ReportQuery`. */
export interface ReportQueryShape {
  readonly report_type?: string
  readonly format?: string
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

  /** True while a generation request is in flight. */
  readonly isGenerating: boolean
  /** The last generation that failed, or `null`. Cleared when a new one starts. */
  readonly generationError: ApiError | null
  /**
   * Ask the backend to produce a report and record it.
   *
   * Resolves with the refusal, or `null` when a report was generated — callers
   * read {@link ReportResource.generated} for its figures. A successful generation
   * also refreshes the listing, so the new row appears without a manual reload.
   */
  readonly generate: (request?: ReportGenerationRequest) => Promise<ApiError | null>
  /** The last report produced through this hook, or `null`. */
  readonly generated: GeneratedReport | null
  /** Forget the last generated report, e.g. when its summary is dismissed. */
  readonly clearGenerated: () => void

  /** True while an artifact download is in flight. */
  readonly isDownloading: boolean
  /** The last download that failed, or `null`. */
  readonly downloadError: ApiError | null
  /** The report id currently being downloaded, or `null` when idle. */
  readonly downloadingId: number | null
  /**
   * Fetch one report's artifact and hand it to the browser.
   *
   * Resolves with the refusal, or `null` when the file was saved. The report's own
   * `downloadable` field says in advance whether this can succeed; a `404` here
   * means the artifact went away between the listing and the click, which is a
   * real possibility and not a client bug.
   */
  readonly download: (reportId: number) => Promise<ApiError | null>
}

/**
 * Read, generate and download reports.
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
    (signal) =>
      fetchReports(
        { report_type: query?.report_type, format: query?.format },
        window,
        signal,
      ),
    [cacheKey],
    { enabled, isEmpty: (page: ReportList) => page.reports.length === 0 },
  )

  const [downloadingId, setDownloadingId] = useState<number | null>(null)

  const generateAction = useAction(generateReport)
  const downloadAction = useAction(downloadReport)

  const generate = useCallback(
    async (request: ReportGenerationRequest = {}): Promise<ApiError | null> => {
      const outcome = await generateAction.run(request)
      if (!outcome.ok) return outcome.error
      // The store has a new row, so the page should show it. Reloading after the
      // write — rather than inserting a guessed row — is what keeps the list a
      // statement about the store rather than about this component's optimism.
      resource.reload()
      return null
    },
    [generateAction, resource],
  )

  const download = useCallback(
    async (reportId: number): Promise<ApiError | null> => {
      setDownloadingId(reportId)
      try {
        const outcome = await downloadAction.run(reportId)
        if (!outcome.ok) return outcome.error
        // The backend's own filename, so two daily reports cannot collide.
        saveBlob(outcome.value.blob, outcome.value.filename)
        return null
      } finally {
        setDownloadingId(null)
      }
    },
    [downloadAction],
  )

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
    generated: generateAction.result,
    clearGenerated: generateAction.reset,

    isDownloading: downloadAction.isRunning,
    downloadError: downloadAction.error,
    downloadingId,
    download,
  }
}
