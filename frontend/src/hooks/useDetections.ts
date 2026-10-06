/**
 * Detection findings and detectors (M15.20).
 *
 * The distinction this hook exists to preserve: **a finding is not an alert**.
 * A finding is M10's raw observation — no severity, no lifecycle, no risk — and
 * only some findings raise an alert, which is M11's decision. Nothing here may
 * present a finding as an untriaged alert, and nothing here reads a severity,
 * because none exists (M15.20).
 *
 * M10 publishes no WebSocket channel, so there is no live path: findings are read
 * from REST and refreshed explicitly. That is not a missing feature — findings are
 * the engine's internal observations, and M11 already publishes the alerts that
 * were derived from them.
 *
 * A finding that has **aged out** of M10's bounded history answers `404` with
 * `FINDING_NOT_FOUND`; that is the honest answer rather than an empty record, and
 * the page renders it as "no longer retained" (M10.19).
 */

import { useCallback, useMemo } from 'react'
import { fetchDetectionRules, fetchDetections, resetDetections } from '@/services'
import type { ApiError, PageWindow } from '@/services'
import type {
  DetectionDiagnostics,
  DetectionFinding,
  DetectionFindingPage,
  DetectionQuery,
  DetectionRule,
  DetectionRuleList,
} from '@/types'
import { useAction } from './useAction'
import { useAsyncResource } from './useAsyncResource'

/** Options for {@link useDetections}. */
export interface DetectionListOptions {
  /** Filters to apply. Compared by value, so it may be built inline. */
  readonly query?: DetectionQuery
  /** Page window. Compared by value. */
  readonly window?: PageWindow
  /** Whether to read the detector table and diagnostics too. Defaults True. */
  readonly withRules?: boolean
  readonly enabled?: boolean
}

/** What {@link useDetections} returns. */
export interface DetectionListResource {
  readonly findings: readonly DetectionFinding[]
  readonly page: DetectionFindingPage | null
  /** The true match count, when the engine could count it. */
  readonly total: number | null
  readonly hasMore: boolean
  /** Every registered detector, or an empty list before it is read. */
  readonly rules: readonly DetectionRule[]
  /** Per-detector execution counters, or `null`. */
  readonly diagnostics: DetectionDiagnostics | null
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  /** A failure of the rules read, kept separate from the listing's failure. */
  readonly rulesError: ApiError | null
  /** The rules-read failure that is blocking the view, if any. */
  readonly rulesBlockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  /** True when the engine answered with no retained findings. */
  readonly isEmpty: boolean
  readonly reload: () => void
  /** True while the M10 verification reset is in flight. */
  readonly isResetting: boolean
  /**
   * Discard retained findings and counters (M10.22 verification helper).
   *
   * Resolves `null` on success or the refusal. This clears in-memory observation
   * state only: it turns no detector on or off, and the page must present it as a
   * development action rather than as a security control.
   */
  readonly reset: () => Promise<ApiError | null>
}

/**
 * Read retained findings and the detector table.
 *
 * @param options Filters, page window, whether to read detectors, whether to run.
 */
export function useDetections(
  options: DetectionListOptions = {},
): DetectionListResource {
  const { query, window, withRules = true, enabled = true } = options

  const cacheKey = useMemo(
    () =>
      JSON.stringify({
        rule_id: query?.rule_id ?? null,
        source_ip: query?.source_ip ?? null,
        destination_ip: query?.destination_ip ?? null,
        device_id: query?.device_id ?? null,
        since: query?.since ?? null,
        until: query?.until ?? null,
        limit: window?.limit ?? null,
        offset: window?.offset ?? null,
      }),
    [query, window],
  )

  const resource = useAsyncResource(
    (signal) => fetchDetections(query ?? {}, window, signal),
    [cacheKey],
    { enabled, isEmpty: (page: DetectionFindingPage) => page.findings.length === 0 },
  )

  const ruleResource = useAsyncResource(
    (signal) => fetchDetectionRules(signal),
    [],
    { enabled: enabled && withRules },
  )

  const resetAction = useAction(resetDetections)
  const { reload } = resource
  const { reload: reloadRules } = ruleResource

  const reset = useCallback(async (): Promise<ApiError | null> => {
    const outcome = await resetAction.run()
    if (!outcome.ok) return outcome.error
    // The reset emptied the retained findings, so both reads are redone rather
    // than trusting the counters it returned as a substitute for the listing.
    reload()
    reloadRules()
    return null
  }, [reload, reloadRules, resetAction])

  const ruleList: DetectionRuleList | null = ruleResource.data

  return {
    findings: resource.data?.findings ?? [],
    page: resource.data,
    total: resource.data?.total ?? null,
    hasMore: resource.data?.has_more === true,
    rules: ruleList?.rules ?? [],
    diagnostics: ruleList?.diagnostics ?? null,
    error: resource.error,
    blockingError: resource.blockingError,
    rulesError: ruleResource.error,
    rulesBlockingError: ruleResource.blockingError,
    isLoading: resource.isLoading || ruleResource.isLoading,
    isInitialLoading: resource.isInitialLoading || ruleResource.isInitialLoading,
    isRefreshing:
      (resource.isLoading && !resource.isInitialLoading) ||
      (ruleResource.isLoading && !ruleResource.isInitialLoading),
    isEmpty: resource.data !== null && resource.data.findings.length === 0,
    reload,
    isResetting: resetAction.isRunning,
    reset,
  }
}
