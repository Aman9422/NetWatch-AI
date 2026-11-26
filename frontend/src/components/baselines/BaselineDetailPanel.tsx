/**
 * One device's behavioural profile (M21.11).
 *
 * The detail read is its own request rather than a row from the listing, because
 * the engine sends `recent_windows` here and bounds it (`MAX_DETAIL_WINDOWS`), and
 * a listing that carried every device's samples would be a page of payloads nobody
 * asked for (M21.10).
 *
 * Four states are distinguished, and two of them are easy to get wrong:
 *
 * * **"The engine says this device has no baseline" (`404`)** is an answer about a
 *   real device, shown as an empty state with the reason it has nothing yet. It is
 *   *not* an error, and it offers no retry — only further capture will produce a
 *   baseline (M21.7).
 * * **"The request failed"** is a fault, shown as an error with a retry.
 *
 * The panel reads `useBaseline` itself so returning to the list does not refetch
 * the page through two hooks, and it keeps `fallback` — the row the operator
 * clicked — so a back-navigation or a failed refresh still has the identity to show.
 */

import { ArrowLeft, RotateCcw } from 'lucide-react'
import { C, tint } from '@/lib/tokens'
import { EmptyState, ErrorState, LoadingState, RefreshFailureBanner } from '@/components/AsyncState'
import { formatRelative, formatTimestamp } from '@/lib/format'
import {
  addressLabel,
  formatSampleCount,
  formatWindowSeconds,
  identityLabel,
} from '@/lib/baseline'
import { useBaseline } from '@/hooks'
import type { Baseline } from '@/types'
import LearningStateBadge from './LearningStateBadge'
import BaselineStatisticsTable from './BaselineStatisticsTable'
import BaselineWindowsTable from './BaselineWindowsTable'

interface Props {
  /** The stable M8 identity whose profile is being inspected. */
  readonly deviceKey: string
  /** The row that was clicked, shown while the detail request is in flight. */
  readonly fallback: Baseline | null
  readonly onBack: () => void
  readonly onRequestReset: (baseline: Baseline) => void
}

/** One labelled fact in the meta grid. */
function Fact({
  label,
  value,
  title,
}: {
  label: string
  value: string
  title?: string
}) {
  return (
    <div title={title}>
      <dt className="text-[10px] font-semibold uppercase tracking-widest" style={{ color: C.dim }}>
        {label}
      </dt>
      <dd className="mono text-xs mt-1 break-all" style={{ color: C.text }}>
        {value}
      </dd>
    </div>
  )
}

/** A titled card, so both tables below read as the same kind of object. */
function Panel({
  title,
  subtitle,
  children,
}: {
  title: string
  subtitle: string
  children: React.ReactNode
}) {
  return (
    <section
      className="rounded-2xl border overflow-hidden"
      style={{ backgroundColor: C.panel, borderColor: C.border }}>
      <header className="px-5 py-3 border-b" style={{ borderColor: C.border }}>
        <h2 className="text-sm font-semibold text-white">{title}</h2>
        <p className="text-xs mt-0.5" style={{ color: C.faint }}>
          {subtitle}
        </p>
      </header>
      {children}
    </section>
  )
}

export default function BaselineDetailPanel({
  deviceKey,
  fallback,
  onBack,
  onRequestReset,
}: Props) {
  const resource = useBaseline(deviceKey)
  // The live payload wins; the row survives a failed refresh so the header still
  // names the device the operator is looking at.
  const baseline = resource.baseline ?? fallback
  const identity = baseline === null
    ? deviceKey
    : identityLabel(baseline.device_key, baseline.identity_kind)

  return (
    <div className="space-y-4">
      <button
        onClick={onBack}
        className="flex items-center gap-1.5 text-xs font-medium"
        style={{ color: C.muted }}>
        <ArrowLeft size={13} /> All baselines
      </button>

      {resource.isInitialLoading && baseline === null && (
        <LoadingState label="Reading this device's baseline…" />
      )}

      {resource.isNotLearnt && (
        <div className="rounded-2xl border overflow-hidden"
          style={{ backgroundColor: C.panel, borderColor: C.border }}>
          <div className="px-5 py-4 border-b" style={{ borderColor: C.border }}>
            <p className="mono text-sm font-semibold text-white break-all">{identity}</p>
            <p className="text-xs mt-1" style={{ color: C.faint }}>
              Identity {baseline === null ? deviceKey : baseline.identity_kind}
            </p>
          </div>
          <EmptyState
            title="No baseline for this device"
            hint="The engine has not completed an observation window for this device yet, so it has nothing to describe. A baseline appears once packets from this device are captured and the aggregation window closes."
            minHeight={180}
          />
        </div>
      )}

      {resource.blockingError !== null && !resource.isNotLearnt && (
        <div className="rounded-2xl border" style={{ backgroundColor: C.panel, borderColor: C.border }}>
          <ErrorState
            error={resource.blockingError}
            title="Unable to read this baseline"
            onRetry={resource.reload}
          />
        </div>
      )}

      {baseline !== null && !resource.isNotLearnt && (
        <>
          {resource.error !== null && (
            <RefreshFailureBanner error={resource.error} onRetry={resource.reload} />
          )}

          <div className="rounded-2xl border overflow-hidden"
            style={{ backgroundColor: C.panel, borderColor: C.border }}>
            <header className="px-5 py-4 border-b flex items-start justify-between gap-4"
              style={{ borderColor: C.border }}>
              <div className="min-w-0">
                <h1 className="text-base font-bold text-white">Behavioural baseline</h1>
                <p className="mono text-sm mt-1 break-all" style={{ color: C.accent }}>
                  {identity}
                </p>
                <div className="flex items-center gap-2 mt-2 flex-wrap">
                  <LearningStateBadge
                    state={baseline.learning_state}
                    description={baseline.state_description}
                  />
                  <span className="text-[11px] px-2 py-0.5 rounded-full font-medium"
                    title={baseline.identity_kind === 'mac'
                      ? 'A hardware identity. It survives an IP change, so the profile follows the device.'
                      : 'An IP fallback identity. Without a MAC this profile may not follow the physical device across an address change.'}
                    style={{
                      backgroundColor: tint(
                        baseline.identity_kind === 'mac' ? C.accent : C.warning,
                        0.12,
                      ),
                      color: baseline.identity_kind === 'mac' ? C.accent : C.warning,
                    }}>
                    {baseline.identity_kind === 'mac' ? 'MAC identity' : 'IP identity (fallback)'}
                  </span>
                </div>
              </div>
              <button
                onClick={() => onRequestReset(baseline)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold shrink-0 border"
                style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
                <RotateCcw size={12} /> Reset
              </button>
            </header>

            <dl className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4 px-5 py-4 border-b"
              style={{ borderColor: C.border }}>
              <Fact label="Samples" value={formatSampleCount(baseline)} />
              <Fact label="Window" value={formatWindowSeconds(baseline.window_seconds)} />
              <Fact label="First observed" value={formatTimestamp(baseline.first_observed_at)} />
              <Fact
                label="Latest observed"
                value={formatRelative(baseline.last_observed_at)}
                title={formatTimestamp(baseline.last_observed_at)}
              />
              <Fact
                label="MAC address"
                value={baseline.mac_address ?? '—'}
              />
              <Fact label="Observed addresses" value={addressLabel(baseline.ip_addresses)} />
            </dl>

            <p className="px-5 py-3 text-xs border-b" style={{ borderColor: C.border, color: C.muted }}>
              {baseline.state_description}
            </p>

            <footer className="px-5 py-3 text-xs" style={{ color: C.faint }}>
              {baseline.disclaimer}
            </footer>
          </div>

          <Panel
            title="Statistical profile"
            subtitle="Calculated by the engine from this device's observation windows. Not re-derived here.">
            <BaselineStatisticsTable statistics={baseline.statistics} />
          </Panel>

          <Panel
            title="Observation windows"
            subtitle="The aggregated samples behind the profile, most recent first.">
            <BaselineWindowsTable windows={baseline.recent_windows} />
          </Panel>
        </>
      )}
    </div>
  )
}
