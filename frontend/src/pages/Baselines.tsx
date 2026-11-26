/**
 * Behavioral Baselines — what the M21 engine has learnt about each device (M21.11).
 *
 * This page is the window onto the learning engine and nothing more. It reads
 * `GET /api/v1/baselines` and `GET /api/v1/baselines/{device_key}`, and shows the
 * observation windows, the statistical profile and the learning state the backend
 * calculated.
 *
 * **What this page must never imply.** M21 learns and describes; it does not detect.
 * A baseline is a record of behaviour already observed — never a verdict, never a
 * "normal" it can deviate from, and `established` means "watched long enough to be
 * worth reading", not "safe". Two deliberate absences keep that honest:
 *
 * * **No anomaly, score or risk column.** The backend sends none
 *   (`app/schemas/baseline.py`); a number invented in React would be an anomaly
 *   verdict this milestone does not issue.
 * * **A device with no observations is absent, not zero.** The engine writes a
 *   window only when it has counters to put in it, so a device discovered seconds
 *   ago simply has no baseline. The page says that plainly instead of rendering a
 *   fabricated row of zeroes, which would report "no traffic" where the truth is
 *   "nothing observed yet".
 *
 * Data is read over REST, not WebSocket: the engine publishes no baseline channel,
 * and a profile changes once per aggregation window (60 seconds by default) — far
 * slower than a person reads a page. An explicit refresh is the honest cadence
 * (M15.34).
 */

import { useMemo, useState } from 'react'
import {
  Brain, ChevronLeft, ChevronRight, Monitor, RefreshCw, RotateCcw, Sprout, TrendingUp,
} from 'lucide-react'
import { AsyncSection, RefreshFailureBanner } from '@/components/AsyncState'
import { useBaselines, useResetBaseline } from '@/hooks'
import { DEFAULT_PAGE_LIMIT } from '@/services'
import { C, LEARNING_STATE_COLORS, tint } from '@/lib/tokens'
import {
  LEARNING_STATE_ORDER,
  formatSampleCount,
  identityLabel,
  learningStateLabel,
} from '@/lib/baseline'
import { formatCount, formatRelative, formatTimestamp, UNKNOWN_TEXT } from '@/lib/format'
import type { Baseline, LearningState } from '@/types'
import type { ToastMsg } from '../App'
import BaselineDetailPanel from '@/components/baselines/BaselineDetailPanel'
import BaselineResetDialog from '@/components/baselines/BaselineResetDialog'
import LearningStateBadge from '@/components/baselines/LearningStateBadge'

/** How many baselines one page shows. */
const PAGE_SIZE = DEFAULT_PAGE_LIMIT

/** The filter's "no filter" member, distinct from any real learning state. */
type StateFilter = LearningState | 'ALL'

// ─── Stat card ────────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, icon, accent = C.accent }: {
  label: string
  value: string | number
  sub: string
  icon: React.ReactNode
  accent?: string
}) {
  return (
    <div className="rounded-2xl border p-4 flex items-center gap-3"
      style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 20px rgba(0,0,0,0.2)' }}>
      <div className="p-2.5 rounded-xl shrink-0" style={{ backgroundColor: tint(accent, 0.08) }}>
        <div style={{ color: accent }}>{icon}</div>
      </div>
      <div className="min-w-0">
        <div className="text-2xl font-bold text-white leading-none tracking-tight">{value}</div>
        <div className="text-xs font-medium mt-0.5" style={{ color: C.muted }}>{label}</div>
        <div className="text-xs mt-0.5" style={{ color: C.faint }}>{sub}</div>
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

interface Props {
  showToast: (msg: string, type?: ToastMsg['type']) => void
}

export default function Baselines({ showToast }: Props) {
  const [selected, setSelected] = useState<Baseline | null>(null)
  const [stateFilter, setStateFilter] = useState<StateFilter>('ALL')
  const [offset, setOffset] = useState(0)
  const [pendingReset, setPendingReset] = useState<Baseline | null>(null)

  const query = useMemo(
    () => (stateFilter === 'ALL' ? {} : { learning_state: stateFilter }),
    [stateFilter],
  )
  const window = useMemo(() => ({ limit: PAGE_SIZE, offset }), [offset])

  const resource = useBaselines({ query, window })
  const reset = useResetBaseline()

  // The detail view owns the rest of the page when a device is open. Keyed off
  // the row the operator clicked, so the header has an identity before the
  // detail request resolves.
  if (selected !== null) {
    return (
      <>
        <BaselineDetailPanel
          deviceKey={selected.device_key}
          fallback={selected}
          onBack={() => setSelected(null)}
          onRequestReset={baseline => {
            reset.reset()
            setPendingReset(baseline)
          }}
        />
        {pendingReset !== null && (
          <BaselineResetDialog
            baseline={pendingReset}
            isResetting={reset.isRunning}
            onCancel={() => setPendingReset(null)}
            onConfirm={() => void confirmReset()}
          />
        )}
      </>
    )
  }

  // The tiles count what is loaded, and the registry's own total is on the second
  // line, so "on this page" and "in total" can never be read as the same figure.
  const loaded = resource.baselines
  const establishedCount = loaded.filter(b => b.learning_state === 'established').length
  const provisionalCount = loaded.filter(b => b.learning_state === 'provisional').length
  const learningCount = loaded.filter(b => b.learning_state === 'learning').length

  async function confirmReset(): Promise<void> {
    const target = pendingReset
    if (target === null) return
    const outcome = await reset.run(target.device_key)
    if (!outcome.ok) {
      // The refusal branch must be handled to read a value, so a reset the backend
      // rejected can never be reported as having happened (M15.15).
      showToast(outcome.error.userMessage, 'error')
      setPendingReset(null)
      return
    }
    const { windows_deleted: windowsDeleted, profile_deleted: profileDeleted } = outcome.value
    const noun = windowsDeleted === 1 ? 'window' : 'windows'
    showToast(
      profileDeleted
        ? `Baseline reset — deleted ${formatCount(windowsDeleted)} observation ${noun} and the profile. Learning restarts on the next observed packet.`
        : `Baseline reset — deleted ${formatCount(windowsDeleted)} observation ${noun}. No profile had been published yet.`,
      'success',
    )
    setPendingReset(null)
    // A reset device keeps its row until the listing is re-read; reloading is what
    // makes the page show the truth rather than a stale profile.
    resource.reload()
  }

  const filtered = stateFilter !== 'ALL'

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-3 sm:gap-4">
        <StatCard label="Baselines on this page" value={loaded.length}
          sub={resource.total === null ? 'Total unknown' : `${formatCount(resource.total)} learnt`}
          icon={<Brain size={16} />} />
        <StatCard label="Established" value={establishedCount}
          sub="Enough windows for a mature profile"
          icon={<TrendingUp size={16} />} accent={C.success} />
        <StatCard label="Provisional" value={provisionalCount}
          sub="Profile still developing"
          icon={<Sprout size={16} />} accent={C.warning} />
        <StatCard label="Learning" value={learningCount}
          sub="Too few windows to describe"
          icon={<Monitor size={16} />} accent={C.faint} />
      </div>

      {/* The page-level statement of what a baseline is. Stated once, above the
          table, because a reader who scans only the rows would otherwise take an
          "Established" badge for a clean bill of health. */}
      <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl border text-xs"
        style={{ backgroundColor: C.panel, borderColor: C.border, color: C.muted }}>
        <Brain size={13} style={{ color: C.faint, flexShrink: 0, marginTop: 1 }} />
        <span>
          A baseline describes behaviour the engine has already observed for a device — how many
          packets and bytes it usually sends, which protocols it uses, how many peers and ports it
          normally reaches. It is <span className="font-medium" style={{ color: C.text }}>not</span>{' '}
          an anomaly verdict: M21 learns, it does not judge, and no device is marked suspicious
          here.
        </span>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <select value={stateFilter}
          onChange={e => {
            setStateFilter(e.target.value as StateFilter)
            setOffset(0)
          }}
          className="px-3 py-2 rounded-xl text-xs border"
          style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted, outline: 'none' }}>
          <option value="ALL">All learning states</option>
          {LEARNING_STATE_ORDER.map(state => (
            <option key={state} value={state}>{learningStateLabel(state)}</option>
          ))}
        </select>
        <button onClick={resource.reload} disabled={resource.isLoading}
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
          <RefreshCw size={12} className={resource.isLoading ? 'animate-spin' : undefined} /> Refresh
        </button>
      </div>

      {resource.error !== null && loaded.length > 0 && (
        <RefreshFailureBanner error={resource.error} onRetry={resource.reload} />
      )}

      <div className="rounded-2xl border overflow-hidden"
        style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b"
          style={{ borderColor: C.border }}>
          <div>
            <h2 className="text-sm font-semibold text-white">Learnt Baselines</h2>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>
              {loaded.length} loaded
              {` · rows ${offset + 1}–${offset + loaded.length}`}
            </p>
          </div>
        </div>

        <AsyncSection
          isInitialLoading={resource.isInitialLoading}
          error={resource.blockingError}
          isEmpty={loaded.length === 0}
          loadingLabel="Loading behavioural baselines…"
          emptyTitle={filtered ? 'No baselines in this learning state' : 'No baselines learnt yet'}
          emptyHint={filtered
            ? 'Choose another learning state, or clear the filter to see every baseline the engine has.'
            : 'A baseline appears once the engine has completed an aggregation window for a device. Start an authorized capture and let it run for a minute.'}
          emptyIcon={<Brain size={28} />}
          errorTitle="Unable to load behavioural baselines"
          onRetry={resource.reload}
          minHeight={220}
        >
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b" style={{ borderColor: C.border }}>
                  <th className="text-left pl-5 py-2.5 pr-4 text-xs font-medium"
                    style={{ color: C.dim }}>
                    Device
                  </th>
                  <th className="text-left py-2.5 pr-4 text-xs font-medium"
                    style={{ color: C.dim }}>
                    Learning state
                  </th>
                  <th className="text-right py-2.5 pr-4 text-xs font-medium"
                    title="Aggregated observation windows that shaped this profile"
                    style={{ color: C.dim }}>
                    Samples
                  </th>
                  <th className="text-left py-2.5 pr-4 text-xs font-medium"
                    style={{ color: C.dim }}>
                    First observed
                  </th>
                  <th className="text-left py-2.5 pr-4 text-xs font-medium"
                    style={{ color: C.dim }}>
                    Latest observed
                  </th>
                  <th className="text-right py-2.5 pr-5 text-xs font-medium"
                    style={{ color: C.dim }}>
                    Action
                  </th>
                </tr>
              </thead>
              <tbody>
                {loaded.map(baseline => {
                  const stateColor = LEARNING_STATE_COLORS[baseline.learning_state] ?? C.dim
                  const identity = identityLabel(baseline.device_key, baseline.identity_kind)
                  return (
                    <tr key={baseline.device_key}
                      onClick={() => setSelected(baseline)}
                      className="border-b transition-all duration-150 cursor-pointer"
                      style={{ borderColor: '#1a2744' }}
                      onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)')}
                      onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
                      <td className="pl-5 py-3 pr-4">
                        <div className="flex items-center gap-2">
                          <div className="mono text-xs font-semibold text-white break-all">
                            {identity}
                          </div>
                          <span className="text-[10px] px-1.5 py-0.5 rounded-full font-semibold shrink-0"
                            title={baseline.identity_kind === 'mac'
                              ? 'Hardware identity. It survives an IP change.'
                              : 'IP fallback identity. This profile may not follow the device across an address change.'}
                            style={{
                              backgroundColor: tint(
                                baseline.identity_kind === 'mac' ? C.accent : C.warning, 0.12,
                              ),
                              color: baseline.identity_kind === 'mac' ? C.accent : C.warning,
                            }}>
                            {baseline.identity_kind === 'mac' ? 'MAC' : 'IP'}
                          </span>
                        </div>
                        <div className="text-[11px] mt-0.5" style={{ color: C.faint }}>
                          {baseline.ip_addresses.length > 0
                            ? baseline.ip_addresses.join(', ')
                            : UNKNOWN_TEXT}
                        </div>
                      </td>
                      <td className="py-3 pr-4" style={{ color: stateColor }}>
                        <LearningStateBadge
                          state={baseline.learning_state}
                          description={baseline.state_description}
                          compact
                        />
                      </td>
                      <td className="py-3 pr-4 mono text-xs text-right text-white">
                        {formatCount(baseline.sample_count)}
                        <div className="text-[10px] font-normal" style={{ color: C.faint }}>
                          {formatSampleCount(baseline)}
                        </div>
                      </td>
                      <td className="py-3 pr-4 text-xs" style={{ color: C.muted }}>
                        {formatTimestamp(baseline.first_observed_at)}
                      </td>
                      <td className="py-3 pr-4 text-xs" style={{ color: C.muted }}>
                        {formatRelative(baseline.last_observed_at)}
                      </td>
                      <td className="py-3 pr-5 text-right">
                        <button
                          onClick={event => {
                            // The row opens the profile; the reset button must not.
                            event.stopPropagation()
                            reset.reset()
                            setPendingReset(baseline)
                          }}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-medium border"
                          title="Delete this device's baseline history so learning restarts"
                          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
                          <RotateCcw size={10} /> Reset
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </AsyncSection>

        <div className="flex items-center justify-between px-5 py-3 border-t"
          style={{ borderColor: C.border }}>
          <button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            disabled={offset === 0 || resource.isLoading}
            className="flex items-center gap-1 px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            <ChevronLeft size={12} /> Previous
          </button>
          <span className="text-xs" style={{ color: C.faint }}>
            {offset === 0 && !resource.hasMore
              ? 'All learnt baselines'
              : `Offset ${offset}`}
          </span>
          <button onClick={() => setOffset(offset + PAGE_SIZE)}
            disabled={!resource.hasMore || resource.isLoading}
            className="flex items-center gap-1 px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            Next <ChevronRight size={12} />
          </button>
        </div>
      </div>

      {pendingReset !== null && (
        <BaselineResetDialog
          baseline={pendingReset}
          isResetting={reset.isRunning}
          onCancel={() => setPendingReset(null)}
          onConfirm={() => void confirmReset()}
        />
      )}
    </div>
  )
}
