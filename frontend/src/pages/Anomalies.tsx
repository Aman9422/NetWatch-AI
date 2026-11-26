/**
 * ML Anomalies — what the M22 engine found unusual (M22.13).
 *
 * This page is the window onto the anomaly engine and nothing more. It reads
 * `GET /api/v1/anomalies*` and shows the verdicts the backend recorded, the model
 * lifecycles behind them, and — for one result — the per-feature comparison
 * against M21's learned baseline.
 *
 * **What this page must never imply.** An anomaly is a *deviation from previously
 * observed behaviour*, not proof of an attack, and a `decision_score` is a raw
 * Isolation Forest output, not a probability. Three deliberate choices keep that
 * honest:
 *
 * * **No percentage, no confidence, no risk.** The backend sends none; a "95%
 *   malicious" invented in React would be exactly the calibration this milestone
 *   forbids (M22.9).
 * * **"Not evaluated" is not "normal".** A window with no model to score it is
 *   stored as `skipped` and rendered as such. Showing it as a clean row would
 *   report the absence of evidence as evidence of normality — the single most
 *   misleading thing this page could do.
 * * **Devices still collecting history are visible.** The model table lists
 *   `collecting_data` rows, because a device with no model is not being checked at
 *   all, and hiding it would leave an operator believing otherwise.
 *
 * Data is read over REST, not WebSocket: the engine publishes no anomaly channel,
 * and an evaluation happens once per 60-second observation window — far slower than
 * a person reads a page. An explicit refresh is the honest cadence (M15.34).
 */

import { useMemo, useState } from 'react'
import {
  Brain, ChevronLeft, ChevronRight, Monitor, RefreshCw, Search, ShieldQuestion,
  TriangleAlert, X,
} from 'lucide-react'
import { AsyncSection, RefreshFailureBanner } from '@/components/AsyncState'
import { useAnomalies, useAnomalyModels, useRetrainAnomalyModel } from '@/hooks'
import { DEFAULT_PAGE_LIMIT } from '@/services'
import { C, tint } from '@/lib/tokens'
import {
  ANOMALY_STATE_ORDER,
  formatDecisionScore,
  hasVerdict,
  modelStateLabel,
  statusLabel,
} from '@/lib/anomaly'
import { formatCount, formatRelative, formatTimestamp, UNKNOWN_TEXT } from '@/lib/format'
import type { AnomalyModel, AnomalyResult, AnomalyStatus } from '@/types'
import type { ToastMsg } from '../App'
import AnomalyDetailPanel from '@/components/anomalies/AnomalyDetailPanel'
import AnomalyModelDetailPanel from '@/components/anomalies/AnomalyModelDetailPanel'
import AnomalyModelsTable from '@/components/anomalies/AnomalyModelsTable'
import RetrainDialog from '@/components/anomalies/RetrainDialog'

/** How many results one page shows. */
const PAGE_SIZE = DEFAULT_PAGE_LIMIT

/** Which tab is open. */
type Tab = 'results' | 'models'

/** The filter's "no filter" members, distinct from any real value. */
type ClassificationFilter = 'ALL' | 'ANOMALIES' | 'NORMAL'
type StatusFilter = AnomalyStatus | 'ALL'

/** The statement every anomaly surface carries (M22.13). */
const DISCLAIMER =
  'An anomaly indicates a deviation from previously observed network behavior. ' +
  'It is not confirmation of malicious activity.'

/**
 * Convert a `<input type="datetime-local">` value into an ISO-8601 instant.
 *
 * The control reports a *local* wall-clock string with no zone (`2026-01-01T10:00`),
 * and the backend's `since`/`until` filters are inclusive/exclusive bounds on a UTC
 * instant. Passing the raw string would be parsed as UTC by the backend while the
 * operator meant their own clock, so the local instant is resolved here and sent
 * with an explicit `Z`. An unparseable value returns `undefined`, which drops the
 * filter rather than sending a bound the backend would reject with a 400.
 */
function toIsoOrUndefined(value: string): string | undefined {
  if (value.trim() === '') return undefined
  const parsed = Date.parse(value)
  if (Number.isNaN(parsed)) return undefined
  return new Date(parsed).toISOString()
}

// ─── Stat card ────────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, icon, accent = C.accent }: {
  label: string
  value: string
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

// ─── Result row ───────────────────────────────────────────────────────────────

function ResultRow({ result, onOpen }: {
  result: AnomalyResult
  onOpen: () => void
}) {
  const verdict = hasVerdict(result)
  const flagged = verdict && result.is_anomaly
  return (
    <tr onClick={onOpen}
      className="border-b transition-all duration-150 cursor-pointer"
      style={{ borderColor: '#1a2744' }}
      onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)')}
      onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
      <td className="pl-5 py-3 pr-4">
        <div className="mono text-xs font-semibold text-white break-all">
          {result.device_key}
        </div>
        <div className="text-[11px] mt-0.5" style={{ color: C.faint }}>
          {formatTimestamp(result.window_start)}
        </div>
      </td>
      <td className="py-3 pr-4">
        {verdict ? (
          <span className="text-[11px] px-2 py-0.5 rounded-full font-medium whitespace-nowrap"
            style={{
              backgroundColor: tint(flagged ? C.warning : C.success, 0.12),
              color: flagged ? C.warning : C.success,
            }}>
            {flagged ? 'Flagged as unusual' : 'Within learned range'}
          </span>
        ) : (
          <span className="text-[11px] px-2 py-0.5 rounded-full font-medium whitespace-nowrap"
            title="No model could evaluate this window, so there is no verdict."
            style={{ backgroundColor: tint(C.faint, 0.12), color: C.faint }}>
            {statusLabel(result.status)}
          </span>
        )}
      </td>
      <td className="py-3 pr-4 mono text-xs text-right"
        style={{ color: verdict ? (flagged ? C.warning : C.text) : C.dim }}>
        {verdict ? formatDecisionScore(result.decision_score) : UNKNOWN_TEXT}
      </td>
      <td className="py-3 pr-4 mono text-xs text-right text-white">
        {result.model_version === 0 ? UNKNOWN_TEXT : `v${result.model_version}`}
        <div className="text-[10px] font-normal" style={{ color: C.faint }}>
          {result.training_sample_count === 0
            ? 'no model'
            : `${formatCount(result.training_sample_count)} samples`}
        </div>
      </td>
      <td className="py-3 pr-4 text-xs" style={{ color: C.muted }}>
        {result.alert_id === null
          ? <span style={{ color: C.dim }}>{UNKNOWN_TEXT}</span>
          : `#${result.alert_id}`}
      </td>
      <td className="py-3 pr-5 text-xs text-right" style={{ color: C.faint }}>
        {formatRelative(result.created_at)}
      </td>
    </tr>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

interface Props {
  showToast: (msg: string, type?: ToastMsg['type']) => void
}

export default function Anomalies({ showToast }: Props) {
  const [tab, setTab] = useState<Tab>('results')
  const [selected, setSelected] = useState<AnomalyResult | null>(null)
  const [classification, setClassification] = useState<ClassificationFilter>('ALL')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('ALL')
  const [offset, setOffset] = useState(0)
  const [pendingRetrain, setPendingRetrain] = useState<AnomalyModel | null>(null)
  const [deviceKey, setDeviceKey] = useState('')
  const [since, setSince] = useState('')
  const [until, setUntil] = useState('')
  // The device whose model detail is open, with the row already on screen so the
  // header renders before the single-model read completes.
  const [openModel, setOpenModel] = useState<AnomalyModel | null>(null)

  const query = useMemo(() => {
    const trimmedDevice = deviceKey.trim()
    return {
      ...(classification === 'ANOMALIES' ? { is_anomaly: true } : {}),
      ...(classification === 'NORMAL' ? { is_anomaly: false } : {}),
      ...(statusFilter === 'ALL' ? {} : { status: statusFilter }),
      // A blank field means "no filter"; the backend validates strictly and would
      // reject an empty string as an unparseable instant.
      ...(trimmedDevice === '' ? {} : { device_key: trimmedDevice }),
      ...(toIsoOrUndefined(since) === undefined ? {} : { since: toIsoOrUndefined(since) }),
      ...(toIsoOrUndefined(until) === undefined ? {} : { until: toIsoOrUndefined(until) }),
    }
  }, [classification, statusFilter, deviceKey, since, until])
  const window = useMemo(() => ({ limit: PAGE_SIZE, offset }), [offset])

  const results = useAnomalies({ query, window })
  const models = useAnomalyModels({ window: { limit: PAGE_SIZE, offset: 0 } })
  const retrain = useRetrainAnomalyModel()

  if (selected !== null) {
    return (
      <AnomalyDetailPanel anomaly={selected} onBack={() => setSelected(null)} />
    )
  }

  if (openModel !== null) {
    // The confirmation dialog is rendered here as well as below, because this
    // branch returns early: without it, "Retrain" on the detail view would set
    // the pending target and then render nothing at all.
    return (
      <>
        <AnomalyModelDetailPanel
          deviceKey={openModel.device_key}
          fallback={openModel}
          onBack={() => setOpenModel(null)}
          onRequestRetrain={model => {
            retrain.reset()
            setPendingRetrain(model)
          }}
        />
        {pendingRetrain !== null && (
          <RetrainDialog
            model={pendingRetrain}
            isRetraining={retrain.isRunning}
            onCancel={() => setPendingRetrain(null)}
            onConfirm={() => void confirmRetrain()}
          />
        )}
      </>
    )
  }

  const summary = results.summary
  const filtered =
    classification !== 'ALL' ||
    statusFilter !== 'ALL' ||
    deviceKey.trim() !== '' ||
    since !== '' ||
    until !== ''

  async function confirmRetrain(): Promise<void> {
    const target = pendingRetrain
    if (target === null) return
    const outcome = await retrain.run(target.device_key)
    if (!outcome.ok) {
      showToast(outcome.error.userMessage, 'error')
      setPendingRetrain(null)
      return
    }
    const value = outcome.value
    if (value.trained) {
      showToast(`Retrained this device's anomaly model — ${value.message}`, 'success')
    } else {
      // A `200` does not mean a model was trained: report what actually happened.
      showToast(value.message, 'info')
    }
    setPendingRetrain(null)
    models.reload()
    results.reload()
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-3 sm:gap-4">
        {/* Every figure is run through `formatCount`, so a five-figure total reads
            as `12,043` rather than `12043`. Zero is a real answer here — the engine
            has evaluated nothing — so it is rendered as `0`, not as unknown. */}
        <StatCard label="Evaluations recorded"
          value={summary === null ? UNKNOWN_TEXT : formatCount(summary.evaluations)}
          sub={summary === null ? 'Total unknown' : `${formatCount(summary.scored)} scored by a model`}
          icon={<Brain size={16} />} />
        <StatCard label="Anomalous windows"
          value={summary === null ? UNKNOWN_TEXT : formatCount(summary.anomalies)}
          sub="Deviations from learned behaviour"
          icon={<TriangleAlert size={16} />} accent={C.warning} />
        <StatCard label="Affected devices"
          value={summary === null ? UNKNOWN_TEXT : formatCount(summary.affected_devices)}
          sub="Devices with at least one anomaly"
          icon={<Monitor size={16} />} accent={C.orange} />
        <StatCard label="Not evaluated"
          value={summary === null ? UNKNOWN_TEXT : formatCount(summary.skipped)}
          sub="No verdict issued — not the same as normal"
          icon={<ShieldQuestion size={16} />} accent={C.faint} />
      </div>

      {/* The page-level statement of what an anomaly is. Stated once, above the
          table, because a reader who scans only the rows would otherwise take
          "flagged as unusual" for a finding of malice. */}
      <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl border text-xs"
        style={{ backgroundColor: C.panel, borderColor: C.border, color: C.muted }}>
        <ShieldQuestion size={13} style={{ color: C.faint, flexShrink: 0, marginTop: 1 }} />
        <span>{DISCLAIMER}</span>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex rounded-xl border overflow-hidden"
          style={{ borderColor: C.border }}>
          {(['results', 'models'] as const).map(value => (
            <button key={value} onClick={() => setTab(value)}
              className="px-3 py-2 text-xs font-medium"
              style={{
                backgroundColor: tab === value ? tint(C.accent, 0.12) : C.card,
                color: tab === value ? C.accent : C.muted,
              }}>
              {value === 'results' ? 'Anomaly results' : 'Device models'}
            </button>
          ))}
        </div>

        {tab === 'results' && (
          <>
            <select value={classification}
              onChange={e => {
                setClassification(e.target.value as ClassificationFilter)
                setOffset(0)
              }}
              className="px-3 py-2 rounded-xl text-xs border"
              style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted, outline: 'none' }}>
              <option value="ALL">All windows</option>
              <option value="ANOMALIES">Anomalous only</option>
              <option value="NORMAL">Within learned range</option>
            </select>
            <select value={statusFilter}
              onChange={e => {
                setStatusFilter(e.target.value as StatusFilter)
                setOffset(0)
              }}
              className="px-3 py-2 rounded-xl text-xs border"
              style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted, outline: 'none' }}>
              <option value="ALL">Any evaluation status</option>
              <option value="scored">Scored</option>
              <option value="skipped">Not evaluated</option>
              <option value="failed">Failed</option>
            </select>

            {/* Device and time-range filters (M22.13). The device field is a plain
                text input rather than a select: the set of devices that have ever
                produced a window is not the set on this page, and a select built
                from the loaded rows would silently lose the ability to filter to a
                device that is not currently listed. */}
            <label className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border text-xs"
              style={{ borderColor: C.border, backgroundColor: C.card, color: C.muted }}>
              <Search size={12} style={{ color: C.dim, flexShrink: 0 }} />
              <input
                type="text"
                value={deviceKey}
                onChange={e => {
                  setDeviceKey(e.target.value)
                  setOffset(0)
                }}
                placeholder="Device key (mac:… or ip:…)"
                aria-label="Filter by device key"
                className="bg-transparent outline-none w-44 mono" />
            </label>

            <label className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border text-xs"
              style={{ borderColor: C.border, backgroundColor: C.card, color: C.dim }}>
              From
              <input
                type="datetime-local"
                value={since}
                onChange={e => {
                  setSince(e.target.value)
                  setOffset(0)
                }}
                aria-label="Observation windows starting at or after"
                className="bg-transparent outline-none text-xs"
                style={{ color: C.muted }} />
            </label>

            <label className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border text-xs"
              style={{ borderColor: C.border, backgroundColor: C.card, color: C.dim }}>
              To
              <input
                type="datetime-local"
                value={until}
                onChange={e => {
                  setUntil(e.target.value)
                  setOffset(0)
                }}
                aria-label="Observation windows starting before"
                className="bg-transparent outline-none text-xs"
                style={{ color: C.muted }} />
            </label>

            {filtered && (
              <button
                onClick={() => {
                  setClassification('ALL')
                  setStatusFilter('ALL')
                  setDeviceKey('')
                  setSince('')
                  setUntil('')
                  setOffset(0)
                }}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-xl text-xs font-medium border"
                style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
                <X size={11} /> Clear filters
              </button>
            )}
          </>
        )}

        <button
          onClick={() => {
            if (tab === 'results') results.reload()
            else models.reload()
          }}
          disabled={tab === 'results' ? results.isLoading : models.isLoading}
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
          <RefreshCw size={12}
            className={(tab === 'results' ? results.isLoading : models.isLoading)
              ? 'animate-spin'
              : undefined} />
          Refresh
        </button>
      </div>

      {tab === 'results' && results.error !== null && results.anomalies.length > 0 && (
        <RefreshFailureBanner error={results.error} onRetry={results.reload} />
      )}
      {tab === 'models' && models.error !== null && models.models.length > 0 && (
        <RefreshFailureBanner error={models.error} onRetry={models.reload} />
      )}

      {tab === 'results' ? (
        <div className="rounded-2xl border overflow-hidden"
          style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
          <div className="flex items-center justify-between px-5 py-4 border-b"
            style={{ borderColor: C.border }}>
            <div>
              <h2 className="text-sm font-semibold text-white">Evaluated observation windows</h2>
              <p className="text-xs mt-0.5" style={{ color: C.faint }}>
                {results.anomalies.length} loaded
                {` · rows ${offset + 1}–${offset + results.anomalies.length}`}
              </p>
            </div>
          </div>

          <AsyncSection
            isInitialLoading={results.isInitialLoading}
            error={results.blockingError}
            isEmpty={results.anomalies.length === 0}
            loadingLabel="Loading anomaly results…"
            emptyTitle={filtered ? 'No results match this filter' : 'No windows evaluated yet'}
            emptyHint={filtered
              ? 'Clear or change the filters to see every recorded evaluation.'
              : 'The ML engine evaluates completed 60-second observation windows once a device has enough history to train a model — 100 windows by default, about 1 hour 40 minutes of continuous observation.'}
            emptyIcon={<Brain size={28} />}
            errorTitle="Unable to load anomaly results"
            onRetry={results.reload}
            minHeight={220}
          >
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b" style={{ borderColor: C.border }}>
                    <th className="text-left pl-5 py-2.5 pr-4 text-xs font-medium"
                      style={{ color: C.dim }}>Device & window</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium"
                      style={{ color: C.dim }}>Classification</th>
                    <th className="text-right py-2.5 pr-4 text-xs font-medium"
                      title="Raw Isolation Forest decision_function output. Lower is more unusual. Not a probability."
                      style={{ color: C.dim }}>Decision score</th>
                    <th className="text-right py-2.5 pr-4 text-xs font-medium"
                      style={{ color: C.dim }}>Model</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium"
                      style={{ color: C.dim }}>Alert</th>
                    <th className="text-right py-2.5 pr-5 text-xs font-medium"
                      style={{ color: C.dim }}>Recorded</th>
                  </tr>
                </thead>
                <tbody>
                  {results.anomalies.map(result => (
                    <ResultRow
                      key={result.evaluation_id}
                      result={result}
                      onOpen={() => setSelected(result)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          </AsyncSection>

          <div className="flex items-center justify-between px-5 py-3 border-t"
            style={{ borderColor: C.border }}>
            <button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              disabled={offset === 0 || results.isLoading}
              className="flex items-center gap-1 px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
              style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
              <ChevronLeft size={12} /> Previous
            </button>
            <span className="text-xs" style={{ color: C.faint }}>
              {offset === 0 && !results.hasMore
                ? 'All anomaly results'
                : `Offset ${offset}`}
            </span>
            <button onClick={() => setOffset(offset + PAGE_SIZE)}
              disabled={!results.hasMore || results.isLoading}
              className="flex items-center gap-1 px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
              style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
              Next <ChevronRight size={12} />
            </button>
          </div>
        </div>
      ) : (
        <div className="rounded-2xl border overflow-hidden"
          style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
          <div className="flex items-center justify-between px-5 py-4 border-b"
            style={{ borderColor: C.border }}>
            <div>
              <h2 className="text-sm font-semibold text-white">Device models</h2>
              <p className="text-xs mt-0.5" style={{ color: C.faint }}>
                {models.models.length} device(s)
                {models.total !== null && ` · ${formatCount(models.total)} in total`}
                {` · ${models.readyCount} ready, ${models.collectingCount} collecting data`}
              </p>
            </div>
          </div>

          <AsyncSection
            isInitialLoading={models.isInitialLoading}
            error={models.blockingError}
            isEmpty={models.models.length === 0}
            loadingLabel="Loading model lifecycles…"
            emptyTitle="No device models yet"
            emptyHint="A model row appears the first time the engine evaluates a window for a device. Until then there is nothing to report — and nothing being checked."
            emptyIcon={<Brain size={28} />}
            errorTitle="Unable to load model lifecycles"
            onRetry={models.reload}
            minHeight={220}
          >
            <AnomalyModelsTable
              models={models.models}
              onRequestRetrain={model => {
                retrain.reset()
                setPendingRetrain(model)
              }}
              onOpenModel={model => setOpenModel(model)}
              retrainingDeviceKey={pendingRetrain?.device_key ?? null}
              isRetraining={retrain.isRunning}
            />
          </AsyncSection>
        </div>
      )}

      {pendingRetrain !== null && (
        <RetrainDialog
          model={pendingRetrain}
          isRetraining={retrain.isRunning}
          onCancel={() => setPendingRetrain(null)}
          onConfirm={() => void confirmRetrain()}
        />
      )}

      <p className="text-[11px] px-1" style={{ color: C.dim }}>
        Decision scores are raw Isolation Forest outputs — lower is more unusual. They
        are not probabilities, are not calibrated, and are not comparable between two
        devices' models. Model states: {ANOMALY_STATE_ORDER.map(modelStateLabel).join(' · ')}.
      </p>
    </div>
  )
}
