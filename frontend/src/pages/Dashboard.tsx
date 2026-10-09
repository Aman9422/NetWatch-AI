/**
 * Dashboard (M15.9/M15.30).
 *
 * Current state comes from `GET /dashboard/summary`; movement comes from
 * `/ws/dashboard`; and the two are combined by `useDashboard`, whose selector is
 * the only thing that decides which source a number came from. This page renders
 * that result and computes nothing: every rate, count and interface is the
 * backend's own value, because a second implementation in React would eventually
 * disagree with the one the API serves (M15.9).
 *
 * What replaced the mock design, and why:
 *
 * * the simulated 2-second `setInterval` that fabricated traffic is gone; the
 *   live tick arrives from the backend;
 * * the "traffic over time" chart no longer invents a series. It now plots the
 *   **observed ticks** — each point is a `packets_per_second` reading the backend
 *   actually sent — held in a bounded buffer so memory is a function of the
 *   configured capacity, not of how long the page is open (M15.36);
 * * the threat gauge, "AI Insights", protocol doughnut, top-talkers table and
 *   threat timeline were all fabricated and had no backend source in the
 *   dashboard aggregate, so they are replaced by real breakdowns the summary does
 *   carry (alerts by severity, incidents by status, devices by status) and by the
 *   recent findings it includes.
 *
 * The dashboard also owns the capture control, because "capture state" and
 * "interface" are two of the scalars M15.9 lists and the summary reports them.
 */

import { useEffect } from 'react'
import {
  Activity, AlertTriangle, Eye, Monitor, Network,
  Play, Radio, Shield, Square, Wifi,
} from 'lucide-react'
import {
  CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import type { ToastMsg } from '../App'
import {
  AsyncSection,
  EmptyState,
  RefreshFailureBanner,
  Spinner,
} from '../components/AsyncState'
import type { DashboardSectionName } from '../types'
import { useBoundedList, useCapture, useDashboard } from '../hooks'
import { UNKNOWN_TEXT, formatBitsPerSecond, formatBytesPerSecond, formatCount, formatItemsPerSecond } from '../lib/format'
import { C, SEVERITY_COLORS, TIP, tint } from '../lib/tokens'

/** How many observed ticks the live chart keeps. */
export const LIVE_TICK_CAPACITY = 60

/** One observed tick, for the live chart. */
interface LiveTick {
  readonly at: number
  readonly packetsPerSecond: number | null
  readonly bytesPerSecond: number | null
}

/** A single labelled metric, in the SOC banner. */
function BannerItem({ label, value, dot, mono = false }: {
  label: string
  value: string
  dot?: string | null
  mono?: boolean
}) {
  return (
    <div className="flex-1 flex flex-col justify-center px-5 py-3" style={{ borderColor: C.border }}>
      <span className="text-xs mb-1" style={{ color: C.faint }}>{label}</span>
      <div className="flex items-center gap-1.5">
        {dot && (
          <span className="relative flex h-1.5 w-1.5 shrink-0">
            <span className="relative inline-flex rounded-full h-1.5 w-1.5" style={{ backgroundColor: dot }} />
          </span>
        )}
        <span className={`text-xs font-semibold text-white ${mono ? 'mono' : ''}`}>{value}</span>
      </div>
    </div>
  )
}

/** One KPI tile. */
function KpiCard({ label, value, sub, icon, accent = C.accent }: {
  label: string
  value: string
  sub: string
  icon: React.ReactNode
  accent?: string
}) {
  return (
    <div
      className="rounded-2xl p-4 border flex flex-col gap-3"
      style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 20px rgba(0,0,0,0.2)' }}
    >
      <div className="p-2 rounded-xl w-fit" style={{ backgroundColor: tint(accent, 0.09) }}>
        <div style={{ color: accent }}>{icon}</div>
      </div>
      <div>
        <div className="text-2xl font-bold text-white leading-none mb-0.5 tracking-tight">{value}</div>
        <div className="text-xs font-medium" style={{ color: C.muted }}>{label}</div>
        <div className="text-xs mt-1" style={{ color: C.faint }}>{sub}</div>
      </div>
    </div>
  )
}

/** A titled card, matching the design's shell. */
function Card({ title, sub, action, children }: {
  title: string
  sub?: string
  action?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div
      className="rounded-2xl border flex flex-col overflow-hidden"
      style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}
    >
      <div className="flex items-center justify-between px-5 py-4 border-b shrink-0" style={{ borderColor: C.border }}>
        <div>
          <h3 className="text-sm font-semibold text-white">{title}</h3>
          {sub && <p className="text-xs mt-0.5" style={{ color: C.faint }}>{sub}</p>}
        </div>
        {action}
      </div>
      <div className="p-5 flex-1">{children}</div>
    </div>
  )
}

/** A breakdown row: label, bar, count. */
function Breakdown({ label, count, total, color }: {
  label: string
  count: number
  total: number
  color: string
}) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0
  return (
    <div className="flex items-center gap-2.5">
      <span className="w-2 h-2 rounded-sm shrink-0" style={{ backgroundColor: color }} />
      <span className="text-xs capitalize w-20" style={{ color: C.muted }}>{label.replace('_', ' ')}</span>
      <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
        <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs mono font-semibold w-8 text-right" style={{ color }}>{count}</span>
    </div>
  )
}

interface Props { showToast: (msg: string, type?: ToastMsg['type']) => void }

export default function Dashboard({ showToast }: Props) {
  const {
    summary, live, metrics, unavailable, error, blockingError,
    isInitialLoading, isRefreshing, reload, isConnected,
  } = useDashboard()
  const capture = useCapture()
  const ticks = useBoundedList<LiveTick>(LIVE_TICK_CAPACITY)
  const { prepend } = ticks

  // Each real tick is appended to the bounded series. Nothing is interpolated:
  // a gap is a gap, and the chart simply has fewer points for that interval.
  useEffect(() => {
    if (live === null) return
    prepend({
      at: Date.now(),
      packetsPerSecond: live.packets_per_second,
      bytesPerSecond: live.bytes_per_second,
    })
  }, [live, prepend])

  const series = ticks.items
    .slice()
    .reverse()
    .map((tick) => ({
      t: new Date(tick.at).toLocaleTimeString('en-US', { hour12: false, minute: '2-digit', second: '2-digit' }),
      pps: tick.packetsPerSecond,
      bps: tick.bytesPerSecond,
    }))

  const alerts = summary?.alerts.data ?? null
  const devices = summary?.devices.data ?? null
  const incidents = summary?.incidents.data ?? null
  const detections = summary?.detections.data ?? null

  const severityRows = alerts
    ? Object.entries(alerts.by_severity).sort((a, b) => b[1] - a[1])
    : []
  const severityTotal = severityRows.reduce((sum, [, n]) => sum + n, 0)

  const deviceRows = devices ? Object.entries(devices.by_status) : []
  const deviceTotal = deviceRows.reduce((sum, [, n]) => sum + n, 0)

  const incidentRows = incidents ? Object.entries(incidents.by_status) : []

  const packetsSub = metrics.packetCount === null
    ? 'Packet total unavailable'
    : `${formatCount(metrics.packetCount)} captured`

  /**
   * The backend's own reason a section could not be read, or `null` when it answered.
   *
   * Passed to each card so an unavailable section reads as *unread* rather than as
   * empty: "No alerts recorded" for a store that could not be reached would state a
   * calm absence where the truth is that nothing was read (M13.29/M15.8).
   */
  const reasonFor = (name: DashboardSectionName): string | null =>
    unavailable.find((entry) => entry.section === name)?.reason ?? null

  return (
    <div className="space-y-4 pb-2">
      {error !== null && summary !== null && (
        <RefreshFailureBanner error={error} onRetry={reload} />
      )}

      {/* ── SOC status banner ─────────────────────────────────────────────── */}
      <div className="rounded-2xl border overflow-hidden" style={{ backgroundColor: C.card, borderColor: C.border }}>
        <div className="flex divide-x" style={{ borderColor: C.border }}>
          <BannerItem
            label="Capture"
            value={metrics.captureRunning === null ? 'Unknown' : metrics.captureRunning ? 'Running' : 'Stopped'}
            dot={metrics.captureRunning ? C.success : C.dim}
          />
          <BannerItem label="Interface" value={metrics.interface ?? 'None selected'} mono />
          <BannerItem label="Live updates" value={isConnected ? 'Streaming' : 'Reconnecting'} dot={isConnected ? C.accent : C.warning} />
          <BannerItem
            label="Sections unavailable"
            value={unavailable.length === 0 ? 'None' : String(unavailable.length)}
            dot={unavailable.length === 0 ? C.success : C.warning}
          />
          <BannerItem label="Source" value={metrics.source === 'live' ? 'Live tick' : metrics.source === 'rest' ? 'Snapshot' : 'Unavailable'} />
        </div>
      </div>

      {/* ── KPI cards ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-4">
        <KpiCard
          label="Packets / sec" value={formatItemsPerSecond(metrics.packetsPerSecond)}
          sub={packetsSub} icon={<Activity size={16} />}
        />
        <KpiCard
          label="Throughput" value={formatBytesPerSecond(metrics.bytesPerSecond)}
          sub={formatBitsPerSecond(metrics.bitsPerSecond)} icon={<Wifi size={16} />} accent={C.info}
        />
        <KpiCard
          label="Active Devices" value={formatCount(metrics.deviceCount)}
          sub={deviceTotal > 0 ? `${deviceTotal} tracked` : 'Registry total'} icon={<Monitor size={16} />} accent={C.success}
        />
        <KpiCard
          label="Connections" value={formatCount(metrics.activeConnections)}
          sub="Currently active" icon={<Network size={16} />} accent={C.purple}
        />
        <KpiCard
          label="Open Alerts" value={formatCount(metrics.openAlerts)}
          sub={alerts ? `${alerts.total} stored` : 'Alert count'} icon={<AlertTriangle size={16} />} accent={C.danger}
        />
        <KpiCard
          label="Active Incidents" value={formatCount(metrics.activeIncidents)}
          sub={incidents ? `peak risk ${incidents.highest_risk_score}` : 'Correlated'} icon={<Shield size={16} />} accent={C.warning}
        />
      </div>

      {/* ── Live chart + capture control ──────────────────────────────────── */}
      <div className="grid gap-4" style={{ gridTemplateColumns: '1fr 320px' }}>
        <Card
          title="Live Throughput"
          sub="Packets and bytes per second, sampled from each backend tick"
          action={
            <div className="flex items-center gap-1.5 text-xs" style={{ color: C.faint }}>
              {isRefreshing ? <Spinner size={12} /> : (
                <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: isConnected ? C.success : C.warning }} />
              )}
              {isConnected ? 'Live' : 'Reconnecting'}
            </div>
          }
        >
          {series.length < 2 ? (
            <EmptyState
              title="Waiting for live ticks"
              hint="The dashboard updates as soon as the backend publishes a sample. Nothing is charted until a real reading arrives."
              icon={<Activity size={26} />}
              minHeight={200}
            />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={series} margin={{ top: 4, right: 6, left: -18, bottom: 0 }}>
                <CartesianGrid strokeDasharray="2 5" stroke="#1a2744" vertical={false} />
                <XAxis dataKey="t" tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
                <YAxis yAxisId="pps" tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false} />
                <YAxis yAxisId="bps" orientation="right" tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={TIP} />
                <Line yAxisId="pps" type="monotone" dataKey="pps" name="Packets/s" stroke={C.accent} strokeWidth={2} dot={false} connectNulls={false} />
                <Line yAxisId="bps" type="monotone" dataKey="bps" name="Bytes/s" stroke={C.info} strokeWidth={2} dot={false} connectNulls={false} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card title="Capture Control" sub="Start and stop the sensor">
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <Radio size={13} style={{ color: capture.isRunning ? C.success : C.faint }} />
              <span className="text-xs font-semibold" style={{ color: capture.isRunning ? C.success : C.muted }}>
                {capture.state ?? UNKNOWN_TEXT}
              </span>
              <span className="ml-auto text-xs mono" style={{ color: C.faint }}>
                {capture.status ? formatCount(capture.status.packet_count) : UNKNOWN_TEXT} pkts
              </span>
            </div>

            <div>
              <label className="text-xs" style={{ color: C.faint }}>Interface</label>
              <select
                value={capture.selectedInterface ?? ''}
                onChange={(e) => {
                  const name = e.target.value
                  if (name === '') return
                  void capture.select(name).then((err) => {
                    if (err) showToast(err.userMessage, 'error')
                    else showToast(`Interface set to ${name}`, 'success')
                  })
                }}
                disabled={capture.interfaces.length === 0 || capture.isStarting || capture.isRunning}
                className="w-full mt-1 px-3 py-2 rounded-xl text-xs border"
                style={{ backgroundColor: C.panel, borderColor: C.border, color: C.text, outline: 'none' }}
              >
                <option value="">{capture.interfaces.length === 0 ? 'No adapter reported' : 'Select an adapter'}</option>
                {capture.interfaces.map((iface) => (
                  <option key={iface.name} value={iface.name}>{iface.name}</option>
                ))}
              </select>
            </div>

            {capture.captureErrorReason && (
              <div className="px-3 py-2 rounded-xl text-xs" style={{ backgroundColor: 'rgba(239,68,68,0.08)', color: C.danger }}>
                {capture.captureErrorReason}
              </div>
            )}
            {capture.actionError && (
              <div className="px-3 py-2 rounded-xl text-xs" style={{ backgroundColor: 'rgba(239,68,68,0.08)', color: C.danger }}>
                {capture.actionError.userMessage}
              </div>
            )}

            <div className="flex gap-2">
              <button
                onClick={() => {
                  void capture.start().then((err) => {
                    if (err) showToast(err.userMessage, 'error')
                    else showToast('Capture started', 'success')
                  })
                }}
                disabled={capture.isRunning || capture.isStarting || capture.isStopping}
                className="flex-1 flex items-center justify-center gap-1.5 py-2.5 rounded-xl text-xs font-semibold disabled:opacity-40"
                style={{ backgroundColor: tint(C.success, 0.16), color: C.success }}
              >
                {capture.isStarting ? <Spinner size={12} color={C.success} /> : <Play size={12} />} Start
              </button>
              <button
                onClick={() => {
                  void capture.stop().then((err) => {
                    if (err) showToast(err.userMessage, 'error')
                    else showToast('Capture stopped', 'info')
                  })
                }}
                disabled={!capture.isRunning || capture.isStarting || capture.isStopping}
                className="flex-1 flex items-center justify-center gap-1.5 py-2.5 rounded-xl text-xs font-semibold disabled:opacity-40"
                style={{ backgroundColor: tint(C.danger, 0.16), color: C.danger }}
              >
                {capture.isStopping ? <Spinner size={12} color={C.danger} /> : <Square size={12} />} Stop
              </button>
            </div>
          </div>
        </Card>
      </div>

      {/* ── Breakdowns ────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-4">
          <Card title="Alerts by Severity" sub="Stored alerts across every state">
            <AsyncSection
              isInitialLoading={isInitialLoading}
              error={blockingError}
              isEmpty={alerts === null || severityRows.length === 0}
              unavailableReason={reasonFor('alerts')}
              emptyTitle="No alerts recorded"
              emptyHint="The alert engine has not raised anything yet."
              emptyIcon={<Shield size={26} />}
              loadingLabel="Loading alert counts…"
              onRetry={reload}
            >
              <div className="space-y-3">
                {severityRows.map(([severity, count]) => (
                  <Breakdown
                    key={severity}
                    label={severity}
                    count={count}
                    total={severityTotal}
                    color={SEVERITY_COLORS[severity] ?? C.dim}
                  />
                ))}
              </div>
            </AsyncSection>
          </Card>
        </div>

        <div className="col-span-4">
          <Card title="Devices by Activity" sub="M8 activity, not a security verdict">
            <AsyncSection
              isInitialLoading={isInitialLoading}
              error={blockingError}
              isEmpty={devices === null || deviceRows.length === 0}
              unavailableReason={reasonFor('devices')}
              emptyTitle="No devices observed"
              emptyHint="The registry reports a device once it appears on the wire."
              emptyIcon={<Monitor size={26} />}
              loadingLabel="Loading device states…"
              onRetry={reload}
            >
              <div className="space-y-3">
                {deviceRows.map(([status, count]) => (
                  <Breakdown key={status} label={status} count={count} total={deviceTotal} color={C.accent} />
                ))}
              </div>
            </AsyncSection>
          </Card>
        </div>

        <div className="col-span-4">
          <Card title="Incidents by Status" sub="Correlated, with their highest risk score">
            <AsyncSection
              isInitialLoading={isInitialLoading}
              error={blockingError}
              isEmpty={incidents === null || incidentRows.length === 0}
              unavailableReason={reasonFor('incidents')}
              emptyTitle="No incidents correlated"
              emptyHint="An incident appears once related events are grouped."
              emptyIcon={<Shield size={26} />}
              loadingLabel="Loading incident states…"
              onRetry={reload}
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-2 border-b" style={{ borderColor: C.border }}>
                  <span className="text-xs" style={{ color: C.faint }}>Highest risk score</span>
                  <span className="text-sm font-bold" style={{ color: C.warning }}>{incidents?.highest_risk_score ?? UNKNOWN_TEXT}</span>
                </div>
                {incidentRows.map(([status, count]) => (
                  <Breakdown key={status} label={status} count={count} total={incidents?.total ?? 0} color={C.purple} />
                ))}
              </div>
            </AsyncSection>
          </Card>
        </div>
      </div>

      {/* ── Recent findings + unavailable sections ────────────────────────── */}
      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-8">
          <Card title="Recent Findings" sub="M10 observations — a finding is not an alert">
            <AsyncSection
              isInitialLoading={isInitialLoading}
              error={blockingError}
              isEmpty={detections === null || detections.recent.length === 0}
              unavailableReason={reasonFor('detections')}
              emptyTitle="No recent findings"
              emptyHint="Detectors raise a finding when their condition is met."
              emptyIcon={<Eye size={26} />}
              loadingLabel="Loading findings…"
              onRetry={reload}
            >
              <div className="space-y-2">
                {detections?.recent.map((finding) => (
                  <div
                    key={finding.finding_id}
                    className="flex items-center gap-3 px-3 py-2.5 rounded-xl"
                    style={{ backgroundColor: C.panel }}
                  >
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-semibold text-white truncate">{finding.rule_name}</div>
                      <div className="text-xs mt-0.5 truncate" style={{ color: C.faint }}>
                        {finding.description}
                      </div>
                    </div>
                    <span className="text-xs mono" style={{ color: C.accent }}>
                      {finding.source_ip ?? UNKNOWN_TEXT}
                    </span>
                  </div>
                ))}
              </div>
            </AsyncSection>
          </Card>
        </div>

        <div className="col-span-4">
          <Card title="Backend Availability" sub="Sections the summary could not read">
            {unavailable.length === 0 ? (
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: C.success }} />
                <span className="text-xs" style={{ color: C.muted }}>Every section answered.</span>
              </div>
            ) : (
              <div className="space-y-2">
                {unavailable.map((section) => (
                  <div
                    key={section.section}
                    className="px-3 py-2.5 rounded-xl border"
                    style={{ backgroundColor: 'rgba(245,158,11,0.06)', borderColor: 'rgba(245,158,11,0.22)' }}
                  >
                    <div className="flex items-center gap-1.5">
                      <AlertTriangle size={12} style={{ color: C.warning }} />
                      <span className="text-xs font-semibold capitalize" style={{ color: C.warning }}>
                        {section.section}
                      </span>
                    </div>
                    <p className="text-xs mt-1" style={{ color: C.muted }}>{section.reason}</p>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  )
}
