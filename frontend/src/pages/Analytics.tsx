/**
 * Analytics — five derived views, read from the endpoints that own them (M15.21).
 *
 * Analytics is a *derived view* over services that already exist, and the mock
 * page this replaces was almost entirely invention: twenty-four hourly traffic
 * points, a monthly threat trend, CPU and link utilisation, a packet-size
 * histogram — series no milestone computes. M6 holds a point-in-time snapshot and
 * M13 exposes rankings and totals, so those charts are **removed rather than
 * faked** (M15.31). What remains is every figure the backend actually answers.
 *
 * Three properties of the data shape this page, and getting any of them wrong
 * would render something false:
 *
 * * **A ranking is traffic, not risk.** The device and connection rankings carry
 *   packet and byte totals; M8 and M9 score nothing, so nothing here is coloured
 *   as a verdict (M15.21).
 * * **The three threat layers stay separate.** M10's findings, M11's alerts and
 *   M12's incidents are distinct objects, and only the incident block carries a
 *   risk score. They are rendered as three cards, never summed into one "threat
 *   level" number no milestone produces.
 * * **A section failure is per-section.** The bundle keeps a failure per endpoint
 *   (`fetchAnalyticsBundle`), so one unavailable block shows a placeholder of its
 *   own while the other four render — instead of blanking the page for one
 *   endpoint (M15.8).
 *
 * Analytics publishes no WebSocket channel, so there is no live path: the data is
 * read and refreshed explicitly (M15.34).
 */

import { useState } from 'react'
import {
  BarChart, Bar, Cell, PieChart, Pie, ResponsiveContainer, Tooltip,
  XAxis, YAxis, CartesianGrid,
} from 'recharts'
import {
  Activity, AlertTriangle, ArrowUpDown, Gauge, Hash, Layers, Network,
  RefreshCw, Server, Share2, ShieldAlert, TrendingUp,
} from 'lucide-react'
import { AsyncSection, EmptyState, Spinner } from '@/components/AsyncState'
import { useAnalytics } from '@/hooks'
import { DEFAULT_ANALYTICS_LIMIT } from '@/services'
import type { AnalyticsBundle } from '@/services'
import {
  C, TIP, tint, ALERT_STATUS_COLORS, DEVICE_STATUS_COLORS,
  INCIDENT_STATUS_COLORS, RISK_BAND_COLORS, SEVERITY_COLORS,
} from '@/lib/tokens'
import {
  UNKNOWN_TEXT, formatBitsPerSecond, formatBytes, formatBytesPerSecond,
  formatCount, formatEndpoint, formatItemsPerSecond, formatPercentage,
  formatRiskScore,
} from '@/lib/format'
import type {
  DirectionStat, ProtocolStat, RankMetric, RankedConnection,
  RankedDevice, ThreatRuleStat, TopEntry,
} from '@/types'

/** How many ranked entries each block asks the backend for. */
const RANK_LIMIT = DEFAULT_ANALYTICS_LIMIT

/** Ranked bars cycle these shades, so two adjacent bars never share a colour. */
const RANK_COLORS: readonly string[] = [
  C.accent, C.purple, C.info, C.success, C.warning, C.orange, C.danger, C.dim,
]

/** A readable label for an enum-ish backend value (`false_positive` → `False positive`). */
function humanise(value: string): string {
  const spaced = value.replace(/_/g, ' ')
  return spaced.charAt(0).toUpperCase() + spaced.slice(1)
}

/** The colour for a key in a counted breakdown, falling back to a neutral shade. */
function breakdownColor(value: string, palette: Readonly<Record<string, string>>): string {
  return palette[value] ?? C.muted
}

// ─── Building blocks ─────────────────────────────────────────────────────────

/** A titled panel. Every block on the page is one of these. */
function ChartCard({ title, sub, children, right }: {
  title: string
  sub?: string
  children: React.ReactNode
  right?: React.ReactNode
}) {
  return (
    <div className="rounded-2xl border p-5"
      style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 20px rgba(0,0,0,0.15)' }}>
      <div className="flex items-start justify-between gap-3 mb-4">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">{title}</h3>
          {sub && <p className="text-xs mt-0.5" style={{ color: C.faint }}>{sub}</p>}
        </div>
        {right}
      </div>
      {children}
    </div>
  )
}

/** One figure with its own unit and an icon. */
function StatTile({ label, value, hint, icon, color }: {
  label: string
  value: string
  hint: string
  icon: React.ReactNode
  color: string
}) {
  return (
    <div className="rounded-2xl border p-3 sm:p-4" title={hint}
      style={{ backgroundColor: C.card, borderColor: C.border }}>
      <div className="flex items-center gap-2 mb-2 min-w-0">
        <div className="p-1.5 rounded-lg shrink-0" style={{ backgroundColor: tint(color, 0.1) }}>
          <span style={{ color }}>{icon}</span>
        </div>
        <span className="text-xs font-medium truncate" style={{ color: C.muted }}>{label}</span>
      </div>
      <div className="text-xl font-bold text-white leading-none">{value}</div>
    </div>
  )
}

/**
 * A placeholder for one analytics block that could not be read.
 *
 * A block, not the page: the remaining four answered, and replacing them with one
 * error would throw away data the backend did return (M15.8).
 */
function SectionFailure({ section, message }: { section: string; message: string }) {
  return (
    <div className="rounded-2xl border p-5 flex flex-col items-center justify-center gap-2 text-center"
      style={{ backgroundColor: C.card, borderColor: 'rgba(239,68,68,0.25)', minHeight: 180 }}>
      <AlertTriangle size={20} style={{ color: C.danger }} />
      <p className="text-sm font-medium text-white">{humanise(section)} unavailable</p>
      <p className="text-xs max-w-sm" style={{ color: C.muted }}>{message}</p>
    </div>
  )
}

/** The failure for a section, or `null` when it answered. */
function failureFor(bundle: AnalyticsBundle | null, section: string): string | null {
  if (bundle === null) return null
  const found = bundle.failures.find(f => f.section === section)
  return found?.message ?? null
}

/** A ranked list of `TopEntry`, with the bars scaled against the leader. */
function TopEntryList({ entries, metric, keyLabel }: {
  entries: readonly TopEntry[]
  metric: RankMetric
  keyLabel: string
}) {
  if (entries.length === 0) {
    return (
      <p className="text-xs py-8 text-center" style={{ color: C.faint }}>
        Nothing recorded in this window.
      </p>
    )
  }
  // The leader sets the scale. Dividing by a fixed maximum would be inventing a
  // denominator the backend never sent.
  const leader = Math.max(...entries.map(e => (metric === 'bytes' ? e.bytes : e.packets)), 1)
  return (
    <div className="space-y-3">
      {entries.map((entry, index) => {
        const value = metric === 'bytes' ? entry.bytes : entry.packets
        const color = RANK_COLORS[index % RANK_COLORS.length]
        return (
          <div key={entry.key} className="flex items-center gap-3">
            <div className="w-5 text-xs font-bold text-right" style={{ color: C.faint }}>
              #{index + 1}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex flex-wrap justify-between gap-x-2 gap-y-0.5 text-xs mb-1">
                <span className="mono truncate" style={{ color: C.muted }} title={`${keyLabel}: ${entry.key}`}>
                  {entry.key}
                </span>
                <span className="mono font-semibold whitespace-nowrap" style={{ color }}>
                  {metric === 'bytes' ? formatBytes(entry.bytes) : formatCount(entry.packets)}
                </span>
              </div>
              <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
                <div className="h-full rounded-full"
                  style={{ width: `${Math.max(2, Math.round((value / leader) * 100))}%`, backgroundColor: color }} />
              </div>
              <div className="text-xs mt-1" style={{ color: C.faint }}>
                {metric === 'bytes'
                  ? `${formatCount(entry.packets)} packets`
                  : formatBytes(entry.bytes)}
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

/** A counted breakdown as chips, e.g. `open 3 · resolved 12`. */
function Breakdown({ counts, palette }: {
  counts: Readonly<Record<string, number>>
  palette: Readonly<Record<string, string>>
}) {
  const entries = Object.entries(counts)
  if (entries.length === 0) {
    return <span className="text-xs" style={{ color: C.faint }}>No breakdown reported.</span>
  }
  return (
    <div className="flex items-center gap-2 flex-wrap">
      {entries.map(([key, count]) => {
        const color = breakdownColor(key, palette)
        return (
          <span key={key} className="flex items-center gap-1.5 px-2 py-1 rounded-lg text-xs"
            style={{ backgroundColor: tint(color, 0.1), color }}>
            <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />
            {humanise(key)}
            <span className="mono font-semibold">{formatCount(count)}</span>
          </span>
        )
      })}
    </div>
  )
}

/** A protocol distribution doughnut, drawn from the percentages M6 computed. */
function ProtocolDoughnut({ protocols }: { protocols: readonly ProtocolStat[] }) {
  if (protocols.length === 0) {
    return (
      <p className="text-xs py-16 text-center" style={{ color: C.faint }}>
        No protocol traffic recorded.
      </p>
    )
  }
  const data = protocols.map((stat, index) => ({
    name: stat.protocol,
    value: stat.packets,
    percentage: stat.percentage,
    color: RANK_COLORS[index % RANK_COLORS.length],
  }))
  return (
    // The doughnut is a fixed 150px. Below `sm` the two stack, so the legend is not
    // squeezed into whatever is left of a narrow card — the row needs ~140px, and at
    // 320px the card offers 66px beside the chart (M16.15).
    <div className="flex flex-col sm:flex-row items-center gap-4">
      <ResponsiveContainer width={150} height={150}>
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" innerRadius={42} outerRadius={66}
            strokeWidth={0} paddingAngle={2} isAnimationActive={false}>
            {data.map(entry => <Cell key={entry.name} fill={entry.color} />)}
          </Pie>
          <Tooltip contentStyle={TIP} />
        </PieChart>
      </ResponsiveContainer>
      <div className="space-y-2 flex-1 min-w-0 w-full">
        {protocols.map((stat, index) => (
          <div key={stat.protocol} className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-sm shrink-0"
              style={{ backgroundColor: RANK_COLORS[index % RANK_COLORS.length] }} />
            <span className="text-xs truncate" style={{ color: C.muted }}>{stat.protocol}</span>
            <span className="mono text-xs font-semibold ml-auto whitespace-nowrap" style={{ color: C.text }}>
              {formatPercentage(stat.percentage)}
            </span>
            <span className="mono text-xs whitespace-nowrap w-20 text-right" style={{ color: C.faint }}>
              {formatCount(stat.packets)}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

/** Inbound / outbound / local traffic, from M6's direction breakdown. */
function DirectionChart({ directions }: { directions: readonly DirectionStat[] }) {
  if (directions.length === 0) {
    return (
      <p className="text-xs py-16 text-center" style={{ color: C.faint }}>
        No directional traffic recorded.
      </p>
    )
  }
  const data = directions.map(stat => ({
    name: humanise(stat.direction),
    packets: stat.packets,
    bytes: stat.bytes,
  }))
  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }} barSize={26}>
        <CartesianGrid strokeDasharray="2 5" stroke="#1a2744" vertical={false} />
        <XAxis dataKey="name" tick={{ fill: C.dim, fontSize: 10 }} tickLine={false} axisLine={false} />
        <YAxis tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={TIP} />
        <Bar dataKey="packets" name="Packets" radius={[4, 4, 0, 0]} isAnimationActive={false}>
          {data.map((_, index) => <Cell key={index} fill={RANK_COLORS[index % RANK_COLORS.length]} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
// ─── Page ────────────────────────────────────────────────────────────────────

/** A small labelled figure, for a counter inside a card. */
function SmallFigure({ label, value, color = C.text }: {
  label: string
  value: string
  color?: string
}) {
  return (
    <div>
      <div className="text-xs mb-0.5" style={{ color: C.faint }}>{label}</div>
      <div className="mono text-lg font-bold leading-none whitespace-nowrap" style={{ color }}>{value}</div>
    </div>
  )
}

/** One ranked device, read from the M8 registry. No risk figure exists to show. */
function DeviceRow({ device, metric }: { device: RankedDevice; metric: RankMetric }) {
  const statusColor = DEVICE_STATUS_COLORS[device.status] ?? C.muted
  const primaryAddress = device.ip_addresses[0] ?? UNKNOWN_TEXT
  return (
    <tr className="border-b" style={{ borderColor: '#1a2744' }}>
      <td className="pl-5 py-2.5 pr-3">
        <div className="text-xs font-semibold text-white truncate max-w-55"
          title={device.hostname ?? device.device_id}>
          {device.hostname ?? device.mac_address ?? device.device_id}
        </div>
        <div className="mono text-xs mt-0.5" style={{ color: C.faint }}>
          {primaryAddress}
          {device.ip_addresses.length > 1 ? ` +${device.ip_addresses.length - 1}` : ''}
        </div>
      </td>
      <td className="py-2.5 pr-3">
        <span className="flex items-center gap-1.5 text-xs w-fit" style={{ color: statusColor }}>
          <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: statusColor }} />
          {humanise(device.status)}
        </span>
      </td>
      <td className="py-2.5 pr-5 text-right">
        <div className="mono text-xs font-semibold" style={{ color: C.text }}>
          {metric === 'bytes' ? formatBytes(device.bytes) : formatCount(device.packets)}
        </div>
        <div className="mono text-xs mt-0.5" style={{ color: C.faint }}>
          {metric === 'bytes' ? `${formatCount(device.packets)} packets` : formatBytes(device.bytes)}
        </div>
      </td>
    </tr>
  )
}

/** One ranked conversation, read from the M9 tracker. Its state is the tracker's own. */
function ConnectionRow({ connection, metric }: { connection: RankedConnection; metric: RankMetric }) {
  return (
    <tr className="border-b" style={{ borderColor: '#1a2744' }}>
      <td className="pl-5 py-2.5 pr-3">
        <div className="flex items-center gap-2">
          <span className="mono text-xs font-semibold px-1.5 py-0.5 rounded"
            style={{ backgroundColor: tint(C.accent, 0.1), color: C.accent }}>
            {connection.protocol}
          </span>
          <span className="mono text-xs truncate" style={{ color: C.text }}>
            {formatEndpoint(connection.source_ip, connection.source_port)}
            <span style={{ color: C.dim }}> → </span>
            {formatEndpoint(connection.destination_ip, connection.destination_port)}
          </span>
        </div>
      </td>
      <td className="py-2.5 pr-3 text-xs" style={{ color: C.muted }}>
        {humanise(connection.state)}
      </td>
      <td className="py-2.5 pr-5 text-right">
        <div className="mono text-xs font-semibold" style={{ color: C.text }}>
          {metric === 'bytes' ? formatBytes(connection.bytes) : formatCount(connection.packets)}
        </div>
        <div className="mono text-xs mt-0.5" style={{ color: C.faint }}>
          {metric === 'bytes' ? `${formatCount(connection.packets)} packets` : formatBytes(connection.bytes)}
        </div>
      </td>
    </tr>
  )
}

/**
 * One detection rule's execution counters (M10.31).
 *
 * The row wraps rather than truncating a counter: `Port Scan` and its five-digit
 * evaluation count do not both fit a column in a three-card row, and a fixed-width
 * counter column would paint its number over the row's edge instead of moving. The
 * name keeps a readable minimum and the counters drop to their own line, so every
 * figure stays legible at any card width (M16.15).
 */
function RuleRow({ rule }: { rule: ThreatRuleStat }) {
  const color = rule.enabled ? C.success : C.dim
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-2 py-2 rounded-lg"
      style={{ backgroundColor: C.panel }}>
      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: color }} />
      <span className="text-xs truncate flex-1 min-w-24" style={{ color: C.text }} title={rule.rule_id}>
        {rule.rule_name}
      </span>
      <span className="flex items-center gap-3 shrink-0">
        <span className="mono text-xs whitespace-nowrap" style={{ color: C.faint }}>
          {formatCount(rule.evaluations)} evals
        </span>
        <span className="mono text-xs whitespace-nowrap text-right"
          style={{ color: rule.findings > 0 ? C.warning : C.dim }}>
          {formatCount(rule.findings)} finds
        </span>
        {rule.errors > 0 && (
          <span className="mono text-xs whitespace-nowrap" style={{ color: C.danger }}
            title={`${rule.errors} detector errors`}>
            {formatCount(rule.errors)} err
          </span>
        )}
      </span>
    </div>
  )
}

export default function Analytics() {
  // The ranking metric is a real query parameter (`by`) on four of the five
  // endpoints, so switching it re-asks the backend rather than re-sorting rows
  // this client already holds.
  const [metric, setMetric] = useState<RankMetric>('packets')

  const resource = useAnalytics({ by: metric, limit: RANK_LIMIT })
  const bundle = resource.bundle

  const traffic = bundle?.traffic ?? null
  const protocols = bundle?.protocols ?? null
  const devices = bundle?.devices ?? null
  const connections = bundle?.connections ?? null
  const threats = bundle?.threats ?? null

  const trafficFailure = failureFor(bundle, 'traffic')
  const protocolsFailure = failureFor(bundle, 'protocols')
  const devicesFailure = failureFor(bundle, 'devices')
  const connectionsFailure = failureFor(bundle, 'connections')
  const threatsFailure = failureFor(bundle, 'threats')

  // A *total* failure is one error and no bundle at all: analytics is unreachable.
  // That is different from a bundle carrying `failures`, where the four blocks that
  // answered are still worth showing.
  if (resource.error !== null && bundle === null) {
    return (
      <div className="rounded-2xl border" style={{ backgroundColor: C.card, borderColor: C.border }}>
        <AsyncSection isInitialLoading={resource.isInitialLoading} error={resource.blockingError}
          isEmpty={false} errorTitle="Unable to load analytics"
          onRetry={resource.reload} minHeight={320}>
          <span />
        </AsyncSection>
      </div>
    )
  }

  return (
    <div className="space-y-4 fade-in-up">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-lg font-bold text-white">Network Analytics</h1>
          <p className="text-xs mt-0.5" style={{ color: C.faint }}>
            Totals and rankings from the M6 snapshot, the M8 registry, the M9 tracker and the
            M10–M12 engines.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 p-1 rounded-xl"
            style={{ backgroundColor: C.card, border: `1px solid ${C.border}` }}>
            {(['packets', 'bytes'] as const).map(option => (
              <button key={option} onClick={() => setMetric(option)}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all capitalize"
                style={{
                  backgroundColor: metric === option ? C.accent : 'transparent',
                  color: metric === option ? '#0F172A' : C.faint,
                }}>
                {option}
              </button>
            ))}
          </div>
          <button onClick={resource.reload} disabled={resource.isLoading}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border disabled:opacity-50"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
            <RefreshCw size={12} className={resource.isLoading ? 'animate-spin' : undefined} />
            Refresh
          </button>
        </div>
      </div>

      {resource.failures.length > 0 && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-xl border text-xs"
          style={{
            backgroundColor: 'rgba(245,158,11,0.08)',
            borderColor: 'rgba(245,158,11,0.25)',
            color: C.warning,
          }}>
          <AlertTriangle size={12} style={{ flexShrink: 0 }} />
          <span className="flex-1" style={{ color: C.muted }}>
            {resource.failures.length} of 5 analytics sections did not answer. The blocks below
            carry the sections that did.
          </span>
          <button onClick={resource.reload} className="font-semibold" style={{ color: C.warning }}>
            Retry
          </button>
        </div>
      )}

      {resource.isInitialLoading && (
        <div className="rounded-2xl border" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="flex flex-col items-center justify-center gap-3" style={{ minHeight: 280 }}>
            <Spinner size={20} />
            <p className="text-xs" style={{ color: C.faint }}>Loading analytics…</p>
          </div>
        </div>
      )}

      {!resource.isInitialLoading && (
        <>
          {/* Traffic totals — one M6 snapshot, so every figure describes the same instant. */}
          <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3 sm:gap-4">
            {traffic === null ? (
              <div className="col-span-2 lg:col-span-3 xl:col-span-6">
                {trafficFailure === null
                  ? null
                  : <SectionFailure section="traffic" message={trafficFailure} />}
              </div>
            ) : (
              <>
                <StatTile label="Packets" value={formatCount(traffic.total_packets)}
                  hint="Total packets the M6 snapshot attributes to the capture session."
                  icon={<Hash size={14} />} color={C.accent} />
                <StatTile label="Bytes" value={formatBytes(traffic.total_bytes)}
                  hint="Total bytes the snapshot counts."
                  icon={<Server size={14} />} color={C.purple} />
                <StatTile label="Packets/sec" value={formatItemsPerSecond(traffic.packets_per_second)}
                  hint="The rate M6 computed. This page does not divide counters itself."
                  icon={<Activity size={14} />} color={C.info} />
                <StatTile label="Bytes/sec" value={formatBytesPerSecond(traffic.bytes_per_second)}
                  hint="The throughput M6 computed."
                  icon={<Gauge size={14} />} color={C.success} />
                <StatTile label="Bits/sec" value={formatBitsPerSecond(traffic.bits_per_second)}
                  hint="The same throughput in the unit a link is sold in."
                  icon={<TrendingUp size={14} />} color={C.warning} />
                <StatTile label="Avg packet" value={formatBytes(traffic.average_packet_bytes)}
                  hint="total_bytes / total_packets, computed by the backend."
                  icon={<ArrowUpDown size={14} />} color={C.orange} />
              </>
            )}
          </div>

          {/* Composition — the snapshot's protocol and direction breakdowns. The doughnut
              is a fixed 150px, so the legend needs the card to itself below 1024px. */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <ChartCard title="Protocol distribution" sub="Share of packets, as the snapshot counted them">
              {protocolsFailure !== null ? (
                <SectionFailure section="protocols" message={protocolsFailure} />
              ) : (
                <ProtocolDoughnut protocols={traffic?.protocols ?? protocols?.protocols ?? []} />
              )}
            </ChartCard>
            <ChartCard title="Traffic direction" sub="Inbound, outbound and local packets">
              {trafficFailure !== null
                ? <SectionFailure section="traffic" message={trafficFailure} />
                : <DirectionChart directions={traffic?.directions ?? []} />}
            </ChartCard>
          </div>

          {/* Leading talkers, from the traffic snapshot. */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <ChartCard title="Top sources" sub={`Ranked by ${metric} — traffic, not risk`}>
              {trafficFailure !== null
                ? <SectionFailure section="traffic" message={trafficFailure} />
                : <TopEntryList entries={traffic?.top_sources ?? []} metric={metric} keyLabel="Source" />}
            </ChartCard>
            <ChartCard title="Top destinations" sub={`Ranked by ${metric} — traffic, not risk`}>
              {trafficFailure !== null
                ? <SectionFailure section="traffic" message={trafficFailure} />
                : <TopEntryList entries={traffic?.top_destinations ?? []} metric={metric} keyLabel="Destination" />}
            </ChartCard>
            <ChartCard title="Top ports" sub={`Ranked by ${metric}`}>
              {trafficFailure !== null
                ? <SectionFailure section="traffic" message={trafficFailure} />
                : <TopEntryList entries={traffic?.top_ports ?? []} metric={metric} keyLabel="Port" />}
            </ChartCard>
          </div>

          {/* Observed entities — traffic rankings, deliberately unscored. Each table
              scrolls inside its own card, so the card may keep half the row. */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <ChartCard title="Busiest devices" sub={`M8 registry, ranked by ${metric} — activity, not risk`}
              right={<Layers size={14} style={{ color: C.faint }} />}>
              {devicesFailure !== null ? (
                <SectionFailure section="devices" message={devicesFailure} />
              ) : devices === null ? (
                <SectionFailure section="devices" message="The block did not answer." />
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center gap-4 flex-wrap">
                    <span className="text-xs" style={{ color: C.muted }}>
                      {formatCount(devices.total)} device{devices.total === 1 ? '' : 's'} known
                    </span>
                    <Breakdown counts={devices.by_status} palette={DEVICE_STATUS_COLORS} />
                  </div>
                  {devices.top.length === 0 ? (
                    <EmptyState title="No devices observed"
                      hint="M8 registers a device when a packet carries its address. Nothing has been observed yet."
                      icon={<Layers size={24} />} minHeight={140} />
                  ) : (
                    <div className="overflow-x-auto -mx-5">
                      <table className="w-full">
                        <thead>
                          <tr className="border-b" style={{ borderColor: C.border }}>
                            <th className="text-left pl-5 py-2 pr-3 text-xs font-medium" style={{ color: C.dim }}>Device</th>
                            <th className="text-left py-2 pr-3 text-xs font-medium" style={{ color: C.dim }}>Status</th>
                            <th className="text-right py-2 pr-5 text-xs font-medium" style={{ color: C.dim }}>Traffic</th>
                          </tr>
                        </thead>
                        <tbody>
                          {devices.top.map(device => (
                            <DeviceRow key={device.device_id} device={device} metric={metric} />
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </ChartCard>

            <ChartCard title="Busiest conversations" sub={`M9 tracker, ranked by ${metric} — not a verdict`}
              right={<Network size={14} style={{ color: C.faint }} />}>
              {connectionsFailure !== null ? (
                <SectionFailure section="connections" message={connectionsFailure} />
              ) : connections === null ? (
                <SectionFailure section="connections" message="The block did not answer." />
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center gap-4 flex-wrap text-xs" style={{ color: C.muted }}>
                    <span className="flex items-center gap-1.5">
                      <Share2 size={11} style={{ color: C.faint }} />
                      {formatCount(connections.tracked)} tracked
                    </span>
                    <span>{formatCount(connections.active)} active</span>
                    <span>{formatCount(connections.historical)} historical</span>
                  </div>
                  {connections.top.length === 0 ? (
                    <EmptyState title="No conversations tracked"
                      hint="M9 opens a conversation when a packet starts one. Start a capture to populate the tracker."
                      icon={<Share2 size={24} />} minHeight={140} />
                  ) : (
                    <div className="overflow-x-auto -mx-5">
                      <table className="w-full">
                        <thead>
                          <tr className="border-b" style={{ borderColor: C.border }}>
                            <th className="text-left pl-5 py-2 pr-3 text-xs font-medium" style={{ color: C.dim }}>Conversation</th>
                            <th className="text-left py-2 pr-3 text-xs font-medium" style={{ color: C.dim }}>State</th>
                            <th className="text-right py-2 pr-5 text-xs font-medium" style={{ color: C.dim }}>Traffic</th>
                          </tr>
                        </thead>
                        <tbody>
                          {connections.top.map(connection => (
                            <ConnectionRow key={connection.connection_id} connection={connection} metric={metric} />
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </ChartCard>
          </div>

          {/* Threats — three layers, three cards, never one number. */}
          {threatsFailure !== null || threats === null ? (
            <SectionFailure section="threats"
              message={threatsFailure ?? 'The block did not answer.'} />
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <ChartCard title="Detection findings" sub="M10 — observations, not alerts"
                right={<Gauge size={14} style={{ color: C.faint }} />}>
                <div className="space-y-4">
                  {/* Figures wrap to the next line instead of painting over the neighbour. */}
                  <div className="flex flex-wrap gap-x-5 gap-y-3">
                    <SmallFigure label="Retained" value={formatCount(threats.findings_retained)} />
                    <SmallFigure label="Evaluations" value={formatCount(threats.detections_evaluated)} />
                    <SmallFigure label="Findings" value={formatCount(threats.detections_findings)} />
                  </div>
                  {threats.detections_errors > 0 && (
                    <p className="flex items-center gap-1.5 text-xs" style={{ color: C.danger }}>
                      <AlertTriangle size={11} />
                      {formatCount(threats.detections_errors)} detector errors recorded
                    </p>
                  )}
                  {threats.rules.length === 0 ? (
                    <p className="text-xs py-4 text-center" style={{ color: C.faint }}>
                      No detection rules registered.
                    </p>
                  ) : (
                    <div className="space-y-2">
                      {threats.rules.map(rule => (
                        <RuleRow key={rule.rule_id} rule={rule} />
                      ))}
                    </div>
                  )}
                </div>
              </ChartCard>

              <ChartCard title="Alerts" sub="M11 — evidence-based judgement"
                right={<ShieldAlert size={14} style={{ color: C.faint }} />}>
                <div className="space-y-4">
                  <div className="flex flex-wrap gap-x-5 gap-y-3">
                    <SmallFigure label="Total" value={formatCount(threats.alerts_total)} />
                    <SmallFigure label="Open" value={formatCount(threats.alerts_open)} color={C.danger} />
                  </div>
                  <div>
                    <p className="text-xs mb-2" style={{ color: C.faint }}>By severity</p>
                    <Breakdown counts={threats.alerts_by_severity} palette={SEVERITY_COLORS} />
                  </div>
                  <div>
                    <p className="text-xs mb-2" style={{ color: C.faint }}>By lifecycle state</p>
                    <Breakdown counts={threats.alerts_by_status} palette={ALERT_STATUS_COLORS} />
                  </div>
                </div>
              </ChartCard>

              <ChartCard title="Incidents" sub="M12 — correlated and prioritised"
                right={<TrendingUp size={14} style={{ color: C.faint }} />}>
                <div className="space-y-4">
                  <div className="flex flex-wrap gap-x-5 gap-y-3">
                    <SmallFigure label="Total" value={formatCount(threats.incidents_total)} />
                    <SmallFigure label="Active" value={formatCount(threats.incidents_active)} color={C.warning} />
                  </div>
                  <div>
                    <p className="text-xs mb-2" style={{ color: C.faint }}>By state</p>
                    <Breakdown counts={threats.incidents_by_status} palette={INCIDENT_STATUS_COLORS} />
                  </div>
                  <div>
                    <p className="text-xs mb-2" style={{ color: C.faint }}>By risk band</p>
                    <Breakdown counts={threats.incidents_by_risk_band} palette={RISK_BAND_COLORS} />
                  </div>
                  <div className="pt-3 border-t" style={{ borderColor: C.border }}>
                    <SmallFigure label="Highest risk score" value={formatRiskScore(threats.highest_risk_score)}
                      color={C.danger} />
                  </div>
                </div>
              </ChartCard>
            </div>
          )}

          {/* What this page deliberately does not show. */}
          <p className="text-xs px-1" style={{ color: C.faint }}>
            These blocks are derived views, not time series: no milestone stores traffic history,
            so there are no trend charts here. Packet- and byte-ranked figures are traffic totals
            — M8 and M9 score nothing — and findings, alerts and incidents are three separate
            layers rather than one combined threat level. A value of {UNKNOWN_TEXT} means the
            backend reported nothing for that field.
          </p>
        </>
      )}
    </div>
  )
}
