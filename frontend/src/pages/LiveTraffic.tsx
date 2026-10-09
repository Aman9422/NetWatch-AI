/**
 * Live Traffic (M15.10/M15.11).
 *
 * The packet table is fed by `/ws/packets` and nothing else. The rows come from
 * `useLiveTraffic`, whose list is **bounded** and newest-first, so a page left
 * open overnight holds a fixed number of rows rather than every packet the
 * interface ever carried (M15.11). The packet ids are not assumed sequential and
 * a gap is not reported as an error, because M14 drops packet events on purpose
 * when a client cannot keep up.
 *
 * What was removed from the mock design, and why:
 *
 * * `makePacket()` and its 350 ms `setInterval` fabricated every row; the stream
 *   now supplies normalized packets the backend actually observed;
 * * the hex view, the "Ethernet/IPv4/TCP header" breakdown, the "AI explanation"
 *   and the risk assessment were all invented — and the payload tabs could only
 *   ever be fiction, because **M7 stores no payload and M14.8 sends none**
 *   (M15.10). The drawer therefore shows the normalized fields that exist and
 *   states plainly that no payload is retained;
 * * "Block IP" had no backend endpoint behind it, so it is gone rather than left
 *   pretending to work.
 *
 * The rates (`packets_per_second`, `bytes_per_second`) come from the M6 snapshot
 * the hook polls, never from dividing counters here (M15.9). "Pause" pauses the
 * **view**, not capture: M14 has no replay buffer, so a paused view discards the
 * events it receives and resumes at the next one.
 */

import { useMemo, useState } from 'react'
import {
  Activity, ChevronLeft, ChevronRight, Download, Eye, Filter, Pause,
  Play, RefreshCw, Search, Shield, Wifi, X,
} from 'lucide-react'
import type { ToastMsg } from '../App'
import {
  EmptyState,
  ErrorState,
  LoadingState,
  RefreshFailureBanner,
} from '../components/AsyncState'
import { useCapture, useLiveTraffic } from '../hooks'
import {
  UNKNOWN_TEXT,
  formatBitsPerSecond,
  formatBytesPerSecond,
  formatCount,
  formatItemsPerSecond,
  formatTimeOfDay,
} from '../lib/format'
import { C, tint } from '../lib/tokens'
import type { PacketEventData, PacketType } from '../types'

/** The protocol tabs offered as quick filters. Values are `PacketType`s (M5). */
const PROTOCOL_TABS: readonly (PacketType | 'ALL')[] = [
  'ALL', 'TCP', 'UDP', 'ICMP', 'DNS', 'ARP', 'IPV4', 'IPV6',
]

/** A stable React key for a live packet, built from the fields it carries. */
function packetKey(packet: PacketEventData): string {
  return [
    packet.packet_id ?? 'x',
    packet.timestamp,
    packet.source_ip ?? '',
    packet.source_port ?? '',
    packet.destination_ip ?? '',
    packet.destination_port ?? '',
  ].join('|')
}

/** One statistic tile. */
function StatCard({ label, value, sub, icon, accent = C.accent }: {
  label: string
  value: string
  sub: string
  icon: React.ReactNode
  accent?: string
}) {
  return (
    <div
      className="rounded-2xl border p-4 flex gap-3 items-center"
      style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 20px rgba(0,0,0,0.2)' }}
    >
      <div className="p-2.5 rounded-xl shrink-0" style={{ backgroundColor: tint(accent, 0.08) }}>
        <div style={{ color: accent }}>{icon}</div>
      </div>
      <div className="min-w-0">
        <div className="text-xl font-bold text-white leading-none mb-0.5 tracking-tight">{value}</div>
        <div className="text-xs font-medium" style={{ color: C.muted }}>{label}</div>
        <div className="text-xs mt-0.5" style={{ color: C.faint }}>{sub}</div>
      </div>
    </div>
  )
}

/** One `label: value` row in the packet drawer. */
function DetailRow({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1.5 border-b" style={{ borderColor: '#1a2744' }}>
      <span className="text-xs shrink-0" style={{ color: C.faint }}>{label}</span>
      <span className={`text-xs font-medium text-right break-all ${mono ? 'mono' : ''}`} style={{ color: C.muted }}>
        {value}
      </span>
    </div>
  )
}

/** The packet detail drawer, showing only the fields M14 actually sends. */
function PacketDrawer({
  packet, onClose, onPrev, onNext, hasPrev, hasNext,
}: {
  packet: PacketEventData
  onClose: () => void
  onPrev: () => void
  onNext: () => void
  hasPrev: boolean
  hasNext: boolean
}) {
  return (
    <div
      className="w-96 shrink-0 flex flex-col rounded-2xl border overflow-hidden fade-in-up"
      style={{ backgroundColor: C.card, borderColor: C.border }}
    >
      <div className="flex items-center justify-between px-4 py-3.5 border-b" style={{ borderColor: C.border }}>
        <div>
          <div className="text-sm font-semibold text-white">
            Packet {packet.packet_id === null ? '(id withheld under load)' : `#${packet.packet_id}`}
          </div>
          <div className="mono text-xs mt-0.5" style={{ color: C.faint }}>{formatTimeOfDay(packet.timestamp)}</div>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={onPrev} disabled={!hasPrev}
            className="p-1.5 rounded-lg disabled:opacity-30"
            style={{ color: C.muted }}
          >
            <ChevronLeft size={15} />
          </button>
          <button
            onClick={onNext} disabled={!hasNext}
            className="p-1.5 rounded-lg disabled:opacity-30"
            style={{ color: C.muted }}
          >
            <ChevronRight size={15} />
          </button>
          <button onClick={onClose} className="p-1.5 rounded-lg ml-1" style={{ color: C.faint }}>
            <X size={15} />
          </button>
        </div>
      </div>

      <div className="px-4 py-2.5 border-b flex items-center gap-2" style={{ borderColor: C.border }}>
        <span className="text-xs px-2 py-0.5 rounded mono" style={{ backgroundColor: tint(C.accent, 0.08), color: C.accent }}>
          {packet.protocol}
        </span>
        <span className="text-xs px-2 py-0.5 rounded mono" style={{ backgroundColor: C.panel, color: C.muted }}>
          {packet.packet_type}
        </span>
        <span className="text-xs ml-auto" style={{ color: C.faint }}>{packet.length} bytes</span>
      </div>

      <div className="flex-1 overflow-y-auto p-4">
        <div className="space-y-1">
          <DetailRow label="Timestamp" value={packet.timestamp} />
          <DetailRow label="Interface" value={packet.interface ?? UNKNOWN_TEXT} />
          <DetailRow label="Source IP" value={packet.source_ip ?? UNKNOWN_TEXT} />
          <DetailRow label="Source port" value={packet.source_port === null ? UNKNOWN_TEXT : String(packet.source_port)} />
          <DetailRow label="Destination IP" value={packet.destination_ip ?? UNKNOWN_TEXT} />
          <DetailRow
            label="Destination port"
            value={packet.destination_port === null ? UNKNOWN_TEXT : String(packet.destination_port)}
          />
          <DetailRow label="Protocol" value={packet.protocol} />
          <DetailRow label="Classification" value={packet.packet_type} />
          <DetailRow label="Frame length" value={`${packet.length} bytes`} />
        </div>

        <div
          className="mt-4 px-3 py-2.5 rounded-xl border text-xs leading-relaxed"
          style={{ backgroundColor: 'rgba(56,189,248,0.06)', borderColor: 'rgba(56,189,248,0.2)', color: C.muted }}
        >
          <div className="flex items-center gap-1.5 mb-1">
            <Shield size={12} style={{ color: C.accent }} />
            <span className="font-semibold" style={{ color: C.accent }}>No payload is available</span>
          </div>
          The base application stores and streams packet <em>metadata</em> only. There is no hex
          dump, no header body and no reassembled content — M7 retains none and M14 sends none.
        </div>
      </div>
    </div>
  )
}

interface Props { showToast: (msg: string, type?: ToastMsg['type']) => void }

export default function LiveTraffic({ showToast }: Props) {
  const traffic = useLiveTraffic()
  const capture = useCapture()

  const [search, setSearch] = useState('')
  const [protocol, setProtocol] = useState<PacketType | 'ALL'>('ALL')
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [showFilters, setShowFilters] = useState(false)
  const [ipFilter, setIpFilter] = useState('')
  const [portFilter, setPortFilter] = useState('')

  const snapshot = traffic.snapshot

  // True when the M6 snapshot could not be read at all. The rates are then
  // unknown, which is not the same as zero: rendering "0/s" for a request that
  // failed would report a quiet network where the truth is that nothing was
  // measured (M15.8).
  const ratesUnavailable = traffic.blockingError !== null

  // Filtering the rows already on screen is a presentation concern, so it is done
  // here — unlike the collections pages, whose filtering is the backend's.
  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase()
    const port = portFilter.trim()
    return traffic.packets.filter((packet) => {
      if (protocol !== 'ALL' && packet.packet_type !== protocol) return false
      if (ipFilter) {
        const source = packet.source_ip ?? ''
        const destination = packet.destination_ip ?? ''
        if (!source.includes(ipFilter) && !destination.includes(ipFilter)) return false
      }
      if (port) {
        if (String(packet.source_port ?? '') !== port && String(packet.destination_port ?? '') !== port) {
          return false
        }
      }
      if (needle) {
        const haystack = [
          packet.source_ip ?? '',
          packet.destination_ip ?? '',
          packet.protocol,
          packet.packet_type,
        ].join(' ').toLowerCase()
        if (!haystack.includes(needle)) return false
      }
      return true
    })
  }, [traffic.packets, protocol, ipFilter, portFilter, search])

  const selectedIndex = selectedKey === null ? -1 : filtered.findIndex((p) => packetKey(p) === selectedKey)
  const selected = selectedIndex >= 0 ? filtered[selectedIndex] : null

  const exportCsv = () => {
    if (filtered.length === 0) {
      showToast('Nothing to export — the current filter matches no packets', 'info')
      return
    }
    const header = 'timestamp,interface,source_ip,source_port,destination_ip,destination_port,protocol,length,packet_type'
    const rows = filtered.map((p) =>
      [
        p.timestamp,
        p.interface ?? '',
        p.source_ip ?? '',
        p.source_port ?? '',
        p.destination_ip ?? '',
        p.destination_port ?? '',
        p.protocol,
        p.length,
        p.packet_type,
      ].join(','),
    )
    const blob = new Blob([[header, ...rows].join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'netwatch-live-packets.csv'
    anchor.click()
    URL.revokeObjectURL(url)
    showToast(`Exported ${filtered.length} displayed packet rows`, 'success')
  }

  const tableColumns = '120px 130px 130px 70px 80px 80px 60px 80px'

  return (
    <div className="flex flex-col gap-4" style={{ height: 'calc(100vh - 72px - 48px)' }}>
      {traffic.error && traffic.snapshot !== null && (
        <RefreshFailureBanner error={traffic.error} onRetry={traffic.reload} />
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-4 shrink-0">
        <StatCard
          label="Packets / sec" value={formatItemsPerSecond(snapshot?.packets_per_second)}
          sub={ratesUnavailable ? 'snapshot unavailable' : 'M6 snapshot · polled'}
          icon={<Activity size={16} />}
        />
        <StatCard
          label="Throughput" value={formatBytesPerSecond(snapshot?.bytes_per_second)}
          sub={ratesUnavailable ? 'snapshot unavailable' : formatBitsPerSecond(snapshot?.bits_per_second)}
          icon={<Wifi size={16} />} accent={C.info}
        />
        <StatCard
          label="Capture" value={capture.state ?? UNKNOWN_TEXT}
          sub={capture.selectedInterface ?? 'no interface selected'}
          icon={<span className="w-2 h-2 rounded-full" style={{ backgroundColor: capture.isRunning ? C.success : C.dim }} />}
          accent={capture.isRunning ? C.success : C.dim}
        />
        <StatCard
          label="Retained rows" value={formatCount(traffic.packets.length)}
          sub={`bounded at ${traffic.capacity}`} icon={<Shield size={16} />} accent={C.purple}
        />
      </div>

      {/* Filters */}
      <div className="shrink-0 space-y-2">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-2 rounded-xl border flex-1"
            style={{ backgroundColor: C.card, borderColor: C.border }}>
            <Search size={13} style={{ color: C.faint, flexShrink: 0 }} />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search source IP, destination, protocol…"
              className="bg-transparent text-xs flex-1 placeholder-slate-600"
              style={{ color: C.text, outline: 'none' }}
            />
          </div>

          <div className="flex items-center gap-0.5 p-1 rounded-xl" style={{ backgroundColor: C.card }}>
            {PROTOCOL_TABS.map((p) => (
              <button
                key={p}
                onClick={() => setProtocol(p)}
                className="px-2.5 py-1.5 rounded-lg text-xs font-medium"
                style={{
                  backgroundColor: protocol === p ? C.accent : 'transparent',
                  color: protocol === p ? '#0F172A' : C.faint,
                }}
              >
                {p}
              </button>
            ))}
          </div>

          <button
            onClick={() => setShowFilters((f) => !f)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl border text-xs font-medium"
            style={{
              borderColor: showFilters ? C.accent : C.border,
              color: showFilters ? C.accent : C.muted,
              backgroundColor: showFilters ? tint(C.accent, 0.06) : C.card,
            }}
          >
            <Filter size={12} /> Filters
          </button>

          <button
            onClick={exportCsv}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl border text-xs font-medium"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}
          >
            <Download size={12} /> Export CSV
          </button>

          <button
            onClick={() => { traffic.clearPackets(); showToast('Retained rows cleared', 'info') }}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl border text-xs font-medium"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}
          >
            <RefreshCw size={12} /> Clear
          </button>

          <button
            onClick={() => {
              traffic.setPaused(!traffic.isPaused)
              showToast(traffic.isPaused ? 'View resumed' : 'View paused — incoming packets are discarded', 'info')
            }}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold"
            style={{
              backgroundColor: traffic.isPaused ? tint(C.success, 0.16) : tint(C.danger, 0.16),
              color: traffic.isPaused ? C.success : C.danger,
            }}
          >
            {traffic.isPaused ? <><Play size={12} /> Resume</> : <><Pause size={12} /> Pause view</>}
          </button>
        </div>

        {showFilters && (
          <div className="flex items-center gap-3 p-3 rounded-xl border fade-in-up"
            style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="flex items-center gap-1.5">
              <span className="text-xs" style={{ color: C.faint }}>IP</span>
              <input
                value={ipFilter}
                onChange={(e) => setIpFilter(e.target.value)}
                placeholder="Filter by IP…"
                className="px-2.5 py-1.5 rounded-lg border text-xs mono"
                style={{ backgroundColor: C.panel, borderColor: C.border, color: C.text, outline: 'none', width: 140 }}
              />
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-xs" style={{ color: C.faint }}>Port</span>
              <input
                value={portFilter}
                onChange={(e) => setPortFilter(e.target.value)}
                placeholder="Port…"
                className="px-2.5 py-1.5 rounded-lg border text-xs mono"
                style={{ backgroundColor: C.panel, borderColor: C.border, color: C.text, outline: 'none', width: 80 }}
              />
            </div>
            <div className="ml-auto flex items-center gap-1.5 text-xs" style={{ color: C.faint }}>
              <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: traffic.isConnected ? C.success : C.warning }} />
              {traffic.phase}
            </div>
          </div>
        )}
      </div>

      {/* Table + drawer */}
      <div className="flex gap-4 flex-1 min-h-0">
        <div
          className="flex flex-col flex-1 min-w-0 rounded-2xl border overflow-hidden"
          style={{ backgroundColor: C.card, borderColor: C.border }}
        >
          <div
            className="grid text-xs font-medium px-4 py-2.5 border-b shrink-0"
            style={{ borderColor: C.border, color: C.dim, gridTemplateColumns: tableColumns }}
          >
            <span>Time</span><span>Source</span><span>Destination</span>
            <span>Proto</span><span>Src Port</span><span>Dst Port</span>
            <span>Bytes</span><span>Type</span>
          </div>

          <div className="flex-1 overflow-y-auto">
            {traffic.isInitialLoading && traffic.packets.length === 0 && (
              <LoadingState label="Waiting for the first packet…" minHeight={200} />
            )}
            {!traffic.isInitialLoading && traffic.blockingError !== null && (
              <ErrorState
                error={traffic.blockingError}
                title="Unable to load traffic rates"
                onRetry={traffic.reload}
                minHeight={200}
              />
            )}
            {!traffic.isInitialLoading && !ratesUnavailable && filtered.length === 0 && (
              <EmptyState
                title={traffic.packets.length === 0 ? 'No packets yet' : 'No packets match your filter'}
                hint={traffic.packets.length === 0
                  ? 'Rows appear as the backend observes traffic on the selected interface.'
                  : 'Adjust the search or filter criteria.'}
                icon={<Shield size={30} />}
                minHeight={200}
              />
            )}
            {filtered.map((packet) => {
              const key = packetKey(packet)
              const isSelected = selectedKey === key
              return (
                <div
                  key={key}
                  onClick={() => setSelectedKey(key)}
                  className="grid items-center px-4 py-2 cursor-pointer border-b"
                  style={{
                    gridTemplateColumns: tableColumns,
                    borderColor: '#1a2744',
                    backgroundColor: isSelected ? tint(C.accent, 0.07) : 'transparent',
                  }}
                >
                  <span className="mono text-xs" style={{ color: C.faint }}>{formatTimeOfDay(packet.timestamp)}</span>
                  <span className="mono text-xs font-medium" style={{ color: C.accent }}>{packet.source_ip ?? UNKNOWN_TEXT}</span>
                  <span className="mono text-xs" style={{ color: C.muted }}>{packet.destination_ip ?? UNKNOWN_TEXT}</span>
                  <span>
                    <span className="text-xs px-1.5 py-0.5 rounded font-medium"
                      style={{ backgroundColor: tint(C.purple, 0.09), color: C.purple }}>
                      {packet.protocol}
                    </span>
                  </span>
                  <span className="mono text-xs" style={{ color: C.muted }}>{packet.source_port ?? UNKNOWN_TEXT}</span>
                  <span className="mono text-xs" style={{ color: C.muted }}>{packet.destination_port ?? UNKNOWN_TEXT}</span>
                  <span className="mono text-xs" style={{ color: C.muted }}>{packet.length}</span>
                  <span>
                    <span className="text-xs px-1.5 py-0.5 rounded-full font-medium"
                      style={{ backgroundColor: C.panel, color: C.dim }}>
                      {packet.packet_type}
                    </span>
                  </span>
                </div>
              )
            })}
          </div>

          <div
            className="flex items-center gap-4 px-4 py-2.5 border-t shrink-0"
            style={{ borderColor: C.border, backgroundColor: C.panel }}
          >
            <span className="mono text-xs" style={{ color: C.dim }}>
              {formatCount(filtered.length)} shown · {formatCount(traffic.packets.length)} retained
            </span>
            <span style={{ color: C.border }}>|</span>
            <span className="mono text-xs" style={{ color: traffic.isConnected ? C.success : C.warning }}>
              {traffic.isConnected ? '● Streaming' : '■ Reconnecting'}
            </span>
            {traffic.isPaused && (
              <>
                <span style={{ color: C.border }}>|</span>
                <span className="mono text-xs" style={{ color: C.warning }}>
                  <Eye size={10} className="inline" /> view paused
                </span>
              </>
            )}
          </div>
        </div>

        {selected && (
          <PacketDrawer
            packet={selected}
            onClose={() => setSelectedKey(null)}
            onPrev={() => selectedIndex > 0 && setSelectedKey(packetKey(filtered[selectedIndex - 1]))}
            onNext={() => selectedIndex < filtered.length - 1 && setSelectedKey(packetKey(filtered[selectedIndex + 1]))}
            hasPrev={selectedIndex > 0}
            hasNext={selectedIndex < filtered.length - 1}
          />
        )}
      </div>
    </div>
  )
}
