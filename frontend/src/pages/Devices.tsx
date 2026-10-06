/**
 * Devices — the observed device registry (M15.12).
 *
 * The Figma page this replaces was an asset inventory: it invented hostnames,
 * operating systems, open ports, per-device threat scores and an "AI assessment"
 * for every row. M8 does not produce any of that. What M8 does produce is a
 * device *observation* — identity, addresses, traffic counters, activity state —
 * and this page renders exactly that and nothing more.
 *
 * Two absences are load-bearing and are called out in the UI rather than papered
 * over:
 *
 * * **There is no risk score.** The device registry does not judge devices, so
 *   the column, the gauge and the "high risk" tile are gone. Replacing them with
 *   a client-side heuristic would be the second implementation M15.9 forbids.
 * * **`status` is an activity observation, not a verdict.** `active` means the
 *   device was seen recently; it does not mean the device is trustworthy. The
 *   label says "Seen" for that reason.
 *
 * Data comes from `GET /api/v1/devices` (M13.10) through {@link useDevices}. M8
 * publishes no device WebSocket channel (M14), so there is nothing to subscribe
 * to and no polling to justify: the page offers an explicit refresh, which is the
 * honest cadence for a registry that changes when a device appears on the wire
 * (M15.34).
 */

import { useMemo, useState } from 'react'
import {
  Search, ArrowLeft, Monitor, Laptop, Server, Smartphone, Wifi, Router,
  Download, ChevronUp, ChevronDown, RefreshCw, Radio, Ban,
} from 'lucide-react'
import {
  AsyncSection, EmptyState, RefreshFailureBanner,
} from '@/components/AsyncState'
import { useDevices } from '@/hooks'
import { DEFAULT_PAGE_LIMIT } from '@/services'
import { C, tint, DEVICE_STATUS_COLORS } from '@/lib/tokens'
import {
  UNKNOWN_TEXT, formatBytes, formatCount, formatRelative, formatTimestamp,
} from '@/lib/format'
import type { Device, DeviceStatus } from '@/types'
import type { ToastMsg } from '../App'

/** How many devices one page shows. */
const PAGE_SIZE = DEFAULT_PAGE_LIMIT

/** The address the header prefers, when the device has any. */
function primaryAddress(device: Device): string {
  return device.ip_addresses.length > 0 ? device.ip_addresses[0] : UNKNOWN_TEXT
}

/** A device's MAC, or an explicit absence. */
function macOf(device: Device): string {
  return device.mac_address ?? UNKNOWN_TEXT
}

/**
 * How a device is displayed when it has no hostname.
 *
 * A blank cell reads as a rendering bug; naming the state reads as an answer.
 * M8 reports `hostname: null` for anything it could not resolve over the wire,
 * which is the common case for a device seen only in passing.
 */
function displayName(device: Device): string {
  if (device.hostname) return device.hostname
  return device.mac_address ? 'Unnamed device' : primaryAddress(device)
}

/** The icon the design gives a device, chosen from what it actually exposed. */
function deviceIcon(device: Device): React.ElementType {
  // M8 resolves a vendor only for a MAC it recognises, so the vendor string is
  // the only class signal available. There is no OS field to key off — M8 does
  // not read one, and passing off a guess as an observation is what this page
  // exists not to do.
  const vendor = (device.vendor ?? '').toLowerCase()
  if (device.is_local) return Server
  if (vendor.includes('apple')) return Laptop
  if (vendor.includes('samsung') || vendor.includes('huawei')) return Smartphone
  if (
    vendor.includes('espressif') || vendor.includes('raspberry') ||
    vendor.includes('tuya') || vendor.includes('shelly')
  ) {
    return Wifi
  }
  if (vendor.includes('cisco') || vendor.includes('asus') || vendor.includes('netgear')) {
    return Router
  }
  return Monitor
}

/** How the design labels an M8 activity state. */
const STATUS_LABEL: Readonly<Record<DeviceStatus, string>> = {
  active: 'Active',
  inactive: 'Inactive',
  unknown: 'Unknown',
}

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
      <div className="p-2.5 rounded-xl flex-shrink-0" style={{ backgroundColor: tint(accent, 0.08) }}>
        <div style={{ color: accent }}>{icon}</div>
      </div>
      <div>
        <div className="text-2xl font-bold text-white leading-none tracking-tight">{value}</div>
        <div className="text-xs font-medium mt-0.5" style={{ color: C.muted }}>{label}</div>
        <div className="text-xs mt-0.5" style={{ color: C.faint }}>{sub}</div>
      </div>
    </div>
  )
}

// ─── Detail panel ─────────────────────────────────────────────────────────────

/** One labelled value in the detail header. */
function DetailField({ label, value, mono = false }: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div>
      <div className="text-xs mb-1" style={{ color: C.faint }}>{label}</div>
      <div className={`text-sm font-semibold text-white ${mono ? 'mono' : ''}`}>{value}</div>
    </div>
  )
}

/** A one-line byte/packet split, used for sent and received counters. */
function CounterRow({ label, packets, bytes }: {
  label: string
  packets: number
  bytes: number
}) {
  return (
    <div className="flex items-center justify-between py-2.5">
      <span className="text-xs" style={{ color: C.muted }}>{label}</span>
      <span className="mono text-xs text-white">
        {formatCount(packets)} pkts · {formatBytes(bytes)}
      </span>
    </div>
  )
}

/**
 * The device detail panel.
 *
 * Everything on it is a field M8 actually reported. The removed "AI Assessment"
 * card is deliberately not replaced by a client-side judgement: an "assessment"
 * written in the browser from traffic counters is not analysis, it is a guess
 * wearing a lab coat, and M15 puts no analysis in the frontend.
 */
function DeviceDetail({ device, onBack }: { device: Device; onBack: () => void }) {
  const Icon = deviceIcon(device)
  const statusColor = DEVICE_STATUS_COLORS[device.status] ?? C.dim

  const addresses =
    device.ip_addresses.length > 0 ? device.ip_addresses.join(', ') : UNKNOWN_TEXT

  return (
    <div className="space-y-4 fade-in-up">
      <button onClick={onBack}
        className="flex items-center gap-2 text-sm font-medium transition-colors"
        style={{ color: C.muted }}
        onMouseEnter={e => (e.currentTarget.style.color = C.accent)}
        onMouseLeave={e => (e.currentTarget.style.color = C.muted)}>
        <ArrowLeft size={15} /> Back to Devices
      </button>

      <div className="rounded-2xl border p-6" style={{ backgroundColor: C.card, borderColor: C.border }}>
        <div className="flex items-start justify-between gap-6">
          <div className="flex items-start gap-5 min-w-0">
            <div className="p-4 rounded-2xl flex-shrink-0" style={{ backgroundColor: C.panel }}>
              <Icon size={32} style={{ color: C.accent }} />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-3 mb-1 flex-wrap">
                <h1 className="text-xl font-bold text-white">{displayName(device)}</h1>
                <span className="flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full"
                  style={{ backgroundColor: tint(statusColor, 0.12), color: statusColor }}>
                  <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: statusColor }} />
                  {STATUS_LABEL[device.status]}
                </span>
                {device.is_local && (
                  <span className="text-xs font-medium px-2.5 py-1 rounded-full"
                    style={{ backgroundColor: tint(C.purple, 0.12), color: C.purple }}>
                    Monitoring host
                  </span>
                )}
              </div>
              <div className="mono text-sm mb-3" style={{ color: C.accent }}>{addresses}</div>
              <div className="flex flex-wrap gap-x-8 gap-y-3">
                <DetailField label="Vendor" value={device.vendor ?? UNKNOWN_TEXT} />
                <DetailField label="MAC" value={macOf(device)} mono />
                <DetailField label="Device ID" value={device.device_id} mono />
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-4 gap-4 mt-6 pt-6 border-t" style={{ borderColor: C.border }}>
          <DetailField label="First Seen" value={formatTimestamp(device.first_seen)} />
          <DetailField label="Last Seen" value={formatRelative(device.last_seen)} />
          <DetailField label="Total Packets" value={formatCount(device.packet_count)} mono />
          <DetailField label="Total Bytes" value={formatBytes(device.byte_count)} mono />
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-7 rounded-2xl border overflow-hidden"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="px-5 py-4 border-b" style={{ borderColor: C.border }}>
            <h3 className="text-sm font-semibold text-white">Traffic Counters</h3>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>
              Counts as M8 observed them on the wire
            </p>
          </div>
          <div className="px-5 py-2 divide-y" style={{ borderColor: C.border }}>
            <CounterRow label="Sent" packets={device.packets_sent} bytes={device.bytes_sent} />
            <CounterRow label="Received" packets={device.packets_received} bytes={device.bytes_received} />
            <CounterRow label="Total" packets={device.packet_count} bytes={device.byte_count} />
          </div>
        </div>

        <div className="col-span-5 rounded-2xl border overflow-hidden"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="px-5 py-4 border-b" style={{ borderColor: C.border }}>
            <h3 className="text-sm font-semibold text-white">Known Addresses</h3>
          </div>
          {device.ip_addresses.length === 0 ? (
            <EmptyState title="No address observed"
              hint="M8 has no IP on record for this device."
              minHeight={120} icon={<Radio size={24} />} />
          ) : (
            <ul className="divide-y" style={{ borderColor: C.border }}>
              {device.ip_addresses.map(ip => (
                <li key={ip} className="px-5 py-3 mono text-xs" style={{ color: C.accent }}>{ip}</li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl border text-xs"
        style={{ backgroundColor: C.panel, borderColor: C.border, color: C.muted }}>
        <Ban size={13} style={{ color: C.faint, flexShrink: 0, marginTop: 1 }} />
        <span>
          Device quarantine and blocking are not available: no M3–M14 component enforces a
          firewall rule, so this console cannot offer an action the backend would not carry out.
        </span>
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

interface Props {
  showToast: (msg: string, type?: ToastMsg['type']) => void
}

/** Sortable columns, restricted to what the registry reports. */
type SortColumn = 'hostname' | 'ip' | 'vendor' | 'packet_count' | 'byte_count' | 'last_seen' | 'status'

/** Extract the sortable value for a column. */
function sortValue(device: Device, column: SortColumn): string | number {
  switch (column) {
    case 'hostname': return displayName(device).toLowerCase()
    case 'ip': return primaryAddress(device)
    case 'vendor': return (device.vendor ?? '').toLowerCase()
    case 'packet_count': return device.packet_count
    case 'byte_count': return device.byte_count
    case 'last_seen': return device.last_seen ? Date.parse(device.last_seen) : 0
    case 'status': return device.status
  }
}

export default function Devices({ showToast }: Props) {
  const [selected, setSelected] = useState<Device | null>(null)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<DeviceStatus | 'ALL'>('ALL')
  const [offset, setOffset] = useState(0)
  const [sortColumn, setSortColumn] = useState<SortColumn>('last_seen')
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc')

  // The status filter is a real backend filter (M13.10); the text search is not,
  // because the registry's listing has no free-text parameter. Search therefore
  // narrows the loaded page — an honest, bounded behaviour — and the row count
  // says "on this page" so the operator is not misled into thinking it searched
  // the whole registry.
  const query = useMemo(
    () => (statusFilter === 'ALL' ? {} : { status: statusFilter }),
    [statusFilter],
  )
  const window = useMemo(() => ({ limit: PAGE_SIZE, offset }), [offset])

  const resource = useDevices({ query, window })

  if (selected) return <DeviceDetail device={selected} onBack={() => setSelected(null)} />

  const needle = search.trim().toLowerCase()
  const visible = resource.devices
    .filter(device => {
      if (needle === '') return true
      return (
        displayName(device).toLowerCase().includes(needle) ||
        (device.vendor ?? '').toLowerCase().includes(needle) ||
        (device.mac_address ?? '').toLowerCase().includes(needle) ||
        device.ip_addresses.some(ip => ip.includes(needle))
      )
    })
    .slice()
    .sort((a, b) => {
      const left = sortValue(a, sortColumn)
      const right = sortValue(b, sortColumn)
      const comparison = typeof left === 'number' && typeof right === 'number'
        ? left - right
        : String(left).localeCompare(String(right))
      return sortDirection === 'asc' ? comparison : -comparison
    })

  const toggleSort = (column: SortColumn) => {
    if (sortColumn === column) {
      setSortDirection(direction => (direction === 'asc' ? 'desc' : 'asc'))
      return
    }
    setSortColumn(column)
    setSortDirection('desc')
  }

  const sortIcon = (column: SortColumn) => {
    if (sortColumn !== column) return null
    return sortDirection === 'asc' ? <ChevronUp size={11} /> : <ChevronDown size={11} />
  }

  const sortableHeader = (column: SortColumn, label: string) => (
    <th className="text-left py-2.5 pr-4 cursor-pointer select-none" onClick={() => toggleSort(column)}>
      <div className="flex items-center gap-1 text-xs font-medium" style={{ color: C.dim }}>
        {label} {sortIcon(column)}
      </div>
    </th>
  )

  // The tiles count what is loaded, not what exists. `total` is the registry's
  // own count and is shown as the second line so the two are never confused.
  const loaded = resource.devices
  const activeCount = loaded.filter(device => device.status === 'active').length
  const inactiveCount = loaded.filter(device => device.status === 'inactive').length
  const unknownCount = loaded.filter(device => device.status === 'unknown').length

  const exportCsv = () => {
    // The export contains the rows on screen. Writing a file the console never
    // loaded — or worse, a "full report" it cannot fetch — is not an option; M13
    // exposes no device export endpoint, so the client offers exactly what it has.
    if (visible.length === 0) {
      showToast('Nothing to export', 'info')
      return
    }
    const header = ['device_id', 'hostname', 'ip_addresses', 'mac_address', 'vendor',
      'first_seen', 'last_seen', 'packet_count', 'byte_count', 'status']
    const rows = visible.map(device => [
      device.device_id,
      device.hostname ?? '',
      device.ip_addresses.join(' '),
      device.mac_address ?? '',
      device.vendor ?? '',
      device.first_seen ?? '',
      device.last_seen ?? '',
      String(device.packet_count),
      String(device.byte_count),
      device.status,
    ])
    const csv = [header, ...rows]
      .map(cells => cells.map(cell => `"${cell.replace(/"/g, '""')}"`).join(','))
      .join('\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `devices-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`
    anchor.click()
    URL.revokeObjectURL(url)
    showToast(`Exported ${visible.length} device${visible.length === 1 ? '' : 's'}`, 'success')
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Devices on this page" value={loaded.length}
          sub={resource.total === null ? 'Total unknown' : `${formatCount(resource.total)} in registry`}
          icon={<Monitor size={16} />} />
        <StatCard label="Active" value={activeCount} sub="Seen within the activity window"
          icon={<Radio size={16} />} accent={C.success} />
        <StatCard label="Inactive" value={inactiveCount} sub="Not seen recently"
          icon={<Monitor size={16} />} accent={C.dim} />
        <StatCard label="Unknown activity" value={unknownCount} sub="Too little history to classify"
          icon={<Monitor size={16} />} accent={C.warning} />
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex items-center gap-2 px-3 py-2 rounded-xl border flex-1 min-w-[240px]"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <Search size={13} style={{ color: C.faint }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Filter this page by hostname, address, MAC or vendor…"
            className="bg-transparent text-xs flex-1"
            style={{ color: C.text, outline: 'none' }} />
        </div>
        <select value={statusFilter}
          onChange={e => {
            const next = e.target.value as DeviceStatus | 'ALL'
            setStatusFilter(next)
            setOffset(0)
          }}
          className="px-3 py-2 rounded-xl text-xs border"
          style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted, outline: 'none' }}>
          <option value="ALL">All activity states</option>
          <option value="active">Active</option>
          <option value="inactive">Inactive</option>
          <option value="unknown">Unknown</option>
        </select>
        <button onClick={resource.reload} disabled={resource.isLoading}
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
          <RefreshCw size={12} className={resource.isLoading ? 'animate-spin' : undefined} /> Refresh
        </button>
      </div>

      {resource.error !== null && resource.devices.length > 0 && (
        <RefreshFailureBanner error={resource.error} onRetry={resource.reload} />
      )}

      <div className="rounded-2xl border overflow-hidden"
        style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: C.border }}>
          <div>
            <h2 className="text-sm font-semibold text-white">Observed Devices</h2>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>
              {resource.devices.length} loaded
              {needle !== '' && ` · ${visible.length} match the filter`}
              {` · rows ${offset + 1}–${offset + resource.devices.length}`}
            </p>
          </div>
          <button onClick={exportCsv}
            disabled={visible.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium border"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            <Download size={12} /> Export page as CSV
          </button>
        </div>

        <AsyncSection
          isInitialLoading={resource.isInitialLoading}
          error={resource.blockingError}
          isEmpty={false}
          loadingLabel="Loading devices…"
          errorTitle="Unable to load the device registry"
          onRetry={resource.reload}
          minHeight={220}
        >
          {visible.length === 0 ? (
            <EmptyState
              title={needle !== '' || statusFilter !== 'ALL'
                ? 'No devices match the filter'
                : 'No devices observed'}
              hint={needle !== '' || statusFilter !== 'ALL'
                ? 'Clear the filter or choose another activity state.'
                : 'M8 records a device when it appears on a captured packet. Start a capture to populate the registry.'}
              icon={<Monitor size={28} />}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b" style={{ borderColor: C.border }}>
                    <th className="text-left pl-5 py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Type</th>
                    {sortableHeader('hostname', 'Device')}
                    {sortableHeader('ip', 'Address')}
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>MAC</th>
                    {sortableHeader('vendor', 'Vendor')}
                    {sortableHeader('packet_count', 'Packets')}
                    {sortableHeader('byte_count', 'Bytes')}
                    {sortableHeader('last_seen', 'Last Seen')}
                    {sortableHeader('status', 'Activity')}
                  </tr>
                </thead>
                <tbody>
                  {visible.map(device => {
                    const Icon = deviceIcon(device)
                    const statusColor = DEVICE_STATUS_COLORS[device.status] ?? C.dim
                    return (
                      <tr key={device.device_id} onClick={() => setSelected(device)}
                        className="border-b transition-all duration-150 cursor-pointer"
                        style={{ borderColor: '#1a2744' }}
                        onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)')}
                        onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
                        <td className="pl-5 py-3 pr-4">
                          <div className="p-1.5 rounded-lg w-fit" style={{ backgroundColor: C.panel }}>
                            <Icon size={13} style={{ color: C.faint }} />
                          </div>
                        </td>
                        <td className="py-3 pr-4">
                          <div className="text-xs font-semibold text-white">{displayName(device)}</div>
                          <div className="mono text-[11px] mt-0.5" style={{ color: C.faint }}>
                            {device.device_id}
                          </div>
                        </td>
                        <td className="py-3 pr-4 mono text-xs font-medium" style={{ color: C.accent }}>
                          {primaryAddress(device)}
                          {device.ip_addresses.length > 1 && (
                            <span className="ml-1.5 text-[11px]" style={{ color: C.faint }}>
                              +{device.ip_addresses.length - 1}
                            </span>
                          )}
                        </td>
                        <td className="py-3 pr-4 mono text-xs" style={{ color: C.dim }}>{macOf(device)}</td>
                        <td className="py-3 pr-4 text-xs" style={{ color: C.muted }}>
                          {device.vendor ?? UNKNOWN_TEXT}
                        </td>
                        <td className="py-3 pr-4 mono text-xs text-white">{formatCount(device.packet_count)}</td>
                        <td className="py-3 pr-4 mono text-xs text-white">{formatBytes(device.byte_count)}</td>
                        <td className="py-3 pr-4 text-xs" style={{ color: C.muted }}>
                          {formatRelative(device.last_seen)}
                        </td>
                        <td className="py-3 pr-5">
                          <span className="flex items-center gap-1.5 text-xs font-medium w-fit"
                            style={{ color: statusColor }}>
                            <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: statusColor }} />
                            {STATUS_LABEL[device.status]}
                          </span>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </AsyncSection>

        <div className="flex items-center justify-between px-5 py-3 border-t" style={{ borderColor: C.border }}>
          <button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            disabled={offset === 0 || resource.isLoading}
            className="px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            Previous
          </button>
          <span className="text-xs" style={{ color: C.faint }}>
            {offset === 0 && !resource.hasMore
              ? 'All observed devices'
              : `Offset ${offset}`}
          </span>
          <button onClick={() => setOffset(offset + PAGE_SIZE)}
            disabled={!resource.hasMore || resource.isLoading}
            className="px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            Next
          </button>
        </div>
      </div>

      {resource.error === null && resource.devices.length === 0 && !resource.isInitialLoading && (
        <p className="text-xs px-1" style={{ color: C.faint }}>
          Nothing to show yet — see the empty-state note above.
        </p>
      )}
    </div>
  )
}
