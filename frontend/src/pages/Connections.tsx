/**
 * Connections — the M9 conversation tracker (M15.13).
 *
 * A connection is a *tracked conversation*, not a verdict: M9 records what it
 * observed between two endpoints and how long it has been quiet. There is no
 * severity, no risk score and no security state, so this page does not colour a row
 * as though there were. `state` and `active` are the **tracker's own** view, derived
 * from its expiry window, and the page renders them without recomputing either —
 * a second opinion in React would disagree with the tracker the moment a timeout
 * fired on the server (M15.13).
 *
 * The "active" view is a **different endpoint**, not a client-side filter of the
 * listing: `GET /connections/active` is a distinct route (M13.11), so the count
 * shown in that mode is the backend's answer rather than one this page derived.
 *
 * M9 publishes no WebSocket channel, so there is no live path: the listing is read
 * and refreshed explicitly (M15.34). The expiry control is the M9.22 verification
 * helper — it forces the sweep the tracker would run on its own timer, and the page
 * presents it as a development action rather than as a security control.
 */

import { useMemo, useState } from 'react'
import {
  Share2, RefreshCw, Search, ArrowRightLeft, Server, Network,
  Hash, Clock, Timer, Ban,
} from 'lucide-react'
import {
  AsyncSection, EmptyState, RefreshFailureBanner,
} from '@/components/AsyncState'
import { useConnection, useConnections } from '@/hooks'
import { DEFAULT_PAGE_LIMIT } from '@/services'
import { C, tint } from '@/lib/tokens'
import {
  UNKNOWN_TEXT, formatBytes, formatCount, formatEndpoint, formatRelative,
  formatTimestamp,
} from '@/lib/format'
import type { Connection, ConnectionProtocol, ConnectionState } from '@/types'
import type { ToastMsg } from '../App'

/** How many conversations one page shows. */
const PAGE_SIZE = DEFAULT_PAGE_LIMIT

/** The transport protocols the tracker covers (M9.5). */
const PROTOCOL_ORDER: readonly ConnectionProtocol[] = ['TCP', 'UDP', 'ICMP']

/** The states the tracker reports (M9.10/M9.11). */
const STATE_ORDER: readonly ConnectionState[] = [
  'active',
  'established',
  'observed',
  'closing',
  'closed',
  'inactive',
  'unknown',
]

/** A readable label for a tracker state. */
function stateLabel(state: string): string {
  return state.charAt(0).toUpperCase() + state.slice(1).replace('_', ' ')
}

/**
 * The colour for a tracker state.
 *
 * These are *activity* states, so the palette reads as availability rather than as
 * severity: still-tracked is neutral-positive, retired is muted. Nothing here is
 * orange-for-warning, because a quiet conversation is not a warning.
 */
const STATE_COLORS: Readonly<Record<string, string>> = {
  active: C.success,
  established: C.success,
  observed: C.info,
  closing: C.warning,
  closed: C.dim,
  inactive: C.dim,
  unknown: C.faint,
}

// ─── Detail panel ────────────────────────────────────────────────────────────

/** One labelled value. */
function MetaField({ label, value, mono = false, icon }: {
  label: string
  value: string
  mono?: boolean
  icon?: React.ReactNode
}) {
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-1.5 text-xs mb-1" style={{ color: C.faint }}>
        {icon}
        {label}
      </div>
      <div className={`text-sm font-semibold text-white ${mono ? 'mono' : ''} wrap-break-word`}>{value}</div>
    </div>
  )
}

/** A sent/received counter pair for one direction. */
function DirectionCounters({ label, packets, bytes, address }: {
  label: string
  packets: number
  bytes: number
  address: string
}) {
  return (
    <div className="px-5 py-4 border-b" style={{ borderColor: C.border }}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-semibold text-white">{label}</span>
        <span className="mono text-xs" style={{ color: C.accent }}>{address}</span>
      </div>
      <div className="flex items-center gap-6">
        <span className="text-xs" style={{ color: C.muted }}>
          {formatCount(packets)} packets
        </span>
        <span className="text-xs" style={{ color: C.muted }}>
          {formatBytes(bytes)}
        </span>
      </div>
    </div>
  )
}

/**
 * One conversation in full, read from `GET /connections/{id}`.
 *
 * The single-conversation endpoint is used rather than trusting the clicked row,
 * because M9 expires conversations on its own timer: a row that was on screen a
 * moment ago can already be retired, and the tracker's honest answer for it is a
 * `404` rather than a stale record. When that has happened the panel says "no
 * longer tracked" rather than reporting a failure.
 */
function ConnectionDetailPanel({ connectionId, fallback, onBack }: {
  connectionId: string
  fallback: Connection | null
  onBack: () => void
}) {
  const resource = useConnection(connectionId)
  const connection = resource.connection ?? fallback
  const stateColor = connection === null
    ? C.muted
    : (STATE_COLORS[connection.state] ?? C.muted)

  return (
    <div className="space-y-4 fade-in-up">
      <button onClick={onBack}
        className="flex items-center gap-2 text-sm font-medium transition-colors"
        style={{ color: C.muted }}
        onMouseEnter={e => (e.currentTarget.style.color = C.accent)}
        onMouseLeave={e => (e.currentTarget.style.color = C.muted)}>
        ← Back to Connections
      </button>

      {resource.isRetired && (
        <div className="rounded-2xl border flex flex-col items-center justify-center gap-3 text-center px-6 py-12"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <Timer size={28} style={{ color: C.border }} />
          <p className="text-sm font-medium text-white">No longer tracked</p>
          <p className="text-xs max-w-md" style={{ color: C.muted }}>
            The tracker answered 404 for this conversation. M9 retires a conversation once it has
            been quiet past its expiry window, so a row that was listed a moment ago can be
            retired — this is the conversation having expired, not the request having failed.
          </p>
        </div>
      )}

      {!resource.isRetired && connection === null && resource.isInitialLoading && (
        <div className="rounded-2xl border" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="flex items-center justify-center gap-3 py-16">
            <RefreshCw size={18} className="animate-spin" style={{ color: C.accent }} />
            <span className="text-xs" style={{ color: C.faint }}>Loading conversation…</span>
          </div>
        </div>
      )}

      {!resource.isRetired && connection !== null && (
        <>
          <div className="rounded-2xl border p-6" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-2xl shrink-0"
                style={{ backgroundColor: tint(stateColor, 0.1) }}>
                <ArrowRightLeft size={24} style={{ color: stateColor }} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap mb-1.5">
                  <span className="text-xs font-semibold px-2.5 py-1 rounded-full"
                    style={{ backgroundColor: tint(stateColor, 0.12), color: stateColor }}>
                    {stateLabel(connection.state)}
                  </span>
                  <span className="mono text-xs px-2 py-0.5 rounded-full"
                    style={{ backgroundColor: tint(C.accent, 0.1), color: C.accent }}>
                    {connection.protocol}
                  </span>
                  {connection.active && (
                    <span className="flex items-center gap-1 text-xs" style={{ color: C.success }}>
                      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: C.success }} />
                      still tracked
                    </span>
                  )}
                </div>
                <div className="mono text-sm" style={{ color: C.text }}>
                  {formatEndpoint(connection.source_ip, connection.source_port)}
                  <span style={{ color: C.dim }}> → </span>
                  {formatEndpoint(connection.destination_ip, connection.destination_port)}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-4 mt-6 pt-6 border-t" style={{ borderColor: C.border }}>
              <MetaField label="Packets" value={formatCount(connection.packet_count)}
                icon={<Hash size={11} />} />
              <MetaField label="Bytes" value={formatBytes(connection.byte_count)}
                icon={<Server size={11} />} />
              <MetaField label="First seen" value={formatTimestamp(connection.first_seen)}
                icon={<Clock size={11} />} />
              <MetaField label="Last seen" value={formatRelative(connection.last_seen)}
                icon={<Clock size={11} />} />
            </div>

            <div className="grid grid-cols-4 gap-4 mt-6">
              <MetaField label="IP version" value={connection.ip_version === null ? UNKNOWN_TEXT : `IPv${connection.ip_version}`} />
              <MetaField label="Conversation id" value={connection.connection_id} mono />
              <MetaField label="Source device" value={connection.source_device_id ?? UNKNOWN_TEXT} mono />
              <MetaField label="Destination device" value={connection.destination_device_id ?? UNKNOWN_TEXT} mono />
            </div>
          </div>

          <div className="rounded-2xl border overflow-hidden"
            style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="px-5 py-4 border-b" style={{ borderColor: C.border }}>
              <h3 className="text-sm font-semibold text-white">Directional counters</h3>
              <p className="text-xs mt-0.5" style={{ color: C.faint }}>
                As the tracker attributed them to each endpoint.
              </p>
            </div>
            <DirectionCounters
              label="From source"
              packets={connection.source_packet_count}
              bytes={connection.source_byte_count}
              address={formatEndpoint(connection.source_ip, connection.source_port)}
            />
            <DirectionCounters
              label="From destination"
              packets={connection.destination_packet_count}
              bytes={connection.destination_byte_count}
              address={formatEndpoint(connection.destination_ip, connection.destination_port)}
            />
          </div>

          <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl border text-xs"
            style={{ backgroundColor: C.panel, borderColor: C.border, color: C.muted }}>
            <Ban size={13} style={{ color: C.faint, flexShrink: 0, marginTop: 1 }} />
            <span>
              This is an observed conversation, not a verdict. It carries no severity and no risk
              score, and its state is the tracker's own expiry view — not a judgement about the
              endpoints.
            </span>
          </div>
        </>
      )}
    </div>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

interface Props {
  showToast: (msg: string, type?: ToastMsg['type']) => void
}

export default function Connections({ showToast }: Props) {
  const [selected, setSelected] = useState<{ id: string; connection: Connection } | null>(null)
  const [protocolFilter, setProtocolFilter] = useState<ConnectionProtocol | 'ALL'>('ALL')
  const [stateFilter, setStateFilter] = useState<ConnectionState | 'ALL'>('ALL')
  const [sourceInput, setSourceInput] = useState('')
  const [destinationInput, setDestinationInput] = useState('')
  const [appliedSource, setAppliedSource] = useState('')
  const [appliedDestination, setAppliedDestination] = useState('')
  const [activeOnly, setActiveOnly] = useState(false)
  const [offset, setOffset] = useState(0)

  const query = useMemo(() => {
    const built: {
      protocol?: ConnectionProtocol
      state?: ConnectionState
      source_ip?: string
      destination_ip?: string
    } = {}
    if (protocolFilter !== 'ALL') built.protocol = protocolFilter
    if (stateFilter !== 'ALL') built.state = stateFilter
    if (appliedSource !== '') built.source_ip = appliedSource
    if (appliedDestination !== '') built.destination_ip = appliedDestination
    return built
  }, [protocolFilter, stateFilter, appliedSource, appliedDestination])

  const window = useMemo(() => ({ limit: PAGE_SIZE, offset }), [offset])
  const resource = useConnections({ query, window, activeOnly })

  if (selected !== null) {
    return (
      <ConnectionDetailPanel
        connectionId={selected.id}
        fallback={selected.connection}
        onBack={() => setSelected(null)}
      />
    )
  }

  const connections = resource.connections
  const isFiltered = protocolFilter !== 'ALL' || stateFilter !== 'ALL' ||
    appliedSource !== '' || appliedDestination !== '' || activeOnly

  const applyAddresses = () => {
    setAppliedSource(sourceInput.trim())
    setAppliedDestination(destinationInput.trim())
    setOffset(0)
  }

  const runExpiry = () => {
    void resource.expire().then(failure => {
      if (failure !== null) {
        showToast(failure.userMessage, 'error')
        return
      }
      const result = resource.lastExpiry
      showToast(
        result === null
          ? 'Expiry sweep completed'
          : `Expiry sweep completed — ${result.expired} retired, ${result.active} active, ${result.historical} historic`,
        'success',
      )
    })
  }

  // Counts over the loaded page, labelled as such: the listing's own `total` is the
  // match count for the current filter, and a per-state breakdown over the whole
  // tracker is not something M13 exposes.
  const trackedCount = connections.filter(c => c.active).length
  const closedCount = connections.filter(c => !c.active).length

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-4 gap-4">
        <div className="rounded-2xl border p-4 flex items-center gap-3"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="p-2.5 rounded-xl" style={{ backgroundColor: tint(C.accent, 0.08) }}>
            <Share2 size={16} style={{ color: C.accent }} />
          </div>
          <div>
            <div className="text-2xl font-bold text-white leading-none">{connections.length}</div>
            <div className="text-xs font-medium mt-0.5" style={{ color: C.muted }}>
              {activeOnly ? 'Active conversations' : 'Conversations on this page'}
            </div>
            <div className="text-xs mt-0.5" style={{ color: C.faint }}>
              {resource.total === null ? 'Total unknown' : `${formatCount(resource.total)} matching`}
            </div>
          </div>
        </div>
        <div className="rounded-2xl border p-4 flex items-center gap-3"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="p-2.5 rounded-xl" style={{ backgroundColor: tint(C.info, 0.08) }}>
            <Clock size={16} style={{ color: C.info }} />
          </div>
          <div>
            <div className="text-2xl font-bold text-white leading-none">{trackedCount}</div>
            <div className="text-xs font-medium mt-0.5" style={{ color: C.muted }}>Still tracked</div>
            <div className="text-xs mt-0.5" style={{ color: C.faint }}>Among the rows loaded</div>
          </div>
        </div>
        <div className="rounded-2xl border p-4 flex items-center gap-3"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="p-2.5 rounded-xl" style={{ backgroundColor: tint(C.dim, 0.08) }}>
            <Timer size={16} style={{ color: C.dim }} />
          </div>
          <div>
            <div className="text-2xl font-bold text-white leading-none">{closedCount}</div>
            <div className="text-xs font-medium mt-0.5" style={{ color: C.muted }}>Retired</div>
            <div className="text-xs mt-0.5" style={{ color: C.faint }}>Among the rows loaded</div>
          </div>
        </div>
        <div className="rounded-2xl border p-4 flex items-center gap-3"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="p-2.5 rounded-xl" style={{ backgroundColor: tint(C.purple, 0.08) }}>
            <Network size={16} style={{ color: C.purple }} />
          </div>
          <div>
            <div className="text-2xl font-bold text-white leading-none capitalize">
              {activeOnly ? 'Active' : 'All'}
            </div>
            <div className="text-xs font-medium mt-0.5" style={{ color: C.muted }}>Listing mode</div>
            <div className="text-xs mt-0.5" style={{ color: C.faint }}>
              {activeOnly ? 'GET /connections/active' : 'GET /connections'}
            </div>
          </div>
        </div>
      </div>

      <form className="flex items-center gap-2 flex-wrap"
        onSubmit={event => { event.preventDefault(); applyAddresses() }}>
        <button type="button" onClick={() => { setActiveOnly(!activeOnly); setOffset(0) }}
          className="px-3 py-2 rounded-xl text-xs font-medium border"
          style={{
            backgroundColor: activeOnly ? tint(C.success, 0.14) : C.card,
            borderColor: activeOnly ? C.success : C.border,
            color: activeOnly ? C.success : C.muted,
          }}>
          {activeOnly ? 'Showing active only' : 'Show active only'}
        </button>
        <select value={protocolFilter}
          onChange={e => {
            setProtocolFilter(e.target.value as ConnectionProtocol | 'ALL')
            setOffset(0)
          }}
          className="px-3 py-2 rounded-xl text-xs border"
          style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted, outline: 'none' }}>
          <option value="ALL">All protocols</option>
          {PROTOCOL_ORDER.map(protocol => (
            <option key={protocol} value={protocol}>{protocol}</option>
          ))}
        </select>
        <select value={stateFilter}
          onChange={e => {
            setStateFilter(e.target.value as ConnectionState | 'ALL')
            setOffset(0)
          }}
          className="px-3 py-2 rounded-xl text-xs border"
          style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted, outline: 'none' }}>
          <option value="ALL">All states</option>
          {STATE_ORDER.map(state => (
            <option key={state} value={state}>{stateLabel(state)}</option>
          ))}
        </select>
        <div className="flex items-center gap-2 px-3 py-2 rounded-xl border min-w-42.5"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <Server size={12} style={{ color: C.faint }} />
          <input value={sourceInput} onChange={e => setSourceInput(e.target.value)}
            placeholder="Source address…"
            className="bg-transparent text-xs flex-1"
            style={{ color: C.text, outline: 'none' }} />
        </div>
        <div className="flex items-center gap-2 px-3 py-2 rounded-xl border min-w-42.5"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <Network size={12} style={{ color: C.faint }} />
          <input value={destinationInput} onChange={e => setDestinationInput(e.target.value)}
            placeholder="Destination address…"
            className="bg-transparent text-xs flex-1"
            style={{ color: C.text, outline: 'none' }} />
        </div>
        <button type="submit"
          className="px-3 py-2 rounded-xl text-xs font-medium border"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
          Apply
        </button>
        {isFiltered && (
          <button type="button"
            onClick={() => {
              setProtocolFilter('ALL'); setStateFilter('ALL')
              setSourceInput(''); setDestinationInput('')
              setAppliedSource(''); setAppliedDestination('')
              setActiveOnly(false); setOffset(0)
            }}
            className="px-3 py-2 rounded-xl text-xs font-medium border"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
            Clear
          </button>
        )}
        <button type="button" onClick={resource.reload} disabled={resource.isLoading}
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
          <RefreshCw size={12} className={resource.isLoading ? 'animate-spin' : undefined} /> Refresh
        </button>
        <button type="button" onClick={runExpiry} disabled={resource.isExpiring}
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border disabled:opacity-50"
          style={{ borderColor: tint(C.warning, 0.4), color: C.warning, backgroundColor: tint(C.warning, 0.06) }}
          title="M9.22 development helper: forces the tracker's expiry sweep immediately instead of waiting for its own timer.">
          <Timer size={12} className={resource.isExpiring ? 'animate-spin' : undefined} />
          Force expiry sweep
        </button>
      </form>

      {resource.error !== null && connections.length > 0 && (
        <RefreshFailureBanner error={resource.error} onRetry={resource.reload} />
      )}

      <div className="rounded-2xl border overflow-hidden"
        style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: C.border }}>
          <div>
            <h2 className="text-sm font-semibold text-white">
              {activeOnly ? 'Active conversations' : 'Tracked conversations'}
            </h2>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>
              {connections.length} loaded
              {resource.total === null ? '' : ` of ${formatCount(resource.total)} matching`}
              {` · rows ${offset + 1}–${offset + connections.length}`}
            </p>
          </div>
          <span className="text-xs" style={{ color: C.faint }}>
            No severity — M9 tracks, it does not score
          </span>
        </div>

        <AsyncSection
          isInitialLoading={resource.isInitialLoading}
          error={resource.blockingError}
          isEmpty={false}
          loadingLabel="Loading conversations…"
          errorTitle="Unable to load conversations"
          onRetry={resource.reload}
          minHeight={240}
        >
          {connections.length === 0 ? (
            <EmptyState
              title={isFiltered ? 'No conversations match the filter' : 'No conversations tracked'}
              hint={isFiltered
                ? 'Widen the protocol or state filter, clear the addresses, or leave the active-only view.'
                : 'M9 opens a conversation when a packet starts one. Start a capture to populate the tracker.'}
              icon={isFiltered ? <Search size={28} /> : <Share2 size={28} />}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b" style={{ borderColor: C.border }}>
                    <th className="text-left pl-5 py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Protocol</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Conversation</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>State</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Packets</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Bytes</th>
                    <th className="text-left py-2.5 pr-5 text-xs font-medium" style={{ color: C.dim }}>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {connections.map(connection => {
                    const stateColor = STATE_COLORS[connection.state] ?? C.muted
                    return (
                      <tr key={connection.connection_id}
                        onClick={() => setSelected({ id: connection.connection_id, connection })}
                        className="border-b transition-all duration-150 cursor-pointer"
                        style={{ borderColor: '#1a2744' }}
                        onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)')}
                        onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
                        <td className="pl-5 py-3 pr-4">
                          <span className="mono text-xs font-semibold px-2 py-0.5 rounded-full"
                            style={{ backgroundColor: tint(C.accent, 0.1), color: C.accent }}>
                            {connection.protocol}
                          </span>
                        </td>
                        <td className="py-3 pr-4 mono text-xs whitespace-nowrap" style={{ color: C.text }}>
                          {formatEndpoint(connection.source_ip, connection.source_port)}
                          <span style={{ color: C.dim }}> → </span>
                          {formatEndpoint(connection.destination_ip, connection.destination_port)}
                        </td>
                        <td className="py-3 pr-4">
                          <span className="flex items-center gap-1.5 text-xs font-medium whitespace-nowrap w-fit"
                            style={{ color: stateColor }}>
                            <span className="w-1.5 h-1.5 rounded-full"
                              style={{ backgroundColor: stateColor }} />
                            {stateLabel(connection.state)}
                          </span>
                        </td>
                        <td className="py-3 pr-4 mono text-xs text-white">
                          {formatCount(connection.packet_count)}
                        </td>
                        <td className="py-3 pr-4 mono text-xs text-white">
                          {formatBytes(connection.byte_count)}
                        </td>
                        <td className="py-3 pr-5 text-xs whitespace-nowrap" style={{ color: C.muted }}>
                          {formatRelative(connection.last_seen)}
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
            {offset === 0 && !resource.hasMore ? 'All matching conversations' : `Offset ${offset}`}
          </span>
          <button onClick={() => setOffset(offset + PAGE_SIZE)}
            disabled={!resource.hasMore || resource.isLoading}
            className="px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            Next
          </button>
        </div>
      </div>

      {resource.lastExpiry !== null && (
        <p className="text-xs px-1" style={{ color: C.faint }}>
          Last forced sweep: {formatCount(resource.lastExpiry.expired)} retired,{' '}
          {formatCount(resource.lastExpiry.active)} still active,{' '}
          {formatCount(resource.lastExpiry.historical)} historic.
        </p>
      )}
    </div>
  )
}
