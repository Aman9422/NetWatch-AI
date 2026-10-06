/**
 * Incidents — correlated event groups (M15.17/M15.18).
 *
 * An incident is what several related events add up to, and the listing shows the
 * three figures that describe it without collapsing them (M12.16): the risk score
 * and its band, the correlation confidence, and the alert confidence. The row
 * gives each its own column with its own unit, and the detail view explains them —
 * a single merged "score" column would be the display error this milestone is most
 * careful to avoid (M15.17).
 *
 * Live updates arrive on the **alerts** channel (M14.12). As on the Alerts page, an
 * update to a row already on screen replaces it, while a newly created incident is
 * held in `pendingNew` and offered behind a reload — inserting it would mean
 * re-implementing the backend's filter and ordering in React (M15.18).
 *
 * Two listings exist and the page chooses between them rather than filtering one:
 * `GET /incidents` takes filters, and `GET /incidents/open` is the backend's own
 * "still active" set. The open figure shown is therefore the server's answer, not a
 * client-side narrowing (M13.15).
 */

import { useMemo, useState } from 'react'
import {
  Layers, RefreshCw, Bell, Search, AlertTriangle, Server, Hash,
} from 'lucide-react'
import {
  AsyncSection, EmptyState, RefreshFailureBanner,
} from '@/components/AsyncState'
import { useIncidents } from '@/hooks'
import { DEFAULT_PAGE_LIMIT } from '@/services'
import { C, tint, INCIDENT_STATUS_COLORS, SEVERITY_COLORS, RISK_BAND_COLORS } from '@/lib/tokens'
import {
  UNKNOWN_TEXT, formatConfidence, formatCount, formatEpochRelative,
  formatRiskScore,
} from '@/lib/format'
import type { IncidentSummary, IncidentStatus } from '@/types'
import type { ToastMsg } from '../App'
import { IncidentDetailPanel } from '@/components/incidents/IncidentDetailPanel'

/** How many incidents one page shows. */
const PAGE_SIZE = DEFAULT_PAGE_LIMIT

/** The four incident states, in the order the filter offers them. */
const INCIDENT_STATUS_ORDER: readonly IncidentStatus[] = [
  'open',
  'investigating',
  'resolved',
  'dismissed',
]

/** A readable label for a state. */
function statusLabel(status: string): string {
  return status.charAt(0).toUpperCase() + status.slice(1)
}

/** A small reading with its own unit, so two figures are never confused. */
function Figure({ label, value, color, hint }: {
  label: string
  value: string
  color: string
  hint: string
}) {
  return (
    <div title={hint}>
      <div className="text-xs" style={{ color: C.faint }}>{label}</div>
      <div className="mono text-sm font-semibold" style={{ color }}>{value}</div>
    </div>
  )
}

// ─── Table row ───────────────────────────────────────────────────────────────

function IncidentRow({ incident, onOpen }: {
  incident: IncidentSummary
  onOpen: () => void
}) {
  const statusColor = INCIDENT_STATUS_COLORS[incident.status] ?? C.muted
  const bandColor = RISK_BAND_COLORS[incident.risk_band] ?? C.muted
  const severityColor = incident.severity === null
    ? C.faint
    : (SEVERITY_COLORS[incident.severity] ?? C.warning)

  return (
    <tr onClick={onOpen}
      className="border-b transition-all duration-150 cursor-pointer align-top"
      style={{ borderColor: '#1a2744' }}
      onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)')}
      onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
      <td className="pl-5 py-3 pr-3">
        <span className="text-xs font-semibold px-2 py-0.5 rounded-full capitalize whitespace-nowrap"
          style={{ backgroundColor: tint(statusColor, 0.12), color: statusColor }}>
          {statusLabel(incident.status)}
        </span>
        {incident.severity !== null && (
          <div className="text-xs mt-1 capitalize" style={{ color: severityColor }}>
            {incident.severity}
          </div>
        )}
      </td>
      <td className="py-3 pr-4 max-w-[320px]">
        <div className="text-xs font-semibold text-white truncate" title={incident.title}>
          {incident.title}
        </div>
        <div className="mono text-[11px] mt-0.5" style={{ color: C.faint }}>
          {incident.incident_id}
        </div>
      </td>
      <td className="py-3 pr-4">
        <div className="flex items-center gap-2">
          <div className="w-12 h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
            <div className="h-full rounded-full"
              style={{ width: `${Math.round(Math.max(0, Math.min(100, incident.risk_score)))}%`,
                backgroundColor: bandColor }} />
          </div>
          <span className="mono text-xs font-bold" style={{ color: bandColor }}>
            {formatRiskScore(incident.risk_score)}
          </span>
        </div>
        <div className="text-xs mt-0.5 capitalize" style={{ color: bandColor }}>
          {incident.risk_band}
        </div>
      </td>
      <td className="py-3 pr-4">
        <Figure
          label="Correlation"
          value={formatConfidence(incident.correlation_confidence)}
          color={C.purple}
          hint="How strongly M12 judged the member events to be related — not evidence strength."
        />
      </td>
      <td className="py-3 pr-4">
        <Figure
          label="Alert evidence"
          value={formatConfidence(incident.alert_confidence)}
          color={C.info}
          hint="The mean evidence strength of the member alerts — not a measure of relatedness."
        />
      </td>
      <td className="py-3 pr-4">
        <div className="flex items-center gap-3 text-xs" style={{ color: C.muted }}>
          <span className="flex items-center gap-1 whitespace-nowrap">
            <Layers size={11} style={{ color: C.faint }} />{formatCount(incident.event_count)}
          </span>
          <span className="flex items-center gap-1 whitespace-nowrap">
            <AlertTriangle size={11} style={{ color: C.faint }} />{formatCount(incident.alert_count)}
          </span>
          <span className="flex items-center gap-1 whitespace-nowrap">
            <Server size={11} style={{ color: C.faint }} />{formatCount(incident.device_ids.length)}
          </span>
        </div>
      </td>
      <td className="py-3 pr-5 text-xs whitespace-nowrap" style={{ color: C.muted }}>
        {formatEpochRelative(incident.last_seen)}
      </td>
    </tr>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

interface Props {
  showToast: (msg: string, type?: ToastMsg['type']) => void
}

export default function Incidents({ showToast }: Props) {
  const [selected, setSelected] = useState<IncidentSummary | null>(null)
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | 'ALL'>('ALL')
  const [order, setOrder] = useState<'recent' | 'risk'>('risk')
  const [openOnly, setOpenOnly] = useState(false)
  const [minRiskInput, setMinRiskInput] = useState('')
  const [appliedMinRisk, setAppliedMinRisk] = useState<number | null>(null)
  const [offset, setOffset] = useState(0)

  const query = useMemo(() => {
    const built: {
      status?: IncidentStatus
      min_risk_score?: number
      order?: 'recent' | 'risk'
    } = { order }
    if (statusFilter !== 'ALL') built.status = statusFilter
    if (appliedMinRisk !== null) built.min_risk_score = appliedMinRisk
    return built
  }, [statusFilter, order, appliedMinRisk])

  // The window is keyed by its values, so a page change re-requests while a mere
  // re-render does not.
  const window = useMemo(() => ({ limit: PAGE_SIZE, offset }), [offset])
  // `openOnly` selects the endpoint rather than filtering the result (M13.15).
  const resource = useIncidents({ query, window, openOnly })

  if (selected !== null) {
    return (
      <IncidentDetailPanel
        incidentId={selected.incident_id}
        onBack={() => setSelected(null)}
        transition={resource.transition}
        summary={selected}
      />
    )
  }

  const incidents = resource.incidents
  const isFiltered = statusFilter !== 'ALL' || appliedMinRisk !== null || openOnly

  const applyMinRisk = () => {
    const parsed = Number.parseFloat(minRiskInput)
    if (minRiskInput.trim() === '' || Number.isNaN(parsed)) {
      setAppliedMinRisk(null)
    } else {
      setAppliedMinRisk(Math.max(0, Math.min(100, parsed)))
    }
    setOffset(0)
  }

  const refreshNew = () => {
    showToast(
      `Reloading — ${resource.pendingNew.length} incident${resource.pendingNew.length === 1 ? '' : 's'} arrived live`,
      'info',
    )
    resource.reload()
  }

  // Counts over the loaded page, labelled as such: the backend exposes no incident
  // summary endpoint, so a "total by state" figure would have to be invented.
  const openCount = incidents.filter(i => i.status === 'open').length
  const investigatingCount = incidents.filter(i => i.status === 'investigating').length
  const highRiskCount = incidents.filter(i => i.risk_band === 'high').length

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-4 gap-4">
        <div className="rounded-2xl border p-4 flex items-center gap-3"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="p-2.5 rounded-xl" style={{ backgroundColor: tint(C.accent, 0.08) }}>
            <Layers size={16} style={{ color: C.accent }} />
          </div>
          <div>
            <div className="text-2xl font-bold text-white leading-none">{incidents.length}</div>
            <div className="text-xs font-medium mt-0.5" style={{ color: C.muted }}>
              Incidents on this page
            </div>
            <div className="text-xs mt-0.5" style={{ color: C.faint }}>
              {resource.total === null ? 'Total unknown' : `${formatCount(resource.total)} matching`}
            </div>
          </div>
        </div>
        <div className="rounded-2xl border p-4 flex items-center gap-3"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="p-2.5 rounded-xl" style={{ backgroundColor: tint(C.danger, 0.08) }}>
            <AlertTriangle size={16} style={{ color: C.danger }} />
          </div>
          <div>
            <div className="text-2xl font-bold text-white leading-none">{openCount}</div>
            <div className="text-xs font-medium mt-0.5" style={{ color: C.muted }}>Open</div>
            <div className="text-xs mt-0.5" style={{ color: C.faint }}>Among the rows loaded</div>
          </div>
        </div>
        <div className="rounded-2xl border p-4 flex items-center gap-3"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="p-2.5 rounded-xl" style={{ backgroundColor: tint(C.warning, 0.08) }}>
            <Search size={16} style={{ color: C.warning }} />
          </div>
          <div>
            <div className="text-2xl font-bold text-white leading-none">{investigatingCount}</div>
            <div className="text-xs font-medium mt-0.5" style={{ color: C.muted }}>Investigating</div>
            <div className="text-xs mt-0.5" style={{ color: C.faint }}>Among the rows loaded</div>
          </div>
        </div>
        <div className="rounded-2xl border p-4 flex items-center gap-3"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="p-2.5 rounded-xl" style={{ backgroundColor: tint(C.danger, 0.08) }}>
            <Hash size={16} style={{ color: C.danger }} />
          </div>
          <div>
            <div className="text-2xl font-bold text-white leading-none">{highRiskCount}</div>
            <div className="text-xs font-medium mt-0.5" style={{ color: C.muted }}>High risk band</div>
            <div className="text-xs mt-0.5" style={{ color: C.faint }}>Among the rows loaded</div>
          </div>
        </div>
      </div>

      <div className="rounded-2xl border px-4 py-3"
        style={{ backgroundColor: C.card, borderColor: C.border }}>
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-4 flex-wrap">
            {INCIDENT_STATUS_ORDER.map(status => (
              <span key={status} className="flex items-center gap-1.5 text-xs">
                <span className="w-1.5 h-1.5 rounded-full"
                  style={{ backgroundColor: INCIDENT_STATUS_COLORS[status] ?? C.muted }} />
                <span style={{ color: C.faint }}>{statusLabel(status)}</span>
              </span>
            ))}
            <span className="text-xs" style={{ color: C.faint }}>
              Correlation confidence and alert confidence are separate readings, shown per row.
            </span>
          </div>
          <span className="flex items-center gap-1.5 text-xs"
            style={{ color: resource.isConnected ? C.success : C.dim }}>
            <span className="w-1.5 h-1.5 rounded-full"
              style={{ backgroundColor: resource.isConnected ? C.success : C.dim }} />
            {resource.isConnected ? 'live' : 'live stream disconnected'}
          </span>
        </div>
      </div>

      {resource.pendingNew.length > 0 && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-2xl border"
          style={{ backgroundColor: tint(C.accent, 0.08), borderColor: tint(C.accent, 0.25) }}>
          <Bell size={14} style={{ color: C.accent, flexShrink: 0 }} />
          <span className="text-xs flex-1" style={{ color: C.muted }}>
            {resource.pendingNew.length} incident{resource.pendingNew.length === 1 ? '' : 's'} arrived
            live and {resource.pendingNew.length === 1 ? 'is' : 'are'} not part of this page. Whether
            {resource.pendingNew.length === 1 ? ' it belongs' : ' they belong'} under this filter is
            the backend's answer, so reload rather than assume.
          </span>
          <button onClick={refreshNew}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold"
            style={{ backgroundColor: tint(C.accent, 0.15), color: C.accent }}>
            <RefreshCw size={11} /> Reload
          </button>
        </div>
      )}

      <form className="flex items-center gap-2 flex-wrap"
        onSubmit={event => { event.preventDefault(); applyMinRisk() }}>
        <button type="button" onClick={() => { setOpenOnly(!openOnly); setOffset(0) }}
          className="px-3 py-2 rounded-xl text-xs font-medium border"
          style={{
            backgroundColor: openOnly ? tint(C.success, 0.14) : C.card,
            borderColor: openOnly ? C.success : C.border,
            color: openOnly ? C.success : C.muted,
          }}>
          {openOnly ? 'Showing open only' : 'Show open only'}
        </button>
        <select value={statusFilter}
          onChange={e => {
            setStatusFilter(e.target.value as IncidentStatus | 'ALL')
            setOffset(0)
          }}
          className="px-3 py-2 rounded-xl text-xs border"
          style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted, outline: 'none' }}>
          <option value="ALL">All states</option>
          {INCIDENT_STATUS_ORDER.map(status => (
            <option key={status} value={status}>{statusLabel(status)}</option>
          ))}
        </select>
        <select value={order}
          onChange={e => setOrder(e.target.value as 'recent' | 'risk')}
          className="px-3 py-2 rounded-xl text-xs border"
          style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted, outline: 'none' }}>
          <option value="risk">Highest risk first</option>
          <option value="recent">Most recent first</option>
        </select>
        <div className="flex items-center gap-2 px-3 py-2 rounded-xl border min-w-[170px]"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <input value={minRiskInput}
            onChange={e => setMinRiskInput(e.target.value)}
            inputMode="numeric"
            placeholder="Min risk score…"
            className="bg-transparent text-xs flex-1"
            style={{ color: C.text, outline: 'none' }} />
          {appliedMinRisk !== null && (
            <button type="button"
              onClick={() => { setMinRiskInput(''); setAppliedMinRisk(null); setOffset(0) }}
              className="text-xs" style={{ color: C.faint }}>
              clear
            </button>
          )}
        </div>
        <button type="button" onClick={resource.reload} disabled={resource.isLoading}
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
          <RefreshCw size={12} className={resource.isLoading ? 'animate-spin' : undefined} /> Refresh
        </button>
      </form>

      {resource.error !== null && incidents.length > 0 && (
        <RefreshFailureBanner error={resource.error} onRetry={resource.reload} />
      )}

      <div className="rounded-2xl border overflow-hidden"
        style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: C.border }}>
          <div>
            <h2 className="text-sm font-semibold text-white">
              {openOnly ? 'Open incidents' : 'Correlated incidents'}
            </h2>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>
              {incidents.length} loaded
              {resource.total === null ? '' : ` of ${formatCount(resource.total)} matching`}
              {` · rows ${offset + 1}–${offset + incidents.length}`}
            </p>
          </div>
        </div>

        <AsyncSection
          isInitialLoading={resource.isInitialLoading}
          error={resource.blockingError}
          isEmpty={false}
          loadingLabel="Loading incidents…"
          errorTitle="Unable to load incidents"
          onRetry={resource.reload}
          minHeight={240}
        >
          {incidents.length === 0 ? (
            <EmptyState
              title={isFiltered ? 'No incidents match the filter' : 'No incidents correlated'}
              hint={isFiltered
                ? 'Widen the state filter, lower the risk floor, or leave the open-only view.'
                : 'M12 forms an incident when several related events correlate. Nothing has correlated yet.'}
              icon={isFiltered ? <Search size={28} /> : <Layers size={28} />}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b" style={{ borderColor: C.border }}>
                    <th className="text-left pl-5 py-2.5 pr-3 text-xs font-medium" style={{ color: C.dim }}>State</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Incident</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Risk</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Correlation confidence</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Alert confidence</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Members</th>
                    <th className="text-left py-2.5 pr-5 text-xs font-medium" style={{ color: C.dim }}>Last event</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map(incident => (
                    <IncidentRow
                      key={incident.incident_id}
                      incident={incident}
                      onOpen={() => setSelected(incident)}
                    />
                  ))}
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
            {offset === 0 && !resource.hasMore ? 'All matching incidents' : `Offset ${offset}`}
          </span>
          <button onClick={() => setOffset(offset + PAGE_SIZE)}
            disabled={!resource.hasMore || resource.isLoading}
            className="px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            Next
          </button>
        </div>
      </div>

      {incidents.length > 0 && (
        <p className="text-xs px-1" style={{ color: C.faint }}>
          A value of {UNKNOWN_TEXT} means the backend recorded no instant, and a member count of
          0 means nothing of that kind was correlated in.
        </p>
      )}
    </div>
  )
}
