/**
 * Alerts — the M11 alert listing (M15.14).
 *
 * What this page replaced invented its alert corpus: a static array with MITRE
 * mappings, indicator-of-compromise lists and an "AI analysis" paragraph per row.
 * None of that exists behind the API. What exists is an alert with a severity, a
 * lifecycle state, an evidence strength and a set of references, and that is what
 * is rendered.
 *
 * The listing is `GET /alerts`; `/ws/alerts` keeps it current. The two are joined
 * by {@link useAlerts}, which makes one distinction this page must not blur: an
 * update to a row **already on screen** replaces that row, while a *new* alert is
 * collected in `pendingNew` rather than inserted. Deciding whether a new alert
 * belongs in the current filtered, paginated page would mean re-implementing the
 * backend's filter and ordering in React, so the page offers a refresh instead and
 * says how many are waiting (M15.14).
 *
 * Nothing here re-derives a lifecycle rule. The buttons come from
 * {@link ALERT_TRANSITIONS} so the UI avoids offering a move that is guaranteed to
 * be refused; the backend still decides, and a refusal is displayed (M15.15).
 */

import { useMemo, useState } from 'react'
import {
  Search, ShieldAlert, RefreshCw, Bell, Inbox, Hash, FileText, Server,
} from 'lucide-react'
import {
  AsyncSection, EmptyState, RefreshFailureBanner,
} from '@/components/AsyncState'
import { useAlerts } from '@/hooks'
import { DEFAULT_PAGE_LIMIT } from '@/services'
import type { ApiError } from '@/services'
import { C, tint, SEVERITY_COLORS, ALERT_STATUS_COLORS } from '@/lib/tokens'
import {
  UNKNOWN_TEXT, formatConfidence, formatCount, formatRelative, formatTimeOfDay,
} from '@/lib/format'
import { ALERT_SEVERITY_ORDER } from '@/types'
import type { Alert, AlertSeverity, AlertStatus } from '@/types'
import type { ToastMsg } from '../App'
import { AlertDetailPanel } from '@/components/alerts/AlertDetailPanel'

/** How many alerts one page shows. */
const PAGE_SIZE = DEFAULT_PAGE_LIMIT

/** The five lifecycle states, in the order the filter offers them. */
const ALERT_STATUS_ORDER: readonly AlertStatus[] = [
  'open',
  'acknowledged',
  'resolved',
  'dismissed',
  'false_positive',
]

/** A readable label for a lifecycle state. */
function statusLabel(status: AlertStatus): string {
  return status === 'false_positive'
    ? 'False positive'
    : status.charAt(0).toUpperCase() + status.slice(1)
}

/** A readable label for a severity. */
function severityLabel(severity: AlertSeverity): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1)
}

// ─── Summary tiles ───────────────────────────────────────────────────────────

/**
 * One count, straight from `GET /alerts/summary`.
 *
 * The counts are the backend's tallies over the whole alert store, not a count of
 * the rows on screen — the caption says so, because "open: 3" meaning "3 open
 * alerts in this page" and "3 open alerts in the system" are very different
 * statements.
 */
function SummaryTile({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="rounded-2xl border px-4 py-3"
      style={{ backgroundColor: C.card, borderColor: C.border }}>
      <div className="flex items-center gap-2">
        <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: color }} />
        <span className="text-xs font-medium" style={{ color: C.muted }}>{label}</span>
      </div>
      <div className="text-2xl font-bold text-white mt-1 leading-none">{formatCount(value)}</div>
    </div>
  )
}

// ─── Table row ───────────────────────────────────────────────────────────────

function AlertRow({ alert, onOpen }: { alert: Alert; onOpen: () => void }) {
  const severityColor = SEVERITY_COLORS[alert.severity] ?? C.warning
  const statusColor = ALERT_STATUS_COLORS[alert.status] ?? C.muted
  return (
    <tr onClick={onOpen}
      className="border-b transition-all duration-150 cursor-pointer"
      style={{ borderColor: '#1a2744' }}
      onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)')}
      onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
      <td className="pl-5 py-3 pr-3">
        <span className="text-xs font-semibold px-2 py-0.5 rounded-full whitespace-nowrap"
          style={{ backgroundColor: tint(severityColor, 0.12), color: severityColor }}>
          {severityLabel(alert.severity)}
        </span>
      </td>
      <td className="py-3 pr-4 max-w-80">
        <div className="text-xs font-semibold text-white truncate" title={alert.title}>{alert.title}</div>
        <div className="text-xs mt-0.5 truncate" style={{ color: C.faint }} title={alert.description}>
          {alert.description}
        </div>
      </td>
      <td className="py-3 pr-4">
        <span className="text-xs font-medium capitalize whitespace-nowrap" style={{ color: statusColor }}>
          {statusLabel(alert.status)}
        </span>
      </td>
      <td className="py-3 pr-4 mono text-xs whitespace-nowrap" style={{ color: C.accent }}>
        {alert.source_ip ?? UNKNOWN_TEXT}
        <span style={{ color: C.dim }}> → </span>
        {alert.destination_ip ?? UNKNOWN_TEXT}
      </td>
      <td className="py-3 pr-4">
        <div className="flex items-center gap-2">
          <div className="w-10 h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
            <div className="h-full rounded-full"
              style={{ width: `${Math.round(alert.confidence * 100)}%`, backgroundColor: C.info }} />
          </div>
          <span className="mono text-xs" style={{ color: C.muted }}>{formatConfidence(alert.confidence)}</span>
        </div>
      </td>
      <td className="py-3 pr-4 mono text-xs whitespace-nowrap" style={{ color: C.faint }}>
        {alert.protocol ?? UNKNOWN_TEXT}
      </td>
      <td className="py-3 pr-4">
        <span className="flex items-center gap-1 text-xs whitespace-nowrap" style={{ color: C.faint }}>
          <FileText size={11} />
          {alert.evidence_count}
        </span>
      </td>
      <td className="py-3 pr-5 text-xs whitespace-nowrap" style={{ color: C.muted }}
        title={alert.created_at ?? undefined}>
        {formatRelative(alert.created_at)}
      </td>
    </tr>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

interface Props {
  showToast: (msg: string, type?: ToastMsg['type']) => void
}

export default function Alerts({ showToast }: Props) {
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [severityFilter, setSeverityFilter] = useState<AlertSeverity | 'ALL'>('ALL')
  const [statusFilter, setStatusFilter] = useState<AlertStatus | 'ALL'>('ALL')
  // The address box is an *applied* backend filter, not a live client-side one.
  // Free-text narrowing of the loaded page would silently search only the current
  // page, which is the mistake the Devices page names explicitly; here the query
  // is the server's, so the result is the whole matching set.
  const [addressInput, setAddressInput] = useState('')
  const [appliedAddress, setAppliedAddress] = useState('')
  const [offset, setOffset] = useState(0)

  const query = useMemo(() => {
    const built: {
      severity?: AlertSeverity
      status?: readonly AlertStatus[]
      source_ip?: string
    } = {}
    if (severityFilter !== 'ALL') built.severity = severityFilter
    if (statusFilter !== 'ALL') built.status = [statusFilter]
    if (appliedAddress !== '') built.source_ip = appliedAddress
    return built
  }, [severityFilter, statusFilter, appliedAddress])

  const window = useMemo(() => ({ limit: PAGE_SIZE, offset }), [offset])
  const resource = useAlerts({ query, window })

  // Opening a row clears any transition refusal left over from the previous one.
  const openAlert = (alertId: number) => {
    setSelectedId(alertId)
  }

  if (selectedId !== null) {
    return (
      <AlertDetailPanel
        alertId={selectedId}
        onBack={() => setSelectedId(null)}
        transition={resource.transition}
      />
    )
  }

  const summary = resource.summary
  const isFiltered = severityFilter !== 'ALL' || statusFilter !== 'ALL' || appliedAddress !== ''

  const applyAddress = () => {
    setAppliedAddress(addressInput.trim())
    setOffset(0)
  }

  const refreshNew = () => {
    showToast(
      `Reloading — ${resource.pendingNew.length} alert${resource.pendingNew.length === 1 ? '' : 's'} arrived live`,
      'info',
    )
    resource.reload()
  }

  return (
    <div className="space-y-4">
      {/* Live counts from the backend, over the whole alert store */}
      <div className="grid grid-cols-4 gap-4">
        {ALERT_SEVERITY_ORDER.map(severity => (
          <SummaryTile key={severity} label={`${severityLabel(severity)} (all time)`}
            value={summary?.by_severity[severity] ?? 0}
            color={SEVERITY_COLORS[severity] ?? C.muted} />
        ))}
      </div>

      <div className="rounded-2xl border px-4 py-3"
        style={{ backgroundColor: C.card, borderColor: C.border }}>
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-4 flex-wrap">
            <span className="text-xs font-medium" style={{ color: C.muted }}>
              Total alerts: <span className="text-white mono">{formatCount(summary?.total ?? null)}</span>
            </span>
            {ALERT_STATUS_ORDER.map(status => (
              <span key={status} className="flex items-center gap-1.5 text-xs">
                <span className="w-1.5 h-1.5 rounded-full"
                  style={{ backgroundColor: ALERT_STATUS_COLORS[status] ?? C.muted }} />
                <span style={{ color: C.faint }}>{statusLabel(status)}</span>
                <span className="mono" style={{ color: C.muted }}>
                  {formatCount(summary?.by_status[status] ?? null)}
                </span>
              </span>
            ))}
          </div>

          <span className="flex items-center gap-1.5 text-xs"
            style={{ color: resource.isConnected ? C.success : C.dim }}>
            <span className="w-1.5 h-1.5 rounded-full"
              style={{ backgroundColor: resource.isConnected ? C.success : C.dim }} />
            {resource.isConnected
              ? `live${resource.lastEventAt !== null ? '' : ' — awaiting first event'}`
              : 'live stream disconnected'}
          </span>
        </div>
      </div>

      {/* Live arrivals the listing does not contain, offered as a refresh */}
      {resource.pendingNew.length > 0 && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-2xl border"
          style={{
            backgroundColor: tint(C.accent, 0.08),
            borderColor: tint(C.accent, 0.25),
          }}>
          <Bell size={14} style={{ color: C.accent, flexShrink: 0 }} />
          <span className="text-xs flex-1" style={{ color: C.muted }}>
            {resource.pendingNew.length} alert{resource.pendingNew.length === 1 ? '' : 's'} arrived live
            and {resource.pendingNew.length === 1 ? 'is' : 'are'} not part of this page. Whether
            {resource.pendingNew.length === 1 ? ' it belongs' : ' they belong'} here is the
            backend's answer, so reload rather than assume.
          </span>
          <button onClick={refreshNew}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold"
            style={{ backgroundColor: tint(C.accent, 0.15), color: C.accent }}>
            <RefreshCw size={11} /> Reload
          </button>
        </div>
      )}

      {/* Filters */}
      <form className="flex items-center gap-2 flex-wrap"
        onSubmit={event => { event.preventDefault(); applyAddress() }}>
        <div className="flex items-center gap-2 px-3 py-2 rounded-xl border flex-1 min-w-55"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <Search size={13} style={{ color: C.faint }} />
          <input value={addressInput}
            onChange={e => setAddressInput(e.target.value)}
            placeholder="Filter by source address, then press Enter…"
            className="bg-transparent text-xs flex-1"
            style={{ color: C.text, outline: 'none' }} />
          {appliedAddress !== '' && (
            <button type="button"
              onClick={() => { setAddressInput(''); setAppliedAddress(''); setOffset(0) }}
              className="text-xs" style={{ color: C.faint }}>
              clear
            </button>
          )}
        </div>
        <select value={severityFilter}
          onChange={e => {
            setSeverityFilter(e.target.value as AlertSeverity | 'ALL')
            setOffset(0)
          }}
          className="px-3 py-2 rounded-xl text-xs border"
          style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted, outline: 'none' }}>
          <option value="ALL">All severities</option>
          {ALERT_SEVERITY_ORDER.map(severity => (
            <option key={severity} value={severity}>{severityLabel(severity)}</option>
          ))}
        </select>
        <select value={statusFilter}
          onChange={e => {
            setStatusFilter(e.target.value as AlertStatus | 'ALL')
            setOffset(0)
          }}
          className="px-3 py-2 rounded-xl text-xs border"
          style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted, outline: 'none' }}>
          <option value="ALL">All states</option>
          {ALERT_STATUS_ORDER.map(status => (
            <option key={status} value={status}>{statusLabel(status)}</option>
          ))}
        </select>
        <button type="button" onClick={resource.reload} disabled={resource.isLoading}
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
          <RefreshCw size={12} className={resource.isLoading ? 'animate-spin' : undefined} /> Refresh
        </button>
      </form>

      {resource.error !== null && resource.alerts.length > 0 && (
        <RefreshFailureBanner error={resource.error} onRetry={resource.reload} />
      )}

      <div className="rounded-2xl border overflow-hidden"
        style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: C.border }}>
          <div>
            <h2 className="text-sm font-semibold text-white">Alerts</h2>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>
              {resource.alerts.length} loaded
              {resource.total === null ? '' : ` of ${formatCount(resource.total)} matching`}
              {` · rows ${offset + 1}–${offset + resource.alerts.length}`}
            </p>
          </div>
          <div className="flex items-center gap-3 text-xs" style={{ color: C.faint }}>
            <span className="flex items-center gap-1"><Hash size={11} /> rule id shown in detail</span>
          </div>
        </div>

        <AsyncSection
          isInitialLoading={resource.isInitialLoading}
          error={resource.blockingError}
          isEmpty={false}
          loadingLabel="Loading alerts…"
          errorTitle="Unable to load alerts"
          onRetry={resource.reload}
          minHeight={240}
        >
          {resource.alerts.length === 0 ? (
            <EmptyState
              title={isFiltered ? 'No alerts match the filter' : 'No alerts raised'}
              hint={isFiltered
                ? 'Widen the severity or state filter, or clear the address box.'
                : 'M11 raises an alert when a detection finding crosses a rule threshold. Nothing has crossed one yet.'}
              icon={isFiltered ? <Search size={28} /> : <ShieldAlert size={28} />}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b" style={{ borderColor: C.border }}>
                    <th className="text-left pl-5 py-2.5 pr-3 text-xs font-medium" style={{ color: C.dim }}>Severity</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Alert</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>State</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Flow</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Confidence</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Protocol</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Evidence</th>
                    <th className="text-left py-2.5 pr-5 text-xs font-medium" style={{ color: C.dim }}>Raised</th>
                  </tr>
                </thead>
                <tbody>
                  {resource.alerts.map(alert => (
                    <AlertRow key={alert.alert_id} alert={alert} onOpen={() => openAlert(alert.alert_id)} />
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
            {offset === 0 && !resource.hasMore ? 'All matching alerts' : `Offset ${offset}`}
          </span>
          <button onClick={() => setOffset(offset + PAGE_SIZE)}
            disabled={!resource.hasMore || resource.isLoading}
            className="px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            Next
          </button>
        </div>
      </div>

      {resource.alerts.length > 0 && (
        <p className="text-xs px-1 flex items-center gap-1.5" style={{ color: C.faint }}>
          <Server size={11} />
          A flow of {UNKNOWN_TEXT} means the backend recorded no address for that side of the alert.
        </p>
      )}
    </div>
  )
}
