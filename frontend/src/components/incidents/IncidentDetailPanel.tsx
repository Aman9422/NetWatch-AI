/**
 * One correlated incident in full (M15.17/M15.18/M15.19).
 *
 * The listing carries a summary; this view adds what only `GET /incidents/{id}`
 * serves — the member references, the correlation *reason trail* and the ISO-8601
 * forms of every instant. The {@link IncidentMetrics} block keeps `risk_score`,
 * `correlation_confidence` and `alert_confidence` visibly apart, which is the one
 * display rule this milestone treats as inviolable (M15.17).
 *
 * Live updates arrive on the **alerts** channel and their payload is a summary,
 * not the detail, so {@link useIncident} re-reads rather than patching. That
 * matters here more than anywhere else: patching a status onto a stale member list
 * would show a resolved incident beside the alerts correlated into it before the
 * change — a snapshot that never existed (M15.18).
 *
 * The timeline is drawn from stored instants only. Nothing here computes a
 * duration the backend did not send; `span_seconds` is M12's own figure and
 * `dropped_events` is displayed rather than hidden, because an incident that lost
 * membership is a fact about the incident, not a rendering detail.
 */

import { useState } from 'react'
import {
  ArrowLeft, Clock, AlertTriangle, Network, Server, Hash,
  FileText, Layers, ShieldAlert, SearchX,
} from 'lucide-react'
import { ErrorState, LoadingState, RefreshFailureBanner } from '@/components/AsyncState'
import { useIncident } from '@/hooks'
import { C, tint, INCIDENT_STATUS_COLORS, SEVERITY_COLORS } from '@/lib/tokens'
import {
  UNKNOWN_TEXT, formatCount, formatEpochRelative, formatEpochSeconds,
  formatDurationSeconds, formatTimestamp,
} from '@/lib/format'
import type { IncidentLifecycleAction, IncidentSummary } from '@/types'
import type { ApiError } from '@/services'
import { IncidentMetrics } from './IncidentMetrics'
import { IncidentLifecycleActions } from './IncidentLifecycleActions'

/** A readable label for an incident state. */
function statusLabel(status: string): string {
  return status.charAt(0).toUpperCase() + status.slice(1)
}

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

/** A titled list of member references. */
function ReferenceList({ title, icon, ids, emptyHint }: {
  title: string
  icon: React.ReactNode
  ids: readonly (string | number)[]
  emptyHint: string
}) {
  return (
    <div className="rounded-xl border overflow-hidden"
      style={{ backgroundColor: C.panel, borderColor: C.border }}>
      <div className="flex items-center justify-between px-4 py-2.5 border-b"
        style={{ borderColor: C.border }}>
        <span className="flex items-center gap-1.5 text-xs font-semibold text-white">
          <span style={{ color: C.accent }}>{icon}</span>
          {title}
        </span>
        <span className="mono text-xs" style={{ color: C.faint }}>{ids.length}</span>
      </div>
      {ids.length === 0 ? (
        <p className="px-4 py-3 text-xs" style={{ color: C.faint }}>{emptyHint}</p>
      ) : (
        <ul className="max-h-40 overflow-y-auto divide-y" style={{ borderColor: '#1a2744' }}>
          {ids.map(id => (
            <li key={String(id)} className="px-4 py-2 mono text-xs"
              style={{ color: C.muted, borderColor: '#1a2744' }}>
              {String(id)}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

/** The panel shown when the incident a route names no longer exists. */
function NotFoundPanel({ incidentId, onBack }: { incidentId: string; onBack: () => void }) {
  return (
    <div className="rounded-2xl border flex flex-col items-center justify-center gap-3 text-center px-6 py-14"
      style={{ backgroundColor: C.card, borderColor: C.border }}>
      <SearchX size={30} style={{ color: C.border }} />
      <p className="text-sm font-medium text-white">Incident not found</p>
      <p className="text-xs max-w-md" style={{ color: C.muted }}>
        The backend answered 404 for incident <span className="mono">{incidentId}</span>.
        Incidents are not permanent records, so this is the incident being gone rather than
        the request having failed.
      </p>
      <button onClick={onBack}
        className="mt-1 flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold"
        style={{ backgroundColor: tint(C.accent, 0.15), color: C.accent }}>
        <ArrowLeft size={12} /> Back to Incidents
      </button>
    </div>
  )
}

/** What {@link IncidentDetailPanel} takes. */
export interface IncidentDetailPanelProps {
  readonly incidentId: string
  readonly onBack: () => void
  readonly transition: (
    incidentId: string,
    action: IncidentLifecycleAction,
  ) => Promise<ApiError | null>
  /** The listing row, used to paint the header before the detail arrives. */
  readonly summary?: IncidentSummary | null
}
/**
 * Render one incident with its membership, its reasons and its lifecycle controls.
 */
export function IncidentDetailPanel({
  incidentId,
  onBack,
  transition,
  summary = null,
}: IncidentDetailPanelProps) {
  const resource = useIncident(incidentId)
  const [transitionError, setTransitionError] = useState<ApiError | null>(null)
  const [isTransitioning, setIsTransitioning] = useState(false)

  const runTransition = (action: IncidentLifecycleAction) => {
    setTransitionError(null)
    setIsTransitioning(true)
    void transition(incidentId, action).then(failure => {
      setTransitionError(failure)
      setIsTransitioning(false)
    })
  }

  const incident = resource.incident
  // The header falls back to the listing row so the screen is not blank while the
  // detail request is in flight; the detail supersedes it when it arrives.
  const header = incident ?? summary
  const statusColor = header === null
    ? C.muted
    : (INCIDENT_STATUS_COLORS[header.status] ?? C.muted)
  const severityColor = header?.severity == null
    ? C.faint
    : (SEVERITY_COLORS[header.severity] ?? C.warning)

  return (
    <div className="space-y-4 fade-in-up">
      <button onClick={onBack}
        className="flex items-center gap-2 text-sm font-medium transition-colors"
        style={{ color: C.muted }}
        onMouseEnter={e => (e.currentTarget.style.color = C.accent)}
        onMouseLeave={e => (e.currentTarget.style.color = C.muted)}>
        <ArrowLeft size={15} /> Back to Incidents
      </button>

      {resource.error !== null && incident !== null && (
        <RefreshFailureBanner error={resource.error} onRetry={resource.reload} />
      )}

      {resource.isNotFound && <NotFoundPanel incidentId={incidentId} onBack={onBack} />}

      {!resource.isNotFound && incident === null && resource.isInitialLoading && (
        <div className="rounded-2xl border" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <LoadingState label="Loading incident…" minHeight={220} />
        </div>
      )}

      {!resource.isNotFound && incident === null && !resource.isInitialLoading &&
        resource.blockingError !== null && (
          <div className="rounded-2xl border" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <ErrorState error={resource.blockingError} title="Unable to load this incident"
              onRetry={resource.reload} minHeight={220} />
          </div>
        )}

      {/* While the detail is in flight the listing row still paints a header, so
          the operator sees which incident they opened rather than a blank panel. */}
      {incident === null && !resource.isInitialLoading && !resource.isNotFound &&
        resource.error === null && summary !== null && (
          <div className="rounded-2xl border p-6" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="flex items-center gap-2 mb-2">
              <span className="text-xs font-semibold px-2.5 py-1 rounded-full capitalize"
                style={{ backgroundColor: tint(statusColor, 0.12), color: statusColor }}>
                {statusLabel(summary.status)}
              </span>
              <span className="text-xs" style={{ color: C.faint }}>
                Loading the full incident from the backend…
              </span>
            </div>
            <h1 className="text-lg font-bold text-white">{summary.title}</h1>
          </div>
        )}

      {incident !== null && header !== null && (
        <>
          <div className="rounded-2xl border p-6" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-2xl shrink-0"
                style={{ backgroundColor: tint(statusColor, 0.1) }}>
                <Layers size={26} style={{ color: statusColor }} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap mb-1.5">
                  <span className="text-xs font-semibold px-2.5 py-1 rounded-full capitalize"
                    style={{ backgroundColor: tint(statusColor, 0.12), color: statusColor }}>
                    {statusLabel(header.status)}
                  </span>
                  {header.severity !== null && (
                    <span className="text-xs font-semibold px-2.5 py-1 rounded-full capitalize"
                      style={{ backgroundColor: tint(severityColor, 0.12), color: severityColor }}>
                      {header.severity}
                    </span>
                  )}
                  <span className="mono text-xs" style={{ color: C.faint }}>{header.incident_id}</span>
                  {resource.isConnected && (
                    <span className="flex items-center gap-1 text-xs" style={{ color: C.success }}>
                      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: C.success }} />
                      live
                    </span>
                  )}
                </div>
                <h1 className="text-lg font-bold text-white">{header.title}</h1>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-4 mt-6 pt-6 border-t" style={{ borderColor: C.border }}>
              <MetaField label="Events" value={formatCount(header.event_count)} icon={<ShieldAlert size={11} />} />
              <MetaField label="Alerts" value={formatCount(header.alert_count)} icon={<AlertTriangle size={11} />} />
              <MetaField label="Findings" value={formatCount(header.finding_count)} icon={<FileText size={11} />} />
              <MetaField label="Devices" value={formatCount(header.device_ids.length)} icon={<Server size={11} />} />
            </div>

            {incident.dropped_events > 0 && (
              <div className="mt-6 flex items-start gap-2.5 px-4 py-3 rounded-xl border text-xs"
                style={{
                  backgroundColor: tint(C.warning, 0.08),
                  borderColor: tint(C.warning, 0.25),
                  color: C.muted,
                }}>
                <AlertTriangle size={13} style={{ color: C.warning, flexShrink: 0, marginTop: 1 }} />
                <span>
                  {formatCount(incident.dropped_events)} event
                  {incident.dropped_events === 1 ? ' was' : 's were'} counted but not retained,
                  because the incident reached its membership cap. The counts above include
                  them; the reference lists below do not.
                </span>
              </div>
            )}
          </div>

          {/* The three judgement figures, kept apart (M15.17) */}
          <div className="rounded-2xl border p-5" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <h3 className="text-sm font-semibold text-white mb-4">Assessment</h3>
            <IncidentMetrics
              riskScore={header.risk_score}
              riskBand={header.risk_band}
              correlationConfidence={header.correlation_confidence}
              alertConfidence={header.alert_confidence}
            />
          </div>

          {/* Timeline, from stored instants only */}
          <div className="rounded-2xl border overflow-hidden"
            style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="px-5 py-4 border-b" style={{ borderColor: C.border }}>
              <h3 className="text-sm font-semibold text-white">Timeline</h3>
              <p className="text-xs mt-0.5" style={{ color: C.faint }}>
                Instants as M12 recorded them; the span is its own figure.
              </p>
            </div>
            <div className="px-5 py-4">
              <div className="grid grid-cols-4 gap-4">
                <MetaField label="Started" value={formatEpochSeconds(incident.start_time)} icon={<Clock size={11} />} />
                <MetaField label="Last event" value={formatEpochRelative(incident.last_seen)} icon={<Clock size={11} />} />
                <MetaField label="Span" value={formatDurationSeconds(incident.span_seconds)} icon={<Clock size={11} />} />
                <MetaField label="Updated" value={formatTimestamp(incident.updated_at_iso)} icon={<Clock size={11} />} />
              </div>

              <div className="mt-5">
                <div className="h-2.5 rounded-full overflow-hidden"
                  style={{ backgroundColor: C.panel }}>
                  <div className="h-full rounded-full"
                    style={{ width: '100%', backgroundColor: tint(statusColor, 0.4) }} />
                </div>
                <div className="flex items-center justify-between mt-2">
                  <span className="text-xs mono" style={{ color: C.faint }}>
                    {formatTimestamp(incident.start_time_iso)}
                  </span>
                  <span className="text-xs mono" style={{ color: C.faint }}>
                    {formatTimestamp(incident.last_seen_iso)}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-4 gap-4 mt-5 pt-5 border-t" style={{ borderColor: C.border }}>
                <MetaField label="Created" value={formatTimestamp(incident.created_at_iso)} />
                <MetaField label="Recorded events" value={formatCount(incident.event_count)} />
                <MetaField label="Dropped events" value={formatCount(incident.dropped_events)} />
                <MetaField label="Span (seconds)" value={formatCount(incident.span_seconds)} mono />
              </div>
            </div>
          </div>

          {/* Correlated alerts and findings */}
          <div className="grid grid-cols-2 gap-4">
            <div className="rounded-2xl border overflow-hidden"
              style={{ backgroundColor: C.card, borderColor: C.border }}>
              <div className="px-5 py-4 border-b" style={{ borderColor: C.border }}>
                <h3 className="text-sm font-semibold text-white">Related alerts</h3>
                <p className="text-xs mt-0.5" style={{ color: C.faint }}>
                  Open one on the Alerts page to read its evidence.
                </p>
              </div>
              {incident.alert_ids.length === 0 ? (
                <p className="px-5 py-6 text-xs" style={{ color: C.faint }}>
                  No alerts are correlated into this incident.
                </p>
              ) : (
                <ul className="max-h-56 overflow-y-auto divide-y" style={{ borderColor: '#1a2744' }}>
                  {incident.alert_ids.map(alertId => (
                    <li key={alertId} className="px-5 py-2.5 flex items-center gap-2">
                      <AlertTriangle size={12} style={{ color: C.warning }} />
                      <span className="mono text-xs" style={{ color: C.accent }}>alert #{alertId}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <ReferenceList
              title="Related findings"
              icon={<FileText size={12} />}
              ids={incident.finding_ids}
              emptyHint="No findings are correlated into this incident."
            />
          </div>

          {/* Correlation reasons */}
          <div className="rounded-2xl border overflow-hidden"
            style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="px-5 py-4 border-b" style={{ borderColor: C.border }}>
              <h3 className="text-sm font-semibold text-white">Why these events were grouped</h3>
              <p className="text-xs mt-0.5" style={{ color: C.faint }}>
                The correlation engine's own recorded reasons (M12.6).
              </p>
            </div>
            {incident.correlation_reasons.length === 0 ? (
              <p className="px-5 py-6 text-xs" style={{ color: C.faint }}>
                The backend recorded no reason trail for this incident.
              </p>
            ) : (
              <ul className="divide-y" style={{ borderColor: '#1a2744' }}>
                {incident.correlation_reasons.map((reason, index) => (
                  <li key={`${index}-${reason}`} className="px-5 py-3 flex items-start gap-2.5">
                    <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0"
                      style={{ backgroundColor: C.purple }} />
                    <span className="text-xs leading-relaxed" style={{ color: C.muted }}>{reason}</span>
                  </li>
                ))}
              </ul>
            )}

            {incident.correlation_rule_ids.length > 0 && (
              <div className="px-5 py-3 border-t flex items-center gap-2 flex-wrap"
                style={{ borderColor: C.border }}>
                <span className="text-xs" style={{ color: C.faint }}>Correlation rules:</span>
                {incident.correlation_rule_ids.map(ruleId => (
                  <span key={ruleId} className="mono text-xs px-2 py-0.5 rounded-full"
                    style={{ backgroundColor: tint(C.purple, 0.12), color: C.purple }}>
                    {ruleId}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Member references */}
          <div className="grid grid-cols-3 gap-4">
            <ReferenceList
              title="Devices"
              icon={<Server size={12} />}
              ids={incident.device_ids}
              emptyHint="No devices are attached to this incident."
            />
            <ReferenceList
              title="Connections"
              icon={<Network size={12} />}
              ids={incident.connection_ids}
              emptyHint="No conversations are attached to this incident."
            />
            <ReferenceList
              title="Detection rules"
              icon={<Hash size={12} />}
              ids={incident.rule_ids}
              emptyHint="No detector rule contributed to this incident."
            />
          </div>

          {/* Lifecycle */}
          <div className="rounded-2xl border p-5" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <h3 className="text-sm font-semibold text-white mb-3">Lifecycle</h3>
            <IncidentLifecycleActions
              status={incident.status}
              onTransition={runTransition}
              isTransitioning={isTransitioning}
              actionError={transitionError}
            />
          </div>

          <p className="text-xs px-1" style={{ color: C.faint }}>
            A value of {UNKNOWN_TEXT} means the backend recorded no instant for that field.
          </p>
        </>
      )}
    </div>
  )
}
