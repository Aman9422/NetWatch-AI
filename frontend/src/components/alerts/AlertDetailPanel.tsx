/**
 * One alert, in full (M15.14/M15.16).
 *
 * The detail view is the listing row plus its evidence, and it keeps three
 * quantities apart that are easy to conflate and wrong to merge (M12.16):
 *
 * * **severity** — how serious the behaviour is judged to be;
 * * **confidence** — how strong the evidence for *this* alert is, a `0..1` ratio;
 * * **evidence count** — how many records support it.
 *
 * Confidence is rendered by {@link formatConfidence}, the one place the `0..1`
 * ratio becomes a percentage; showing `0.72` as `0.72%` is the bug that function
 * exists to prevent.
 *
 * Live updates come through {@link useAlertDetail}: a lifecycle event for this
 * alert patches the header immediately and triggers a re-read to reconcile the
 * evidence beside it, because the event carries the alert and not its evidence.
 *
 * A deleted alert is a case in its own right. `GET /alerts/{id}` answers `404`,
 * and this panel says "this alert no longer exists" rather than rendering an empty
 * shell — a distinction that matters when alerts are removed by retention while an
 * operator is looking at one.
 */

import { useState } from 'react'
import {
  ArrowLeft, ShieldAlert, Activity, Clock, Hash, FileText, Server, Network,
  SearchX,
} from 'lucide-react'
import { ErrorState, LoadingState, RefreshFailureBanner } from '@/components/AsyncState'
import { useAlertDetail } from '@/hooks'
import { C, tint, SEVERITY_COLORS, ALERT_STATUS_COLORS } from '@/lib/tokens'
import { formatConfidence, formatTimestamp, formatRelative, UNKNOWN_TEXT } from '@/lib/format'
import type { AlertLifecycleAction, AlertSeverity, AlertStatus } from '@/types'
import type { ApiError } from '@/services'
import { AlertLifecycleActions } from './AlertLifecycleActions'
import { EvidenceList } from './EvidenceList'

/** A readable label for a lifecycle state. */
function statusLabel(status: AlertStatus): string {
  return status === 'false_positive' ? 'False positive' : status.charAt(0).toUpperCase() + status.slice(1)
}

/** A readable label for a severity. */
function severityLabel(severity: AlertSeverity): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1)
}

/** A small coloured pill. */
function Pill({ label, color }: { label: string; color: string }) {
  return (
    <span className="text-xs font-semibold px-2.5 py-1 rounded-full"
      style={{ backgroundColor: tint(color, 0.12), color }}>
      {label}
    </span>
  )
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
      <div className={`text-sm font-semibold text-white ${mono ? 'mono' : ''} break-words`}>{value}</div>
    </div>
  )
}

/** A four-column block of labelled values. */
function MetaGrid({ children }: { children: React.ReactNode }) {
  return <div className="grid grid-cols-4 gap-4">{children}</div>
}

/** The panel shown when the alert a route names no longer exists. */
function NotFoundPanel({ alertId, onBack }: { alertId: number; onBack: () => void }) {
  return (
    <div className="rounded-2xl border flex flex-col items-center justify-center gap-3 text-center px-6 py-14"
      style={{ backgroundColor: C.card, borderColor: C.border }}>
      <SearchX size={30} style={{ color: C.border }} />
      <p className="text-sm font-medium text-white">Alert #{alertId} no longer exists</p>
      <p className="text-xs max-w-md" style={{ color: C.muted }}>
        The backend answered <span className="mono">404</span> for this alert. Alerts can be
        removed by retention rules after the operator has left the page open, so this is the
        alert being gone rather than the request having failed.
      </p>
      <button onClick={onBack}
        className="mt-1 flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold"
        style={{ backgroundColor: tint(C.accent, 0.15), color: C.accent }}>
        <ArrowLeft size={12} /> Back to Alerts
      </button>
    </div>
  )
}

/** What {@link AlertDetailPanel} takes. */
export interface AlertDetailPanelProps {
  readonly alertId: number
  readonly onBack: () => void
  /** Ask the backend to move the alert. Resolves the refusal, or `null`. */
  readonly transition: (alertId: number, action: AlertLifecycleAction) => Promise<ApiError | null>
}

/**
 * Render one alert with its evidence and its lifecycle controls.
 */
export function AlertDetailPanel({ alertId, onBack, transition }: AlertDetailPanelProps) {
  const resource = useAlertDetail(alertId)
  const [transitionError, setTransitionError] = useState<ApiError | null>(null)
  const [isTransitioning, setIsTransitioning] = useState(false)

  const runTransition = (action: AlertLifecycleAction) => {
    setTransitionError(null)
    setIsTransitioning(true)
    void transition(alertId, action).then(failure => {
      setTransitionError(failure)
      setIsTransitioning(false)
    })
  }

  const alert = resource.alert
  const detailError = resource.error

  return (
    <div className="space-y-4 fade-in-up">
      <button onClick={onBack}
        className="flex items-center gap-2 text-sm font-medium transition-colors"
        style={{ color: C.muted }}
        onMouseEnter={e => (e.currentTarget.style.color = C.accent)}
        onMouseLeave={e => (e.currentTarget.style.color = C.muted)}>
        <ArrowLeft size={15} /> Back to Alerts
      </button>

      {detailError !== null && alert !== null && (
        <RefreshFailureBanner error={detailError} onRetry={resource.reload} />
      )}

      {resource.isInitialLoading && (
        <div className="rounded-2xl border" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <LoadingState label="Loading alert…" minHeight={220} />
        </div>
      )}

      {!resource.isInitialLoading && resource.isNotFound && (
        <NotFoundPanel alertId={alertId} onBack={onBack} />
      )}

      {!resource.isInitialLoading && !resource.isNotFound && alert === null && detailError !== null && (
        <div className="rounded-2xl border" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <ErrorState error={detailError} title="Unable to load this alert"
            onRetry={resource.reload} minHeight={220} />
        </div>
      )}

      {alert !== null && (
        <>
          <div className="rounded-2xl border p-6" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-2xl flex-shrink-0"
                style={{ backgroundColor: tint(SEVERITY_COLORS[alert.severity] ?? C.warning, 0.1) }}>
                <ShieldAlert size={26} style={{ color: SEVERITY_COLORS[alert.severity] ?? C.warning }} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap mb-1.5">
                  <Pill label={severityLabel(alert.severity)}
                    color={SEVERITY_COLORS[alert.severity] ?? C.warning} />
                  <Pill label={statusLabel(alert.status)}
                    color={ALERT_STATUS_COLORS[alert.status] ?? C.muted} />
                  <span className="mono text-xs" style={{ color: C.faint }}>alert #{alert.alert_id}</span>
                  {resource.isConnected && (
                    <span className="flex items-center gap-1 text-xs" style={{ color: C.success }}>
                      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: C.success }} />
                      live
                    </span>
                  )}
                </div>
                <h1 className="text-lg font-bold text-white mb-2">{alert.title}</h1>
                <p className="text-sm leading-relaxed" style={{ color: C.muted }}>{alert.description}</p>
              </div>
            </div>

            <div className="mt-6 pt-6 border-t" style={{ borderColor: C.border }}>
              <MetaGrid>
                <MetaField label="Rule" value={alert.rule_id} mono icon={<Hash size={11} />} />
                <MetaField label="Confidence" value={formatConfidence(alert.confidence)}
                  icon={<Activity size={11} />} />
                <MetaField label="Evidence"
                  value={`${alert.evidence_count} record${alert.evidence_count === 1 ? '' : 's'}`}
                  icon={<FileText size={11} />} />
                <MetaField label="First raised" value={formatTimestamp(alert.created_at)}
                  icon={<Clock size={11} />} />
              </MetaGrid>
            </div>

            <div className="mt-6">
              <MetaGrid>
                <MetaField label="Source" value={alert.source_ip ?? UNKNOWN_TEXT} mono icon={<Server size={11} />} />
                <MetaField label="Destination" value={alert.destination_ip ?? UNKNOWN_TEXT} mono icon={<Server size={11} />} />
                <MetaField label="Protocol" value={alert.protocol ?? UNKNOWN_TEXT} mono icon={<Network size={11} />} />
                <MetaField label="Last updated" value={formatRelative(alert.updated_at)} icon={<Clock size={11} />} />
              </MetaGrid>
            </div>

            {alert.resolved_at !== null && (
              <div className="mt-6 pt-6 border-t" style={{ borderColor: C.border }}>
                <MetaGrid>
                  <MetaField label="Closed at" value={formatTimestamp(alert.resolved_at)} icon={<Clock size={11} />} />
                </MetaGrid>
              </div>
            )}

            {(alert.source_device_id !== null || alert.destination_device_id !== null ||
              alert.connection_id !== null || alert.finding_id !== null) && (
              <div className="mt-6 pt-6 border-t" style={{ borderColor: C.border }}>
                <p className="text-xs mb-3" style={{ color: C.faint }}>
                  References — the records this alert was derived from
                </p>
                <div className="grid grid-cols-2 gap-4">
                  {alert.finding_id !== null && (
                    <MetaField label="Raised by finding" value={alert.finding_id} mono />
                  )}
                  {alert.connection_id !== null && (
                    <MetaField label="Connection" value={alert.connection_id} mono />
                  )}
                  {alert.source_device_id !== null && (
                    <MetaField label="Source device" value={alert.source_device_id} mono />
                  )}
                  {alert.destination_device_id !== null && (
                    <MetaField label="Destination device" value={alert.destination_device_id} mono />
                  )}
                </div>
              </div>
            )}

            {alert.correlation_key !== null && (
              <div className="mt-6 pt-6 border-t" style={{ borderColor: C.border }}>
                <MetaField label="Correlation key" value={alert.correlation_key} mono />
                <p className="text-xs mt-2" style={{ color: C.faint }}>
                  M12 groups alerts sharing this key into an incident; the grouping itself is
                  the correlation engine's decision, not this page's.
                </p>
              </div>
            )}
          </div>

          <div className="rounded-2xl border p-5" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <h3 className="text-sm font-semibold text-white mb-3">Lifecycle</h3>
            <AlertLifecycleActions
              alert={alert}
              onTransition={runTransition}
              isTransitioning={isTransitioning}
              actionError={transitionError}
            />
          </div>

          <EvidenceList alertId={alert.alert_id} />
        </>
      )}
    </div>
  )
}
