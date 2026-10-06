/**
 * System — the running process, as the backend reports it (M15.24).
 *
 * This page did not exist before M15. It is built entirely from what M13.22
 * answers, and three things it deliberately does **not** do are the substance of
 * the milestone:
 *
 * * **It does not probe anything.** The frontend does not test the database, time
 *   a request to decide whether the backend is "responsive", or compute a health
 *   grade. Every verdict here was computed by the backend and is rendered as
 *   given. A second opinion in React could only disagree with the process that
 *   owns the facts (M15.24).
 * * **It does not display a database URL.** The payload reports the *dialect*,
 *   which is the part a client can act on, and nothing else. There is no field on
 *   the page for a connection string because there is none in the model.
 * * **It distinguishes "not recorded" from "zero".** `uptime_seconds` is `null`
 *   when startup was never recorded, which is not the same as being up for zero
 *   seconds and must not render as `0s`. The duration formatter returns *unknown*
 *   for `null`, and this page passes the value through rather than defaulting it.
 *
 * The **system channel** is used as M15.27/M15.30 intend: an event is the signal
 * that a system fact changed, so it triggers a re-read of the consolidated status
 * rather than being patched into the view field by field. The events' own payloads
 * are shown as transient banners, because they carry a reason — and a moment —
 * that a status read cannot reconstruct.
 */

import {
  Activity, AlertTriangle, CheckCircle2, Cpu, Database, Globe, Info,
  Layers, RefreshCw, Server, Wifi, WifiOff, XCircle,
} from 'lucide-react'
import {
  AsyncSection, EmptyState, RefreshFailureBanner,
} from '@/components/AsyncState'
import { useSystemStatus } from '@/hooks'
import { C, tint } from '@/lib/tokens'
import {
  UNKNOWN_TEXT, formatCount, formatDurationSeconds, formatRelative, formatTimestamp,
} from '@/lib/format'
import type {
  CaptureEventData, ConnectionPhase, DatabaseStatusEventData, HealthCheck,
  ServiceState, ServiceStatusEventData, SystemHealth, SystemInfo, SystemStatus,
} from '@/types'

// ─── Shared pieces ───────────────────────────────────────────────────────────

/** A coloured pill naming a state the backend reported. */
function VerdictPill({ label, color, icon }: {
  label: string
  color: string
  icon?: React.ReactNode
}) {
  return (
    <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold whitespace-nowrap"
      style={{ backgroundColor: tint(color, 0.12), color }}>
      {icon}
      {label}
    </span>
  )
}

/** A readable label for a channel phase (M15.27). */
function phaseLabel(phase: ConnectionPhase): string {
  switch (phase) {
    case 'connected':
      return 'live'
    case 'connecting':
      return 'connecting'
    case 'reconnecting':
      return 'reconnecting'
    case 'closed':
      return 'stream closed'
    default:
      return 'idle'
  }
}

/** The colour a channel phase reads as. */
function phaseColor(phase: ConnectionPhase): string {
  if (phase === 'connected') return C.success
  if (phase === 'connecting' || phase === 'reconnecting') return C.warning
  return C.dim
}

/** One labelled value, with unknown rendered as unknown. */
function StatLine({ label, value, mono = false, hint }: {
  label: string
  value: string
  mono?: boolean
  hint?: string
}) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1.5 border-b"
      style={{ borderColor: '#1a2744' }} title={hint}>
      <span className="text-xs flex-shrink-0" style={{ color: C.faint }}>{label}</span>
      <span className={`text-xs font-semibold text-white text-right break-all ${mono ? 'mono' : ''}`}>
        {value}
      </span>
    </div>
  )
}

/** A panel with a heading and a sub-line. */
function Panel({ title, sub, icon, right, children }: {
  title: string
  sub?: string
  icon?: React.ReactNode
  right?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div className="rounded-2xl border p-5" style={{ backgroundColor: C.card, borderColor: C.border }}>
      <div className="flex items-start justify-between gap-3 mb-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            {icon}
            <h2 className="text-sm font-semibold text-white">{title}</h2>
          </div>
          {sub && <p className="text-xs mt-0.5" style={{ color: C.faint }}>{sub}</p>}
        </div>
        {right}
      </div>
      {children}
    </div>
  )
}

/** One health probe's verdict. */
function HealthRow({ check }: { check: HealthCheck }) {
  const color = check.ok ? C.success : C.danger
  return (
    <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-xl"
      style={{ backgroundColor: C.panel }}>
      {check.ok
        ? <CheckCircle2 size={14} style={{ color, flexShrink: 0, marginTop: 1 }} />
        : <XCircle size={14} style={{ color, flexShrink: 0, marginTop: 1 }} />}
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="mono text-xs font-semibold text-white">{check.name}</span>
          <span className="text-xs font-medium" style={{ color }}>
            {check.ok ? 'ok' : 'failed'}
          </span>
        </div>
        <p className="text-xs mt-0.5" style={{ color: C.muted }}>{check.detail}</p>
      </div>
    </div>
  )
}

/** One pipeline stage and whether it is switched on and attached. */
function ServiceRow({ service }: { service: ServiceState }) {
  // Three readings, and they are not interchangeable: a stage can be enabled by
  // configuration and still not be attached to the running pipeline, and
  // `attached: null` means the backend could not say — which is not "false".
  const attachedLabel = service.attached === null
    ? 'not reported'
    : service.attached
      ? 'attached'
      : 'not attached'
  const color = service.attached === null ? C.dim : service.attached ? C.success : C.warning
  return (
    <tr className="border-b" style={{ borderColor: '#1a2744' }}>
      <td className="py-2.5 pr-4 pl-1">
        <span className="mono text-xs text-white">{service.name}</span>
      </td>
      <td className="py-2.5 pr-4 text-xs" style={{ color: service.enabled ? C.success : C.dim }}>
        {service.enabled ? 'enabled' : 'disabled'}
      </td>
      <td className="py-2.5 pr-1 text-xs" style={{ color }}>
        {attachedLabel}
      </td>
    </tr>
  )
}

/**
 * The transient event banners.
 *
 * Each carries something the consolidated read cannot reconstruct: the *reason* a
 * capture failed, or the moment a dependency changed. They are transient facts,
 * cleared on reconnect, rather than a second copy of the status.
 */
function EventBanners({ capture, database, service }: {
  capture: CaptureEventData | null
  database: DatabaseStatusEventData | null
  service: ServiceStatusEventData | null
}) {
  if (capture === null && database === null && service === null) return null
  return (
    <div className="space-y-2">
      {capture !== null && (
        <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl border"
          style={{
            backgroundColor: tint(capture.status === 'error' ? C.danger : C.info, 0.07),
            borderColor: tint(capture.status === 'error' ? C.danger : C.info, 0.28),
          }}>
          <Activity size={13}
            style={{ color: capture.status === 'error' ? C.danger : C.info, flexShrink: 0, marginTop: 1 }} />
          <div className="min-w-0">
            <p className="text-xs font-semibold"
              style={{ color: capture.status === 'error' ? C.danger : C.info }}>
              Capture {capture.status}
              {capture.interface === null ? '' : ` on ${capture.interface}`}
            </p>
            <p className="text-xs mt-0.5" style={{ color: C.muted }}>
              {formatCount(capture.packet_count)} packets counted at the time of the event.
              {capture.reason === undefined ? '' : ` ${capture.reason}`}
            </p>
          </div>
        </div>
      )}

      {database !== null && (
        <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl border"
          style={{
            backgroundColor: tint(database.reachable ? C.success : C.danger, 0.07),
            borderColor: tint(database.reachable ? C.success : C.danger, 0.28),
          }}>
          {database.reachable
            ? <Database size={13} style={{ color: C.success, flexShrink: 0, marginTop: 1 }} />
            : <AlertTriangle size={13} style={{ color: C.danger, flexShrink: 0, marginTop: 1 }} />}
          <p className="text-xs" style={{ color: C.muted }}>
            <span className="font-semibold" style={{ color: database.reachable ? C.success : C.danger }}>
              Database {database.reachable ? 'reachable' : 'unreachable'}
            </span>
            {' — '}
            <span className="mono">{database.dialect}</span>. The API reports the dialect and never a
            connection string.
          </p>
        </div>
      )}

      {service !== null && (
        <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl border"
          style={{ backgroundColor: tint(C.purple, 0.07), borderColor: tint(C.purple, 0.28) }}>
          <Layers size={13} style={{ color: C.purple, flexShrink: 0, marginTop: 1 }} />
          <p className="text-xs" style={{ color: C.muted }}>
            <span className="mono font-semibold" style={{ color: C.purple }}>{service.service}</span>
            {' changed to '}
            <span className="font-semibold text-white">{service.state}</span>
            {service.detail === undefined ? '' : ` — ${service.detail}`}
          </p>
        </div>
      )}
    </div>
  )
}
// ─── Page ────────────────────────────────────────────────────────────────────

export default function System() {
  const resource = useSystemStatus()

  const status: SystemStatus | null = resource.status
  const health: SystemHealth | null = resource.health
  const info: SystemInfo | null = resource.info

  // The verdict is the backend's word for it, and "unknown" is kept distinct from
  // both outcomes: before health has been read, the page says so rather than
  // defaulting to a reassuring green (M15.24).
  const verdictColor = resource.isHealthy === null
    ? C.dim
    : resource.isHealthy ? C.success : C.warning
  const verdictLabel = resource.isHealthy === null
    ? 'health unknown'
    : resource.isHealthy ? 'healthy' : 'degraded'

  return (
    <div className="space-y-4">
      {/* Header — identity, the backend's verdict, and the live channel. */}
      <div className="rounded-2xl border p-5" style={{ backgroundColor: C.card, borderColor: C.border }}>
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1.5">
              <Server size={15} style={{ color: C.accent }} />
              <h1 className="text-sm font-semibold text-white">System</h1>
            </div>
            <p className="text-xs max-w-2xl" style={{ color: C.muted }}>
              What the running process reports about itself: identity, every health probe, capture
              state, database reachability, the pipeline stages and basic runtime facts. Nothing here
              is measured by this page — the backend owns every verdict.
            </p>
            {status !== null && (
              <p className="text-xs mt-1.5" style={{ color: C.faint }}>
                Response generated {formatRelative(status.runtime.generated_at)} ·{' '}
                <span className="mono">{status.info.app_name} {status.info.app_version}</span> ·{' '}
                {status.info.environment}
              </p>
            )}
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <VerdictPill
              label={verdictLabel}
              color={verdictColor}
              icon={resource.isHealthy === true
                ? <CheckCircle2 size={11} />
                : resource.isHealthy === false
                  ? <AlertTriangle size={11} />
                  : <Info size={11} />}
            />
            <VerdictPill
              label={`system channel ${phaseLabel(resource.phase)}`}
              color={phaseColor(resource.phase)}
              icon={resource.phase === 'connected'
                ? <Wifi size={11} />
                : <WifiOff size={11} />}
            />
            <button onClick={resource.reload} disabled={resource.isLoading}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border disabled:opacity-50"
              style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
              <RefreshCw size={12} className={resource.isLoading ? 'animate-spin' : undefined} />
              Refresh
            </button>
          </div>
        </div>
      </div>

      <EventBanners
        capture={resource.lastCaptureEvent}
        database={resource.lastDatabaseEvent}
        service={resource.lastServiceEvent}
      />

      {resource.isConnected && resource.lastEventAt !== null && (
        <p className="text-xs px-1" style={{ color: C.faint }}>
          Following <span className="mono">/ws/system</span>. Last event{' '}
          {formatRelative(new Date(resource.lastEventAt).toISOString())}. Each event re-reads the
          consolidated status rather than being merged into it, because an event carries only the
          fields that changed.
        </p>
      )}

      {resource.error !== null && status !== null && (
        <RefreshFailureBanner error={resource.error} onRetry={resource.reload} />
      )}

      <AsyncSection
        isInitialLoading={resource.isInitialLoading}
        error={resource.blockingError}
        isEmpty={false}
        loadingLabel="Reading system status…"
        onRetry={resource.reload}
        minHeight={280}
      >
        <div className="space-y-4">
          {/* Health — the probes, verbatim. */}
          <Panel
            title="Health"
            sub="One verdict per dependency, computed by the backend. This page probes nothing itself."
            icon={resource.isHealthy === false
              ? <AlertTriangle size={14} style={{ color: C.warning }} />
              : <CheckCircle2 size={14} style={{ color: C.success }} />}
            right={health === null
              ? undefined
              : <VerdictPill label={health.status} color={verdictColor} />}>
            {health === null ? (
              resource.healthError !== null ? (
                <p className="text-xs" style={{ color: C.muted }}>
                  The health endpoint did not answer: {resource.healthError.userMessage}
                </p>
              ) : (
                <EmptyState title="No health verdict" minHeight={120}
                  hint="The backend reported no probe result." />
              )
            ) : (
              <div className="space-y-2">
                {health.checks.map(check => (
                  <HealthRow key={check.name} check={check} />
                ))}
              </div>
            )}
          </Panel>

          <div className="grid grid-cols-2 gap-4">
            {/* Capture — the M4 state, as the system endpoint reports it. */}
            {status !== null && (
              <Panel
                title="Capture"
                sub="The M4 capture session and how many packets it has processed."
                icon={<Activity size={14} style={{ color: status.capture.running ? C.success : C.dim }} />}
                right={<VerdictPill
                  label={status.capture.status}
                  color={status.capture.running ? C.success : C.dim}
                />}>
                <StatLine label="Interface"
                  value={status.capture.interface ?? UNKNOWN_TEXT} mono />
                <StatLine label="Packets captured"
                  value={formatCount(status.capture.packet_count)} mono />
                <StatLine label="Packets processed"
                  value={formatCount(status.capture.processed_packet_count)} mono
                  hint="Read from the same status read as the capture counts, so the two describe one instant." />
                <div className="mt-4">
                  <p className="text-xs mb-2" style={{ color: C.faint }}>Error counts by kind</p>
                  {Object.keys(status.capture.error_counts).length === 0 ? (
                    <p className="text-xs" style={{ color: C.muted }}>
                      No capture error recorded.
                    </p>
                  ) : (
                    <div className="flex items-center gap-2 flex-wrap">
                      {Object.entries(status.capture.error_counts).map(([kind, count]) => (
                        <span key={kind} className="flex items-center gap-1.5 px-2 py-1 rounded-lg text-xs"
                          style={{ backgroundColor: tint(C.danger, 0.1), color: C.danger }}>
                          {kind}
                          <span className="mono font-semibold">{formatCount(count)}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </Panel>
            )}

            {/* Database — reachability and dialect, never a connection string. */}
            {status !== null && (
              <Panel
                title="Database"
                sub="Reachability and engine family. The API never returns a connection string."
                icon={<Database size={14}
                  style={{ color: status.database.reachable ? C.success : C.danger }} />}
                right={<VerdictPill
                  label={status.database.reachable ? 'reachable' : 'unreachable'}
                  color={status.database.reachable ? C.success : C.danger}
                />}>
                <StatLine label="Dialect" value={status.database.dialect} mono
                  hint="The engine family, which is the part a client can act on." />
                <StatLine label="Reachable" value={status.database.reachable ? 'yes' : 'no'} />
                <p className="text-xs mt-4" style={{ color: C.faint }}>
                  The connection string is withheld by the API, so it cannot appear here: it is a
                  path or a credential-bearing DSN, and publishing it would leak the deployment's
                  layout. The dialect is reported instead.
                </p>
              </Panel>
            )}
          </div>

          {/* Pipeline stages. */}
          {status !== null && (
            <Panel
              title="Pipeline stages"
              sub="Each stage the running application holds, whether it is switched on, and whether it is attached."
              icon={<Layers size={14} style={{ color: C.purple }} />}>
              {status.services.length === 0 ? (
                <EmptyState title="No pipeline stage reported" minHeight={120}
                  hint="The backend listed no service." icon={<Layers size={24} />} />
              ) : (
                <div className="overflow-x-auto -mx-1">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b" style={{ borderColor: C.border }}>
                        <th className="text-left pl-1 py-2 pr-4 text-xs font-medium" style={{ color: C.dim }}>Stage</th>
                        <th className="text-left py-2 pr-4 text-xs font-medium" style={{ color: C.dim }}>Configured</th>
                        <th className="text-left py-2 pr-1 text-xs font-medium" style={{ color: C.dim }}>Attached</th>
                      </tr>
                    </thead>
                    <tbody>
                      {status.services.map(service => (
                        <ServiceRow key={service.name} service={service} />
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>
          )}

          <div className="grid grid-cols-2 gap-4">
            {/* Identity — read even when a dependency is down. */}
            {info !== null && (
              <Panel
                title="Application"
                sub="Identity and environment. This endpoint touches no dependency, so it answers even when the database does not."
                icon={<Globe size={14} style={{ color: C.accent }} />}>
                <StatLine label="Name" value={info.app_name} />
                <StatLine label="Version" value={info.app_version} mono />
                <StatLine label="Environment" value={info.environment} />
                <StatLine label="API version" value={info.api_version} mono />
                <StatLine label="Timezone" value={info.timezone} mono />
                <StatLine label="Platform" value={info.platform} mono />
                <StatLine label="Registered routes"
                  value={info.registered_route_count === null
                    ? UNKNOWN_TEXT
                    : formatCount(info.registered_route_count)}
                  mono
                  hint="Null when the backend could not count its own routes — which is not zero routes." />
                <div className="flex items-center gap-3 mt-3 flex-wrap">
                  {info.docs_url !== null && (
                    <a href={info.docs_url} target="_blank" rel="noreferrer"
                      className="text-xs font-medium" style={{ color: C.accent }}>
                      API docs ↗
                    </a>
                  )}
                  {info.openapi_url !== null && (
                    <a href={info.openapi_url} target="_blank" rel="noreferrer"
                      className="text-xs font-medium" style={{ color: C.accent }}>
                      OpenAPI schema ↗
                    </a>
                  )}
                </div>
              </Panel>
            )}

            {/* Runtime — process facts, with "not recorded" kept distinct from zero. */}
            {status !== null && (
              <Panel
                title="Runtime"
                sub="Facts about the process itself."
                icon={<Cpu size={14} style={{ color: C.info }} />}>
                <StatLine
                  label="Uptime"
                  value={formatDurationSeconds(status.runtime.uptime_seconds)}
                  mono
                  hint="Unknown when startup was never recorded — which is not the same as being up for zero seconds." />
                {status.runtime.uptime_seconds === null && (
                  <p className="text-xs mt-1.5" style={{ color: C.faint }}>
                    The backend did not record a startup instant, so uptime cannot be stated. It is
                    shown as unknown rather than as <span className="mono">0s</span>.
                  </p>
                )}
                <StatLine label="Started at" value={formatTimestamp(status.runtime.started_at)} mono />
                <StatLine label="Response generated" value={formatTimestamp(status.runtime.generated_at)} mono />
                <StatLine label="Python" value={status.runtime.python_version} mono />
                <StatLine label="Process id" value={String(status.runtime.pid)} mono />
              </Panel>
            )}
          </div>

          <p className="text-xs px-1" style={{ color: C.faint }}>
            A value of {UNKNOWN_TEXT} means the backend reported nothing for that field, which is a
            different statement from a zero. The system channel announces that one of these facts
            changed; it is not a stream of measurements, so this page re-reads the status when an
            event arrives instead of patching the view from the event's own fields.
          </p>
        </div>
      </AsyncSection>
    </div>
  )
}
