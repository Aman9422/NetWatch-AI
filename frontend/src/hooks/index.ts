/**
 * The hook layer's public surface (M15.33).
 *
 * Every page imports the data-access it needs from `@/hooks` rather than reaching
 * into a module by path, for the same reason the service layer has a barrel
 * (`@/services`): "what does this page read?" is answerable from one import list,
 * and the set of hooks a component may use is a file rather than a convention.
 *
 * The two primitives — {@link useAsyncResource} and {@link useAction} — are
 * exported beside the feature hooks because a page may legitimately need them
 * directly for a one-off read or write that has no dedicated hook, and re-deriving
 * the loading/error contract by hand is exactly what they exist to prevent.
 *
 * Types are re-exported with `export type`, because `isolatedModules` is on and a
 * plain re-export of a type would leave a runtime binding for something that does
 * not exist.
 */

// ── Primitives ───────────────────────────────────────────────────────────────

export { useAsyncResource } from './useAsyncResource'
export type { AsyncResource, AsyncResourceOptions } from './useAsyncResource'

export { useAction } from './useAction'
export type { ActionResult, ActionResource } from './useAction'

export {
  MIN_BOUNDED_CAPACITY,
  useBoundedKeyedList,
  useBoundedList,
} from './useBoundedList'
export type { BoundedKeyedList, BoundedList } from './useBoundedList'

export { useChannelEvents } from './useChannelEvents'
export type { ChannelEventsOptions, ChannelEventsResult } from './useChannelEvents'

// ── Capture and live traffic ─────────────────────────────────────────────────

export {
  NO_INTERFACE_SELECTED_CODE,
  captureStatusFromPayload,
  readSelectedInterface,
  useCapture,
} from './useCapture'
export type { CaptureOptions, CaptureResource } from './useCapture'

export {
  LIVE_PACKET_CAPACITY,
  TRAFFIC_SNAPSHOT_POLL_MS,
  useLiveTraffic,
} from './useLiveTraffic'
export type { LiveTrafficOptions, LiveTrafficResource } from './useLiveTraffic'

// ── Dashboard ────────────────────────────────────────────────────────────────

export { useDashboard } from './useDashboard'
export type { DashboardOptions, DashboardResource } from './useDashboard'

// ── Observed entities ────────────────────────────────────────────────────────

export { useDevices } from './useDevices'
export type { DeviceListOptions, DeviceListResource } from './useDevices'

export { useConnections } from './useConnections'
export type { ConnectionListOptions, ConnectionListResource } from './useConnections'

export { useConnection } from './useConnection'
export type { ConnectionDetailResource } from './useConnection'

// ── Detection, alerts, incidents, evidence ───────────────────────────────────

export { useDetections } from './useDetections'
export type { DetectionListOptions, DetectionListResource } from './useDetections'

export { useDetection } from './useDetection'
export type { DetectionDetailResource } from './useDetection'

export { LIVE_ALERT_CAPACITY, alertKey, useAlerts } from './useAlerts'
export type { AlertListOptions, AlertListResource } from './useAlerts'

export { useAlertDetail } from './useAlertDetail'
export type { AlertDetailResource } from './useAlertDetail'

export {
  EVIDENCE_TYPE_ORDER,
  isEvidenceType,
  useAlertEvidence,
} from './useAlertEvidence'
export type { AlertEvidenceResource } from './useAlertEvidence'

export { useEvidence } from './useEvidence'
export type { EvidenceResource } from './useEvidence'

export { LIVE_INCIDENT_CAPACITY, incidentKey, useIncidents } from './useIncidents'
export type { IncidentListOptions, IncidentListResource } from './useIncidents'

export { useIncident } from './useIncident'
export type { IncidentDetailResource } from './useIncident'

// ── Derived views and operational surface ────────────────────────────────────

export { useAnalytics } from './useAnalytics'
export type { AnalyticsOptions, AnalyticsResource } from './useAnalytics'

export { useReports } from './useReports'
export type { ReportOptions, ReportResource } from './useReports'

export { useSettings } from './useSettings'
export type { SettingsResource, WritableSettingValue } from './useSettings'

export { useSystemStatus } from './useSystemStatus'
export type { SystemResource } from './useSystemStatus'

export { useNotifications } from './useNotifications'
export type { NotificationOptions, NotificationResource } from './useNotifications'
