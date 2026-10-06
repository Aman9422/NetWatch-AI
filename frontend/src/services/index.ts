/**
 * The service layer's public surface (M15.4).
 *
 * Every hook and page imports from `@/services` rather than reaching into a
 * module by path. Two reasons:
 *
 * * **One import path to review.** "Which endpoint does this page touch?" is
 *   answerable by reading its imports, and the set of things a component may do
 *   to the backend is a list in one file rather than a convention.
 * * **No raw `fetch` in a component.** M15.4 forbids a page calling `fetch`
 *   directly, and the practical way to enforce that is for the client, the
 *   envelope and the error model to be the only way in.
 *
 * Types are re-exported with `export type`, because `isolatedModules` is on and
 * a plain re-export of a type would leave a runtime binding for something that
 * does not exist.
 */

// ── Transport ────────────────────────────────────────────────────────────────

export {
  buildQueryString,
  buildUrl,
  apiRequest,
  apiGet,
  apiPost,
  apiPut,
  CLIENT_FALLBACK_MESSAGE,
} from './client'
export type { BodyRequestOptions, QueryParams, QueryValue, RequestOptions } from './client'

export {
  ApiError,
  GENERIC_MESSAGE,
  NETWORK_MESSAGE,
  TIMEOUT_MESSAGE,
  NOT_IMPLEMENTED_MESSAGE,
  isApiError,
  kindForStatus,
  malformedResponseError,
  messageFor,
  messageForKind,
  networkError,
  toApiError,
  toUserMessage,
} from './errors'
export type { ApiErrorKind, ApiErrorOptions } from './errors'

export {
  API_ROOT,
  AlertPaths,
  AnalyticsPaths,
  BaselinePaths,
  CapturePaths,
  ConnectionPaths,
  DashboardPaths,
  DetectionPaths,
  DevicePaths,
  EvidencePaths,
  IncidentPaths,
  NotificationPaths,
  PacketPaths,
  ReportPaths,
  SettingPaths,
  StatisticsPaths,
  SystemPaths,
} from './endpoints'

export {
  DEFAULT_PAGE_LIMIT,
  MAX_PAGE_LIMIT,
  clampLimit,
  clampOffset,
  toQueryParams,
  withPageWindow,
} from './query'
export type { PageWindow } from './query'

// ── Capture and packets ──────────────────────────────────────────────────────

export {
  fetchCaptureStatus,
  fetchInterfaces,
  fetchSelectedInterface,
  selectInterface,
  startCapture,
  stopCapture,
} from './capture'

export {
  fetchStoredPacket,
  fetchStoredPackets,
  runPacketRetentionCleanup,
} from './packets'

export {
  DEFAULT_RECENT_FINDINGS,
  MAX_RECENT_FINDINGS,
  fetchDashboardSummary,
  fetchProtocolStatistics,
  fetchTopPorts,
  fetchTopTalkers,
  fetchTrafficSnapshot,
} from './dashboard'

// ── Observed entities ────────────────────────────────────────────────────────

export { fetchActiveDevices, fetchDevice, fetchDevices } from './devices'

export {
  expireConnections,
  fetchActiveConnections,
  fetchConnection,
  fetchConnections,
} from './connections'

// ── Detection, alerts, incidents, evidence ───────────────────────────────────

export {
  fetchDetection,
  fetchDetectionRules,
  fetchDetections,
  resetDetections,
} from './detections'

export {
  applyAlertLifecycle,
  fetchAlert,
  fetchAlertDiagnostics,
  fetchAlertEvidence,
  fetchAlertSummary,
  fetchAlerts,
  setAlertStatus,
} from './alerts'

export { fetchEvidence } from './evidence'

export {
  applyIncidentLifecycle,
  fetchIncident,
  fetchIncidents,
  fetchOpenIncidents,
} from './incidents'

// ── Derived views and operational surface ────────────────────────────────────

export {
  DEFAULT_ANALYTICS_LIMIT,
  analyticsQueryParams,
  fetchAnalyticsBundle,
  fetchAnalyticsConnections,
  fetchAnalyticsDevices,
  fetchAnalyticsProtocols,
  fetchAnalyticsThreats,
  fetchAnalyticsTraffic,
} from './analytics'
export type {
  AnalyticsBundle,
  AnalyticsBundleOptions,
  AnalyticsSectionFailure,
} from './analytics'

export { fetchReport, fetchReports, requestReportGeneration } from './reports'
export type { ReportQuery } from './reports'

export { fetchSetting, fetchSettings, requiresRestart, updateSettings } from './settings'
export type { SettingValues, WritableSettingValue } from './settings'

export {
  SYSTEM_STATUS_DEGRADED,
  SYSTEM_STATUS_HEALTHY,
  fetchSystemHealth,
  fetchSystemInfo,
  fetchSystemStatus,
  hasUptime,
  isSystemHealthy,
} from './system'

export { fetchNotification, fetchNotifications, fetchUnreadCount } from './notifications'

// ── Real-time ────────────────────────────────────────────────────────────────

export {
  DEFAULT_BACKOFF,
  DEFAULT_BACKOFF_BASE_MS,
  DEFAULT_BACKOFF_FACTOR,
  DEFAULT_BACKOFF_JITTER,
  DEFAULT_BACKOFF_MAX_MS,
  DEFAULT_DEDUP_CAPACITY,
  DEFAULT_MAX_RECONNECT_ATTEMPTS,
  ChannelHub,
  ChannelSocket,
  EventIdTracker,
  backoffDelay,
  channelHub,
} from './websocket'
export type {
  BackoffOptions,
  ChannelSocketHandlers,
  ChannelSocketOptions,
  ChannelSubscriber,
  ChannelSubscription,
  TimerHandle,
} from './websocket'
