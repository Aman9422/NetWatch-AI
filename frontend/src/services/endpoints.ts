/**
 * Every REST path the frontend calls (M15.4).
 *
 * The paths are written down once, here, rather than inline in each service. That
 * is not ceremony: the backend mounts each router under its own prefix in
 * `app/api/v1/__init__.py`, so a path is decided in one place server-side, and
 * this file is the single corresponding place client-side. A typo is then a wrong
 * constant rather than a wrong string buried in a function.
 *
 * Builders that need an id are functions rather than templates with `{}`, so an id
 * is interpolated with the caller's own type and cannot be forgotten.
 *
 * Note what is *not* here: no `/ws/...` path. A socket path belongs to the
 * WebSocket service, which is a different transport with its own base URL.
 */

/** Base path of every resource below, relative to the configured API base URL. */
export const API_ROOT = '/api/v1'

/** Capture surface (M4). */
export const CapturePaths = {
  interfaces: '/capture/interfaces',
  interface: '/capture/interface',
  status: '/capture/status',
  start: '/capture/start',
  stop: '/capture/stop',
} as const

/** Consolidated dashboard summary (M13.19). */
export const DashboardPaths = {
  summary: '/dashboard/summary',
} as const

/** Tracked devices (M8/M13.10). */
export const DevicePaths = {
  list: '/devices',
  detail: (deviceId: string): string => `/devices/${encodeURIComponent(deviceId)}`,
} as const

/** Tracked conversations (M9/M13.11). */
export const ConnectionPaths = {
  list: '/connections',
  active: '/connections/active',
  expire: '/connections/expire',
  /**
   * The id may contain `|` and `:`, so it is encoded as a single path segment.
   * The backend captures it with `{connection_id:path}`, so a slash inside the id
   * would be accepted — but encoding keeps the URL unambiguous either way.
   */
  detail: (connectionId: string): string =>
    `/connections/${encodeURIComponent(connectionId)}`,
} as const

/** Detection findings and detectors (M10/M13.12). */
export const DetectionPaths = {
  list: '/detections',
  rules: '/detections/rules',
  reset: '/detections/reset',
  detail: (findingId: string): string =>
    `/detections/${encodeURIComponent(findingId)}`,
} as const

/** Stored packets (M7/M13.8). */
export const PacketPaths = {
  list: '/packets',
  detail: (packetId: number): string => `/packets/${packetId}`,
  retentionCleanup: '/packets/retention/cleanup',
} as const

/** Traffic statistics (M6). */
export const StatisticsPaths = {
  traffic: '/statistics/traffic',
  protocols: '/statistics/protocols',
  ports: '/statistics/ports',
  topTalkers: '/statistics/top-talkers',
  reset: '/statistics/reset',
} as const

/** Stored alerts and their lifecycle (M11/M13.13). */
export const AlertPaths = {
  list: '/alerts',
  summary: '/alerts/summary',
  diagnostics: '/alerts/diagnostics',
  detail: (alertId: number): string => `/alerts/${alertId}`,
  evidence: (alertId: number): string => `/alerts/${alertId}/evidence`,
  status: (alertId: number): string => `/alerts/${alertId}/status`,
  acknowledge: (alertId: number): string => `/alerts/${alertId}/acknowledge`,
  resolve: (alertId: number): string => `/alerts/${alertId}/resolve`,
  dismiss: (alertId: number): string => `/alerts/${alertId}/dismiss`,
  falsePositive: (alertId: number): string => `/alerts/${alertId}/false-positive`,
} as const

/** Standalone evidence lookup (M13.14). */
export const EvidencePaths = {
  detail: (evidenceId: number): string => `/evidence/${evidenceId}`,
} as const

/** Correlated incidents and their lifecycle (M12/M13.15). */
export const IncidentPaths = {
  list: '/incidents',
  open: '/incidents/open',
  detail: (incidentId: string): string =>
    `/incidents/${encodeURIComponent(incidentId)}`,
  investigate: (incidentId: string): string =>
    `/incidents/${encodeURIComponent(incidentId)}/investigate`,
  resolve: (incidentId: string): string =>
    `/incidents/${encodeURIComponent(incidentId)}/resolve`,
  dismiss: (incidentId: string): string =>
    `/incidents/${encodeURIComponent(incidentId)}/dismiss`,
} as const

/** Derived analytics views (M13.18). */
export const AnalyticsPaths = {
  traffic: '/analytics/traffic',
  protocols: '/analytics/protocols',
  devices: '/analytics/devices',
  connections: '/analytics/connections',
  threats: '/analytics/threats',
} as const

/**
 * Stored reports: metadata, generation and the artifact itself (M13.20/M17).
 *
 * `download` fetches the file by the report's *id*, which is the only handle a
 * client ever has on it: no payload carries a location (M13.30), so there is no
 * path to build a URL from and nothing here that could leak one.
 */
export const ReportPaths = {
  list: '/reports',
  generate: '/reports/generate',
  detail: (reportId: number): string => `/reports/${reportId}`,
  download: (reportId: number): string => `/reports/${reportId}/download`,
} as const

/** Application settings (M13.21). */
export const SettingPaths = {
  list: '/settings',
  detail: (key: string): string => `/settings/${encodeURIComponent(key)}`,
} as const

/** Process, database and pipeline state (M13.22). */
export const SystemPaths = {
  status: '/system/status',
  health: '/system/health',
  info: '/system/info',
  /** The one unversioned operational route M13.3 keeps. */
  healthRoot: '/health',
} as const

/** Stored notifications (M13.23). */
export const NotificationPaths = {
  list: '/notifications',
  detail: (notificationId: number): string => `/notifications/${notificationId}`,
} as const

/**
 * Per-device behavioural baselines (M21.10).
 *
 * A device key is `mac:aa:bb:...` or `ip:10.0.0.7`, so it carries colons — the
 * builders encode it as one path segment, exactly as the device and connection
 * paths do.
 *
 * `reset` is a POST rather than a DELETE because it does not remove the device:
 * it discards that one device's observation windows and profile and returns it to
 * `learning`, which is a state change the response describes. Nothing else —
 * packets, devices, alerts, incidents — is touched (M21.10).
 */
export const BaselinePaths = {
  list: '/baselines',
  detail: (deviceKey: string): string =>
    `/baselines/${encodeURIComponent(deviceKey)}`,
  reset: (deviceKey: string): string =>
    `/baselines/${encodeURIComponent(deviceKey)}/reset`,
} as const

/**
 * ML anomaly detection surfaces (M22.12).
 *
 * `models` is declared before `detail` in intent, not in path: `/models` is a
 * literal segment while `detail` takes an integer id, so FastAPI's router matches
 * the literal first and an evaluation id is never mistaken for a device model
 * request. The builders encode a device key because `mac:aa:bb:...` carries colons,
 * exactly as the baseline paths do.
 *
 * `retrain` is a POST rather than a PUT because it is not idempotent in the way a
 * put would be: each call runs a training pass and produces a new model version.
 * It answers `200` whether or not a model was produced, so the caller reads
 * `trained` from the payload rather than inferring the outcome from the status.
 */
export const AnomalyPaths = {
  list: '/anomalies',
  models: '/anomalies/models',
  model: (deviceKey: string): string =>
    `/anomalies/models/${encodeURIComponent(deviceKey)}`,
  retrain: (deviceKey: string): string =>
    `/anomalies/models/${encodeURIComponent(deviceKey)}/retrain`,
  detail: (evaluationId: number): string => `/anomalies/${evaluationId}`,
} as const
