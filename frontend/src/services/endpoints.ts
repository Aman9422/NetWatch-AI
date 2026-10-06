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

/** Stored report metadata (M13.20). Generation is M17 and answers 501. */
export const ReportPaths = {
  list: '/reports',
  generate: '/reports/generate',
  detail: (reportId: number): string => `/reports/${reportId}`,
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

/** Per-device baselines. */
export const BaselinePaths = {
  list: '/baselines',
  detail: (deviceId: string): string => `/baselines/${encodeURIComponent(deviceId)}`,
} as const
