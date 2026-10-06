/**
 * The frontend's backend-type barrel (M15.6).
 *
 * Pages and hooks import from `@/types` so that where a model lives is a detail of
 * this directory rather than something every import site has to know. A page that
 * needs to name a backend field imports it here; only a module implementing the
 * same domain reaches into a specific file.
 */

export type {
  ApiEnvelope,
  ApiFailure,
  ApiFieldError,
  ApiSuccess,
  ErrorCodeValue,
  PageMeta,
  Paged,
  ValidationDetail,
  ValidationErrorBody,
} from './api'
export { ErrorCode, isApiSuccess, isValidationErrorBody } from './api'

export type {
  CaptureStateValue,
  CaptureStatus,
  DirectionStat,
  InterfaceSelectionRequest,
  NetworkInterface,
  PacketEventData,
  PacketQuery,
  PacketType,
  ProtocolStat,
  RankMetric,
  RetentionCleanupResult,
  StatisticsWindow,
  StoredPacket,
  StoredPacketPage,
  TopEntry,
  TopTalkers,
  TrafficDirection,
  TrafficSnapshot,
} from './traffic'
export {
  ACTIVE_CAPTURE_STATES,
  CaptureState,
  formatEndpoints,
  isCaptureActive,
  isCaptureRunning,
  isCaptureState,
} from './traffic'

export type {
  Connection,
  ConnectionPage,
  ConnectionProtocol,
  ConnectionQuery,
  ConnectionState,
  Device,
  DevicePage,
  DeviceQuery,
  DeviceStatus,
  ExpireResult,
} from './network'

export type {
  Incident,
  IncidentLifecycleAction,
  IncidentOrder,
  IncidentPage,
  IncidentQuery,
  IncidentStatus,
  IncidentSummary,
  RiskBand,
} from './security'
export type {
  Alert,
  AlertDetail,
  AlertDiagnostics,
  AlertEvidence,
  AlertLifecycleAction,
  AlertLifecycleRequest,
  AlertPage,
  AlertQuery,
  AlertSeverity,
  AlertStatus,
  AlertSummary,
  DetectionDiagnostics,
  DetectionFinding,
  DetectionFindingPage,
  DetectionQuery,
  DetectionRule,
  DetectionRuleList,
  EvidenceDetail,
  EvidenceList,
  EvidenceType,
  EvidenceValue,
} from './security'
export {
  ACTIVE_ALERT_STATUSES,
  ACTIVE_INCIDENT_STATUSES,
  ALERT_SEVERITY_ORDER,
  ALERT_TRANSITIONS,
  INCIDENT_TRANSITIONS,
  RISK_BAND_RANGES,
  TERMINAL_ALERT_STATUSES,
  riskBandFor,
  severityRank,
} from './security'

export type {
  AnalyticsConnections,
  AnalyticsDevices,
  AnalyticsProtocols,
  AnalyticsRank,
  AnalyticsThreats,
  AnalyticsTraffic,
  DashboardAlerts,
  DashboardCapture,
  DashboardConnections,
  DashboardDetections,
  DashboardDevices,
  DashboardIncidents,
  DashboardSection,
  DashboardSectionName,
  DashboardSummary,
  DashboardTraffic,
  DashboardUpdateEvent,
  RankedConnection,
  RankedDevice,
  ThreatRuleStat,
} from './analytics'

export type {
  Baseline,
  DatabaseState,
  HealthCheck,
  Notification,
  NotificationList,
  NotificationQuery,
  Report,
  ReportList,
  RuntimeMetrics,
  ServiceState,
  Setting,
  SettingList,
  SettingUpdateRequest,
  SettingUpdateResult,
  SettingValue,
  SystemCaptureState,
  SystemHealth,
  SystemInfo,
  SystemStatus,
} from './system'

export type {
  AlertEvent,
  CaptureEvent,
  CaptureEventData,
  Channel,
  ConnectionPhase,
  DashboardEvent,
  DatabaseStatusEvent,
  DatabaseStatusEventData,
  EventSource,
  EventTypeValue,
  IncidentEvent,
  KeepaliveEventData,
  PacketEvent,
  RefusalEventData,
  ServerEvent,
  ServiceStatusEvent,
  ServiceStatusEventData,
  UnknownPayload,
} from './websocket'
export {
  CHANNELS,
  CHANNEL_PATHS,
  EVENT_TYPES,
  EventType,
  SUPPORTED_SCHEMA_VERSION,
  channelPath,
  isAlertEvent,
  isCaptureEvent,
  isChannel,
  isDashboardEvent,
  isDatabaseStatusEvent,
  isIncidentEvent,
  isKnownEventType,
  isPacketEvent,
  isServiceStatusEvent,
  keepaliveFrame,
  parseServerEvent,
} from './websocket'
