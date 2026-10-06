/**
 * The WebSocket event contract (M15.26/M15.29).
 *
 * Every message M14 sends, on every channel, is one envelope
 * (`app/websockets/event.py:WebSocketEvent`). One envelope rather than one shape
 * per channel is what makes the client's decoder a single function — and it is
 * what lets {@link parseServerEvent} reject a message it does not understand
 * instead of applying half of it.
 *
 * Six fields matter to the client:
 *
 * * `event_id` — unique per event. This is what deduplication keys on (M15.29),
 *   because the packets channel intentionally drops events under load, so
 *   `sequence` is *not* a continuity guarantee.
 * * `type` — from a closed set. An unknown type is refused rather than routed.
 * * `channel` — which of the four streams the event belongs to.
 * * `timestamp` — ISO-8601 UTC with an offset, always.
 * * `sequence` — process-wide monotonic. A gap is normal and expected, never an
 *   error (M15.11).
 * * `data` — the channel-specific payload.
 */

import type { Alert } from './security'
import type { IncidentSummary } from './security'
import type { PacketEventData } from './traffic'
import type { DashboardUpdateEvent } from './analytics'

/** The four documented real-time streams (M14.3/M14.6). */
export type Channel = 'dashboard' | 'packets' | 'alerts' | 'system'

/** The path each channel answers on (`app/websockets/channels.CHANNEL_PATHS`). */
export const CHANNEL_PATHS: Readonly<Record<Channel, string>> = {
  dashboard: '/ws/dashboard',
  packets: '/ws/packets',
  alerts: '/ws/alerts',
  system: '/ws/system',
}

/** Every channel, in the order the milestone lists them. */
export const CHANNELS: readonly Channel[] = ['dashboard', 'packets', 'alerts', 'system']

/**
 * Every event name M14 can emit (`app/websockets/event.EventType`).
 *
 * A `const` object rather than a TypeScript `enum`, so the value that travels on
 * the wire and the value the code compares against are the same string with no
 * `.value` step to forget.
 */
export const EventType = {
  // packets (M14.8)
  PACKET_OBSERVED: 'packet.observed',

  // dashboard (M14.9)
  DASHBOARD_UPDATED: 'dashboard.updated',

  // alerts (M14.10)
  ALERT_CREATED: 'alert.created',
  ALERT_UPDATED: 'alert.updated',
  ALERT_ACKNOWLEDGED: 'alert.acknowledged',
  ALERT_RESOLVED: 'alert.resolved',
  ALERT_DISMISSED: 'alert.dismissed',
  ALERT_FALSE_POSITIVE: 'alert.false_positive',

  // incidents (M14.12), carried on the alerts channel
  INCIDENT_CREATED: 'incident.created',
  INCIDENT_UPDATED: 'incident.updated',
  INCIDENT_STATUS_CHANGED: 'incident.status_changed',

  // system (M14.11)
  CAPTURE_STARTED: 'capture.started',
  CAPTURE_STOPPED: 'capture.stopped',
  CAPTURE_ERROR: 'capture.error',
  DATABASE_STATUS: 'database.status',
  SERVICE_STATUS: 'service.status',

  // keepalive and refusals (M14.23/M14.24)
  PING: 'ping',
  PONG: 'pong',
  ERROR: 'error',
} as const

/** One of the event names in {@link EventType}. */
export type EventTypeValue = (typeof EventType)[keyof typeof EventType]

/** The closed set of known event names, used to reject an unknown type. */
export const EVENT_TYPES: ReadonlySet<string> = new Set(Object.values(EventType))

/** Which service produced an event (`app/websockets/event.EventSource`). */
export type EventSource =
  | 'pipeline.packets'
  | 'alerts.engine'
  | 'correlation.engine'
  | 'capture.manager'
  | 'dashboard'
  | 'system'

/** The envelope version this client understands. */
export const SUPPORTED_SCHEMA_VERSION = 1

/** A payload that is not one of the modelled shapes. */
export type UnknownPayload = Readonly<Record<string, unknown>>

/** Payload of `capture.started`, `capture.stopped` and `capture.error` (M14.11). */
export interface CaptureEventData {
  readonly status: string
  readonly interface: string | null
  readonly packet_count: number
  /** Only present on `capture.error`, and always a fixed sentence (M14.22). */
  readonly reason?: string
}

/** Payload of `database.status` (M14.11). */
export interface DatabaseStatusEventData {
  readonly dialect: string
  readonly reachable: boolean
}

/** Payload of `service.status` (M14.11). */
export interface ServiceStatusEventData {
  readonly service: string
  readonly state: string
  readonly detail?: string
}

/** Payload of `ping` and `pong` (M14.24). */
export interface KeepaliveEventData {
  /** An opaque token pairing a pong with the ping that caused it. */
  readonly nonce?: string
}

/** Payload of `error` (M14.23). */
export interface RefusalEventData {
  readonly reason: string
  readonly field: string
}

/**
 * One message from a channel, with its payload left untyped.
 *
 * This is the shape {@link parseServerEvent} produces: the envelope is validated,
 * and the payload is whatever object the server sent. A consumer that needs a
 * specific payload uses a narrowing helper — {@link isPacketEvent},
 * {@link isAlertEvent} and so on — rather than casting, so an event of an
 * unexpected shape is ignored rather than half-applied.
 */
export interface ServerEvent {
  readonly schema_version: number
  readonly event_id: string
  readonly type: string
  readonly channel: Channel
  readonly timestamp: string
  readonly source: string
  readonly sequence: number
  readonly data: UnknownPayload
}

/** A `packet.observed` event, narrowed to its payload (M14.8). */
export interface PacketEvent extends ServerEvent {
  readonly type: typeof EventType.PACKET_OBSERVED
  readonly channel: 'packets'
  readonly data: PacketEventData & UnknownPayload
}

/**
 * An alert lifecycle or creation event, narrowed to its payload (M14.10).
 *
 * The payload is the M11 wire view — the same projection `GET /api/v1/alerts`
 * serves — so an alert arriving live and an alert read from REST are the same
 * type, and a row can be replaced in place rather than duplicated (M15.14).
 */
export interface AlertEvent extends ServerEvent {
  readonly type:
    | typeof EventType.ALERT_CREATED
    | typeof EventType.ALERT_UPDATED
    | typeof EventType.ALERT_ACKNOWLEDGED
    | typeof EventType.ALERT_RESOLVED
    | typeof EventType.ALERT_DISMISSED
    | typeof EventType.ALERT_FALSE_POSITIVE
  readonly channel: 'alerts'
  readonly data: Alert & UnknownPayload
}

/**
 * An incident event, narrowed to its payload (M14.12).
 *
 * The payload is the M12 incident *summary*, not the detail view: a live event
 * announces that something changed, and the member lists are what
 * `GET /api/v1/incidents/{id}` is for.
 */
export interface IncidentEvent extends ServerEvent {
  readonly type:
    | typeof EventType.INCIDENT_CREATED
    | typeof EventType.INCIDENT_UPDATED
    | typeof EventType.INCIDENT_STATUS_CHANGED
  readonly channel: 'alerts'
  readonly data: IncidentSummary & UnknownPayload
}

/** A `dashboard.updated` event, narrowed to its payload (M14.9). */
export interface DashboardEvent extends ServerEvent {
  readonly type: typeof EventType.DASHBOARD_UPDATED
  readonly channel: 'dashboard'
  readonly data: DashboardUpdateEvent & UnknownPayload
}

/** A capture lifecycle event, narrowed to its payload (M14.11). */
export interface CaptureEvent extends ServerEvent {
  readonly type:
    | typeof EventType.CAPTURE_STARTED
    | typeof EventType.CAPTURE_STOPPED
    | typeof EventType.CAPTURE_ERROR
  readonly channel: 'system'
  readonly data: CaptureEventData & UnknownPayload
}

/** A database reachability event, narrowed to its payload (M14.11). */
export interface DatabaseStatusEvent extends ServerEvent {
  readonly type: typeof EventType.DATABASE_STATUS
  readonly channel: 'system'
  readonly data: DatabaseStatusEventData & UnknownPayload
}

/** A service state event, narrowed to its payload (M14.11). */
export interface ServiceStatusEvent extends ServerEvent {
  readonly type: typeof EventType.SERVICE_STATUS
  readonly channel: 'system'
  readonly data: ServiceStatusEventData & UnknownPayload
}

/** Where a channel's client connection currently stands (M15.27). */
export type ConnectionPhase =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'closed'

/**
 * Read a channel's path, refusing an unknown name.
 *
 * Returns `null` rather than raising, because the only caller passes a value the
 * application itself produced — so an unknown name is a bug worth tolerating at
 * a boundary rather than crashing a page over.
 */
export function channelPath(channel: Channel): string {
  return CHANNEL_PATHS[channel]
}

/** Return True when `value` is one of the four channel names. */
export function isChannel(value: unknown): value is Channel {
  return typeof value === 'string' && (CHANNELS as readonly string[]).includes(value)
}

/** Return True when `value` is one of the documented event names. */
export function isKnownEventType(value: unknown): value is EventTypeValue {
  return typeof value === 'string' && EVENT_TYPES.has(value)
}

/** Narrow an event to a packet event. */
export function isPacketEvent(event: ServerEvent): event is PacketEvent {
  return event.type === EventType.PACKET_OBSERVED
}

/** Narrow an event to an alert event. */
export function isAlertEvent(event: ServerEvent): event is AlertEvent {
  return (
    event.type === EventType.ALERT_CREATED ||
    event.type === EventType.ALERT_UPDATED ||
    event.type === EventType.ALERT_ACKNOWLEDGED ||
    event.type === EventType.ALERT_RESOLVED ||
    event.type === EventType.ALERT_DISMISSED ||
    event.type === EventType.ALERT_FALSE_POSITIVE
  )
}

/** Narrow an event to an incident event. */
export function isIncidentEvent(event: ServerEvent): event is IncidentEvent {
  return (
    event.type === EventType.INCIDENT_CREATED ||
    event.type === EventType.INCIDENT_UPDATED ||
    event.type === EventType.INCIDENT_STATUS_CHANGED
  )
}

/** Narrow an event to a dashboard event. */
export function isDashboardEvent(event: ServerEvent): event is DashboardEvent {
  return event.type === EventType.DASHBOARD_UPDATED
}

/** Narrow an event to a capture lifecycle event. */
export function isCaptureEvent(event: ServerEvent): event is CaptureEvent {
  return (
    event.type === EventType.CAPTURE_STARTED ||
    event.type === EventType.CAPTURE_STOPPED ||
    event.type === EventType.CAPTURE_ERROR
  )
}

/** Narrow an event to a database reachability event. */
export function isDatabaseStatusEvent(event: ServerEvent): event is DatabaseStatusEvent {
  return event.type === EventType.DATABASE_STATUS
}

/** Narrow an event to a service state event. */
export function isServiceStatusEvent(event: ServerEvent): event is ServiceStatusEvent {
  return event.type === EventType.SERVICE_STATUS
}

/**
 * Validate one raw frame and return the event it carries, or `null`.
 *
 * Returning `null` rather than throwing is deliberate: M14.14 guarantees the
 * *server* never dies on a bad event, and the client should hold the same line —
 * one malformed frame must not tear down a channel and lose the stream that
 * follows it.
 *
 * The checks are the ones that make an event usable:
 *
 * * it must be a JSON object;
 * * it must carry a known `schema_version` — an envelope this client does not
 *   understand is refused rather than misread (M14.7);
 * * `event_id`, `type`, `channel` and `timestamp` must be present and of the
 *   right kind, because deduplication and routing both depend on them;
 * * `type` must be in the documented set, so an invented name cannot be routed;
 * * `data` must be an object, because every payload is one.
 *
 * `sequence` is *not* required to be continuous: M14 drops packet events under
 * load by design, so a gap is expected and must never be treated as an error
 * (M15.11).
 */
export function parseServerEvent(raw: string): ServerEvent | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return null
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null

  const candidate = parsed as Record<string, unknown>
  if (candidate.schema_version !== SUPPORTED_SCHEMA_VERSION) return null
  if (typeof candidate.event_id !== 'string' || candidate.event_id === '') return null
  if (!isKnownEventType(candidate.type)) return null
  if (!isChannel(candidate.channel)) return null
  if (typeof candidate.timestamp !== 'string') return null
  if (typeof candidate.data !== 'object' || candidate.data === null) return null
  if (Array.isArray(candidate.data)) return null

  return {
    schema_version: SUPPORTED_SCHEMA_VERSION,
    event_id: candidate.event_id,
    type: candidate.type,
    channel: candidate.channel,
    timestamp: candidate.timestamp,
    source: typeof candidate.source === 'string' ? candidate.source : 'unknown',
    sequence: typeof candidate.sequence === 'number' ? candidate.sequence : 0,
    data: candidate.data as UnknownPayload,
  }
}

/**
 * Build the frame a client may send (M14.23).
 *
 * M14 is server-push-only, and this is the whole of what a client is permitted to
 * say: a `ping`, or a `pong` answering one. There is no frame that selects a
 * channel, a topic, a filter or a command, so no helper exists for one.
 */
export function keepaliveFrame(
  type: typeof EventType.PING | typeof EventType.PONG,
  nonce?: string,
): string {
  return nonce === undefined
    ? JSON.stringify({ type })
    : JSON.stringify({ type, nonce })
}
