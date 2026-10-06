/**
 * Capture, packet and traffic-statistics models (M15.6).
 *
 * These mirror the M4/M5/M6/M7 wire shapes. Three properties are load-bearing and
 * are restated here because a client that got them wrong would render something
 * false:
 *
 * * **A live packet has no payload.** `app/schemas/packet.py` has no payload field
 *   and `app/websockets/payloads.py:packet_payload` sends a fixed field list
 *   (M7.5/M14.8). {@link PacketEventData} therefore has nowhere to put one.
 * * **A stored packet and a live packet are different shapes.** The stored row is
 *   {@link StoredPacket} (`id`, `packet_length`, `tcp_flags`); the live event is
 *   {@link PacketEventData} (`packet_id`, `length`, `packet_type`). They are two
 *   models rather than one with optional fields, because the fields genuinely
 *   differ and merging them would invite a page to read `packet_length` off a
 *   stream event and render `undefined`.
 * * **A rate is supplied, never computed.** `packets_per_second` and friends come
 *   from the M6 snapshot. The frontend must not divide counters itself (M15.9).
 */

/** `GET /api/v1/capture/status` — the live capture state (M4). */
export interface CaptureStatus {
  /** One of {@link CaptureState}. Typed `string` because that is what M4 sends. */
  readonly status: string
  readonly interface: string | null
  readonly packet_count: number
}

/**
 * The capture lifecycle states M4 reports (`app/services/capture_state.py`).
 *
 * A `const` object rather than a union, for the same reason the event types are:
 * the value on the wire and the value compared against are then the same string
 * with no mapping step to forget.
 */
export const CaptureState = {
  STOPPED: 'stopped',
  STARTING: 'starting',
  RUNNING: 'running',
  STOPPING: 'stopping',
  ERROR: 'error',
} as const

/** One of the states in {@link CaptureState}. */
export type CaptureStateValue = (typeof CaptureState)[keyof typeof CaptureState]

/**
 * States during which a session exists at all
 * (`app/services/capture_manager._ACTIVE_STATUSES`).
 *
 * Includes `starting` and `stopping`, which is why a page must not treat "active"
 * as "capturing": a start button is disabled while a session is starting, but the
 * page should still say "starting" rather than claiming packets are flowing.
 */
export const ACTIVE_CAPTURE_STATES: readonly CaptureStateValue[] = [
  CaptureState.STARTING,
  CaptureState.RUNNING,
  CaptureState.STOPPING,
]

/** Return True when `value` is one of the five documented capture states. */
export function isCaptureState(value: unknown): value is CaptureStateValue {
  return (
    typeof value === 'string' &&
    (Object.values(CaptureState) as readonly string[]).includes(value)
  )
}

/**
 * True only when capture is genuinely running (`CaptureManager.is_running`).
 *
 * `null` is `false`: a status that was never read is not a running session.
 */
export function isCaptureRunning(status: CaptureStatus | null): boolean {
  return status?.status === CaptureState.RUNNING
}

/** True when a session exists, including while it is starting or stopping. */
export function isCaptureActive(status: CaptureStatus | null): boolean {
  if (status === null) return false
  return (ACTIVE_CAPTURE_STATES as readonly string[]).includes(status.status)
}

/**
 * One entry of `GET /api/v1/capture/interfaces` (M4).
 *
 * Field-for-field what `app/schemas/interface.py:NetworkInterface` returns, which
 * was checked against the live response rather than inferred from the schema doc:
 * every entry carries all five keys. `description` and `mac_address` are `null`
 * when the OS does not report them — loopback has no MAC — but neither key is
 * ever absent, and `ip_addresses` is always a list (possibly empty), never
 * omitted. They are therefore non-optional and nullable rather than optional.
 *
 * An earlier version of this model called the address list `addresses`. The
 * backend has never sent that key, so a page reading it would have rendered an
 * empty address list forever while the type still checked cleanly — which is
 * exactly the kind of drift M15.6 exists to prevent.
 */
export interface NetworkInterface {
  readonly name: string
  readonly description: string | null
  readonly mac_address: string | null
  readonly ip_addresses: readonly string[]
  readonly is_up: boolean
}

/** Body of `PUT /api/v1/capture/interface`. */
export interface InterfaceSelectionRequest {
  readonly name: string
}

/**
 * Packet classification (M5), mirroring `app.schemas.packet.PacketType`.
 *
 * This is a traffic classification, never a threat verdict.
 */
export type PacketType =
  | 'TCP'
  | 'UDP'
  | 'ICMP'
  | 'DNS'
  | 'ARP'
  | 'IPV4'
  | 'IPV6'
  | 'OTHER'

/**
 * One normalized packet as it arrives on `/ws/packets` (M14.8).
 *
 * The field list is exactly the projection in
 * `app/websockets/payloads.py:packet_payload`. Keeping it to that list is what
 * makes "no payload reaches the browser" true at the type level.
 */
export interface PacketEventData {
  readonly packet_id: number | null
  /** ISO-8601 UTC. */
  readonly timestamp: string
  readonly interface: string | null
  readonly source_ip: string | null
  readonly destination_ip: string | null
  readonly protocol: string
  readonly source_port: number | null
  readonly destination_port: number | null
  /** Captured frame length in bytes. */
  readonly length: number
  readonly packet_type: PacketType
}

/** One row of `GET /api/v1/packets` — a *stored* packet (M7.16). */
export interface StoredPacket {
  readonly id: number
  /** ISO-8601 UTC. */
  readonly timestamp: string
  readonly source_ip: string
  readonly destination_ip: string
  readonly source_port: number | null
  readonly destination_port: number | null
  readonly protocol: string
  readonly packet_length: number
  readonly tcp_flags: string | null
}

/**
 * Filters accepted by `GET /api/v1/packets` (M13.8).
 *
 * Two filters that other collections have are deliberately absent, and the
 * backend's own module says why: the `packets` table has no capture-interface
 * column and its `device_id` is always `NULL`, so a filter on either would match
 * nothing. A filter that can never match is worse than no filter, so neither side
 * offers one.
 *
 * `since` and `until` are ISO-8601 and are compared against the naive UTC the
 * packet table stores (M13.26). `since` is inclusive and `until` exclusive, so
 * two adjacent windows never both claim the same instant.
 */
export interface PacketQuery {
  readonly source_ip?: string
  readonly destination_ip?: string
  readonly protocol?: string
  readonly source_port?: number
  readonly destination_port?: number
  readonly since?: string
  readonly until?: string
}

/** Result of `POST /api/v1/packets/retention/cleanup` (M7.14). */
export interface RetentionCleanupResult {
  /** How many rows were older than the retention window and were deleted. */
  readonly deleted: number
}

/** Payload of `GET /api/v1/packets`. */
export interface StoredPacketPage {
  readonly count: number
  readonly total: number
  readonly limit?: number | null
  readonly offset: number
  readonly has_more?: boolean | null
  readonly packets: readonly StoredPacket[]
}

/** Direction of traffic relative to the monitoring host (M6). */
export type TrafficDirection = 'inbound' | 'outbound' | 'local' | 'unknown'

/** Traffic attributed to one protocol (M6). */
export interface ProtocolStat {
  readonly protocol: string
  readonly packets: number
  readonly bytes: number
  readonly percentage: number
}

/** Traffic attributed to one direction (M6). */
export interface DirectionStat {
  readonly direction: TrafficDirection
  readonly packets: number
  readonly bytes: number
}

/** A ranked item — an address, a port or a conversation key (M6). */
export interface TopEntry {
  readonly key: string
  readonly packets: number
  readonly bytes: number
}

/** `GET /api/v1/statistics/traffic` — a point-in-time M6 snapshot. */
export interface TrafficSnapshot {
  /** Epoch seconds of the snapshot. */
  readonly timestamp: number
  readonly total_packets: number
  readonly total_bytes: number
  readonly packets_per_second: number
  readonly bytes_per_second: number
  readonly bits_per_second: number
  readonly protocol_statistics: readonly ProtocolStat[]
  readonly direction_statistics: readonly DirectionStat[]
  readonly top_sources: readonly TopEntry[]
  readonly top_destinations: readonly TopEntry[]
  readonly top_ports: readonly TopEntry[]
}

/**
 * `GET /api/v1/statistics/top-talkers`.
 *
 * There is deliberately no `rank_by` field. The caller chose the metric, and
 * `app/schemas/statistics.py:TopTalkers` does not echo it back — so a model that
 * declared one would read `undefined` and render an empty ordering label.
 */
export interface TopTalkers {
  readonly sources: readonly TopEntry[]
  readonly destinations: readonly TopEntry[]
  readonly conversations: readonly TopEntry[]
}

/** The rate window a statistics endpoint may be asked for (M6). */
export type StatisticsWindow = '1s' | '10s' | '60s'

/** The metric a ranked statistics or analytics list is ordered by. */
export type RankMetric = 'packets' | 'bytes'

/**
 * Formatting helper: a stored or live packet's endpoints as `src → dst`.
 *
 * Lives here rather than in a component because both the live table and the
 * stored-packet table render it, and they hold different models — so it takes the
 * two nullable addresses rather than either model.
 */
export function formatEndpoints(
  sourceIp: string | null,
  sourcePort: number | null,
  destinationIp: string | null,
  destinationPort: number | null,
): string {
  const withPort = (ip: string | null, port: number | null): string => {
    const address = ip ?? '—'
    return port === null ? address : `${address}:${port}`
  }
  return `${withPort(sourceIp, sourcePort)} → ${withPort(destinationIp, destinationPort)}`
}
