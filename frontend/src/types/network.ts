/**
 * Device and connection models (M15.6).
 *
 * Two absences here are deliberate and must not be "fixed" by a page:
 *
 * * **A device has no risk score.** M8 discovers and tracks devices; it does not
 *   score them (`app/schemas/device.py`). The `devices.risk_score` column is seed
 *   data rather than a runtime observation, and M13.10 does not expose it. A page
 *   that displayed one would be inventing a verdict (M15.12).
 * * **A connection has no severity.** M9 tracks conversations, never judges them.
 *
 * `status` on a device and `state` on a connection are both *activity/protocol*
 * observations, not security verdicts.
 */

/** A device's activity state, derived from last-seen timing (M8.9). */
export type DeviceStatus = 'active' | 'inactive' | 'unknown'

/** One observed device (M8.3). */
export interface Device {
  /** Stable identity: `mac:...` or `ip:...`. */
  readonly device_id: string
  readonly mac_address: string | null
  readonly ip_addresses: readonly string[]
  /** ISO-8601 UTC. */
  readonly first_seen: string | null
  /** ISO-8601 UTC. */
  readonly last_seen: string | null
  readonly packet_count: number
  readonly byte_count: number
  readonly packets_sent: number
  readonly bytes_sent: number
  readonly packets_received: number
  readonly bytes_received: number
  readonly hostname: string | null
  readonly vendor: string | null
  readonly status: DeviceStatus
  /** True for the monitoring host itself. */
  readonly is_local: boolean
}

/** Payload of `GET /api/v1/devices` (M13.10/M13.24). */
export interface DevicePage {
  readonly count: number
  readonly limit?: number | null
  readonly offset: number
  /** The true match count; the device registry can count it (M13.10). */
  readonly total?: number | null
  readonly has_more?: boolean | null
  readonly devices: readonly Device[]
}

/** Filters accepted by `GET /api/v1/devices`. */
export interface DeviceQuery {
  readonly status?: DeviceStatus
  readonly ip?: string
  readonly mac?: string
  readonly limit?: number
  readonly offset?: number
}

/** A conversation's observed protocol state (M9.10/M9.11). */
export type ConnectionState =
  | 'observed'
  | 'established'
  | 'closing'
  | 'closed'
  | 'active'
  | 'inactive'
  | 'unknown'

/** The transport protocols M9 tracks. */
export type ConnectionProtocol = 'TCP' | 'UDP' | 'ICMP'

/** One tracked conversation (M9.6). */
export interface Connection {
  /** Deterministic id, e.g. `TCP|10.0.0.1:52134|1.1.1.1:443`. */
  readonly connection_id: string
  readonly protocol: string
  readonly source_ip: string
  readonly source_port: number | null
  readonly destination_ip: string
  readonly destination_port: number | null
  readonly ip_version: number | null
  /** ISO-8601 UTC. */
  readonly first_seen: string | null
  /** ISO-8601 UTC. */
  readonly last_seen: string | null
  readonly packet_count: number
  readonly byte_count: number
  readonly source_packet_count: number
  readonly source_byte_count: number
  readonly destination_packet_count: number
  readonly destination_byte_count: number
  readonly state: ConnectionState
  /** M8 device identity, when the address is known. */
  readonly source_device_id: string | null
  readonly destination_device_id: string | null
  /** True while the conversation is still tracked. */
  readonly active: boolean
}

/** Payload of `GET /api/v1/connections` and `/connections/active`. */
export interface ConnectionPage {
  readonly count: number
  readonly limit?: number | null
  readonly offset: number
  readonly total?: number | null
  readonly has_more?: boolean | null
  readonly connections: readonly Connection[]
}

/** Filters accepted by `GET /api/v1/connections`. */
export interface ConnectionQuery {
  readonly protocol?: ConnectionProtocol
  readonly source_ip?: string
  readonly destination_ip?: string
  readonly source_port?: number
  readonly destination_port?: number
  readonly device_id?: string
  readonly state?: ConnectionState
  readonly active_only?: boolean
  readonly limit?: number
  readonly offset?: number
}

/** Payload of `POST /api/v1/connections/expire` (M9.22 dev helper). */
export interface ExpireResult {
  readonly expired: number
  readonly active: number
  readonly historical: number
}
