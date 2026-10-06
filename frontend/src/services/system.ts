/**
 * System service (M13.22, M15.24).
 *
 * Three angles on the running process, each read from the service that already
 * owns the fact. Nothing here is a frontend health metric: the frontend does not
 * probe the backend, and it must not invent a status of its own (M15.24).
 *
 * What the API deliberately withholds, and therefore what no page may display:
 *
 * * the **database URL** — the payload reports the *dialect* instead, which is
 *   the part a client can act on;
 * * **exception text** — a failed probe reports which dependency failed, never a
 *   driver message that could name a path or a host;
 * * the **capture interface list**, packet payloads, and anything else a caller
 *   would have to be entitled to.
 *
 * `/system/health` always answers `200`: a dependency being down is a *verdict in
 * the payload*, not a failure of the request. So the caller reads `status` rather
 * than treating a non-2xx response as the signal.
 */

import { apiGet } from './client'
import { SystemPaths } from './endpoints'
import type { SystemHealth, SystemInfo, SystemStatus } from '@/types'

/** The aggregate verdicts `SystemHealth.status` may carry (M13.22). */
export const SYSTEM_STATUS_HEALTHY = 'healthy'
/** The verdict reported when at least one probe failed. */
export const SYSTEM_STATUS_DEGRADED = 'degraded'

/**
 * `GET /api/v1/system/status` — the consolidated picture.
 *
 * Identity, capture state, database reachability, every pipeline stage and basic
 * runtime metrics, assembled from the services that own each fact. This is the
 * one request the System view makes on load.
 */
export function fetchSystemStatus(signal?: AbortSignal): Promise<SystemStatus> {
  return apiGet<SystemStatus>(SystemPaths.status, undefined, { signal })
}

/**
 * `GET /api/v1/system/health` — one probe verdict per dependency.
 *
 * Resolves even when the application is degraded: the endpoint reports health, it
 * does not gate on it. Use {@link isSystemHealthy} to read the verdict.
 */
export function fetchSystemHealth(signal?: AbortSignal): Promise<SystemHealth> {
  return apiGet<SystemHealth>(SystemPaths.health, undefined, { signal })
}

/**
 * `GET /api/v1/system/info` — application identity and environment.
 *
 * Touches no dependency, so it answers even when the database is unreachable —
 * which is exactly when a caller most wants to know which build it is talking to.
 */
export function fetchSystemInfo(signal?: AbortSignal): Promise<SystemInfo> {
  return apiGet<SystemInfo>(SystemPaths.info, undefined, { signal })
}

/** True when every probe passed (M13.22). */
export function isSystemHealthy(health: SystemHealth): boolean {
  return health.status === SYSTEM_STATUS_HEALTHY
}

/**
 * True when `uptime_seconds` is a real measurement.
 *
 * `null` means startup was never recorded, which is **not** the same as "up for
 * zero seconds" — a distinction the System view must preserve rather than render
 * as `0s`.
 */
export function hasUptime(status: SystemStatus): boolean {
  return status.runtime.uptime_seconds !== null
}
