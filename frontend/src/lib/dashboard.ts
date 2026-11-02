/**
 * Dashboard view model (M15.9/M15.30).
 *
 * The dashboard reads two sources and they answer different questions:
 *
 * * `GET /api/v1/dashboard/summary` is the **current state** — per-section,
 *   independently available, with breakdowns;
 * * `/ws/dashboard` is the **movement** — nine scalars, sampled once per tick.
 *
 * {@link dashboardMetrics} is where they meet, and it is deliberately a pure
 * function of both inputs rather than state: a page renders from it, and a test
 * asserts its behaviour without a socket or a server.
 *
 * Two rules the selector exists to enforce:
 *
 * * **A live tick overrides, never fills in.** If a section is unavailable, its
 *   REST fields are "unknown" and they stay unknown until a tick actually
 *   supplies them — the selector never turns a missing number into `0`.
 * * **Nothing is derived.** Every value is copied from one source or the other.
 *   No rate is recomputed, no count is summed: M15.9 forbids a second
 *   implementation of a backend metric, because the moment either changes the
 *   two would disagree.
 *
 * `bits_per_second` is the one field that can only come from REST, because the
 * live projection does not carry it (M14.9). That is stated rather than worked
 * around: the bit-rate card keeps its last REST value while the packet counters
 * advance live, and a stale-by-one-refresh bit rate is honest where an invented
 * one would not be.
 */

import type {
  DashboardSection,
  DashboardSectionName,
  DashboardSummary,
  DashboardUpdateEvent,
} from '@/types'

/** Where a metric's value came from. */
export type MetricSource = 'rest' | 'live' | 'unavailable'

/** The nine scalars the dashboard shows, and where each stands. */
export interface DashboardMetrics {
  /** Whether capture is running, or `null` when neither source reported it. */
  readonly captureRunning: boolean | null
  /** The captured interface, or `null` when it is unknown or unset. */
  readonly interface: string | null
  readonly packetCount: number | null
  readonly packetsPerSecond: number | null
  readonly bytesPerSecond: number | null
  /** Only ever from REST: the live projection carries no bit rate. */
  readonly bitsPerSecond: number | null
  readonly deviceCount: number | null
  readonly activeConnections: number | null
  readonly openAlerts: number | null
  readonly activeIncidents: number | null
  /**
   * Whether these numbers are live.
   *
   * `live` means a tick has been applied to everything it can update; `rest`
   * means they are the summary as read; `unavailable` means neither source had
   * them.
   */
  readonly source: MetricSource
}

/** The label each dashboard section is known by in the UI. */
export const DASHBOARD_SECTION_LABELS: Readonly<Record<DashboardSectionName, string>> = {
  capture: 'Capture',
  traffic: 'Traffic',
  devices: 'Devices',
  connections: 'Connections',
  alerts: 'Alerts',
  incidents: 'Incidents',
  detections: 'Detections',
}

/** The section names, in the order the page renders them. */
export const DASHBOARD_SECTIONS: readonly DashboardSectionName[] = [
  'capture',
  'traffic',
  'devices',
  'connections',
  'alerts',
  'incidents',
  'detections',
]

/** One section the summary reported as unread, and why. */
export interface UnavailableSection {
  readonly section: DashboardSectionName
  /** The backend's safe sentence, or a fallback naming the section. */
  readonly reason: string
}

/** Read a section's payload, or `null` when it is absent or unavailable. */
export function sectionData<T>(section: DashboardSection<T> | undefined): T | null {
  if (section === undefined || !section.available) return null
  return section.data
}

/**
 * Every section that could not be read, with the reason the backend gave.
 *
 * Built from the sections themselves rather than from
 * `summary.unavailable_sections`, because the per-section `error` is the more
 * specific statement — it says which dependency failed. The name list is the
 * fallback for a section that reported itself unavailable without a sentence.
 */
export function unavailableSections(
  summary: DashboardSummary | null,
): readonly UnavailableSection[] {
  if (summary === null) return []
  const result: UnavailableSection[] = []
  for (const name of DASHBOARD_SECTIONS) {
    const section: DashboardSection<unknown> = summary[name]
    if (section.available) continue
    result.push({
      section: name,
      reason:
        section.error ??
        `${DASHBOARD_SECTION_LABELS[name]} could not be read from the backend.`,
    })
  }
  return result
}

/**
 * Combine the REST summary with the last live tick.
 *
 * @param summary The summary as read, or `null` before it has loaded.
 * @param live The most recent `dashboard.updated` payload, or `null`.
 */
export function dashboardMetrics(
  summary: DashboardSummary | null,
  live: DashboardUpdateEvent | null,
): DashboardMetrics {
  const capture = sectionData(summary?.capture)
  const traffic = sectionData(summary?.traffic)
  const devices = sectionData(summary?.devices)
  const connections = sectionData(summary?.connections)
  const alerts = sectionData(summary?.alerts)
  const incidents = sectionData(summary?.incidents)

  return {
    captureRunning: live?.capture_running ?? capture?.running ?? null,
    // An interface is taken from the tick when the tick reports one. A tick
    // carrying `null` means "no interface is selected", not "no news", so it
    // overrides a REST value — the two are the same fact observed twice.
    interface: live !== null ? live.interface : capture?.interface ?? null,
    packetCount: live?.packet_count ?? capture?.packet_count ?? null,
    packetsPerSecond: live?.packets_per_second ?? traffic?.packets_per_second ?? null,
    bytesPerSecond: live?.bytes_per_second ?? traffic?.bytes_per_second ?? null,
    // Never live: M14.9's projection has no bit rate, so this stays the REST
    // reading rather than being derived from `bytes_per_second`.
    bitsPerSecond: traffic?.bits_per_second ?? null,
    deviceCount: live?.device_count ?? devices?.total ?? null,
    activeConnections: live?.active_connections ?? connections?.active ?? null,
    openAlerts: live?.open_alerts ?? alerts?.open ?? null,
    activeIncidents: live?.active_incidents ?? incidents?.active ?? null,
    source: live !== null ? 'live' : summary !== null ? 'rest' : 'unavailable',
  }
}
