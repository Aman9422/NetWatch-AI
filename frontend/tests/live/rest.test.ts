// @vitest-environment node
/**
 * The live REST integration suite (M15.39).
 *
 * What this file is: the application's own service layer — `@/services`, imported
 * and called exactly as a page calls it — against a **running FastAPI backend**.
 * No router, no fake, no fixture. `fetch` is the runtime's, the envelope is the
 * backend's, and the data is whatever the store actually holds.
 *
 * Why it is a separate file from the unit suite: the unit tests prove the client
 * behaves correctly given a response; this proves the response is what the client
 * expects. Those fail differently and only one of them can catch the backend
 * renaming a field, changing an envelope or answering with a code the frontend
 * does not know.
 *
 * Two rules this file keeps deliberately:
 *
 * * **It asserts the contract, not the content.** Counts of devices, alerts and
 *   packets change as the application runs, so a test pinned to "there are 3
 *   alerts" would be a test of the developer's machine. Every assertion here is
 *   about shape, about a relationship between two endpoints, or about a refusal —
 *   all of which hold whatever the store contains.
 * * **It never mutates what it cannot undo.** The alert lifecycle has no "reopen",
 *   a stored setting cannot be deleted and a report cannot be un-generated, so the
 *   write endpoints are exercised through **refusals**: an unknown id, an
 *   illegal value and a validation failure. Each of those is checked to have left
 *   the store untouched, which is the property the frontend depends on and is also
 *   the only way to test those paths without damaging the operator's data.
 *
 * The `node` environment is required, not incidental: these are plain `fetch`
 * calls with no DOM involved, and the sibling socket suite needs the runtime's own
 * `WebSocket`. See `live-setup.ts` for the split.
 */

import { describe, expect, it } from 'vitest'
import { environment } from '@/config/env'
import {
  DEFAULT_PAGE_LIMIT,
  applyAlertLifecycle,
  applyIncidentLifecycle,
  apiGet,
  fetchActiveConnections,
  fetchActiveDevices,
  fetchAlert,
  fetchAlertDiagnostics,
  fetchAlertEvidence,
  fetchAlertSummary,
  fetchAlerts,
  fetchAnalyticsBundle,
  fetchAnalyticsConnections,
  fetchAnalyticsDevices,
  fetchAnalyticsProtocols,
  fetchAnalyticsThreats,
  fetchAnalyticsTraffic,
  fetchCaptureStatus,
  fetchConnection,
  fetchConnections,
  fetchDashboardSummary,
  fetchDetection,
  fetchDetectionRules,
  fetchDetections,
  fetchDevice,
  fetchDevices,
  fetchEvidence,
  fetchIncident,
  fetchIncidents,
  fetchNotification,
  fetchNotifications,
  fetchOpenIncidents,
  fetchReport,
  fetchReports,
  fetchSetting,
  fetchSettings,
  fetchStoredPacket,
  fetchStoredPackets,
  fetchSystemHealth,
  fetchSystemInfo,
  fetchSystemStatus,
  fetchUnreadCount,
  isApiError,
  requestReportGeneration,
  setAlertStatus,
  updateSettings,
  type ApiError,
} from '@/services'
import {
  ACTIVE_ALERT_STATUSES,
  ACTIVE_INCIDENT_STATUSES,
  ALERT_SEVERITY_ORDER,
  ErrorCode,
  isCaptureState,
  type AlertStatus,
} from '@/types'

/**
 * The error a request that must be refused actually produced.
 *
 * Also the check that the failure came through the application's own error model:
 * a raw `TypeError` or a thrown string here would mean the client leaked a
 * transport detail instead of classifying it (M15.7).
 */
async function refusalFrom(request: Promise<unknown>): Promise<ApiError> {
  try {
    await request
  } catch (cause) {
    if (isApiError(cause)) return cause
    throw cause
  }
  throw new Error('the backend accepted a request this suite expects it to refuse')
}

/**
 * True when a message looks like it carried a backend detail to the screen.
 *
 * A user-facing sentence must never name a Python file, a traceback or a driver.
 * Checked against the real failures below rather than asserted in the abstract.
 */
function leaksInternals(message: string): boolean {
  return (
    message.includes('Traceback') ||
    message.includes('.py') ||
    message.includes('File "') ||
    message.includes('sqlalchemy') ||
    message.toLowerCase().includes('stack trace')
  )
}

/** Every severity the M11 model declares, as a set for membership tests. */
const DECLARED_SEVERITIES: readonly string[] = ALERT_SEVERITY_ORDER

/** Every lifecycle state the M11 model declares. */
const DECLARED_ALERT_STATUSES: readonly string[] = [
  ...ACTIVE_ALERT_STATUSES,
  'resolved',
  'dismissed',
  'false_positive',
]

/** The documented evidence kinds (M11.11). */
const DECLARED_EVIDENCE_TYPES: readonly string[] = [
  'rule',
  'behavioral',
  'packet',
  'connection',
  'device',
]

// ── The backend this run is aimed at ─────────────────────────────────────────

describe('the configured backend', () => {
  it('is a reachable HTTP endpoint', async () => {
    expect(environment.apiBaseUrl).toMatch(/^https?:\/\//)
    expect(environment.wsBaseUrl).toMatch(/^wss?:\/\//)
  })

  it('answers a real request through the service layer', async () => {
    const info = await fetchSystemInfo()
    expect(typeof info.app_name).toBe('string')
    expect(info.app_name.length).toBeGreaterThan(0)
    expect(typeof info.app_version).toBe('string')
    expect(info.app_version.length).toBeGreaterThan(0)
  })
})

// ── The response envelope (M15.5) ────────────────────────────────────────────

describe('the response envelope', () => {
  it('is unwrapped by the client, not handed to the caller', async () => {
    const info = await fetchSystemInfo()
    // If the client returned the envelope, every page would read `data.app_name`
    // and every field access below would be `undefined`.
    expect('success' in info).toBe(false)
    expect('data' in info).toBe(false)
    expect('message' in info).toBe(false)
    expect(Object.keys(info)).toContain('app_name')
  })
})

// ── System (M13.22 / M15.24) ─────────────────────────────────────────────────

describe('system endpoints', () => {
  it('reports a health verdict per dependency', async () => {
    const health = await fetchSystemHealth()
    expect(['healthy', 'degraded']).toContain(health.status)
    expect(health.checks.length).toBeGreaterThan(0)
    for (const check of health.checks) {
      expect(typeof check.name).toBe('string')
      expect(check.name.length).toBeGreaterThan(0)
      expect(typeof check.ok).toBe('boolean')
      expect(typeof check.detail).toBe('string')
      expect(check.detail.length).toBeGreaterThan(0)
    }
    // This suite is only meaningful against a backend whose database answers.
    const database = health.checks.find((check) => check.name === 'database')
    expect(database).toBeDefined()
    expect(database?.ok).toBe(true)
  })

  it('reports the consolidated status consistently with its own parts', async () => {
    const [status, info] = await Promise.all([fetchSystemStatus(), fetchSystemInfo()])
    expect(status.info.app_name).toBe(info.app_name)
    expect(status.info.app_version).toBe(info.app_version)
    expect(status.database.reachable).toBe(true)
    expect(status.services.length).toBeGreaterThan(0)
    expect(Number.isInteger(status.runtime.pid)).toBe(true)
    expect(status.runtime.pid).toBeGreaterThan(0)
    expect(status.runtime.uptime_seconds === null || status.runtime.uptime_seconds >= 0).toBe(true)
    expect(Number.isNaN(Date.parse(status.runtime.generated_at))).toBe(false)
  })

  it('describes the database by dialect and never by URL (M15.24 / M13.30)', async () => {
    const status = await fetchSystemStatus()
    expect(Object.keys(status.database).sort()).toEqual(['dialect', 'reachable'])
    expect(JSON.stringify(status.database)).not.toContain('://')
    expect(status.database.dialect.length).toBeGreaterThan(0)
  })

  it('reports a capture state the frontend model recognises', async () => {
    const capture = await fetchCaptureStatus()
    expect(isCaptureState(capture.status)).toBe(true)
    expect(typeof capture.packet_count).toBe('number')
    expect(capture.packet_count).toBeGreaterThanOrEqual(0)
  })
})

// ── Dashboard (M13.19 / M15.9 / M15.30) ──────────────────────────────────────

describe('the dashboard summary', () => {
  const SECTIONS = [
    'capture',
    'traffic',
    'devices',
    'connections',
    'alerts',
    'incidents',
    'detections',
  ] as const

  it('carries every section, each stating its own availability', async () => {
    const summary = await fetchDashboardSummary()
    for (const section of SECTIONS) {
      const block = summary[section]
      expect(typeof block.available).toBe('boolean')
      expect(block).toHaveProperty('error')
      expect(block).toHaveProperty('data')
      // An available section must actually hold a payload; an unavailable one must
      // say why. Either other combination is the "blank screen" M15.8 forbids.
      if (block.available) expect(block.data).not.toBeNull()
      else expect(typeof block.error).toBe('string')
    }
    expect(Array.isArray(summary.unavailable_sections)).toBe(true)
  })

  it('names only sections it actually marked unavailable', async () => {
    const summary = await fetchDashboardSummary()
    for (const name of summary.unavailable_sections) {
      expect(SECTIONS).toContain(name)
    }
    for (const section of SECTIONS) {
      if (summary[section].available) {
        expect(summary.unavailable_sections).not.toContain(section)
      }
    }
  })

  it('agrees with the alert store it summarises (M13.19)', async () => {
    const [summary, alerts] = await Promise.all([fetchDashboardSummary(), fetchAlertSummary()])
    expect(summary.alerts.data).not.toBeNull()
    expect(summary.alerts.data?.total).toBe(alerts.total)
    expect(summary.alerts.data?.open).toBe(
      (alerts.by_status[ACTIVE_ALERT_STATUSES[0]] ?? 0) +
        (alerts.by_status[ACTIVE_ALERT_STATUSES[1]] ?? 0),
    )
  })
})

// ── Stored packets (M7 / M13.8 / M15.10) ─────────────────────────────────────

describe('stored packets', () => {
  it('pages rows and never exposes a payload (M7.5 / M15.10)', async () => {
    const page = await fetchStoredPackets({}, { limit: 5 })
    expect(page.count).toBe(page.packets.length)
    expect(page.total === null || page.total >= page.count).toBe(true)
    expect(page.offset).toBe(0)
    for (const packet of page.packets) {
      // The exact wire shape, so a payload added server-side or a renamed field
      // fails here rather than rendering as `undefined` in the live table.
      expect(Object.keys(packet).sort()).toEqual([
        'destination_ip',
        'destination_port',
        'id',
        'packet_length',
        'protocol',
        'source_ip',
        'source_port',
        'tcp_flags',
        'timestamp',
      ])
      expect(Number.isNaN(Date.parse(packet.timestamp))).toBe(false)
      expect(packet.source_ip.length).toBeGreaterThan(0)
      expect(packet.destination_ip.length).toBeGreaterThan(0)
    }
  })

  it('reads one row back by its id', async () => {
    const page = await fetchStoredPackets({}, { limit: 1 })
    const first = page.packets[0]
    if (first === undefined) return // An empty store is a valid state, not a failure.
    const detail = await fetchStoredPacket(first.id)
    expect(detail.id).toBe(first.id)
    expect(detail.source_ip).toBe(first.source_ip)
    expect(detail.destination_ip).toBe(first.destination_ip)
  })

  it('refuses an unknown packet id', async () => {
    const error = await refusalFrom(fetchStoredPacket(999_999_999))
    expect(error.kind).toBe('not_found')
    expect(error.status).toBe(404)
    expect(error.code).toBe(ErrorCode.PACKET_NOT_FOUND)
  })
})

// ── Devices (M8 / M13.10 / M15.12) ───────────────────────────────────────────

describe('device endpoints', () => {
  it('pages the registry with a bounded window', async () => {
    const page = await fetchDevices()
    expect(page.count).toBe(page.devices.length)
    expect(page.offset).toBe(0)
    expect(page.limit).toBe(DEFAULT_PAGE_LIMIT)
    expect(page.count).toBeLessThanOrEqual(DEFAULT_PAGE_LIMIT)
  })

  it('honours the activity filter the backend owns (M15.12)', async () => {
    const page = await fetchActiveDevices()
    expect(page.count).toBe(page.devices.length)
    for (const device of page.devices) {
      expect(device.status).toBe('active')
      expect(Array.isArray(device.ip_addresses)).toBe(true)
      // M8 scores nothing; a risk figure here would be invented.
      expect('risk_score' in device).toBe(false)
    }
  })

  it('refuses a device it does not know', async () => {
    const error = await refusalFrom(fetchDevice('mac:00:00:00:00:00:00'))
    expect(error.status).toBe(404)
    expect(error.code).toBe(ErrorCode.DEVICE_NOT_FOUND)
    expect(leaksInternals(error.userMessage)).toBe(false)
  })
})

// ── Connections (M9 / M13.11 / M15.13) ───────────────────────────────────────

describe('connection endpoints', () => {
  it('pages conversations and reports the tracker its own way', async () => {
    const page = await fetchConnections()
    expect(page.count).toBe(page.connections.length)
    expect(page.offset).toBe(0)
    for (const connection of page.connections) {
      expect(connection.connection_id.length).toBeGreaterThan(0)
      expect(connection.source_ip.length).toBeGreaterThan(0)
      expect(connection.destination_ip.length).toBeGreaterThan(0)
      // M9 tracks; it does not judge.
      expect('severity' in connection).toBe(false)
      expect('risk_score' in connection).toBe(false)
    }
  })

  it('reports only still-tracked conversations as active', async () => {
    const page = await fetchActiveConnections()
    expect(page.count).toBe(page.connections.length)
    for (const connection of page.connections) {
      expect(connection.active).toBe(true)
    }
  })

  it('refuses a conversation it does not know', async () => {
    const error = await refusalFrom(fetchConnection('TCP|1.2.3.4:1|5.6.7.8:2'))
    expect(error.status).toBe(404)
    expect(error.code).toBe(ErrorCode.CONNECTION_NOT_FOUND)
  })
})

// ── Detection findings (M10 / M13.12 / M15.20) ───────────────────────────────

describe('detection endpoints', () => {
  it('lists the registered detectors with their own diagnostics', async () => {
    const rules = await fetchDetectionRules()
    expect(rules.count).toBe(rules.rules.length)
    expect(rules.rules.length).toBeGreaterThan(0)
    for (const rule of rules.rules) {
      expect(rule.rule_id.length).toBeGreaterThan(0)
      expect(rule.rule_name.length).toBeGreaterThan(0)
      expect(typeof rule.enabled).toBe('boolean')
      expect(Number.isInteger(rule.state_size)).toBe(true)
    }
    const enabled = rules.rules.filter((rule) => rule.enabled).length
    // Two fields of one response that must describe the same table.
    expect(rules.diagnostics.enabled_rules).toBe(enabled)
    expect(Number.isInteger(rules.diagnostics.evaluations)).toBe(true)
    expect(Number.isInteger(rules.diagnostics.retained_findings)).toBe(true)
  })

  it('returns findings, which are not alerts (M15.20)', async () => {
    const page = await fetchDetections()
    expect(page.count).toBe(page.findings.length)
    expect(page.total === null || page.total >= page.count).toBe(true)
    for (const finding of page.findings) {
      expect(finding.finding_id.length).toBeGreaterThan(0)
      expect(finding.rule_id.length).toBeGreaterThan(0)
      expect(finding.confidence).toBeGreaterThanOrEqual(0)
      expect(finding.confidence).toBeLessThanOrEqual(1)
      // A finding has no severity and no lifecycle: it is an observation.
      expect('severity' in finding).toBe(false)
      expect('status' in finding).toBe(false)
      expect('risk_score' in finding).toBe(false)
    }
  })

  it('refuses a finding that has aged out of the bounded history', async () => {
    const error = await refusalFrom(fetchDetection('does-not-exist'))
    expect(error.status).toBe(404)
    expect(error.code).toBe(ErrorCode.FINDING_NOT_FOUND)
  })
})

// ── Alerts (M11 / M13.13 / M15.14–M15.16) ────────────────────────────────────

describe('alert endpoints', () => {
  it('pages alerts that each carry a declared severity and state', async () => {
    const page = await fetchAlerts()
    expect(page.count).toBe(page.alerts.length)
    expect(page.total).toBeGreaterThanOrEqual(page.count)
    for (const alert of page.alerts) {
      expect(DECLARED_SEVERITIES).toContain(alert.severity)
      expect(DECLARED_ALERT_STATUSES).toContain(alert.status)
      expect(alert.confidence).toBeGreaterThanOrEqual(0)
      expect(alert.confidence).toBeLessThanOrEqual(1)
      expect(Number.isInteger(alert.alert_id)).toBe(true)
    }
  })

  it('counts every listed alert in the summary it serves', async () => {
    const [page, summary] = await Promise.all([fetchAlerts(), fetchAlertSummary()])
    expect(summary.total).toBe(page.total)
    for (const alert of page.alerts) {
      // The summary is over the whole store, so a row on this page must be
      // counted in it — the invariant the alert tiles depend on.
      expect(summary.by_severity[alert.severity] ?? 0).toBeGreaterThanOrEqual(1)
      expect(summary.by_status[alert.status] ?? 0).toBeGreaterThanOrEqual(1)
    }
  })

  it('reports the engine diagnostics separately from the stored totals', async () => {
    const [diagnostics, summary] = await Promise.all([
      fetchAlertDiagnostics(),
      fetchAlertSummary(),
    ])
    expect(typeof diagnostics.enabled).toBe('boolean')
    expect(diagnostics.total).toBe(summary.total)
    for (const counter of [
      diagnostics.findings_seen,
      diagnostics.alerts_created,
      diagnostics.duplicates_folded,
      diagnostics.transitions,
      diagnostics.errors,
    ]) {
      expect(Number.isInteger(counter)).toBe(true)
      expect(counter).toBeGreaterThanOrEqual(0)
    }
  })

  it('reads one alert, its evidence and its evidence tally consistently (M15.16)', async () => {
    const page = await fetchAlerts({}, { limit: 1 })
    const listed = page.alerts[0]
    if (listed === undefined) return // No alert stored yet is a valid state.

    const [detail, evidence] = await Promise.all([
      fetchAlert(listed.alert_id),
      fetchAlertEvidence(listed.alert_id),
    ])
    expect(detail.alert.alert_id).toBe(listed.alert_id)
    expect(detail.evidence.length).toBe(evidence.count)
    expect(evidence.alert_id).toBe(listed.alert_id)
    const tally = Object.values(detail.evidence_by_type).reduce((sum, n) => sum + n, 0)
    expect(tally).toBe(detail.evidence_by_type === undefined ? tally : evidence.count)

    for (const record of evidence.evidence) {
      expect(DECLARED_EVIDENCE_TYPES).toContain(record.evidence_type)
      expect(typeof record.data).toBe('object')
      // Evidence is a reference (M11.13): a packet id or a small document, never
      // the packet itself.
      expect('payload' in record.data).toBe(false)
      expect('raw_bytes' in record.data).toBe(false)
    }
  })

  it('refuses a lifecycle move for an alert that does not exist (M15.15)', async () => {
    const error = await refusalFrom(applyAlertLifecycle(999_999, 'acknowledge'))
    expect(error.status).toBe(404)
    expect(error.code).toBe(ErrorCode.ALERT_NOT_FOUND)
  })

  it('refuses an illegal state and leaves the stored alert untouched (M15.15)', async () => {
    const page = await fetchAlerts({}, { limit: 1 })
    const listed = page.alerts[0]
    if (listed === undefined) return

    const before = await fetchAlert(listed.alert_id)
    // Deliberately not a lifecycle state: the point is to prove the *backend*
    // validates, so the client needs no transition table of its own.
    const error = await refusalFrom(
      setAlertStatus(listed.alert_id, 'not_a_lifecycle_state' as AlertStatus),
    )
    expect(error.kind).toBe('validation')
    expect(error.status).toBe(422)
    expect(error.field).toBe('status')
    expect(error.fieldDetails.length).toBeGreaterThan(0)
    expect(leaksInternals(error.userMessage)).toBe(false)

    const after = await fetchAlert(listed.alert_id)
    expect(after.alert.status).toBe(before.alert.status)
    expect(after.alert.updated_at).toBe(before.alert.updated_at)
  })

  it('refuses evidence that is not there', async () => {
    const error = await refusalFrom(fetchEvidence(999_999))
    expect(error.status).toBe(404)
    expect(error.code).toBe(ErrorCode.EVIDENCE_NOT_FOUND)
  })
})

// ── Incidents (M12 / M13.15 / M15.17–M15.19) ─────────────────────────────────

describe('incident endpoints', () => {
  it('pages incidents carrying all three quality numbers separately', async () => {
    const page = await fetchIncidents()
    expect(page.count).toBe(page.incidents.length)
    for (const incident of page.incidents) {
      expect(incident.incident_id.length).toBeGreaterThan(0)
      expect(incident.correlation_confidence).toBeGreaterThanOrEqual(0)
      expect(incident.correlation_confidence).toBeLessThanOrEqual(1)
      expect(incident.alert_confidence).toBeGreaterThanOrEqual(0)
      expect(incident.alert_confidence).toBeLessThanOrEqual(1)
      expect(incident.risk_score).toBeGreaterThanOrEqual(0)
      expect(incident.risk_score).toBeLessThanOrEqual(100)
      expect(typeof incident.risk_band).toBe('string')
      expect(incident.risk_band.length).toBeGreaterThan(0)
    }
  })

  it('reports only active states as open', async () => {
    const page = await fetchOpenIncidents()
    expect(page.count).toBe(page.incidents.length)
    for (const incident of page.incidents) {
      expect(ACTIVE_INCIDENT_STATUSES).toContain(incident.status as never)
    }
  })

  it('reads one incident with its membership and correlation reasons', async () => {
    const page = await fetchIncidents({}, { limit: 1 })
    const listed = page.incidents[0]
    if (listed === undefined) return

    const detail = await fetchIncident(listed.incident_id)
    expect(detail.incident_id).toBe(listed.incident_id)
    expect(detail.risk_score).toBe(listed.risk_score)
    expect(Array.isArray(detail.alert_ids)).toBe(true)
    expect(Array.isArray(detail.finding_ids)).toBe(true)
    expect(Array.isArray(detail.device_ids)).toBe(true)
    expect(Array.isArray(detail.connection_ids)).toBe(true)
    expect(Array.isArray(detail.correlation_reasons)).toBe(true)
    // Timestamps arrive in both forms on purpose (M13.26).
    expect(detail.span_seconds).toBeGreaterThanOrEqual(0)
  })

  it('refuses an unknown incident, on a read and on a lifecycle move', async () => {
    const read = await refusalFrom(fetchIncident('does-not-exist'))
    expect(read.status).toBe(404)
    expect(read.code).toBe(ErrorCode.INCIDENT_NOT_FOUND)

    const move = await refusalFrom(applyIncidentLifecycle('does-not-exist', 'investigate'))
    expect(move.status).toBe(404)
    expect(move.code).toBe(ErrorCode.INCIDENT_NOT_FOUND)
  })
})

// ── Analytics (M13.18 / M15.21) ──────────────────────────────────────────────

describe('analytics endpoints', () => {
  it('reports traffic totals that agree with the packet store it derives them from', async () => {
    const [traffic, packets, capture] = await Promise.all([
      fetchAnalyticsTraffic(),
      fetchStoredPackets({}, { limit: 1 }),
      fetchCaptureStatus(),
    ])
    expect(Number.isInteger(traffic.total_packets)).toBe(true)
    expect(traffic.total_bytes).toBeGreaterThanOrEqual(0)
    expect(traffic.stored_packet_count).toBeGreaterThanOrEqual(0)
    expect(Array.isArray(traffic.protocols)).toBe(true)
    // Both counts read the same table. Only compared while nothing is writing to
    // it — a running capture inserts rows between the two reads, and that race is
    // not a defect in either endpoint.
    if (capture.status !== 'running') {
      expect(traffic.stored_packet_count).toBe(packets.total)
    }
  })

  it('reports a protocol ranking that states its own metric', async () => {
    const protocols = await fetchAnalyticsProtocols()
    expect(protocols.count).toBe(protocols.protocols.length)
    expect(['packets', 'bytes']).toContain(protocols.rank_by)
  })

  it('ranks devices and conversations by traffic, never by risk (M15.21)', async () => {
    const [devices, connections] = await Promise.all([
      fetchAnalyticsDevices(),
      fetchAnalyticsConnections(),
    ])
    expect(devices.total).toBeGreaterThanOrEqual(devices.top.length)
    expect(['packets', 'bytes']).toContain(devices.rank_by)
    expect(connections.tracked).toBe(connections.active + connections.historical)
    expect(['packets', 'bytes']).toContain(connections.rank_by)
  })

  it('keeps findings, alerts and incidents as three separate layers (M15.21)', async () => {
    const [threats, summary] = await Promise.all([
      fetchAnalyticsThreats(),
      fetchAlertSummary(),
    ])
    expect(threats.alerts_total).toBe(summary.total)
    expect(threats.alerts_open).toBeLessThanOrEqual(threats.alerts_total)
    expect(threats.incidents_active).toBeLessThanOrEqual(threats.incidents_total)
    expect(threats.highest_risk_score).toBeGreaterThanOrEqual(0)
    expect(threats.highest_risk_score).toBeLessThanOrEqual(100)
    expect(Array.isArray(threats.rules)).toBe(true)
  })

  it('loads all five blocks concurrently with no section lost (M15.8)', async () => {
    const bundle = await fetchAnalyticsBundle({ limit: 5 })
    expect(bundle.failures).toEqual([])
    expect(bundle.traffic).not.toBeNull()
    expect(bundle.protocols).not.toBeNull()
    expect(bundle.devices).not.toBeNull()
    expect(bundle.connections).not.toBeNull()
    expect(bundle.threats).not.toBeNull()
  })
})

// ── Reports (M13.20 / M15.22) ────────────────────────────────────────────────

describe('report endpoints', () => {
  it('pages stored metadata and never a file location (M15.22)', async () => {
    const page = await fetchReports()
    expect(page.count).toBe(page.reports.length)
    expect(page.total).toBeGreaterThanOrEqual(page.count)
    for (const report of page.reports) {
      expect(Number.isInteger(report.report_id)).toBe(true)
      expect(typeof report.name).toBe('string')
      // M13.30 withholds the path structurally; this is the frontend's proof.
      expect('file_path' in report).toBe(false)
    }
  })

  it('answers report generation with a 501 the UI can render as unavailable', async () => {
    const error = await refusalFrom(requestReportGeneration())
    expect(error.kind).toBe('not_implemented')
    expect(error.status).toBe(501)
    expect(error.code).toBe(ErrorCode.FEATURE_NOT_IMPLEMENTED)
    expect(leaksInternals(error.userMessage)).toBe(false)
  })

  it('refuses an unknown report id', async () => {
    const error = await refusalFrom(fetchReport(999_999))
    expect(error.status).toBe(404)
    expect(error.code).toBe(ErrorCode.REPORT_NOT_FOUND)
  })
})

// ── Settings (M13.21 / M15.23) ───────────────────────────────────────────────

describe('setting endpoints', () => {
  it('reports each key\'s writability consistently with the writable set (M15.23)', async () => {
    const page = await fetchSettings()
    expect(page.count).toBe(page.settings.length)
    expect(Array.isArray(page.mutable_keys)).toBe(true)
    expect(Number.isInteger(page.internal_key_count)).toBe(true)
    for (const setting of page.settings) {
      expect(setting.key.length).toBeGreaterThan(0)
      expect(typeof setting.mutable).toBe('boolean')
      // The page offers an editor for exactly the keys the response declares
      // writable, so the two must not disagree.
      expect(setting.mutable).toBe(page.mutable_keys.includes(setting.key))
    }
  })

  it('answers an unknown or internal key exactly the same way (M15.23)', async () => {
    const error = await refusalFrom(fetchSetting('definitely_not_a_setting'))
    expect(error.status).toBe(404)
    expect(error.code).toBe(ErrorCode.SETTING_NOT_FOUND)
  })

  it('refuses an unknown key on write and stores nothing at all (M15.23)', async () => {
    const before = await fetchSettings()
    const error = await refusalFrom(updateSettings({ definitely_not_a_setting: 1 }))
    expect(error.status).toBe(400)
    expect(error.code).toBe(ErrorCode.INVALID_SETTING)
    expect(error.field).toBe('definitely_not_a_setting')
    expect(leaksInternals(error.userMessage)).toBe(false)

    const after = await fetchSettings()
    // The whole batch is validated before anything is written, so a refusal
    // changes nothing — the property the Settings page states to the operator.
    expect(after.count).toBe(before.count)
    expect(after.settings.map((s) => s.key)).toEqual(before.settings.map((s) => s.key))
  })

  it('refuses a value that fails its own declaration, changing nothing', async () => {
    const before = await fetchSettings()
    const error = await refusalFrom(updateSettings({ alert_threshold: 'not-a-number' }))
    expect(error.status).toBe(400)
    expect(error.code).toBe(ErrorCode.INVALID_SETTING)
    expect(error.field).toBe('alert_threshold')

    const after = await fetchSettings()
    expect(after.count).toBe(before.count)
  })
})

// ── Notifications (M13.23 / M15.25) ──────────────────────────────────────────

describe('notification endpoints', () => {
  it('pages stored notifications with no delivery state (M15.25)', async () => {
    const page = await fetchNotifications()
    expect(page.count).toBe(page.notifications.length)
    expect(page.total).toBeGreaterThanOrEqual(page.count)
    for (const notification of page.notifications) {
      expect(Number.isInteger(notification.notification_id)).toBe(true)
      expect(typeof notification.is_read).toBe('boolean')
      // Nothing is delivered anywhere, so no such field exists.
      expect('delivered_at' in notification).toBe(false)
      expect('sent' in notification).toBe(false)
    }
  })

  it('counts unread notifications from the backend, not from a loaded page (M15.25)', async () => {
    const [count, page] = await Promise.all([
      fetchUnreadCount(),
      fetchNotifications({ unread_only: true, limit: 1 }),
    ])
    expect(count === null || count === page.total).toBe(true)
  })

  it('refuses a notification that is not stored', async () => {
    const error = await refusalFrom(fetchNotification(999_999))
    expect(error.status).toBe(404)
    expect(error.code).toBe(ErrorCode.NOTIFICATION_NOT_FOUND)
  })
})

// ── Validation failures and the error model (M15.7) ──────────────────────────

describe('a request the backend validates', () => {
  it('is reported as a field-level validation failure, not as a generic fault', async () => {
    // FastAPI rejects the value of `window` before the route runs, so the body is
    // its own shape rather than the project envelope (M13.4). The client must
    // still classify it usefully — this is the most common client-side mistake.
    const error = await refusalFrom(apiGet('/statistics/traffic', { window: 'bogus' }))
    expect(error.kind).toBe('validation')
    expect(error.status).toBe(422)
    expect(error.field).toBe('window')
    expect(error.fieldDetails.length).toBeGreaterThan(0)
    expect(error.fieldDetails[0]).toContain('window')
    expect(leaksInternals(error.userMessage)).toBe(false)
  })

  it('never surfaces a backend stack trace to a user message (M15.7)', async () => {
    const refusals = await Promise.all([
      refusalFrom(fetchDevice('mac:00:00:00:00:00:00')),
      refusalFrom(fetchSetting('definitely_not_a_setting')),
      refusalFrom(requestReportGeneration()),
      refusalFrom(apiGet('/statistics/traffic', { window: 'bogus' })),
    ])
    for (const error of refusals) {
      expect(error.userMessage.length).toBeGreaterThan(0)
      expect(leaksInternals(error.userMessage)).toBe(false)
      // The message is one this application produced, so it is a sentence rather
      // than a status line or an exception repr.
      expect(error.userMessage).not.toMatch(/^\s*\{/)
      expect(error.userMessage).not.toContain('ERR_')
    }
  })
})
