/**
 * Analytics — five derived views that are read, never recomputed (M15.21, M15.38).
 *
 * Three rules from M15.21 shape these tests:
 *
 * * **Every figure comes from the endpoint that owns it.** The page asks five
 *   endpoints and does no arithmetic; the request assertions check the window,
 *   the limit and the ranking metric actually travel on the wire.
 * * **A ranking is traffic, not risk.** Device and connection rankings carry
 *   packet and byte totals, so the only place a score may appear on this page is
 *   the incident block, which M12 owns.
 * * **A section failure is per-section.** A broken block shows its own placeholder
 *   while the other four render — the whole page must not blank for one endpoint.
 */

import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { DEFAULT_ANALYTICS_LIMIT } from '@/services'
import type {
  AnalyticsConnections,
  AnalyticsDevices,
  AnalyticsPeriod,
  AnalyticsProtocols,
  AnalyticsSection,
  AnalyticsThreats,
  AnalyticsTraffic,
  DeviceWindowData,
  DirectionStat,
  FindingsSummary,
  IncidentLinkage,
  ProtocolStat,
  RankedConnection,
  RankedDevice,
  StoredAlertsData,
  StoredConnectionsData,
  StoredProtocolsData,
  StoredTrafficData,
  ThreatRuleStat,
  TopEntry,
} from '@/types'
import Analytics from '@/pages/Analytics'
import { failure, installFetch, networkDownFetch, ok, type RouteTable } from '@/test/harness'

/** One ranked address/port entry. */
function top(key: string, packets: number, bytes: number): TopEntry {
  return { key, packets, bytes }
}

/** One protocol share, with the percentage M6 computed. */
function protocol(name: string, packets: number, percentage: number): ProtocolStat {
  return { protocol: name, packets, bytes: 1_500_000, percentage }
}

/** One direction total. */
function direction(name: DirectionStat['direction'], packets: number): DirectionStat {
  return { direction: name, packets, bytes: 1_048_576 }
}

/**
 * The window the M16 blocks were read over, as every response now reports it
 * (M16.7). The M15 page does not render it; the fixtures carry it because the
 * contract does, and a fixture that omitted it would no longer describe a
 * response the backend can send.
 */
function period(overrides: Partial<AnalyticsPeriod> = {}): AnalyticsPeriod {
  return {
    since: '2026-08-10T09:00:00Z',
    until: '2026-08-10T10:00:00Z',
    seconds: 3600,
    bucket_seconds: 60,
    buckets: 60,
    max_buckets: 120,
    defaulted: true,
    ...overrides,
  }
}

/** One block that answered, wrapping the payload it returned (M16.8). */
function section<T>(data: T): AnalyticsSection<T> {
  return { available: true, error: null, data }
}

/** The windowed `packets`-table block inside `GET /analytics/traffic` (M16.2). */
function storedTraffic(overrides: Partial<StoredTrafficData> = {}): StoredTrafficData {
  return {
    total_packets: 900,
    total_bytes: 1_530_000,
    packets_per_second: 0.25,
    bytes_per_second: 425,
    average_packet_bytes: 1700,
    first_timestamp: '2026-08-10T09:01:00Z',
    last_timestamp: '2026-08-10T09:59:00Z',
    distinct_protocols: 1,
    packets_without_source_port: 0,
    packets_without_destination_port: 0,
    stored_packet_count: 900,
    series: [{ start: '2026-08-10T09:00:00Z', packets: 900, bytes: 1_530_000 }],
    top_sources: [top('10.0.0.5', 500, 700_000)],
    top_destinations: [top('10.0.0.9', 400, 600_000)],
    top_ports: [top('443', 300, 500_000)],
    protocols: [protocol('TCP', 1000, 81)],
    ...overrides,
  }
}

/** The windowed `packets`-table block inside `GET /analytics/protocols` (M16.3). */
function storedProtocols(overrides: Partial<StoredProtocolsData> = {}): StoredProtocolsData {
  return {
    count: 1,
    distinct_protocols: 1,
    truncated: false,
    total_packets: 1234,
    total_bytes: 2_097_152,
    rank_by: 'packets',
    protocols: [protocol('TCP', 1000, 81)],
    ...overrides,
  }
}

/** The re-filtered M8 registry block inside `GET /analytics/devices` (M16.4). */
function deviceWindow(overrides: Partial<DeviceWindowData> = {}): DeviceWindowData {
  return {
    total: 1,
    by_status: { active: 1 },
    rank_by: 'packets',
    top: [rankedDevice()],
    ...overrides,
  }
}

/** The windowed `connections`-table block in `GET /analytics/connections` (M16.5). */
function storedConnections(
  overrides: Partial<StoredConnectionsData> = {},
): StoredConnectionsData {
  return {
    total: 5,
    active: 2,
    first_timestamp: '2026-08-10T09:00:30Z',
    last_timestamp: '2026-08-10T09:58:00Z',
    by_protocol: { UDP: 5 },
    by_status: { established: 2, closed: 3 },
    duration: { samples: 3, min_seconds: 1.5, mean_seconds: 12.25, max_seconds: 40 },
    series: [{ start: '2026-08-10T09:00:00Z', connections: 5 }],
    top_sources: [top('10.0.0.21', 700, 900_000)],
    top_destinations: [top('10.0.0.9', 700, 900_000)],
    ...overrides,
  }
}

/** The windowed `alerts`-table block inside `GET /analytics/threats` (M16.6). */
function storedAlerts(overrides: Partial<StoredAlertsData> = {}): StoredAlertsData {
  return {
    total: 6,
    without_rule_key: 1,
    first_timestamp: '2026-08-10T09:05:00Z',
    last_timestamp: '2026-08-10T09:55:00Z',
    by_severity: { high: 2, medium: 4 },
    by_status: { open: 3, acknowledged: 2, resolved: 1 },
    by_risk_band: { minimal: 4, high: 2 },
    by_confidence_range: { '70-89': 1 },
    rules: [{ rule_key: 'port_scan', alerts: 5 }],
    series: [{ start: '2026-08-10T09:00:00Z', alerts: 6 }],
    ...overrides,
  }
}

/** The M10 findings still held and inside the window (M16.6). */
function findingsSummary(overrides: Partial<FindingsSummary> = {}): FindingsSummary {
  return {
    retained: 5,
    in_window: 2,
    mean_confidence: 0.74,
    by_confidence_range: { '70-89': 2 },
    by_rule: [{ rule_id: 'port_scan', rule_name: 'Port scan', findings: 2 }],
    ...overrides,
  }
}

/** The alert-to-incident references M12 already holds (M16.6). */
function incidentLinks(overrides: Partial<IncidentLinkage> = {}): IncidentLinkage {
  return {
    incidents_total: 2,
    incidents_with_alerts: 1,
    alerts_in_incidents: 4,
    ...overrides,
  }
}

/** `GET /analytics/traffic` — one M6 snapshot. */
function traffic(overrides: Partial<AnalyticsTraffic> = {}): AnalyticsTraffic {
  return {
    total_packets: 1234,
    total_bytes: 2_097_152,
    // Below ten, so the formatter keeps the decimal and the unit is visible.
    packets_per_second: 8.5,
    bytes_per_second: 20_480,
    bits_per_second: 163_840,
    average_packet_bytes: 1700,
    stored_packet_count: 900,
    protocol_count: 1,
    directions: [direction('inbound', 800)],
    protocols: [protocol('TCP', 1000, 81)],
    top_sources: [top('10.0.0.5', 500, 700_000)],
    top_destinations: [top('10.0.0.9', 400, 600_000)],
    top_ports: [top('443', 300, 500_000)],
    period: period(),
    stored: section(storedTraffic()),
    ...overrides,
  }
}

/** `GET /analytics/protocols` — the same shares, ranked. */
function protocols(overrides: Partial<AnalyticsProtocols> = {}): AnalyticsProtocols {
  return {
    count: 1,
    total_packets: 1234,
    total_bytes: 2_097_152,
    rank_by: 'packets',
    protocols: [protocol('TCP', 1000, 81)],
    period: period(),
    stored: section(storedProtocols()),
    ...overrides,
  }
}

/** One ranked device, from the M8 registry. */
function rankedDevice(overrides: Partial<RankedDevice> = {}): RankedDevice {
  return {
    device_id: 'mac:aa:bb:cc:dd:ee:01',
    mac_address: 'aa:bb:cc:dd:ee:01',
    ip_addresses: ['10.0.0.21'],
    hostname: 'web-01',
    status: 'active',
    first_seen: '2026-08-10T08:00:00Z',
    last_seen: '2026-08-10T09:59:00Z',
    packets: 900,
    bytes: 1_200_000,
    ...overrides,
  }
}

/** `GET /analytics/devices`. */
function devices(overrides: Partial<AnalyticsDevices> = {}): AnalyticsDevices {
  return {
    total: 3,
    by_status: { active: 3 },
    rank_by: 'packets',
    top: [rankedDevice()],
    period: period(),
    windowed: section(deviceWindow()),
    ...overrides,
  }
}

/** One ranked conversation, from the M9 tracker. */
function rankedConnection(overrides: Partial<RankedConnection> = {}): RankedConnection {
  return {
    connection_id: '10.0.0.21:51000|10.0.0.9:443|UDP',
    protocol: 'UDP',
    source_ip: '10.0.0.21',
    source_port: 51_000,
    destination_ip: '10.0.0.9',
    destination_port: 443,
    state: 'established',
    packets: 700,
    bytes: 900_000,
    ...overrides,
  }
}

/** `GET /analytics/connections`. */
function connections(overrides: Partial<AnalyticsConnections> = {}): AnalyticsConnections {
  return {
    active: 2,
    historical: 5,
    tracked: 7,
    rank_by: 'bytes',
    top: [rankedConnection()],
    period: period(),
    stored: section(storedConnections()),
    ...overrides,
  }
}

/** One detector's counters. */
function rule(overrides: Partial<ThreatRuleStat> = {}): ThreatRuleStat {
  return {
    rule_id: 'port_scan',
    rule_name: 'Port scan',
    enabled: true,
    evaluations: 40,
    findings: 2,
    errors: 0,
    ...overrides,
  }
}

/** `GET /analytics/threats` — findings, alerts and incidents side by side. */
function threats(overrides: Partial<AnalyticsThreats> = {}): AnalyticsThreats {
  return {
    alerts_total: 6,
    alerts_open: 3,
    alerts_by_severity: { high: 2 },
    alerts_by_status: { open: 3 },
    findings_retained: 5,
    detections_evaluated: 40,
    detections_findings: 2,
    detections_errors: 0,
    rules: [rule()],
    incidents_total: 2,
    incidents_active: 1,
    incidents_by_status: { open: 1 },
    incidents_by_risk_band: { high: 1 },
    highest_risk_score: 88,
    period: period(),
    stored: section(storedAlerts()),
    findings: findingsSummary(),
    incident_links: incidentLinks(),
    ...overrides,
  }
}

/** Every route the page needs, unless a test overrides one. */
function analyticsRoutes(overrides: RouteTable = {}): RouteTable {
  return {
    'GET /analytics/traffic': () => ok(traffic()),
    'GET /analytics/protocols': () => ok(protocols()),
    'GET /analytics/devices': () => ok(devices()),
    'GET /analytics/connections': () => ok(connections()),
    'GET /analytics/threats': () => ok(threats()),
    ...overrides,
  }
}

describe('Analytics requesting', () => {
  it('reads all five blocks, each with the shared limit and ranking', async () => {
    const router = installFetch(analyticsRoutes())
    render(<Analytics />)

    await waitFor(() => {
      expect(router.countOf('GET /analytics/traffic')).toBe(1)
    })
    for (const path of [
      '/analytics/traffic', '/analytics/protocols', '/analytics/devices',
      '/analytics/connections', '/analytics/threats',
    ]) {
      expect(router.countOf(`GET ${path}`)).toBe(1)
    }

    // The window is the snapshot's own live rate, and the ranking is the default.
    const trafficCall = router.lastCall('GET /analytics/traffic')
    expect(trafficCall?.params['window']).toBe('1s')
    expect(trafficCall?.params['by']).toBe('packets')
    expect(trafficCall?.params['limit']).toBe(String(DEFAULT_ANALYTICS_LIMIT))
    expect(router.lastCall('GET /analytics/devices')?.params['limit'])
      .toBe(String(DEFAULT_ANALYTICS_LIMIT))
    // The page passes its own metric to every ranked block, which overrides the
    // service's default for connections (`bytes`): what the page displays selected
    // is what it asked the backend to rank by.
    expect(router.lastCall('GET /analytics/connections')?.params['by']).toBe('packets')
    expect(router.lastCall('GET /analytics/protocols')?.params['by']).toBe('packets')
  })

  it('re-asks the backend when the ranking metric changes', async () => {
    // `by` is a real query parameter on four endpoints, so switching it is a
    // request rather than a client-side re-sort of rows already held.
    const router = installFetch(analyticsRoutes())
    render(<Analytics />)
    await waitFor(() => {
      expect(router.countOf('GET /analytics/traffic')).toBe(1)
    })

    fireEvent.click(screen.getByRole('button', { name: 'bytes' }))

    await waitFor(() => {
      expect(router.countOf('GET /analytics/traffic')).toBe(2)
    })
    expect(router.lastCall('GET /analytics/traffic')?.params['by']).toBe('bytes')
    expect(router.lastCall('GET /analytics/devices')?.params['by']).toBe('bytes')
    expect(router.lastCall('GET /analytics/connections')?.params['by']).toBe('bytes')
    // The five blocks sit behind one hook, so the metric change re-reads the whole
    // bundle — including `threats`, which takes no ranking. That is an explicit
    // re-read on an operator action, not background polling (M15.34).
    expect(router.countOf('GET /analytics/threats')).toBe(2)
  })
})

describe('Analytics rendering', () => {
  it('renders the totals the snapshot reported, with the backend’s own units', async () => {
    installFetch(analyticsRoutes())
    render(<Analytics />)

    await waitFor(() => {
      expect(screen.getByText('1,234')).toBeInTheDocument()
    })
    // Each value is formatted from the field the backend sent; none is derived here.
    expect(screen.getByText('2.0 MB')).toBeInTheDocument()
    expect(screen.getByText('8.5/s')).toBeInTheDocument()
    expect(screen.getByText('20 KB/s')).toBeInTheDocument()
    expect(screen.getByText('164 Kbps')).toBeInTheDocument()
    expect(screen.getByText('1.7 KB')).toBeInTheDocument()
  })

  it('renders the protocol share as the percentage M6 computed', async () => {
    installFetch(analyticsRoutes())
    render(<Analytics />)
    await waitFor(() => {
      expect(screen.getByText('TCP')).toBeInTheDocument()
    })
    expect(screen.getByText('81%')).toBeInTheDocument()
  })

  it('ranks devices by traffic and shows no score for them', async () => {
    // M8 scores nothing, so the row carries packets and bytes and nothing that
    // reads as a verdict.
    installFetch(analyticsRoutes())
    render(<Analytics />)
    await waitFor(() => {
      expect(screen.getByText('web-01')).toBeInTheDocument()
    })
    const row = screen.getByText('web-01').closest('tr')
    expect(row).not.toBeNull()
    const cells = within(row as HTMLElement)
    expect(cells.getByText('900')).toBeInTheDocument()
    expect(cells.getByText(/10\.0\.0\.21/)).toBeInTheDocument()
    expect(cells.queryByText(/score/i)).toBeNull()
  })

  it('shows a score in exactly one place: the incident block M12 owns', async () => {
    installFetch(analyticsRoutes())
    render(<Analytics />)
    await waitFor(() => {
      expect(screen.getByText('Highest risk score')).toBeInTheDocument()
    })
    expect(screen.getByText('88')).toBeInTheDocument()
    // The two traffic rankings carry no score at all: M8 and M9 produce traffic
    // totals, so a score inside either card would be an invention. The assertion is
    // scoped to the cards because the page's own footer states that absence.
    const devicesCard = screen
      .getByText('Busiest devices').closest('.rounded-2xl') as HTMLElement
    const connectionsCard = screen
      .getByText('Busiest conversations').closest('.rounded-2xl') as HTMLElement
    expect(within(devicesCard).queryByText(/score/i)).toBeNull()
    expect(within(connectionsCard).queryByText(/score/i)).toBeNull()
  })

  it('keeps findings, alerts and incidents as three separate cards', async () => {
    // Collapsing them would invent a single "threat level" no milestone produces.
    installFetch(analyticsRoutes())
    render(<Analytics />)
    await waitFor(() => {
      expect(screen.getByText('Detection findings')).toBeInTheDocument()
    })
    expect(screen.getByText('M10 — observations, not alerts')).toBeInTheDocument()
    expect(screen.getByText('M11 — evidence-based judgement')).toBeInTheDocument()
    expect(screen.getByText('M12 — correlated and prioritised')).toBeInTheDocument()
  })

  it('says there are no trend charts, because nothing stores traffic history', async () => {
    installFetch(analyticsRoutes())
    render(<Analytics />)
    await waitFor(() => {
      expect(screen.getByText(/derived views, not time series/i)).toBeInTheDocument()
    })
  })

  it('shows the empty state for a ranking the backend reported no rows for', async () => {
    installFetch(analyticsRoutes({
      'GET /analytics/devices': () => ok(devices({ total: 0, top: [], by_status: {} })),
      'GET /analytics/connections': () =>
        ok(connections({ tracked: 0, active: 0, historical: 0, top: [] })),
    }))
    render(<Analytics />)
    await waitFor(() => {
      expect(screen.getByText('No devices observed')).toBeInTheDocument()
    })
    expect(screen.getByText('No conversations tracked')).toBeInTheDocument()
  })
})

describe('Analytics section isolation (M15.21/M15.8)', () => {
  it('renders the four blocks that answered when one section fails', async () => {
    installFetch(analyticsRoutes({
      'GET /analytics/protocols': () =>
        failure(500, 'The server failed while handling this request.', [
          { field: 'request', code: 'INTERNAL_ERROR' },
        ]),
    }))
    render(<Analytics />)

    await waitFor(() => {
      expect(screen.getByText(/1 of 5 analytics sections did not answer/i)).toBeInTheDocument()
    })
    // The failed block says which one it is, in its own card.
    expect(screen.getByText('Protocols unavailable')).toBeInTheDocument()
    // And the other four are still on screen.
    expect(screen.getByText('1,234')).toBeInTheDocument()
    expect(screen.getByText('web-01')).toBeInTheDocument()
    expect(screen.getByText('Detection findings')).toBeInTheDocument()
  })

  it('degrades block by block when every block is unreachable', async () => {
    // A bundle that carries five failures is still a bundle: the page names the
    // blocks it could not read rather than claiming analytics is unavailable.
    vi.stubGlobal('fetch', networkDownFetch())
    render(<Analytics />)

    await waitFor(() => {
      expect(screen.getByText(/5 of 5 analytics sections did not answer/i)).toBeInTheDocument()
    })
    // One M6 snapshot feeds five blocks — the totals row, the direction chart and
    // the three rankings — so its placeholder appears in each of them.
    expect(screen.getAllByText('Traffic unavailable')).toHaveLength(5)
    expect(screen.getByText('Threats unavailable')).toBeInTheDocument()
    // Not the whole-page failure: the layout the backend describes is still drawn.
    expect(screen.queryByText('Unable to load analytics')).toBeNull()
  })

  it('re-reads every block when the operator retries after a partial failure', async () => {
    let failNext = true
    const router = installFetch(analyticsRoutes({
      'GET /analytics/protocols': () =>
        failNext
          ? failure(503, '', [{ field: 'service', code: 'SERVICE_UNAVAILABLE' }])
          : ok(protocols()),
    }))
    render(<Analytics />)
    await waitFor(() => {
      expect(screen.getByText('Protocols unavailable')).toBeInTheDocument()
    })

    failNext = false
    fireEvent.click(screen.getByRole('button', { name: /^retry$/i }))

    await waitFor(() => {
      expect(screen.queryByText('Protocols unavailable')).toBeNull()
    })
    expect(router.countOf('GET /analytics/protocols')).toBe(2)
    expect(screen.getByText('81%')).toBeInTheDocument()
  })
})

describe('Analytics loading', () => {
  it('shows a busy panel while the first read is in flight', () => {
    installFetch({
      'GET /analytics/traffic': () => new Promise<Response>(() => {}),
      'GET /analytics/protocols': () => new Promise<Response>(() => {}),
      'GET /analytics/devices': () => new Promise<Response>(() => {}),
      'GET /analytics/connections': () => new Promise<Response>(() => {}),
      'GET /analytics/threats': () => new Promise<Response>(() => {}),
    })
    render(<Analytics />)
    expect(screen.getByText('Loading analytics…')).toBeInTheDocument()
  })
})
