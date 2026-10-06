/**
 * Dashboard — current state read once, movement delivered live (M15.9/M15.30/M15.38).
 *
 * The dashboard has two sources and they answer different questions, so these
 * tests keep them apart rather than asserting a merged number:
 *
 * * `GET /dashboard/summary` is the state the page shows on arrival, per section,
 *   each independently available (M13.19/M13.29);
 * * `/ws/dashboard` is a nine-scalar tick that **overrides** the scalars it covers
 *   and nothing else (M14.9/M15.30).
 *
 * Three consequences are asserted directly, because each is a rule the milestone
 * states and a reader would otherwise have to take on trust:
 *
 * * **A live tick never fills in a hole.** A section the summary reported
 *   unavailable stays unknown until a tick genuinely supplies the number, and
 *   never becomes `0` (M15.9).
 * * **The bit rate is REST-only**, because M14.9's projection does not carry it, so
 *   it keeps its last snapshot value while the counters advance (M15.9).
 * * **A reconnect re-reads REST instead of replaying events** (M15.27), because M14
 *   keeps no per-client buffer.
 *
 * The sockets are driven through the global constructor, because the page
 * subscribes through the application hub and the hub's default factory is
 * `new WebSocket(url)`.
 */

import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { DEFAULT_RECENT_FINDINGS } from '@/services'
import { EventType } from '@/types'
import type {
  DashboardSection, DashboardSummary, DashboardUpdateEvent, DetectionFinding,
} from '@/types'
import Dashboard from '@/pages/Dashboard'
import { UNKNOWN_TEXT } from '@/lib/format'
import {
  MockWebSocket, channelHub, eventFrame, failure, installFetch, networkDownFetch, ok,
  type RouteTable,
} from '@/test/harness'

// ── The socket harness ───────────────────────────────────────────────────────

/** Every socket the hub created through the stubbed constructor, in order. */
const sockets: MockWebSocket[] = []

/** The toast sink the page is given, so a test can assert what it was told. */
const showToast = vi.fn()

/**
 * Replace the global constructor with the controllable fake.
 *
 * `MockWebSocket` already satisfies what `ChannelSocket` duck-types for, so the
 * subclass only has to record the instance.
 */
function installFakeWebSocket(): void {
  vi.stubGlobal(
    'WebSocket',
    class extends MockWebSocket {
      constructor(url: string) {
        super(url)
        sockets.push(this)
      }
    },
  )
}

/** Every socket opened for one channel path. */
function socketsFor(path: string): MockWebSocket[] {
  return sockets.filter((socket) => socket.url.endsWith(path))
}

/** The most recent socket opened for one channel path. */
function socketFor(path: string): MockWebSocket {
  const found = socketsFor(path)
  const last = found[found.length - 1]
  if (last === undefined) throw new Error(`No socket was opened for ${path}.`)
  return last
}

// ── Frames ───────────────────────────────────────────────────────────────────

/** A `dashboard.updated` frame carrying the nine-scalar projection (M14.9). */
function dashboardFrame(data: Record<string, unknown>, eventId?: string): string {
  return eventFrame({
    type: EventType.DASHBOARD_UPDATED,
    channel: 'dashboard',
    source: 'dashboard',
    data,
    ...(eventId === undefined ? {} : { event_id: eventId }),
  })
}

/** A capture lifecycle frame on the system channel (M14.11). */
function captureFrame(
  type: string,
  data: Record<string, unknown>,
  eventId?: string,
): string {
  return eventFrame({
    type,
    channel: 'system',
    source: 'capture.manager',
    data,
    ...(eventId === undefined ? {} : { event_id: eventId }),
  })
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

/** One retained finding, as the summary's detections block carries it (M13.19). */
function finding(overrides: Partial<DetectionFinding> = {}): DetectionFinding {
  return {
    finding_id: 'port_scan:10.0.0.5',
    rule_id: 'port_scan',
    rule_name: 'Port scan',
    description: 'Sequential connection attempts from 10.0.0.5',
    source_ip: '10.0.0.5',
    confidence: 0.8,
    evidence: {},
    metadata: {},
    ...overrides,
  }
}

/** One section the summary reported as readable, holding its payload. */
function section<T>(data: T): DashboardSection<T> {
  return { available: true, error: null, data }
}

/** One section the summary reported it could not read (M13.29). */
function unavailableSection<T>(reason: string): DashboardSection<T> {
  return { available: false, error: reason, data: null }
}

/** `GET /dashboard/summary` — every section present, each available on its own. */
function summary(overrides: Partial<DashboardSummary> = {}): DashboardSummary {
  return {
    generated_at: '2026-01-01T10:00:00+00:00',
    unavailable_sections: [],
    capture: section({
      running: true,
      status: 'running',
      interface: 'eth0',
      packet_count: 4321,
    }),
    traffic: section({
      total_packets: 1000,
      total_bytes: 2_000_000,
      packets_per_second: 8.5,
      bytes_per_second: 20_480,
      bits_per_second: 163_840,
      protocol_count: 3,
    }),
    devices: section({ total: 7, by_status: { active: 6, inactive: 1 } }),
    connections: section({ active: 12, historical: 30, tracked: 42 }),
    alerts: section({
      total: 9,
      open: 4,
      by_severity: { high: 3, low: 6 },
      by_status: { open: 4, resolved: 5 },
    }),
    incidents: section({
      total: 5,
      active: 3,
      highest_risk_score: 88,
      by_status: { open: 3, resolved: 2 },
    }),
    detections: section({ retained: 5, recent: [finding()] }),
    ...overrides,
  }
}

/** The nine scalars `/ws/dashboard` sends, as one backend tick (M14.9). */
const BASE_TICK: DashboardUpdateEvent = {
  capture_running: true,
  interface: 'eth0',
  packet_count: 1000,
  packets_per_second: 8.5,
  bytes_per_second: 20_480,
  device_count: 7,
  active_connections: 12,
  open_alerts: 4,
  active_incidents: 3,
}

/** One tick, with a test overriding only the scalar it is about. */
function tick(overrides: Partial<DashboardUpdateEvent> = {}): Record<string, unknown> {
  return { ...BASE_TICK, ...overrides }
}

/** Every route the page needs, unless a test overrides one. */
function dashboardRoutes(overrides: RouteTable = {}): RouteTable {
  return {
    'GET /dashboard/summary': () => ok(summary()),
    'GET /capture/status': () => ok({ status: 'running', interface: 'eth0', packet_count: 4321 }),
    'GET /capture/interfaces': () => ok([{ name: 'eth0' }]),
    // The documented precondition when nothing has been chosen (M13.6), which the
    // hook treats as "nothing selected" rather than as a failure.
    'GET /capture/interface': () =>
      failure(400, 'No interface has been selected.', [
        { field: 'interface', code: 'NO_INTERFACE_SELECTED' },
      ]),
    ...overrides,
  }
}

/** Render the page with the toast sink a test can inspect. */
function renderDashboard(): void {
  render(<Dashboard showToast={showToast} />)
}

/**
 * The figure inside one KPI card.
 *
 * Read from the card rather than from the page, because the same number can
 * legitimately appear twice — a registry total and a by-status breakdown — and
 * `getByText` would then match two elements for one question.
 */
function kpi(label: string): string {
  const card = screen.getByText(label).closest('.rounded-2xl')
  if (card === null) throw new Error(`No KPI card is labelled ${label}.`)
  const value = (card as HTMLElement).querySelector('div.text-2xl')
  return value?.textContent ?? ''
}

/** The sub-line inside one KPI card — a second figure, from a second unit. */
function kpiSub(label: string): string {
  const card = screen.getByText(label).closest('.rounded-2xl')
  if (card === null) throw new Error(`No KPI card is labelled ${label}.`)
  const sub = (card as HTMLElement).querySelector('div.text-xs.mt-1')
  return sub?.textContent ?? ''
}

/** The value of one item in the SOC status banner. */
function banner(label: string): string {
  const item = screen.getByText(label).closest('div.flex-1')
  if (item === null) throw new Error(`No banner item is labelled ${label}.`)
  const value = (item as HTMLElement).querySelector('span.font-semibold')
  return value?.textContent ?? ''
}

beforeEach(() => {
  sockets.length = 0
  showToast.mockClear()
  installFakeWebSocket()
})
describe('Dashboard requesting', () => {
  it('reads the summary once, with the service’s own recent-finding limit', async () => {
    const router = installFetch(dashboardRoutes())
    renderDashboard()

    await waitFor(() => {
      expect(router.countOf('GET /dashboard/summary')).toBe(1)
    })
    // The limit travels on the wire rather than being applied to a larger page.
    expect(router.lastCall('GET /dashboard/summary')?.params['recent_limit'])
      .toBe(String(DEFAULT_RECENT_FINDINGS))
  })

  it('opens one socket per channel it needs, and no others', async () => {
    // M15.28: the four channels are separate connections and are not multiplexed.
    installFetch(dashboardRoutes())
    renderDashboard()

    await waitFor(() => {
      expect(sockets).toHaveLength(2)
    })
    expect(socketsFor('/ws/dashboard')).toHaveLength(1)
    expect(socketsFor('/ws/system')).toHaveLength(1)
    // The dashboard shows current state and capture control; it reads no packet
    // stream and no alert stream of its own.
    expect(channelHub.subscriberCount('packets')).toBe(0)
    expect(channelHub.subscriberCount('alerts')).toBe(0)
  })

  it('does not re-read REST while the socket is silent', async () => {
    // M15.34: the dashboard channel exists so this page needs no poll. A live tick
    // updates state without a second summary read, which is what this asserts.
    const router = installFetch(dashboardRoutes())
    renderDashboard()
    await waitFor(() => {
      expect(router.countOf('GET /dashboard/summary')).toBe(1)
    })

    act(() => socketFor('/ws/dashboard').open())
    act(() => socketFor('/ws/dashboard').emit(dashboardFrame(tick())))

    expect(router.countOf('GET /dashboard/summary')).toBe(1)
  })
})

describe('Dashboard from REST', () => {
  it('renders every scalar the summary reported', async () => {
    installFetch(dashboardRoutes())
    renderDashboard()

    await waitFor(() => {
      expect(kpi('Packets / sec')).toBe('8.5/s')
    })
    expect(kpi('Throughput')).toBe('20 KB/s')
    expect(kpi('Active Devices')).toBe('7')
    expect(kpi('Connections')).toBe('12')
    expect(kpi('Open Alerts')).toBe('4')
    expect(kpi('Active Incidents')).toBe('3')
    // Before any tick arrives, the page is honest that these are a snapshot.
    expect(screen.getByText('Snapshot')).toBeInTheDocument()
  })

  it('shows the capture state and interface the summary reported', async () => {
    installFetch(dashboardRoutes())
    renderDashboard()

    await waitFor(() => {
      expect(screen.getByText('4,321 pkts')).toBeInTheDocument()
    })
    // The banner names the captured adapter, and the control lists it as an
    // adapter to choose — so the same name legitimately appears in both.
    expect(screen.getAllByText('eth0')).toHaveLength(2)
    expect(screen.getByRole('option', { name: 'eth0' })).toBeInTheDocument()
    expect(banner('Capture')).toBe('Running')
    // No section reported itself unread, so the count is the literal word.
    expect(banner('Sections unavailable')).toBe('None')
    expect(banner('Source')).toBe('Snapshot')
  })

  it('lists the breakdowns the summary carries', async () => {
    installFetch(dashboardRoutes())
    renderDashboard()

    await waitFor(() => {
      expect(screen.getByText('Alerts by Severity')).toBeInTheDocument()
    })
    expect(screen.getByText('Devices by Activity')).toBeInTheDocument()
    expect(screen.getByText('Incidents by Status')).toBeInTheDocument()
    // Severity rows come from the summary's own counted map, ranked by count.
    expect(screen.getByText('high')).toBeInTheDocument()
    expect(screen.getByText('low')).toBeInTheDocument()
    // The incident block is the one place on this page a score belongs (M12).
    expect(screen.getByText('Highest risk score')).toBeInTheDocument()
    expect(screen.getByText('88')).toBeInTheDocument()
    // Every section answered, so there is nothing to report as unavailable.
    expect(screen.getByText('Every section answered.')).toBeInTheDocument()
  })

  it('renders the retained findings the summary included', async () => {
    installFetch(dashboardRoutes())
    renderDashboard()

    await waitFor(() => {
      expect(screen.getByText('Port scan')).toBeInTheDocument()
    })
    expect(
      screen.getByText('Sequential connection attempts from 10.0.0.5'),
    ).toBeInTheDocument()
    expect(screen.getByText('10.0.0.5')).toBeInTheDocument()
  })

  it('shows an empty state for each section that answered with no rows', async () => {
    // An available section holding nothing is not an error and not unavailable: it
    // is the honest report of an idle registry (M13.19).
    installFetch(dashboardRoutes({
      'GET /dashboard/summary': () => ok(summary({
        alerts: section({ total: 0, open: 0, by_severity: {}, by_status: {} }),
        devices: section({ total: 0, by_status: {} }),
        incidents: section({
          total: 0, active: 0, highest_risk_score: 0, by_status: {},
        }),
        detections: section({ retained: 0, recent: [] }),
      })),
    }))
    renderDashboard()

    await waitFor(() => {
      expect(screen.getByText('No alerts recorded')).toBeInTheDocument()
    })
    expect(screen.getByText('No devices observed')).toBeInTheDocument()
    expect(screen.getByText('No incidents correlated')).toBeInTheDocument()
    expect(screen.getByText('No recent findings')).toBeInTheDocument()
    // Empty is not the same as unread, so no unavailable panel appears.
    expect(screen.queryByText('This section could not be read')).toBeNull()
  })
})

describe('Dashboard live updates (M15.30)', () => {
  it('replaces the REST scalars with the ones a tick carries', async () => {
    installFetch(dashboardRoutes())
    renderDashboard()
    await waitFor(() => {
      expect(kpi('Packets / sec')).toBe('8.5/s')
    })

    act(() => socketFor('/ws/dashboard').open())
    act(() => socketFor('/ws/dashboard').emit(dashboardFrame(tick({
      packets_per_second: 42,
      device_count: 11,
      open_alerts: 9,
      packet_count: 2000,
    }))))

    expect(kpi('Packets / sec')).toBe('42/s')
    expect(kpi('Active Devices')).toBe('11')
    expect(kpi('Open Alerts')).toBe('9')
    // The scalars the tick does not carry are untouched by it.
    expect(kpi('Connections')).toBe('12')
    expect(screen.getByText('2,000 captured')).toBeInTheDocument()
    expect(screen.getByText('Live tick')).toBeInTheDocument()
  })

  it('keeps the bit rate from REST, because the tick does not carry one', async () => {
    // M14.9's projection has no `bits_per_second`, so this figure stays the last
    // snapshot reading rather than being derived from `bytes_per_second` (M15.9).
    installFetch(dashboardRoutes())
    renderDashboard()
    await waitFor(() => {
      expect(kpi('Throughput')).toBe('20 KB/s')
    })

    act(() => socketFor('/ws/dashboard').open())
    act(() => socketFor('/ws/dashboard').emit(dashboardFrame(tick({ bytes_per_second: 2048 }))))

    expect(kpi('Throughput')).toBe('2.0 KB/s')
    // The sub-line is still the M6 snapshot's own bit rate.
    expect(screen.getByText('164 Kbps')).toBeInTheDocument()
  })

  it('does not turn an unavailable section’s missing number into zero', async () => {
    // A section the backend could not read is unknown, not idle. The selector may
    // only replace it with a number a tick actually carried (M15.9).
    installFetch(dashboardRoutes({
      'GET /dashboard/summary': () => ok(summary({
        traffic: unavailableSection('The traffic snapshot could not be read.'),
      })),
    }))
    renderDashboard()

    await waitFor(() => {
      expect(kpi('Packets / sec')).toBe(UNKNOWN_TEXT)
    })
    expect(kpi('Throughput')).toBe(UNKNOWN_TEXT)

    // The tick does carry a byte rate, so that figure becomes real — but the bit
    // rate, which no tick carries and which REST had no value for, stays unknown
    // rather than being derived from the byte rate (M14.9/M15.9).
    act(() => socketFor('/ws/dashboard').open())
    act(() => socketFor('/ws/dashboard').emit(dashboardFrame(tick({ packets_per_second: 8.5 }))))

    expect(kpi('Packets / sec')).toBe('8.5/s')
    expect(kpi('Throughput')).toBe('20 KB/s')
    expect(kpiSub('Throughput')).toBe(UNKNOWN_TEXT)
    // And the source of the numbers is now the tick, not the summary.
    expect(banner('Source')).toBe('Live tick')
  })

  it('ignores a frame that is not a dashboard update', async () => {
    installFetch(dashboardRoutes())
    renderDashboard()
    await waitFor(() => {
      expect(kpi('Packets / sec')).toBe('8.5/s')
    })

    act(() => socketFor('/ws/dashboard').open())
    act(() => socketFor('/ws/dashboard').emit(eventFrame({
      type: EventType.PACKET_OBSERVED,
      channel: 'packets',
      data: { packet_id: 1 },
    })))

    // An event of the wrong type is refused rather than half-applied, so nothing
    // on this page moved.
    expect(kpi('Packets / sec')).toBe('8.5/s')
    expect(screen.getByText('Snapshot')).toBeInTheDocument()
  })

  it('applies a redelivered tick once', async () => {
    // Deduplication keys on `event_id` (M15.29), and the observable consequence is
    // the chart: one applied tick cannot draw a line, so a duplicate that was
    // applied twice would produce one.
    installFetch(dashboardRoutes())
    renderDashboard()
    await waitFor(() => {
      expect(kpi('Packets / sec')).toBe('8.5/s')
    })

    act(() => socketFor('/ws/dashboard').open())
    const frame = dashboardFrame(tick({ packets_per_second: 42 }), 'evt-tick-1')
    act(() => socketFor('/ws/dashboard').emit(frame))
    act(() => socketFor('/ws/dashboard').emit(frame))

    expect(kpi('Packets / sec')).toBe('42/s')
    expect(screen.getByText('Waiting for live ticks')).toBeInTheDocument()
  })

  it('charts only observed ticks', async () => {
    // Nothing is interpolated and no series is invented: with fewer than two real
    // readings the card says so instead of drawing a line (M15.36).
    installFetch(dashboardRoutes())
    renderDashboard()
    await waitFor(() => {
      expect(kpi('Packets / sec')).toBe('8.5/s')
    })
    expect(screen.getByText('Waiting for live ticks')).toBeInTheDocument()

    act(() => socketFor('/ws/dashboard').open())
    act(() => socketFor('/ws/dashboard').emit(dashboardFrame(tick({ packets_per_second: 20 }))))
    expect(screen.getByText('Waiting for live ticks')).toBeInTheDocument()

    act(() => socketFor('/ws/dashboard').emit(dashboardFrame(tick({ packets_per_second: 30 }))))
    await waitFor(() => {
      expect(screen.queryByText('Waiting for live ticks')).toBeNull()
    })
  })

  it('adopts a capture state announced on the system channel', async () => {
    // The summary's capture block and the capture service are two writers, so this
    // asserts the *sensor's* own state on the control card.
    installFetch(dashboardRoutes({
      'GET /capture/status': () => ok({ status: 'idle', interface: 'eth0', packet_count: 0 }),
    }))
    renderDashboard()
    await waitFor(() => {
      expect(screen.getByText('idle')).toBeInTheDocument()
    })

    act(() => socketFor('/ws/system').open())
    act(() => socketFor('/ws/system').emit(captureFrame(EventType.CAPTURE_STARTED, {
      status: 'running',
      interface: 'eth0',
      packet_count: 12,
    })))

    expect(screen.getByText('running')).toBeInTheDocument()
    expect(screen.getByText('12 pkts')).toBeInTheDocument()
  })
})
describe('Dashboard capture control (M15.41)', () => {
  it('offers the adapters the host reported and starts a session', async () => {
    const router = installFetch(dashboardRoutes({
      'GET /capture/status': () => ok({ status: 'idle', interface: 'eth0', packet_count: 0 }),
      'GET /capture/interfaces': () => ok([{ name: 'eth0' }, { name: 'wlan0' }]),
      'POST /capture/start': () =>
        ok({ status: 'running', interface: 'eth0', packet_count: 0 }),
    }))
    renderDashboard()
    await waitFor(() => {
      expect(screen.getByText('idle')).toBeInTheDocument()
    })

    // The adapters are the machine's own list, read from the backend (M13.7).
    expect(screen.getByRole('option', { name: 'eth0' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'wlan0' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /start/i }))

    await waitFor(() => {
      expect(router.countOf('POST /capture/start')).toBe(1)
    })
    // The POST response is authoritative and arrives before the event does.
    await waitFor(() => {
      expect(screen.getByText('running')).toBeInTheDocument()
    })
    expect(showToast).toHaveBeenCalledWith('Capture started', 'success')
  })

  it('reports a refused start with the backend’s own sentence', async () => {
    // The transition table belongs to the capture manager, so a refusal is rendered
    // rather than second-guessed here (M15.9).
    installFetch(dashboardRoutes({
      'GET /capture/status': () => ok({ status: 'idle', interface: 'eth0', packet_count: 0 }),
      'POST /capture/start': () =>
        failure(409, 'Capture is already running.', [
          { field: 'capture', code: 'CAPTURE_ALREADY_RUNNING' },
        ]),
    }))
    renderDashboard()
    await waitFor(() => {
      expect(screen.getByText('idle')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /start/i }))

    await waitFor(() => {
      expect(showToast).toHaveBeenCalledWith('Capture is already running.', 'error')
    })
    // Nothing changed: the refusal is the backend's answer, not a new state.
    expect(screen.getByText('idle')).toBeInTheDocument()
  })

  it('shows a capture error announced on the system channel', async () => {
    // `capture.error` carries a fixed sentence and never an exception text (M14.22).
    installFetch(dashboardRoutes())
    renderDashboard()
    await waitFor(() => {
      expect(screen.getByText('4,321 pkts')).toBeInTheDocument()
    })

    act(() => socketFor('/ws/system').open())
    act(() => socketFor('/ws/system').emit(captureFrame(EventType.CAPTURE_ERROR, {
      status: 'error',
      interface: 'eth0',
      packet_count: 10,
      reason: 'The capture device disappeared.',
    })))

    expect(screen.getByText('The capture device disappeared.')).toBeInTheDocument()
  })
})

describe('Dashboard failures (M15.8)', () => {
  it('shows an error panel per section when nothing could be read', async () => {
    // No blank screen: each data-driven block reports its own failure, the scalars
    // read as unknown rather than zero, and no stale-content banner is shown
    // because there is no content to call stale.
    vi.stubGlobal('fetch', networkDownFetch())
    renderDashboard()

    await waitFor(() => {
      expect(screen.getAllByText('Unable to load')).toHaveLength(4)
    })
    expect(kpi('Packets / sec')).toBe(UNKNOWN_TEXT)
    expect(kpi('Throughput')).toBe(UNKNOWN_TEXT)
    expect(screen.getAllByRole('button', { name: /retry|reload/i })).toHaveLength(4)
    expect(screen.queryByText(/may be out of date/i)).toBeNull()
  })

  it('keeps the content and warns when a refresh fails', async () => {
    // A failed *re-read* must not replace what the operator is reading; the banner
    // is how they learn it may be stale (M15.8). The re-read is triggered by the
    // reconnect path, which is M15.27's whole point: REST first, then live again.
    let failing = false
    const router = installFetch(dashboardRoutes({
      'GET /dashboard/summary': () =>
        failing
          ? failure(500, 'The server failed while handling this request.', [])
          : ok(summary()),
    }))
    renderDashboard()
    await waitFor(() => {
      expect(kpi('Packets / sec')).toBe('8.5/s')
    })

    act(() => socketFor('/ws/dashboard').open())
    failing = true
    act(() => socketFor('/ws/dashboard').serverClose(1006))

    // The socket retries after its documented backoff, and the reopened connection
    // is announced as a reconnect — which is the signal to re-read REST.
    await waitFor(() => {
      expect(socketsFor('/ws/dashboard')).toHaveLength(2)
    }, { timeout: 5_000 })
    act(() => socketFor('/ws/dashboard').open())

    await waitFor(() => {
      expect(router.countOf('GET /dashboard/summary')).toBe(2)
    })
    expect(screen.getByText(/may be out of date/i)).toBeInTheDocument()
    // The reading the operator already had is still on screen.
    expect(kpi('Packets / sec')).toBe('8.5/s')
  })

  it('names a section the backend could not read instead of calling it empty', async () => {
    // "No alerts recorded" for a store that could not be reached would state a calm
    // absence where the truth is that nothing was read (M13.29/M15.8). The reason is
    // the backend's own sentence, and it appears on the block and in the summary.
    installFetch(dashboardRoutes({
      'GET /dashboard/summary': () => ok(summary({
        alerts: unavailableSection('The alert store could not be read.'),
        detections: section({ retained: 0, recent: [] }),
      })),
    }))
    renderDashboard()

    await waitFor(() => {
      expect(screen.getByText('This section could not be read')).toBeInTheDocument()
    })
    expect(screen.getAllByText('The alert store could not be read.')).toHaveLength(2)
    expect(screen.queryByText('No alerts recorded')).toBeNull()
    // One section is unread, which the banner counts — read from the banner
    // itself, because a bare "1" is also a legitimate breakdown count.
    expect(banner('Sections unavailable')).toBe('1')
    // A section that answered with no rows is still just empty.
    expect(screen.getByText('No recent findings')).toBeInTheDocument()
  })
})
