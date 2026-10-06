/**
 * Live Traffic — one stream, one bounded list (M15.10/M15.11/M15.36/M15.38).
 *
 * This page is the only one fed by a continuous stream, so it is where the two
 * rules that make a stream safe to render are worth asserting directly:
 *
 * * **The packet list is bounded.** Every row arrives from `/ws/packets`; without
 *   a bound, an afternoon on a busy interface would put every observed packet in
 *   React state. The list holds {@link LIVE_PACKET_CAPACITY} rows and drops the
 *   oldest (M15.11/M15.36).
 * * **A gap is normal, not an error.** M14 drops packet events on purpose when a
 *   client cannot keep up, so ids are not assumed sequential and a missing id is
 *   never reported as a failure (M15.11).
 *
 * The rates are a second source, and deliberately so: `packets_per_second` comes
 * from the M6 snapshot because the packet stream does not carry it, and this page
 * must not divide counters to invent it (M15.9). The snapshot is the one thing
 * this page polls, and M15.34 allows polling exactly where the backend publishes
 * no event for the data.
 */

import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { LIVE_PACKET_CAPACITY } from '@/hooks'
import { EventType } from '@/types'
import type { PacketEventData, TrafficSnapshot } from '@/types'
import LiveTraffic from '@/pages/LiveTraffic'
import { UNKNOWN_TEXT } from '@/lib/format'
import {
  MockWebSocket, channelHub, eventFrame, failure, installFetch, networkDownFetch, ok,
  packetFrame, type RouteTable,
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

/** True when `later` appears after `earlier` in the document. */
function follows(later: HTMLElement, earlier: HTMLElement): boolean {
  return (earlier.compareDocumentPosition(later) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

/** One normalized packet, as `packet.observed` carries it (M14.8). */
function packet(overrides: Partial<PacketEventData> = {}): Record<string, unknown> {
  return {
    packet_id: 1,
    timestamp: '2026-01-01T10:00:00+00:00',
    interface: 'eth0',
    source_ip: '10.0.0.5',
    destination_ip: '10.0.0.9',
    protocol: 'TCP',
    source_port: 51_000,
    destination_port: 443,
    length: 60,
    packet_type: 'TCP',
    ...overrides,
  }
}

/** `GET /statistics/traffic` — the M6 snapshot (M6/M13.5). */
function snapshot(overrides: Partial<TrafficSnapshot> = {}): TrafficSnapshot {
  return {
    timestamp: 1_767_268_800,
    total_packets: 1000,
    total_bytes: 2_000_000,
    packets_per_second: 8.5,
    bytes_per_second: 20_480,
    bits_per_second: 163_840,
    protocol_statistics: [],
    direction_statistics: [],
    top_sources: [],
    top_destinations: [],
    top_ports: [],
    ...overrides,
  }
}

/** Every route the page needs, unless a test overrides one. */
function trafficRoutes(overrides: RouteTable = {}): RouteTable {
  return {
    'GET /statistics/traffic': () => ok(snapshot()),
    'GET /capture/status': () => ok({ status: 'running', interface: 'eth0', packet_count: 42 }),
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
function renderPage(): void {
  render(<LiveTraffic showToast={showToast} />)
}

/**
 * Stream `count` packets, each with a distinct identity.
 *
 * Every packet differs in its ports and id, so the rows have distinct React keys
 * and the page cannot collapse two observations into one.
 */
function stream(socket: MockWebSocket, count: number, base = 1): void {
  const frames: string[] = []
  for (let index = 0; index < count; index += 1) {
    const id = base + index
    frames.push(packetFrame(packet({
      packet_id: id,
      source_ip: `10.0.1.${id % 250}`,
      source_port: 40_000 + id,
      length: 60 + id,
    })))
  }
  act(() => {
    for (const frame of frames) socket.emit(frame)
  })
}

/** One statistic tile's figure, read from its own card. */
function stat(label: string): string {
  const card = screen.getByText(label).closest('.rounded-2xl')
  if (card === null) throw new Error(`No stat card is labelled ${label}.`)
  const value = (card as HTMLElement).querySelector('div.text-xl')
  return value?.textContent ?? ''
}

/** The table's retained/shown counter, as the footer renders it. */
function footer(): string {
  const line = screen.getByText(/shown ·/)
  return line.textContent ?? ''
}

beforeEach(() => {
  sockets.length = 0
  showToast.mockClear()
  installFakeWebSocket()
})
// ── Helpers that touch React's batching ──────────────────────────────────────

/** Complete a channel's handshake, inside React's batching. */
function openSocket(path: string): MockWebSocket {
  const socket = socketFor(path)
  act(() => {
    socket.open()
  })
  return socket
}

/** Deliver one or more frames on a socket, inside React's batching. */
function deliver(socket: MockWebSocket, ...frames: string[]): void {
  act(() => {
    for (const frame of frames) socket.emit(frame)
  })
}

// ── Reading the rates ────────────────────────────────────────────────────────

describe('Live Traffic — reading the M6 rates', () => {
  it('reads the snapshot once and subscribes to the packet channel', async () => {
    const router = installFetch(trafficRoutes())
    renderPage()
    expect(await screen.findByText('20 KB/s')).toBeInTheDocument()

    // One snapshot, asked for the one-second window M6 documents.
    expect(router.countOf('GET /statistics/traffic')).toBe(1)
    expect(router.lastCall('GET /statistics/traffic')?.params.window).toBe('1s')

    // One socket for the stream and one for the capture state the page also shows.
    expect(socketsFor('/ws/packets')).toHaveLength(1)
    expect(socketsFor('/ws/system')).toHaveLength(1)
    expect(sockets).toHaveLength(2)
    expect(channelHub.subscriberCount('packets')).toBe(1)
    expect(channelHub.subscriberCount('system')).toBe(1)

    // Nothing is subscribed on a channel this page does not read (M15.28).
    expect(channelHub.subscriberCount('dashboard')).toBe(0)
    expect(channelHub.subscriberCount('alerts')).toBe(0)
  })

  it('renders every rate the snapshot supplied, formatted', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')

    expect(stat('Packets / sec')).toBe('8.5/s')
    expect(stat('Throughput')).toBe('20 KB/s')
    expect(stat('Retained rows')).toBe('0')
    expect(stat('Capture')).toBe('running')
    // The bit rate the snapshot carried, not a recomputed one (M15.9).
    expect(screen.getByText('164 Kbps')).toBeInTheDocument()
    expect(screen.getByText('bounded at 500')).toBeInTheDocument()
  })

  it('keeps displaying the snapshot rate after packets arrive', async () => {
    installFetch(trafficRoutes({
      'GET /statistics/traffic': () => ok(snapshot({ packets_per_second: 2 })),
    }))
    renderPage()
    await screen.findByText('2/s')

    const socket = openSocket('/ws/packets')
    stream(socket, 12)

    // A client that divided its own counters would show something other than the
    // rate the backend published for the window (M15.9).
    expect(stat('Packets / sec')).toBe('2/s')
    expect(stat('Retained rows')).toBe('12')
  })

  it('shows the empty state before the backend has observed anything', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')

    expect(screen.getByText('No packets yet')).toBeInTheDocument()
    expect(screen.getByText(/Rows appear as the backend observes traffic/)).toBeInTheDocument()
    expect(footer()).toBe('0 shown · 0 retained')
  })

  it('shows the capture state and interface the capture service reported', async () => {
    installFetch(trafficRoutes({
      'GET /capture/status': () => ok({ status: 'running', interface: 'eth0', packet_count: 42 }),
    }))
    renderPage()

    expect(await screen.findByText('running')).toBeInTheDocument()
    expect(stat('Capture')).toBe('running')
    // The selection endpoint answers `400 NO_INTERFACE_SELECTED` until an adapter
    // is chosen, which is a documented precondition rather than a failure (M13.6).
    expect(screen.getByText('no interface selected')).toBeInTheDocument()

    // A transition announced on the system channel is applied, including one this
    // browser did not cause (M15.9).
    const system = openSocket('/ws/system')
    deliver(system, eventFrame({
      type: EventType.CAPTURE_STOPPED,
      channel: 'system',
      data: { status: 'stopped', interface: 'eth0', packet_count: 42 },
    }))

    expect(stat('Capture')).toBe('stopped')
    expect(screen.queryByText('running')).toBeNull()
  })
})

// ── The packet stream ────────────────────────────────────────────────────────

describe('Live Traffic — the packet stream', () => {
  it('renders every normalized field of a packet the backend observed', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')
    const socket = openSocket('/ws/packets')

    deliver(socket, packetFrame(packet()))

    expect(await screen.findByText('10.0.0.5')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.9')).toBeInTheDocument()
    expect(screen.getByText('51000')).toBeInTheDocument()
    expect(screen.getByText('443')).toBeInTheDocument()
    expect(screen.getByText('60')).toBeInTheDocument()
    // The classification and the protocol both come from the event, never guessed.
    expect(screen.getAllByText('TCP').length).toBeGreaterThanOrEqual(2)
    expect(footer()).toBe('1 shown · 1 retained')
  })

  it('places the newest observation first', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')
    const socket = openSocket('/ws/packets')

    deliver(
      socket,
      packetFrame(packet({ packet_id: 1, source_ip: '10.0.0.5', destination_ip: '10.0.0.9' })),
      packetFrame(packet({ packet_id: 2, source_ip: '10.0.0.6', destination_ip: '10.0.0.10' })),
    )

    const older = await screen.findByText('10.0.0.5')
    const newer = screen.getByText('10.0.0.6')
    // The second observation is the newer one, so the first row is its.
    expect(follows(older, newer)).toBe(true)
    expect(footer()).toBe('2 shown · 2 retained')
  })

  it('holds at the documented capacity, dropping the oldest rows', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')
    const socket = openSocket('/ws/packets')

    stream(socket, LIVE_PACKET_CAPACITY + 1)

    // One more packet than the bound: the list did not grow past it (M15.36).
    expect(stat('Retained rows')).toBe(String(LIVE_PACKET_CAPACITY))
    expect(footer()).toBe(`${LIVE_PACKET_CAPACITY} shown · ${LIVE_PACKET_CAPACITY} retained`)
    expect(screen.getByText(`bounded at ${LIVE_PACKET_CAPACITY}`)).toBeInTheDocument()
    // The oldest observation was evicted; the second-oldest survived.
    expect(screen.queryByText('40001')).toBeNull()
    expect(screen.getByText('40002')).toBeInTheDocument()
  })

  it('treats a missing packet id as normal rather than as a failure', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')
    const socket = openSocket('/ws/packets')

    // M14 drops packet events under load, so an id gap is expected on a busy
    // interface and must not be reported as an error (M15.11).
    deliver(
      socket,
      packetFrame(packet({ packet_id: 1, source_port: 40_001 })),
      packetFrame(packet({ packet_id: 2, source_port: 40_002 })),
      packetFrame(packet({ packet_id: 9, source_port: 40_009 })),
    )

    expect(await screen.findByText('40009')).toBeInTheDocument()
    expect(footer()).toBe('3 shown · 3 retained')
    expect(screen.queryByText('Unable to load traffic rates')).toBeNull()
    expect(screen.queryByText(/may be out of date/)).toBeNull()
  })

  it('ignores a valid event that is not a packet observation', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')
    const socket = openSocket('/ws/packets')

    // A documented capture event delivered on the wrong channel: it parses, and is
    // still not a packet, so it must not become a row.
    deliver(socket, eventFrame({
      type: EventType.CAPTURE_STARTED,
      channel: 'packets',
      data: { status: 'running', interface: 'eth0', packet_count: 0 },
    }))

    expect(footer()).toBe('0 shown · 0 retained')
    expect(screen.getByText('No packets yet')).toBeInTheDocument()
  })

  it('applies a redelivered packet event once', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')
    const socket = openSocket('/ws/packets')

    // The same `event_id` twice, which is what a redelivery looks like (M15.29).
    const frame = packetFrame(packet({ packet_id: 1, source_port: 40_001 }), 'evt-redelivered')
    deliver(socket, frame, frame)

    expect(footer()).toBe('1 shown · 1 retained')
  })

  it('reports the stream as connecting until the channel opens', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')

    expect(screen.getByText('■ Reconnecting')).toBeInTheDocument()
    const socket = openSocket('/ws/packets')
    expect(screen.getByText('● Streaming')).toBeInTheDocument()
    expect(socket.readyState).toBe(MockWebSocket.OPEN)
  })
})
// ── Filtering, pausing, clearing ─────────────────────────────────────────────

describe('Live Traffic — filtering the retained rows', () => {
  it('filters by classification without discarding the retained rows', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')
    const socket = openSocket('/ws/packets')

    deliver(
      socket,
      packetFrame(packet({ packet_id: 1, protocol: 'TCP', packet_type: 'TCP', source_port: 40_001 })),
      packetFrame(packet({ packet_id: 2, protocol: 'UDP', packet_type: 'UDP', source_port: 40_002 })),
    )
    expect(await screen.findByText('40002')).toBeInTheDocument()
    expect(footer()).toBe('2 shown · 2 retained')

    fireEvent.click(screen.getByRole('button', { name: 'UDP' }))

    // The filter narrows the view; it does not throw rows away (they are still
    // retained and come back when the filter is cleared).
    expect(footer()).toBe('1 shown · 2 retained')
    expect(screen.getByText('40002')).toBeInTheDocument()
    expect(screen.queryByText('40001')).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'ICMP' }))
    expect(screen.getByText('No packets match your filter')).toBeInTheDocument()
    expect(footer()).toBe('0 shown · 2 retained')
  })

  it('searches the retained rows by address and protocol', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')
    const socket = openSocket('/ws/packets')

    deliver(
      socket,
      packetFrame(packet({ packet_id: 1, source_ip: '10.0.0.5', source_port: 40_001 })),
      packetFrame(packet({
        packet_id: 2, source_ip: '10.0.0.6', destination_ip: '10.0.0.10', source_port: 40_002,
      })),
    )
    expect(await screen.findByText('40002')).toBeInTheDocument()

    fireEvent.change(screen.getByPlaceholderText(/search source ip/i), {
      target: { value: '10.0.0.6' },
    })

    expect(footer()).toBe('1 shown · 2 retained')
    expect(screen.getByText('40002')).toBeInTheDocument()
    expect(screen.queryByText('40001')).toBeNull()
  })
})

describe('Live Traffic — pausing, clearing and exporting', () => {
  it('discards incoming packets while the view is paused, and resumes at the next one', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')
    const socket = openSocket('/ws/packets')

    fireEvent.click(screen.getByRole('button', { name: /pause view/i }))
    expect(showToast).toHaveBeenCalledWith(
      'View paused — incoming packets are discarded', 'info',
    )

    // Pausing pauses the *view*: M14 keeps no replay buffer, so the events that
    // arrive while paused are discarded rather than queued (M15.10).
    deliver(socket, packetFrame(packet({ packet_id: 1, source_port: 40_001 })))
    expect(footer()).toBe('0 shown · 0 retained')
    expect(screen.getByText('view paused')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /resume/i }))
    expect(showToast).toHaveBeenCalledWith('View resumed', 'info')

    deliver(socket, packetFrame(packet({ packet_id: 2, source_port: 40_002 })))
    expect(footer()).toBe('1 shown · 1 retained')
    expect(screen.getByText('40002')).toBeInTheDocument()
    expect(screen.queryByText('view paused')).toBeNull()
  })

  it('clears every retained row on demand', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')
    const socket = openSocket('/ws/packets')

    stream(socket, 3)
    expect(footer()).toBe('3 shown · 3 retained')

    fireEvent.click(screen.getByRole('button', { name: /clear/i }))

    expect(showToast).toHaveBeenCalledWith('Retained rows cleared', 'info')
    expect(footer()).toBe('0 shown · 0 retained')
    expect(screen.getByText('No packets yet')).toBeInTheDocument()
  })

  it('refuses to export when the current filter matches nothing', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')

    fireEvent.click(screen.getByRole('button', { name: /export csv/i }))

    // Nothing is written: the guard returns before a blob is built, so a table
    // with no rows cannot download an empty file that looks like data.
    expect(showToast).toHaveBeenCalledWith(
      'Nothing to export — the current filter matches no packets', 'info',
    )
    expect(showToast).toHaveBeenCalledTimes(1)
  })
})

// ── The packet drawer ────────────────────────────────────────────────────────

describe('Live Traffic — the packet drawer', () => {
  it('shows the fields the backend sent and states that no payload is retained', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')
    const socket = openSocket('/ws/packets')

    deliver(socket, packetFrame(packet()))
    fireEvent.click(await screen.findByText('10.0.0.5'))

    expect(screen.getByText('Packet #1')).toBeInTheDocument()
    const notice = screen.getByText('No payload is available')
    const drawer = notice.closest('div.w-96')
    expect(drawer).not.toBeNull()

    const scope = within(drawer as HTMLElement)
    expect(scope.getByText('Source IP')).toBeInTheDocument()
    expect(scope.getByText('10.0.0.5')).toBeInTheDocument()
    expect(scope.getByText('Destination IP')).toBeInTheDocument()
    expect(scope.getByText('443')).toBeInTheDocument()
    expect(scope.getByText('Frame length')).toBeInTheDocument()
    // The frame length is stated twice: as a chip in the header and as a row.
    expect(scope.getAllByText('60 bytes')).toHaveLength(2)
    // The payload affordances the mock design offered are gone, because M7 stores
    // no payload and M14.8 sends none (M15.10).
    expect(scope.queryByRole('button', { name: /hex|payload|raw/i })).toBeNull()
  })

  it('closes the drawer without dropping the row', async () => {
    installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')
    const socket = openSocket('/ws/packets')

    deliver(socket, packetFrame(packet()))
    fireEvent.click(await screen.findByText('10.0.0.5'))
    expect(screen.getByText('Packet #1')).toBeInTheDocument()

    // The close control is the icon-only button in the drawer header.
    const drawer = screen.getByText('No payload is available').closest('div.w-96') as HTMLElement
    const closeButton = drawer.querySelector('button:last-of-type')
    expect(closeButton).not.toBeNull()
    fireEvent.click(closeButton as Element)

    expect(screen.queryByText('Packet #1')).toBeNull()
    expect(footer()).toBe('1 shown · 1 retained')
  })
})
// ── Failures and reconnection ────────────────────────────────────────────────

describe('Live Traffic — failures and reconnection', () => {
  it('shows an error state when the rates could not be read, and recovers on retry', async () => {
    let broken = true
    installFetch(trafficRoutes({
      'GET /statistics/traffic': () =>
        broken ? failure(503, 'Statistics are unavailable.') : ok(snapshot()),
    }))
    renderPage()

    expect(await screen.findByText('Unable to load traffic rates')).toBeInTheDocument()
    // The backend's own sentence, not a stack trace (M15.7).
    expect(screen.getByText('Statistics are unavailable.')).toBeInTheDocument()

    // Unknown, not zero: a rate that could not be read must not render as quiet.
    expect(stat('Packets / sec')).toBe(UNKNOWN_TEXT)
    expect(stat('Throughput')).toBe(UNKNOWN_TEXT)
    expect(screen.getAllByText('snapshot unavailable')).toHaveLength(2)
    expect(screen.queryByText('No packets yet')).toBeNull()

    broken = false
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))

    expect(await screen.findByText('20 KB/s')).toBeInTheDocument()
    expect(stat('Packets / sec')).toBe('8.5/s')
    expect(screen.queryByText('Unable to load traffic rates')).toBeNull()
  })

  it('names the transport when nothing is listening at all', async () => {
    vi.stubGlobal('fetch', networkDownFetch())
    renderPage()

    expect(await screen.findByText('Unable to load traffic rates')).toBeInTheDocument()
    expect(screen.getByText(
      'Cannot reach the NetWatch backend. Check that it is running and that the API base URL is correct.',
    )).toBeInTheDocument()
    expect(stat('Packets / sec')).toBe(UNKNOWN_TEXT)
    // The capture service could not be read either, so its state is unknown too.
    expect(stat('Capture')).toBe(UNKNOWN_TEXT)
  })

  it('keeps the retained rows and warns when a later refresh fails', async () => {
    let failRefresh = false
    installFetch(trafficRoutes({
      'GET /statistics/traffic': () =>
        failRefresh ? failure(500, 'Statistics are unavailable.') : ok(snapshot()),
    }))
    renderPage()
    await screen.findByText('20 KB/s')

    const first = openSocket('/ws/packets')
    stream(first, 2)
    expect(footer()).toBe('2 shown · 2 retained')

    // The refresh fails, driven through the documented reconnect path.
    failRefresh = true
    first.serverClose(1006)
    await waitFor(() => expect(socketsFor('/ws/packets')).toHaveLength(2), { timeout: 5_000 })
    act(() => {
      socketFor('/ws/packets').open()
    })

    expect(await screen.findByText(/may be out of date/)).toBeInTheDocument()
    // A failed refresh does not blank the table or discard the stream (M15.8).
    expect(footer()).toBe('2 shown · 2 retained')
    expect(screen.getByText('40002')).toBeInTheDocument()
  })

  it('re-reads the rates after a reconnect and keeps the received packets', async () => {
    const router = installFetch(trafficRoutes())
    renderPage()
    await screen.findByText('20 KB/s')

    const first = openSocket('/ws/packets')
    stream(first, 3)
    expect(footer()).toBe('3 shown · 3 retained')
    expect(router.countOf('GET /statistics/traffic')).toBe(1)

    // The server drops the connection the way a restart would.
    first.serverClose(1006)
    await waitFor(() => expect(socketsFor('/ws/packets')).toHaveLength(2), { timeout: 5_000 })
    act(() => {
      socketFor('/ws/packets').open()
    })

    // Rates are state, so an outage is repaired from REST (M15.27) …
    await waitFor(() => expect(router.countOf('GET /statistics/traffic')).toBe(2))
    // … while packets are a stream: M14 has no replay, so the retained rows stay.
    expect(footer()).toBe('3 shown · 3 retained')
    expect(screen.getByText('● Streaming')).toBeInTheDocument()
  })
})
