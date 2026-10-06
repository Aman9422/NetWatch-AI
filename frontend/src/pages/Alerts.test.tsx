/**
 * Alerts — listing, live updates and lifecycle (M15.14–M15.16, M15.38 "Pages").
 *
 * The two rules this page exists to honour are the two that are easiest to get
 * wrong, so they are tested directly:
 *
 * * **A live event either replaces a row or is offered as a refresh — never
 *   inserted.** An update to an alert on screen patches that row; a *new* alert
 *   becomes a "waiting" notice, because deciding whether it belongs in a filtered,
 *   paginated page would mean re-deriving the backend's filter in React.
 * * **No transition rule lives in the frontend.** The buttons come from
 *   `ALERT_TRANSITIONS`, but the request goes to the backend's own named route and
 *   a refusal is displayed rather than worked around.
 *
 * The socket is driven explicitly through the global constructor stub, because the
 * hub's default factory is `new WebSocket(url)` — without the stub these tests
 * would open real sockets to a backend that is not running.
 */

import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { DEFAULT_PAGE_LIMIT, NETWORK_MESSAGE } from '@/services'
import { UNKNOWN_TEXT } from '@/lib/format'
import { EventType } from '@/types'
import type { Alert, AlertPage, AlertSummary, EvidenceList as EvidencePage } from '@/types'
import Alerts from '@/pages/Alerts'
import {
  MockWebSocket, eventFrame, failure, installFetch, networkDownFetch, ok,
  type RouteTable, type RoutedCall,
} from '@/test/harness'

/** Every socket the hub created through the stubbed constructor, in order. */
const sockets: MockWebSocket[] = []

/** The most recently created socket. */
function latest(): MockWebSocket {
  const socket = sockets[sockets.length - 1]
  if (socket === undefined) throw new Error('The page created no socket.')
  return socket
}

beforeEach(() => {
  sockets.length = 0
  vi.stubGlobal(
    'WebSocket',
    class extends MockWebSocket {
      constructor(url: string) {
        super(url)
        sockets.push(this)
      }
    },
  )
})

/** One alert as M11 reports it, with everything settable for a given case. */
function alert(overrides: Partial<Alert> = {}): Alert {
  return {
    alert_id: 1,
    rule_id: 'port_scan',
    title: 'Port scan detected',
    // Deliberately free of addresses, so an address assertion cannot match the
    // description cell as well as the flow cell.
    description: 'Forty distinct destination ports were probed in one window.',
    severity: 'high',
    confidence: 0.82,
    status: 'open',
    // Two minutes ago, so the relative formatter reads "2m ago" whatever the
    // wall clock says when the suite runs.
    created_at: new Date(Date.now() - 120_000).toISOString(),
    updated_at: new Date().toISOString(),
    resolved_at: null,
    source_ip: '10.0.0.5',
    destination_ip: '10.0.0.9',
    source_device_id: 'mac:aa:bb:cc:dd:ee:01',
    destination_device_id: 'mac:aa:bb:cc:dd:ee:02',
    protocol: 'TCP',
    connection_id: '10.0.0.5:1234|10.0.0.9:80|TCP',
    finding_id: 'finding-1',
    evidence_count: 3,
    correlation_key: 'ck-1',
    ...overrides,
  }
}

/** A page of alerts as the listing endpoint answers. */
function alertPage(alerts: readonly Alert[], overrides: Partial<AlertPage> = {}): AlertPage {
  return {
    count: alerts.length,
    total: alerts.length,
    limit: DEFAULT_PAGE_LIMIT,
    offset: 0,
    has_more: false,
    alerts,
    ...overrides,
  }
}

/** The counts endpoint, which every severity reports even at zero. */
function summary(overrides: Partial<AlertSummary> = {}): AlertSummary {
  return {
    total: 10,
    by_severity: { low: 1, medium: 2, high: 3, critical: 4 },
    by_status: { open: 5, acknowledged: 1, resolved: 2, dismissed: 1, false_positive: 1 },
    ...overrides,
  }
}

/** One page of evidence for an alert. */
function evidencePage(alertId: number): EvidencePage {
  return {
    alert_id: alertId,
    count: 1,
    evidence: [
      {
        evidence_type: 'rule',
        packet_id: 412,
        created_at: '2026-01-01T10:00:00+00:00',
        data: { threshold: 40, observed: 118 },
      },
    ],
  }
}

/** The routes a listing test needs, unless it overrides one. */
function listingRoutes(overrides: RouteTable = {}): RouteTable {
  return {
    'GET /alerts': () => ok(alertPage([alert()])),
    'GET /alerts/summary': () => ok(summary()),
    ...overrides,
  }
}

/** Render the page with a toast recorder. */
function renderPage() {
  const showToast = vi.fn()
  const view = render(<Alerts showToast={showToast} />)
  return { ...view, showToast }
}

/**
 * The count beside a status label in the summary bar.
 *
 * Scoped deliberately: the same label is also an `<option>` in the filter, so an
 * unscoped query would match both and prove nothing about the chip.
 */
function chipCount(label: string): string {
  const chip = screen
    .getAllByText(label)
    .filter(node => node.tagName !== 'OPTION')
    .map(node => node.closest('span.flex'))
    .find((cell): cell is HTMLElement => cell instanceof HTMLElement)
  if (chip === undefined) throw new Error(`No summary chip for ${label}`)
  return within(chip).getAllByText(/^\d+$/)[0]?.textContent ?? ''
}

describe('Alerts requesting', () => {
  it('asks for one page of the listing with the configured window', async () => {
    const router = installFetch(listingRoutes())
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /alerts')).toBe(1)
    })
    const call = router.lastCall('GET /alerts')
    expect(call?.params['limit']).toBe(String(DEFAULT_PAGE_LIMIT))
    expect(call?.params['offset']).toBe('0')
  })

  it('reads the counts from their own endpoint, not from the page it loaded', async () => {
    // M11.18's summary is a tally over the whole store, so counting the loaded
    // rows instead would report a page as the system.
    const router = installFetch(listingRoutes())
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /alerts/summary')).toBe(1)
    })
    expect(router.countOf('GET /alerts')).toBe(1)
  })

  it('sends no filter while every severity and state is shown', async () => {
    const router = installFetch(listingRoutes())
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /alerts')).toBe(1)
    })
    const call = router.lastCall('GET /alerts')
    expect(call?.params['severity']).toBeUndefined()
    expect(call?.params['status']).toBeUndefined()
    expect(call?.params['source_ip']).toBeUndefined()
  })

  it('sends the chosen severity and state to the backend', async () => {
    const router = installFetch(listingRoutes())
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /alerts')).toBe(1)
    })

    const selects = screen.getAllByRole('combobox')
    fireEvent.change(selects[0] as HTMLElement, { target: { value: 'critical' } })

    await waitFor(() => {
      expect(router.countOf('GET /alerts')).toBe(2)
    })
    expect(router.lastCall('GET /alerts')?.params['severity']).toBe('critical')
    // The window restarts, so the operator does not land on page 3 of a new filter.
    expect(router.lastCall('GET /alerts')?.params['offset']).toBe('0')
  })

  it('sends a chosen lifecycle state as the state filter', async () => {
    const router = installFetch(listingRoutes())
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /alerts')).toBe(1)
    })

    const selects = screen.getAllByRole('combobox')
    fireEvent.change(selects[1] as HTMLElement, { target: { value: 'acknowledged' } })

    await waitFor(() => {
      expect(router.countOf('GET /alerts')).toBe(2)
    })
    expect(router.lastCall('GET /alerts')?.params['status']).toBe('acknowledged')
  })

  it('sends the address to the backend rather than narrowing the loaded page', async () => {
    // A free-text client-side narrowing would silently search only the current
    // page, which is the mistake this page avoids by making the query the server's.
    const router = installFetch(listingRoutes())
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /alerts')).toBe(1)
    })

    const input = screen.getByPlaceholderText(/filter by source address/i)
    fireEvent.change(input, { target: { value: '10.0.0.5' } })
    // Typing alone must not re-request.
    expect(router.countOf('GET /alerts')).toBe(1)

    fireEvent.submit(input.closest('form') as HTMLFormElement)

    await waitFor(() => {
      expect(router.countOf('GET /alerts')).toBe(2)
    })
    expect(router.lastCall('GET /alerts')?.params['source_ip']).toBe('10.0.0.5')
  })
})

describe('Alerts rendering', () => {
  it('renders the fields M11 actually reports for an alert', async () => {
    installFetch(listingRoutes())
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Port scan detected')).toBeInTheDocument()
    })
    const row = screen.getByText('Port scan detected').closest('tr')
    expect(row).not.toBeNull()
    const cells = within(row as HTMLElement)

    expect(cells.getByText('High')).toBeInTheDocument()
    expect(cells.getByText('Open')).toBeInTheDocument()
    // Both addresses and the arrow between them are one cell's own text, so they
    // are matched as substrings of that cell rather than as separate elements.
    expect(cells.getByText(/10\.0\.0\.5/)).toBeInTheDocument()
    expect(cells.getByText(/10\.0\.0\.9/)).toBeInTheDocument()
    // `confidence` is a 0..1 ratio; the one conversion to a percentage lives in
    // `formatConfidence`, so 0.82 renders as 82% and never as "0.82%".
    expect(cells.getByText('82%')).toBeInTheDocument()
    expect(cells.getByText('TCP')).toBeInTheDocument()
    expect(cells.getByText('3')).toBeInTheDocument()
    expect(cells.getByText('2m ago')).toBeInTheDocument()
    expect(cells.getByText(/Forty distinct destination ports were probed/)).toBeInTheDocument()
  })

  it('renders the backend tallies and labels them as all-time', async () => {
    // "3 high alerts" meaning "3 in this page" and "3 in the system" are very
    // different claims, so the labels say which.
    installFetch(listingRoutes())
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('High (all time)')).toBeInTheDocument()
    })
    const tile = screen.getByText('High (all time)').closest('div.flex')?.parentElement
    expect(tile).not.toBeNull()
    expect(within(tile as HTMLElement).getByText('3')).toBeInTheDocument()

    expect(screen.getByText(/Total alerts:/)).toBeInTheDocument()
    expect(chipCount('Resolved')).toBe('2')
    expect(chipCount('False positive')).toBe('1')
  })

  it('shows the unknown marker for a side M11 recorded no address for', async () => {
    installFetch(listingRoutes({
      'GET /alerts': () =>
        ok(alertPage([alert({ source_ip: null, destination_ip: null, protocol: null })])),
    }))
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Port scan detected')).toBeInTheDocument()
    })
    // The flow cell holds two markers and the protocol cell one, and the first two
    // share an element — so the count is of elements, matched loosely.
    expect(screen.getAllByText(new RegExp(UNKNOWN_TEXT)).length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText(/recorded no address for that side/i)).toBeInTheDocument()
  })
})

describe('Alerts live updates', () => {
  it('replaces a row already on screen instead of adding a duplicate', async () => {
    // The event payload is the same wire view the listing serves, which is what
    // makes an in-place replacement possible (M15.14).
    installFetch(listingRoutes())
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Port scan detected')).toBeInTheDocument()
    })

    act(() => latest().open())
    act(() =>
      latest().emit(
        eventFrame({
          type: EventType.ALERT_ACKNOWLEDGED,
          channel: 'alerts',
          data: { ...alert({ status: 'acknowledged' }) },
        }),
      ),
    )

    await waitFor(() => {
      const row = screen.getByText('Port scan detected').closest('tr')
      expect(within(row as HTMLElement).getByText('Acknowledged')).toBeInTheDocument()
    })
    // One row, not two: a replacement was applied.
    expect(screen.getAllByText('Port scan detected')).toHaveLength(1)
  })

  it('collects a newly created alert as waiting rather than inserting it', async () => {
    // Whether a new alert belongs in this filtered, paginated page is the
    // backend's answer, so the page offers a refresh instead of guessing.
    installFetch(listingRoutes())
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Port scan detected')).toBeInTheDocument()
    })

    act(() => latest().open())
    act(() =>
      latest().emit(
        eventFrame({
          type: EventType.ALERT_CREATED,
          channel: 'alerts',
          data: { ...alert({ alert_id: 99, title: 'NEW: SYN flood' }) },
        }),
      ),
    )

    await waitFor(() => {
      expect(screen.getByText(/1 alert arrived live/)).toBeInTheDocument()
    })
    // It is *not* in the table: the listing is still the backend's page.
    expect(screen.queryByText('NEW: SYN flood')).toBeNull()
  })

  it('offers a reload for the waiting arrivals and says how many there are', async () => {
    const router = installFetch(listingRoutes())
    const { showToast } = renderPage()
    await waitFor(() => {
      expect(screen.getByText('Port scan detected')).toBeInTheDocument()
    })

    act(() => latest().open())
    act(() =>
      latest().emit(
        eventFrame({
          type: EventType.ALERT_CREATED,
          channel: 'alerts',
          data: { ...alert({ alert_id: 99 }) },
          event_id: 'evt-a',
        }),
      ),
    )
    act(() =>
      latest().emit(
        eventFrame({
          type: EventType.ALERT_CREATED,
          channel: 'alerts',
          data: { ...alert({ alert_id: 98 }) },
          event_id: 'evt-b',
        }),
      ),
    )

    await waitFor(() => {
      expect(screen.getByText(/2 alerts arrived live/)).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /reload/i }))

    await waitFor(() => {
      expect(router.countOf('GET /alerts')).toBe(2)
    })
    expect(showToast).toHaveBeenCalledWith('Reloading — 2 alerts arrived live', 'info')
  })

  it('applies a redelivered event once, keyed on event_id', async () => {
    // Two distinct arrivals, one event id: the second is a redelivery and must not
    // be counted twice.
    installFetch(listingRoutes())
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Port scan detected')).toBeInTheDocument()
    })

    act(() => latest().open())
    const first = eventFrame({
      type: EventType.ALERT_CREATED,
      channel: 'alerts',
      data: { ...alert({ alert_id: 99 }) },
      event_id: 'evt-dup',
    })
    act(() => latest().emit(first))
    act(() =>
      latest().emit(
        eventFrame({
          type: EventType.ALERT_CREATED,
          channel: 'alerts',
          data: { ...alert({ alert_id: 98 }) },
          event_id: 'evt-dup',
        }),
      ),
    )

    await waitFor(() => {
      expect(screen.getByText(/1 alert arrived live/)).toBeInTheDocument()
    })
  })

  it('does not grow the page for an update to an alert it is not showing', async () => {
    installFetch(listingRoutes())
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Port scan detected')).toBeInTheDocument()
    })

    act(() => latest().open())
    act(() =>
      latest().emit(
        eventFrame({
          type: EventType.ALERT_UPDATED,
          channel: 'alerts',
          data: { ...alert({ alert_id: 4242, title: 'ELSEWHERE' }) },
        }),
      ),
    )

    expect(screen.queryByText('ELSEWHERE')).toBeNull()
    expect(screen.getAllByText('Port scan detected')).toHaveLength(1)
  })

  it('reports the stream as disconnected until the socket opens', async () => {
    installFetch(listingRoutes())
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Port scan detected')).toBeInTheDocument()
    })
    expect(screen.getByText('live stream disconnected')).toBeInTheDocument()

    act(() => latest().open())
    await waitFor(() => {
      expect(screen.getByText('live — awaiting first event')).toBeInTheDocument()
    })
  })
})

describe('Alerts loading, empty and error states', () => {
  it('shows a busy panel while the first request is in flight', () => {
    installFetch({ 'GET /alerts': () => new Promise<Response>(() => {}) })
    renderPage()
    expect(screen.getByText('Loading alerts…')).toBeInTheDocument()
  })

  it('shows the empty state and explains what would raise an alert', async () => {
    installFetch(listingRoutes({ 'GET /alerts': () => ok(alertPage([])) }))
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('No alerts raised')).toBeInTheDocument()
    })
    expect(screen.getByText(/Nothing has crossed one yet/i)).toBeInTheDocument()
  })

  it('says the filter matched nothing rather than claiming none were raised', async () => {
    installFetch(listingRoutes({
      'GET /alerts': (call: RoutedCall) =>
        ok(alertPage(call.params['severity'] === 'critical' ? [] : [alert()])),
    }))
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Port scan detected')).toBeInTheDocument()
    })

    fireEvent.change(screen.getAllByRole('combobox')[0] as HTMLElement, {
      target: { value: 'critical' },
    })

    await waitFor(() => {
      expect(screen.getByText('No alerts match the filter')).toBeInTheDocument()
    })
    expect(screen.queryByText('No alerts raised')).toBeNull()
  })

  it('shows a usable error panel when the backend cannot be reached', async () => {
    vi.stubGlobal('fetch', networkDownFetch())
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Unable to load alerts')).toBeInTheDocument()
    })
    expect(screen.getByText(NETWORK_MESSAGE)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('keeps the loaded rows and warns they may be stale when a refresh fails', async () => {
    let failNext = false
    installFetch(listingRoutes({
      'GET /alerts': () =>
        failNext
          ? failure(500, 'The server failed while handling this request.', [
              { field: 'request', code: 'INTERNAL_ERROR' },
            ])
          : ok(alertPage([alert()])),
    }))
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Port scan detected')).toBeInTheDocument()
    })

    failNext = true
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }))

    await waitFor(() => {
      expect(screen.getByText(/may be out of date/i)).toBeInTheDocument()
    })
    expect(screen.getByText('Port scan detected')).toBeInTheDocument()
  })

  it('offers no next page when the backend reported no more rows', async () => {
    installFetch(listingRoutes({
      'GET /alerts': () => ok(alertPage([alert()], { has_more: false })),
    }))
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('All matching alerts')).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: /next/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /previous/i })).toBeDisabled()
  })

  it('pages forward by the page size when more rows exist', async () => {
    const router = installFetch(listingRoutes({
      'GET /alerts': (call: RoutedCall) =>
        call.params['offset'] === '0'
          ? ok(alertPage([alert()], { has_more: true, total: 120 }))
          : ok(
              alertPage([alert({ alert_id: 2, title: 'Later alert' })], {
                offset: DEFAULT_PAGE_LIMIT,
                has_more: false,
                total: 120,
              }),
            ),
    }))
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /next/i })).toBeEnabled()
    })

    fireEvent.click(screen.getByRole('button', { name: /next/i }))

    await waitFor(() => {
      expect(screen.getByText('Later alert')).toBeInTheDocument()
    })
    expect(router.lastCall('GET /alerts')?.params['offset']).toBe(String(DEFAULT_PAGE_LIMIT))
  })
})

describe('Alert detail, evidence and lifecycle (M15.15/M15.16)', () => {
  /** Routes for opening alert #1 and reading its evidence. */
  function detailRoutes(overrides: RouteTable = {}): RouteTable {
    return listingRoutes({
      'GET /alerts/1': () => ok({ alert: alert(), evidence: evidencePage(1).evidence, evidence_by_type: { rule: 1 } }),
      'GET /alerts/1/evidence': () => ok(evidencePage(1)),
      ...overrides,
    })
  }

  it('opens the detail with its evidence and returns to the listing', async () => {
    const router = installFetch(detailRoutes())
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Port scan detected')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Port scan detected').closest('tr') as HTMLElement)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /back to alerts/i })).toBeInTheDocument()
    })
    await waitFor(() => {
      expect(router.countOf('GET /alerts/1')).toBeGreaterThanOrEqual(1)
    })
    await waitFor(() => {
      expect(router.countOf('GET /alerts/1/evidence')).toBe(1)
    })
    // The M10 finding that raised it is a reference, and so is the packet.
    expect(screen.getByText('finding-1')).toBeInTheDocument()
    expect(screen.getByText('Lifecycle')).toBeInTheDocument()
    // Evidence inlines no payload, because M7 stored none.
    expect(screen.getByText(/not stored and not served/i)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /back to alerts/i }))
    await waitFor(() => {
      expect(screen.getByText(/Total alerts:/)).toBeInTheDocument()
    })
  })

  it('moves an alert through the backend’s own named route', async () => {
    // The frontend offers the move; the backend performs and validates it.
    const router = installFetch(detailRoutes({
      'POST /alerts/1/acknowledge': () => ok(alert({ status: 'acknowledged' })),
    }))
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Port scan detected')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('Port scan detected').closest('tr') as HTMLElement)
    await waitFor(() => {
      expect(screen.getByText('Lifecycle')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /^acknowledge$/i }))

    await waitFor(() => {
      expect(router.countOf('POST /alerts/1/acknowledge')).toBe(1)
    })

    // The response is applied straight away, so the listing row is already the
    // backend's new answer when the operator goes back.
    fireEvent.click(screen.getByRole('button', { name: /back to alerts/i }))
    await waitFor(() => {
      const row = screen.getByText('Port scan detected').closest('tr')
      expect(within(row as HTMLElement).getByText('Acknowledged')).toBeInTheDocument()
    })
  })

  it('shows the refusal when the backend rejects a transition', async () => {
    // M15.15: the transition table is the backend's, and a refused move is
    // reported rather than routed around.
    installFetch(detailRoutes({
      'POST /alerts/1/resolve': () =>
        failure(409, 'That lifecycle change is not allowed from the current state.', [
          { field: 'status', code: 'INVALID_TRANSITION' },
        ]),
    }))
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Port scan detected')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('Port scan detected').closest('tr') as HTMLElement)
    await waitFor(() => {
      expect(screen.getByText('Lifecycle')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /^resolve$/i }))

    await waitFor(() => {
      expect(screen.getByText(/Transition refused/i)).toBeInTheDocument()
    })
    expect(
      screen.getByText(/not allowed from the current state/i),
    ).toBeInTheDocument()
  })

  it('says an alert is gone rather than rendering an empty shell after a 404', async () => {
    installFetch(detailRoutes({
      'GET /alerts/1': () =>
        failure(404, 'No alert with that id.', [{ field: 'alert_id', code: 'ALERT_NOT_FOUND' }]),
    }))
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Port scan detected')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Port scan detected').closest('tr') as HTMLElement)

    await waitFor(() => {
      expect(screen.getByText('Alert #1 no longer exists')).toBeInTheDocument()
    })
    expect(screen.queryByText('Unable to load this alert')).toBeNull()
  })

  it('offers only the moves the transition table allows from the alert’s state', async () => {
    // A resolved alert is terminal: the page says so instead of showing a row of
    // controls that would all be refused.
    installFetch(detailRoutes({
      'GET /alerts/1': () =>
        ok({
          alert: alert({ status: 'resolved', resolved_at: new Date().toISOString() }),
          evidence: [],
          evidence_by_type: {},
        }),
    }))
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Port scan detected')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('Port scan detected').closest('tr') as HTMLElement)

    await waitFor(() => {
      expect(screen.getByText(/terminal state/i)).toBeInTheDocument()
    })
    expect(screen.queryByRole('button', { name: /^acknowledge$/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /^resolve$/i })).toBeNull()
  })
})
