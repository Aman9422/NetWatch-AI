/**
 * Devices — the observed registry (M15.12, M15.38 "Pages").
 *
 * The page tests assert two different things, and both matter:
 *
 * 1. **What the page asked for.** The harness records every request, so a page
 *    that renders nicely from a payload it never requested is caught — the
 *    server-side filter and the page window are checked on the wire, not inferred
 *    from the render.
 * 2. **What appeared on screen.** Values are asserted from the fixture, so a
 *    wiring mistake that silently drops a field fails here rather than looking
 *    plausible.
 *
 * The two absences M15.12 names are checked too: no risk score is rendered, and a
 * device with no vendor or MAC shows the explicit unknown marker rather than an
 * empty cell that reads as a rendering bug.
 */

import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { DEFAULT_PAGE_LIMIT, NETWORK_MESSAGE } from '@/services'
import { UNKNOWN_TEXT } from '@/lib/format'
import type { Device, DevicePage } from '@/types'
import Devices from '@/pages/Devices'
import { failure, installFetch, networkDownFetch, ok, type RoutedCall } from '@/test/harness'

/** One device as M8 reports it, with everything settable for a given case. */
function device(overrides: Partial<Device> = {}): Device {
  return {
    device_id: 'mac:aa:bb:cc:dd:ee:01',
    mac_address: 'aa:bb:cc:dd:ee:01',
    ip_addresses: ['10.0.0.21'],
    first_seen: '2026-01-01T10:00:00+00:00',
    // Slightly in the future, so the elapsed-time formatter reports "just now"
    // whatever the wall clock says when the suite runs.
    last_seen: new Date(Date.now() + 1_000).toISOString(),
    packet_count: 42,
    byte_count: 4_096,
    packets_sent: 30,
    bytes_sent: 3_000,
    packets_received: 12,
    bytes_received: 1_096,
    hostname: 'web-01',
    vendor: 'Raspberry Pi Foundation',
    status: 'active',
    is_local: false,
    ...overrides,
  }
}

/** A page of devices as the listing endpoint answers. */
function devicePage(devices: readonly Device[], overrides: Partial<DevicePage> = {}): DevicePage {
  return {
    count: devices.length,
    limit: DEFAULT_PAGE_LIMIT,
    offset: 0,
    total: devices.length,
    has_more: false,
    devices,
    ...overrides,
  }
}

/** Render the page with a toast recorder. */
function renderPage() {
  const showToast = vi.fn()
  const view = render(<Devices showToast={showToast} />)
  return { ...view, showToast }
}

describe('Devices requesting', () => {
  it('asks for one page of the registry with the configured window', async () => {
    const router = installFetch({ 'GET /devices': () => ok(devicePage([device()])) })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /devices')).toBe(1)
    })
    const call = router.lastCall('GET /devices')
    expect(call?.params['limit']).toBe(String(DEFAULT_PAGE_LIMIT))
    expect(call?.params['offset']).toBe('0')
  })

  it('does not send a status filter while every state is shown', async () => {
    const router = installFetch({ 'GET /devices': () => ok(devicePage([device()])) })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /devices')).toBe(1)
    })
    expect(router.lastCall('GET /devices')?.params['status']).toBeUndefined()
  })

  it('sends the activity state to the backend when one is chosen', async () => {
    // M13.10 serves `status` as a real filter, so choosing one must narrow the
    // request rather than the loaded page.
    const router = installFetch({
      'GET /devices': (call: RoutedCall) =>
        ok(devicePage([device({ status: call.params['status'] === 'inactive' ? 'inactive' : 'active' })])),
    })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /devices')).toBe(1)
    })

    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'inactive' } })

    await waitFor(() => {
      expect(router.countOf('GET /devices')).toBe(2)
    })
    expect(router.lastCall('GET /devices')?.params['status']).toBe('inactive')
    // The window restarts, so the operator does not land on page 3 of a new filter.
    expect(router.lastCall('GET /devices')?.params['offset']).toBe('0')
  })
})

describe('Devices rendering', () => {
  it('renders the observed fields of a real device', async () => {
    installFetch({ 'GET /devices': () => ok(devicePage([device()])) })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('web-01')).toBeInTheDocument()
    })

    // Scoped to the row: "Active" is also the label of a tile and of a filter
    // option, so an unscoped query would match three elements and prove nothing
    // about the row. Every value below is asserted inside the row's own cells.
    const row = screen.getByText('web-01').closest('tr')
    expect(row).not.toBeNull()
    const cells = within(row as HTMLElement)

    expect(cells.getByText('10.0.0.21')).toBeInTheDocument()
    expect(cells.getByText('aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    expect(cells.getByText('mac:aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    expect(cells.getByText('Raspberry Pi Foundation')).toBeInTheDocument()
    expect(cells.getByText('42')).toBeInTheDocument()
    expect(cells.getByText('4.0 KB')).toBeInTheDocument()
    expect(cells.getByText('Active')).toBeInTheDocument()
  })

  it('shows the explicit unknown marker for values M8 did not report', async () => {
    // A blank cell reads as a rendering bug; the marker reads as an answer.
    installFetch({
      'GET /devices': () =>
        ok(
          devicePage([
            device({
              hostname: null,
              mac_address: null,
              vendor: null,
              ip_addresses: [],
              status: 'unknown',
            }),
          ]),
        ),
    })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Unknown')).toBeInTheDocument()
    })
    // Name, address and MAC each fall back, so three markers are on screen.
    expect(screen.getAllByText(UNKNOWN_TEXT).length).toBeGreaterThanOrEqual(3)
  })

  it('names an unnamed device rather than leaving the cell empty', async () => {
    installFetch({
      'GET /devices': () => ok(devicePage([device({ hostname: null })])),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Unnamed device')).toBeInTheDocument()
    })
  })

  it('renders no risk score, because M8 does not produce one', async () => {
    // M15.12 is explicit: the registry tracks, it does not judge. A score on this
    // page would be a frontend invention.
    installFetch({ 'GET /devices': () => ok(devicePage([device()])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('web-01')).toBeInTheDocument()
    })
    expect(screen.queryByText(/risk/i)).toBeNull()
  })

  it('counts the loaded page and names the registry total separately', async () => {
    // The tile counts what is loaded; `total` is the registry's own count. Showing
    // one as the other would misreport a paged listing.
    installFetch({
      'GET /devices': () =>
        ok(devicePage([device()], { total: 137, has_more: true })),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('137 in registry')).toBeInTheDocument()
    })
    expect(screen.getByText('Devices on this page')).toBeInTheDocument()
    expect(screen.getByText('Seen within the activity window')).toBeInTheDocument()
  })

  it('exports only the rows it actually loaded, and says how many', async () => {
    const { showToast } = renderPageOnce()
    await waitFor(() => {
      expect(screen.getByText('web-01')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button', { name: /export page as csv/i }))
    expect(showToast).toHaveBeenCalledWith('Exported 1 device', 'success')
  })
})

/** Render the page with a router already installed for the export case. */
function renderPageOnce() {
  installFetch({ 'GET /devices': () => ok(devicePage([device()])) })
  return renderPage()
}

describe('Devices loading, empty and error states', () => {
  it('shows a busy panel while the first request is in flight', () => {
    // A promise that never settles: the initial state is what is being asserted.
    installFetch({ 'GET /devices': () => new Promise<Response>(() => {}) })
    renderPage()
    expect(screen.getByText('Loading devices…')).toBeInTheDocument()
  })

  it('shows the empty state, and explains what would populate it', async () => {
    installFetch({ 'GET /devices': () => ok(devicePage([])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('No devices observed')).toBeInTheDocument()
    })
    expect(screen.getByText(/start a capture to populate the registry/i)).toBeInTheDocument()
  })

  it('shows a usable error panel when the backend cannot be reached', async () => {
    vi.stubGlobal('fetch', networkDownFetch())
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(NETWORK_MESSAGE)).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('does not report a failed request as an empty registry', async () => {
    // The distinction the empty state exists to preserve: "no devices" and "we
    // could not ask" are different answers.
    vi.stubGlobal('fetch', networkDownFetch())
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(NETWORK_MESSAGE)).toBeInTheDocument()
    })
    expect(screen.queryByText('No devices observed')).toBeNull()
  })

  it('re-requests the registry when the operator retries', async () => {
    let failNext = true
    const router = installFetch({
      'GET /devices': () => {
        if (failNext) {
          failNext = false
          return failure(503, '', [{ field: 'service', code: 'SERVICE_UNAVAILABLE' }])
        }
        return ok(devicePage([device()]))
      },
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /retry/i }))

    await waitFor(() => {
      expect(screen.getByText('web-01')).toBeInTheDocument()
    })
    expect(router.countOf('GET /devices')).toBe(2)
  })

  it('keeps the loaded rows and warns they may be stale when a refresh fails', async () => {
    // Replacing good rows with an error panel would lose what the operator was
    // reading; the banner is the honest alternative (M15.8).
    let failNext = false
    installFetch({
      'GET /devices': () =>
        failNext
          ? failure(500, 'The server failed while handling this request.', [
              { field: 'request', code: 'INTERNAL_ERROR' },
            ])
          : ok(devicePage([device()])),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('web-01')).toBeInTheDocument()
    })

    failNext = true
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }))

    await waitFor(() => {
      expect(screen.getByText(/may be out of date/i)).toBeInTheDocument()
    })
    expect(screen.getByText('web-01')).toBeInTheDocument()
  })
})

describe('Devices interaction', () => {
  it('opens the detail panel for a row and returns to the listing', async () => {
    installFetch({ 'GET /devices': () => ok(devicePage([device()])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('web-01')).toBeInTheDocument()
    })

    const row = screen.getByText('web-01').closest('tr')
    expect(row).not.toBeNull()
    fireEvent.click(row as HTMLElement)

    await waitFor(() => {
      expect(screen.getByText('Back to Devices')).toBeInTheDocument()
    })
    // Counters as M8 observed them, taken from the fixture's split.
    expect(screen.getByText('Traffic Counters')).toBeInTheDocument()
    expect(screen.getByText('30 pkts · 2.9 KB')).toBeInTheDocument()
    expect(screen.getByText('12 pkts · 1.1 KB')).toBeInTheDocument()

    fireEvent.click(screen.getByText('Back to Devices'))
    await waitFor(() => {
      expect(screen.getByText('Observed Devices')).toBeInTheDocument()
    })
  })

  it('narrows the loaded page without issuing another request', async () => {
    // The registry listing has no free-text parameter (M13.10), so the search is a
    // client-side narrowing of one page and must not pretend otherwise.
    const router = installFetch({
      'GET /devices': () =>
        ok(
          devicePage([
            device({ hostname: 'web-01', device_id: 'mac:aa:00', mac_address: 'aa:00' }),
            device({ hostname: 'db-01', device_id: 'mac:bb:00', mac_address: 'bb:00' }),
          ]),
        ),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('db-01')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByPlaceholderText(/filter this page/i), {
      target: { value: 'web' },
    })

    await waitFor(() => {
      expect(screen.queryByText('db-01')).toBeNull()
    })
    expect(screen.getByText('web-01')).toBeInTheDocument()
    expect(router.countOf('GET /devices')).toBe(1)
  })

  it('says the filter matched nothing, rather than claiming the registry is empty', async () => {
    installFetch({ 'GET /devices': () => ok(devicePage([device()])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('web-01')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByPlaceholderText(/filter this page/i), {
      target: { value: 'nothing-matches-this' },
    })

    await waitFor(() => {
      expect(screen.getByText('No devices match the filter')).toBeInTheDocument()
    })
    expect(screen.queryByText('No devices observed')).toBeNull()
  })

  it('offers no next page when the registry reported no more rows', async () => {
    installFetch({ 'GET /devices': () => ok(devicePage([device()], { has_more: false })) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('All observed devices')).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: /next/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /previous/i })).toBeDisabled()
  })

  it('pages forward by the page size when more rows exist', async () => {
    const router = installFetch({
      'GET /devices': (call: RoutedCall) =>
        call.params['offset'] === '0'
          ? ok(devicePage([device()], { has_more: true, total: 120 }))
          : ok(
              devicePage([device({ hostname: 'web-02', device_id: 'mac:02' })], {
                offset: DEFAULT_PAGE_LIMIT,
                has_more: false,
                total: 120,
              }),
            ),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /next/i })).toBeEnabled()
    })

    fireEvent.click(screen.getByRole('button', { name: /next/i }))

    await waitFor(() => {
      expect(screen.getByText('web-02')).toBeInTheDocument()
    })
    expect(router.lastCall('GET /devices')?.params['offset']).toBe(String(DEFAULT_PAGE_LIMIT))
  })

  it('states plainly that quarantine and blocking do not exist', async () => {
    // The console must not offer an action no backend component would carry out.
    installFetch({ 'GET /devices': () => ok(devicePage([device()])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('web-01')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('web-01').closest('tr') as HTMLElement)

    await waitFor(() => {
      expect(screen.getByText(/quarantine and blocking are not available/i)).toBeInTheDocument()
    })
  })
})
