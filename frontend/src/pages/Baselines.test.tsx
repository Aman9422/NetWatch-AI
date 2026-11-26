/**
 * Behavioral Baselines — the M21 learning engine's frontend (M21.11/M21.13).
 *
 * These tests assert two different things, and the second is what makes them
 * evidence rather than decoration:
 *
 * 1. **What the page asked for.** The harness records every request, so the page
 *    window, the learning-state filter and the reset's POST path are checked on
 *    the wire rather than inferred from a render.
 * 2. **What appeared on screen.** Values are asserted from a fixture shaped like
 *    `app/schemas/baseline.py`, so a wiring mistake that drops a field fails here.
 *
 * The milestone's own boundaries are asserted too, because they are the easiest
 * thing for a later change to break: **no anomaly or risk wording is rendered**,
 * a `404` is shown as "no baseline for this device" rather than as a failed
 * request, an unmeasurable `new_connections` shows the unknown marker instead of
 * a zero, and a reset reports the counts the backend actually returned.
 */

import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { DEFAULT_PAGE_LIMIT, NETWORK_MESSAGE } from '@/services'
import { UNKNOWN_TEXT } from '@/lib/format'
import type {
  Baseline,
  BaselinePage,
  BaselineResetResult,
  BaselineWindow,
  FeatureStatistics,
} from '@/types'
import Baselines from '@/pages/Baselines'
import { failure, installFetch, networkDownFetch, ok, type RoutedCall } from '@/test/harness'

/** One feature's statistics, as the engine calculates them. */
function feature(overrides: Partial<FeatureStatistics> = {}): FeatureStatistics {
  return {
    feature: 'packet_count',
    label: 'Packets',
    count: 12,
    mean: 40.5,
    median: 38,
    mad: 6,
    mad_scaled: 8.9,
    stdev: 9.2,
    p95: 61,
    min: 20,
    max: 64,
    truncated: false,
    ...overrides,
  }
}

/** One aggregated observation window. */
function window(overrides: Partial<BaselineWindow> = {}): BaselineWindow {
  return {
    window_start: '2026-01-01T10:00:00+00:00',
    window_seconds: 60,
    packet_count: 38,
    byte_count: 4_096,
    tcp_packets: 30,
    udp_packets: 8,
    icmp_packets: 0,
    dns_packets: 4,
    unique_peers: 5,
    unique_destination_ports: 7,
    new_connections: 3,
    peers_truncated: false,
    ports_truncated: false,
    ...overrides,
  }
}

/** One device's learnt baseline. */
function baseline(overrides: Partial<Baseline> = {}): Baseline {
  return {
    device_key: 'mac:aa:bb:cc:dd:ee:01',
    identity_kind: 'mac',
    mac_address: 'aa:bb:cc:dd:ee:01',
    ip_addresses: ['10.0.0.21'],
    learning_state: 'established',
    state_description: 'Enough observation windows have been collected for a mature profile.',
    sample_count: 12,
    statistics_sample_count: 12,
    window_seconds: 60,
    first_observed_at: '2026-01-01T10:00:00+00:00',
    last_observed_at: new Date(Date.now() + 1_000).toISOString(),
    statistics: [feature()],
    recent_windows: [],
    disclaimer:
      'A baseline describes previously observed behaviour. It is not an anomaly verdict.',
    ...overrides,
  }
}

/** A page of baselines as the listing endpoint answers. */
function baselinePage(
  baselines: readonly Baseline[],
  overrides: Partial<BaselinePage> = {},
): BaselinePage {
  return {
    count: baselines.length,
    limit: DEFAULT_PAGE_LIMIT,
    offset: 0,
    total: baselines.length,
    has_more: false,
    baselines,
    ...overrides,
  }
}

/** The reset endpoint's answer, with what it actually deleted. */
function resetResult(overrides: Partial<BaselineResetResult> = {}): BaselineResetResult {
  return {
    device_key: 'mac:aa:bb:cc:dd:ee:01',
    windows_deleted: 12,
    profile_deleted: true,
    learning_restarted: true,
    message: 'Deleted 12 observation windows. Nothing else was affected.',
    ...overrides,
  }
}

/** Render the page with a toast recorder. */
function renderPage() {
  const showToast = vi.fn()
  const view = render(<Baselines showToast={showToast} />)
  return { ...view, showToast }
}

describe('Baselines requesting', () => {
  it('asks for one page of baselines with the configured window', async () => {
    const router = installFetch({ 'GET /baselines': () => ok(baselinePage([baseline()])) })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /baselines')).toBe(1)
    })
    const call = router.lastCall('GET /baselines')
    expect(call?.params['limit']).toBe(String(DEFAULT_PAGE_LIMIT))
    expect(call?.params['offset']).toBe('0')
  })

  it('sends no learning-state filter while every state is shown', async () => {
    const router = installFetch({ 'GET /baselines': () => ok(baselinePage([baseline()])) })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /baselines')).toBe(1)
    })
    expect(router.lastCall('GET /baselines')?.params['learning_state']).toBeUndefined()
  })

  it('narrows the request when a learning state is chosen, restarting the window', async () => {
    const router = installFetch({
      'GET /baselines': (call: RoutedCall) =>
        ok(
          baselinePage([
            baseline({
              learning_state:
                call.params['learning_state'] === 'provisional' ? 'provisional' : 'established',
            }),
          ]),
        ),
    })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /baselines')).toBe(1)
    })

    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'provisional' } })

    await waitFor(() => {
      expect(router.countOf('GET /baselines')).toBe(2)
    })
    expect(router.lastCall('GET /baselines')?.params['learning_state']).toBe('provisional')
    expect(router.lastCall('GET /baselines')?.params['offset']).toBe('0')
  })

  it('reads the detail endpoint for the row that was opened', async () => {
    const router = installFetch({
      'GET /baselines': () => ok(baselinePage([baseline()])),
      'GET /baselines/mac%3Aaa%3Abb%3Acc%3Add%3Aee%3A01': () =>
        ok(baseline({ recent_windows: [window()] })),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('aa:bb:cc:dd:ee:01').closest('tr') as HTMLElement)

    await waitFor(() => {
      expect(router.countOf('GET /baselines/mac*')).toBe(1)
    })
    // The encoded key is the whole path segment, so the colons are not separators.
    expect(router.lastCall('GET /baselines/mac*')?.path).toBe(
      '/baselines/mac%3Aaa%3Abb%3Acc%3Add%3Aee%3A01',
    )
  })
})

describe('Baselines rendering', () => {
  it('renders the device identity, learning state, sample count and timestamps', async () => {
    installFetch({ 'GET /baselines': () => ok(baselinePage([baseline()])) })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })

    const row = screen.getByText('aa:bb:cc:dd:ee:01').closest('tr')
    expect(row).not.toBeNull()
    const cells = within(row as HTMLElement)

    expect(cells.getByText('Established')).toBeInTheDocument()
    // The sample count is the primary figure; the phrase beneath it names windows
    // rather than packets, so the row never overstates what was aggregated.
    expect(cells.getByText('12')).toBeInTheDocument()
    expect(cells.getByText('12 windows')).toBeInTheDocument()
    expect(cells.getByText('just now')).toBeInTheDocument()
    expect(cells.getByText('10.0.0.21')).toBeInTheDocument()
  })

  it('shows every learning state the engine can report', async () => {
    installFetch({
      'GET /baselines': () =>
        ok(
          baselinePage([
            baseline({ device_key: 'mac:01', learning_state: 'learning', sample_count: 1 }),
            baseline({ device_key: 'mac:02', learning_state: 'provisional', sample_count: 6 }),
            baseline({ device_key: 'mac:03', learning_state: 'established', sample_count: 40 }),
          ]),
        ),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Learnt Baselines')).toBeInTheDocument()
    })
    // Scoped to the table, because the stat cards use the same three words as
    // labels: an unscoped query would match a tile and prove nothing about a row.
    const table = within(screen.getByRole('table'))
    expect(table.getByText('Learning')).toBeInTheDocument()
    expect(table.getByText('Provisional')).toBeInTheDocument()
    expect(table.getByText('Established')).toBeInTheDocument()
  })

  it('shows a tile for each learning state', async () => {
    // The tiles are captions only; each figure is the count of loaded rows in that
    // state. Asserting the captions is what proves the page distinguishes the
    // three states rather than lumping them together.
    installFetch({
      'GET /baselines': () =>
        ok(
          baselinePage([
            baseline({ device_key: 'mac:01', learning_state: 'learning', sample_count: 1 }),
            baseline({ device_key: 'mac:02', learning_state: 'provisional', sample_count: 6 }),
          ]),
        ),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Enough windows for a mature profile')).toBeInTheDocument()
    })
    expect(screen.getByText('Profile still developing')).toBeInTheDocument()
    expect(screen.getByText('Too few windows to describe')).toBeInTheDocument()
    expect(screen.getByText('Baselines on this page')).toBeInTheDocument()
  })

  it('counts the loaded page and names the total separately', async () => {
    installFetch({
      'GET /baselines': () => ok(baselinePage([baseline()], { total: 43, has_more: true })),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('43 learnt')).toBeInTheDocument()
    })
    expect(screen.getByText('Baselines on this page')).toBeInTheDocument()
  })

  it('states that a baseline is not an anomaly verdict', async () => {
    // The milestone's central claim, and the one a reader is most likely to
    // misread from an "Established" badge. Asserted against rendered text rather
    // than one element, because the page emphasises "not" inside its own span and
    // `getByText` only reads an element's own text nodes.
    installFetch({ 'GET /baselines': () => ok(baselinePage([baseline()])) })
    const { container } = renderPage()
    await waitFor(() => {
      expect(container.textContent).toMatch(/not\s+an anomaly verdict/i)
    })
  })

  it('renders no risk or anomaly score, because M21 produces none', async () => {
    installFetch({ 'GET /baselines': () => ok(baselinePage([baseline()])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })
    expect(screen.queryByText(/risk score/i)).toBeNull()
    expect(screen.queryByText(/anomaly score/i)).toBeNull()
  })

  it('marks an IP fallback identity as the weaker identity it is', async () => {
    installFetch({
      'GET /baselines': () =>
        ok(
          baselinePage([
            baseline({
              device_key: 'ip:10.0.0.99',
              identity_kind: 'ip',
              mac_address: null,
            }),
          ]),
        ),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('10.0.0.99')).toBeInTheDocument()
    })
    expect(screen.getByText('IP')).toBeInTheDocument()
  })
})

describe('Baselines detail view', () => {
  it('opens a device profile with its statistics and observation windows', async () => {
    installFetch({
      'GET /baselines': () => ok(baselinePage([baseline()])),
      'GET /baselines/mac*': () =>
        ok(baseline({ recent_windows: [window()], statistics: [feature()] })),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('aa:bb:cc:dd:ee:01').closest('tr') as HTMLElement)

    await waitFor(() => {
      expect(screen.getByText('Behavioural baseline')).toBeInTheDocument()
    })
    expect(screen.getByText('Statistical profile')).toBeInTheDocument()
    expect(screen.getByText('Observation windows')).toBeInTheDocument()
    expect(screen.getByText('MAC identity')).toBeInTheDocument()
    // The window row's counters, and the byte figure rendered as bytes.
    expect(screen.getByText('4.0 KB')).toBeInTheDocument()
    // The backend's own disclaimer sentence is rendered, split across spans.
    expect(document.body.textContent).toMatch(/not an anomaly verdict/i)
  })

  it('shows an unmeasurable new-connection count as unknown, never as zero', async () => {
    // "Could not measure" and "measured zero" are different facts (M21.5).
    installFetch({
      'GET /baselines': () => ok(baselinePage([baseline()])),
      'GET /baselines/mac*': () =>
        ok(baseline({ recent_windows: [window({ new_connections: null })] })),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('aa:bb:cc:dd:ee:01').closest('tr') as HTMLElement)

    await waitFor(() => {
      expect(screen.getByText('Observation windows')).toBeInTheDocument()
    })
    expect(screen.getByText('New conns')).toBeInTheDocument()
    expect(screen.getAllByText(UNKNOWN_TEXT).length).toBeGreaterThanOrEqual(1)
  })

  it('reports a 404 as a device with no baseline, not as a failed request', async () => {
    installFetch({
      'GET /baselines': () => ok(baselinePage([baseline()])),
      'GET /baselines/mac*': () =>
        failure(404, 'No baseline has been learnt for this device.', [
          { field: 'device_key', code: 'BASELINE_NOT_FOUND' },
        ]),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('aa:bb:cc:dd:ee:01').closest('tr') as HTMLElement)

    await waitFor(() => {
      expect(screen.getByText('No baseline for this device')).toBeInTheDocument()
    })
    // A 404 is an answer, so no retry is offered as though one would help.
    expect(screen.queryByRole('button', { name: /retry/i })).toBeNull()
  })

  it('returns to the listing', async () => {
    installFetch({
      'GET /baselines': () => ok(baselinePage([baseline()])),
      'GET /baselines/mac*': () => ok(baseline()),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('aa:bb:cc:dd:ee:01').closest('tr') as HTMLElement)
    await waitFor(() => {
      expect(screen.getByText('All baselines')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('All baselines'))
    await waitFor(() => {
      expect(screen.getByText('Learnt Baselines')).toBeInTheDocument()
    })
  })
})

describe('Baselines loading, empty and error states', () => {
  it('shows a busy panel while the first request is in flight', () => {
    installFetch({ 'GET /baselines': () => new Promise<Response>(() => {}) })
    renderPage()
    expect(screen.getByText('Loading behavioural baselines…')).toBeInTheDocument()
  })

  it('shows the empty state, and says what would populate it', async () => {
    installFetch({ 'GET /baselines': () => ok(baselinePage([])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('No baselines learnt yet')).toBeInTheDocument()
    })
    expect(screen.getByText(/start an authorized capture/i)).toBeInTheDocument()
  })

  it('distinguishes a filter that matched nothing from an empty engine', async () => {
    installFetch({ 'GET /baselines': () => ok(baselinePage([])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('No baselines learnt yet')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'established' } })

    await waitFor(() => {
      expect(screen.getByText('No baselines in this learning state')).toBeInTheDocument()
    })
    expect(screen.queryByText('No baselines learnt yet')).toBeNull()
  })

  it('shows a usable error panel when the backend cannot be reached', async () => {
    vi.stubGlobal('fetch', networkDownFetch())
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(NETWORK_MESSAGE)).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('does not report a failed request as an empty engine', async () => {
    vi.stubGlobal('fetch', networkDownFetch())
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(NETWORK_MESSAGE)).toBeInTheDocument()
    })
    expect(screen.queryByText('No baselines learnt yet')).toBeNull()
  })
})

describe('Baselines reset', () => {
  it('asks for confirmation before deleting, and sends the POST to the encoded path', async () => {
    const router = installFetch({
      'GET /baselines': () => ok(baselinePage([baseline()])),
      'POST /baselines/mac*': () => ok(resetResult()),
    })
    const { showToast } = renderPage()
    await waitFor(() => {
      expect(screen.getByText('aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })

    const row = screen.getByText('aa:bb:cc:dd:ee:01').closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /reset/i }))

    await waitFor(() => {
      expect(screen.getByText('Reset this device’s baseline?')).toBeInTheDocument()
    })
    // Nothing has been sent yet: the dialog is the confirmation step.
    expect(router.countOf('POST /baselines/mac*')).toBe(0)

    fireEvent.click(screen.getByRole('button', { name: /^reset baseline$/i }))

    await waitFor(() => {
      expect(router.countOf('POST /baselines/mac*')).toBe(1)
    })
    expect(router.lastCall('POST /baselines/mac*')?.path).toBe(
      '/baselines/mac%3Aaa%3Abb%3Acc%3Add%3Aee%3A01/reset',
    )
    // The confirmation reports the counts the backend returned, not a guess.
    await waitFor(() => {
      expect(showToast).toHaveBeenCalledWith(
        expect.stringContaining('deleted 12 observation windows'),
        'success',
      )
    })
  })

  it('cancels without sending anything', async () => {
    const router = installFetch({
      'GET /baselines': () => ok(baselinePage([baseline()])),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })

    const row = screen.getByText('aa:bb:cc:dd:ee:01').closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /reset/i }))
    await waitFor(() => {
      expect(screen.getByText('Reset this device’s baseline?')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))

    await waitFor(() => {
      expect(screen.queryByText('Reset this device’s baseline?')).toBeNull()
    })
    expect(router.countOf('POST /baselines*')).toBe(0)
  })

  it('reports a refused reset as an error, and never as success', async () => {
    installFetch({
      'GET /baselines': () => ok(baselinePage([baseline()])),
      'POST /baselines/mac*': () =>
        failure(503, 'The baseline store is unavailable.', [
          { field: 'database', code: 'SERVICE_UNAVAILABLE' },
        ]),
    })
    const { showToast } = renderPage()
    await waitFor(() => {
      expect(screen.getByText('aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })

    const row = screen.getByText('aa:bb:cc:dd:ee:01').closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /reset/i }))
    await waitFor(() => {
      expect(screen.getByText('Reset this device’s baseline?')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button', { name: /^reset baseline$/i }))

    await waitFor(() => {
      expect(showToast).toHaveBeenCalledWith(expect.any(String), 'error')
    })
    expect(showToast).not.toHaveBeenCalledWith(expect.anything(), 'success')
  })

  it('re-reads the listing after a reset, so the page shows the engine', async () => {
    let resets = 0
    const router = installFetch({
      'GET /baselines': () => ok(baselinePage([baseline()])),
      'POST /baselines/mac*': () => {
        resets += 1
        return ok(resetResult())
      },
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })

    const row = screen.getByText('aa:bb:cc:dd:ee:01').closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /reset/i }))
    await waitFor(() => {
      expect(screen.getByText('Reset this device’s baseline?')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button', { name: /^reset baseline$/i }))

    await waitFor(() => {
      expect(resets).toBe(1)
    })
    await waitFor(() => {
      expect(router.countOf('GET /baselines')).toBeGreaterThanOrEqual(2)
    })
  })

  it('resets from the detail view too', async () => {
    const router = installFetch({
      'GET /baselines': () => ok(baselinePage([baseline()])),
      'GET /baselines/mac*': () => ok(baseline()),
      'POST /baselines/mac*': () =>
        ok(resetResult({ windows_deleted: 4, profile_deleted: false })),
    })
    const { showToast } = renderPage()
    await waitFor(() => {
      expect(screen.getByText('aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('aa:bb:cc:dd:ee:01').closest('tr') as HTMLElement)
    await waitFor(() => {
      expect(screen.getByText('Behavioural baseline')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /^reset$/i }))
    await waitFor(() => {
      expect(screen.getByText('Reset this device’s baseline?')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button', { name: /^reset baseline$/i }))

    await waitFor(() => {
      expect(router.countOf('POST /baselines/mac*')).toBe(1)
    })
    // With no published profile, the confirmation must not claim one was deleted.
    await waitFor(() => {
      expect(showToast).toHaveBeenCalledWith(
        expect.stringContaining('No profile had been published yet'),
        'success',
      )
    })
  })
})

describe('Baselines pagination', () => {
  it('offers no next page when the engine reported no more rows', async () => {
    installFetch({ 'GET /baselines': () => ok(baselinePage([baseline()], { has_more: false })) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('All learnt baselines')).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: /next/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /previous/i })).toBeDisabled()
  })

  it('pages forward by the page size when more rows exist', async () => {
    const router = installFetch({
      'GET /baselines': (call: RoutedCall) =>
        call.params['offset'] === '0'
          ? ok(baselinePage([baseline()], { has_more: true, total: 120 }))
          : ok(
              baselinePage([baseline({ device_key: 'mac:02', mac_address: '00:00:00:00:00:02' })], {
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
      expect(router.lastCall('GET /baselines')?.params['offset']).toBe(
        String(DEFAULT_PAGE_LIMIT),
      )
    })
  })
})
