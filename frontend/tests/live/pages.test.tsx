// @vitest-environment jsdom
/**
 * The live page suite (M15.39).
 *
 * This is the last link in the chain the milestone names:
 *
 *     FastAPI REST  →  the application's service layer  →  a page  →  the DOM
 *
 * It renders the **real `<App />`** — the real shell, the real sidebar, the real
 * pages, their real hooks — and drives navigation by clicking the sidebar, so what
 * is asserted is what an operator sees rather than a page mounted in isolation.
 * `fetch` is the runtime's and the backend is the running FastAPI application: no
 * service is stubbed and no response is fabricated.
 *
 * **What the page must show is derived from the backend, not hardcoded.** Every
 * expectation below is computed by calling the same endpoint the page calls and
 * turning the answer into the string the page would render. A test pinned to "3
 * alerts" would be a test of this developer's database; a test that asks the
 * backend and then asks the screen is a test of the application.
 *
 * ## Why Live Traffic is not in this file
 *
 * That page's data arrives on `/ws/packets`, and a DOM environment here cannot use
 * a real socket — not a preference, a measured limit, explained in full in
 * `live-setup.ts`. Rendering the page under an inert socket would assert nothing
 * about the stream, so it is covered where it can be:
 *
 * * `tests/live/websocket.test.ts` proves the real channel, the real frames and the
 *   application's own socket layer;
 * * `src/pages/LiveTraffic.test.tsx` proves the page's rendering of a packet event
 *   against the application's controllable fake;
 * * the browser run (M15.40) proves the two together, as a user would.
 */

import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import App from '@/App'
import { environment } from '@/config/env'
import { formatCount } from '@/lib/format'
import {
  channelHub,
  fetchAlerts,
  fetchDashboardSummary,
  fetchDevices,
  fetchReports,
  fetchSettings,
  fetchSystemHealth,
  fetchSystemInfo,
} from '@/services'
import { ALERT_SEVERITY_ORDER } from '@/types'

/** The severity label the Alerts page renders for one severity. */
function severityLabel(severity: string): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1)
}

/**
 * Click a sidebar entry.
 *
 * The rail is the application's own navigation, so navigating by clicking it tests
 * the route table and the page together — the reachability M15.35 requires.
 */
async function navigateTo(label: string): Promise<void> {
  const user = userEvent.setup()
  // Scoped to the navigation rail. The header carries its own "System" and
  // "Notifications" buttons, so an unscoped role query matches two elements —
  // and taking whichever came first would make the test order-dependent.
  const rail = screen.getByRole('navigation')
  await user.click(within(rail).getByRole('button', { name: label }))
}

describe('the application against the live backend', () => {
  it('renders the dashboard from the real summary endpoint (M15.9)', async () => {
    const summary = await fetchDashboardSummary()
    render(<App />)

    // The shell renders its own navigation and states the backend it is pointed at
    // (M15.3): a public build-time value, which is why it may be shown at all.
    // The endpoint is shown twice on purpose — the rail's "Connected backend" card
    // and the header's endpoint chip (M15.37) — so both are expected, not one.
    expect(screen.getAllByText(environment.apiBaseUrl).length).toBeGreaterThan(0)
    expect(await screen.findByText('Live Throughput')).toBeInTheDocument()

    const alerts = summary.alerts.data
    if (alerts === null) {
      // An unavailable section must say so rather than render a calm zero
      // (M13.29/M15.8).
      expect(await screen.findByText('This section could not be read')).toBeInTheDocument()
      return
    }

    // The stored-alert total, as the backend reports it and formatted the way the
    // page formats it.
    expect(await screen.findByText(`${formatCount(alerts.total)} stored`)).toBeInTheDocument()

    const devices = summary.devices.data
    if (devices !== null && Object.keys(devices.by_status).length === 0) {
      expect(await screen.findByText('No devices observed')).toBeInTheDocument()
    }
  })

  it('navigates to Devices and renders the live registry (M15.12 / M15.35)', async () => {
    const page = await fetchDevices()
    render(<App />)
    await navigateTo('Devices')

    expect(await screen.findByText('Observed Devices')).toBeInTheDocument()

    if (page.count === 0) {
      // The empty state is the honest rendering of an empty registry, not a blank
      // screen (M15.8).
      expect(await screen.findByText('No devices observed')).toBeInTheDocument()
      return
    }

    const first = page.devices[0]
    if (first === undefined) return
    expect((await screen.findAllByText(first.device_id)).length).toBeGreaterThan(0)
  })

  it('navigates to Alerts and renders a stored alert (M15.14)', async () => {
    const page = await fetchAlerts({}, { limit: 5 })
    render(<App />)
    await navigateTo('Alerts')

    // The header shows the route name as an `h1` and the page titles its own table
    // `Alerts` too, so more than one match is the correct state rather than a bug.
    expect((await screen.findAllByRole('heading', { name: 'Alerts' })).length).toBeGreaterThan(0)

    const first = page.alerts[0]
    if (first === undefined) {
      expect(await screen.findByText('No alerts raised')).toBeInTheDocument()
      return
    }

    // The row's own title and severity, both read from the backend.
    expect((await screen.findAllByText(first.title)).length).toBeGreaterThan(0)
    expect(ALERT_SEVERITY_ORDER).toContain(first.severity)
    expect((await screen.findAllByText(severityLabel(first.severity))).length).toBeGreaterThan(0)
  })

  it('navigates to System and renders the backend\'s own verdict (M15.24)', async () => {
    const [info, health] = await Promise.all([fetchSystemInfo(), fetchSystemHealth()])
    render(<App />)
    await navigateTo('System')

    // Two headings read `System` here: the header names the route and the page
    // names itself. Both are intended, so more than one match is the state that is
    // correct — asserting a single match would fail on the shell doing its job.
    expect((await screen.findAllByRole('heading', { name: 'System' })).length).toBeGreaterThan(0)

    // Identity comes from `/system/info` and is rendered as the backend reported
    // it — the page computes nothing (M15.24).
    expect((await screen.findAllByText(info.app_name)).length).toBeGreaterThan(0)
    expect((await screen.findAllByText(info.app_version)).length).toBeGreaterThan(0)

    // The verdict is the backend's word for it, and each probe is shown verbatim.
    expect((await screen.findAllByText(health.status)).length).toBeGreaterThan(0)
    for (const check of health.checks) {
      expect((await screen.findAllByText(check.name)).length).toBeGreaterThan(0)
    }
  })

  it('navigates to every REST-only page without an error state (M15.8)', async () => {
    render(<App />)

    await navigateTo('Analytics')
    expect(await screen.findByText('Network Analytics')).toBeInTheDocument()
    expect(screen.queryByText('Unable to load analytics')).toBeNull()

    await navigateTo('Reports')
    expect(await screen.findByText('Stored reports')).toBeInTheDocument()
    expect(screen.queryByText('Unable to load reports')).toBeNull()

    await navigateTo('Settings')
    expect(await screen.findByText('Runtime settings')).toBeInTheDocument()
    expect(screen.queryByText('Unable to load settings')).toBeNull()
  })

  it('closes the dashboard channel when the route changes (M15.35)', async () => {
    render(<App />)
    // The dashboard subscribes on mount; its socket is real to the hub, whichever
    // constructor produced it.
    await screen.findByText('Live Throughput')
    expect(channelHub.socketFor('dashboard')).not.toBeNull()

    await navigateTo('Devices')
    expect(await screen.findByText('Observed Devices')).toBeInTheDocument()
    // Navigating away released the subscription, and the hub closed the channel
    // because nobody was left listening.
    expect(channelHub.socketFor('dashboard')).toBeNull()
  })

  it('renders the settings page from the real listing (M15.23)', async () => {
    const page = await fetchSettings()
    render(<App />)
    await navigateTo('Settings')

    expect(await screen.findByText('Runtime settings')).toBeInTheDocument()
    if (page.count === 0) {
      expect(await screen.findByText('No readable settings')).toBeInTheDocument()
    }
  })

  it('renders the reports page from the real metadata listing (M15.22)', async () => {
    const page = await fetchReports()
    render(<App />)
    await navigateTo('Reports')

    expect(await screen.findByText('Stored reports')).toBeInTheDocument()
    if (page.total === 0) {
      expect(await screen.findByText('No reports stored')).toBeInTheDocument()
    }
  })
})
