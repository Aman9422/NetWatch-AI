/**
 * The header bar (M15.35).
 *
 * The mock-era header carried four things that were not real: three notifications
 * with fixed text and "2 min ago" stamps, a "Capture Running" pill that was not
 * reading anything, a search field for a search endpoint that does not exist, and
 * a signed-in profile for an application with no user model. All four are gone
 * rather than restyled — a control that cannot do what it says is worse than no
 * control (M15.31).
 *
 * What remains is what the shell can honestly show at all times:
 *
 * * the page's own name, and a clock that actually ticks;
 * * the configured backend endpoint, which is **public by design** — every
 *   `VITE_*` value is client-visible (M15.37) — and is the fastest way for an
 *   operator to see which backend a browser is talking to;
 * * a link to Notifications with no invented count. A real unread tally exists,
 *   but reading it here would issue a request on every page for a badge, and
 *   M15.34 rules out polling that is not needed; the notifications page carries
 *   its own authoritative count instead.
 *
 * This component deliberately opens **no** WebSocket subscription. It is mounted
 * on every route, so a channel opened here would be a second connection beside
 * the page's own — exactly the duplication M15.28 and M15.35 forbid.
 */

import { useEffect, useState } from 'react'
import { Bell, Menu, Server } from 'lucide-react'
import { environment } from '../config/env'
import { C } from '../lib/tokens'
import type { Page } from '../App'

/** The heading shown for each route. */
const TITLES: Readonly<Record<Page, string>> = {
  'dashboard': 'Dashboard',
  'live-traffic': 'Live Traffic',
  'devices': 'Devices',
  'connections': 'Connections',
  'detections': 'Detections',
  'alerts': 'Alerts',
  'incidents': 'Incidents',
  'analytics': 'Analytics',
  'reports': 'Reports',
  'notifications': 'Notifications',
  'system': 'System',
  'settings': 'Settings',
}

/** How often the clock re-renders, so it does not show a stale minute. */
const CLOCK_TICK_MS = 30_000

interface Props {
  onMenuToggle: () => void
  currentPage: Page
  onNavigate: (page: Page) => void
}

export default function Navbar({ onMenuToggle, currentPage, onNavigate }: Props) {
  const [now, setNow] = useState(() => new Date())

  // A real clock, updated on a timer and cleaned up on unmount — the one timer in
  // this shell that is not simulating anything.
  useEffect(() => {
    const handle = window.setInterval(() => setNow(new Date()), CLOCK_TICK_MS)
    return () => window.clearInterval(handle)
  }, [])

  const dateText = now.toLocaleDateString(undefined, {
    weekday: 'long', month: 'long', day: 'numeric',
  })
  const timeText = now.toLocaleTimeString(undefined, {
    hour: '2-digit', minute: '2-digit',
  })

  return (
    <header
      className="flex items-center px-6 gap-4 border-b shrink-0 relative z-30"
      style={{ height: '72px', backgroundColor: C.panel, borderColor: C.card }}>
      <button
        onClick={onMenuToggle}
        aria-label="Toggle navigation"
        className="p-2 rounded-xl transition-colors"
        style={{ color: C.muted }}
        onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.05)')}
        onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
        <Menu size={18} />
      </button>

      {/* Below `sm` the two route buttons drop to their icons, so that the page
          name keeps a readable width instead of being squeezed until it paints
          over the page under it. */}
      <div className="min-w-0">
        <h1 className="text-base font-semibold text-white truncate">{TITLES[currentPage]}</h1>
        <p className="text-xs truncate" style={{ color: C.faint }}>{dateText} · {timeText}</p>
      </div>

      <div className="flex-1" />

      {/* Which backend this browser is talking to. Public configuration, shown
          because knowing it is what makes a failed request diagnosable. */}
      <div
        className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-xl border max-w-85"
        style={{ backgroundColor: C.card, borderColor: C.border }}
        title={`REST API base URL: ${environment.apiBaseUrl} — a Vite environment value, so it is visible to the browser by design.`}>
        <Server size={12} style={{ color: C.faint, flexShrink: 0 }} />
        <span className="mono text-xs truncate" style={{ color: C.muted }}>
          {environment.apiBaseUrl}
        </span>
      </div>

      <button
        onClick={() => onNavigate('notifications')}
        className="flex items-center gap-2 px-3 py-2 rounded-xl border text-xs font-medium transition-colors"
        style={{
          backgroundColor: currentPage === 'notifications' ? 'rgba(56,189,248,0.12)' : C.card,
          borderColor: currentPage === 'notifications' ? C.accent : C.border,
          color: currentPage === 'notifications' ? C.accent : C.muted,
        }}
        title="Stored notifications. The page reads the backend's own unread count — this button shows no count of its own.">
        <Bell size={14} />
        <span className="hidden sm:inline">Notifications</span>
      </button>

      <button
        onClick={() => onNavigate('system')}
        className="flex items-center gap-2 px-3 py-2 rounded-xl border text-xs font-medium transition-colors"
        style={{
          backgroundColor: currentPage === 'system' ? 'rgba(56,189,248,0.12)' : C.card,
          borderColor: currentPage === 'system' ? C.accent : C.border,
          color: currentPage === 'system' ? C.accent : C.muted,
        }}
        title="Process, database and pipeline status, as the backend reports it.">
        <Server size={14} />
        <span className="hidden sm:inline">System</span>
      </button>
    </header>
  )
}
