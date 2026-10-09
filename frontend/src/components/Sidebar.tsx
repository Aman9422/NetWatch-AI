/**
 * The navigation rail (M15.35).
 *
 * Two pieces of the mock-era rail are gone, and both were the same mistake in
 * different clothes — a number that looked live and was not:
 *
 * * **`badge: 3` on Alerts.** A hardcoded count beside a link is a claim about
 *   current state, and it was never read from anywhere. A real open-alert figure
 *   exists in the dashboard summary, but fetching it here would mean this rail —
 *   mounted on every route — subscribing to a resource the page is already
 *   reading, which is the duplicate subscription M15.28 forbids. The rail
 *   therefore shows no count, and each page shows its own authoritative one.
 * * **"Capture Running · eth0 · 952 pkts/s".** A capture indicator that is not
 *   reading the capture state is worse than none: an operator would trust it.
 *   The real state is on the Dashboard and on System, where it is read from the
 *   backend.
 *
 * The footer states the two configured endpoints instead. Those are public
 * configuration — every `VITE_*` value is client-visible by design (M15.37) — and
 * showing them is how an operator confirms which backend a browser reached
 * without opening a console.
 *
 * The routes are grouped by what the operator is doing rather than listed flat,
 * because twelve entries in one column of equal weight gives no clue which of
 * them answers the same question.
 */

import type { ElementType } from 'react'
import {
  Activity, BarChart2, Bell, FileText, Gauge, GitCompareArrows, Layers,
  Monitor, Radar, Server, Settings as Cog, Shield, ShieldAlert, TriangleAlert,
} from 'lucide-react'
import { environment } from '../config/env'
import { C, tint } from '../lib/tokens'
import type { Page } from '../App'

/** One navigation entry. */
interface NavItem {
  readonly id: Page
  readonly label: string
  readonly icon: ElementType
  /** One line on what the page answers, shown as a tooltip. */
  readonly hint: string
}

/** One titled group of entries. */
interface NavGroup {
  readonly title: string
  readonly items: readonly NavItem[]
}

/**
 * Every route, grouped.
 *
 * The order follows the pipeline rather than the alphabet: what is on the wire
 * first, then what was derived from it, then the operational surface.
 */
const NAV_GROUPS: readonly NavGroup[] = [
  {
    title: 'Observe',
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: Gauge,
        hint: 'The consolidated summary, refreshed from REST and kept current by the dashboard channel.' },
      { id: 'live-traffic', label: 'Live Traffic', icon: Activity,
        hint: 'Normalized packets as they arrive on the packets channel. Bounded, and no payload is ever sent.' },
      { id: 'devices', label: 'Devices', icon: Monitor,
        hint: 'Devices the registry has observed. Activity state only — M8 scores nothing.' },
      { id: 'connections', label: 'Connections', icon: GitCompareArrows,
        hint: 'Conversations the tracker follows, with the tracker\'s own expiry state.' },
    ],
  },
  {
    title: 'Detect',
    items: [
      { id: 'detections', label: 'Detections', icon: Radar,
        hint: 'Raw findings from the detection engine, with their evidence. A finding is not an alert.' },
      { id: 'alerts', label: 'Alerts', icon: TriangleAlert,
        hint: 'Evidence-based alerts and their lifecycle, updated live on the alerts channel.' },
      { id: 'incidents', label: 'Incidents', icon: ShieldAlert,
        hint: 'Correlated alerts, with risk score, correlation confidence and alert confidence kept separate.' },
    ],
  },
  {
    title: 'Analyse',
    items: [
      { id: 'analytics', label: 'Analytics', icon: BarChart2,
        hint: 'Derived totals and rankings from the M6 snapshot, the registries and the detection layers.' },
      { id: 'reports', label: 'Reports', icon: FileText,
        hint: 'Stored report metadata. No report writer exists yet, and no file is served.' },
    ],
  },
  {
    title: 'Operate',
    items: [
      { id: 'notifications', label: 'Notifications', icon: Bell,
        hint: 'Stored notification records. Nothing is delivered anywhere, and there is no mark-as-read.' },
      { id: 'system', label: 'System', icon: Layers,
        hint: 'Process identity, health probes, database reachability and pipeline stages.' },
      { id: 'settings', label: 'Settings', icon: Cog,
        hint: 'The keys the backend exposes, with only the writable ones editable.' },
    ],
  },
]

interface Props {
  currentPage: Page
  onNavigate: (page: Page) => void
  isOpen: boolean
}

export default function Sidebar({ currentPage, onNavigate, isOpen }: Props) {
  return (
    <aside
      className="flex flex-col shrink-0 border-r transition-all duration-300 overflow-hidden"
      style={{
        width: isOpen ? '272px' : '0',
        minWidth: isOpen ? '272px' : '0',
        backgroundColor: C.panel,
        borderColor: C.card,
      }}>
      {/* Identity */}
      <div className="flex items-center gap-3 px-6 py-5 border-b shrink-0"
        style={{ borderColor: C.card }}>
        <div className="flex items-center justify-center w-9 h-9 rounded-xl shrink-0"
          style={{ background: 'linear-gradient(135deg, #38BDF8, #0EA5E9)' }}>
          <Shield size={18} color="#0F172A" />
        </div>
        <div className="min-w-0">
          <div className="text-sm font-bold text-white tracking-wide">NetWatch AI</div>
          <div className="text-xs font-medium" style={{ color: C.accent }}>
            Network detection
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 overflow-y-auto">
        {NAV_GROUPS.map(group => (
          <div key={group.title} className="mb-4">
            <p className="text-xs font-semibold uppercase tracking-widest px-3 mb-2"
              style={{ color: C.dim }}>
              {group.title}
            </p>
            <div className="space-y-0.5">
              {group.items.map(({ id, label, icon: Icon, hint }) => {
                const active = currentPage === id
                return (
                  <button
                    key={id}
                    onClick={() => onNavigate(id)}
                    title={hint}
                    className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-150"
                    style={{
                      backgroundColor: active ? tint(C.accent, 0.12) : 'transparent',
                      color: active ? C.accent : C.muted,
                      borderLeft: active ? `2px solid ${C.accent}` : '2px solid transparent',
                    }}
                    onMouseEnter={e => {
                      if (!active) e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.04)'
                    }}
                    onMouseLeave={e => {
                      if (!active) e.currentTarget.style.backgroundColor = 'transparent'
                    }}>
                    <Icon size={16} />
                    <span className="flex-1 text-left">{label}</span>
                  </button>
                )
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Which backend this session is pointed at. Public configuration only —
          no secret is read here, and none could be: Vite inlines VITE_* into the
          bundle, so anything here is already visible to the browser. */}
      <div className="mx-3 mb-4 shrink-0">
        <div className="px-4 py-3 rounded-xl border"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="flex items-center gap-2 mb-2">
            <Server size={11} style={{ color: C.faint }} />
            <span className="text-xs font-semibold" style={{ color: C.muted }}>Connected backend</span>
          </div>
          <div className="space-y-1">
            <div className="mono text-xs break-all" style={{ color: C.faint }}
              title="REST API base URL (VITE_API_BASE_URL)">
              {environment.apiBaseUrl}
            </div>
            <div className="mono text-xs break-all" style={{ color: C.faint }}
              title="WebSocket base URL (VITE_WS_BASE_URL)">
              {environment.wsBaseUrl}
            </div>
          </div>
          <p className="text-xs mt-2" style={{ color: C.dim }}>
            Both are browser-visible build-time values; no credential is read here.
          </p>
        </div>
      </div>
    </aside>
  )
}
