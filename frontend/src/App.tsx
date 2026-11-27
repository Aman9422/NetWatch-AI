/**
 * The application shell (M15.35).
 *
 * One `Page` union, one switch, and every route present. The mock-era shell routed
 * seven pages and had no route for the sections the backend actually exposes —
 * incidents, detections, connections, system and notifications had no way in — so
 * those pages existed but were unreachable by navigation. Reachability is part of
 * the deliverable, not an afterthought (M15.35).
 *
 * Two details of this file are deliberate:
 *
 * * **A page receives `showToast` only if it can act.** The read-only views
 *   (analytics, system, notifications) declare no props at all, so they cannot
 *   raise a toast for something that did not happen. The prop's presence is the
 *   contract.
 * * **Switching a route unmounts the page it leaves.** That is what makes
 *   cleanup real: each page's hooks abort their in-flight reads and close their
 *   WebSocket subscriptions on unmount, so navigating away cannot leave a second
 *   connection behind (M15.35/M15.27).
 */

import { lazy, useEffect, useState } from 'react'
import Sidebar from './components/Sidebar'
import Navbar from './components/Navbar'
import Toast from './components/Toast'
import { LazyPage } from './components/PageBoundary'
import { isNarrowViewport, onEnterNarrowViewport } from './lib/viewport'

/**
 * The pages, each in its own chunk (M19.8).
 *
 * M18 measured the built shell at 907.84 kB of JavaScript in a single file —
 * every page, the charting library and the icon set, over Vite's 500 kB advisory.
 * `lazy` keeps each page's code out of that first download, so the shell and the
 * sidebar arrive immediately and a page's chunk follows when it is opened.
 *
 * Dashboard is lazy too, despite being the landing page: it is one of only two
 * pages that import the charting library, so leaving it eager would keep that
 * library in the entry chunk and the split would move almost nothing. The cost is
 * a brief `LazyPage` fallback on first paint.
 *
 * The page modules are unchanged; this is a delivery change, not a redesign.
 */
const Dashboard = lazy(() => import('./pages/Dashboard'))
const LiveTraffic = lazy(() => import('./pages/LiveTraffic'))
const Devices = lazy(() => import('./pages/Devices'))
const Connections = lazy(() => import('./pages/Connections'))
const Baselines = lazy(() => import('./pages/Baselines'))
const Anomalies = lazy(() => import('./pages/Anomalies'))
const Detections = lazy(() => import('./pages/Detections'))
const Alerts = lazy(() => import('./pages/Alerts'))
const Incidents = lazy(() => import('./pages/Incidents'))
const Analytics = lazy(() => import('./pages/Analytics'))
const Reports = lazy(() => import('./pages/Reports'))
const Notifications = lazy(() => import('./pages/Notifications'))
const System = lazy(() => import('./pages/System'))
const AIConfiguration = lazy(() => import('./pages/AIConfiguration'))
const Settings = lazy(() => import('./pages/Settings'))

/** Every view the shell can show. The sidebar renders this set. */
export type Page =
  | 'dashboard'
  | 'live-traffic'
  | 'devices'
  | 'connections'
  | 'baselines'
  | 'anomalies'
  | 'detections'
  | 'alerts'
  | 'incidents'
  | 'analytics'
  | 'reports'
  | 'notifications'
  | 'system'
  | 'ai-configuration'
  | 'settings'

/** A message the shell shows briefly and then clears. */
export interface ToastMsg {
  message: string
  type: 'success' | 'error' | 'info'
}

/** How long a toast stays on screen. */
const TOAST_LIFETIME_MS = 4_000

export default function App() {
  const [page, setPage] = useState<Page>('dashboard')
  const [toast, setToast] = useState<ToastMsg | null>(null)
  // The rail is a 272px column. A phone-width window would leave the page a few
  // dozen pixels wide, so a narrow viewport starts with the rail collapsed; the
  // navbar's menu button still opens it (M16.15).
  const [sidebarOpen, setSidebarOpen] = useState(() => !isNarrowViewport())

  useEffect(() => onEnterNarrowViewport(() => setSidebarOpen(false)), [])

  const showToast = (message: string, type: ToastMsg['type'] = 'success') => {
    setToast({ message, type })
    window.setTimeout(() => setToast(null), TOAST_LIFETIME_MS)
  }

  const dismissToast = () => setToast(null)

  const renderPage = () => {
    switch (page) {
      case 'dashboard':
        return <Dashboard showToast={showToast} />
      case 'live-traffic':
        return <LiveTraffic showToast={showToast} />
      case 'devices':
        return <Devices showToast={showToast} />
      case 'connections':
        return <Connections showToast={showToast} />
      case 'baselines':
        return <Baselines showToast={showToast} />
      case 'anomalies':
        return <Anomalies showToast={showToast} />
      case 'detections':
        return <Detections showToast={showToast} />
      case 'alerts':
        return <Alerts showToast={showToast} />
      case 'incidents':
        return <Incidents showToast={showToast} />
      case 'analytics':
        return <Analytics />
      case 'reports':
        return <Reports showToast={showToast} />
      case 'notifications':
        return <Notifications />
      case 'system':
        return <System />
      case 'ai-configuration':
        return <AIConfiguration showToast={showToast} />
      case 'settings':
        return <Settings showToast={showToast} />
    }
  }

  return (
    <div className="flex h-screen overflow-hidden" style={{ backgroundColor: '#020617' }}>
      <Sidebar currentPage={page} onNavigate={setPage} isOpen={sidebarOpen} />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <Navbar
          onMenuToggle={() => setSidebarOpen(open => !open)}
          currentPage={page}
          onNavigate={setPage}
        />
        {/* The page is keyed by its own name, so a route change tears the previous
            page down rather than letting its subscriptions linger beside the new
            page's (M15.35). */}
        <main className="flex-1 overflow-auto p-6" style={{ backgroundColor: '#020617' }}>
          <div key={page} className="fade-in-up">
            {/* The route name also resets a page whose chunk failed to load, so
                returning to it later is a fresh attempt rather than a stale error
                (M19.8). */}
            <LazyPage resetKey={page}>{renderPage()}</LazyPage>
          </div>
        </main>
      </div>
      {toast !== null && (
        <Toast message={toast.message} type={toast.type} onClose={dismissToast} />
      )}
    </div>
  )
}
