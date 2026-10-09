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

import { useEffect, useState } from 'react'
import Sidebar from './components/Sidebar'
import Navbar from './components/Navbar'
import Toast from './components/Toast'
import Dashboard from './pages/Dashboard'
import LiveTraffic from './pages/LiveTraffic'
import Devices from './pages/Devices'
import Connections from './pages/Connections'
import Detections from './pages/Detections'
import Alerts from './pages/Alerts'
import Incidents from './pages/Incidents'
import Analytics from './pages/Analytics'
import Reports from './pages/Reports'
import Notifications from './pages/Notifications'
import System from './pages/System'
import Settings from './pages/Settings'
import { isNarrowViewport, onEnterNarrowViewport } from './lib/viewport'

/** Every view the shell can show. The sidebar renders this set. */
export type Page =
  | 'dashboard'
  | 'live-traffic'
  | 'devices'
  | 'connections'
  | 'detections'
  | 'alerts'
  | 'incidents'
  | 'analytics'
  | 'reports'
  | 'notifications'
  | 'system'
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
            {renderPage()}
          </div>
        </main>
      </div>
      {toast !== null && (
        <Toast message={toast.message} type={toast.type} onClose={dismissToast} />
      )}
    </div>
  )
}
