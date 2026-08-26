import { useState } from 'react'
import Sidebar from './components/Sidebar'
import Navbar from './components/Navbar'
import Toast from './components/Toast'
import Dashboard from './pages/Dashboard'
import LiveTraffic from './pages/LiveTraffic'
import Devices from './pages/Devices'
import Alerts from './pages/Alerts'
import Analytics from './pages/Analytics'
import Reports from './pages/Reports'
import Settings from './pages/Settings'

export type Page = 'dashboard' | 'live-traffic' | 'devices' | 'alerts' | 'analytics' | 'reports' | 'settings'

export interface ToastMsg {
  message: string
  type: 'success' | 'error' | 'info'
}

export default function App() {
  const [page, setPage] = useState<Page>('dashboard')
  const [toast, setToast] = useState<ToastMsg | null>(null)
  const [sidebarOpen, setSidebarOpen] = useState(true)

  const showToast = (message: string, type: ToastMsg['type'] = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 3000)
  }

  const renderPage = () => {
    switch (page) {
      case 'dashboard':     return <Dashboard showToast={showToast} />
      case 'live-traffic':  return <LiveTraffic showToast={showToast} />
      case 'devices':       return <Devices showToast={showToast} />
      case 'alerts':        return <Alerts showToast={showToast} />
      case 'analytics':     return <Analytics />
      case 'reports':       return <Reports showToast={showToast} />
      case 'settings':      return <Settings showToast={showToast} />
    }
  }

  return (
    <div className="flex h-screen overflow-hidden" style={{ backgroundColor: '#020617' }}>
      <Sidebar currentPage={page} onNavigate={setPage} isOpen={sidebarOpen} />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <Navbar
          onMenuToggle={() => setSidebarOpen(o => !o)}
          currentPage={page}
          showToast={showToast}
        />
        <main
          className="flex-1 overflow-auto p-6"
          style={{ backgroundColor: '#020617' }}
        >
          {renderPage()}
        </main>
      </div>
      {toast && (
        <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />
      )}
    </div>
  )
}
