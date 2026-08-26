import { useState } from 'react'
import { Menu, Bell, Search, ChevronDown, Shield, AlertTriangle, CheckCircle, Info } from 'lucide-react'
import type { Page, ToastMsg } from '../App'

const TITLES: Record<Page, string> = {
  'dashboard':    'Dashboard',
  'live-traffic': 'Live Traffic',
  'devices':      'Devices',
  'alerts':       'Alerts',
  'analytics':    'Analytics',
  'reports':      'Reports',
  'settings':     'Settings',
}

const NOTIFS = [
  { id: 1, icon: AlertTriangle, color: '#EF4444', label: 'High', msg: 'Port scan detected on 192.168.1.20', time: '2 min ago' },
  { id: 2, icon: Info,          color: '#38BDF8', label: 'Info', msg: 'Capture started on interface eth0', time: '15 min ago' },
  { id: 3, icon: CheckCircle,   color: '#22C55E', label: 'OK',   msg: 'Network report generated successfully', time: '1 hr ago' },
]

interface Props {
  onMenuToggle: () => void
  currentPage: Page
  showToast: (msg: string, type?: ToastMsg['type']) => void
}

export default function Navbar({ onMenuToggle, currentPage, showToast: _showToast }: Props) {
  const [notifOpen, setNotifOpen] = useState(false)
  const now = new Date()
  const dateStr = now.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' })
  const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })

  return (
    <header
      className="flex items-center px-6 gap-4 border-b flex-shrink-0 relative z-30"
      style={{ height: '72px', backgroundColor: '#0F172A', borderColor: '#1E293B' }}
    >
      <button
        onClick={onMenuToggle}
        className="p-2 rounded-xl transition-colors"
        style={{ color: '#94A3B8' }}
        onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.05)')}
        onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
      >
        <Menu size={18} />
      </button>

      <div className="min-w-0">
        <h1 className="text-base font-semibold text-white">{TITLES[currentPage]}</h1>
        <p className="text-xs" style={{ color: '#64748B' }}>{dateStr} · {timeStr}</p>
      </div>

      {/* Live badge */}
      <div
        className="flex items-center gap-2 px-3 py-1.5 rounded-full border"
        style={{ backgroundColor: 'rgba(34,197,94,0.08)', borderColor: 'rgba(34,197,94,0.25)' }}
      >
        <span className="relative flex h-1.5 w-1.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style={{ backgroundColor: '#22C55E' }} />
          <span className="relative inline-flex rounded-full h-1.5 w-1.5" style={{ backgroundColor: '#22C55E' }} />
        </span>
        <span className="text-xs font-medium" style={{ color: '#22C55E' }}>Capture Running</span>
      </div>

      <div className="flex-1" />

      {/* Search */}
      <button
        className="flex items-center gap-2 px-3 py-2 rounded-xl border text-xs"
        style={{ backgroundColor: '#1E293B', borderColor: '#334155', color: '#64748B', width: '220px' }}
      >
        <Search size={13} />
        <span className="flex-1 text-left">Search packets, IPs, alerts…</span>
        <span
          className="px-1.5 py-0.5 rounded border mono text-xs"
          style={{ borderColor: '#334155', color: '#475569' }}
        >
          ⌘K
        </span>
      </button>

      {/* Notifications */}
      <div className="relative">
        <button
          onClick={() => setNotifOpen(o => !o)}
          className="relative p-2 rounded-xl transition-colors"
          style={{ color: '#94A3B8' }}
          onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.05)')}
          onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
        >
          <Bell size={18} />
          <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full" style={{ backgroundColor: '#EF4444' }} />
        </button>

        {notifOpen && (
          <div
            className="absolute right-0 top-14 w-80 rounded-2xl border shadow-2xl z-50 overflow-hidden fade-in-up"
            style={{ backgroundColor: '#1E293B', borderColor: '#334155' }}
          >
            <div className="flex items-center justify-between px-4 py-3 border-b" style={{ borderColor: '#334155' }}>
              <span className="text-sm font-semibold text-white">Notifications</span>
              <span className="text-xs px-2 py-0.5 rounded-full font-medium" style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: '#EF4444' }}>
                3 new
              </span>
            </div>
            {NOTIFS.map(({ id, icon: Icon, color, label, msg, time }) => (
              <div key={id} className="flex items-start gap-3 px-4 py-3 border-b" style={{ borderColor: '#1E293B' }}>
                <div className="p-1.5 rounded-lg flex-shrink-0" style={{ backgroundColor: `${color}18` }}>
                  <Icon size={13} style={{ color }} />
                </div>
                <div className="min-w-0">
                  <p className="text-xs text-white leading-snug">{msg}</p>
                  <p className="text-xs mt-1" style={{ color: '#64748B' }}>{time}</p>
                </div>
              </div>
            ))}
            <div className="px-4 py-2.5">
              <button className="text-xs font-medium w-full text-center" style={{ color: '#38BDF8' }}>
                View all notifications
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Profile */}
      <button
        className="flex items-center gap-2.5 px-3 py-1.5 rounded-xl border transition-colors"
        style={{ borderColor: '#334155', backgroundColor: 'transparent' }}
        onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.04)')}
        onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
      >
        <div
          className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0"
          style={{ background: 'linear-gradient(135deg, #38BDF8, #0EA5E9)', color: '#0F172A' }}
        >
          JD
        </div>
        <div className="text-left hidden lg:block">
          <div className="text-xs font-medium text-white">John Doe</div>
          <div className="text-xs" style={{ color: '#64748B' }}>Admin</div>
        </div>
        <ChevronDown size={12} style={{ color: '#64748B' }} />
      </button>
    </header>
  )
}
