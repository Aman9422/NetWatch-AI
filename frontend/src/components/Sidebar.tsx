import React from 'react'
import { Gauge, Activity, Monitor, TriangleAlert, BarChart2, FileText, Settings, Shield, Radio, ChevronRight } from 'lucide-react'
import type { Page } from '../App'

const NAV: { id: Page; label: string; icon: React.ElementType; badge?: number }[] = [
  { id: 'dashboard',    label: 'Dashboard',    icon: Gauge },
  { id: 'live-traffic', label: 'Live Traffic',  icon: Activity },
  { id: 'devices',      label: 'Devices',       icon: Monitor },
  { id: 'alerts',       label: 'Alerts',        icon: TriangleAlert, badge: 3 },
  { id: 'analytics',    label: 'Analytics',     icon: BarChart2 },
  { id: 'reports',      label: 'Reports',       icon: FileText },
  { id: 'settings',     label: 'Settings',      icon: Settings },
]

interface Props {
  currentPage: Page
  onNavigate: (p: Page) => void
  isOpen: boolean
}

export default function Sidebar({ currentPage, onNavigate, isOpen }: Props) {
  return (
    <aside
      className="flex flex-col flex-shrink-0 border-r transition-all duration-300 overflow-hidden"
      style={{
        width: isOpen ? '280px' : '0',
        minWidth: isOpen ? '280px' : '0',
        backgroundColor: '#0F172A',
        borderColor: '#1E293B',
      }}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-6 py-5 border-b" style={{ borderColor: '#1E293B' }}>
        <div
          className="flex items-center justify-center w-9 h-9 rounded-xl flex-shrink-0"
          style={{ background: 'linear-gradient(135deg, #38BDF8, #0EA5E9)' }}
        >
          <Shield size={18} color="#0F172A" />
        </div>
        <div className="min-w-0">
          <div className="text-sm font-bold text-white tracking-wide">NetWatch AI</div>
          <div className="text-xs font-medium" style={{ color: '#38BDF8' }}>Security Platform</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-5 overflow-y-auto">
        <p className="text-xs font-semibold uppercase tracking-widest px-3 mb-3" style={{ color: '#475569' }}>
          Main Menu
        </p>
        <div className="space-y-0.5">
          {NAV.map(({ id, label, icon: Icon, badge }) => {
            const active = currentPage === id
            return (
              <button
                key={id}
                onClick={() => onNavigate(id as Page)}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-150"
                style={{
                  backgroundColor: active ? 'rgba(56,189,248,0.12)' : 'transparent',
                  color: active ? '#38BDF8' : '#94A3B8',
                  borderLeft: active ? '2px solid #38BDF8' : '2px solid transparent',
                }}
                onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.backgroundColor = 'rgba(255,255,255,0.04)' }}
                onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.backgroundColor = 'transparent' }}
              >
                <Icon size={16} />
                <span className="flex-1 text-left">{label}</span>
                {badge && (
                  <span className="text-xs px-1.5 py-0.5 rounded-full font-semibold" style={{ backgroundColor: '#EF4444', color: '#fff' }}>
                    {badge}
                  </span>
                )}
                {active && <ChevronRight size={14} className="opacity-60" />}
              </button>
            )
          })}
        </div>
      </nav>

      {/* Capture indicator */}
      <div className="mx-3 mb-4">
        <div
          className="px-4 py-3 rounded-xl border"
          style={{ backgroundColor: 'rgba(34,197,94,0.07)', borderColor: 'rgba(34,197,94,0.2)' }}
        >
          <div className="flex items-center gap-2 mb-1.5">
            <span className="relative flex h-2 w-2">
              <span
                className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75"
                style={{ backgroundColor: '#22C55E' }}
              />
              <span className="relative inline-flex rounded-full h-2 w-2" style={{ backgroundColor: '#22C55E' }} />
            </span>
            <span className="text-xs font-semibold" style={{ color: '#22C55E' }}>Capture Running</span>
          </div>
          <div className="flex items-center gap-2">
            <Radio size={10} style={{ color: '#64748B' }} />
            <span className="text-xs mono" style={{ color: '#64748B' }}>eth0 · 952 pkts/s</span>
          </div>
        </div>
      </div>
    </aside>
  )
}
