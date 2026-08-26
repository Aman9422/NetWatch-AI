import { useState, useMemo } from 'react'
import {
  Search, ArrowLeft, Shield, Monitor, Laptop, Server,
  Smartphone, Wifi, AlertTriangle, Download, FileText,
  ChevronUp, ChevronDown, Activity, Brain,
} from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis,
  Tooltip, ResponsiveContainer, CartesianGrid, Cell,
} from 'recharts'
import type { ToastMsg } from '../App'

// ─── Tokens ──────────────────────────────────────────────────────────────────
const C = {
  accent: '#38BDF8', success: '#22C55E', warning: '#F59E0B',
  danger: '#EF4444', info: '#06B6D4', purple: '#818CF8',
  card: '#1E293B', panel: '#0F172A', border: '#334155',
  text: '#F8FAFC', muted: '#94A3B8', faint: '#64748B', dim: '#475569',
}
const TIP = { backgroundColor: C.panel, border: `1px solid ${C.border}`, borderRadius: '10px', fontSize: '12px', fontFamily: 'Inter' }

// ─── Data ─────────────────────────────────────────────────────────────────────
interface Device {
  id: number; hostname: string; ip: string; mac: string; vendor: string
  os: string; type: 'laptop' | 'server' | 'phone' | 'iot' | 'unknown' | 'router'
  bandwidth: string; bwMbps: number; threatScore: number; status: 'online' | 'offline' | 'idle'
  firstSeen: string; lastSeen: string; openPorts: number[]; threats: number; connections: number
}

const DEVICES: Device[] = [
  { id:1, hostname:'DESKTOP-JD01',   ip:'192.168.1.10', mac:'aa:bb:cc:01:02:03', vendor:'Dell Inc.',    os:'Windows 11 Pro',   type:'laptop',  bandwidth:'2.5 GB', bwMbps:18.4, threatScore:22, status:'online',  firstSeen:'2024-01-15', lastSeen:'Just now',  openPorts:[80,443,3389,445],   threats:2,  connections:34 },
  { id:2, hostname:'UNKNOWN-FF00',   ip:'192.168.1.25', mac:'ff:ee:dd:cc:bb:aa', vendor:'Unknown',      os:'Unknown',          type:'unknown', bandwidth:'1.2 GB', bwMbps:24.1, threatScore:94, status:'online',  firstSeen:'2024-03-01', lastSeen:'2 min ago', openPorts:[22,8080,9999,4444], threats:18, connections:12 },
  { id:3, hostname:'NAS-SYNOLOGY',   ip:'192.168.1.5',  mac:'aa:bb:cc:04:05:06', vendor:'Synology',     os:'DSM 7.2',          type:'server',  bandwidth:'980 MB', bwMbps:9.2,  threatScore:5,  status:'online',  firstSeen:'2023-06-10', lastSeen:'Just now',  openPorts:[22,5000,5001,80],   threats:0,  connections:8  },
  { id:4, hostname:'iPhone-15-Pro',  ip:'192.168.1.45', mac:'aa:bb:cc:07:08:09', vendor:'Apple Inc.',   os:'iOS 17.4',         type:'phone',   bandwidth:'450 MB', bwMbps:4.1,  threatScore:8,  status:'online',  firstSeen:'2024-02-20', lastSeen:'5 min ago', openPorts:[443],               threats:0,  connections:6  },
  { id:5, hostname:'GATEWAY-ASUS',   ip:'192.168.1.1',  mac:'aa:bb:cc:0a:0b:0c', vendor:'ASUSTeK',      os:'AsusWRT',          type:'router',  bandwidth:'8.2 GB', bwMbps:42.0, threatScore:12, status:'online',  firstSeen:'2023-01-01', lastSeen:'Just now',  openPorts:[22,80,443,8443],    threats:1,  connections:48 },
  { id:6, hostname:'SAMSUNG-TV',     ip:'192.168.1.88', mac:'aa:bb:cc:10:11:12', vendor:'Samsung',      os:'Tizen 7.0',        type:'iot',     bandwidth:'320 MB', bwMbps:2.8,  threatScore:15, status:'idle',    firstSeen:'2024-01-30', lastSeen:'12 min ago',openPorts:[1900,8001,8080],    threats:0,  connections:4  },
  { id:7, hostname:'IOT-ESP32-01',   ip:'10.0.0.22',    mac:'aa:bb:cc:13:14:15', vendor:'Espressif',    os:'FreeRTOS 5.1',     type:'iot',     bandwidth:'12 MB',  bwMbps:0.4,  threatScore:48, status:'online',  firstSeen:'2024-03-15', lastSeen:'1 min ago', openPorts:[80,1883],           threats:3,  connections:2  },
  { id:8, hostname:'MACBOOK-PRO',    ip:'192.168.1.72', mac:'aa:bb:cc:16:17:18', vendor:'Apple Inc.',   os:'macOS 14.4',       type:'laptop',  bandwidth:'1.8 GB', bwMbps:14.2, threatScore:10, status:'online',  firstSeen:'2024-02-01', lastSeen:'3 min ago', openPorts:[22,443,7000],       threats:0,  connections:22 },
  { id:9, hostname:'UBUNTU-SRV-02',  ip:'10.0.0.15',    mac:'aa:bb:cc:19:1a:1b', vendor:'Dell Inc.',    os:'Ubuntu 22.04 LTS', type:'server',  bandwidth:'980 MB', bwMbps:8.1,  threatScore:7,  status:'online',  firstSeen:'2023-09-01', lastSeen:'Just now',  openPorts:[22,80,443,3306],    threats:0,  connections:15 },
  { id:10,hostname:'ANDROID-PIXEL',  ip:'192.168.1.91', mac:'aa:bb:cc:1c:1d:1e', vendor:'Google LLC',   os:'Android 14',       type:'phone',   bandwidth:'290 MB', bwMbps:2.1,  threatScore:5,  status:'offline', firstSeen:'2024-03-10', lastSeen:'2 hrs ago', openPorts:[],                  threats:0,  connections:0  },
  { id:11,hostname:'RASPI-4B',       ip:'10.0.0.5',     mac:'aa:bb:cc:1f:20:21', vendor:'Raspberry Pi', os:'Raspbian 11',      type:'server',  bandwidth:'145 MB', bwMbps:1.2,  threatScore:18, status:'online',  firstSeen:'2023-11-01', lastSeen:'8 min ago', openPorts:[22,80,8080],        threats:1,  connections:5  },
  { id:12,hostname:'PRINTER-HP',     ip:'192.168.1.99', mac:'aa:bb:cc:22:23:24', vendor:'HP Inc.',      os:'Embedded',         type:'iot',     bandwidth:'8 MB',   bwMbps:0.1,  threatScore:3,  status:'idle',    firstSeen:'2023-07-01', lastSeen:'45 min ago',openPorts:[80,9100,443],       threats:0,  connections:1  },
]

const TYPE_ICON: Record<string, React.ElementType> = {
  laptop: Laptop, server: Server, phone: Smartphone, iot: Wifi,
  unknown: Monitor, router: Activity,
}

function scoreColor(s: number) {
  return s >= 70 ? C.danger : s >= 40 ? C.warning : s >= 20 ? C.info : C.success
}

function trafficSpark(base: number) {
  return Array.from({ length: 24 }, (_, i) => ({
    h: `${String(i).padStart(2, '0')}:00`,
    v: Math.round(Math.max(0, base + Math.sin(i * 0.6) * base * 0.4 + (Math.random() - 0.5) * base * 0.3)),
  }))
}

function protoData() {
  return [
    { name: 'TCP',   value: 55+Math.round(Math.random()*10), color: C.accent  },
    { name: 'UDP',   value: 20+Math.round(Math.random()*8),  color: C.info    },
    { name: 'HTTPS', value: 15+Math.round(Math.random()*6),  color: C.purple  },
    { name: 'Other', value: 5+Math.round(Math.random()*4),   color: C.dim     },
  ]
}

// ─── Stat card ────────────────────────────────────────────────────────────────
function StatCard({ label, value, sub, icon, accent = C.accent }: {
  label: string; value: string | number; sub: string; icon: React.ReactNode; accent?: string
}) {
  return (
    <div className="rounded-2xl border p-4 flex items-center gap-3"
      style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 20px rgba(0,0,0,0.2)' }}>
      <div className="p-2.5 rounded-xl flex-shrink-0" style={{ backgroundColor: `${accent}15` }}>
        <div style={{ color: accent }}>{icon}</div>
      </div>
      <div>
        <div className="text-2xl font-bold text-white leading-none tracking-tight">{value}</div>
        <div className="text-xs font-medium mt-0.5" style={{ color: C.muted }}>{label}</div>
        <div className="text-xs mt-0.5" style={{ color: C.faint }}>{sub}</div>
      </div>
    </div>
  )
}

// ─── Device Details ───────────────────────────────────────────────────────────
function DeviceDetails({ device, onBack, showToast }: {
  device: Device; onBack: () => void; showToast: (m: string, t?: ToastMsg['type']) => void
}) {
  const [tab, setTab] = useState<'traffic' | 'protocols' | 'alerts' | 'timeline'>('traffic')
  const Icon = TYPE_ICON[device.type] ?? Monitor
  const sc = scoreColor(device.threatScore)
  const sparkData = useMemo(() => trafficSpark(device.bwMbps), [device.id])
  const protoDataMemo = useMemo(() => protoData(), [device.id])

  const DEVICE_ALERTS = Array.from({ length: device.threats }, (_, i) => ({
    id: i,
    sev: i === 0 ? 'critical' : i < 3 ? 'high' : 'medium',
    type: ['Port Scan', 'ARP Spoof', 'DNS Flood', 'SYN Flood', 'Data Exfil'][i % 5],
    time: `${12 - i}:${String(Math.floor(Math.random() * 59)).padStart(2,'0')}:${String(Math.floor(Math.random() * 59)).padStart(2,'0')}`,
  }))

  const SEV_C: Record<string, string> = { critical: C.danger, high: C.warning, medium: C.info, low: C.success }

  const TIMELINE = [
    { time: '12:21', event: 'Port scan detected', sev: 'high' },
    { time: '11:45', event: 'Connected to network', sev: 'info' },
    { time: '10:30', event: 'DNS query anomaly', sev: 'medium' },
    { time: '09:15', event: 'First seen on segment', sev: 'info' },
  ]

  return (
    <div className="space-y-4 fade-in-up">
      {/* Breadcrumb */}
      <button onClick={onBack}
        className="flex items-center gap-2 text-sm font-medium transition-colors"
        style={{ color: C.muted }}
        onMouseEnter={e => (e.currentTarget.style.color = C.accent)}
        onMouseLeave={e => (e.currentTarget.style.color = C.muted)}>
        <ArrowLeft size={15} /> Back to Devices
      </button>

      {/* Header card */}
      <div className="rounded-2xl border p-6" style={{ backgroundColor: C.card, borderColor: C.border }}>
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-5">
            <div className="p-4 rounded-2xl" style={{ backgroundColor: C.panel }}>
              <Icon size={32} style={{ color: C.accent }} />
            </div>
            <div>
              <div className="flex items-center gap-3 mb-1">
                <h1 className="text-xl font-bold text-white">{device.hostname}</h1>
                <span className="flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full"
                  style={{ backgroundColor: device.status === 'online' ? 'rgba(34,197,94,0.12)' : 'rgba(100,116,139,0.12)',
                    color: device.status === 'online' ? C.success : C.dim }}>
                  <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: device.status === 'online' ? C.success : C.dim }} />
                  {device.status.charAt(0).toUpperCase() + device.status.slice(1)}
                </span>
              </div>
              <div className="mono text-sm mb-3" style={{ color: C.accent }}>{device.ip}</div>
              <div className="flex flex-wrap gap-x-8 gap-y-2">
                {[
                  ['Vendor', device.vendor], ['OS', device.os], ['MAC', device.mac],
                  ['Type', device.type], ['Connections', String(device.connections)],
                ].map(([k, v]) => (
                  <div key={k}>
                    <div className="text-xs" style={{ color: C.faint }}>{k}</div>
                    <div className="text-sm font-medium text-white mono">{v}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className="flex flex-col items-end gap-3">
            <div className="text-right">
              <div className="text-xs mb-1" style={{ color: C.faint }}>Threat Score</div>
              <div className="text-3xl font-bold" style={{ color: sc }}>{device.threatScore}</div>
              <div className="text-xs font-medium" style={{ color: sc }}>
                {device.threatScore >= 70 ? 'Critical' : device.threatScore >= 40 ? 'High' : device.threatScore >= 20 ? 'Medium' : 'Low'} Risk
              </div>
            </div>
            <div className="w-32 h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
              <div className="h-full rounded-full" style={{ width: `${device.threatScore}%`, backgroundColor: sc }} />
            </div>
          </div>
        </div>

        {/* Meta row */}
        <div className="grid grid-cols-4 gap-4 mt-6 pt-6 border-t" style={{ borderColor: C.border }}>
          {[
            ['First Seen',  device.firstSeen, false],
            ['Last Seen',   device.lastSeen, false],
            ['Total Traffic', device.bandwidth, true],
            ['Open Ports',  device.openPorts.length > 0 ? device.openPorts.join(', ') : 'None', true],
          ].map(([k, v, mono]) => (
            <div key={String(k)}>
              <div className="text-xs mb-1" style={{ color: C.faint }}>{k}</div>
              <div className={`text-sm font-semibold text-white ${mono ? 'mono' : ''}`}>{v}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Action buttons */}
      <div className="flex gap-3">
        <button onClick={() => showToast(`Blocking ${device.ip}`, 'info')}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold"
          style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: C.danger }}>
          <Shield size={14}/> Block Device
        </button>
        <button onClick={() => showToast('Report generation queued', 'success')}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold border"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
          <FileText size={14}/> Generate Report
        </button>
        <button onClick={() => showToast('Device data exported', 'success')}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold border"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
          <Download size={14}/> Export
        </button>
      </div>

      {/* Charts + sidebar */}
      <div className="grid grid-cols-12 gap-4">
        {/* Left: tabs + chart */}
        <div className="col-span-8 rounded-2xl border overflow-hidden" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="flex border-b" style={{ borderColor: C.border }}>
            {(['traffic', 'protocols', 'alerts', 'timeline'] as const).map(t => (
              <button key={t} onClick={() => setTab(t)}
                className="px-5 py-3.5 text-xs font-semibold capitalize transition-colors"
                style={{ color: tab === t ? C.accent : C.faint, borderBottom: tab === t ? `2px solid ${C.accent}` : '2px solid transparent' }}>
                {t.charAt(0).toUpperCase() + t.slice(1)}
              </button>
            ))}
          </div>
          <div className="p-5">
            {tab === 'traffic' && (
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="text-sm font-semibold text-white">Historical Traffic</h3>
                    <p className="text-xs mt-0.5" style={{ color: C.faint }}>24-hour bandwidth usage</p>
                  </div>
                  <div className="mono text-lg font-bold" style={{ color: C.accent }}>{device.bandwidth}</div>
                </div>
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={sparkData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="dg1" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={C.accent} stopOpacity={0.25} />
                        <stop offset="100%" stopColor={C.accent} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="2 5" stroke="#1a2744" vertical={false} />
                    <XAxis dataKey="h" tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false} interval={3} />
                    <YAxis tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false} />
                    <Tooltip contentStyle={TIP} />
                    <Area type="monotone" dataKey="v" name="Mbps" stroke={C.accent} strokeWidth={2} fill="url(#dg1)" dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
            {tab === 'protocols' && (
              <div>
                <h3 className="text-sm font-semibold text-white mb-4">Protocol Breakdown</h3>
                <div className="space-y-4">
                  {protoDataMemo.map(p => (
                    <div key={p.name}>
                      <div className="flex justify-between text-xs mb-1.5">
                        <div className="flex items-center gap-2">
                          <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: p.color }} />
                          <span style={{ color: C.muted }}>{p.name}</span>
                        </div>
                        <span className="mono font-semibold" style={{ color: p.color }}>{p.value}%</span>
                      </div>
                      <div className="h-2 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
                        <div className="h-full rounded-full transition-all duration-700"
                          style={{ width: `${p.value}%`, backgroundColor: p.color }} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {tab === 'alerts' && (
              <div>
                <h3 className="text-sm font-semibold text-white mb-4">Device Alerts ({device.threats})</h3>
                {device.threats === 0 ? (
                  <div className="flex flex-col items-center py-12 gap-3">
                    <Shield size={28} style={{ color: C.success }} />
                    <p className="text-sm font-medium text-white">No threats detected</p>
                    <p className="text-xs" style={{ color: C.faint }}>This device has a clean security record.</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {DEVICE_ALERTS.map(a => (
                      <div key={a.id} className="flex items-center gap-3 p-3 rounded-xl border"
                        style={{ backgroundColor: C.panel, borderColor: `${SEV_C[a.sev]}25` }}>
                        <AlertTriangle size={14} style={{ color: SEV_C[a.sev], flexShrink: 0 }} />
                        <div className="flex-1 min-w-0">
                          <div className="text-xs font-semibold text-white">{a.type}</div>
                          <div className="mono text-xs" style={{ color: C.faint }}>{a.time}</div>
                        </div>
                        <span className="text-xs px-2 py-0.5 rounded-full font-semibold capitalize"
                          style={{ backgroundColor: `${SEV_C[a.sev]}15`, color: SEV_C[a.sev] }}>{a.sev}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
            {tab === 'timeline' && (
              <div>
                <h3 className="text-sm font-semibold text-white mb-4">Device Timeline</h3>
                <div className="space-y-0">
                  {TIMELINE.map((e, i) => (
                    <div key={i} className="flex gap-4">
                      <div className="flex flex-col items-center">
                        <div className="w-2.5 h-2.5 rounded-full mt-0.5 flex-shrink-0"
                          style={{ backgroundColor: e.sev === 'high' ? C.danger : e.sev === 'medium' ? C.warning : C.accent }} />
                        {i < TIMELINE.length - 1 && <div className="w-px flex-1 my-1" style={{ backgroundColor: C.border }} />}
                      </div>
                      <div className="pb-4">
                        <div className="text-xs font-semibold text-white">{e.event}</div>
                        <div className="mono text-xs mt-0.5" style={{ color: C.faint }}>{e.time}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right: AI assessment + connected hosts */}
        <div className="col-span-4 space-y-4">
          <div className="rounded-2xl border overflow-hidden relative"
            style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="absolute top-0 right-0 w-32 h-32 opacity-[0.04] pointer-events-none"
              style={{ background: `radial-gradient(circle, ${C.accent}, transparent 70%)` }} />
            <div className="flex items-center gap-2 px-5 py-4 border-b" style={{ borderColor: C.border }}>
              <Brain size={13} style={{ color: C.accent }} />
              <h3 className="text-sm font-semibold text-white">AI Assessment</h3>
            </div>
            <div className="p-5 space-y-3">
              <p className="text-xs leading-relaxed" style={{ color: C.muted }}>
                {device.threatScore >= 70
                  ? `${device.hostname} shows strong indicators of compromise. Immediate isolation recommended. Multiple attack patterns detected matching known threat profiles.`
                  : device.threatScore >= 40
                  ? `${device.hostname} exhibits suspicious behavior patterns. Elevated monitoring recommended. Some traffic anomalies detected that warrant further investigation.`
                  : `${device.hostname} appears to be operating normally. Traffic patterns are consistent with expected device behavior for its category.`}
              </p>
              <div className="flex items-center justify-between text-xs">
                <span style={{ color: C.faint }}>AI Confidence</span>
                <span className="font-bold" style={{ color: sc }}>
                  {device.threatScore >= 70 ? '96' : device.threatScore >= 40 ? '78' : '91'}%
                </span>
              </div>
              <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
                <div className="h-full rounded-full"
                  style={{ width: device.threatScore >= 70 ? '96%' : device.threatScore >= 40 ? '78%' : '91%', backgroundColor: sc }} />
              </div>
            </div>
          </div>

          <div className="rounded-2xl border overflow-hidden" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="px-5 py-4 border-b" style={{ borderColor: C.border }}>
              <h3 className="text-sm font-semibold text-white">Connected Hosts</h3>
            </div>
            <div className="divide-y" style={{ borderColor: C.border }}>
              {['192.168.1.1', '8.8.8.8', '142.250.80.46'].map(ip => (
                <div key={ip} className="flex items-center justify-between px-5 py-3">
                  <span className="mono text-xs" style={{ color: C.accent }}>{ip}</span>
                  <span className="text-xs" style={{ color: C.faint }}>Active</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Main ─────────────────────────────────────────────────────────────────────
interface Props { showToast: (msg: string, type?: ToastMsg['type']) => void }

export default function Devices({ showToast }: Props) {
  const [selected, setSelected] = useState<Device | null>(null)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [sortCol, setSortCol] = useState<keyof Device>('threatScore')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  if (selected) return <DeviceDetails device={selected} onBack={() => setSelected(null)} showToast={showToast} />

  const filtered = DEVICES.filter(d => {
    if (typeFilter !== 'ALL' && d.type !== typeFilter) return false
    if (statusFilter !== 'ALL' && d.status !== statusFilter) return false
    if (search && !d.hostname.toLowerCase().includes(search.toLowerCase()) &&
        !d.ip.includes(search) && !d.vendor.toLowerCase().includes(search.toLowerCase()) &&
        !d.os.toLowerCase().includes(search.toLowerCase())) return false
    return true
  }).sort((a, b) => {
    const av = a[sortCol], bv = b[sortCol]
    const cmp = typeof av === 'number' ? av - (bv as number) : String(av).localeCompare(String(bv))
    return sortDir === 'asc' ? cmp : -cmp
  })

  const toggleSort = (col: keyof Device) => {
    if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortCol(col); setSortDir('desc') }
  }

  const SortIcon = ({ col }: { col: keyof Device }) => sortCol !== col ? null :
    sortDir === 'asc' ? <ChevronUp size={11} /> : <ChevronDown size={11} />

  const thBtn = (col: keyof Device, label: string) => (
    <th className="text-left py-2.5 pr-4 cursor-pointer select-none" onClick={() => toggleSort(col)}>
      <div className="flex items-center gap-1 text-xs font-medium" style={{ color: C.dim }}>
        {label} <SortIcon col={col} />
      </div>
    </th>
  )

  const online  = DEVICES.filter(d => d.status === 'online').length
  const offline = DEVICES.filter(d => d.status === 'offline').length
  const highRisk = DEVICES.filter(d => d.threatScore >= 70).length
  const unknown  = DEVICES.filter(d => d.type === 'unknown').length

  return (
    <div className="space-y-4">
      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Online Devices"   value={online}   sub={`${DEVICES.length} total on network`} icon={<Monitor size={16}/>}       accent={C.success} />
        <StatCard label="Offline Devices"  value={offline}  sub="Last seen recently"                    icon={<Monitor size={16}/>}       accent={C.dim}     />
        <StatCard label="High Risk"        value={highRisk} sub="Score ≥ 70 — immediate action"         icon={<AlertTriangle size={16}/>} accent={C.danger}  />
        <StatCard label="Unknown Devices"  value={unknown}  sub="Unclassified endpoints"                icon={<Shield size={16}/>}        accent={C.warning} />
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2">
        <div className="flex items-center gap-2 px-3 py-2 rounded-xl border flex-1"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <Search size={13} style={{ color: C.faint }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search hostname, IP, vendor, OS…"
            className="bg-transparent text-xs flex-1 placeholder-slate-600"
            style={{ color: C.text, outline: 'none' }} />
        </div>
        {['ALL', 'laptop', 'server', 'phone', 'iot', 'router', 'unknown'].map(t => (
          <button key={t} onClick={() => setTypeFilter(t)}
            className="px-3 py-2 rounded-xl text-xs font-medium transition-all capitalize"
            style={{ backgroundColor: typeFilter === t ? C.accent : C.card, color: typeFilter === t ? '#0F172A' : C.faint, border: `1px solid ${typeFilter === t ? C.accent : C.border}` }}>
            {t}
          </button>
        ))}
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
          className="px-3 py-2 rounded-xl text-xs border"
          style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted, outline: 'none' }}>
          <option value="ALL">All Status</option>
          <option value="online">Online</option>
          <option value="offline">Offline</option>
          <option value="idle">Idle</option>
        </select>
      </div>

      {/* Table */}
      <div className="rounded-2xl border overflow-hidden"
        style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: C.border }}>
          <div>
            <h2 className="text-sm font-semibold text-white">Asset Inventory</h2>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>{filtered.length} devices</p>
          </div>
          <button onClick={() => showToast('Device list exported', 'success')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium border"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            <Download size={12}/> Export CSV
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b" style={{ borderColor: C.border }}>
                <th className="text-left pl-5 py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Type</th>
                {thBtn('hostname', 'Hostname')}
                {thBtn('ip', 'IP Address')}
                <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>MAC</th>
                {thBtn('vendor', 'Vendor')}
                {thBtn('os', 'OS')}
                {thBtn('bandwidth', 'Bandwidth')}
                {thBtn('threatScore', 'Threat Score')}
                {thBtn('status', 'Status')}
              </tr>
            </thead>
            <tbody>
              {filtered.map(d => {
                const Icon = TYPE_ICON[d.type] ?? Monitor
                const sc = scoreColor(d.threatScore)
                return (
                  <tr key={d.id} onClick={() => setSelected(d)}
                    className="border-b transition-all duration-150 cursor-pointer"
                    style={{ borderColor: '#1a2744' }}
                    onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)')}
                    onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
                    <td className="pl-5 py-3 pr-4">
                      <div className="p-1.5 rounded-lg w-fit" style={{ backgroundColor: C.panel }}>
                        <Icon size={13} style={{ color: C.faint }} />
                      </div>
                    </td>
                    <td className="py-3 pr-4">
                      <div className="text-xs font-semibold text-white">{d.hostname}</div>
                      {d.threats > 0 && <div className="text-xs mt-0.5" style={{ color: C.danger }}>{d.threats} threat{d.threats > 1 ? 's' : ''}</div>}
                    </td>
                    <td className="py-3 pr-4 mono text-xs font-medium" style={{ color: C.accent }}>{d.ip}</td>
                    <td className="py-3 pr-4 mono text-xs" style={{ color: C.dim }}>{d.mac}</td>
                    <td className="py-3 pr-4 text-xs" style={{ color: C.muted }}>{d.vendor}</td>
                    <td className="py-3 pr-4 text-xs" style={{ color: C.muted }}>{d.os}</td>
                    <td className="py-3 pr-4 mono text-xs text-white">{d.bandwidth}</td>
                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-2">
                        <div className="w-12 h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
                          <div className="h-full rounded-full" style={{ width: `${d.threatScore}%`, backgroundColor: sc }} />
                        </div>
                        <span className="mono text-xs font-bold" style={{ color: sc }}>{d.threatScore}</span>
                      </div>
                    </td>
                    <td className="py-3 pr-5">
                      <span className="flex items-center gap-1.5 text-xs font-medium w-fit"
                        style={{ color: d.status === 'online' ? C.success : d.status === 'idle' ? C.warning : C.dim }}>
                        <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: d.status === 'online' ? C.success : d.status === 'idle' ? C.warning : C.dim }} />
                        {d.status.charAt(0).toUpperCase() + d.status.slice(1)}
                      </span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        {filtered.length === 0 && (
          <div className="flex flex-col items-center py-16 gap-3">
            <Monitor size={28} style={{ color: C.border }} />
            <p className="text-sm font-medium text-white">No devices found</p>
            <p className="text-xs" style={{ color: C.faint }}>Try adjusting your search or filter criteria.</p>
          </div>
        )}
      </div>
    </div>
  )
}
