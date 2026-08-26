import { useState, useEffect, useCallback } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell,
} from 'recharts'
import {
  Activity, Shield, Monitor, Wifi, ArrowUpRight,
  AlertTriangle, TrendingUp, TrendingDown,
  Play, Square, FileText, Download, RefreshCw,
  Brain, Cpu, HardDrive, Network,
} from 'lucide-react'
import type { ToastMsg } from '../App'

// ─── Design tokens ────────────────────────────────────────────────────────────
const C = {
  accent:  '#38BDF8',
  success: '#22C55E',
  warning: '#F59E0B',
  danger:  '#EF4444',
  info:    '#06B6D4',
  purple:  '#818CF8',
  orange:  '#F97316',
  bg:      '#020617',
  card:    '#1E293B',
  panel:   '#0F172A',
  border:  '#334155',
  text:    '#F8FAFC',
  muted:   '#94A3B8',
  faint:   '#64748B',
  dim:     '#475569',
}

const TIP_STYLE = {
  backgroundColor: C.panel,
  border: `1px solid ${C.border}`,
  borderRadius: '10px',
  fontSize: '12px',
  fontFamily: 'Inter',
  color: C.text,
  boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
}

// ─── Data ─────────────────────────────────────────────────────────────────────
function spark(base: number, variance: number, len = 22): number[] {
  return Array.from({ length: len }, (_, i) =>
    Math.max(0, base + Math.sin(i * 0.7) * variance * 0.6 + (Math.random() - 0.5) * variance)
  )
}

function genTrafficPoint(i: number) {
  return {
    t: new Date(Date.now() - (59 - i) * 2000)
      .toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    in:  Math.round(700 + Math.random() * 400 + Math.sin(i * 0.4) * 200),
    out: Math.round(350 + Math.random() * 250 + Math.cos(i * 0.5) * 120),
  }
}

const THREAT_TIMELINE = Array.from({ length: 24 }, (_, i) => ({
  h:        `${String(i).padStart(2, '0')}:00`,
  critical: Math.floor(Math.random() * 3),
  high:     Math.floor(Math.random() * 5),
  medium:   Math.floor(Math.random() * 7),
}))

const PROTOCOLS = [
  { name: 'TCP',   value: 55, color: C.accent },
  { name: 'UDP',   value: 22, color: C.info },
  { name: 'HTTPS', value: 18, color: C.purple },
  { name: 'DNS',   value:  5, color: C.warning },
]

const TOP_TALKERS = [
  { rank: 1, ip: '192.168.1.25', device: 'Unknown Device', traffic: '1.2 GB', pct: 28, threats: 18, risk: 'critical' },
  { rank: 2, ip: '192.168.1.10', device: 'Dell XPS Laptop', traffic: '2.5 GB', pct: 58, threats: 2,  risk: 'medium'   },
  { rank: 3, ip: '10.0.0.15',    device: 'NAS Server',      traffic: '980 MB', pct: 23, threats: 0,  risk: 'none'     },
  { rank: 4, ip: '192.168.1.5',  device: 'Gateway',         traffic: '750 MB', pct: 17, threats: 1,  risk: 'low'      },
  { rank: 5, ip: '10.0.0.22',    device: 'IoT Sensor',      traffic: '310 MB', pct: 7,  threats: 3,  risk: 'medium'   },
]

const ALERTS = [
  { id: 1, sev: 'critical', type: 'Port Scan',     ip: '192.168.1.20',  time: '12:21:08', confidence: 91, status: 'active',       proto: 'TCP',  desc: 'SYN flood across 1,024 ports' },
  { id: 2, sev: 'high',     type: 'DNS Tunneling', ip: '10.0.0.22',     time: '12:15:33', confidence: 84, status: 'investigating',  proto: 'DNS',  desc: 'Encoded payload in DNS TXT records' },
  { id: 3, sev: 'medium',   type: 'ARP Spoofing',  ip: '192.168.1.100', time: '11:58:14', confidence: 77, status: 'acknowledged',  proto: 'ARP',  desc: 'ARP cache poisoning attempt' },
  { id: 4, sev: 'low',      type: 'ICMP Flood',    ip: '192.168.1.55',  time: '11:42:55', confidence: 45, status: 'resolved',      proto: 'ICMP', desc: 'High-rate ICMP echo requests' },
]

const SEV_CFG: Record<string, { color: string; bg: string; label: string }> = {
  critical: { color: C.danger,  bg: 'rgba(239,68,68,0.12)',   label: 'Critical' },
  high:     { color: C.orange,  bg: 'rgba(249,115,22,0.12)',  label: 'High'     },
  medium:   { color: C.warning, bg: 'rgba(245,158,11,0.12)',  label: 'Medium'   },
  low:      { color: C.info,    bg: 'rgba(6,182,212,0.12)',   label: 'Low'      },
}

const STATUS_CFG: Record<string, { color: string; bg: string }> = {
  active:        { color: C.danger,  bg: 'rgba(239,68,68,0.12)'  },
  investigating: { color: C.warning, bg: 'rgba(245,158,11,0.12)' },
  acknowledged:  { color: C.info,    bg: 'rgba(6,182,212,0.12)'  },
  resolved:      { color: C.success, bg: 'rgba(34,197,94,0.12)'  },
}

const RISK_COLOR: Record<string, string> = {
  critical: C.danger, medium: C.warning, low: C.info, none: C.success,
}

// ─── Sparkline ────────────────────────────────────────────────────────────────
function Sparkline({ data, color }: { data: number[]; color: string }) {
  const W = 80, H = 28
  const max = Math.max(...data), min = Math.min(...data)
  const range = max - min || 1
  const pts = data.map((v, i) => ({
    x: (i / (data.length - 1)) * W,
    y: H - ((v - min) / range) * H * 0.8 - H * 0.1,
  }))
  let line = `M ${pts[0].x.toFixed(2)} ${pts[0].y.toFixed(2)}`
  for (let i = 1; i < pts.length; i++) {
    const p = pts[i - 1], c = pts[i]
    const cpx = (c.x - p.x) / 3
    line += ` C ${(p.x + cpx).toFixed(2)} ${p.y.toFixed(2)} ${(c.x - cpx).toFixed(2)} ${c.y.toFixed(2)} ${c.x.toFixed(2)} ${c.y.toFixed(2)}`
  }
  const last = pts[pts.length - 1]
  const area = `${line} L ${last.x} ${H} L 0 ${H} Z`
  const id = `sk${color.replace(/[^0-9a-z]/gi, '')}`
  return (
    <svg width={W} height={H} style={{ overflow: 'hidden', display: 'block', flexShrink: 0 }}>
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor={color} stopOpacity={0.25} />
          <stop offset="100%" stopColor={color} stopOpacity={0}    />
        </linearGradient>
      </defs>
      <path d={area} fill={`url(#${id})`} />
      <path d={line} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  )
}

// ─── Threat Gauge ─────────────────────────────────────────────────────────────
function ThreatGauge({ score }: { score: number }) {
  const r = 62, sw = 10
  const W = 170, H = 100
  const cx = W / 2, cy = H - 6

  // Score 0 → left (π rad), Score 100 → right (0 rad)
  const angle   = Math.PI * (1 - score / 100)
  const nX      = +(cx + r * Math.cos(angle)).toFixed(3)
  const nY      = +(cy - r * Math.sin(angle)).toFixed(3)
  const bgPath  = `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`
  const fillPath = score > 0 ? `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${nX} ${nY}` : null

  const color = score < 33 ? C.success : score < 66 ? C.warning : C.danger
  const label = score < 33 ? 'Low'     : score < 66 ? 'Medium'   : 'High'

  // Zone segments (drawn as faint track overlays)
  const zonePath = (from: number, to: number) => {
    const a1 = Math.PI * (1 - from / 100), a2 = Math.PI * (1 - to / 100)
    const x1 = +(cx + r * Math.cos(a1)).toFixed(2), y1 = +(cy - r * Math.sin(a1)).toFixed(2)
    const x2 = +(cx + r * Math.cos(a2)).toFixed(2), y2 = +(cy - r * Math.sin(a2)).toFixed(2)
    return `M ${x1} ${y1} A ${r} ${r} 0 0 1 ${x2} ${y2}`
  }

  return (
    <div className="flex flex-col items-center w-full">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ overflow: 'visible' }}>
        {/* Faint zone tints */}
        <path d={zonePath(0, 33)}   fill="none" stroke={C.success} strokeWidth={sw} strokeLinecap="butt" opacity={0.15} />
        <path d={zonePath(33, 66)}  fill="none" stroke={C.warning} strokeWidth={sw} strokeLinecap="butt" opacity={0.15} />
        <path d={zonePath(66, 100)} fill="none" stroke={C.danger}  strokeWidth={sw} strokeLinecap="butt" opacity={0.15} />
        {/* Dark track */}
        <path d={bgPath} fill="none" stroke={C.panel} strokeWidth={sw - 2} strokeLinecap="round" />
        {/* Filled arc */}
        {fillPath && (
          <path d={fillPath} fill="none" stroke={color} strokeWidth={sw - 2}
            strokeLinecap="round" style={{ filter: `drop-shadow(0 0 4px ${color}80)` }} />
        )}
        {/* Needle */}
        <circle cx={nX} cy={nY} r={7}   fill={C.card}  stroke={color} strokeWidth={2.5} />
        <circle cx={nX} cy={nY} r={3}   fill={color} />
        {/* Score label */}
        <text x={cx} y={cy - 22} textAnchor="middle" fill={C.text}  fontSize={32} fontWeight="700" fontFamily="Inter" letterSpacing="-1">{score}</text>
        <text x={cx} y={cy - 5}  textAnchor="middle" fill={color}   fontSize={10} fontWeight="600" fontFamily="Inter" letterSpacing="1">{label.toUpperCase()} RISK</text>
        {/* Scale ticks */}
        <text x={cx - r - 6} y={cy + 14} textAnchor="middle" fill={C.faint} fontSize={9} fontFamily="Inter">0</text>
        <text x={cx + r + 6} y={cy + 14} textAnchor="middle" fill={C.faint} fontSize={9} fontFamily="Inter">100</text>
      </svg>
    </div>
  )
}

// ─── KPI Card ─────────────────────────────────────────────────────────────────
interface KpiProps {
  label: string; value: string; sub: string
  icon: React.ReactNode; sparkData: number[]
  accent?: string
  trend?: { dir: 'up' | 'down'; val: string; positive: boolean }
  alert?: boolean
}

function KpiCard({ label, value, sub, icon, sparkData, accent = C.accent, trend, alert }: KpiProps) {
  const [hovered, setHovered] = useState(false)
  return (
    <div
      className="rounded-2xl p-4 border flex flex-col gap-3 relative overflow-hidden cursor-default transition-all duration-200"
      style={{
        backgroundColor: C.card,
        borderColor: hovered ? `${accent}50` : C.border,
        boxShadow: hovered ? `0 8px 32px rgba(0,0,0,0.3), 0 0 0 1px ${accent}20` : '0 4px 20px rgba(0,0,0,0.2)',
        transform: hovered ? 'translateY(-1px)' : 'none',
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      {/* Alert dot */}
      {alert && <span className="absolute top-3 right-3 w-1.5 h-1.5 rounded-full animate-pulse" style={{ backgroundColor: C.danger }} />}
      {/* Top row: icon + trend */}
      <div className="flex items-center justify-between">
        <div className="p-2 rounded-xl" style={{ backgroundColor: `${accent}15` }}>
          <div style={{ color: accent }}>{icon}</div>
        </div>
        {trend && (
          <span className="flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-full"
            style={{
              backgroundColor: trend.positive ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
              color: trend.positive ? C.success : C.danger,
            }}
          >
            {trend.dir === 'up' ? <TrendingUp size={10} /> : <TrendingDown size={10} />}
            {trend.val}
          </span>
        )}
      </div>
      {/* Value */}
      <div>
        <div className="text-2xl font-bold text-white leading-none mb-0.5 tracking-tight">{value}</div>
        <div className="text-xs font-medium" style={{ color: C.muted }}>{label}</div>
      </div>
      {/* Sparkline + sub */}
      <div className="flex items-end justify-between gap-2">
        <span className="text-xs leading-snug" style={{ color: C.faint }}>{sub}</span>
        <Sparkline data={sparkData} color={accent} />
      </div>
      {/* Subtle bottom accent line on hover */}
      <div
        className="absolute bottom-0 left-0 right-0 h-px transition-opacity duration-200"
        style={{ background: `linear-gradient(90deg, transparent, ${accent}, transparent)`, opacity: hovered ? 0.6 : 0 }}
      />
    </div>
  )
}

// ─── Card shell ───────────────────────────────────────────────────────────────
function Card({ title, sub, action, children, noPad = false, style: s }: {
  title?: string; sub?: string; action?: React.ReactNode
  children: React.ReactNode; noPad?: boolean; style?: React.CSSProperties
}) {
  return (
    <div
      className="rounded-2xl border flex flex-col overflow-hidden"
      style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)', ...s }}
    >
      {title && (
        <div className="flex items-center justify-between px-5 py-4 border-b flex-shrink-0" style={{ borderColor: C.border }}>
          <div>
            <h3 className="text-sm font-semibold text-white">{title}</h3>
            {sub && <p className="text-xs mt-0.5" style={{ color: C.faint }}>{sub}</p>}
          </div>
          {action}
        </div>
      )}
      <div className={noPad ? 'flex-1' : 'p-5 flex-1'}>{children}</div>
    </div>
  )
}

// ─── RangeSelector ────────────────────────────────────────────────────────────
function RangeSelector<T extends string>({ options, value, onChange }: { options: T[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="flex items-center gap-0.5 p-1 rounded-xl" style={{ backgroundColor: C.panel }}>
      {options.map(o => (
        <button key={o} onClick={() => onChange(o)}
          className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-150"
          style={{ backgroundColor: value === o ? C.accent : 'transparent', color: value === o ? C.panel : C.faint }}
        >
          {o}
        </button>
      ))}
    </div>
  )
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
interface Props { showToast: (msg: string, type?: ToastMsg['type']) => void }

export default function Dashboard({ showToast }: Props) {
  const [trafficData, setTrafficData] = useState(() => Array.from({ length: 60 }, (_, i) => genTrafficPoint(i)))
  const [pps,    setPps]    = useState(952)
  const [bw,     setBw]     = useState(34.2)
  const [range,  setRange]  = useState<'1m' | '5m' | '15m' | '1h'>('1m')
  const [threatScore]       = useState(42)
  const now                 = new Date()

  const tick = useCallback(() => {
    setTrafficData(prev => [...prev.slice(-59), genTrafficPoint(59)])
    setPps(Math.round(880 + Math.random() * 160))
    setBw(parseFloat((28 + Math.random() * 12).toFixed(1)))
  }, [])

  useEffect(() => {
    const id = setInterval(tick, 2000)
    return () => clearInterval(id)
  }, [tick])

  const visible = range === '1m' ? 30 : range === '5m' ? 45 : 60
  const upload  = parseFloat((bw * 0.36).toFixed(1))

  return (
    <div className="space-y-4 pb-2">

      {/* ── SOC Status Banner ──────────────────────────────────────────────── */}
      <div
        className="rounded-2xl border overflow-hidden"
        style={{ backgroundColor: C.card, borderColor: C.border }}
      >
        <div className="flex divide-x" style={{ borderColor: C.border }}>
          {[
            { label: 'System Status',  value: 'Operational',  dot: C.success, mono: false },
            { label: 'Monitoring',     value: 'Active',       dot: C.success, mono: false },
            { label: 'Threat Level',   value: 'Medium',       dot: C.warning, mono: false },
            { label: 'Interface',      value: 'eth0',         dot: null,      mono: true  },
            { label: 'Last Updated',   value: now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }), dot: null, mono: true },
            { label: 'Capture',        value: 'Running',      dot: C.accent,  mono: false },
          ].map((item, i) => (
            <div key={i} className="flex-1 flex flex-col justify-center px-5 py-3" style={{ borderColor: C.border }}>
              <span className="text-xs mb-1" style={{ color: C.faint }}>{item.label}</span>
              <div className="flex items-center gap-1.5">
                {item.dot && (
                  <span className="relative flex h-1.5 w-1.5 flex-shrink-0">
                    {item.dot === C.success && (
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-60" style={{ backgroundColor: item.dot }} />
                    )}
                    <span className="relative inline-flex rounded-full h-1.5 w-1.5" style={{ backgroundColor: item.dot }} />
                  </span>
                )}
                <span className={`text-xs font-semibold text-white ${item.mono ? 'mono' : ''}`}>{item.value}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── KPI Cards ──────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-4">
        <KpiCard
          label="Packets / sec" value={pps.toLocaleString()} sub="eth0 · live capture"
          icon={<Activity size={16} />} sparkData={spark(pps, 140)}
          trend={{ dir: 'up', val: '+12%', positive: true }}
        />
        <KpiCard
          label="Bandwidth" value={`${bw} Mbps`} sub={`↑ ${upload} Mbps · ↓ ${bw} Mbps`}
          icon={<Wifi size={16} />} accent={C.info} sparkData={spark(bw, 7)}
        />
        <KpiCard
          label="Active Devices" value="12" sub="10 healthy · 2 flagged"
          icon={<Monitor size={16} />} accent={C.success} sparkData={spark(12, 2)}
          trend={{ dir: 'up', val: '+2', positive: true }}
        />
        <KpiCard
          label="Connections" value="248" sub="TCP 180 · UDP 68"
          icon={<Network size={16} />} accent={C.purple} sparkData={spark(248, 40)}
        />
        <KpiCard
          label="Active Alerts" value="3" sub="1 critical · 1 high · 1 medium"
          icon={<AlertTriangle size={16} />} accent={C.danger} sparkData={spark(3, 2.5)}
          trend={{ dir: 'up', val: '+1', positive: false }} alert
        />
        <KpiCard
          label="Threat Score" value={`${threatScore}/100`} sub="Medium — 42 pts"
          icon={<Shield size={16} />} accent={C.warning} sparkData={spark(threatScore, 12)}
          trend={{ dir: 'down', val: '−8', positive: true }}
        />
      </div>

      {/* ── Traffic Chart · Threat Gauge · AI Insights ─────────────────────── */}
      <div className="grid gap-4" style={{ gridTemplateColumns: '1fr 210px 296px' }}>

        {/* Traffic Chart */}
        <Card
          title="Live Network Traffic"
          sub="Inbound vs outbound — refreshes every 2s"
          action={<RangeSelector options={['1m', '5m', '15m', '1h'] as const} value={range} onChange={setRange} />}
        >
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={trafficData.slice(-visible)} margin={{ top: 4, right: 4, left: -18, bottom: 0 }}>
              <defs>
                <linearGradient id="gIn" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%"   stopColor={C.accent} stopOpacity={0.22} />
                  <stop offset="100%" stopColor={C.accent} stopOpacity={0}    />
                </linearGradient>
                <linearGradient id="gOut" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%"   stopColor={C.info} stopOpacity={0.18} />
                  <stop offset="100%" stopColor={C.info} stopOpacity={0}    />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="2 5" stroke="#1a2744" vertical={false} />
              <XAxis dataKey="t" tick={{ fill: C.dim, fontSize: 9, fontFamily: 'JetBrains Mono' }}
                tickLine={false} axisLine={false} interval="preserveStartEnd" />
              <YAxis tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false}
                tickFormatter={v => `${(v / 1000).toFixed(0)}k`} />
              <Tooltip contentStyle={TIP_STYLE} labelStyle={{ color: C.faint }} itemStyle={{ color: C.text }} />
              <Area type="monotone" dataKey="in"  name="Inbound"  stroke={C.accent} strokeWidth={2}
                fill="url(#gIn)"  dot={false} activeDot={{ r: 4, fill: C.accent, strokeWidth: 0 }} />
              <Area type="monotone" dataKey="out" name="Outbound" stroke={C.info}   strokeWidth={2}
                fill="url(#gOut)" dot={false} activeDot={{ r: 4, fill: C.info,   strokeWidth: 0 }} />
            </AreaChart>
          </ResponsiveContainer>
          <div className="flex items-center gap-5 mt-3">
            {[{ label: 'Inbound', color: C.accent }, { label: 'Outbound', color: C.info }].map(l => (
              <div key={l.label} className="flex items-center gap-1.5 text-xs" style={{ color: C.muted }}>
                <span className="w-5 h-0.5 rounded-full inline-block" style={{ backgroundColor: l.color }} />
                {l.label}
              </div>
            ))}
            <div className="ml-auto flex items-center gap-1.5 text-xs" style={{ color: C.faint }}>
              <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: C.success }} />
              Live
            </div>
          </div>
        </Card>

        {/* Threat Score Gauge */}
        <div className="rounded-2xl border flex flex-col overflow-hidden"
          style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
          <div className="px-5 pt-4 pb-3 border-b" style={{ borderColor: C.border }}>
            <h3 className="text-sm font-semibold text-white">Threat Score</h3>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>0 = safe · 100 = critical</p>
          </div>
          <div className="flex-1 flex flex-col justify-between p-4">
            <ThreatGauge score={threatScore} />
            <div className="space-y-2 mt-2">
              {[
                { label: 'Active Threats', val: '3',            color: C.danger  },
                { label: 'Anomalies',      val: '7 today',      color: C.warning },
                { label: 'Score Δ',        val: '−8 vs 24h ago', color: C.success },
              ].map(item => (
                <div key={item.label} className="flex items-center justify-between">
                  <span className="text-xs" style={{ color: C.faint }}>{item.label}</span>
                  <span className="text-xs font-semibold" style={{ color: item.color }}>{item.val}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* AI Insights */}
        <div className="rounded-2xl border flex flex-col overflow-hidden relative"
          style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
          {/* Subtle radial glow top-right */}
          <div className="absolute top-0 right-0 w-40 h-40 opacity-[0.04] pointer-events-none"
            style={{ background: `radial-gradient(circle, ${C.accent}, transparent 70%)` }} />

          <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: C.border }}>
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg" style={{ backgroundColor: `${C.accent}15` }}>
                <Brain size={13} style={{ color: C.accent }} />
              </div>
              <h3 className="text-sm font-semibold text-white">AI Insights</h3>
            </div>
            <span className="text-xs px-2 py-0.5 rounded-full font-medium"
              style={{ backgroundColor: `${C.accent}15`, color: C.accent }}>Powered by GPT-4o</span>
          </div>

          <div className="p-5 flex-1 flex flex-col gap-4">
            {/* Summary */}
            <p className="text-xs leading-relaxed" style={{ color: C.muted }}>
              Network behavior is within normal parameters. One suspicious host identified on the internal LAN. No evidence of lateral movement detected yet.
            </p>

            {/* Suspicious host callout */}
            <div className="p-3.5 rounded-xl border"
              style={{ backgroundColor: 'rgba(239,68,68,0.06)', borderColor: 'rgba(239,68,68,0.22)' }}>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-1.5">
                  <AlertTriangle size={11} style={{ color: C.danger }} />
                  <span className="text-xs font-semibold" style={{ color: C.danger }}>Suspicious Host</span>
                </div>
                <span className="mono text-xs font-medium" style={{ color: C.accent }}>192.168.1.25</span>
              </div>
              <p className="text-xs mb-3" style={{ color: C.faint }}>Unknown Device · 18 active threats</p>
              <div className="flex items-center justify-between text-xs mb-1.5">
                <span style={{ color: C.faint }}>AI Confidence</span>
                <span className="font-bold" style={{ color: C.danger }}>84%</span>
              </div>
              <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
                <div className="h-full rounded-full transition-all duration-700"
                  style={{ width: '84%', background: `linear-gradient(90deg, ${C.orange}, ${C.danger})` }} />
              </div>
            </div>

            {/* Recommendation */}
            <div>
              <p className="text-xs font-semibold uppercase tracking-widest mb-2" style={{ color: C.dim }}>Recommendation</p>
              <p className="text-xs leading-relaxed" style={{ color: C.muted }}>
                Quarantine 192.168.1.25 immediately and block outbound traffic. Review DNS query logs for exfiltration indicators.
              </p>
            </div>

            <button
              onClick={() => showToast('Quarantine initiated for 192.168.1.25', 'success')}
              className="mt-auto w-full py-2.5 rounded-xl text-xs font-semibold transition-opacity hover:opacity-90"
              style={{ background: `linear-gradient(135deg, #DC2626, ${C.danger})`, color: '#fff' }}
            >
              Quarantine Host
            </button>
          </div>
        </div>
      </div>

      {/* ── Protocol · Bandwidth · Top Talkers ─────────────────────────────── */}
      <div className="grid grid-cols-12 gap-4">

        {/* Protocol Doughnut */}
        <div className="col-span-3 rounded-2xl border flex flex-col overflow-hidden"
          style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
          <div className="px-5 py-4 border-b" style={{ borderColor: C.border }}>
            <h3 className="text-sm font-semibold text-white">Protocol Mix</h3>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>By packet volume · last 60s</p>
          </div>
          <div className="p-4 flex flex-col items-center">
            <div className="relative" style={{ width: 160, height: 160 }}>
              <PieChart width={160} height={160}>
                <Pie data={PROTOCOLS} cx={80} cy={80} innerRadius={50} outerRadius={72}
                  paddingAngle={3} dataKey="value" startAngle={90} endAngle={-270} stroke="none">
                  {PROTOCOLS.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Pie>
                <Tooltip contentStyle={TIP_STYLE} />
              </PieChart>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-lg font-bold text-white">4</span>
                <span className="text-xs" style={{ color: C.faint }}>protocols</span>
              </div>
            </div>
            <div className="w-full space-y-2.5 mt-2">
              {PROTOCOLS.map(p => (
                <div key={p.name} className="flex items-center gap-2.5">
                  <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{ backgroundColor: p.color }} />
                  <span className="text-xs w-10" style={{ color: C.muted }}>{p.name}</span>
                  <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
                    <div className="h-full rounded-full" style={{ width: `${p.value}%`, backgroundColor: p.color }} />
                  </div>
                  <span className="text-xs mono font-semibold w-7 text-right" style={{ color: p.color }}>{p.value}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Bandwidth Usage */}
        <div className="col-span-3 rounded-2xl border flex flex-col overflow-hidden"
          style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
          <div className="px-5 py-4 border-b" style={{ borderColor: C.border }}>
            <h3 className="text-sm font-semibold text-white">Bandwidth Usage</h3>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>Upload / download · real-time</p>
          </div>
          <div className="p-5 flex-1 flex flex-col justify-between">
            <div className="grid grid-cols-2 gap-2.5 mb-5">
              {[
                { label: 'Upload',   val: `${upload} Mbps`, pct: (upload / 50) * 100, color: C.accent  },
                { label: 'Download', val: `${bw} Mbps`,     pct: (bw    / 50) * 100, color: C.success },
                { label: 'Peak',     val: '48.2 Mbps',      pct: 96,                  color: C.warning },
                { label: '24h Avg',  val: '22.1 Mbps',      pct: 44,                  color: C.info    },
              ].map(s => (
                <div key={s.label} className="p-3 rounded-xl" style={{ backgroundColor: C.panel }}>
                  <div className="text-xs mb-1.5" style={{ color: C.faint }}>{s.label}</div>
                  <div className="text-sm font-bold text-white mono leading-none">{s.val}</div>
                  <div className="mt-2 h-1 rounded-full overflow-hidden" style={{ backgroundColor: C.border }}>
                    <div className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${Math.min(s.pct, 100)}%`, backgroundColor: s.color }} />
                  </div>
                </div>
              ))}
            </div>
            {[
              { label: 'Upload',   val: upload, max: 50, color: C.accent  },
              { label: 'Download', val: bw,     max: 50, color: C.success },
            ].map(({ label, val, max, color }) => (
              <div key={label} className="mb-3 last:mb-0">
                <div className="flex justify-between text-xs mb-1.5">
                  <span style={{ color: C.muted }}>{label}</span>
                  <span className="mono font-semibold" style={{ color }}>{val.toFixed(1)} Mbps</span>
                </div>
                <div className="h-2 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
                  <div className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${Math.min((val / max) * 100, 100)}%`, background: `linear-gradient(90deg, ${color}90, ${color})` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Talkers */}
        <div className="col-span-6 rounded-2xl border overflow-hidden"
          style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
          <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: C.border }}>
            <div>
              <h3 className="text-sm font-semibold text-white">Top Talkers</h3>
              <p className="text-xs mt-0.5" style={{ color: C.faint }}>Highest traffic hosts · last 5 min</p>
            </div>
            <button onClick={() => showToast('Opening Live Traffic view', 'info')}
              className="flex items-center gap-1 text-xs font-medium px-3 py-1.5 rounded-lg"
              style={{ color: C.accent, backgroundColor: `${C.accent}12` }}>
              View all <ArrowUpRight size={11} />
            </button>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b" style={{ borderColor: C.border }}>
                {['#', 'IP Address', 'Device', 'Traffic', 'Volume', 'Threats'].map(h => (
                  <th key={h} className="text-left px-4 py-2.5 text-xs font-medium" style={{ color: C.dim }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {TOP_TALKERS.map(row => {
                const rc = RISK_COLOR[row.risk]
                return (
                  <tr key={row.rank} className="border-b transition-all duration-150 cursor-pointer"
                    style={{ borderColor: '#1a2744' }}
                    onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)')}
                    onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
                  >
                    <td className="px-4 py-3 text-xs font-medium" style={{ color: C.dim }}>{row.rank}</td>
                    <td className="px-4 py-3 mono text-xs font-semibold" style={{ color: C.accent }}>{row.ip}</td>
                    <td className="px-4 py-3 text-xs" style={{ color: C.muted }}>{row.device}</td>
                    <td className="px-4 py-3 mono text-xs font-semibold text-white">{row.traffic}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: C.panel, width: 64 }}>
                          <div className="h-full rounded-full" style={{ width: `${row.pct}%`, backgroundColor: rc }} />
                        </div>
                        <span className="mono text-xs" style={{ color: C.dim }}>{row.pct}%</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {row.threats > 0
                        ? <span className="text-xs px-2 py-0.5 rounded-full font-semibold" style={{ backgroundColor: `${rc}18`, color: rc }}>{row.threats} found</span>
                        : <span className="text-xs px-2 py-0.5 rounded-full font-medium" style={{ backgroundColor: 'rgba(34,197,94,0.12)', color: C.success }}>Clean</span>
                      }
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Recent Alerts · Quick Actions · System Health ───────────────────── */}
      <div className="grid grid-cols-12 gap-4">

        {/* Recent Alerts */}
        <div className="col-span-7 rounded-2xl border overflow-hidden"
          style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
          <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: C.border }}>
            <div>
              <h3 className="text-sm font-semibold text-white">Recent Alerts</h3>
              <p className="text-xs mt-0.5" style={{ color: C.faint }}>Last 4 security events · auto-refreshing</p>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ backgroundColor: C.danger }} />
              <span className="text-xs" style={{ color: C.faint }}>Live</span>
            </div>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b" style={{ borderColor: C.border }}>
                {['Severity', 'Type', 'Source IP', 'Proto', 'Confidence', 'Status', 'Time'].map(h => (
                  <th key={h} className="text-left px-4 py-2.5 text-xs font-medium" style={{ color: C.dim }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {ALERTS.map(a => {
                const sev = SEV_CFG[a.sev]
                const st  = STATUS_CFG[a.status]
                return (
                  <tr key={a.id} className="border-b transition-all duration-150 cursor-pointer"
                    style={{ borderColor: '#1a2744', borderLeft: `2px solid ${sev.color}40` }}
                    onMouseEnter={e => { e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)'; e.currentTarget.style.borderLeftColor = sev.color }}
                    onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'transparent'; e.currentTarget.style.borderLeftColor = `${sev.color}40` }}
                  >
                    <td className="px-4 py-3">
                      <span className="text-xs px-2 py-0.5 rounded-full font-semibold" style={{ backgroundColor: sev.bg, color: sev.color }}>
                        {sev.label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-xs font-semibold text-white">{a.type}</div>
                      <div className="text-xs mt-0.5" style={{ color: C.faint }}>{a.desc}</div>
                    </td>
                    <td className="px-4 py-3 mono text-xs font-medium" style={{ color: C.accent }}>{a.ip}</td>
                    <td className="px-4 py-3">
                      <span className="text-xs px-1.5 py-0.5 rounded mono" style={{ backgroundColor: C.panel, color: C.muted }}>{a.proto}</span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="h-1 rounded-full overflow-hidden" style={{ backgroundColor: C.panel, width: 40 }}>
                          <div className="h-full rounded-full" style={{ width: `${a.confidence}%`, backgroundColor: sev.color }} />
                        </div>
                        <span className="mono text-xs font-semibold" style={{ color: sev.color }}>{a.confidence}%</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs px-2 py-0.5 rounded-full font-medium capitalize"
                        style={{ backgroundColor: st.bg, color: st.color }}>{a.status}</span>
                    </td>
                    <td className="px-4 py-3 mono text-xs" style={{ color: C.faint }}>{a.time}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* Quick Actions */}
        <div className="col-span-2 rounded-2xl border overflow-hidden"
          style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
          <div className="px-5 py-4 border-b" style={{ borderColor: C.border }}>
            <h3 className="text-sm font-semibold text-white">Quick Actions</h3>
          </div>
          <div className="p-3 space-y-2">
            {[
              { label: 'Start Capture', icon: Play,       color: C.success, msg: 'Capture started on eth0',      type: 'success' as const },
              { label: 'Stop Capture',  icon: Square,     color: C.danger,  msg: 'Capture stopped',              type: 'info'    as const },
              { label: 'Generate PDF',  icon: FileText,   color: C.accent,  msg: 'Report queued for generation', type: 'info'    as const },
              { label: 'Export CSV',    icon: Download,   color: C.purple,  msg: 'CSV exported successfully',    type: 'success' as const },
              { label: 'Refresh Data',  icon: RefreshCw,  color: C.info,    msg: 'Data refreshed',              type: 'info'    as const },
            ].map(({ label, icon: Icon, color, msg, type }) => (
              <button key={label}
                onClick={() => showToast(msg, type)}
                className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl border text-xs font-medium text-left transition-all duration-150"
                style={{ borderColor: C.border, color: C.muted, backgroundColor: 'transparent' }}
                onMouseEnter={e => {
                  const el = e.currentTarget as HTMLElement
                  el.style.backgroundColor = `${color}10`
                  el.style.borderColor = `${color}35`
                  el.style.color = color
                }}
                onMouseLeave={e => {
                  const el = e.currentTarget as HTMLElement
                  el.style.backgroundColor = 'transparent'
                  el.style.borderColor = C.border
                  el.style.color = C.muted
                }}
              >
                <div className="p-1.5 rounded-lg" style={{ backgroundColor: `${color}15` }}>
                  <Icon size={11} style={{ color }} />
                </div>
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* System Health */}
        <div className="col-span-3 rounded-2xl border overflow-hidden"
          style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
          <div className="px-5 py-4 border-b" style={{ borderColor: C.border }}>
            <h3 className="text-sm font-semibold text-white">System Health</h3>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>Host resource utilization</p>
          </div>
          <div className="p-5 space-y-4">
            {[
              { label: 'CPU Usage', val: 42, icon: Cpu,       color: C.accent,  sub: '8 cores · 3.4 GHz' },
              { label: 'RAM',       val: 39, icon: HardDrive, color: C.success, sub: '6.2 GB / 16 GB'     },
            ].map(({ label, val, icon: Icon, color, sub }) => (
              <div key={label}>
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-1.5">
                    <Icon size={11} style={{ color: C.faint }} />
                    <span className="text-xs" style={{ color: C.muted }}>{label}</span>
                  </div>
                  <span className="text-xs font-bold text-white">{val}%</span>
                </div>
                <div className="h-1.5 rounded-full overflow-hidden mb-0.5" style={{ backgroundColor: C.panel }}>
                  <div className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${val}%`, background: `linear-gradient(90deg, ${color}70, ${color})` }} />
                </div>
                <p className="text-xs" style={{ color: C.dim }}>{sub}</p>
              </div>
            ))}

            <div className="pt-3 space-y-2.5 border-t" style={{ borderColor: C.border }}>
              <p className="text-xs font-semibold uppercase tracking-widest mb-1" style={{ color: C.dim }}>Services</p>
              {[
                { label: 'Capture Engine', status: 'Running',   ok: true  },
                { label: 'Database',       status: 'Connected', ok: true  },
                { label: 'WebSocket',      status: 'Active',    ok: true  },
                { label: 'AI Engine',      status: 'Online',    ok: true  },
              ].map(({ label, status, ok }) => (
                <div key={label} className="flex items-center justify-between">
                  <span className="text-xs" style={{ color: C.faint }}>{label}</span>
                  <div className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: ok ? C.success : C.danger }} />
                    <span className="text-xs font-medium" style={{ color: ok ? C.success : C.danger }}>{status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ── Threat Timeline ─────────────────────────────────────────────────── */}
      <Card
        title="Threat Timeline"
        sub="Detected events by severity · last 24 hours"
        action={
          <div className="flex items-center gap-3">
            {[{ label: 'Critical', color: C.danger }, { label: 'High', color: C.orange }, { label: 'Medium', color: C.warning }].map(l => (
              <div key={l.label} className="flex items-center gap-1.5 text-xs" style={{ color: C.muted }}>
                <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: l.color }} />
                {l.label}
              </div>
            ))}
            <span className="text-xs mono px-2.5 py-1 rounded-lg" style={{ backgroundColor: C.panel, color: C.faint }}>24h</span>
          </div>
        }
      >
        <ResponsiveContainer width="100%" height={130}>
          <BarChart data={THREAT_TIMELINE} margin={{ top: 4, right: 4, left: -20, bottom: 0 }} barSize={9} barCategoryGap="40%">
            <CartesianGrid strokeDasharray="2 5" stroke="#1a2744" vertical={false} />
            <XAxis dataKey="h" tick={{ fill: C.dim, fontSize: 9, fontFamily: 'JetBrains Mono' }}
              tickLine={false} axisLine={false} interval={2} />
            <YAxis tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false} />
            <Tooltip contentStyle={TIP_STYLE} />
            <Bar dataKey="critical" name="Critical" stackId="a" fill={C.danger}  radius={0} />
            <Bar dataKey="high"     name="High"     stackId="a" fill={C.orange}  radius={0} />
            <Bar dataKey="medium"   name="Medium"   stackId="a" fill={C.warning} radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
        <p className="text-xs mt-3 text-right" style={{ color: C.faint }}>
          {THREAT_TIMELINE.reduce((s, h) => s + h.critical + h.high + h.medium, 0)} total events today
        </p>
      </Card>

    </div>
  )
}
