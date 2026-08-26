import { useState } from 'react'
import {
  AreaChart, Area, BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend,
} from 'recharts'

// ─── Tokens ──────────────────────────────────────────────────────────────────
const C = {
  accent: '#38BDF8', success: '#22C55E', warning: '#F59E0B',
  danger: '#EF4444', info: '#06B6D4', purple: '#818CF8', orange: '#F97316',
  card: '#1E293B', panel: '#0F172A', border: '#334155',
  text: '#F8FAFC', muted: '#94A3B8', faint: '#64748B', dim: '#475569',
}
const TIP = { backgroundColor: C.panel, border: `1px solid ${C.border}`, borderRadius: '10px', fontSize: '12px', fontFamily: 'Inter', color: C.text }

// ─── Data generators ──────────────────────────────────────────────────────────
const HOURS  = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2,'0')}:00`)
const DAYS   = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun']
const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']

function rand(min: number, max: number) { return Math.round(min + Math.random() * (max - min)) }

const trafficData    = HOURS.map(h => ({ h, inbound: rand(200,900), outbound: rand(100,600) }))
const bandwidthData  = DAYS.map(d => ({ d, peak: rand(600,1200), avg: rand(200,500) }))
const threatTrend    = MONTHS.map(m => ({ m, critical: rand(0,12), high: rand(5,30), medium: rand(10,60) }))
const alertTrend     = MONTHS.map(m => ({ m, total: rand(80,400), resolved: rand(60,350) }))
const connTrend      = DAYS.map(d => ({ d, conns: rand(800,2400) }))
const utilizationData = HOURS.map(h => ({ h, cpu: rand(20,90), net: rand(15,75) }))
const pktSizeData    = [
  { range: '<64B',    count: rand(5000,15000) }, { range: '64-128B', count: rand(8000,20000) },
  { range: '128-256B',count: rand(6000,18000) }, { range: '256-512B',count: rand(3000,10000) },
  { range: '512-1KB', count: rand(2000,8000)  }, { range: '1-1.5KB', count: rand(1000,5000)  },
]
const protoData  = [
  { name: 'TCP',   value: 52, color: C.accent  },
  { name: 'UDP',   value: 22, color: C.info    },
  { name: 'HTTPS', value: 14, color: C.purple  },
  { name: 'DNS',   value:  7, color: C.success },
  { name: 'Other', value:  5, color: C.dim     },
]
const topPorts = [
  { port: '443 (HTTPS)', count: rand(12000,30000) }, { port: '80 (HTTP)',  count: rand(8000,20000) },
  { port: '22 (SSH)',    count: rand(2000,8000)   }, { port: '53 (DNS)',   count: rand(3000,10000) },
  { port: '3306 (MySQL)',count: rand(500,3000)    }, { port: '8080 (Alt)', count: rand(200,1500)   },
  { port: '445 (SMB)',   count: rand(100,1000)    },
]
const topSrcIPs = [
  { ip: '192.168.1.25', bytes: '3.2 GB', pct: 28, color: C.danger  },
  { ip: '192.168.1.1',  bytes: '2.1 GB', pct: 18, color: C.accent  },
  { ip: '10.0.0.22',    bytes: '1.4 GB', pct: 12, color: C.warning },
  { ip: '192.168.1.10', bytes: '980 MB', pct:  9, color: C.info    },
  { ip: '192.168.1.72', bytes: '780 MB', pct:  7, color: C.success },
]
const topDstIPs = [
  { ip: '104.21.45.2',  bytes: '3.2 GB', pct: 26, color: C.danger },
  { ip: '8.8.8.8',      bytes: '1.8 GB', pct: 15, color: C.accent },
  { ip: '1.1.1.1',      bytes: '1.2 GB', pct: 10, color: C.info   },
  { ip: '142.250.80.4', bytes: '980 MB', pct:  8, color: C.purple },
  { ip: '20.190.160.2', bytes: '640 MB', pct:  5, color: C.success},
]

// ─── Chart card ───────────────────────────────────────────────────────────────
function ChartCard({ title, sub, children }: { title: string; sub?: string; children: React.ReactNode }) {
  return (
    <div className="rounded-2xl border p-5"
      style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 20px rgba(0,0,0,0.15)' }}>
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-white">{title}</h3>
        {sub && <p className="text-xs mt-0.5" style={{ color: C.faint }}>{sub}</p>}
      </div>
      {children}
    </div>
  )
}

function IPTable({ data }: { data: typeof topSrcIPs }) {
  return (
    <div className="space-y-3">
      {data.map((d, i) => (
        <div key={d.ip} className="flex items-center gap-3">
          <div className="w-5 text-xs font-bold" style={{ color: C.faint }}>#{i+1}</div>
          <div className="flex-1 min-w-0">
            <div className="flex justify-between text-xs mb-1">
              <span className="mono font-medium" style={{ color: C.accent }}>{d.ip}</span>
              <span style={{ color: C.muted }}>{d.bytes}</span>
            </div>
            <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
              <div className="h-full rounded-full" style={{ width: `${d.pct}%`, backgroundColor: d.color }} />
            </div>
          </div>
          <div className="w-10 text-right mono text-xs font-bold" style={{ color: d.color }}>{d.pct}%</div>
        </div>
      ))}
    </div>
  )
}

const RANGES = ['1H','24H','7D','30D','90D']

export default function Analytics() {
  const [range, setRange] = useState('24H')

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-white">Network Analytics</h1>
          <p className="text-xs mt-0.5" style={{ color: C.faint }}>Interactive traffic intelligence and threat metrics</p>
        </div>
        <div className="flex gap-1 p-1 rounded-xl" style={{ backgroundColor: C.card, border: `1px solid ${C.border}` }}>
          {RANGES.map(r => (
            <button key={r} onClick={() => setRange(r)}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all"
              style={{ backgroundColor: range === r ? C.accent : 'transparent', color: range === r ? '#0F172A' : C.faint }}>
              {r}
            </button>
          ))}
        </div>
      </div>

      {/* Row 1: Traffic + Bandwidth */}
      <div className="grid grid-cols-2 gap-4">
        <ChartCard title="Traffic Over Time" sub="Inbound vs outbound packet rate">
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={trafficData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="gIn"  x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.accent} stopOpacity={0.3}/>
                  <stop offset="100%" stopColor={C.accent} stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="gOut" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.purple} stopOpacity={0.3}/>
                  <stop offset="100%" stopColor={C.purple} stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="2 5" stroke="#1a2744" vertical={false}/>
              <XAxis dataKey="h" tick={{ fill: C.dim, fontSize: 9, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} interval={5}/>
              <YAxis tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false}/>
              <Tooltip contentStyle={TIP}/>
              <Area type="monotone" dataKey="inbound"  name="Inbound"  stroke={C.accent} strokeWidth={2} fill="url(#gIn)"  dot={false}/>
              <Area type="monotone" dataKey="outbound" name="Outbound" stroke={C.purple} strokeWidth={2} fill="url(#gOut)" dot={false}/>
            </AreaChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Bandwidth Usage" sub="Peak vs average daily throughput (Mbps)">
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={bandwidthData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }} barGap={3}>
              <CartesianGrid strokeDasharray="2 5" stroke="#1a2744" vertical={false}/>
              <XAxis dataKey="d" tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false}/>
              <YAxis tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false}/>
              <Tooltip contentStyle={TIP}/>
              <Bar dataKey="peak" name="Peak" fill={C.accent} radius={[3,3,0,0]} barSize={14}/>
              <Bar dataKey="avg"  name="Avg"  fill={C.purple} radius={[3,3,0,0]} barSize={14}/>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      {/* Row 2: Protocol doughnut + Top Ports + Packet Size */}
      <div className="grid grid-cols-3 gap-4">
        <ChartCard title="Protocol Distribution" sub="Share by packet count">
          <div className="flex items-center gap-4">
            <ResponsiveContainer width={140} height={140}>
              <PieChart>
                <Pie data={protoData} dataKey="value" innerRadius={40} outerRadius={62} strokeWidth={0} paddingAngle={2}>
                  {protoData.map((entry, i) => <Cell key={i} fill={entry.color}/>)}
                </Pie>
                <Tooltip contentStyle={TIP}/>
              </PieChart>
            </ResponsiveContainer>
            <div className="space-y-2">
              {protoData.map(p => (
                <div key={p.name} className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{ backgroundColor: p.color }}/>
                  <span className="text-xs" style={{ color: C.muted }}>{p.name}</span>
                  <span className="text-xs font-bold ml-auto mono" style={{ color: p.color }}>{p.value}%</span>
                </div>
              ))}
            </div>
          </div>
        </ChartCard>

        <ChartCard title="Top Ports" sub="By connection count">
          <div className="space-y-2.5">
            {topPorts.map((p, i) => (
              <div key={p.port} className="flex items-center gap-2">
                <div className="w-4 text-xs font-bold text-right" style={{ color: C.faint }}>#{i+1}</div>
                <div className="flex-1 min-w-0">
                  <div className="flex justify-between text-xs mb-0.5">
                    <span className="mono" style={{ color: C.muted }}>{p.port}</span>
                    <span className="mono font-semibold" style={{ color: C.accent }}>{p.count.toLocaleString()}</span>
                  </div>
                  <div className="h-1 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
                    <div className="h-full rounded-full" style={{ width: `${Math.round(p.count / 30000 * 100)}%`, backgroundColor: C.accent }}/>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </ChartCard>

        <ChartCard title="Packet Size Distribution" sub="Frequency by byte range">
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={pktSizeData} margin={{ top: 4, right: 4, left: -10, bottom: 10 }} barSize={18}>
              <CartesianGrid strokeDasharray="2 5" stroke="#1a2744" vertical={false}/>
              <XAxis dataKey="range" tick={{ fill: C.dim, fontSize: 8 }} tickLine={false} axisLine={false}/>
              <YAxis tick={{ fill: C.dim, fontSize: 8 }} tickLine={false} axisLine={false}/>
              <Tooltip contentStyle={TIP}/>
              <Bar dataKey="count" name="Packets" radius={[3,3,0,0]}>
                {pktSizeData.map((_, i) => <Cell key={i} fill={`hsl(${200 + i * 12}, 70%, ${55 + i * 3}%)`}/>)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      {/* Row 3: Threat Trend + Alert Trend */}
      <div className="grid grid-cols-2 gap-4">
        <ChartCard title="Threat Trend" sub="Monthly threat severity breakdown">
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={threatTrend} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="2 5" stroke="#1a2744" vertical={false}/>
              <XAxis dataKey="m" tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false}/>
              <YAxis tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false}/>
              <Tooltip contentStyle={TIP}/>
              <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 10, color: C.dim }}/>
              <Line type="monotone" dataKey="critical" name="Critical" stroke={C.danger}  strokeWidth={2} dot={{ r: 3, fill: C.danger  }} activeDot={{ r: 5 }}/>
              <Line type="monotone" dataKey="high"     name="High"     stroke={C.orange}  strokeWidth={2} dot={{ r: 3, fill: C.orange  }} activeDot={{ r: 5 }}/>
              <Line type="monotone" dataKey="medium"   name="Medium"   stroke={C.warning} strokeWidth={2} dot={{ r: 3, fill: C.warning }} activeDot={{ r: 5 }}/>
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Alert Trend" sub="Total alerts raised vs resolved">
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={alertTrend} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.danger} stopOpacity={0.25}/>
                  <stop offset="100%" stopColor={C.danger} stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="gResolved" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.success} stopOpacity={0.2}/>
                  <stop offset="100%" stopColor={C.success} stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="2 5" stroke="#1a2744" vertical={false}/>
              <XAxis dataKey="m" tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false}/>
              <YAxis tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false}/>
              <Tooltip contentStyle={TIP}/>
              <Area type="monotone" dataKey="total"    name="Total"    stroke={C.danger}  strokeWidth={2} fill="url(#gTotal)"    dot={false}/>
              <Area type="monotone" dataKey="resolved" name="Resolved" stroke={C.success} strokeWidth={2} fill="url(#gResolved)" dot={false}/>
            </AreaChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      {/* Row 4: Top IPs + Utilization + Connections */}
      <div className="grid grid-cols-4 gap-4">
        <ChartCard title="Top Source IPs" sub="By bandwidth consumed">
          <IPTable data={topSrcIPs}/>
        </ChartCard>

        <ChartCard title="Top Destination IPs" sub="By data transferred">
          <IPTable data={topDstIPs}/>
        </ChartCard>

        <ChartCard title="Network Utilization" sub="CPU and link saturation (%)">
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={utilizationData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="gCPU" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.warning} stopOpacity={0.3}/>
                  <stop offset="100%" stopColor={C.warning} stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="gNet" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.info} stopOpacity={0.25}/>
                  <stop offset="100%" stopColor={C.info} stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="2 5" stroke="#1a2744" vertical={false}/>
              <XAxis dataKey="h" tick={{ fill: C.dim, fontSize: 8, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} interval={5}/>
              <YAxis tick={{ fill: C.dim, fontSize: 8 }} tickLine={false} axisLine={false} domain={[0, 100]}/>
              <Tooltip contentStyle={TIP}/>
              <Area type="monotone" dataKey="cpu" name="CPU %"  stroke={C.warning} strokeWidth={1.5} fill="url(#gCPU)" dot={false}/>
              <Area type="monotone" dataKey="net" name="Link %" stroke={C.info}    strokeWidth={1.5} fill="url(#gNet)" dot={false}/>
            </AreaChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Connection Trend" sub="Active connections per day">
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={connTrend} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="2 5" stroke="#1a2744" vertical={false}/>
              <XAxis dataKey="d" tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false}/>
              <YAxis tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false}/>
              <Tooltip contentStyle={TIP}/>
              <Line type="monotone" dataKey="conns" name="Connections" stroke={C.success} strokeWidth={2.5} dot={{ r: 4, fill: C.success, strokeWidth: 0 }} activeDot={{ r: 6 }}/>
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>
    </div>
  )
}
