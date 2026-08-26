import { useState } from 'react'
import {
  FileText, Download, RefreshCw, Calendar, CheckCircle,
  BarChart2, Clock, AlertTriangle,
} from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts'
import type { ToastMsg } from '../App'

const C = {
  accent: '#38BDF8', success: '#22C55E', warning: '#F59E0B',
  danger: '#EF4444', info: '#06B6D4', purple: '#818CF8',
  card: '#1E293B', panel: '#0F172A', border: '#334155',
  text: '#F8FAFC', muted: '#94A3B8', faint: '#64748B', dim: '#475569',
}
const TIP = { backgroundColor: C.panel, border: `1px solid ${C.border}`, borderRadius: '10px', fontSize: '12px', fontFamily: 'Inter', color: C.text }

type ReportType = 'daily' | 'weekly' | 'monthly' | 'custom'
type ExportFmt  = 'pdf' | 'csv' | 'json'

const REPORT_TYPES: { id: ReportType; label: string; desc: string }[] = [
  { id: 'daily',   label: 'Daily Report',   desc: 'Last 24 hours of activity' },
  { id: 'weekly',  label: 'Weekly Report',  desc: 'Rolling 7-day summary' },
  { id: 'monthly', label: 'Monthly Report', desc: '30-day executive overview' },
  { id: 'custom',  label: 'Custom Range',   desc: 'Define your own date range' },
]

const HISTORY = [
  { id: 'RPT-2024-0318', type: 'Daily',   date: '2024-03-18', size: '1.4 MB', status: 'ready',  fmt: 'PDF' },
  { id: 'RPT-2024-0317', type: 'Weekly',  date: '2024-03-17', size: '3.2 MB', status: 'ready',  fmt: 'PDF' },
  { id: 'RPT-2024-0315', type: 'Monthly', date: '2024-03-15', size: '8.6 MB', status: 'ready',  fmt: 'PDF' },
  { id: 'RPT-2024-0314', type: 'Daily',   date: '2024-03-14', size: '1.2 MB', status: 'ready',  fmt: 'CSV' },
  { id: 'RPT-2024-0310', type: 'Custom',  date: '2024-03-10', size: '2.9 MB', status: 'ready',  fmt: 'JSON'},
  { id: 'RPT-2024-0308', type: 'Daily',   date: '2024-03-08', size: '-',      status: 'failed', fmt: 'PDF' },
]

function make24h() {
  return Array.from({ length: 24 }, (_, i) => ({
    h: `${String(i).padStart(2,'0')}:00`,
    traffic: Math.round(200 + Math.sin(i * 0.5) * 150 + Math.random() * 80),
  }))
}

const data24h = make24h()
const protoPreview = [
  { name: 'TCP', value: 52, color: C.accent }, { name: 'UDP', value: 22, color: C.info },
  { name: 'HTTPS', value: 14, color: C.purple }, { name: 'Other', value: 12, color: C.dim },
]
const sevBar = [
  { sev: 'Critical', count: 3, color: C.danger }, { sev: 'High', count: 8, color: C.warning },
  { sev: 'Medium', count: 21, color: C.info }, { sev: 'Low', count: 42, color: C.success },
]

function ReportPreview({ type }: { type: ReportType }) {
  const date = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' })
  const period = type === 'daily' ? 'Past 24 Hours' : type === 'weekly' ? 'Past 7 Days' : type === 'monthly' ? 'Past 30 Days' : 'Custom Period'

  const KPI = [
    { label: 'Total Packets',    value: '1.24M',   color: C.accent  },
    { label: 'Data Transferred', value: '42.8 GB', color: C.info    },
    { label: 'Active Devices',   value: '11',      color: C.success },
    { label: 'Threats Detected', value: '74',      color: C.danger  },
    { label: 'Alerts Fired',     value: '6',       color: C.warning },
    { label: 'Mean TDR',         value: '4.2 min', color: C.purple  },
  ]

  return (
    <div className="h-full overflow-y-auto" style={{ backgroundColor: '#0A1628' }}>
      <div className="px-8 py-6 border-b" style={{ borderColor: C.border }}>
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <div className="w-6 h-6 rounded flex items-center justify-center" style={{ backgroundColor: C.accent }}>
                <BarChart2 size={12} style={{ color: '#0F172A' }} />
              </div>
              <span className="text-xs font-bold tracking-widest" style={{ color: C.accent }}>NETWATCH AI</span>
            </div>
            <h1 className="text-xl font-bold text-white mb-1">
              {type.charAt(0).toUpperCase() + type.slice(1)} Security Report
            </h1>
            <div className="text-xs" style={{ color: C.faint }}>{period} · Generated {date}</div>
          </div>
          <div className="text-right">
            <div className="text-xs font-semibold" style={{ color: C.muted }}>Report ID</div>
            <div className="mono text-xs mt-0.5" style={{ color: C.dim }}>RPT-{Date.now().toString().slice(-8)}</div>
          </div>
        </div>
      </div>

      <div className="px-8 py-6 space-y-6">
        <div className="grid grid-cols-6 gap-3">
          {KPI.map(k => (
            <div key={k.label} className="rounded-xl p-3" style={{ backgroundColor: C.card, border: `1px solid ${C.border}` }}>
              <div className="text-lg font-bold" style={{ color: k.color }}>{k.value}</div>
              <div className="text-xs mt-0.5" style={{ color: C.faint }}>{k.label}</div>
            </div>
          ))}
        </div>

        <div className="rounded-xl p-4" style={{ backgroundColor: C.card, border: `1px solid ${C.border}` }}>
          <h3 className="text-xs font-semibold text-white mb-3">Network Traffic Volume</h3>
          <ResponsiveContainer width="100%" height={120}>
            <AreaChart data={data24h} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="rg1" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.accent} stopOpacity={0.3}/>
                  <stop offset="100%" stopColor={C.accent} stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="2 5" stroke="#1a2744" vertical={false}/>
              <XAxis dataKey="h" tick={{ fill: C.dim, fontSize: 8, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} interval={5}/>
              <YAxis tick={{ fill: C.dim, fontSize: 8 }} tickLine={false} axisLine={false}/>
              <Tooltip contentStyle={TIP}/>
              <Area type="monotone" dataKey="traffic" name="Traffic" stroke={C.accent} strokeWidth={2} fill="url(#rg1)" dot={false}/>
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="rounded-xl p-4" style={{ backgroundColor: C.card, border: `1px solid ${C.border}` }}>
            <h3 className="text-xs font-semibold text-white mb-3">Alert Severity Breakdown</h3>
            <ResponsiveContainer width="100%" height={100}>
              <BarChart data={sevBar} margin={{ top: 4, right: 4, left: -20, bottom: 0 }} barSize={20}>
                <XAxis dataKey="sev" tick={{ fill: C.dim, fontSize: 8 }} tickLine={false} axisLine={false}/>
                <YAxis tick={{ fill: C.dim, fontSize: 8 }} tickLine={false} axisLine={false}/>
                <Tooltip contentStyle={TIP}/>
                <Bar dataKey="count" name="Alerts" radius={[3,3,0,0]}>
                  {sevBar.map((e, i) => <Cell key={i} fill={e.color}/>)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="rounded-xl p-4" style={{ backgroundColor: C.card, border: `1px solid ${C.border}` }}>
            <h3 className="text-xs font-semibold text-white mb-3">Protocol Mix</h3>
            <div className="flex items-center gap-4">
              <ResponsiveContainer width={100} height={100}>
                <PieChart>
                  <Pie data={protoPreview} dataKey="value" innerRadius={28} outerRadius={45} strokeWidth={0} paddingAngle={2}>
                    {protoPreview.map((e, i) => <Cell key={i} fill={e.color}/>)}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-1.5">
                {protoPreview.map(p => (
                  <div key={p.name} className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: p.color }}/>
                    <span className="text-xs" style={{ color: C.muted }}>{p.name}</span>
                    <span className="text-xs font-bold mono ml-1" style={{ color: p.color }}>{p.value}%</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="rounded-xl p-4" style={{ backgroundColor: C.card, border: `1px solid ${C.border}` }}>
          <h3 className="text-xs font-semibold text-white mb-3">Top Security Events</h3>
          <table className="w-full">
            <thead>
              <tr>
                {['Severity','Event','Source','MITRE','Status'].map(h => (
                  <th key={h} className="text-left text-xs pb-2 font-medium" style={{ color: C.dim }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {([
                ['Critical', 'Port Scan',        '192.168.1.20', 'T1046',     'Active'],
                ['High',     'DNS Tunneling',     '10.0.0.22',    'T1071.004', 'Investigating'],
                ['High',     'Brute Force (SSH)', '192.168.1.45', 'T1110',     'Acknowledged'],
                ['Medium',   'ARP Spoofing',      '192.168.1.100','T1557',     'Resolved'],
              ] as const).map(([sev, evt, src, mid, sta]) => {
                const cc = sev === 'Critical' ? C.danger : sev === 'High' ? C.warning : C.info
                return (
                  <tr key={evt} className="border-t" style={{ borderColor: '#1a2744' }}>
                    <td className="py-1.5 pr-4"><span className="text-xs px-2 py-0.5 rounded-full" style={{ backgroundColor: `${cc}15`, color: cc }}>{sev}</span></td>
                    <td className="py-1.5 pr-4 text-xs text-white">{evt}</td>
                    <td className="py-1.5 pr-4 mono text-xs" style={{ color: C.accent }}>{src}</td>
                    <td className="py-1.5 pr-4 mono text-xs" style={{ color: C.faint }}>{mid}</td>
                    <td className="py-1.5 text-xs" style={{ color: C.muted }}>{sta}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

interface Props { showToast: (msg: string, type?: ToastMsg['type']) => void }

export default function Reports({ showToast }: Props) {
  const [reportType, setReportType] = useState<ReportType>('daily')
  const [generating, setGenerating] = useState(false)
  const [customFrom, setCustomFrom] = useState('2024-03-01')
  const [customTo, setCustomTo] = useState('2024-03-18')

  const handleGenerate = (fmt: ExportFmt) => {
    setGenerating(true)
    setTimeout(() => {
      setGenerating(false)
      showToast(`${reportType.charAt(0).toUpperCase() + reportType.slice(1)} report exported as ${fmt.toUpperCase()}`, 'success')
    }, 1400)
  }

  return (
    <div className="flex gap-4" style={{ height: 'calc(100vh - 200px)', minHeight: 0 }}>
      {/* Left: controls */}
      <div className="w-72 flex-shrink-0 space-y-4 overflow-y-auto">
        <div className="rounded-2xl border overflow-hidden" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="px-4 py-4 border-b" style={{ borderColor: C.border }}>
            <h2 className="text-sm font-semibold text-white">Report Type</h2>
          </div>
          <div className="p-2 space-y-1">
            {REPORT_TYPES.map(r => (
              <button key={r.id} onClick={() => setReportType(r.id)}
                className="w-full text-left px-3 py-3 rounded-xl transition-all"
                style={{ backgroundColor: reportType === r.id ? `${C.accent}10` : 'transparent', border: `1px solid ${reportType === r.id ? `${C.accent}30` : 'transparent'}` }}>
                <div className="text-xs font-semibold" style={{ color: reportType === r.id ? C.accent : C.muted }}>{r.label}</div>
                <div className="text-xs mt-0.5" style={{ color: C.faint }}>{r.desc}</div>
              </button>
            ))}
          </div>
        </div>

        {reportType === 'custom' && (
          <div className="rounded-2xl border p-4 space-y-3" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <h3 className="text-xs font-semibold text-white flex items-center gap-1.5">
              <Calendar size={12} style={{ color: C.accent }}/> Date Range
            </h3>
            {(['From', 'To'] as const).map(label => {
              const val = label === 'From' ? customFrom : customTo
              const setter = label === 'From' ? setCustomFrom : setCustomTo
              return (
                <div key={label}>
                  <label className="text-xs" style={{ color: C.faint }}>{label}</label>
                  <input type="date" value={val} onChange={e => setter(e.target.value)}
                    className="w-full mt-1 px-3 py-2 rounded-xl text-xs border"
                    style={{ backgroundColor: C.panel, borderColor: C.border, color: C.text, outline: 'none' }} />
                </div>
              )
            })}
          </div>
        )}

        <div className="rounded-2xl border p-4 space-y-2" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <h3 className="text-xs font-semibold text-white mb-3">Export Format</h3>
          {(['pdf', 'csv', 'json'] as ExportFmt[]).map(fmt => {
            const cfg = {
              pdf:  { icon: <FileText size={13}/>,  label: 'Export PDF',  color: C.danger  },
              csv:  { icon: <Download size={13}/>,  label: 'Export CSV',  color: C.success },
              json: { icon: <BarChart2 size={13}/>, label: 'Export JSON', color: C.accent  },
            }[fmt]
            return (
              <button key={fmt} onClick={() => handleGenerate(fmt)} disabled={generating}
                className="w-full flex items-center gap-2 px-3 py-2.5 rounded-xl text-xs font-semibold transition-all"
                style={{ backgroundColor: `${cfg.color}12`, color: cfg.color, opacity: generating ? 0.5 : 1 }}>
                {generating ? <RefreshCw size={12} className="animate-spin"/> : cfg.icon}
                {generating ? 'Generating...' : cfg.label}
              </button>
            )
          })}
        </div>

        <div className="rounded-2xl border overflow-hidden" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="px-4 py-3 border-b" style={{ borderColor: C.border }}>
            <h3 className="text-xs font-semibold text-white">Report History</h3>
          </div>
          <div>
            {HISTORY.map(h => (
              <div key={h.id} className="flex items-center justify-between px-4 py-3 border-b group transition-colors cursor-pointer"
                style={{ borderColor: '#1a2744' }}
                onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)')}
                onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
                <div>
                  <div className="flex items-center gap-1.5">
                    {h.status === 'ready'
                      ? <CheckCircle size={10} style={{ color: C.success }}/>
                      : <AlertTriangle size={10} style={{ color: C.danger }}/>}
                    <span className="text-xs font-semibold text-white">{h.type}</span>
                    <span className="text-xs px-1.5 py-0.5 rounded mono" style={{ backgroundColor: C.panel, color: C.faint, fontSize: '9px' }}>{h.fmt}</span>
                  </div>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <Clock size={9} style={{ color: C.faint }}/>
                    <span className="text-xs" style={{ color: C.faint }}>{h.date} · {h.size}</span>
                  </div>
                </div>
                {h.status === 'ready' && (
                  <button onClick={() => showToast(`Downloading ${h.id}`, 'info')}
                    className="opacity-0 group-hover:opacity-100 transition-opacity p-1.5 rounded-lg"
                    style={{ backgroundColor: `${C.accent}15` }}>
                    <Download size={11} style={{ color: C.accent }}/>
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Right: preview */}
      <div className="flex-1 min-w-0 rounded-2xl border overflow-hidden" style={{ backgroundColor: '#0A1628', borderColor: C.border }}>
        <div className="flex items-center justify-between px-5 py-3 border-b" style={{ borderColor: C.border, backgroundColor: C.card }}>
          <div className="flex items-center gap-2">
            <FileText size={13} style={{ color: C.accent }}/>
            <span className="text-xs font-semibold text-white">Report Preview</span>
            <span className="text-xs px-2 py-0.5 rounded-full" style={{ backgroundColor: `${C.accent}15`, color: C.accent }}>
              {reportType.charAt(0).toUpperCase() + reportType.slice(1)}
            </span>
          </div>
          <span className="text-xs" style={{ color: C.faint }}>Live preview</span>
        </div>
        <div style={{ height: 'calc(100% - 48px)', overflow: 'hidden' }}>
          <ReportPreview type={reportType}/>
        </div>
      </div>
    </div>
  )
}
