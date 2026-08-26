import { useState } from 'react'
import {
  Search, Filter, Download, ArrowLeft, Shield, AlertTriangle,
  Brain, CheckCircle, FileText, Clock, Target,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid,
} from 'recharts'
import type { ToastMsg } from '../App'

// ─── Tokens ──────────────────────────────────────────────────────────────────
const C = {
  accent: '#38BDF8', success: '#22C55E', warning: '#F59E0B',
  danger: '#EF4444', info: '#06B6D4', purple: '#818CF8', orange: '#F97316',
  card: '#1E293B', panel: '#0F172A', border: '#334155',
  text: '#F8FAFC', muted: '#94A3B8', faint: '#64748B', dim: '#475569',
}
const TIP = { backgroundColor: C.panel, border: `1px solid ${C.border}`, borderRadius: '10px', fontSize: '12px', fontFamily: 'Inter' }

const SEV_CFG: Record<string, { color: string; bg: string; label: string; border: string }> = {
  critical: { color: C.danger,  bg: 'rgba(239,68,68,0.12)',   label: 'Critical', border: 'rgba(239,68,68,0.3)'   },
  high:     { color: C.orange,  bg: 'rgba(249,115,22,0.12)',  label: 'High',     border: 'rgba(249,115,22,0.3)'  },
  medium:   { color: C.warning, bg: 'rgba(245,158,11,0.12)',  label: 'Medium',   border: 'rgba(245,158,11,0.3)'  },
  low:      { color: C.info,    bg: 'rgba(6,182,212,0.12)',   label: 'Low',      border: 'rgba(6,182,212,0.3)'   },
}
const STATUS_CFG: Record<string, { color: string; bg: string }> = {
  active:        { color: C.danger,  bg: 'rgba(239,68,68,0.12)'  },
  investigating: { color: C.warning, bg: 'rgba(245,158,11,0.12)' },
  acknowledged:  { color: C.info,    bg: 'rgba(6,182,212,0.12)'  },
  resolved:      { color: C.success, bg: 'rgba(34,197,94,0.12)'  },
}

// ─── Data ─────────────────────────────────────────────────────────────────────
interface Alert {
  id: number; sev: string; type: string; src: string; dst: string
  srcDevice: string; confidence: number; mitre: string; mitreId: string
  status: string; time: string; proto: string; desc: string
  recommendation: string; iocs: string[]
  evidence: { type: string; value: string }[]
}

const ALERTS: Alert[] = [
  {
    id:1, sev:'critical', type:'Port Scan',        src:'192.168.1.20', dst:'192.168.1.0/24',
    srcDevice:'UNKNOWN-C001',  confidence:91, mitre:'Network Service Scanning', mitreId:'T1046',
    status:'active',        time:'12:21:08', proto:'TCP',  desc:'Systematic SYN scan detected across 1,024 ports. Source is performing network reconnaissance against the internal subnet.',
    recommendation:'Immediately block 192.168.1.20 at the firewall. Enable IPS blocking rule. Isolate device and perform forensic investigation.',
    iocs:['192.168.1.20 scanning 1,024 ports','SYN packets with no ACK responses','Source port randomization pattern detected'],
    evidence:[{type:'IP',value:'192.168.1.20'},{type:'Port Range',value:'1–1024'},{type:'Packets',value:'8,420 SYN pkts/min'},{type:'Duration',value:'4 min 32s'}],
  },
  {
    id:2, sev:'high',     type:'DNS Tunneling',   src:'10.0.0.22',    dst:'8.8.8.8',
    srcDevice:'IOT-ESP32-01',  confidence:84, mitre:'Application Layer Protocol: DNS', mitreId:'T1071.004',
    status:'investigating', time:'12:15:33', proto:'DNS', desc:'Encoded data detected in DNS TXT query payloads. Payload exceeds normal DNS response size by 4x and contains base64-encoded content.',
    recommendation:'Quarantine IoT device. Block DNS to external resolvers. Review all DNS traffic from 10.0.0.22 over last 48 hours.',
    iocs:['DNS TXT records >512 bytes','Base64 encoded subdomains','Query rate: 240/min vs baseline 12/min'],
    evidence:[{type:'IP',value:'10.0.0.22'},{type:'Domain',value:'c2.attacker.io'},{type:'Payload',value:'Encoded 4.2KB'},{type:'Queries',value:'240/min'}],
  },
  {
    id:3, sev:'high',     type:'Brute Force',     src:'192.168.1.45', dst:'192.168.1.5',
    srcDevice:'iPhone-15-Pro', confidence:78, mitre:'Brute Force',  mitreId:'T1110',
    status:'acknowledged',  time:'11:58:14', proto:'SSH', desc:'420 failed SSH authentication attempts detected in 60 seconds against NAS server. Credential stuffing attack pattern.',
    recommendation:'Lock SSH account after 5 failed attempts. Implement 2FA for SSH. Consider whitelisting SSH source IPs.',
    iocs:['420 failed auth attempts in 60s','Multiple username variants tried','Sequential user enumeration pattern'],
    evidence:[{type:'Target',value:'192.168.1.5:22'},{type:'Attempts',value:'420 in 60s'},{type:'Usernames',value:'28 variants'},{type:'Source',value:'192.168.1.45'}],
  },
  {
    id:4, sev:'medium',   type:'ARP Spoofing',    src:'192.168.1.100',dst:'192.168.1.0/24',
    srcDevice:'SAMSUNG-TV',    confidence:72, mitre:'Adversary-in-the-Middle', mitreId:'T1557',
    status:'acknowledged',  time:'11:42:55', proto:'ARP', desc:'Gratuitous ARP replies detected from Samsung TV. Host may be attempting to poison the ARP cache of neighboring devices.',
    recommendation:'Enable Dynamic ARP Inspection on managed switches. Monitor for man-in-the-middle indicators.',
    iocs:['Unsolicited ARP replies','MAC spoofing attempt','Gateway ARP entry modification'],
    evidence:[{type:'Source',value:'192.168.1.100'},{type:'Target MAC',value:'Broadcast'},{type:'Rate',value:'120 ARP/min'},{type:'Duration',value:'8 min'}],
  },
  {
    id:5, sev:'medium',   type:'Data Exfiltration',src:'192.168.1.25',dst:'104.21.45.2',
    srcDevice:'UNKNOWN-FF00',  confidence:68, mitre:'Exfiltration Over C2',mitreId:'T1041',
    status:'investigating', time:'11:20:02', proto:'HTTPS',desc:'Large encrypted data transfer detected to unknown external host. Volume 3.2GB over 12 minutes is anomalous for this device.',
    recommendation:'Block outbound connection to 104.21.45.2. Perform memory forensics on device. Check for installed backdoors.',
    iocs:['3.2GB upload in 12 minutes','Connection to uncategorized IP','Encrypted channel to unknown host'],
    evidence:[{type:'Dst IP',value:'104.21.45.2'},{type:'Volume',value:'3.2 GB upload'},{type:'Duration',value:'12 min'},{type:'Encryption',value:'TLS 1.3'}],
  },
  {
    id:6, sev:'low',      type:'ICMP Flood',      src:'192.168.1.55', dst:'192.168.1.1',
    srcDevice:'RASPI-4B',      confidence:45, mitre:'Network Denial of Service',mitreId:'T1498',
    status:'resolved',      time:'10:55:18', proto:'ICMP',desc:'High-rate ICMP echo requests detected against the gateway. Could indicate DoS attempt or automated network testing.',
    recommendation:'Rate-limit ICMP at perimeter. Investigate if device is running unauthorized network tools.',
    iocs:['1,200 ICMP/s against gateway','Packet size 65,507 bytes (max ICMP)','Continuous for 3 minutes'],
    evidence:[{type:'Target',value:'192.168.1.1'},{type:'Rate',value:'1,200 pkts/s'},{type:'Size',value:'65,507 bytes'},{type:'Duration',value:'3 min'}],
  },
]

// ─── Threat Gauge (mini) ─────────────────────────────────────────────────────
function MiniGauge({ score, color }: { score: number; color: string }) {
  const r = 36, sw = 7, W = 100, H = 62, cx = W/2, cy = H - 4
  const angle = Math.PI * (1 - score / 100)
  const nx = +(cx + r * Math.cos(angle)).toFixed(2)
  const ny = +(cy - r * Math.sin(angle)).toFixed(2)
  const bg  = `M ${cx-r} ${cy} A ${r} ${r} 0 0 1 ${cx+r} ${cy}`
  const fill = score > 0 ? `M ${cx-r} ${cy} A ${r} ${r} 0 0 1 ${nx} ${ny}` : null
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width={W} height={H} style={{ overflow: 'visible' }}>
      <path d={bg} fill="none" stroke={C.panel} strokeWidth={sw-2} strokeLinecap="round" />
      {fill && <path d={fill} fill="none" stroke={color} strokeWidth={sw-2} strokeLinecap="round" />}
      <circle cx={nx} cy={ny} r={4} fill={color} />
      <text x={cx} y={cy-10} textAnchor="middle" fill={C.text} fontSize={18} fontWeight="700" fontFamily="Inter">{score}</text>
      <text x={cx} y={cy+2}  textAnchor="middle" fill={color} fontSize={8} fontWeight="600" fontFamily="Inter">RISK SCORE</text>
    </svg>
  )
}

// ─── Alert Investigation ──────────────────────────────────────────────────────
function AlertInvestigation({ alert, onBack, showToast }: {
  alert: Alert; onBack: () => void; showToast: (m: string, t?: ToastMsg['type']) => void
}) {
  const sev  = SEV_CFG[alert.sev]
  const stat = STATUS_CFG[alert.status]
  const riskScore = alert.sev === 'critical' ? 94 : alert.sev === 'high' ? 72 : alert.sev === 'medium' ? 48 : 22

  const timelineData = Array.from({ length: 12 }, (_, i) => ({
    t: `${String(12 - i).padStart(2,'0')}:${String(i * 5).padStart(2,'0')}`,
    events: Math.floor(Math.random() * (alert.sev === 'critical' ? 40 : 20)),
  }))

  return (
    <div className="space-y-4 fade-in-up">
      <button onClick={onBack}
        className="flex items-center gap-2 text-sm font-medium transition-colors"
        style={{ color: C.muted }}
        onMouseEnter={e => (e.currentTarget.style.color = C.accent)}
        onMouseLeave={e => (e.currentTarget.style.color = C.muted)}>
        <ArrowLeft size={15}/> Back to Alerts
      </button>

      {/* Header */}
      <div className="rounded-2xl border p-6" style={{ backgroundColor: C.card, borderColor: sev.border }}>
        <div className="flex items-start justify-between gap-6">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2 flex-wrap">
              <span className="text-xs px-2.5 py-1 rounded-full font-semibold"
                style={{ backgroundColor: sev.bg, color: sev.color }}>{sev.label}</span>
              <span className="text-xs px-2.5 py-1 rounded-full font-medium capitalize"
                style={{ backgroundColor: stat.bg, color: stat.color }}>{alert.status}</span>
              <span className="text-xs px-2 py-0.5 rounded mono"
                style={{ backgroundColor: C.panel, color: C.muted }}>{alert.proto}</span>
              <span className="mono text-xs ml-auto" style={{ color: C.faint }}>{alert.time}</span>
            </div>
            <h1 className="text-xl font-bold text-white mb-1">{alert.type}</h1>
            <div className="mono text-sm mb-3" style={{ color: C.accent }}>{alert.mitreId} — {alert.mitre}</div>
            <p className="text-sm leading-relaxed" style={{ color: C.muted }}>{alert.desc}</p>
          </div>
          <div className="flex flex-col items-center flex-shrink-0">
            <MiniGauge score={riskScore} color={sev.color} />
          </div>
        </div>

        {/* Evidence grid */}
        <div className="grid grid-cols-4 gap-3 mt-5 pt-5 border-t" style={{ borderColor: C.border }}>
          {alert.evidence.map(ev => (
            <div key={ev.type} className="p-3 rounded-xl" style={{ backgroundColor: C.panel }}>
              <div className="text-xs mb-1" style={{ color: C.faint }}>{ev.type}</div>
              <div className="mono text-xs font-semibold text-white">{ev.value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Actions */}
      <div className="flex gap-3">
        <button onClick={() => showToast(`Alert #${alert.id} acknowledged`, 'info')}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold"
          style={{ backgroundColor: `${C.info}15`, color: C.info }}>
          <CheckCircle size={14}/> Acknowledge
        </button>
        <button onClick={() => showToast(`Alert #${alert.id} resolved`, 'success')}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold"
          style={{ backgroundColor: `${C.success}15`, color: C.success }}>
          <Shield size={14}/> Resolve
        </button>
        <button onClick={() => showToast('Alert report exported', 'success')}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold border"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
          <Download size={14}/> Export
        </button>
      </div>

      {/* Main content grid */}
      <div className="grid grid-cols-12 gap-4">
        {/* Left col (8) */}
        <div className="col-span-8 space-y-4">
          {/* Packet timeline */}
          <div className="rounded-2xl border p-5" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <h3 className="text-sm font-semibold text-white mb-1">Attack Timeline</h3>
            <p className="text-xs mb-4" style={{ color: C.faint }}>Event frequency over last 60 minutes</p>
            <ResponsiveContainer width="100%" height={150}>
              <BarChart data={timelineData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }} barSize={12}>
                <CartesianGrid strokeDasharray="2 5" stroke="#1a2744" vertical={false} />
                <XAxis dataKey="t" tick={{ fill: C.dim, fontSize: 9, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fill: C.dim, fontSize: 9 }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={TIP} />
                <Bar dataKey="events" name="Events" fill={sev.color} radius={[3,3,0,0]} opacity={0.9} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* MITRE ATT&CK */}
          <div className="rounded-2xl border p-5" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="flex items-center gap-2 mb-4">
              <Target size={14} style={{ color: C.accent }} />
              <h3 className="text-sm font-semibold text-white">MITRE ATT&CK Mapping</h3>
            </div>
            <div className="grid grid-cols-3 gap-3">
              {[
                { phase: 'Reconnaissance',    technique: alert.mitreId, name: alert.mitre, active: true },
                { phase: 'Initial Access',    technique: '—',           name: 'No mapping', active: false },
                { phase: 'Execution',         technique: '—',           name: 'No mapping', active: false },
                { phase: 'Persistence',       technique: '—',           name: 'No mapping', active: false },
                { phase: 'Lateral Movement',  technique: alert.sev === 'critical' ? 'T1021' : '—', name: alert.sev === 'critical' ? 'Remote Services' : 'No mapping', active: alert.sev === 'critical' },
                { phase: 'Exfiltration',      technique: alert.type.includes('Exfil') ? 'T1041' : '—', name: alert.type.includes('Exfil') ? 'C2 Channel' : 'No mapping', active: alert.type.includes('Exfil') },
              ].map(m => (
                <div key={m.phase} className="p-3 rounded-xl border transition-all"
                  style={{ backgroundColor: m.active ? `${C.accent}08` : C.panel, borderColor: m.active ? `${C.accent}30` : C.border }}>
                  <div className="text-xs font-semibold mb-1" style={{ color: m.active ? C.accent : C.dim }}>{m.phase}</div>
                  <div className="mono text-xs font-bold text-white">{m.technique}</div>
                  <div className="text-xs mt-0.5" style={{ color: C.faint }}>{m.name}</div>
                </div>
              ))}
            </div>
          </div>

          {/* IOCs */}
          <div className="rounded-2xl border p-5" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <h3 className="text-sm font-semibold text-white mb-4">Indicators of Compromise</h3>
            <div className="space-y-2">
              {alert.iocs.map((ioc, i) => (
                <div key={i} className="flex items-center gap-3 p-3 rounded-xl"
                  style={{ backgroundColor: C.panel }}>
                  <AlertTriangle size={12} style={{ color: sev.color, flexShrink: 0 }} />
                  <span className="text-xs" style={{ color: C.muted }}>{ioc}</span>
                  <span className="ml-auto text-xs px-2 py-0.5 rounded-full font-medium"
                    style={{ backgroundColor: sev.bg, color: sev.color }}>IOC</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right col (4) */}
        <div className="col-span-4 space-y-4">
          {/* AI Analysis */}
          <div className="rounded-2xl border overflow-hidden relative"
            style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="absolute top-0 right-0 w-28 h-28 opacity-[0.04] pointer-events-none"
              style={{ background: `radial-gradient(circle, ${C.accent}, transparent 70%)` }} />
            <div className="flex items-center gap-2 px-5 py-4 border-b" style={{ borderColor: C.border }}>
              <Brain size={13} style={{ color: C.accent }} />
              <h3 className="text-sm font-semibold text-white">AI Analysis</h3>
            </div>
            <div className="p-5 space-y-3">
              <p className="text-xs leading-relaxed" style={{ color: C.muted }}>
                This alert matches the behavioral signature of an automated {alert.type.toLowerCase()} tool
                with {alert.confidence}% confidence. The attack pattern aligns with known threat actor TTPs
                targeting internal network infrastructure.
              </p>
              <div className="flex justify-between text-xs">
                <span style={{ color: C.faint }}>Model Confidence</span>
                <span className="font-bold" style={{ color: sev.color }}>{alert.confidence}%</span>
              </div>
              <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
                <div className="h-full rounded-full" style={{ width: `${alert.confidence}%`, backgroundColor: sev.color }} />
              </div>
            </div>
          </div>

          {/* Affected device */}
          <div className="rounded-2xl border p-5" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <h3 className="text-sm font-semibold text-white mb-3">Affected Device</h3>
            <div className="space-y-2">
              {[['Hostname', alert.srcDevice], ['Source IP', alert.src], ['Destination', alert.dst], ['Protocol', alert.proto]].map(([k, v]) => (
                <div key={k} className="flex justify-between items-center py-1.5 border-b" style={{ borderColor: '#1a2744' }}>
                  <span className="text-xs" style={{ color: C.faint }}>{k}</span>
                  <span className="mono text-xs font-medium" style={{ color: C.muted }}>{v}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Recommendations */}
          <div className="rounded-2xl border p-5" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <h3 className="text-sm font-semibold text-white mb-3">Recommended Actions</h3>
            <p className="text-xs leading-relaxed" style={{ color: C.muted }}>{alert.recommendation}</p>
            <div className="mt-4 space-y-2">
              <button onClick={() => showToast(`Blocking ${alert.src}`, 'info')}
                className="w-full py-2 rounded-xl text-xs font-semibold"
                style={{ backgroundColor: `${C.danger}15`, color: C.danger }}>
                Block Source IP
              </button>
              <button onClick={() => showToast('Creating firewall rule', 'success')}
                className="w-full py-2 rounded-xl text-xs font-semibold border"
                style={{ borderColor: C.border, color: C.muted }}>
                Create Firewall Rule
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Main ─────────────────────────────────────────────────────────────────────
interface Props { showToast: (msg: string, type?: ToastMsg['type']) => void }

export default function Alerts({ showToast }: Props) {
  const [selected, setSelected] = useState<Alert | null>(null)
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [protoFilter, setProtoFilter] = useState('ALL')

  if (selected) return <AlertInvestigation alert={selected} onBack={() => setSelected(null)} showToast={showToast} />

  const counts = { critical: ALERTS.filter(a => a.sev === 'critical').length, high: ALERTS.filter(a => a.sev === 'high').length, medium: ALERTS.filter(a => a.sev === 'medium').length, low: ALERTS.filter(a => a.sev === 'low').length }

  const filtered = ALERTS.filter(a => {
    if (sevFilter !== 'ALL' && a.sev !== sevFilter) return false
    if (statusFilter !== 'ALL' && a.status !== statusFilter) return false
    if (protoFilter !== 'ALL' && a.proto !== protoFilter) return false
    if (search && !a.type.toLowerCase().includes(search.toLowerCase()) && !a.src.includes(search) && !a.srcDevice.toLowerCase().includes(search.toLowerCase()) && !a.mitreId.includes(search)) return false
    return true
  })

  return (
    <div className="space-y-4">
      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-4">
        {([['critical', C.danger], ['high', C.orange], ['medium', C.warning], ['low', C.info]] as const).map(([sev, color]) => (
          <button key={sev} onClick={() => setSevFilter(sevFilter === sev ? 'ALL' : sev)}
            className="rounded-2xl border p-4 flex items-center justify-between transition-all text-left"
            style={{ backgroundColor: sevFilter === sev ? `${color}10` : C.card, borderColor: sevFilter === sev ? `${color}40` : C.border, boxShadow: '0 4px 20px rgba(0,0,0,0.2)' }}>
            <div>
              <div className="text-2xl font-bold" style={{ color }}>{counts[sev]}</div>
              <div className="text-xs font-medium capitalize mt-0.5" style={{ color: C.muted }}>{sev} Severity</div>
            </div>
            <div className="p-2.5 rounded-xl" style={{ backgroundColor: `${color}15` }}>
              <AlertTriangle size={16} style={{ color }} />
            </div>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2">
        <div className="flex items-center gap-2 px-3 py-2 rounded-xl border flex-1"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <Search size={13} style={{ color: C.faint }} />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search alerts, IPs, MITRE ID, devices…"
            className="bg-transparent text-xs flex-1 placeholder-slate-600"
            style={{ color: C.text, outline: 'none' }} />
        </div>
        {['ALL','critical','high','medium','low'].map(s => {
          const color = s === 'ALL' ? C.faint : { critical: C.danger, high: C.orange, medium: C.warning, low: C.info }[s]!
          return (
            <button key={s} onClick={() => setSevFilter(s)}
              className="px-3 py-2 rounded-xl text-xs font-medium capitalize transition-all"
              style={{ backgroundColor: sevFilter === s ? `${color}15` : C.card, color: sevFilter === s ? color : C.faint, border: `1px solid ${sevFilter === s ? `${color}40` : C.border}` }}>
              {s}
            </button>
          )
        })}
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
          className="px-3 py-2 rounded-xl text-xs border" style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted, outline: 'none' }}>
          <option value="ALL">All Status</option>
          <option value="active">Active</option>
          <option value="investigating">Investigating</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
        </select>
        <select value={protoFilter} onChange={e => setProtoFilter(e.target.value)}
          className="px-3 py-2 rounded-xl text-xs border" style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted, outline: 'none' }}>
          <option value="ALL">All Protocols</option>
          {['TCP','UDP','DNS','SSH','ARP','HTTPS','ICMP'].map(p => <option key={p} value={p}>{p}</option>)}
        </select>
        <button onClick={() => showToast('Alerts exported', 'success')}
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl border text-xs font-medium"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
          <Download size={12}/> Export
        </button>
      </div>

      {/* Table */}
      <div className="rounded-2xl border overflow-hidden" style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: C.border }}>
          <div>
            <h2 className="text-sm font-semibold text-white">Security Alerts</h2>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>{filtered.length} events — click any row to investigate</p>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ backgroundColor: C.danger }}/>
            <span className="text-xs" style={{ color: C.faint }}>Live</span>
          </div>
        </div>
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center py-16 gap-3">
            <Shield size={28} style={{ color: C.success }}/>
            <p className="text-sm font-medium text-white">No alerts match your filter</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b" style={{ borderColor: C.border }}>
                {['Severity','Attack Type','Source','Destination','Confidence','MITRE Technique','Status','Time'].map(h => (
                  <th key={h} className="text-left px-4 py-2.5 text-xs font-medium" style={{ color: C.dim }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(a => {
                const sev  = SEV_CFG[a.sev]
                const stat = STATUS_CFG[a.status]
                return (
                  <tr key={a.id} onClick={() => setSelected(a)}
                    className="border-b transition-all duration-150 cursor-pointer"
                    style={{ borderColor: '#1a2744', borderLeft: `2px solid ${sev.color}40` }}
                    onMouseEnter={e => { e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)'; e.currentTarget.style.borderLeftColor = sev.color }}
                    onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'transparent'; e.currentTarget.style.borderLeftColor = `${sev.color}40` }}>
                    <td className="px-4 py-3.5">
                      <span className="text-xs px-2 py-0.5 rounded-full font-semibold" style={{ backgroundColor: sev.bg, color: sev.color }}>{sev.label}</span>
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="text-xs font-semibold text-white">{a.type}</div>
                      <div className="text-xs mt-0.5" style={{ color: C.faint }}>{a.proto}</div>
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="mono text-xs font-medium" style={{ color: C.accent }}>{a.src}</div>
                      <div className="text-xs mt-0.5" style={{ color: C.faint }}>{a.srcDevice}</div>
                    </td>
                    <td className="px-4 py-3.5 mono text-xs" style={{ color: C.muted }}>{a.dst}</td>
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-2">
                        <div className="w-10 h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
                          <div className="h-full rounded-full" style={{ width: `${a.confidence}%`, backgroundColor: sev.color }}/>
                        </div>
                        <span className="mono text-xs font-bold" style={{ color: sev.color }}>{a.confidence}%</span>
                      </div>
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="mono text-xs font-semibold" style={{ color: C.accent }}>{a.mitreId}</div>
                      <div className="text-xs mt-0.5" style={{ color: C.faint }}>{a.mitre}</div>
                    </td>
                    <td className="px-4 py-3.5">
                      <span className="text-xs px-2 py-0.5 rounded-full font-medium capitalize" style={{ backgroundColor: stat.bg, color: stat.color }}>{a.status}</span>
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-1.5 text-xs" style={{ color: C.faint }}>
                        <Clock size={10}/>{a.time}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
