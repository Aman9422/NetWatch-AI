import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Search, Download, RefreshCw, Pause, Play, X, Filter,
  ChevronLeft, ChevronRight, Shield, AlertTriangle, Activity, Wifi,
} from 'lucide-react'
import type { ToastMsg } from '../App'

// ─── Tokens ──────────────────────────────────────────────────────────────────
const C = {
  accent: '#38BDF8', success: '#22C55E', warning: '#F59E0B',
  danger: '#EF4444', info: '#06B6D4', purple: '#818CF8', orange: '#F97316',
  card: '#1E293B', panel: '#0F172A', border: '#334155',
  text: '#F8FAFC', muted: '#94A3B8', faint: '#64748B', dim: '#475569',
}

const PROTO_COLOR: Record<string, string> = {
  TCP: C.accent, UDP: C.info, HTTPS: C.purple, DNS: C.warning,
  ARP: C.orange, ICMP: C.muted, HTTP: C.success,
}
const PROTO_LIST = ['TCP', 'UDP', 'HTTPS', 'DNS', 'ARP', 'ICMP', 'HTTP']
const FLAGS_LIST  = ['SYN', 'ACK', 'SYN-ACK', 'PSH-ACK', 'FIN-ACK', 'RST', '—']
const SRCS = ['192.168.1.10', '192.168.1.25', '10.0.0.15', '192.168.1.100', '10.0.0.22', '172.16.0.5']
const DSTS = ['8.8.8.8', '142.250.80.46', '104.21.45.2', '192.168.1.1', '1.1.1.1', '104.26.10.23']
const RISK_CFG = {
  normal:     { color: C.success, bg: 'rgba(34,197,94,0.12)',   label: 'Normal'     },
  suspicious: { color: C.warning, bg: 'rgba(245,158,11,0.12)',  label: 'Suspicious' },
  malicious:  { color: C.danger,  bg: 'rgba(239,68,68,0.12)',   label: 'Malicious'  },
}
const rnd = <T,>(a: T[]) => a[Math.floor(Math.random() * a.length)]

// ─── Packet factory ───────────────────────────────────────────────────────────
interface Packet {
  id: number; ts: string; src: string; dst: string; proto: string
  srcPort: number; dstPort: number; size: number; flags: string
  ttl: number; risk: 'normal' | 'suspicious' | 'malicious'
  rawHex: string; seq: number; ack: number; win: number; checksum: string
}

let _id = 1
function makePacket(): Packet {
  const proto = rnd(['TCP', 'TCP', 'TCP', 'UDP', 'HTTPS', 'DNS', 'ARP', 'ICMP'])
  const risk  = Math.random() > 0.96 ? 'malicious' : Math.random() > 0.88 ? 'suspicious' : 'normal'
  const now   = new Date()
  return {
    id:       _id++,
    ts:       `${now.getHours().toString().padStart(2,'0')}:${now.getMinutes().toString().padStart(2,'0')}:${now.getSeconds().toString().padStart(2,'0')}.${now.getMilliseconds().toString().padStart(3,'0')}`,
    src:      rnd(SRCS),
    dst:      rnd(DSTS),
    proto,
    srcPort:  Math.round(1024 + Math.random() * 60000),
    dstPort:  rnd([80, 443, 53, 22, 8080, 3306, 25, 123, 8443]),
    size:     Math.round(40 + Math.random() * 1420),
    flags:    proto === 'TCP' ? rnd(FLAGS_LIST) : '—',
    ttl:      rnd([64, 128, 255]),
    risk,
    rawHex:   Array.from({ length: 64 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(' '),
    seq:      Math.floor(Math.random() * 4294967295),
    ack:      Math.floor(Math.random() * 4294967295),
    win:      rnd([8192, 16384, 32768, 65535]),
    checksum: `0x${Math.floor(Math.random() * 65535).toString(16).padStart(4, '0')}`,
  }
}

// ─── Stat card ────────────────────────────────────────────────────────────────
function StatCard({ label, value, sub, icon, accent = C.accent }: {
  label: string; value: string; sub: string; icon: React.ReactNode; accent?: string
}) {
  return (
    <div className="rounded-2xl border p-4 flex gap-3 items-center"
      style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 20px rgba(0,0,0,0.2)' }}>
      <div className="p-2.5 rounded-xl flex-shrink-0" style={{ backgroundColor: `${accent}15` }}>
        <div style={{ color: accent }}>{icon}</div>
      </div>
      <div className="min-w-0">
        <div className="text-xl font-bold text-white leading-none mb-0.5 tracking-tight">{value}</div>
        <div className="text-xs font-medium" style={{ color: C.muted }}>{label}</div>
        <div className="text-xs mt-0.5" style={{ color: C.faint }}>{sub}</div>
      </div>
    </div>
  )
}

// ─── Packet Drawer ────────────────────────────────────────────────────────────
function PacketDrawer({ packet, onClose, onPrev, onNext, hasPrev, hasNext }: {
  packet: Packet; onClose: () => void
  onPrev: () => void; onNext: () => void; hasPrev: boolean; hasNext: boolean
}) {
  const [tab, setTab] = useState<'summary' | 'headers' | 'hex' | 'risk'>('summary')

  const rows = (fields: [string, string][]) => (
    <div className="space-y-1.5">
      {fields.map(([k, v]) => (
        <div key={k} className="flex items-start justify-between gap-4 py-1.5 border-b" style={{ borderColor: '#1a2744' }}>
          <span className="text-xs flex-shrink-0" style={{ color: C.faint }}>{k}</span>
          <span className="text-xs mono font-medium text-right break-all" style={{ color: C.muted }}>{v}</span>
        </div>
      ))}
    </div>
  )

  const rc = RISK_CFG[packet.risk]
  const hexLines = Array.from({ length: 8 }, (_, row) => ({
    offset: (row * 8).toString(16).padStart(4, '0'),
    hex: packet.rawHex.split(' ').slice(row * 8, row * 8 + 8).join(' ').padEnd(23, ' '),
    ascii: packet.rawHex.split(' ').slice(row * 8, row * 8 + 8)
      .map(b => { const n = parseInt(b, 16); return n >= 32 && n < 127 ? String.fromCharCode(n) : '.' }).join(''),
  }))

  return (
    <div className="w-96 flex-shrink-0 flex flex-col rounded-2xl border overflow-hidden fade-in-up"
      style={{ backgroundColor: C.card, borderColor: C.border }}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3.5 border-b" style={{ borderColor: C.border }}>
        <div>
          <div className="text-sm font-semibold text-white">Packet #{packet.id}</div>
          <div className="mono text-xs mt-0.5" style={{ color: C.faint }}>{packet.ts}</div>
        </div>
        <div className="flex items-center gap-1">
          <button onClick={onPrev} disabled={!hasPrev}
            className="p-1.5 rounded-lg transition-colors disabled:opacity-30"
            style={{ color: C.muted }} onMouseEnter={e => !hasPrev || ((e.currentTarget as HTMLElement).style.backgroundColor = 'rgba(255,255,255,0.06)')}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.backgroundColor = 'transparent'}>
            <ChevronLeft size={15} />
          </button>
          <button onClick={onNext} disabled={!hasNext}
            className="p-1.5 rounded-lg transition-colors disabled:opacity-30"
            style={{ color: C.muted }} onMouseEnter={e => !hasNext || ((e.currentTarget as HTMLElement).style.backgroundColor = 'rgba(255,255,255,0.06)')}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.backgroundColor = 'transparent'}>
            <ChevronRight size={15} />
          </button>
          <button onClick={onClose} className="p-1.5 rounded-lg ml-1"
            style={{ color: C.faint }} onMouseEnter={e => (e.currentTarget as HTMLElement).style.backgroundColor = 'rgba(255,255,255,0.06)'}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.backgroundColor = 'transparent'}>
            <X size={15} />
          </button>
        </div>
      </div>

      {/* Risk badge */}
      <div className="px-4 py-2.5 border-b flex items-center gap-2" style={{ borderColor: C.border }}>
        <span className="text-xs px-2 py-0.5 rounded-full font-semibold" style={{ backgroundColor: rc.bg, color: rc.color }}>
          {rc.label}
        </span>
        <span className="text-xs px-2 py-0.5 rounded mono" style={{ backgroundColor: `${PROTO_COLOR[packet.proto] ?? C.dim}15`, color: PROTO_COLOR[packet.proto] ?? C.muted }}>
          {packet.proto}
        </span>
        <span className="text-xs ml-auto" style={{ color: C.faint }}>{packet.size} bytes</span>
      </div>

      {/* Tabs */}
      <div className="flex border-b" style={{ borderColor: C.border }}>
        {(['summary', 'headers', 'hex', 'risk'] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className="flex-1 py-2.5 text-xs font-medium capitalize transition-colors"
            style={{ color: tab === t ? C.accent : C.faint, borderBottom: tab === t ? `2px solid ${C.accent}` : '2px solid transparent' }}>
            {t === 'risk' ? 'Risk' : t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4">
        {tab === 'summary' && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-2">
              {[
                { label: 'Source IP',    val: packet.src,                 color: C.accent  },
                { label: 'Destination',  val: packet.dst,                 color: C.muted   },
                { label: 'Src Port',     val: String(packet.srcPort),     color: C.text    },
                { label: 'Dst Port',     val: String(packet.dstPort),     color: C.text    },
                { label: 'Flags',        val: packet.flags,               color: C.muted   },
                { label: 'TTL',          val: String(packet.ttl),         color: C.muted   },
              ].map(f => (
                <div key={f.label} className="p-2.5 rounded-xl" style={{ backgroundColor: C.panel }}>
                  <div className="text-xs mb-1" style={{ color: C.faint }}>{f.label}</div>
                  <div className="mono text-xs font-semibold" style={{ color: f.color }}>{f.val}</div>
                </div>
              ))}
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-widest mb-2" style={{ color: C.dim }}>AI Explanation</p>
              <p className="text-xs leading-relaxed" style={{ color: C.muted }}>
                {packet.risk === 'malicious'
                  ? `This ${packet.proto} packet shows indicators of malicious activity. The source port ${packet.srcPort} is commonly associated with scanning behavior. Immediate investigation recommended.`
                  : packet.risk === 'suspicious'
                  ? `Unusual ${packet.proto} traffic pattern detected from ${packet.src}. Flag combination and destination may indicate probing or reconnaissance.`
                  : `Standard ${packet.proto} packet. Traffic appears normal. No anomalies detected in header fields or payload structure.`}
              </p>
            </div>
          </div>
        )}

        {tab === 'headers' && (
          <div className="space-y-4">
            <div>
              <p className="text-xs font-semibold mb-2" style={{ color: C.accent }}>Ethernet Frame</p>
              {rows([['Src MAC', 'aa:bb:cc:dd:ee:ff'], ['Dst MAC', '00:11:22:33:44:55'], ['EtherType', '0x0800 (IPv4)']])}
            </div>
            <div>
              <p className="text-xs font-semibold mb-2" style={{ color: C.accent }}>IPv4 Header</p>
              {rows([
                ['Version', '4'],
                ['IHL', '20 bytes'],
                ['DSCP/ECN', '0x00'],
                ['Total Length', `${packet.size}`],
                ['TTL', String(packet.ttl)],
                ['Protocol', packet.proto],
                ['Src IP', packet.src],
                ['Dst IP', packet.dst],
                ['Checksum', packet.checksum],
              ])}
            </div>
            {(packet.proto === 'TCP' || packet.proto === 'HTTPS') && (
              <div>
                <p className="text-xs font-semibold mb-2" style={{ color: C.accent }}>TCP Header</p>
                {rows([
                  ['Src Port', String(packet.srcPort)],
                  ['Dst Port', String(packet.dstPort)],
                  ['Seq #', String(packet.seq)],
                  ['Ack #', String(packet.ack)],
                  ['Flags', packet.flags],
                  ['Window', String(packet.win)],
                  ['Checksum', packet.checksum],
                ])}
              </div>
            )}
            {packet.proto === 'UDP' && (
              <div>
                <p className="text-xs font-semibold mb-2" style={{ color: C.accent }}>UDP Header</p>
                {rows([
                  ['Src Port', String(packet.srcPort)],
                  ['Dst Port', String(packet.dstPort)],
                  ['Length', String(packet.size)],
                  ['Checksum', packet.checksum],
                ])}
              </div>
            )}
          </div>
        )}

        {tab === 'hex' && (
          <div>
            <div className="p-3 rounded-xl text-xs mono overflow-x-auto" style={{ backgroundColor: C.panel }}>
              <div className="flex gap-4 mb-2 border-b pb-1" style={{ borderColor: C.border, color: C.dim }}>
                <span className="w-10">Offset</span>
                <span className="flex-1">Hex</span>
                <span>ASCII</span>
              </div>
              {hexLines.map(line => (
                <div key={line.offset} className="flex gap-4 py-0.5" style={{ color: C.muted }}>
                  <span className="w-10" style={{ color: C.dim }}>{line.offset}</span>
                  <span className="flex-1" style={{ color: C.accent }}>{line.hex}</span>
                  <span style={{ color: C.success }}>{line.ascii}</span>
                </div>
              ))}
            </div>
            <p className="text-xs mt-3" style={{ color: C.faint }}>Showing first 64 bytes of payload</p>
          </div>
        )}

        {tab === 'risk' && (
          <div className="space-y-4">
            <div className="p-4 rounded-xl border" style={{ backgroundColor: `${rc.color}08`, borderColor: `${rc.color}25` }}>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold" style={{ color: rc.color }}>Risk Assessment</span>
                <span className="text-xs px-2 py-0.5 rounded-full font-semibold" style={{ backgroundColor: rc.bg, color: rc.color }}>{rc.label}</span>
              </div>
              <div className="space-y-2">
                {[
                  { label: 'Anomaly Score', val: packet.risk === 'malicious' ? 94 : packet.risk === 'suspicious' ? 62 : 8 },
                  { label: 'Confidence',    val: packet.risk === 'malicious' ? 91 : packet.risk === 'suspicious' ? 74 : 96 },
                ].map(s => (
                  <div key={s.label}>
                    <div className="flex justify-between text-xs mb-1">
                      <span style={{ color: C.faint }}>{s.label}</span>
                      <span className="font-semibold" style={{ color: rc.color }}>{s.val}%</span>
                    </div>
                    <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: C.panel }}>
                      <div className="h-full rounded-full" style={{ width: `${s.val}%`, backgroundColor: rc.color }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-widest mb-2" style={{ color: C.dim }}>IOCs Detected</p>
              {packet.risk !== 'normal' ? (
                <div className="space-y-1.5">
                  {[`Port ${packet.srcPort} scanning pattern`, `${packet.src} in watchlist`, 'Unusual flag combination'].slice(0, packet.risk === 'malicious' ? 3 : 1).map(ioc => (
                    <div key={ioc} className="flex items-center gap-2 text-xs p-2 rounded-lg" style={{ backgroundColor: C.panel }}>
                      <AlertTriangle size={10} style={{ color: C.danger, flexShrink: 0 }} />
                      <span style={{ color: C.muted }}>{ioc}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs" style={{ color: C.faint }}>No indicators of compromise detected.</p>
              )}
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-widest mb-2" style={{ color: C.dim }}>Recommended Action</p>
              <p className="text-xs leading-relaxed" style={{ color: C.muted }}>
                {packet.risk === 'malicious'
                  ? 'Block source IP immediately and escalate to Tier 2 analyst. Preserve packet capture for forensics.'
                  : packet.risk === 'suspicious'
                  ? 'Monitor source IP for 15 minutes. Flag for further investigation if pattern continues.'
                  : 'No action required. Traffic matches expected behavior profile.'}
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="px-4 py-3 border-t flex gap-2" style={{ borderColor: C.border }}>
        <button className="flex-1 py-2 rounded-xl text-xs font-semibold"
          style={{ backgroundColor: `${C.accent}15`, color: C.accent }}>
          Export Packet
        </button>
        {packet.risk !== 'normal' && (
          <button className="flex-1 py-2 rounded-xl text-xs font-semibold"
            style={{ backgroundColor: `${C.danger}15`, color: C.danger }}>
            Block IP
          </button>
        )}
      </div>
    </div>
  )
}

// ─── Main ─────────────────────────────────────────────────────────────────────
interface Props { showToast: (msg: string, type?: ToastMsg['type']) => void }

export default function LiveTraffic({ showToast }: Props) {
  const [packets, setPackets] = useState<Packet[]>(() => Array.from({ length: 50 }, makePacket))
  const [running, setRunning]       = useState(true)
  const [selected, setSelected]     = useState<Packet | null>(null)
  const [search, setSearch]         = useState('')
  const [protoFilter, setProtoFilter] = useState('ALL')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [ipFilter, setIpFilter]     = useState('')
  const [portFilter, setPortFilter] = useState('')
  const [showFilters, setShowFilters] = useState(false)
  const [pps, setPps]               = useState(952)
  const [bw, setBw]                 = useState(34.2)
  const total                       = useRef(packets.length)

  const addPacket = useCallback(() => {
    const p = makePacket()
    total.current++
    setPackets(prev => [p, ...prev.slice(0, 299)])
    setPps(Math.round(880 + Math.random() * 160))
    setBw(parseFloat((28 + Math.random() * 12).toFixed(1)))
  }, [])

  useEffect(() => {
    if (!running) return
    const id = setInterval(addPacket, 350)
    return () => clearInterval(id)
  }, [running, addPacket])

  const filtered = packets.filter(p => {
    if (protoFilter !== 'ALL' && p.proto !== protoFilter) return false
    if (severityFilter !== 'ALL' && p.risk !== severityFilter.toLowerCase()) return false
    if (ipFilter && !p.src.includes(ipFilter) && !p.dst.includes(ipFilter)) return false
    if (portFilter && String(p.srcPort) !== portFilter && String(p.dstPort) !== portFilter) return false
    if (search && !p.src.includes(search) && !p.dst.includes(search) && !p.proto.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  const selIdx   = selected ? filtered.findIndex(p => p.id === selected.id) : -1
  const hasPrev  = selIdx > 0
  const hasNext  = selIdx >= 0 && selIdx < filtered.length - 1

  const selectPacket = (p: Packet) => setSelected(p)
  const goPrev = () => selIdx > 0 && setSelected(filtered[selIdx - 1])
  const goNext = () => selIdx >= 0 && selIdx < filtered.length - 1 && setSelected(filtered[selIdx + 1])

  const selectStyle = { backgroundColor: '#334155' }
  const inputBase = { backgroundColor: C.panel, borderColor: C.border, color: C.text, outline: 'none' } as const

  return (
    <div className="flex flex-col gap-4" style={{ height: 'calc(100vh - 72px - 48px)' }}>

      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-4 flex-shrink-0">
        <StatCard label="Packets / sec"  value={pps.toLocaleString()} sub="eth0 · live"     icon={<Activity size={16}/>} />
        <StatCard label="Bandwidth"      value={`${bw} Mbps`}         sub="Current throughput" icon={<Wifi size={16}/>}     accent={C.info} />
        <StatCard label="Capture Status" value={running ? 'Active' : 'Paused'} sub={`Interface eth0`}
          icon={<div className={`w-2 h-2 rounded-full ${running ? 'animate-pulse' : ''}`} style={{ backgroundColor: running ? C.success : C.warning }} />}
          accent={running ? C.success : C.warning} />
        <StatCard label="Packets Captured" value={total.current.toLocaleString()} sub="Since session start" icon={<Shield size={16}/>} accent={C.purple} />
      </div>

      {/* Filter bar */}
      <div className="flex-shrink-0 space-y-2">
        <div className="flex items-center gap-2">
          {/* Search */}
          <div className="flex items-center gap-2 px-3 py-2 rounded-xl border flex-1"
            style={{ backgroundColor: C.card, borderColor: C.border }}>
            <Search size={13} style={{ color: C.faint, flexShrink: 0 }} />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search source IP, destination, protocol…"
              className="bg-transparent text-xs flex-1 placeholder-slate-600"
              style={{ color: C.text, outline: 'none' }} />
          </div>

          {/* Protocol tabs */}
          <div className="flex items-center gap-0.5 p-1 rounded-xl" style={{ backgroundColor: C.card }}>
            {['ALL', ...PROTO_LIST.slice(0, 5)].map(p => (
              <button key={p} onClick={() => setProtoFilter(p)}
                className="px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all"
                style={{ backgroundColor: protoFilter === p ? C.accent : 'transparent', color: protoFilter === p ? '#0F172A' : C.faint }}>
                {p}
              </button>
            ))}
          </div>

          {/* Advanced filters toggle */}
          <button onClick={() => setShowFilters(f => !f)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl border text-xs font-medium"
            style={{ borderColor: showFilters ? C.accent : C.border, color: showFilters ? C.accent : C.muted, backgroundColor: showFilters ? `${C.accent}10` : C.card }}>
            <Filter size={12} /> Filters
          </button>

          {/* Export */}
          <button onClick={() => showToast('Packets exported as PCAP', 'success')}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl border text-xs font-medium"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
            <Download size={12} /> Export
          </button>

          {/* Clear */}
          <button onClick={() => { setPackets([]); showToast('Capture buffer cleared', 'info') }}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl border text-xs font-medium"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
            <RefreshCw size={12} /> Clear
          </button>

          {/* Pause / Resume */}
          <button onClick={() => { setRunning(r => !r); showToast(running ? 'Capture paused' : 'Capture resumed', 'info') }}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold"
            style={{ backgroundColor: running ? 'rgba(239,68,68,0.15)' : 'rgba(34,197,94,0.15)', color: running ? C.danger : C.success }}>
            {running ? <><Pause size={12}/> Pause</> : <><Play size={12}/> Resume</>}
          </button>
        </div>

        {/* Advanced filters row */}
        {showFilters && (
          <div className="flex items-center gap-2 p-3 rounded-xl border fade-in-up"
            style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="flex items-center gap-1.5">
              <span className="text-xs" style={{ color: C.faint }}>IP</span>
              <input value={ipFilter} onChange={e => setIpFilter(e.target.value)}
                placeholder="Filter by IP…" className="px-2.5 py-1.5 rounded-lg border text-xs mono"
                style={{ ...inputBase, borderColor: C.border, width: 140 }} />
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-xs" style={{ color: C.faint }}>Port</span>
              <input value={portFilter} onChange={e => setPortFilter(e.target.value)}
                placeholder="Port…" className="px-2.5 py-1.5 rounded-lg border text-xs mono"
                style={{ ...inputBase, borderColor: C.border, width: 80 }} />
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-xs" style={{ color: C.faint }}>Status</span>
              <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg border text-xs"
                style={{ ...inputBase, borderColor: C.border }}>
                <option value="ALL">All</option>
                <option value="MALICIOUS">Malicious</option>
                <option value="SUSPICIOUS">Suspicious</option>
                <option value="NORMAL">Normal</option>
              </select>
            </div>
            <div className="flex items-center gap-1.5 ml-auto">
              <span className="text-xs" style={{ color: C.faint }}>Time range</span>
              <select className="px-2.5 py-1.5 rounded-lg border text-xs"
                style={{ ...inputBase, borderColor: C.border }}>
                <option>Live</option><option>Last 1 min</option><option>Last 5 min</option><option>Last 15 min</option>
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Table + drawer */}
      <div className="flex gap-4 flex-1 min-h-0">
        <div className="flex flex-col flex-1 min-w-0 rounded-2xl border overflow-hidden"
          style={{ backgroundColor: C.card, borderColor: C.border }}>

          {/* Table header */}
          <div className="grid text-xs font-medium px-4 py-2.5 border-b flex-shrink-0"
            style={{ borderColor: C.border, color: C.dim,
              gridTemplateColumns: '120px 120px 120px 70px 70px 70px 70px 80px 50px 90px' }}>
            <span>Timestamp</span><span>Source IP</span><span>Destination</span>
            <span>Protocol</span><span>Src Port</span><span>Dst Port</span>
            <span>Size</span><span>Flags</span><span>TTL</span><span>Status</span>
          </div>

          {/* Rows */}
          <div className="flex-1 overflow-y-auto">
            {filtered.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full gap-3">
                <Shield size={32} style={{ color: C.border }} />
                <p className="text-sm font-medium" style={{ color: C.dim }}>No packets match your filter</p>
                <p className="text-xs" style={{ color: C.faint }}>Try adjusting the search or filter criteria</p>
              </div>
            )}
            {filtered.map(p => {
              const rc = RISK_CFG[p.risk]
              const sel = selected?.id === p.id
              return (
                <div key={p.id} onClick={() => selectPacket(p)}
                  className="grid items-center px-4 py-2 cursor-pointer border-b transition-colors"
                  style={{
                    gridTemplateColumns: '120px 120px 120px 70px 70px 70px 70px 80px 50px 90px',
                    borderColor: '#1a2744',
                    backgroundColor: sel ? 'rgba(56,189,248,0.07)' : 'transparent',
                    borderLeft: p.risk === 'malicious' ? `2px solid ${C.danger}` : p.risk === 'suspicious' ? `2px solid ${C.warning}` : '2px solid transparent',
                  }}
                  onMouseEnter={e => { if (!sel) e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)' }}
                  onMouseLeave={e => { if (!sel) e.currentTarget.style.backgroundColor = 'transparent' }}
                >
                  <span className="mono text-xs" style={{ color: C.faint }}>{p.ts}</span>
                  <span className="mono text-xs font-medium" style={{ color: C.accent }}>{p.src}</span>
                  <span className="mono text-xs" style={{ color: C.muted }}>{p.dst}</span>
                  <span>
                    <span className="text-xs px-1.5 py-0.5 rounded font-medium"
                      style={{ backgroundColor: `${PROTO_COLOR[p.proto] ?? C.dim}15`, color: PROTO_COLOR[p.proto] ?? C.muted }}>
                      {p.proto}
                    </span>
                  </span>
                  <span className="mono text-xs" style={{ color: C.muted }}>{p.srcPort}</span>
                  <span className="mono text-xs" style={{ color: C.muted }}>{p.dstPort}</span>
                  <span className="mono text-xs" style={{ color: C.muted }}>{p.size}B</span>
                  <span className="mono text-xs" style={{ color: p.flags !== '—' ? C.text : C.dim }}>{p.flags}</span>
                  <span className="mono text-xs" style={{ color: C.dim }}>{p.ttl}</span>
                  <span>
                    <span className="text-xs px-1.5 py-0.5 rounded-full font-medium"
                      style={{ backgroundColor: rc.bg, color: rc.color }}>{rc.label}</span>
                  </span>
                </div>
              )
            })}
          </div>

          {/* Status bar */}
          <div className="flex items-center gap-4 px-4 py-2.5 border-t flex-shrink-0"
            style={{ borderColor: C.border, backgroundColor: C.panel }}>
            <span className="mono text-xs" style={{ color: C.dim }}>{filtered.length.toLocaleString()} packets</span>
            <span style={{ color: C.border }}>|</span>
            <span className="mono text-xs" style={{ color: running ? C.success : C.warning }}>
              {running ? '● Capturing' : '■ Paused'}
            </span>
            <span style={{ color: C.border }}>|</span>
            <span className="mono text-xs" style={{ color: C.dim }}>
              {packets.filter(p => p.risk === 'malicious').length} malicious · {packets.filter(p => p.risk === 'suspicious').length} suspicious
            </span>
          </div>
        </div>

        {/* Packet Drawer */}
        {selected && (
          <PacketDrawer
            packet={selected}
            onClose={() => setSelected(null)}
            onPrev={goPrev}
            onNext={goNext}
            hasPrev={hasPrev}
            hasNext={hasNext}
          />
        )}
      </div>
    </div>
  )
}
