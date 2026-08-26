import { useState } from 'react'
import {
  Settings as Cog, Wifi, Activity, Shield, Bell, Brain, Database,
  HardDrive, Palette, Info, Save, RotateCcw, ChevronRight,
  CheckCircle, ToggleLeft, ToggleRight,
} from 'lucide-react'
import type { ToastMsg } from '../App'

const C = {
  accent: '#38BDF8', success: '#22C55E', warning: '#F59E0B',
  danger: '#EF4444', info: '#06B6D4', purple: '#818CF8',
  card: '#1E293B', panel: '#0F172A', border: '#334155',
  text: '#F8FAFC', muted: '#94A3B8', faint: '#64748B', dim: '#475569',
}

type SettingSection =
  | 'general' | 'network' | 'capture' | 'detection' | 'thresholds'
  | 'ai' | 'database' | 'backup' | 'theme' | 'notifications' | 'system'

const SECTIONS: { id: SettingSection; label: string; icon: React.ElementType; desc: string }[] = [
  { id: 'general',       label: 'General',           icon: Cog,        desc: 'System name, timezone, logging' },
  { id: 'network',       label: 'Network Interface',  icon: Wifi,       desc: 'Capture interface configuration' },
  { id: 'capture',       label: 'Capture Engine',     icon: Activity,   desc: 'Buffer size, filters, performance' },
  { id: 'detection',     label: 'Detection Rules',    icon: Shield,     desc: 'IDS rules, custom signatures' },
  { id: 'thresholds',    label: 'Alert Thresholds',   icon: Bell,       desc: 'Severity triggers and limits' },
  { id: 'ai',            label: 'AI Settings',        icon: Brain,      desc: 'Model, confidence, auto-actions' },
  { id: 'database',      label: 'Database',           icon: Database,   desc: 'Connection, retention, indexing' },
  { id: 'backup',        label: 'Backup & Restore',   icon: HardDrive,  desc: 'Schedule, export, recovery' },
  { id: 'theme',         label: 'Theme',              icon: Palette,    desc: 'Color scheme, density, layout' },
  { id: 'notifications', label: 'Notifications',      icon: Bell,       desc: 'Email, Slack, webhook alerts' },
  { id: 'system',        label: 'System Information', icon: Info,       desc: 'Version, license, diagnostics' },
]

// ─── Reusable field components ─────────────────────────────────────────────────
function FieldGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-2xl border overflow-hidden" style={{ backgroundColor: C.card, borderColor: C.border }}>
      <div className="px-6 py-4 border-b" style={{ borderColor: C.border }}>
        <h3 className="text-sm font-semibold text-white">{title}</h3>
      </div>
      <div className="p-6 space-y-5">{children}</div>
    </div>
  )
}

function Field({ label, sub, children }: { label: string; sub?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-8">
      <div className="flex-shrink-0 w-56">
        <div className="text-sm font-medium text-white">{label}</div>
        {sub && <div className="text-xs mt-0.5" style={{ color: C.faint }}>{sub}</div>}
      </div>
      <div className="flex-1 min-w-0">{children}</div>
    </div>
  )
}

function Input({ value, onChange, placeholder, type = 'text' }: { value: string; onChange: (v: string) => void; placeholder?: string; type?: string }) {
  return (
    <input type={type} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
      className="w-full px-3 py-2 rounded-xl text-sm border"
      style={{ backgroundColor: C.panel, borderColor: C.border, color: C.text, outline: 'none' }} />
  )
}

function Select({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: string[] }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)}
      className="w-full px-3 py-2 rounded-xl text-sm border"
      style={{ backgroundColor: C.panel, borderColor: C.border, color: C.text, outline: 'none' }}>
      {options.map(o => <option key={o} value={o}>{o}</option>)}
    </select>
  )
}

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label?: string }) {
  return (
    <div className="flex items-center gap-3">
      <button onClick={() => onChange(!checked)} className="flex-shrink-0 transition-all"
        style={{ color: checked ? C.accent : C.dim }}>
        {checked ? <ToggleRight size={26}/> : <ToggleLeft size={26}/>}
      </button>
      {label && <span className="text-sm" style={{ color: C.muted }}>{label}</span>}
    </div>
  )
}

function Slider({ value, onChange, min = 0, max = 100, unit = '' }: { value: number; onChange: (v: number) => void; min?: number; max?: number; unit?: string }) {
  return (
    <div className="flex items-center gap-3">
      <input type="range" min={min} max={max} value={value} onChange={e => onChange(Number(e.target.value))}
        className="flex-1" style={{ accentColor: C.accent }} />
      <span className="mono text-sm font-semibold w-20 text-right" style={{ color: C.accent }}>{value}{unit}</span>
    </div>
  )
}

// ─── Section panels ───────────────────────────────────────────────────────────
function GeneralPanel() {
  const [name, setName] = useState('NetWatch-Prod-01')
  const [tz, setTz]     = useState('UTC+00:00')
  const [logLevel, setLogLevel] = useState('INFO')
  const [retainDays, setRetainDays] = useState(90)
  const [autoUpdate, setAutoUpdate] = useState(true)

  return (
    <div className="space-y-4">
      <FieldGroup title="Identity">
        <Field label="Sensor Name" sub="Unique identifier for this instance">
          <Input value={name} onChange={setName} />
        </Field>
        <Field label="Timezone" sub="Used for timestamps and reports">
          <Select value={tz} onChange={setTz} options={['UTC+00:00','UTC+01:00','UTC+02:00','UTC-05:00','UTC-08:00']} />
        </Field>
      </FieldGroup>
      <FieldGroup title="Logging">
        <Field label="Log Level" sub="Verbosity of system logs">
          <Select value={logLevel} onChange={setLogLevel} options={['DEBUG','INFO','WARNING','ERROR']} />
        </Field>
        <Field label="Retention Period" sub="Days to keep packet data on disk">
          <Slider value={retainDays} onChange={setRetainDays} min={7} max={365} unit=" days" />
        </Field>
        <Field label="Auto-Update" sub="Automatically apply minor version updates">
          <Toggle checked={autoUpdate} onChange={setAutoUpdate} label={autoUpdate ? 'Enabled' : 'Disabled'} />
        </Field>
      </FieldGroup>
    </div>
  )
}

function NetworkPanel() {
  const [iface, setIface] = useState('eth0')
  const [mode, setMode] = useState('Promiscuous')
  const [mtu, setMtu]   = useState('1500')
  const [vlan, setVlan] = useState(false)

  return (
    <div className="space-y-4">
      <FieldGroup title="Interface Configuration">
        <Field label="Capture Interface" sub="Network adapter to monitor">
          <Select value={iface} onChange={setIface} options={['eth0','eth1','ens3','bond0','lo']} />
        </Field>
        <Field label="Capture Mode" sub="How packets are captured from the wire">
          <Select value={mode} onChange={setMode} options={['Promiscuous','Tap','Mirror Port','Inline']} />
        </Field>
        <Field label="MTU Size" sub="Maximum Transmission Unit in bytes">
          <Input value={mtu} onChange={setMtu} placeholder="1500" />
        </Field>
        <Field label="VLAN Decapsulation" sub="Strip 802.1Q VLAN tags from packets">
          <Toggle checked={vlan} onChange={setVlan} label={vlan ? 'Enabled' : 'Disabled'} />
        </Field>
      </FieldGroup>
    </div>
  )
}

function CapturePanel() {
  const [bufMB, setBufMB] = useState(512)
  const [maxPkt, setMaxPkt] = useState(65535)
  const [snaplen, setSnaplen] = useState(1518)
  const [bpf, setBpf] = useState('not port 22')
  const [ringBuffer, setRingBuffer] = useState(true)

  return (
    <div className="space-y-4">
      <FieldGroup title="Engine Parameters">
        <Field label="Ring Buffer Size" sub="MB allocated for capture ring buffer">
          <Slider value={bufMB} onChange={setBufMB} min={64} max={4096} unit=" MB" />
        </Field>
        <Field label="Max Packet Size" sub="Maximum bytes captured per packet">
          <Slider value={snaplen} onChange={setSnaplen} min={64} max={65535} unit=" B" />
        </Field>
        <Field label="BPF Filter" sub="Berkeley Packet Filter expression">
          <Input value={bpf} onChange={setBpf} placeholder="e.g. not port 22" />
        </Field>
        <Field label="Ring Buffer Mode" sub="Overwrite oldest packets when buffer full">
          <Toggle checked={ringBuffer} onChange={setRingBuffer} label={ringBuffer ? 'Enabled' : 'Disabled'} />
        </Field>
      </FieldGroup>
    </div>
  )
}

function DetectionPanel() {
  const [ruleSet, setRuleSet] = useState('Snort Community')
  const [autoFetch, setAutoFetch] = useState(true)
  const [interval, setInterval] = useState('24')
  const [customRules, setCustomRules] = useState('alert tcp any any -> any 4444 (msg:"Suspicious port 4444"; sid:9000001; rev:1;)')

  return (
    <div className="space-y-4">
      <FieldGroup title="Rule Management">
        <Field label="Rule Set" sub="Base detection rule database">
          <Select value={ruleSet} onChange={setRuleSet} options={['Snort Community','Snort Registered','Emerging Threats','Custom Only']} />
        </Field>
        <Field label="Auto-Update Rules" sub="Fetch new signatures automatically">
          <Toggle checked={autoFetch} onChange={setAutoFetch} label={autoFetch ? 'Enabled' : 'Disabled'} />
        </Field>
        <Field label="Update Interval" sub="Hours between rule update checks">
          <Select value={interval} onChange={setInterval} options={['1','6','12','24','48','168']} />
        </Field>
      </FieldGroup>
      <FieldGroup title="Custom Signatures">
        <Field label="Custom Rules" sub="Snort rule syntax, one rule per line">
          <textarea rows={5} value={customRules} onChange={e => setCustomRules(e.target.value)}
            className="w-full px-3 py-2 rounded-xl text-xs border mono resize-none"
            style={{ backgroundColor: C.panel, borderColor: C.border, color: C.accent, outline: 'none' }} />
        </Field>
      </FieldGroup>
    </div>
  )
}

function ThresholdsPanel() {
  const [critScore, setCritScore]   = useState(80)
  const [highScore, setHighScore]   = useState(60)
  const [medScore, setMedScore]     = useState(35)
  const [scanRate, setScanRate]     = useState(100)
  const [connRate, setConnRate]     = useState(1000)
  const [dnsRate, setDnsRate]       = useState(60)

  return (
    <div className="space-y-4">
      <FieldGroup title="Severity Score Thresholds">
        <Field label="Critical Threshold" sub="Min threat score to trigger critical alert">
          <Slider value={critScore} onChange={setCritScore} min={50} max={100} />
        </Field>
        <Field label="High Threshold" sub="Min threat score to trigger high alert">
          <Slider value={highScore} onChange={setHighScore} min={30} max={90} />
        </Field>
        <Field label="Medium Threshold" sub="Min threat score for medium severity">
          <Slider value={medScore} onChange={setMedScore} min={10} max={60} />
        </Field>
      </FieldGroup>
      <FieldGroup title="Rate-based Triggers">
        <Field label="Port Scan Rate" sub="SYN packets/min to flag as port scan">
          <Slider value={scanRate} onChange={setScanRate} min={10} max={1000} unit="/min" />
        </Field>
        <Field label="Connection Rate" sub="New connections/min per host threshold">
          <Slider value={connRate} onChange={setConnRate} min={100} max={10000} unit="/min" />
        </Field>
        <Field label="DNS Query Rate" sub="DNS queries/min before anomaly flag">
          <Slider value={dnsRate} onChange={setDnsRate} min={10} max={500} unit="/min" />
        </Field>
      </FieldGroup>
    </div>
  )
}

function AIPanel() {
  const [model, setModel] = useState('NetWatch-7B-v2')
  const [confidence, setConfidence] = useState(70)
  const [autoBlock, setAutoBlock] = useState(false)
  const [autoAck, setAutoAck] = useState(true)
  const [explain, setExplain] = useState(true)

  return (
    <div className="space-y-4">
      <FieldGroup title="Model Configuration">
        <Field label="Detection Model" sub="Neural network used for anomaly detection">
          <Select value={model} onChange={setModel} options={['NetWatch-7B-v2','NetWatch-3B-v1','Custom ONNX']} />
        </Field>
        <Field label="Confidence Threshold" sub="Min confidence to surface AI alerts (%)">
          <Slider value={confidence} onChange={setConfidence} unit="%" />
        </Field>
      </FieldGroup>
      <FieldGroup title="Automated Actions">
        <Field label="Auto-Block on Critical" sub="Automatically block IPs on critical AI alerts">
          <Toggle checked={autoBlock} onChange={setAutoBlock} label={autoBlock ? 'Enabled — use with caution' : 'Disabled'} />
        </Field>
        <Field label="Auto-Acknowledge Low" sub="Automatically acknowledge low severity findings">
          <Toggle checked={autoAck} onChange={setAutoAck} label={autoAck ? 'Enabled' : 'Disabled'} />
        </Field>
        <Field label="Explainability" sub="Show AI reasoning alongside each detection">
          <Toggle checked={explain} onChange={setExplain} label={explain ? 'Enabled' : 'Disabled'} />
        </Field>
      </FieldGroup>
    </div>
  )
}

function DatabasePanel() {
  const [host, setHost]   = useState('localhost')
  const [port, setPort]   = useState('5432')
  const [db, setDb]       = useState('netwatch')
  const [maxConn, setMaxConn] = useState(50)
  const [compress, setCompress] = useState(true)

  return (
    <div className="space-y-4">
      <FieldGroup title="Connection">
        <Field label="Host" sub="PostgreSQL server hostname or IP"><Input value={host} onChange={setHost} /></Field>
        <Field label="Port" sub="Database port number"><Input value={port} onChange={setPort} /></Field>
        <Field label="Database Name"><Input value={db} onChange={setDb} /></Field>
      </FieldGroup>
      <FieldGroup title="Performance">
        <Field label="Max Connections" sub="Connection pool size">
          <Slider value={maxConn} onChange={setMaxConn} min={5} max={200} />
        </Field>
        <Field label="Compress Old Data" sub="LZ4 compress packet data older than 7 days">
          <Toggle checked={compress} onChange={setCompress} label={compress ? 'Enabled' : 'Disabled'} />
        </Field>
      </FieldGroup>
    </div>
  )
}

function BackupPanel() {
  const [enabled, setEnabled] = useState(true)
  const [freq, setFreq]       = useState('Daily')
  const [dest, setDest]       = useState('/var/backups/netwatch')
  const [encrypt, setEncrypt] = useState(true)

  return (
    <div className="space-y-4">
      <FieldGroup title="Backup Configuration">
        <Field label="Automated Backups">
          <Toggle checked={enabled} onChange={setEnabled} label={enabled ? 'Enabled' : 'Disabled'} />
        </Field>
        <Field label="Frequency" sub="How often backups run">
          <Select value={freq} onChange={setFreq} options={['Hourly','Daily','Weekly','Monthly']} />
        </Field>
        <Field label="Destination Path" sub="Local filesystem path for backups">
          <Input value={dest} onChange={setDest} />
        </Field>
        <Field label="Encrypt Backups" sub="AES-256 encryption for backup archives">
          <Toggle checked={encrypt} onChange={setEncrypt} label={encrypt ? 'Enabled' : 'Disabled'} />
        </Field>
      </FieldGroup>
    </div>
  )
}

function ThemePanel() {
  const [density, setDensity] = useState('Comfortable')
  const [sidebar, setSidebar] = useState('Expanded')
  const [monoBold, setMonoBold] = useState(true)

  return (
    <div className="space-y-4">
      <FieldGroup title="Display">
        <Field label="UI Density" sub="Padding and spacing between elements">
          <Select value={density} onChange={setDensity} options={['Compact','Comfortable','Spacious']} />
        </Field>
        <Field label="Sidebar" sub="Default sidebar state on load">
          <Select value={sidebar} onChange={setSidebar} options={['Expanded','Collapsed','Auto']} />
        </Field>
        <Field label="Bold Monospace" sub="Use bold weight for IP addresses and hex data">
          <Toggle checked={monoBold} onChange={setMonoBold} label={monoBold ? 'Enabled' : 'Disabled'} />
        </Field>
      </FieldGroup>
      <FieldGroup title="Color Scheme">
        <div className="grid grid-cols-3 gap-3">
          {[
            { name: 'Midnight Blue', accent: '#38BDF8' },
            { name: 'Emerald',       accent: '#10B981' },
            { name: 'Violet',        accent: '#818CF8' },
          ].map(t => (
            <button key={t.name}
              className="p-3 rounded-xl border text-left transition-all"
              style={{ backgroundColor: C.panel, borderColor: t.accent === '#38BDF8' ? t.accent : C.border }}>
              <div className="w-6 h-6 rounded-lg mb-2" style={{ backgroundColor: t.accent }} />
              <div className="text-xs font-semibold text-white">{t.name}</div>
            </button>
          ))}
        </div>
      </FieldGroup>
    </div>
  )
}

function NotificationsPanel() {
  const [email, setEmail]   = useState(true)
  const [slack, setSlack]   = useState(false)
  const [webhook, setWebhook] = useState(false)
  const [slackUrl, setSlackUrl] = useState('')
  const [webhookUrl, setWebhookUrl] = useState('')

  return (
    <div className="space-y-4">
      <FieldGroup title="Channels">
        <Field label="Email Alerts" sub="Send alerts to configured email addresses">
          <Toggle checked={email} onChange={setEmail} label={email ? 'Enabled' : 'Disabled'} />
        </Field>
        <Field label="Slack Integration" sub="Post alerts to a Slack channel">
          <Toggle checked={slack} onChange={setSlack} label={slack ? 'Enabled' : 'Disabled'} />
        </Field>
        {slack && (
          <Field label="Slack Webhook URL">
            <Input value={slackUrl} onChange={setSlackUrl} placeholder="https://hooks.slack.com/..." />
          </Field>
        )}
        <Field label="Custom Webhook" sub="POST alert JSON to an external URL">
          <Toggle checked={webhook} onChange={setWebhook} label={webhook ? 'Enabled' : 'Disabled'} />
        </Field>
        {webhook && (
          <Field label="Webhook URL">
            <Input value={webhookUrl} onChange={setWebhookUrl} placeholder="https://your-service.com/webhook" />
          </Field>
        )}
      </FieldGroup>
    </div>
  )
}

function SystemPanel() {
  const INFO = [
    ['Product',        'NetWatch AI NDR'],
    ['Version',        '3.8.2'],
    ['Build',          '2024.03.18-prod'],
    ['License',        'Enterprise — 100 nodes'],
    ['License Expiry', '2025-12-31'],
    ['OS',             'Ubuntu 22.04.4 LTS'],
    ['Kernel',         '5.15.0-101-generic'],
    ['CPU',            'Intel Xeon E5-2680 v4 (28 cores)'],
    ['Memory',         '64 GB DDR4'],
    ['Uptime',         '47 days, 3 hrs, 12 min'],
    ['DB Size',        '128.4 GB'],
    ['Packets Stored', '14.2 billion'],
  ]

  return (
    <FieldGroup title="System Information">
      <div className="grid grid-cols-2 gap-x-8 gap-y-3">
        {INFO.map(([k, v]) => (
          <div key={k} className="flex justify-between py-2 border-b" style={{ borderColor: '#1a2744' }}>
            <span className="text-xs" style={{ color: C.faint }}>{k}</span>
            <span className="mono text-xs font-semibold" style={{ color: C.muted }}>{v}</span>
          </div>
        ))}
      </div>
      <div className="mt-4 pt-4 border-t" style={{ borderColor: C.border }}>
        <div className="flex items-center gap-2">
          <CheckCircle size={14} style={{ color: C.success }} />
          <span className="text-xs font-medium" style={{ color: C.success }}>All systems operational</span>
        </div>
      </div>
    </FieldGroup>
  )
}

const SECTION_PANELS: Record<SettingSection, React.ComponentType> = {
  general:       GeneralPanel,
  network:       NetworkPanel,
  capture:       CapturePanel,
  detection:     DetectionPanel,
  thresholds:    ThresholdsPanel,
  ai:            AIPanel,
  database:      DatabasePanel,
  backup:        BackupPanel,
  theme:         ThemePanel,
  notifications: NotificationsPanel,
  system:        SystemPanel,
}

interface Props { showToast: (msg: string, type?: ToastMsg['type']) => void }

export default function Settings({ showToast }: Props) {
  const [active, setActive] = useState<SettingSection>('general')
  const Panel = SECTION_PANELS[active]
  const section = SECTIONS.find(s => s.id === active)!

  return (
    <div className="flex gap-4" style={{ minHeight: '600px' }}>
      {/* Left nav */}
      <div className="w-64 flex-shrink-0 rounded-2xl border overflow-hidden"
        style={{ backgroundColor: C.card, borderColor: C.border, alignSelf: 'start' }}>
        <div className="px-4 py-4 border-b" style={{ borderColor: C.border }}>
          <h2 className="text-sm font-semibold text-white">Settings</h2>
          <p className="text-xs mt-0.5" style={{ color: C.faint }}>Platform configuration</p>
        </div>
        <div className="py-2">
          {SECTIONS.map(s => {
            const Icon = s.icon
            const isActive = active === s.id
            return (
              <button key={s.id} onClick={() => setActive(s.id)}
                className="w-full flex items-center gap-3 px-4 py-2.5 text-left transition-all"
                style={{ backgroundColor: isActive ? `${C.accent}10` : 'transparent', borderLeft: `2px solid ${isActive ? C.accent : 'transparent'}` }}>
                <Icon size={14} style={{ color: isActive ? C.accent : C.faint, flexShrink: 0 }} />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-semibold" style={{ color: isActive ? C.text : C.muted }}>{s.label}</div>
                </div>
                {isActive && <ChevronRight size={12} style={{ color: C.accent, flexShrink: 0 }} />}
              </button>
            )
          })}
        </div>
      </div>

      {/* Right: content */}
      <div className="flex-1 min-w-0 space-y-4">
        {/* Section header */}
        <div>
          <h1 className="text-lg font-bold text-white">{section.label}</h1>
          <p className="text-xs mt-0.5" style={{ color: C.faint }}>{section.desc}</p>
        </div>

        <Panel />

        {/* Save bar */}
        {active !== 'system' && (
          <div className="flex items-center justify-between p-4 rounded-2xl border"
            style={{ backgroundColor: C.card, borderColor: C.border }}>
            <p className="text-xs" style={{ color: C.faint }}>
              Changes require a service restart to take full effect.
            </p>
            <div className="flex gap-2">
              <button onClick={() => showToast('Settings reset to defaults', 'info')}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold border"
                style={{ borderColor: C.border, color: C.muted }}>
                <RotateCcw size={12}/> Reset
              </button>
              <button onClick={() => showToast('Settings saved successfully', 'success')}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold"
                style={{ backgroundColor: C.accent, color: '#0F172A' }}>
                <Save size={12}/> Save Changes
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
