import { CheckCircle, XCircle, Info, X } from 'lucide-react'

interface Props {
  message: string
  type: 'success' | 'error' | 'info'
  onClose: () => void
}

const CONFIG = {
  success: { icon: CheckCircle, color: '#22C55E', bg: 'rgba(34,197,94,0.12)', border: 'rgba(34,197,94,0.3)' },
  error:   { icon: XCircle,     color: '#EF4444', bg: 'rgba(239,68,68,0.12)',  border: 'rgba(239,68,68,0.3)' },
  info:    { icon: Info,        color: '#38BDF8', bg: 'rgba(56,189,248,0.12)', border: 'rgba(56,189,248,0.3)' },
}

export default function Toast({ message, type, onClose }: Props) {
  const { icon: Icon, color, bg, border } = CONFIG[type]
  return (
    <div
      className="fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-xl border shadow-2xl fade-in-up"
      style={{ backgroundColor: '#1E293B', borderColor: border, minWidth: '280px', maxWidth: '400px' }}
    >
      <div className="p-1.5 rounded-lg flex-shrink-0" style={{ backgroundColor: bg }}>
        <Icon size={14} style={{ color }} />
      </div>
      <p className="text-sm text-white flex-1">{message}</p>
      <button onClick={onClose} style={{ color: '#64748B' }}>
        <X size={14} />
      </button>
    </div>
  )
}
