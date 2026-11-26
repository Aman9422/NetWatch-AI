/**
 * The aggregated windows behind a baseline (M21.11).
 *
 * The samples the profile was calculated from, shown so an operator can see the
 * shape of a device's behaviour rather than only its summary. Every column is a
 * counter the engine recorded — no peer address, port number or payload appears
 * here, because the engine stores none (`app/models/baseline_observation.py`).
 *
 * Two absences render as absences:
 *
 * * `new_connections: null` means the feature could not be measured for that
 *   window and is shown as unknown — **not** as zero, which would report "no new
 *   conversations" for a window where nothing was counted (M21.5).
 * * A truncated peer or port count is marked as a floor, because the cap means the
 *   real number was at least what is shown (M21.6).
 */

import { C, tint } from '@/lib/tokens'
import { UNKNOWN_TEXT, formatBytes, formatCount, formatTimestamp } from '@/lib/format'
import type { BaselineWindow } from '@/types'

interface Props {
  readonly windows: readonly BaselineWindow[]
}

/** Column headers, in the order the rows render them. */
const COLUMNS: readonly { readonly label: string; readonly hint?: string }[] = [
  { label: 'Packets' },
  { label: 'Bytes' },
  { label: 'TCP' },
  { label: 'UDP' },
  { label: 'ICMP' },
  { label: 'DNS' },
  { label: 'Peers', hint: 'Distinct peers contacted in this window' },
  { label: 'Dst ports', hint: 'Distinct destination ports contacted in this window' },
  {
    label: 'New conns',
    hint: 'Conversations seen for the first time. Unknown when the tracker could not measure it.',
  },
]

/** A cardinality, with a floor marker when the engine hit its cap. */
function Cardinality({ value, truncated }: { value: number; truncated: boolean }) {
  return (
    <>
      {formatCount(value)}
      {truncated && (
        <span
          className="ml-1 text-[10px] font-semibold"
          title="This window hit the cardinality cap, so the real figure was at least this."
          style={{ backgroundColor: tint(C.warning, 0.14), color: C.warning }}>
          ≥
        </span>
      )}
    </>
  )
}

export default function BaselineWindowsTable({ windows }: Props) {
  if (windows.length === 0) {
    return (
      <div className="px-5 py-8 text-center">
        <p className="text-sm font-medium text-white">No windows to show</p>
        <p className="text-xs mt-1 max-w-md mx-auto" style={{ color: C.faint }}>
          No observation window has been persisted for this device yet, or every one has aged out
          of retention. The summary above still describes what was observed.
        </p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b" style={{ borderColor: C.border }}>
            <th
              className="text-left pl-5 py-2.5 pr-4 text-xs font-medium whitespace-nowrap"
              style={{ color: C.dim }}>
              Window start
            </th>
            {COLUMNS.map(column => (
              <th
                key={column.label}
                title={column.hint}
                className="text-right py-2.5 pr-4 text-xs font-medium whitespace-nowrap"
                style={{ color: C.dim }}>
                {column.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {windows.map(window => (
            <tr key={window.window_start} className="border-b" style={{ borderColor: '#1a2744' }}>
              <td className="pl-5 py-2.5 pr-4 text-xs whitespace-nowrap" style={{ color: C.muted }}>
                {formatTimestamp(window.window_start)}
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right text-white">
                {formatCount(window.packet_count)}
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right text-white">
                {formatBytes(window.byte_count)}
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right" style={{ color: C.muted }}>
                {formatCount(window.tcp_packets)}
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right" style={{ color: C.muted }}>
                {formatCount(window.udp_packets)}
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right" style={{ color: C.faint }}>
                {formatCount(window.icmp_packets)}
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right" style={{ color: C.faint }}>
                {formatCount(window.dns_packets)}
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right" style={{ color: C.muted }}>
                <Cardinality value={window.unique_peers} truncated={window.peers_truncated} />
              </td>
              <td className="py-2.5 pr-4 mono text-xs text-right" style={{ color: C.muted }}>
                <Cardinality
                  value={window.unique_destination_ports}
                  truncated={window.ports_truncated}
                />
              </td>
              <td className="py-2.5 pr-5 mono text-xs text-right" style={{ color: C.faint }}>
                {window.new_connections === null
                  ? UNKNOWN_TEXT
                  : formatCount(window.new_connections)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="px-5 py-3 border-t text-xs" style={{ borderColor: C.border, color: C.faint }}>
        {windows.length} window{windows.length === 1 ? '' : 's'} shown · counters only, no
        addresses or payloads
      </div>
    </div>
  )
}
