/**
 * The evidence behind an alert (M15.16).
 *
 * Evidence in NetWatch is a **reference, never a copy** (M11.13). A record names
 * the packet, connection or device it points at and carries a small document
 * describing why it is relevant. M7 stores no packet payload and M13 exposes none,
 * so there is nothing here to "expand" into a hex dump — and this component says
 * so rather than leaving an operator to wonder whether the expander is broken.
 *
 * It reads `GET /alerts/{alert_id}/evidence` through {@link useAlertEvidence},
 * optionally restricted to one kind. The filter is the backend's, so the list is
 * the server's match set rather than a client-side narrowing of everything.
 *
 * A `404` is kept distinct from an empty list: "this alert has no packet evidence"
 * and "there is no such alert" are different answers (M11.18), and only the first
 * of them is an empty state.
 */

import { useState } from 'react'
import { FileText, Link2, Inbox } from 'lucide-react'
import { AsyncSection, EmptyState, RefreshFailureBanner } from '@/components/AsyncState'
import { KeyValueDocument } from '@/components/KeyValueDocument'
import { EVIDENCE_TYPE_ORDER, useAlertEvidence } from '@/hooks'
import { C, tint } from '@/lib/tokens'
import { formatTimestamp } from '@/lib/format'
import type { AlertEvidence, EvidenceType } from '@/types'

/** The colour the design gives each evidence kind. */
const EVIDENCE_COLORS: Readonly<Record<string, string>> = {
  rule: C.accent,
  behavioral: C.purple,
  packet: C.info,
  connection: C.orange,
  device: C.success,
}

/** A readable title for an evidence kind. */
function typeLabel(type: string): string {
  if (type === 'rule') return 'Rule'
  if (type === 'behavioral') return 'Behavioural'
  if (type === 'packet') return 'Packet'
  if (type === 'connection') return 'Connection'
  if (type === 'device') return 'Device'
  return type
}

/** One evidence record, with its reference and its document. */
function EvidenceRow({ evidence }: { evidence: AlertEvidence }) {
  const color = EVIDENCE_COLORS[evidence.evidence_type] ?? C.muted
  return (
    <div className="px-5 py-4 border-b" style={{ borderColor: C.border }}>
      <div className="flex items-center gap-2 mb-2.5 flex-wrap">
        <span className="text-xs font-semibold px-2 py-0.5 rounded-full"
          style={{ backgroundColor: tint(color, 0.12), color }}>
          {typeLabel(evidence.evidence_type)}
        </span>
        {evidence.packet_id !== null && (
          <span className="flex items-center gap-1 text-xs" style={{ color: C.info }}>
            <Link2 size={11} />
            <span className="mono">packet #{evidence.packet_id}</span>
          </span>
        )}
        <span className="text-xs ml-auto" style={{ color: C.faint }}>
          {formatTimestamp(evidence.created_at)}
        </span>
      </div>
      <KeyValueDocument data={evidence.data} />
    </div>
  )
}

/** What {@link EvidenceList} takes. */
export interface EvidenceListProps {
  readonly alertId: number | null
}

/**
 * Render an alert's evidence, with a kind filter.
 *
 * The filter is applied by the backend on each change, so switching tabs is a
 * request rather than a re-slice — which is what makes the count under each tab
 * the server's answer.
 */
export function EvidenceList({ alertId }: EvidenceListProps) {
  const [activeType, setActiveType] = useState<EvidenceType | 'ALL'>('ALL')

  const resource = useAlertEvidence(
    alertId,
    activeType === 'ALL' ? undefined : activeType,
    { enabled: alertId !== null },
  )

  return (
    <div className="rounded-2xl border overflow-hidden"
      style={{ backgroundColor: C.card, borderColor: C.border }}>
      <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: C.border }}>
        <div className="flex items-center gap-2">
          <FileText size={14} style={{ color: C.accent }} />
          <h3 className="text-sm font-semibold text-white">Evidence</h3>
        </div>
        {resource.count !== null && (
          <span className="text-xs" style={{ color: C.faint }}>
            {resource.count} record{resource.count === 1 ? '' : 's'}
          </span>
        )}
      </div>

      <div className="flex items-center gap-1.5 px-5 py-3 border-b overflow-x-auto"
        style={{ borderColor: C.border }}>
        <button onClick={() => setActiveType('ALL')}
          className="px-3 py-1.5 rounded-xl text-xs font-medium whitespace-nowrap border"
          style={{
            backgroundColor: activeType === 'ALL' ? C.accent : 'transparent',
            borderColor: activeType === 'ALL' ? C.accent : C.border,
            color: activeType === 'ALL' ? C.bg : C.faint,
          }}>
          All
        </button>
        {EVIDENCE_TYPE_ORDER.map(type => (
          <button key={type} onClick={() => setActiveType(type)}
            className="px-3 py-1.5 rounded-xl text-xs font-medium capitalize whitespace-nowrap border"
            style={{
              backgroundColor: activeType === type ? tint(EVIDENCE_COLORS[type] ?? C.accent, 0.14) : 'transparent',
              borderColor: activeType === type ? (EVIDENCE_COLORS[type] ?? C.accent) : C.border,
              color: activeType === type ? (EVIDENCE_COLORS[type] ?? C.accent) : C.faint,
            }}>
            {typeLabel(type)}
          </button>
        ))}
      </div>

      {resource.error !== null && resource.evidence.length > 0 && (
        <div className="px-5 pt-3">
          <RefreshFailureBanner error={resource.error} onRetry={resource.reload} />
        </div>
      )}

      <AsyncSection
        isInitialLoading={resource.isInitialLoading}
        error={resource.isNotFound
          // A missing alert is not an evidence failure; the parent screen owns
          // that message, so this panel only reports a genuine request failure.
          ? null
          : resource.blockingError}
        isEmpty={resource.isEmpty}
        loadingLabel="Loading evidence…"
        emptyTitle={activeType === 'ALL' ? 'No evidence recorded' : `No ${typeLabel(activeType).toLowerCase()} evidence`}
        emptyHint="The detector attached no evidence records of this kind to the alert."
        emptyIcon={<Inbox size={24} />}
        errorTitle="Unable to load evidence"
        onRetry={resource.reload}
        minHeight={180}
      >
        {resource.evidence.map((evidence, index) => (
          <EvidenceRow
            key={`${evidence.evidence_type}-${evidence.packet_id ?? 'x'}-${evidence.created_at ?? index}`}
            evidence={evidence}
          />
        ))}
      </AsyncSection>

      <div className="px-5 py-3 border-t text-xs" style={{ borderColor: C.border, color: C.faint }}>
        Evidence records point at packets, connections and devices. Packet contents are
        not stored and not served, so there is nothing further to expand.
      </div>
    </div>
  )
}
