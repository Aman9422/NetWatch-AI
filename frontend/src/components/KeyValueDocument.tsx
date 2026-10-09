/**
 * A free-form evidence/metadata document, rendered as labelled values.
 *
 * Several backend payloads carry a small open-ended document beside a record: M10
 * findings have `evidence` and `metadata`, M11 evidence rows have `data`. They all
 * share a shape — a map of names to scalars — and none of them has a fixed schema,
 * because one detector's keys are not another's. Rendering them through one
 * component keeps the policy in a single place:
 *
 * * a key renders its **value**, not a guess at what the key means;
 * * `null` renders as an explicit unknown rather than an empty cell, because
 *   "the detector recorded no value" and "the detector recorded nothing" are
 *   different facts;
 * * booleans render as `true`/`false` rather than as `1`/`0`, which a reader would
 *   have to decode;
 * * an empty document says so, rather than showing nothing and looking broken.
 *
 * Nothing is stringified with `JSON.stringify` for a scalar, so `"5"` and `5` are
 * distinguishable only by their source type — which is how the backend sent them.
 */

import { C } from '@/lib/tokens'
import { UNKNOWN_TEXT } from '@/lib/format'
import type { EvidenceValue } from '@/types'

/** Render one document value without collapsing a null into an empty string. */
function renderValue(value: EvidenceValue): string {
  if (value === null || value === undefined) return UNKNOWN_TEXT
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  return String(value)
}

/** What {@link KeyValueDocument} takes. */
export interface KeyValueDocumentProps {
  /** The document to render. Keys are shown in the order the backend sent them. */
  readonly data: Readonly<Record<string, EvidenceValue>>
  /** Shown when the document carries no entries at all. */
  readonly emptyText?: string
}

/**
 * Render a document as a compact list of labelled values.
 */
export function KeyValueDocument({
  data,
  emptyText = 'This record carries no document — it is a bare reference.',
}: KeyValueDocumentProps) {
  const entries = Object.entries(data)
  if (entries.length === 0) {
    return (
      <p className="text-xs" style={{ color: C.faint }}>{emptyText}</p>
    )
  }
  return (
    <dl className="grid grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)] gap-x-4 gap-y-1.5">
      {entries.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="text-xs truncate" style={{ color: C.faint }} title={key}>{key}</dt>
          <dd className="mono text-xs text-white wrap-break-word">{renderValue(value)}</dd>
        </div>
      ))}
    </dl>
  )
}
