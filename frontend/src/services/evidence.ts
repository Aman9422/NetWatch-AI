/**
 * Standalone evidence service (M13.14, M15.16).
 *
 * The per-alert evidence listing lives in `./alerts`, beside the alert it belongs
 * to. This module adds the one thing evidence needs as a resource in its own
 * right: `GET /api/v1/evidence/{id}`, which returns a record **together with the
 * alert that owns it**. That is what lets a page holding an evidence reference
 * navigate back to its alert rather than searching every alert for it.
 *
 * Evidence is a **reference, never a copy** (M11.13). A record names a packet id,
 * a connection id or a device id and carries a small document describing why; it
 * never inlines the packet. The frontend must not go looking for a payload it was
 * never given — M7 stores none and M13 exposes none.
 */

import { apiGet } from './client'
import { EvidencePaths } from './endpoints'
import type { EvidenceDetail } from '@/types'

/**
 * `GET /api/v1/evidence/{evidence_id}` — one record and its owning alert.
 *
 * A pruned record, or an id that never existed, answers `404` rather than an
 * empty object: "this reference is no longer resolvable" and "this evidence has
 * no content" are different statements and only one of them is true.
 */
export function fetchEvidence(
  evidenceId: number,
  signal?: AbortSignal,
): Promise<EvidenceDetail> {
  return apiGet<EvidenceDetail>(EvidencePaths.detail(evidenceId), undefined, { signal })
}
