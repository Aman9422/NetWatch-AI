/**
 * Stored-packet service (M7, M15.10/M15.11).
 *
 * Two different things are called "a packet" in this application, and this module
 * is careful about which one it means:
 *
 * * a **stored** packet is a row M7 persisted, read back through REST with
 *   `packet_length` and `tcp_flags`;
 * * a **live** packet is a `/ws/packets` event with `length` and `packet_type`.
 *
 * Both are exposed, and they are deliberately different models. The stored table
 * is what an operator browses after the fact; the live stream is a bounded,
 * lossy window (M14 caps packet events on purpose). Merging the two would let a
 * page read `packet_length` off a stream event and render `undefined`.
 *
 * **No payload is ever returned or requested** — M7 does not store one and M13.8
 * does not expose one (M7.5).
 */

import { apiGet, apiPost } from './client'
import { PacketPaths } from './endpoints'
import { withPageWindow, type PageWindow } from './query'
import type { PacketQuery, RetentionCleanupResult, StoredPacket, StoredPacketPage } from '@/types'

/**
 * `GET /api/v1/packets` — stored packets, newest first.
 *
 * Ordering is `timestamp DESC, id DESC` and total, so the same request returns
 * the same page rather than shuffling rows with equal timestamps.
 */
export function fetchStoredPackets(
  query: PacketQuery = {},
  window?: PageWindow,
  signal?: AbortSignal,
): Promise<StoredPacketPage> {
  return apiGet<StoredPacketPage>(
    PacketPaths.list,
    withPageWindow(query, window),
    { signal },
  )
}

/** `GET /api/v1/packets/{id}` — one stored packet, or a `404`. */
export function fetchStoredPacket(
  packetId: number,
  signal?: AbortSignal,
): Promise<StoredPacket> {
  return apiGet<StoredPacket>(PacketPaths.detail(packetId), undefined, { signal })
}

/**
 * `POST /api/v1/packets/retention/cleanup` — the M7.14 development helper.
 *
 * Deletes only rows older than the configured retention window. It is exposed
 * because the endpoint exists for verification; the UI does not need to police
 * retention itself and must not imply that it does.
 */
export function runPacketRetentionCleanup(
  signal?: AbortSignal,
): Promise<RetentionCleanupResult> {
  return apiPost<RetentionCleanupResult>(PacketPaths.retentionCleanup, { signal })
}
