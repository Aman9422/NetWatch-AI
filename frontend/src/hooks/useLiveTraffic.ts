/**
 * Live traffic (M15.10/M15.11/M15.34).
 *
 * Two sources again, for the reason they exist:
 *
 * * `/ws/packets` carries `packet.observed` — one normalized packet per event,
 *   with no payload, because M7 stores none and M14.8 sends none;
 * * `GET /statistics/traffic` supplies the M6 rates, which the packet stream does
 *   **not** carry and which the frontend must not compute for itself (M15.9).
 *
 * Three behaviours this hook is responsible for:
 *
 * * **The packet list is bounded.** M14 deliberately caps packet events under
 *   load, and a page left open would otherwise grow without limit. The list holds
 *   the most recent {@link LIVE_PACKET_CAPACITY} observations and drops the
 *   oldest — memory is a function of configuration, not of uptime (M15.11/M15.36).
 * * **A gap is normal.** Packet ids are not assumed sequential and the hook never
 *   treats a missing id as an error, because the backend drops events on purpose
 *   when a client cannot keep up (M15.11).
 * * **Rates are polled, and only because there is no event for them.** M15.34
 *   allows polling exactly where the backend publishes no event, and the packets
 *   channel publishes none. The interval is deliberately slow, and it pauses
 *   while the tab is hidden rather than making a hidden page keep asking.
 *
 * Pausing is a client-side decision with a server-side consequence that is worth
 * being explicit about: a paused page **discards** the events it receives, so the
 * backend keeps capturing and the table resumes from the next event rather than
 * from a backlog. That is the honest behaviour — this application has no replay
 * buffer to offer — and it is why the button says "pause view" rather than
 * "pause capture".
 */

import { useCallback, useEffect, useState } from 'react'
import { fetchTrafficSnapshot } from '@/services'
import { isPacketEvent } from '@/types'
import type { ApiError } from '@/services'
import type {
  ConnectionPhase,
  PacketEventData,
  TrafficSnapshot,
} from '@/types'
import { useAsyncResource } from './useAsyncResource'
import { useBoundedList } from './useBoundedList'
import { useChannelEvents } from './useChannelEvents'

/** How many live packets are retained. Roughly a screenful and a half of scroll. */
export const LIVE_PACKET_CAPACITY = 500

/**
 * How often the M6 snapshot is re-read, in milliseconds.
 *
 * Five seconds is chosen against the tick the backend publishes on
 * `/ws/dashboard`: polling harder would add load for a number that a human reads
 * once, and polling less often would make a rate look stuck.
 */
export const TRAFFIC_SNAPSHOT_POLL_MS = 5_000

/** Options for {@link useLiveTraffic}. */
export interface LiveTrafficOptions {
  /** How many packets to retain. Defaults to {@link LIVE_PACKET_CAPACITY}. */
  readonly capacity?: number
  /** When False nothing is subscribed or polled. Defaults True. */
  readonly enabled?: boolean
}

/** What {@link useLiveTraffic} returns. */
export interface LiveTrafficResource {
  /** Retained live packets, newest first. */
  readonly packets: readonly PacketEventData[]
  /** The bound applied to {@link packets}. */
  readonly capacity: number
  /** The last M6 snapshot read, or `null`. */
  readonly snapshot: TrafficSnapshot | null
  /** True while the packet channel is open. */
  readonly isConnected: boolean
  /** Where the packet connection stands. */
  readonly phase: ConnectionPhase
  /** When the last packet event arrived, in epoch milliseconds. */
  readonly lastEventAt: number | null
  /** True when incoming packets are being discarded rather than displayed. */
  readonly isPaused: boolean
  /** Stop or resume applying incoming packets. */
  readonly setPaused: (paused: boolean) => void
  /** Discard every retained packet. */
  readonly clearPackets: () => void
  /** The failure of the snapshot read, when it could not be made. */
  readonly error: ApiError | null
  /** The snapshot failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  /** Re-read the snapshot now. */
  readonly reload: () => void
}

/**
 * Subscribe to live packets and keep the M6 rates current.
 *
 * @param options Retained packet count, and whether to run at all.
 */
export function useLiveTraffic(
  options: LiveTrafficOptions = {},
): LiveTrafficResource {
  const capacity = options.capacity ?? LIVE_PACKET_CAPACITY
  const enabled = options.enabled ?? true
  const [isPaused, setPaused] = useState(false)

  const packets = useBoundedList<PacketEventData>(capacity)
  const { prepend } = packets
  const { clear } = packets

  const snapshot = useAsyncResource(
    (signal) => fetchTrafficSnapshot({ signal }),
    [],
    { enabled },
  )
  const { reload } = snapshot

  const channel = useChannelEvents({
    channel: 'packets',
    enabled,
    onEvent: (event) => {
      if (!isPacketEvent(event)) return
      if (isPaused) return
      // A single prepend per event, newest first. No id ordering is assumed and
      // no gap is reported: the stream is documented as lossy under load.
      prepend(event.data)
    },
    onReconnect: () => {
      // Rates are state, so they are re-read after an outage; packets are a
      // stream and there is nothing to recover, so the retained rows stay.
      reload()
    },
  })

  // Poll only for the rates, only while enabled, and only while the tab is
  // visible. `visibilitychange` triggers an immediate refresh so returning to the
  // tab never shows a rate from an unknown while ago.
  useEffect(() => {
    if (!enabled) return
    const tick = (): void => {
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
        return
      }
      reload()
    }
    const handle = globalThis.setInterval(tick, TRAFFIC_SNAPSHOT_POLL_MS)
    const onVisible = (): void => {
      if (typeof document !== 'undefined' && document.visibilityState === 'visible') {
        reload()
      }
    }
    document?.addEventListener('visibilitychange', onVisible)
    return () => {
      globalThis.clearInterval(handle)
      document?.removeEventListener('visibilitychange', onVisible)
    }
  }, [enabled, reload])

  const handleSetPaused = useCallback((next: boolean) => {
    setPaused(next)
  }, [])

  return {
    packets: packets.items,
    capacity,
    snapshot: snapshot.data,
    isConnected: channel.isConnected,
    phase: channel.phase,
    lastEventAt: channel.lastEventAt,
    isPaused,
    setPaused: handleSetPaused,
    clearPackets: clear,
    error: snapshot.error,
    blockingError: snapshot.blockingError,
    isLoading: snapshot.isLoading,
    isInitialLoading: snapshot.isInitialLoading,
    reload,
  }
}
