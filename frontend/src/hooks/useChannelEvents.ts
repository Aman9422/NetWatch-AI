/**
 * Subscribe a component to one real-time channel (M15.26/M15.28/M15.33).
 *
 * This is the only place a component touches a socket. It wraps
 * {@link channelHub}, so two components that ask for the same channel share one
 * connection — the hub owns reference counting, this owns the React lifecycle.
 *
 * Three behaviours a caller depends on:
 *
 * * **A reconnect is announced separately from a first connect.** `onReconnect`
 *   fires when a socket that had already been open comes back. That is the hook's
 *   whole reason for existing next to `onEvent`: M14 keeps no replay buffer, so a
 *   page that wants correct state after an outage must re-read REST when it hears
 *   this, and must *not* try to rebuild state from the events it missed (M15.27).
 * * **Handlers are read from refs.** A page almost always passes an inline arrow
 *   function, so treating the handler as a subscription key would resubscribe — and
 *   therefore reconnect — on every render. The effect re-runs only when the channel
 *   or `enabled` changes, which are the two things that genuinely require a new
 *   connection.
 * * **Unmounting unsubscribes.** Navigating away releases the reference, and the
 *   hub closes the socket when the last listener leaves, so a route change cannot
 *   leave a connection open behind it (M15.35).
 *
 * Events are delivered **once per subscriber**. Deduplication happens below this
 * hook, in `ChannelSocket`, keyed on `event_id` — so a redelivered event is
 * suppressed for every listener at once rather than once per listener.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { channelHub, type ChannelSubscriber } from '@/services'
import type { Channel, ConnectionPhase, ServerEvent } from '@/types'

/** Options for {@link useChannelEvents}. */
export interface ChannelEventsOptions {
  /** Which of the four streams to listen to. */
  readonly channel: Channel
  /** When False nothing is subscribed — for a tab that is not open. Defaults True. */
  readonly enabled?: boolean
  /** Called for each validated, not-yet-seen event. */
  readonly onEvent: (event: ServerEvent) => void
  /**
   * Called when an already-open channel reconnects.
   *
   * The signal to re-read current state from REST before trusting further events.
   */
  readonly onReconnect?: () => void
}

/** What {@link useChannelEvents} exposes to the component. */
export interface ChannelEventsResult {
  /** Where the connection currently stands. */
  readonly phase: ConnectionPhase
  /** True only while a socket is open. */
  readonly isConnected: boolean
  /** When the last event arrived, in epoch milliseconds; `null` before any. */
  readonly lastEventAt: number | null
  /**
   * Send one client-side `ping`.
   *
   * The only frame a client may send besides a `pong` (M14.23). Exposed because
   * the Live Traffic page offers an explicit liveness check, and because it is
   * the honest way to prove a silent channel is still there.
   */
  readonly ping: () => void
}

/**
 * Listen to a channel for as long as the component is mounted.
 *
 * @param options The channel, whether to listen, and the handlers.
 */
export function useChannelEvents(options: ChannelEventsOptions): ChannelEventsResult {
  const { channel, enabled = true } = options
  const [phase, setPhase] = useState<ConnectionPhase>('idle')
  const [lastEventAt, setLastEventAt] = useState<number | null>(null)
  const socketRef = useRef<{ ping: () => boolean } | null>(null)

  // Handlers live in refs so a caller's inline arrow does not resubscribe. The
  // latest function is always the one called, even though the subscription was
  // created with an earlier closure.
  const onEventRef = useRef(options.onEvent)
  onEventRef.current = options.onEvent
  const onReconnectRef = useRef(options.onReconnect)
  onReconnectRef.current = options.onReconnect

  useEffect(() => {
    if (!enabled) {
      setPhase('idle')
      socketRef.current = null
      return
    }

    const subscriber: ChannelSubscriber = {
      onEvent: (event) => {
        setLastEventAt(Date.now())
        onEventRef.current(event)
      },
      onOpen: (isReconnect) => {
        // The phase is set here rather than waiting for `onPhase`, so a component
        // sees `connected` on the same tick as the reconnect notification.
        setPhase('connected')
        if (isReconnect) onReconnectRef.current?.()
      },
      onPhase: (next) => setPhase(next),
      onRefusal: () => {
        // A refusal is the server rejecting a frame this client sent. The only
        // frame a client may send is a ping, so the useful response is to stop
        // pretending the connection is healthy until it reconnects.
        setPhase((current) => (current === 'connected' ? 'reconnecting' : current))
      },
    }

    const subscription = channelHub.subscribe(channel, subscriber)
    socketRef.current = subscription.socket

    return () => {
      socketRef.current = null
      subscription.unsubscribe()
    }
  }, [channel, enabled])

  const ping = useCallback(() => {
    socketRef.current?.ping()
  }, [])

  return {
    phase,
    isConnected: phase === 'connected',
    lastEventAt,
    ping,
  }
}
