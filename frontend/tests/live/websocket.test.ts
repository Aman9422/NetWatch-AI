// @vitest-environment node
/**
 * The live WebSocket integration suite (M15.39).
 *
 * This file is the reason the live run is split by environment. Under the `node`
 * environment the ambient `WebSocket` is the runtime's own client and the ambient
 * `Event` is the runtime's own class, so a connection behaves exactly as it does
 * in a browser: `open` fires, frames arrive, and a client `ping` is answered. Under
 * vitest's jsdom it does not, and could not be made to — see `live-setup.ts` for
 * the measurement. Everything here is therefore a real connection to
 * `ws://127.0.0.1:8000`.
 *
 * Two layers are tested, and they are different claims:
 *
 * * **The protocol**, through a raw socket: the handshake completes, the
 *   application's own decoder accepts every frame the server sends, and the one
 *   message a client is allowed to send is answered (M14.23).
 * * **The application's socket layer**, through `channelHub`: one connection per
 *   channel, shared by every subscriber, reporting real connection phases,
 *   applying each event exactly once, and closing when the last listener leaves
 *   (M15.26/M15.28).
 *
 * What is deliberately **not** here: reconnection and duplicate suppression are
 * exercised as units in `src/services/websocket.test.ts`, where a socket factory
 * and a clock are injectable. A live test cannot drop the server's connection on
 * command, and a test that waited for a real 30-second backoff would be slower than
 * the thing it verified.
 */

import { describe, expect, it } from 'vitest'
import { webSocketUrl } from '@/config/env'
import { channelHub } from '@/services'
import {
  CHANNELS,
  EventType,
  channelPath,
  isDashboardEvent,
  keepaliveFrame,
  parseServerEvent,
  type Channel,
  type ConnectionPhase,
  type ServerEvent,
} from '@/types'

/** How long a real handshake or a real frame may take before the test fails. */
const CONNECT_TIMEOUT_MS = 15_000

/** How long a frame that the backend publishes on its own schedule may take. */
const EVENT_TIMEOUT_MS = 15_000

/** Poll `predicate` until it holds, or fail with what was being waited for. */
async function until(
  predicate: () => boolean,
  timeoutMs: number,
  description: string,
): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
  throw new Error(`waited ${timeoutMs} ms for ${description}, and it never happened`)
}

/** Resolve when the socket reports it is open. */
function waitForOpen(socket: WebSocket, timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`the socket did not open within ${timeoutMs} ms`)),
      timeoutMs,
    )
    socket.onopen = () => {
      clearTimeout(timer)
      resolve()
    }
    socket.onerror = () => {
      clearTimeout(timer)
      reject(new Error('the socket reported an error before opening'))
    }
  })
}

/**
 * Resolve with the first frame the application's decoder accepts and `match`
 * approves.
 *
 * Frames are parsed with `parseServerEvent` rather than `JSON.parse`, so a frame
 * this client cannot accept fails the test instead of being silently skipped —
 * which is the drift this run exists to catch.
 */
function waitForEvent(
  socket: WebSocket,
  match: (event: ServerEvent) => boolean,
  timeoutMs: number,
): Promise<ServerEvent> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`no matching event arrived within ${timeoutMs} ms`)),
      timeoutMs,
    )
    socket.onmessage = (message: MessageEvent<unknown>) => {
      const raw = typeof message.data === 'string' ? message.data : ''
      const event = parseServerEvent(raw)
      if (event === null) {
        clearTimeout(timer)
        reject(new Error(`the server sent a frame this client cannot parse: ${raw.slice(0, 200)}`))
        return
      }
      if (!match(event)) return
      clearTimeout(timer)
      resolve(event)
    }
  })
}

/** Every key `dashboard.updated` carries (M14.9). */
const DASHBOARD_PAYLOAD_KEYS = [
  'active_connections',
  'active_incidents',
  'bytes_per_second',
  'capture_running',
  'device_count',
  'interface',
  'open_alerts',
  'packet_count',
  'packets_per_second',
]

describe('the real socket, used directly', () => {
  it('completes a handshake and fires open, which the DOM environment cannot', async () => {
    expect(typeof globalThis.WebSocket).toBe('function')
    const socket = new WebSocket(webSocketUrl(channelPath('system')))
    try {
      await waitForOpen(socket, CONNECT_TIMEOUT_MS)
      expect(socket.readyState).toBe(1)
    } finally {
      socket.close(1000, 'test finished')
    }
  })

  it('answers a client ping with a pong on the same channel (M14.23)', async () => {
    const socket = new WebSocket(webSocketUrl(channelPath('system')))
    try {
      await waitForOpen(socket, CONNECT_TIMEOUT_MS)
      const pong = waitForEvent(socket, (event) => event.type === EventType.PONG, EVENT_TIMEOUT_MS)
      expect(socket.send(keepaliveFrame(EventType.PING))).toBeUndefined()
      const event = await pong
      // A `pong` is transport, and it must still be a well-formed envelope.
      expect(event.schema_version).toBe(1)
      expect(event.channel).toBe('system')
      expect(event.event_id.length).toBeGreaterThan(0)
      expect(Number.isNaN(Date.parse(event.timestamp))).toBe(false)
    } finally {
      socket.close(1000, 'test finished')
    }
  })
})

describe('the application hub against live channels', () => {
  it('opens one real connection per channel and reports each as connected', async () => {
    const phases = new Map<Channel, ConnectionPhase>()
    const subscriptions = CHANNELS.map((channel) =>
      channelHub.subscribe(channel, {
        onEvent: () => undefined,
        onPhase: (phase) => phases.set(channel, phase),
      }),
    )

    try {
      await until(
        () => CHANNELS.every((channel) => phases.get(channel) === 'connected'),
        CONNECT_TIMEOUT_MS,
        'all four channels to report connected',
      )

      for (const channel of CHANNELS) {
        expect(channelHub.subscriberCount(channel)).toBe(1)
        const socket = channelHub.socketFor(channel)
        expect(socket).not.toBeNull()
        expect(socket?.isOpen).toBe(true)
      }

      // Four separate connections, not one multiplexed stream (M14.28/M15.28).
      const sockets = CHANNELS.map((channel) => channelHub.socketFor(channel))
      expect(new Set(sockets).size).toBe(CHANNELS.length)
    } finally {
      for (const subscription of subscriptions) subscription.unsubscribe()
    }
    // The last unsubscribe closes each channel's socket.
    for (const channel of CHANNELS) {
      expect(channelHub.socketFor(channel)).toBeNull()
    }
  })

  it('delivers a real dashboard.updated event, parsed as the client models it (M15.30)', async () => {
    let live: ServerEvent | null = null
    const subscription = channelHub.subscribe('dashboard', {
      onEvent: (event) => {
        live = event
      },
    })

    try {
      await until(() => live !== null, EVENT_TIMEOUT_MS, 'a dashboard.updated event')
      const event = live as ServerEvent | null
      expect(event).not.toBeNull()
      if (event === null) return

      expect(isDashboardEvent(event)).toBe(true)
      expect(event.type).toBe(EventType.DASHBOARD_UPDATED)
      expect(event.channel).toBe('dashboard')
      expect(event.schema_version).toBe(1)
      expect(event.event_id.length).toBeGreaterThan(0)
      expect(Number.isNaN(Date.parse(event.timestamp))).toBe(false)
      expect(Number.isInteger(event.sequence)).toBe(true)

      // The payload is the nine-scalar projection, and nothing more (M14.9).
      expect(Object.keys(event.data).sort()).toEqual(DASHBOARD_PAYLOAD_KEYS)
      expect(typeof event.data.capture_running).toBe('boolean')
      expect(event.data.interface === null || typeof event.data.interface === 'string').toBe(true)
      for (const counter of [
        event.data.packet_count,
        event.data.device_count,
        event.data.active_connections,
        event.data.open_alerts,
        event.data.active_incidents,
      ]) {
        expect(Number.isInteger(counter)).toBe(true)
        expect(counter).toBeGreaterThanOrEqual(0)
      }
      for (const rate of [event.data.packets_per_second, event.data.bytes_per_second]) {
        expect(typeof rate).toBe('number')
        expect(rate).toBeGreaterThanOrEqual(0)
      }
    } finally {
      subscription.unsubscribe()
    }
  })

  it('applies each distinct event exactly once, and records transport frames as no event', async () => {
    const received: ServerEvent[] = []
    const subscription = channelHub.subscribe('dashboard', {
      onEvent: (event) => received.push(event),
    })

    try {
      // The dashboard channel publishes on its own tick, so two events arrive
      // about a second apart without this test asking for anything.
      await until(() => received.length >= 2, EVENT_TIMEOUT_MS, 'two dashboard events')

      // The tracker holds one id per data event. A ping or a pong passing through
      // the same socket must not be counted, and no event may be applied twice —
      // which is what `event_id` deduplication exists to guarantee (M15.29).
      expect(subscription.socket.dedupSize).toBe(received.length)
      const ids = new Set(received.map((event) => event.event_id))
      expect(ids.size).toBe(received.length)
      expect(received.every((event) => event.type === EventType.DASHBOARD_UPDATED)).toBe(true)
    } finally {
      subscription.unsubscribe()
    }
  })

  it('shares one connection between two subscribers and stops delivering once both leave', async () => {
    const first: ServerEvent[] = []
    const second: ServerEvent[] = []
    const one = channelHub.subscribe('dashboard', { onEvent: (event) => first.push(event) })
    const two = channelHub.subscribe('dashboard', { onEvent: (event) => second.push(event) })

    expect(channelHub.subscriberCount('dashboard')).toBe(2)
    expect(channelHub.socketFor('dashboard')).not.toBeNull()

    try {
      await until(() => first.length >= 1 && second.length >= 1, EVENT_TIMEOUT_MS, 'both subscribers')
      // Every subscriber sees every event: the channel is shared, the delivery is
      // per listener (M15.26).
      expect(first[0]?.event_id).toBe(second[0]?.event_id)
    } finally {
      one.unsubscribe()
      two.unsubscribe()
    }

    expect(channelHub.socketFor('dashboard')).toBeNull()
    const deliveredBefore = first.length
    await new Promise((resolve) => setTimeout(resolve, 1_500))
    // The connection is genuinely closed, not merely detached: nothing arrives.
    expect(first.length).toBe(deliveredBefore)
  })
})
