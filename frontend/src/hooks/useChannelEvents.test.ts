/**
 * The real-time subscription hook (M15.26–M15.29, M15.33, M15.38).
 *
 * This hook is the only place a component touches a socket, so the things worth
 * asserting are the React-lifecycle ones the hook owns rather than the wire
 * behaviour `websocket.test.ts` already covers: that mounting subscribes and
 * unmounting releases, that two components on one channel share a connection, and
 * that an inline handler — which a page always passes — does not resubscribe (and
 * therefore does not reconnect) on every render.
 *
 * The global `WebSocket` is replaced, because the hook goes through the application
 * hub (`channelHub.subscribe(channel, subscriber)` with no options) and the hub's
 * default factory is `new WebSocket(url)`. Without the stub these tests would open
 * real sockets to a backend that is not running and then retry against it for
 * thirty seconds.
 */

import { act, renderHook, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { channelHub } from '@/services'
import { useChannelEvents } from '@/hooks'
import { EventType, type ServerEvent } from '@/types'
import { MockWebSocket, eventFrame, packetFrame, pingFrame } from '@/test/harness'

/** Every socket the hub created through the stubbed constructor, in order. */
const sockets: MockWebSocket[] = []

/**
 * Replace the global constructor with the controllable fake.
 *
 * `MockWebSocket` already satisfies what `ChannelSocket` duck-types for, so the
 * subclass only has to record the instance.
 */
function installFakeWebSocket(): void {
  vi.stubGlobal(
    'WebSocket',
    class extends MockWebSocket {
      constructor(url: string) {
        super(url)
        sockets.push(this)
      }
    },
  )
}

/** The most recently created socket. */
function latest(): MockWebSocket {
  const socket = sockets[sockets.length - 1]
  if (socket === undefined) throw new Error('The hook created no socket.')
  return socket
}

beforeEach(() => {
  sockets.length = 0
  installFakeWebSocket()
})

describe('useChannelEvents subscribing', () => {
  it('creates one socket on the channel it was asked for', () => {
    renderHook(() => useChannelEvents({ channel: 'packets', onEvent: () => {} }))
    expect(sockets).toHaveLength(1)
    expect(latest().url).toMatch(/\/ws\/packets$/)
  })

  it('starts idle and becomes connected on the handshake', () => {
    const { result } = renderHook(() =>
      useChannelEvents({ channel: 'packets', onEvent: () => {} }),
    )
    expect(result.current.phase).toBe('idle')
    expect(result.current.isConnected).toBe(false)

    act(() => latest().open())
    expect(result.current.phase).toBe('connected')
    expect(result.current.isConnected).toBe(true)
  })

  it('creates nothing while disabled', () => {
    // A tab that is not open must not hold a server slot.
    const { result } = renderHook(() =>
      useChannelEvents({ channel: 'packets', enabled: false, onEvent: () => {} }),
    )
    expect(sockets).toEqual([])
    expect(result.current.phase).toBe('idle')
    expect(result.current.isConnected).toBe(false)
  })

  it('subscribes when it becomes enabled', () => {
    const { rerender } = renderHook(
      ({ enabled }: { enabled: boolean }) =>
        useChannelEvents({ channel: 'alerts', enabled, onEvent: () => {} }),
      { initialProps: { enabled: false } },
    )
    expect(sockets).toEqual([])
    rerender({ enabled: true })
    expect(sockets).toHaveLength(1)
  })

  it('shares one socket between two components on the same channel', () => {
    // The hub owns reference counting precisely so the header badge and the table
    // do not open two connections to the same stream.
    renderHook(() => useChannelEvents({ channel: 'alerts', onEvent: () => {} }))
    renderHook(() => useChannelEvents({ channel: 'alerts', onEvent: () => {} }))
    expect(sockets).toHaveLength(1)
    expect(channelHub.subscriberCount('alerts')).toBe(2)
  })

  it('does not resubscribe when the caller passes a new inline handler', () => {
    // A page writes `onEvent={event => ...}`, which is a new function every render.
    // Treating it as a subscription key would reconnect on every render.
    const { rerender } = renderHook(
      ({ tick }: { tick: number }) =>
        useChannelEvents({ channel: 'packets', onEvent: () => tick }),
      { initialProps: { tick: 0 } },
    )
    act(() => latest().open())
    rerender({ tick: 1 })
    rerender({ tick: 2 })
    expect(sockets).toHaveLength(1)
  })
})

describe('useChannelEvents delivering', () => {
  it('reports no event time before anything has arrived', () => {
    const { result } = renderHook(() =>
      useChannelEvents({ channel: 'packets', onEvent: () => {} }),
    )
    expect(result.current.lastEventAt).toBeNull()
  })

  it('delivers a data event and records when it arrived', () => {
    const received: ServerEvent[] = []
    const { result } = renderHook(() =>
      useChannelEvents({
        channel: 'packets',
        onEvent: (event) => {
          received.push(event)
        },
      }),
    )
    act(() => latest().open())
    act(() => latest().emit(packetFrame({ packet_id: 1 }, 'evt-1')))

    expect(received).toHaveLength(1)
    expect(received[0]?.type).toBe(EventType.PACKET_OBSERVED)
    expect(result.current.lastEventAt).not.toBeNull()
  })

  it('calls the latest handler, not the one captured at subscribe time', () => {
    // The handlers live in refs for exactly this: the subscription was created with
    // an earlier closure, and the newest one must still be the one called.
    const first: ServerEvent[] = []
    const second: ServerEvent[] = []
    const { rerender } = renderHook(
      ({ useSecond }: { useSecond: boolean }) =>
        useChannelEvents({
          channel: 'packets',
          onEvent: (event) => {
            if (useSecond) second.push(event)
            else first.push(event)
          },
        }),
      { initialProps: { useSecond: false } },
    )
    act(() => latest().open())
    rerender({ useSecond: true })
    act(() => latest().emit(packetFrame({ packet_id: 1 }, 'evt-1')))

    expect(first).toEqual([])
    expect(second).toHaveLength(1)
  })

  it('never delivers a keepalive frame as data', () => {
    const received: ServerEvent[] = []
    renderHook(() =>
      useChannelEvents({
        channel: 'system',
        onEvent: (event) => {
          received.push(event)
        },
      }),
    )
    act(() => latest().open())
    act(() => latest().emit(pingFrame('nonce')))
    expect(received).toEqual([])
  })

  it('suppresses a redelivered event, because dedup happens below the hook', () => {
    const received: ServerEvent[] = []
    renderHook(() =>
      useChannelEvents({
        channel: 'packets',
        onEvent: (event) => {
          received.push(event)
        },
      }),
    )
    act(() => latest().open())
    const frame = packetFrame({ packet_id: 1 }, 'evt-1')
    act(() => latest().emit(frame))
    act(() => latest().emit(frame))
    expect(received).toHaveLength(1)
  })
})

describe('useChannelEvents reconnecting', () => {
  it('does not report a first open as a reconnect', () => {
    // A first open means the state the page just read from REST is still current,
    // so re-reading it would be wasted work.
    const onReconnect = vi.fn()
    renderHook(() =>
      useChannelEvents({ channel: 'packets', onEvent: () => {}, onReconnect }),
    )
    act(() => latest().open())
    expect(onReconnect).not.toHaveBeenCalled()
  })

  it('reports an abnormal close as reconnecting', () => {
    const { result } = renderHook(() =>
      useChannelEvents({ channel: 'packets', onEvent: () => {} }),
    )
    act(() => latest().open())
    act(() => latest().serverClose(1006))
    expect(result.current.phase).toBe('reconnecting')
    expect(result.current.isConnected).toBe(false)
  })

  it('announces a reconnect, which is the signal to re-read REST', async () => {
    // M15.27: M14 keeps no replay buffer, so the only way back to a correct view is
    // REST and then live updates. The backoff is a real second here, which is the
    // documented default and the price of not injecting a clock into the singleton.
    const onReconnect = vi.fn()
    renderHook(() =>
      useChannelEvents({ channel: 'packets', onEvent: () => {}, onReconnect }),
    )
    act(() => latest().open())
    act(() => latest().serverClose(1006))

    await waitFor(
      () => {
        expect(sockets).toHaveLength(2)
      },
      { timeout: 5_000 },
    )
    act(() => latest().open())

    expect(onReconnect).toHaveBeenCalledTimes(1)
  })

  it('treats a server refusal as a connection that is no longer healthy', () => {
    // The only frame a client may send is a ping; a refusal means the peer is not
    // the one this client was written against, so it must stop claiming to be
    // connected rather than keep rendering as if it were.
    const { result } = renderHook(() =>
      useChannelEvents({ channel: 'system', onEvent: () => {} }),
    )
    act(() => latest().open())
    expect(result.current.phase).toBe('connected')
    act(() =>
      latest().emit(eventFrame({ type: EventType.ERROR, channel: 'system', data: {} })),
    )
    expect(result.current.phase).toBe('reconnecting')
  })

  it('does not invent a phase change for a refusal that arrives while idle', () => {
    const { result } = renderHook(() =>
      useChannelEvents({ channel: 'system', onEvent: () => {} }),
    )
    act(() =>
      latest().emit(eventFrame({ type: EventType.ERROR, channel: 'system', data: {} })),
    )
    expect(result.current.phase).toBe('idle')
  })
})

describe('useChannelEvents unsubscribing', () => {
  it('releases the channel on unmount, and the last release closes the socket', () => {
    // M15.35: a route change must not leave a connection open behind it.
    const { unmount } = renderHook(() =>
      useChannelEvents({ channel: 'alerts', onEvent: () => {} }),
    )
    act(() => latest().open())
    expect(channelHub.subscriberCount('alerts')).toBe(1)

    unmount()

    expect(channelHub.subscriberCount('alerts')).toBe(0)
    expect(channelHub.socketFor('alerts')).toBeNull()
    expect(latest().closeRequests).toHaveLength(1)
  })

  it('keeps the socket open when one of two listeners unmounts', () => {
    const first = renderHook(() => useChannelEvents({ channel: 'alerts', onEvent: () => {} }))
    renderHook(() => useChannelEvents({ channel: 'alerts', onEvent: () => {} }))
    act(() => latest().open())

    first.unmount()

    expect(channelHub.subscriberCount('alerts')).toBe(1)
    expect(latest().closeRequests).toEqual([])
  })

  it('does not deliver an event that arrives after unmount', () => {
    const received: ServerEvent[] = []
    const { unmount } = renderHook(() =>
      useChannelEvents({
        channel: 'packets',
        onEvent: (event) => {
          received.push(event)
        },
      }),
    )
    const socket = latest()
    act(() => socket.open())
    unmount()
    // The socket's handlers are detached by then, so nothing is delivered.
    socket.emit(packetFrame({ packet_id: 1 }, 'evt-late'))
    expect(received).toEqual([])
  })
})

describe('useChannelEvents ping', () => {
  it('sends a ping once the socket is open', () => {
    // The only frame a client may send, and the honest way to prove a silent
    // channel is still there (M14.23).
    const { result } = renderHook(() =>
      useChannelEvents({ channel: 'packets', onEvent: () => {} }),
    )
    act(() => latest().open())
    act(() => {
      result.current.ping()
    })
    expect(latest().sent).toEqual([JSON.stringify({ type: EventType.PING })])
  })

  it('does not throw when the socket is not open yet', () => {
    const { result } = renderHook(() =>
      useChannelEvents({ channel: 'packets', onEvent: () => {} }),
    )
    expect(() => {
      act(() => {
        result.current.ping()
      })
    }).not.toThrow()
    expect(latest().sent).toEqual([])
  })
})
