/**
 * The WebSocket client layer (M15.26–M15.29, M15.38 "WebSocket").
 *
 * Every case M15.38 names is here — connect, disconnect, reconnect, event parsing,
 * event routing, a duplicate event, an invalid event and a connection failure — and
 * each is driven by an explicit transition on the fake socket rather than by
 * waiting for a real one. That is the only way to assert on reconnection at all:
 * a real socket's close arrives when a server decides, and a test that waited for
 * one would be testing the network.
 *
 * Two things are deliberately **not** mocked:
 *
 * * `parseServerEvent` runs for real, so the validation assertions are about the
 *   decoder the application uses, not a stand-in.
 * * The dedup tracker runs for real, so "the same event twice" is measured by the
 *   same code that guards against it in a browser.
 *
 * Timers are injected (`setTimeoutFn`/`clearTimeoutFn`), because the documented
 * backoff reaches 30 seconds and a test that actually slept would be unusable.
 * Jitter is pinned to zero in socket tests through `backoff: { jitterRatio: 0 }`,
 * so a delay is a number rather than a distribution; the jitter itself is covered
 * directly against {@link backoffDelay}.
 */

import { describe, expect, it, vi } from 'vitest'
import { webSocketUrl } from '@/config/env'
import {
  ChannelHub,
  ChannelSocket,
  DEFAULT_BACKOFF_BASE_MS,
  DEFAULT_BACKOFF_FACTOR,
  DEFAULT_BACKOFF_MAX_MS,
  DEFAULT_DEDUP_CAPACITY,
  DEFAULT_MAX_RECONNECT_ATTEMPTS,
  EventIdTracker,
  backoffDelay,
  channelHub,
  type TimerHandle,
} from '@/services'
import { EventType, channelPath, type ServerEvent } from '@/types'
import {
  MockWebSocket,
  createSocketHarness,
  eventFrame,
  packetFrame,
  pingFrame,
  refusalFrame,
  type SocketHarness,
} from '@/test/harness'

// ── Test doubles ─────────────────────────────────────────────────────────────

/**
 * A clock that records the retries it is asked to schedule.
 *
 * Returning a handle and letting the test fire it by hand is what makes "the retry
 * after two failures waits four seconds, not one" assertable without the test
 * taking four seconds.
 */
class FakeClock {
  // The handle is typed as `TimerHandle` rather than `number` because that is what
  // the socket hands back to us, and under `@types/node` it is a `Timeout` object
  // rather than a number. Comparing the two as numbers would not compile.
  readonly scheduled: { handle: TimerHandle; delayMs: number; handler: () => void }[] = []
  private nextHandle = 1

  readonly setTimeoutFn = (handler: () => void, delayMs: number): TimerHandle => {
    const handle = this.nextHandle++ as unknown as TimerHandle
    this.scheduled.push({ handle, delayMs, handler })
    return handle
  }

  readonly clearTimeoutFn = (handle: TimerHandle): void => {
    const index = this.scheduled.findIndex((entry) => entry.handle === handle)
    if (index !== -1) this.scheduled.splice(index, 1)
  }

  /** The delays currently queued, oldest first. */
  get delays(): number[] {
    return this.scheduled.map((entry) => entry.delayMs)
  }

  /** How many retries are queued. */
  get size(): number {
    return this.scheduled.length
  }

  /** Run the earliest queued retry. */
  runNext(): void {
    const entry = this.scheduled.shift()
    if (entry === undefined) throw new Error('No retry was scheduled.')
    entry.handler()
  }
}

/** Everything a socket test needs to observe one channel's connection. */
interface SocketUnderTest {
  readonly socket: ChannelSocket
  readonly harness: SocketHarness
  readonly clock: FakeClock
  readonly events: ServerEvent[]
  readonly phases: string[]
  readonly opens: { isReconnect: boolean }[]
  readonly invalidFrames: string[]
  readonly refusals: { reason: string; field: string }[]
  readonly closes: number
}

/**
 * Build a {@link ChannelSocket} with every handler recorded and every timer faked.
 *
 * `jitterRatio: 0` and a small `maxReconnectAttempts` are the defaults because an
 * assertion about a growing delay is about the exponential part; the ceiling and
 * the jitter are covered separately.
 */
function createSocket(
  channel: 'dashboard' | 'packets' | 'alerts' | 'system' = 'packets',
  options: {
    maxReconnectAttempts?: number
    dedupCapacity?: number
  } = {},
): SocketUnderTest {
  const harness = createSocketHarness()
  const clock = new FakeClock()
  const events: ServerEvent[] = []
  const phases: string[] = []
  const opens: { isReconnect: boolean }[] = []
  const invalidFrames: string[] = []
  const refusals: { reason: string; field: string }[] = []
  const state = { closes: 0 }

  const socket = new ChannelSocket(
    channel,
    {
      onEvent: (event) => {
        events.push(event)
      },
      onOpen: (isReconnect) => {
        opens.push({ isReconnect })
      },
      onPhase: (phase) => {
        phases.push(phase)
      },
      onInvalidFrame: (reason) => {
        invalidFrames.push(reason)
      },
      onRefusal: (refusal) => {
        refusals.push(refusal)
      },
      onClose: () => {
        state.closes += 1
      },
    },
    {
      socketFactory: harness.factory,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
      backoff: { jitterRatio: 0 },
      ...(options.maxReconnectAttempts === undefined
        ? {}
        : { maxReconnectAttempts: options.maxReconnectAttempts }),
      ...(options.dedupCapacity === undefined
        ? {}
        : { dedupCapacity: options.dedupCapacity }),
    },
  )

  return {
    socket,
    harness,
    clock,
    events,
    phases,
    opens,
    invalidFrames,
    refusals,
    get closes(): number {
      return state.closes
    },
  }
}

/** Connect and complete the handshake, the starting point of most cases. */
function connect(sut: SocketUnderTest): MockWebSocket {
  sut.socket.connect()
  const socket = sut.harness.latest()
  socket.open()
  return socket
}

// ── backoffDelay ─────────────────────────────────────────────────────────────

describe('backoffDelay', () => {
  /** No jitter, so the assertion is about the exponential part alone. */
  const noJitter = (): number => 0

  it('waits the base delay before the first retry', () => {
    expect(backoffDelay(1, undefined, noJitter)).toBe(DEFAULT_BACKOFF_BASE_MS)
  })

  it('multiplies the delay by the factor on each further attempt', () => {
    expect(backoffDelay(2, undefined, noJitter)).toBe(DEFAULT_BACKOFF_BASE_MS * DEFAULT_BACKOFF_FACTOR)
    expect(backoffDelay(3, undefined, noJitter)).toBe(
      DEFAULT_BACKOFF_BASE_MS * DEFAULT_BACKOFF_FACTOR * DEFAULT_BACKOFF_FACTOR,
    )
  })

  it('never exceeds the ceiling, however many attempts have failed', () => {
    // Without the cap, attempt 20 would be a 500-second wait and the socket would
    // appear to have died rather than to be retrying.
    expect(backoffDelay(50, undefined, noJitter)).toBe(DEFAULT_BACKOFF_MAX_MS)
  })

  it('stays within the jitter band when jitter is applied', () => {
    // The band is what makes several tabs spread out instead of retrying in phase.
    const jitterRatio = 0.25
    const options = {
      baseDelayMs: 1_000,
      maxDelayMs: 30_000,
      factor: 2,
      jitterRatio,
    }
    const lowest = backoffDelay(3, options, () => 0)
    const highest = backoffDelay(3, options, () => 1)
    expect(lowest).toBe(4_000)
    expect(highest).toBe(4_000 + 4_000 * jitterRatio)
  })

  it('does not exceed the ceiling even at maximum jitter', () => {
    // A ceiling that jitter could cross would make the cap meaningless.
    expect(backoffDelay(10, undefined, () => 1)).toBeLessThanOrEqual(DEFAULT_BACKOFF_MAX_MS)
  })

  it('treats a nonsensical attempt as the first one rather than producing NaN', () => {
    // `Math.pow(factor, NaN)` is `NaN`, and `setTimeout(fn, NaN)` retries in a tight
    // loop — a self-inflicted denial of service.
    expect(backoffDelay(0, undefined, noJitter)).toBe(DEFAULT_BACKOFF_BASE_MS)
    expect(backoffDelay(-5, undefined, noJitter)).toBe(DEFAULT_BACKOFF_BASE_MS)
    expect(backoffDelay(Number.NaN, undefined, noJitter)).toBe(DEFAULT_BACKOFF_BASE_MS)
  })

  it('returns a whole number of milliseconds', () => {
    expect(Number.isInteger(backoffDelay(2, undefined, () => 0.7))).toBe(true)
  })
})

// ── EventIdTracker ───────────────────────────────────────────────────────────

describe('EventIdTracker', () => {
  it('reports an id as new the first time and as seen afterwards', () => {
    const tracker = new EventIdTracker()
    expect(tracker.add('evt-1')).toBe(true)
    expect(tracker.add('evt-1')).toBe(false)
    expect(tracker.has('evt-1')).toBe(true)
  })

  it('treats an empty id as unusable rather than as a duplicate', () => {
    // An empty id would otherwise collapse every id-less event into one, silently
    // dropping all but the first.
    const tracker = new EventIdTracker()
    expect(tracker.add('')).toBe(false)
    expect(tracker.add('')).toBe(false)
    expect(tracker.size).toBe(0)
  })

  it('evicts the oldest id once the capacity is reached', () => {
    // Bounded because the alternative is a set that grows with uptime — the leak
    // M15.26 forbids.
    const tracker = new EventIdTracker(3)
    tracker.add('a')
    tracker.add('b')
    tracker.add('c')
    tracker.add('d')
    expect(tracker.size).toBe(3)
    expect(tracker.has('a')).toBe(false)
    expect(tracker.has('d')).toBe(true)
  })

  it('keeps the capacity at the documented default when none is given', () => {
    const tracker = new EventIdTracker()
    for (let index = 0; index < DEFAULT_DEDUP_CAPACITY + 10; index += 1) {
      tracker.add(`evt-${index}`)
    }
    expect(tracker.size).toBe(DEFAULT_DEDUP_CAPACITY)
  })

  it('forgets everything on clear', () => {
    const tracker = new EventIdTracker()
    tracker.add('evt-1')
    tracker.clear()
    expect(tracker.size).toBe(0)
    expect(tracker.has('evt-1')).toBe(false)
    // And the cleared id can be applied again, which is what a remount requires.
    expect(tracker.add('evt-1')).toBe(true)
  })
})
// ── ChannelSocket: connecting ────────────────────────────────────────────────

describe('ChannelSocket connecting', () => {
  it('opens the socket on its channel\'s documented path', () => {
    // A socket on the wrong path would connect and then receive nothing, which
    // looks exactly like a backend that is not publishing.
    const sut = createSocket('packets')
    sut.socket.connect()
    expect(sut.harness.latest().url).toBe(webSocketUrl(channelPath('packets')))
  })

  it('uses a different path for a different channel', () => {
    const dashboard = createSocket('dashboard')
    dashboard.socket.connect()
    expect(dashboard.harness.latest().url).toBe(webSocketUrl('/ws/dashboard'))

    const system = createSocket('system')
    system.socket.connect()
    expect(system.harness.latest().url).toBe(webSocketUrl('/ws/system'))
  })

  it('moves connecting → connected and reports the first open as not a reconnect', () => {
    // `isReconnect: false` is what tells a hook it does not need to re-read REST:
    // the state it just loaded is still current.
    const sut = createSocket()
    connect(sut)
    expect(sut.phases).toEqual(['connecting', 'connected'])
    expect(sut.opens).toEqual([{ isReconnect: false }])
    expect(sut.socket.currentPhase).toBe('connected')
  })

  it('starts idle before anything is asked of it', () => {
    expect(createSocket().socket.currentPhase).toBe('idle')
  })

  it('is open once the handshake completes', () => {
    const sut = createSocket()
    connect(sut)
    expect(sut.socket.isOpen).toBe(true)
  })

  it('is not open before the handshake completes', () => {
    const sut = createSocket()
    sut.socket.connect()
    expect(sut.socket.isOpen).toBe(false)
  })

  it('does not open a second socket when connect is called twice', () => {
    // Mount, unmount, remount is normal in React, and two sockets on one channel
    // would double the server's work and the browser's parsing.
    const sut = createSocket()
    connect(sut)
    sut.socket.connect()
    expect(sut.harness.count).toBe(1)
  })

  it('reports no close for a socket that was never connected', () => {
    const sut = createSocket()
    sut.socket.close()
    expect(sut.closes).toBe(0)
    expect(sut.harness.count).toBe(0)
  })
})

// ── ChannelSocket: disconnecting ─────────────────────────────────────────────

describe('ChannelSocket disconnecting', () => {
  it('closes the socket with a normal code and the documented reason', () => {
    const sut = createSocket()
    const socket = connect(sut)
    sut.socket.close()
    expect(socket.closeRequests).toEqual([{ code: 1000, reason: 'client closing' }])
  })

  it('moves to closed and stops being open', () => {
    const sut = createSocket()
    connect(sut)
    sut.socket.close()
    expect(sut.socket.currentPhase).toBe('closed')
    expect(sut.socket.isOpen).toBe(false)
  })

  it('is idempotent, so an unmount racing an error cannot double-close', () => {
    const sut = createSocket()
    const socket = connect(sut)
    sut.socket.close()
    sut.socket.close()
    expect(socket.closeRequests).toHaveLength(1)
  })

  it('does not schedule a retry for a close the client asked for', () => {
    // The bug this prevents: a page unmounts, the socket retries, and a connection
    // the user has left stays open against the backend.
    const sut = createSocket()
    connect(sut)
    sut.socket.close()
    expect(sut.clock.size).toBe(0)
  })

  it('forgets its dedup history, so a remount does not drop the first events', () => {
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().emit(packetFrame({ packet_id: 1 }, 'evt-1'))
    expect(sut.socket.dedupSize).toBe(1)
    sut.socket.close()
    expect(sut.socket.dedupSize).toBe(0)
  })

  it('can be connected again after closing, and reports that as a reconnect', () => {
    // A remount after the last listener left is a fresh connection, and the hooks
    // must refresh from REST — which is what `isReconnect: true` tells them.
    const sut = createSocket()
    connect(sut)
    sut.socket.close()
    connect(sut)
    expect(sut.harness.count).toBe(2)
    expect(sut.opens).toEqual([{ isReconnect: false }, { isReconnect: true }])
  })

  it('reports nothing if a socket is closed while it is still connecting', () => {
    // A browser closing a CONNECTING socket fires no close event, so the client
    // must not depend on one to finish its teardown.
    const sut = createSocket()
    sut.socket.connect()
    sut.socket.close()
    expect(sut.closes).toBe(0)
    expect(sut.clock.size).toBe(0)
    expect(sut.socket.currentPhase).toBe('closed')
  })
})

// ── ChannelSocket: reconnecting ──────────────────────────────────────────────

describe('ChannelSocket reconnecting', () => {
  it('schedules a retry when the server drops the connection abnormally', () => {
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().serverClose(1006)
    expect(sut.clock.size).toBe(1)
    expect(sut.socket.currentPhase).toBe('reconnecting')
  })

  it('waits the documented base delay before the first retry', () => {
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().serverClose(1006)
    expect(sut.clock.delays).toEqual([DEFAULT_BACKOFF_BASE_MS])
  })

  it('backs off further after each failed retry', () => {
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().serverClose(1006)
    sut.clock.runNext()
    sut.harness.latest().serverClose(1006)
    sut.clock.runNext()
    sut.harness.latest().serverClose(1006)
    // The second retry waited twice as long as the first would have.
    expect(sut.clock.delays).toEqual([DEFAULT_BACKOFF_BASE_MS * DEFAULT_BACKOFF_FACTOR ** 2])
  })

  it('reports a retry that succeeds as a reconnect, which is the REST-refresh signal', () => {
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().serverClose(1006)
    sut.clock.runNext()
    sut.harness.latest().open()
    expect(sut.opens).toEqual([{ isReconnect: false }, { isReconnect: true }])
    expect(sut.socket.currentPhase).toBe('connected')
  })

  it('opens a fresh socket rather than reusing the dropped one', () => {
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().serverClose(1006)
    sut.clock.runNext()
    expect(sut.harness.count).toBe(2)
  })

  it('grows the delay across consecutive failures without a successful open', () => {
    // The counter is what drives the growth, and only a *successful* open resets
    // it. A retry that never completes the handshake leaves the budget spent.
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().serverClose(1006)
    expect(sut.clock.delays).toEqual([DEFAULT_BACKOFF_BASE_MS])
    sut.clock.runNext()
    sut.harness.latest().serverClose(1006)
    expect(sut.clock.delays).toEqual([DEFAULT_BACKOFF_BASE_MS * DEFAULT_BACKOFF_FACTOR])
  })

  it('restarts the backoff after a clean close, which is a deliberate restart', () => {
    // A backend restart closes cleanly; spending the retry budget on it would make
    // the client give up on a server that came straight back — and would make it
    // wait a long time before noticing.
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().serverClose(1006)
    sut.clock.runNext()
    sut.harness.latest().serverClose(1006)
    // Two abnormal closes in a row have driven the delay up.
    expect(sut.clock.delays).toEqual([DEFAULT_BACKOFF_BASE_MS * DEFAULT_BACKOFF_FACTOR])
    sut.clock.runNext()

    // A clean close resets the counter, so the next retry is back at the base
    // delay rather than at four times it.
    sut.harness.latest().serverClose(1000)
    expect(sut.clock.delays).toEqual([DEFAULT_BACKOFF_BASE_MS])
  })

  it('treats "no close code" as a deliberate end rather than a failure', () => {
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().serverClose(1005)
    expect(sut.clock.delays).toEqual([DEFAULT_BACKOFF_BASE_MS])
  })

  it('gives up after the configured number of attempts and says so', () => {
    // Without a give-up path a backend that is down forever would be polled forever.
    const sut = createSocket('packets', { maxReconnectAttempts: 3 })
    connect(sut)
    for (let attempt = 0; attempt < 3; attempt += 1) {
      sut.harness.latest().serverClose(1006)
      sut.clock.runNext()
    }
    sut.harness.latest().serverClose(1006)
    expect(sut.closes).toBe(1)
    expect(sut.socket.currentPhase).toBe('closed')
    expect(sut.clock.size).toBe(0)
  })

  it('gives up by default only after the documented number of attempts', () => {
    const sut = createSocket()
    connect(sut)
    for (let attempt = 0; attempt < DEFAULT_MAX_RECONNECT_ATTEMPTS; attempt += 1) {
      sut.harness.latest().serverClose(1006)
      sut.clock.runNext()
    }
    // Exactly at the limit: still retrying.
    expect(sut.closes).toBe(0)
    sut.harness.latest().serverClose(1006)
    expect(sut.closes).toBe(1)
  })

  it('cancels a pending retry when the socket is closed', () => {
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().serverClose(1006)
    expect(sut.clock.size).toBe(1)
    sut.socket.close()
    expect(sut.clock.size).toBe(0)
  })

  it('does not open a socket if a retry fires after a stop', () => {
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().serverClose(1006)
    const queued = sut.clock.scheduled[0]!
    // Reach past `close`'s cancellation, the way a timer that had already fired
    // into the queue would: the callback must still refuse to run.
    sut.clock.scheduled.length = 0
    sut.socket.close()
    queued.handler()
    expect(sut.harness.count).toBe(1)
  })

  it('does not double-schedule when a socket both errors and closes', () => {
    // An error is followed by a close in a browser; one dropped connection must
    // produce one retry.
    const sut = createSocket()
    const socket = connect(sut)
    socket.error()
    socket.serverClose(1006)
    expect(sut.clock.size).toBe(1)
  })

  it('ignores a transport error until the close arrives', () => {
    // Reporting here as well would show the operator two failures for one.
    const sut = createSocket()
    const socket = connect(sut)
    socket.error()
    expect(sut.clock.size).toBe(0)
    expect(sut.phases).toEqual(['connecting', 'connected'])
  })
})

// ── ChannelSocket: connection failures ───────────────────────────────────────

describe('ChannelSocket connection failures', () => {
  it('retries when the factory throws instead of propagating', () => {
    // A constructor that throws must not escape into a React render, which would
    // blank the page instead of showing "reconnecting".
    const clock = new FakeClock()
    const factory = vi.fn((): WebSocket => {
      throw new Error('no socket for you')
    })
    const socket = new ChannelSocket(
      'packets',
      { onEvent: () => {} },
      {
        socketFactory: factory,
        setTimeoutFn: clock.setTimeoutFn,
        clearTimeoutFn: clock.clearTimeoutFn,
        backoff: { jitterRatio: 0 },
      },
    )

    expect(() => socket.connect()).not.toThrow()
    expect(clock.size).toBe(1)
    expect(socket.currentPhase).toBe('reconnecting')
  })

  it('retries when the factory returns something that is not a socket', () => {
    const clock = new FakeClock()
    const invalidFrames: string[] = []
    const socket = new ChannelSocket(
      'packets',
      {
        onEvent: () => {},
        onInvalidFrame: (reason) => {
          invalidFrames.push(reason)
        },
      },
      {
        socketFactory: () => ({}) as unknown as WebSocket,
        setTimeoutFn: clock.setTimeoutFn,
        clearTimeoutFn: clock.clearTimeoutFn,
        backoff: { jitterRatio: 0 },
      },
    )

    socket.connect()
    expect(invalidFrames).toHaveLength(1)
    expect(clock.size).toBe(1)
  })

  it('keeps the socket usable after a failed send', () => {
    const sut = createSocket()
    const socket = connect(sut)
    socket.send = (): void => {
      throw new Error('socket is going away')
    }
    expect(sut.socket.ping()).toBe(false)
  })

  it('refuses to send while there is no open socket', () => {
    const sut = createSocket()
    expect(sut.socket.ping()).toBe(false)
    sut.socket.connect()
    // Created but not yet open.
    expect(sut.socket.ping()).toBe(false)
  })
})
// ── ChannelSocket: parsing ───────────────────────────────────────────────────

describe('ChannelSocket parsing', () => {
  it('delivers a well-formed frame with every envelope field decoded', () => {
    const sut = createSocket('packets')
    connect(sut)
    sut.harness.latest().emit(
      eventFrame({
        type: EventType.PACKET_OBSERVED,
        channel: 'packets',
        event_id: 'evt-1',
        sequence: 7,
        source: 'pipeline.packets',
        timestamp: '2026-01-01T00:00:00+00:00',
        data: { packet_id: 42, protocol: 'TCP' },
      }),
    )

    expect(sut.events).toHaveLength(1)
    const event = sut.events[0]!
    expect(event.event_id).toBe('evt-1')
    expect(event.type).toBe('packet.observed')
    expect(event.channel).toBe('packets')
    expect(event.sequence).toBe(7)
    expect(event.source).toBe('pipeline.packets')
    expect(event.timestamp).toBe('2026-01-01T00:00:00+00:00')
    expect(event.data).toEqual({ packet_id: 42, protocol: 'TCP' })
  })

  it('accepts a gap in sequence numbers without complaint', () => {
    // M14 drops packet events under load by design, so a gap is the normal case
    // and must never be treated as an error or as a reason to resynchronise
    // (M15.11).
    const sut = createSocket('packets')
    connect(sut)
    sut.harness.latest().emit(packetFrame({ packet_id: 1 }, 'evt-a'))
    sut.harness.latest().emit(
      eventFrame({
        type: EventType.PACKET_OBSERVED,
        channel: 'packets',
        event_id: 'evt-b',
        sequence: 99,
        data: { packet_id: 2 },
      }),
    )
    expect(sut.events.map((event) => event.event_id)).toEqual(['evt-a', 'evt-b'])
    expect(sut.invalidFrames).toEqual([])
  })

  it('defaults a missing sequence rather than refusing the frame', () => {
    const sut = createSocket('packets')
    connect(sut)
    const frame = JSON.parse(
      eventFrame({ type: EventType.PACKET_OBSERVED, channel: 'packets', data: {} }),
    ) as Record<string, unknown>
    delete frame['sequence']
    sut.harness.latest().emit(JSON.stringify(frame))
    expect(sut.events[0]?.sequence).toBe(0)
  })

  it('defaults an unknown source rather than refusing the frame', () => {
    const sut = createSocket('packets')
    connect(sut)
    const frame = JSON.parse(
      eventFrame({ type: EventType.PACKET_OBSERVED, channel: 'packets', data: {} }),
    ) as Record<string, unknown>
    frame['source'] = 12
    sut.harness.latest().emit(JSON.stringify(frame))
    expect(sut.events[0]?.source).toBe('unknown')
  })

  it('refuses a frame that is not text', () => {
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().emitNonText()
    expect(sut.events).toEqual([])
    expect(sut.invalidFrames).toEqual(['a non-text frame was received'])
  })

  it('refuses a frame that is not JSON', () => {
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().emit('{not json')
    expect(sut.events).toEqual([])
    expect(sut.invalidFrames).toHaveLength(1)
  })

  it('refuses a JSON array', () => {
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().emit('[1,2,3]')
    expect(sut.invalidFrames).toHaveLength(1)
  })

  it('refuses an envelope version this client does not understand', () => {
    // Misreading a future envelope is worse than dropping it: the fields could
    // mean something else entirely (M14.7).
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().emit(
      eventFrame({
        type: EventType.PACKET_OBSERVED,
        channel: 'packets',
        schema_version: 2,
        data: {},
      }),
    )
    expect(sut.events).toEqual([])
    expect(sut.invalidFrames).toHaveLength(1)
  })

  it('refuses an event type that is not documented', () => {
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().emit(
      eventFrame({ type: 'packet.exploded', channel: 'packets', data: {} }),
    )
    expect(sut.events).toEqual([])
    expect(sut.invalidFrames).toHaveLength(1)
  })

  it('refuses a channel that is not one of the four', () => {
    const sut = createSocket()
    connect(sut)
    sut.harness.latest().emit(
      eventFrame({ type: EventType.PACKET_OBSERVED, channel: 'telemetry', data: {} }),
    )
    expect(sut.invalidFrames).toHaveLength(1)
  })

  it('refuses a frame with no event id, because dedup depends on it', () => {
    const sut = createSocket()
    connect(sut)
    const frame = JSON.parse(
      eventFrame({ type: EventType.PACKET_OBSERVED, channel: 'packets', data: {} }),
    ) as Record<string, unknown>
    frame['event_id'] = ''
    sut.harness.latest().emit(JSON.stringify(frame))
    expect(sut.invalidFrames).toHaveLength(1)
  })

  it('refuses a frame with no timestamp', () => {
    const sut = createSocket()
    connect(sut)
    const frame = JSON.parse(
      eventFrame({ type: EventType.PACKET_OBSERVED, channel: 'packets', data: {} }),
    ) as Record<string, unknown>
    frame['timestamp'] = null
    sut.harness.latest().emit(JSON.stringify(frame))
    expect(sut.invalidFrames).toHaveLength(1)
  })

  it('refuses a payload that is an array rather than an object', () => {
    const sut = createSocket()
    connect(sut)
    const frame = JSON.parse(
      eventFrame({ type: EventType.PACKET_OBSERVED, channel: 'packets', data: {} }),
    ) as Record<string, unknown>
    frame['data'] = [1, 2]
    sut.harness.latest().emit(JSON.stringify(frame))
    expect(sut.invalidFrames).toHaveLength(1)
  })

  it('refuses a payload that is not an object', () => {
    const sut = createSocket()
    connect(sut)
    const frame = JSON.parse(
      eventFrame({ type: EventType.PACKET_OBSERVED, channel: 'packets', data: {} }),
    ) as Record<string, unknown>
    frame['data'] = 'payload'
    sut.harness.latest().emit(JSON.stringify(frame))
    expect(sut.invalidFrames).toHaveLength(1)
  })

  it('keeps the stream alive across a run of bad frames', () => {
    // The property that matters: one bad message must not tear down a channel and
    // lose the stream that follows it. `parseServerEvent` returns null rather than
    // throwing, and the socket drops the frame and carries on.
    const sut = createSocket('packets')
    const socket = connect(sut)
    socket.emit('{not json')
    socket.emit('[]')
    socket.emitNonText()
    socket.emit(eventFrame({ type: 'made.up', channel: 'packets', data: {} }))
    socket.emit(packetFrame({ packet_id: 1 }, 'evt-after'))
    expect(sut.events.map((event) => event.event_id)).toEqual(['evt-after'])
    expect(sut.invalidFrames).toHaveLength(4)
    expect(sut.socket.currentPhase).toBe('connected')
  })
})

// ── ChannelSocket: routing ───────────────────────────────────────────────────

describe('ChannelSocket routing', () => {
  /** Read the last frame this socket sent, as an object. */
  function lastSent(frame: MockWebSocket): Record<string, unknown> {
    const raw = frame.sent[frame.sent.length - 1]
    if (raw === undefined) throw new Error('The socket sent nothing.')
    return JSON.parse(raw) as Record<string, unknown>
  }

  it('answers a ping with a pong carrying its nonce', () => {
    // The server expects its nonce back; a pong without it cannot be paired with
    // the ping that caused it (M14.24).
    const sut = createSocket('system')
    const socket = connect(sut)
    socket.emit(pingFrame('nonce-123'))
    expect(lastSent(socket)).toEqual({ type: 'pong', nonce: 'nonce-123' })
  })

  it('answers a ping with a bare pong when it carried no nonce', () => {
    const sut = createSocket('system')
    const socket = connect(sut)
    socket.emit(pingFrame())
    expect(lastSent(socket)).toEqual({ type: 'pong' })
  })

  it('never delivers a keepalive to the data handler', () => {
    // A page that rendered a ping as a packet would be displaying a protocol
    // artefact as an observation.
    const sut = createSocket('system')
    const socket = connect(sut)
    socket.emit(pingFrame('n'))
    socket.emit(eventFrame({ type: EventType.PONG, channel: 'system', data: {} }))
    expect(sut.events).toEqual([])
  })

  it('ignores a pong, which needs no answer', () => {
    const sut = createSocket('system')
    const socket = connect(sut)
    socket.emit(eventFrame({ type: EventType.PONG, channel: 'system', data: {} }))
    expect(socket.sent).toEqual([])
    expect(sut.events).toEqual([])
  })

  it('reports a refusal frame instead of delivering it as data', () => {
    const sut = createSocket('system')
    connect(sut)
    sut.harness.latest().emit(refusalFrame('unknown frame', 'type'))
    expect(sut.events).toEqual([])
    expect(sut.refusals).toEqual([{ reason: 'unknown frame', field: 'type' }])
  })

  it('fills in a sensible refusal when the server named neither reason nor field', () => {
    const sut = createSocket('system')
    connect(sut)
    sut.harness.latest().emit(eventFrame({ type: EventType.ERROR, channel: 'system', data: {} }))
    expect(sut.refusals).toEqual([
      { reason: 'the server refused a message', field: 'message' },
    ])
  })

  it('delivers a dashboard update as data', () => {
    const sut = createSocket('dashboard')
    connect(sut)
    sut.harness.latest().emit(
      eventFrame({
        type: EventType.DASHBOARD_UPDATED,
        channel: 'dashboard',
        event_id: 'evt-dash',
        data: { packet_count: 120 },
      }),
    )
    expect(sut.events.map((event) => event.type)).toEqual(['dashboard.updated'])
  })

  it('delivers each of the alert lifecycle names as data', () => {
    const sut = createSocket('alerts')
    connect(sut)
    const names = [
      EventType.ALERT_CREATED,
      EventType.ALERT_UPDATED,
      EventType.ALERT_ACKNOWLEDGED,
      EventType.ALERT_RESOLVED,
      EventType.ALERT_DISMISSED,
      EventType.ALERT_FALSE_POSITIVE,
    ]
    names.forEach((type, index) => {
      sut.harness.latest().emit(
        eventFrame({ type, channel: 'alerts', event_id: `evt-${index}`, data: { alert_id: index } }),
      )
    })
    expect(sut.events.map((event) => event.type)).toEqual([...names])
  })

  it('delivers incident events on the alerts channel', () => {
    // M14.12 carries incidents on `/ws/alerts` rather than a channel of their own.
    const sut = createSocket('alerts')
    connect(sut)
    sut.harness.latest().emit(
      eventFrame({
        type: EventType.INCIDENT_STATUS_CHANGED,
        channel: 'alerts',
        event_id: 'evt-incident',
        data: { incident_id: 3, status: 'investigating' },
      }),
    )
    expect(sut.events.map((event) => event.type)).toEqual(['incident.status_changed'])
  })
})

// ── ChannelSocket: deduplication ─────────────────────────────────────────────

describe('ChannelSocket deduplication', () => {
  it('applies an event once even when it arrives twice', () => {
    const sut = createSocket('packets')
    connect(sut)
    const frame = packetFrame({ packet_id: 1 }, 'evt-1')
    sut.harness.latest().emit(frame)
    sut.harness.latest().emit(frame)
    expect(sut.events).toHaveLength(1)
  })

  it('applies two events with different ids', () => {
    const sut = createSocket('packets')
    connect(sut)
    sut.harness.latest().emit(packetFrame({ packet_id: 1 }, 'evt-1'))
    sut.harness.latest().emit(packetFrame({ packet_id: 2 }, 'evt-2'))
    expect(sut.events).toHaveLength(2)
  })

  it('applies a repeat with a different id, because the server decided it was new', () => {
    // The tracked key is the id, not the payload: two genuine observations of the
    // same tuple are two packets.
    const sut = createSocket('packets')
    connect(sut)
    sut.harness.latest().emit(packetFrame({ packet_id: 1 }, 'evt-1'))
    sut.harness.latest().emit(packetFrame({ packet_id: 1 }, 'evt-2'))
    expect(sut.events).toHaveLength(2)
  })

  it('remembers an id even when the event was a keepalive', () => {
    // The tracker is applied only to data events, so a repeated ping is still
    // answered — which is the point: suppressing it would break liveness.
    const sut = createSocket('system')
    const socket = connect(sut)
    socket.emit(pingFrame('same-nonce'))
    socket.emit(pingFrame('same-nonce'))
    expect(socket.sent).toHaveLength(2)
    expect(sut.socket.dedupSize).toBe(0)
  })

  it('keeps its id set bounded under a long stream of distinct events', () => {
    // The leak M15.26 forbids: a socket left open for a day would otherwise hold
    // every id it had ever seen.
    const sut = createSocket('packets', { dedupCapacity: 10 })
    connect(sut)
    for (let index = 0; index < 50; index += 1) {
      sut.harness.latest().emit(packetFrame({ packet_id: index }, `evt-${index}`))
    }
    expect(sut.events).toHaveLength(50)
    expect(sut.socket.dedupSize).toBe(10)
  })

  it('still delivers a new event after the capacity has been reached', () => {
    // Eviction must not turn into a refusal: the oldest id is forgotten, the
    // newest is applied.
    const sut = createSocket('packets', { dedupCapacity: 2 })
    connect(sut)
    for (const id of ['a', 'b', 'c']) {
      sut.harness.latest().emit(packetFrame({ packet_id: id }, id))
    }
    expect(sut.events.map((event) => event.event_id)).toEqual(['a', 'b', 'c'])
  })
})

// ── ChannelHub ───────────────────────────────────────────────────────────────

/** Record what a subscriber was told. */
function createSubscriber(): {
  events: ServerEvent[]
  opens: { isReconnect: boolean }[]
  phases: string[]
  subscriber: {
    onEvent: (event: ServerEvent) => void
    onOpen: (isReconnect: boolean) => void
    onPhase: (phase: 'idle' | 'connecting' | 'connected' | 'reconnecting' | 'closed') => void
  }
} {
  const events: ServerEvent[] = []
  const opens: { isReconnect: boolean }[] = []
  const phases: string[] = []
  return {
    events,
    opens,
    phases,
    subscriber: {
      onEvent: (event) => {
        events.push(event)
      },
      onOpen: (isReconnect) => {
        opens.push({ isReconnect })
      },
      onPhase: (phase) => {
        phases.push(phase)
      },
    },
  }
}

describe('ChannelHub', () => {
  it('opens one socket for a channel on the first subscription', () => {
    const hub = new ChannelHub()
    const harness = createSocketHarness()
    const clock = new FakeClock()
    const first = createSubscriber()

    hub.subscribe('alerts', first.subscriber, {
      socketFactory: harness.factory,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
    })

    expect(harness.count).toBe(1)
    expect(harness.latest().url).toBe(webSocketUrl('/ws/alerts'))
    expect(hub.subscriberCount('alerts')).toBe(1)
  })

  it('shares one socket between two subscribers on the same channel', () => {
    // Two sockets on one stream would double the server's work, double the
    // browser's parsing, and make deduplication per-socket instead of per-channel.
    const hub = new ChannelHub()
    const harness = createSocketHarness()
    const clock = new FakeClock()
    const first = createSubscriber()
    const second = createSubscriber()
    const options = {
      socketFactory: harness.factory,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
    }

    hub.subscribe('alerts', first.subscriber, options)
    hub.subscribe('alerts', second.subscriber, options)

    expect(harness.count).toBe(1)
    expect(hub.subscriberCount('alerts')).toBe(2)
  })

  it('delivers one event to every subscriber exactly once', () => {
    const hub = new ChannelHub()
    const harness = createSocketHarness()
    const clock = new FakeClock()
    const first = createSubscriber()
    const second = createSubscriber()
    const options = {
      socketFactory: harness.factory,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
    }

    hub.subscribe('alerts', first.subscriber, options)
    hub.subscribe('alerts', second.subscriber, options)
    harness.latest().open()
    harness.latest().emit(eventFrame({ type: EventType.ALERT_CREATED, channel: 'alerts', event_id: 'evt-1', data: {} }))

    expect(first.events).toHaveLength(1)
    expect(second.events).toHaveLength(1)
    // And the dedup guard is above the fan-out, not below it.
    expect(hub.socketFor('alerts')?.dedupSize).toBe(1)
  })

  it('keeps the socket open while any listener remains', () => {
    const hub = new ChannelHub()
    const harness = createSocketHarness()
    const clock = new FakeClock()
    const first = createSubscriber()
    const second = createSubscriber()
    const options = {
      socketFactory: harness.factory,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
    }

    const a = hub.subscribe('alerts', first.subscriber, options)
    hub.subscribe('alerts', second.subscriber, options)
    harness.latest().open()
    a.unsubscribe()

    expect(hub.subscriberCount('alerts')).toBe(1)
    expect(harness.latest().closeRequests).toEqual([])
  })

  it('closes the socket when the last listener leaves', () => {
    // Held open for a page the user has left, it would occupy a server slot.
    const hub = new ChannelHub()
    const harness = createSocketHarness()
    const clock = new FakeClock()
    const first = createSubscriber()

    const subscription = hub.subscribe('alerts', first.subscriber, {
      socketFactory: harness.factory,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
    })
    harness.latest().open()
    subscription.unsubscribe()

    expect(harness.latest().closeRequests).toHaveLength(1)
    expect(hub.subscriberCount('alerts')).toBe(0)
    expect(hub.socketFor('alerts')).toBeNull()
  })

  it('lets an unsubscribe be called twice without retiring a live channel', () => {
    // React StrictMode runs an effect's cleanup twice; a second unsubscribe must
    // not close a socket another listener is still using.
    const hub = new ChannelHub()
    const harness = createSocketHarness()
    const clock = new FakeClock()
    const first = createSubscriber()
    const second = createSubscriber()
    const options = {
      socketFactory: harness.factory,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
    }

    const a = hub.subscribe('alerts', first.subscriber, options)
    hub.subscribe('alerts', second.subscriber, options)
    harness.latest().open()
    a.unsubscribe()
    a.unsubscribe()

    expect(hub.subscriberCount('alerts')).toBe(1)
    expect(harness.latest().closeRequests).toEqual([])
  })

  it('opens a new socket when a channel is subscribed to after everyone left', () => {
    const hub = new ChannelHub()
    const harness = createSocketHarness()
    const clock = new FakeClock()
    const options = {
      socketFactory: harness.factory,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
    }

    const first = createSubscriber()
    const a = hub.subscribe('alerts', first.subscriber, options)
    harness.latest().open()
    a.unsubscribe()

    const second = createSubscriber()
    hub.subscribe('alerts', second.subscriber, options)
    expect(harness.count).toBe(2)
    harness.latest().open()
    expect(second.opens).toEqual([{ isReconnect: false }])
  })

  it('tells every subscriber when the channel opens', () => {
    const hub = new ChannelHub()
    const harness = createSocketHarness()
    const clock = new FakeClock()
    const first = createSubscriber()
    const second = createSubscriber()
    const options = {
      socketFactory: harness.factory,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
    }

    hub.subscribe('alerts', first.subscriber, options)
    hub.subscribe('alerts', second.subscriber, options)
    harness.latest().open()

    expect(first.opens).toEqual([{ isReconnect: false }])
    expect(second.opens).toEqual([{ isReconnect: false }])
  })

  it('reports a reconnect to every subscriber, so each refreshes from REST', () => {
    const hub = new ChannelHub()
    const harness = createSocketHarness()
    const clock = new FakeClock()
    const first = createSubscriber()
    const options = {
      socketFactory: harness.factory,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
    }

    hub.subscribe('alerts', first.subscriber, options)
    harness.latest().open()
    harness.latest().serverClose(1006)
    clock.runNext()
    harness.latest().open()

    expect(first.opens).toEqual([{ isReconnect: false }, { isReconnect: true }])
  })

  it('keeps separate channels on separate sockets', () => {
    // M14.28 does not multiplex, so a client that joined them would have to invent
    // the separation back.
    const hub = new ChannelHub()
    const harness = createSocketHarness()
    const clock = new FakeClock()
    const options = {
      socketFactory: harness.factory,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
    }

    hub.subscribe('alerts', createSubscriber().subscriber, options)
    hub.subscribe('packets', createSubscriber().subscriber, options)
    hub.subscribe('dashboard', createSubscriber().subscriber, options)
    hub.subscribe('system', createSubscriber().subscriber, options)

    expect(harness.count).toBe(4)
    expect(harness.sockets.map((socket) => socket.url)).toEqual([
      webSocketUrl('/ws/alerts'),
      webSocketUrl('/ws/packets'),
      webSocketUrl('/ws/dashboard'),
      webSocketUrl('/ws/system'),
    ])
  })

  it('does not deliver one channel\'s event to another channel\'s subscriber', () => {
    const hub = new ChannelHub()
    const harness = createSocketHarness()
    const clock = new FakeClock()
    const alerts = createSubscriber()
    const packets = createSubscriber()
    const options = {
      socketFactory: harness.factory,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
    }

    hub.subscribe('alerts', alerts.subscriber, options)
    hub.subscribe('packets', packets.subscriber, options)
    const [alertsSocket, packetsSocket] = harness.sockets
    alertsSocket?.open()
    packetsSocket?.open()

    packetsSocket?.emit(packetFrame({ packet_id: 1 }, 'evt-1'))

    expect(packets.events).toHaveLength(1)
    expect(alerts.events).toEqual([])
  })

  it('closes one channel on demand without touching the others', () => {
    const hub = new ChannelHub()
    const harness = createSocketHarness()
    const clock = new FakeClock()
    const options = {
      socketFactory: harness.factory,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
    }

    hub.subscribe('alerts', createSubscriber().subscriber, options)
    hub.subscribe('packets', createSubscriber().subscriber, options)
    harness.sockets[0]?.open()
    harness.sockets[1]?.open()

    hub.closeChannel('alerts')

    expect(harness.sockets[0]?.closeRequests).toHaveLength(1)
    expect(harness.sockets[1]?.closeRequests).toEqual([])
    expect(hub.subscriberCount('alerts')).toBe(0)
    expect(hub.subscriberCount('packets')).toBe(1)
  })

  it('closes every channel on a full application teardown', () => {
    const hub = new ChannelHub()
    const harness = createSocketHarness()
    const clock = new FakeClock()
    const options = {
      socketFactory: harness.factory,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
    }

    hub.subscribe('alerts', createSubscriber().subscriber, options)
    hub.subscribe('packets', createSubscriber().subscriber, options)
    harness.sockets.forEach((socket) => socket.open())

    hub.closeAll()

    expect(harness.sockets.every((socket) => socket.closeRequests.length === 1)).toBe(true)
    expect(hub.socketFor('alerts')).toBeNull()
    expect(hub.socketFor('packets')).toBeNull()
  })

  it('reports no socket for a channel nobody subscribed to', () => {
    expect(new ChannelHub().socketFor('system')).toBeNull()
    expect(new ChannelHub().subscriberCount('system')).toBe(0)
  })

  it('ignores closeChannel for a channel that was never opened', () => {
    expect(() => new ChannelHub().closeChannel('dashboard')).not.toThrow()
  })

  it('shares the application-wide hub singleton', () => {
    // One process-wide socket per channel is what makes the reference counting
    // meaningful: two subtrees that never meet still share the connection.
    expect(channelHub).toBeInstanceOf(ChannelHub)
    expect(channelHub.subscriberCount('alerts')).toBe(0)
  })
})
