/**
 * The WebSocket client layer (M15.26–M15.29).
 *
 * One socket per channel, because M14.28 does not multiplex: `/ws/dashboard`,
 * `/ws/packets`, `/ws/alerts` and `/ws/system` are four separate connections with
 * four separate policies server-side, and a client that joined them would have to
 * invent the separation back.
 *
 * Five responsibilities, and nothing else:
 *
 * 1. **Connect and disconnect** — a socket is opened on demand and closed on
 *    demand, and closing is idempotent so a React unmount and an error cannot
 *    both try to tear it down.
 * 2. **Reconnect** — a dropped connection is retried with exponential backoff and
 *    jitter. Reconnection is *not* replay: M14 keeps no per-client buffer, so the
 *    only way back to a correct view is to re-read REST and then resume live
 *    updates (M15.27). The socket therefore reports a reconnect as an event of its
 *    own — {@link ChannelSocketHandlers.onOpen} receives `true` — and the hooks
 *    above it refresh from REST when they hear it.
 * 3. **Parse and validate** — every frame goes through
 *    {@link parseServerEvent}, which rejects an unknown schema version, an
 *    undocumented event type and a non-object payload. A frame that fails is
 *    dropped, never half-applied: one bad message must not tear down a stream.
 * 4. **Deduplicate** — events are keyed by `event_id`, because `sequence` is
 *    deliberately discontinuous (the packets channel drops events under load) and
 *    therefore cannot be used to tell a replay from a gap (M15.29).
 * 5. **Keep the keepalive** — an incoming `ping` is answered with a `pong`
 *    carrying its nonce, exactly as `app/websockets/messages.py` expects. That is
 *    the whole of what a client may send (M14.23).
 *
 * **Nothing here keeps unbounded state.** The dedup set is a bounded ring: a
 * client that ran for a week would otherwise hold every event id it ever saw.
 */

import { webSocketUrl } from '@/config/env'
import {
  EventType,
  channelPath,
  keepaliveFrame,
  parseServerEvent,
  type Channel,
  type ConnectionPhase,
  type RefusalEventData,
  type ServerEvent,
} from '@/types'

/** How many event ids are remembered for deduplication. */
export const DEFAULT_DEDUP_CAPACITY = 512

/** First retry delay. Short, because a local backend restarts in a second or two. */
export const DEFAULT_BACKOFF_BASE_MS = 1_000

/** Ceiling on the retry delay, so a long outage does not become a 15-minute wait. */
export const DEFAULT_BACKOFF_MAX_MS = 30_000

/** Multiplier applied to the delay after each failed attempt. */
export const DEFAULT_BACKOFF_FACTOR = 2

/**
 * Fraction of the delay applied as random jitter, `0..1`.
 *
 * Jitter is not decoration: several tabs or channels reconnecting in lockstep
 * would retry in phase and hammer a backend that is already struggling. Spreading
 * them is what makes a restart survivable.
 */
export const DEFAULT_BACKOFF_JITTER = 0.25

/** Retries before the socket gives up and reports `closed`. */
export const DEFAULT_MAX_RECONNECT_ATTEMPTS = 20

/** Options controlling retry timing. */
export interface BackoffOptions {
  readonly baseDelayMs: number
  readonly maxDelayMs: number
  readonly factor: number
  readonly jitterRatio: number
}

/** The documented retry timing. */
export const DEFAULT_BACKOFF: BackoffOptions = {
  baseDelayMs: DEFAULT_BACKOFF_BASE_MS,
  maxDelayMs: DEFAULT_BACKOFF_MAX_MS,
  factor: DEFAULT_BACKOFF_FACTOR,
  jitterRatio: DEFAULT_BACKOFF_JITTER,
}

/**
 * The handle a timer returns.
 *
 * A named alias rather than `number`, because the same code runs in a browser
 * (where it is a number) and under Node in a test (where it is a `Timeout`
 * object). Typing it as `number` compiles against the DOM lib and fails against
 * `@types/node`, which this project includes for the Vite config.
 */
export type TimerHandle = ReturnType<typeof globalThis.setTimeout>

/** Return True when `value` is a plausible WebSocket. */
function isWebSocketLike(value: unknown): value is WebSocket {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { close?: unknown }).close === 'function' &&
    typeof (value as { send?: unknown }).send === 'function'
  )
}

/** Return True when a handshake code means "a socket, no server behind it". */
function isClosedNormally(code: number | undefined): boolean {
  // 1000 is a normal closure; 1005 is "no code was present". Both mean the peer
  // ended the session on purpose rather than failing, so neither is retried.
  return code === 1000 || code === 1005
}

/**
 * The delay before retry number `attempt` (1-based).
 *
 * Exponential with a ceiling, then jittered. `random` is injectable so a test can
 * assert the deterministic part without stubbing the global generator.
 */
export function backoffDelay(
  attempt: number,
  options: BackoffOptions = DEFAULT_BACKOFF,
  random: () => number = Math.random,
): number {
  const safeAttempt = Number.isFinite(attempt) && attempt > 0 ? Math.floor(attempt) : 1
  const raw = options.baseDelayMs * Math.pow(options.factor, safeAttempt - 1)
  const capped = Math.min(raw, options.maxDelayMs)
  const jitter = capped * options.jitterRatio * random()
  return Math.round(Math.min(capped + jitter, options.maxDelayMs))
}

/**
 * A bounded set of recently seen event ids (M15.29).
 *
 * Bounded because the alternative is a memory leak that grows with uptime: a
 * socket kept open for a day on an active channel would collect hundreds of
 * thousands of ids. Eviction is oldest-first, which is correct here because a
 * duplicate arrives immediately after its original — a redelivery from a *previous*
 * day is not a case the protocol produces.
 *
 * Implemented as an array plus a `Set` rather than a `Map`, so both the ordering
 * and the membership test are O(1) and nothing is allocated per hit.
 */
export class EventIdTracker {
  private readonly order: string[] = []
  private readonly seen = new Set<string>()

  constructor(private readonly capacity: number = DEFAULT_DEDUP_CAPACITY) {}

  /** How many ids are currently remembered. */
  get size(): number {
    return this.seen.size
  }

  /** Return True when this id has already been applied. */
  has(eventId: string): boolean {
    return this.seen.has(eventId)
  }

  /**
   * Record `eventId`, returning True when it is new.
   *
   * One call both tests and records, so a caller cannot check and then forget to
   * record — which is the bug that makes deduplication appear to work in a test
   * and fail in a browser.
   */
  add(eventId: string): boolean {
    if (eventId === '' || this.seen.has(eventId)) return false
    this.seen.add(eventId)
    this.order.push(eventId)
    while (this.order.length > this.capacity) {
      const evicted = this.order.shift()
      if (evicted !== undefined) this.seen.delete(evicted)
    }
    return true
  }

  /** Forget every remembered id. */
  clear(): void {
    this.order.length = 0
    this.seen.clear()
  }
}

/** What a {@link ChannelSocket} tells its owner. */
export interface ChannelSocketHandlers {
  /** One validated, not-yet-seen event. */
  readonly onEvent: (event: ServerEvent) => void
  /**
   * The socket opened. `isReconnect` is `true` after a retry, which is the signal
   * to re-read current state from REST (M15.27).
   */
  readonly onOpen?: (isReconnect: boolean) => void
  /** The connection phase changed. */
  readonly onPhase?: (phase: ConnectionPhase) => void
  /** The socket closed and will not retry. */
  readonly onClose?: () => void
  /** The server refused a message this client sent (M14.23). */
  readonly onRefusal?: (refusal: RefusalEventData) => void
  /** A frame arrived that could not be parsed or validated. Never thrown. */
  readonly onInvalidFrame?: (reason: string) => void
}

/** Construction options, all with documented defaults. */
export interface ChannelSocketOptions {
  readonly backoff?: Partial<BackoffOptions>
  readonly dedupCapacity?: number
  readonly maxReconnectAttempts?: number
  /** Injectable so a test can drive the socket without a server. */
  readonly socketFactory?: (url: string) => WebSocket
  /** Injectable clock, so a retry test does not wait 30 seconds. */
  readonly setTimeoutFn?: (handler: () => void, delayMs: number) => TimerHandle
  readonly clearTimeoutFn?: (handle: TimerHandle) => void
}
/**
 * One channel's connection, with reconnection and deduplication.
 *
 * Deliberately a plain class rather than a React hook: React re-renders, and a
 * socket that was recreated on every render would reconnect constantly. The hook
 * layer (`@/hooks/useChannel`) owns the lifecycle; this object owns the wire.
 *
 * The class never throws. Every failure mode — a factory that returns nonsense, a
 * frame that will not parse, a socket that closes mid-send — is reported to a
 * handler or ignored, because a socket that throws inside an `onmessage` callback
 * would take the page down with it, which is exactly what M14.14 refuses to do
 * server-side and the client should match.
 */
export class ChannelSocket {
  /** Which stream this socket carries. */
  readonly channel: Channel

  private readonly handlers: ChannelSocketHandlers
  private readonly backoff: BackoffOptions
  private readonly tracker: EventIdTracker
  private readonly maxAttempts: number
  private readonly socketFactory: (url: string) => WebSocket
  private readonly setTimeoutFn: (handler: () => void, delayMs: number) => TimerHandle
  private readonly clearTimeoutFn: (handle: TimerHandle) => void

  private socket: WebSocket | null = null
  private phase: ConnectionPhase = 'idle'
  private attempt = 0
  private timer: TimerHandle | null = null
  private stopped = false
  private openedOnce = false

  constructor(
    channel: Channel,
    handlers: ChannelSocketHandlers,
    options: ChannelSocketOptions = {},
  ) {
    this.channel = channel
    this.handlers = handlers
    this.backoff = { ...DEFAULT_BACKOFF, ...options.backoff }
    this.tracker = new EventIdTracker(options.dedupCapacity ?? DEFAULT_DEDUP_CAPACITY)
    this.maxAttempts = options.maxReconnectAttempts ?? DEFAULT_MAX_RECONNECT_ATTEMPTS
    this.socketFactory =
      options.socketFactory ??
      ((url: string): WebSocket => new WebSocket(url))
    this.setTimeoutFn =
      options.setTimeoutFn ?? ((handler, delay) => globalThis.setTimeout(handler, delay))
    this.clearTimeoutFn =
      options.clearTimeoutFn ?? ((handle) => globalThis.clearTimeout(handle))
  }

  /** Where the connection currently stands. */
  get currentPhase(): ConnectionPhase {
    return this.phase
  }

  /** True while the socket is open and usable. */
  get isOpen(): boolean {
    return this.socket !== null && this.socket.readyState === 1 /* OPEN */
  }

  /** How many event ids are currently remembered. Exposed for tests. */
  get dedupSize(): number {
    return this.tracker.size
  }

  /**
   * Open the connection, or resume retrying after {@link close}.
   *
   * Calling it twice is safe: a socket is already connecting or open does nothing,
   * so mount-then-unmount-then-mount does not produce two connections.
   */
  connect(): void {
    this.stopped = false
    if (this.socket !== null) return
    this.openSocket()
  }

  /**
   * Close the connection and stop retrying.
   *
   * Idempotent, and it clears the dedup set: a socket that is being retired has no
   * future event to compare against, and keeping the ids would make a remount
   * silently drop the first events of the new connection.
   */
  close(): void {
    this.stopped = true
    if (this.timer !== null) {
      this.clearTimeoutFn(this.timer)
      this.timer = null
    }
    const socket = this.socket
    this.socket = null
    if (socket !== null) {
      // Detach first: tearing the handlers off means the close we are about to
      // cause cannot schedule a retry.
      socket.onopen = null
      socket.onmessage = null
      socket.onerror = null
      socket.onclose = null
      try {
        socket.close(1000, 'client closing')
      } catch {
        // A socket that had already failed cannot be closed again; nothing to do.
      }
    }
    this.tracker.clear()
    this.setPhase('closed')
  }

  /** Send one frame. Returns False when the socket is not open. */
  send(frame: string): boolean {
    const socket = this.socket
    if (socket === null || socket.readyState !== 1 /* OPEN */) return false
    try {
      socket.send(frame)
      return true
    } catch {
      // A send that fails means the socket is going away; its own close handler
      // will schedule the retry. Reporting False lets the caller stop trying.
      return false
    }
  }

  /**
   * Send one client-side `ping` (M14.23).
   *
   * Permitted, and the only other frame a client may send: the server answers it
   * with a `pong`. It is not needed for keepalive — the server pings us — but it
   * is the documented way to prove liveness from this side.
   */
  ping(): boolean {
    return this.send(keepaliveFrame(EventType.PING))
  }

  /** Move to `next`, notifying the owner only when it is a real change. */
  private setPhase(next: ConnectionPhase): void {
    if (this.phase === next) return
    this.phase = next
    this.handlers.onPhase?.(next)
  }

  /** Create the socket and attach its handlers. */
  private openSocket(): void {
    const url = webSocketUrl(channelPath(this.channel))
    let socket: WebSocket
    try {
      socket = this.socketFactory(url)
    } catch {
      // A constructor that throws is a failure to connect like any other; the
      // retry path is what handles it rather than an exception out of `connect`.
      this.scheduleReconnect()
      return
    }
    if (!isWebSocketLike(socket)) {
      this.handlers.onInvalidFrame?.('the socket factory did not return a WebSocket')
      this.scheduleReconnect()
      return
    }

    this.socket = socket
    this.setPhase(this.openedOnce ? 'reconnecting' : 'connecting')

    socket.onopen = () => {
      this.attempt = 0
      const isReconnect = this.openedOnce
      this.openedOnce = true
      this.setPhase('connected')
      this.handlers.onOpen?.(isReconnect)
    }

    socket.onmessage = (message: MessageEvent<unknown>) => {
      this.handleFrame(message.data)
    }

    socket.onerror = () => {
      // Deliberately quiet: a browser follows an error with a close, and the close
      // is where the retry decision belongs. Reporting here as well would show the
      // operator two failures for one.
    }

    socket.onclose = (event: CloseEvent) => {
      this.socket = null
      if (this.stopped) return
      // A clean close is the server ending the session on purpose — a restart, or
      // a channel it has switched off — so the retry budget starts fresh rather
      // than being spent on a deliberate restart.
      if (isClosedNormally(event?.code)) this.attempt = 0
      this.scheduleReconnect()
    }
  }

  /**
   * Validate one frame and dispatch it.
   *
   * Keepalive and refusal frames are handled here and never reach `onEvent`: they
   * are transport, not data, and a page that rendered a `ping` as a packet would
   * be displaying a protocol artefact as an observation.
   */
  private handleFrame(raw: unknown): void {
    if (typeof raw !== 'string') {
      this.handlers.onInvalidFrame?.('a non-text frame was received')
      return
    }
    const event = parseServerEvent(raw)
    if (event === null) {
      this.handlers.onInvalidFrame?.('a frame was not a recognisable NetWatch event')
      return
    }

    if (event.type === EventType.PING) {
      const nonce = event.data.nonce
      this.send(keepaliveFrame(EventType.PONG, typeof nonce === 'string' ? nonce : undefined))
      return
    }
    if (event.type === EventType.PONG) return
    if (event.type === EventType.ERROR) {
      const reason = event.data.reason
      const field = event.data.field
      this.handlers.onRefusal?.({
        reason: typeof reason === 'string' ? reason : 'the server refused a message',
        field: typeof field === 'string' ? field : 'message',
      })
      return
    }

    // Deduplicate last, after the transport frames are dealt with: a repeated ping
    // must still be answered, and only a *data* event is what the tracker exists
    // to suppress (M15.29).
    if (!this.tracker.add(event.event_id)) return
    this.handlers.onEvent(event)
  }

  /** Queue a retry, or give up once the attempt budget is spent. */
  private scheduleReconnect(): void {
    if (this.stopped || this.timer !== null) return
    this.attempt += 1
    if (this.attempt > this.maxAttempts) {
      this.setPhase('closed')
      this.handlers.onClose?.()
      return
    }
    this.setPhase('reconnecting')
    const delay = backoffDelay(this.attempt, this.backoff)
    this.timer = this.setTimeoutFn(() => {
      this.timer = null
      if (this.stopped) return
      this.openSocket()
    }, delay)
  }
}
/** One listener on a channel. */
export interface ChannelSubscriber {
  /** A validated, not-yet-duplicated event from this channel. */
  readonly onEvent: (event: ServerEvent) => void
  /** The channel opened; `isReconnect` means state should be re-read from REST. */
  readonly onOpen?: (isReconnect: boolean) => void
  /** The connection phase changed. */
  readonly onPhase?: (phase: ConnectionPhase) => void
  /** The server refused a frame this client sent. */
  readonly onRefusal?: (refusal: RefusalEventData) => void
  /** A frame could not be parsed. Never thrown. */
  readonly onInvalidFrame?: (reason: string) => void
  /** The channel gave up reconnecting. */
  readonly onClose?: () => void
}

/** A live subscription. Calling {@link ChannelSubscription.unsubscribe} is idempotent. */
export interface ChannelSubscription {
  readonly channel: Channel
  /**
   * The shared socket behind this subscription.
   *
   * Exposed so a caller that owns the channel's lifecycle can send the one frame a
   * client is allowed to send. It is not for reading events — those arrive through
   * the subscriber callbacks, so every listener sees every event exactly once.
   */
  readonly socket: ChannelSocket
  unsubscribe(): void
}

/** One channel's shared socket and its listeners. */
interface ChannelEntry {
  readonly socket: ChannelSocket
  readonly subscribers: Set<ChannelSubscriber>
}

/**
 * One socket per channel, shared by every listener (M15.26).
 *
 * The reason this exists rather than each hook owning a socket: a page can mount
 * several components over one stream — the header badge and the table both want
 * `/ws/alerts` — and two sockets on one channel would double the server's work,
 * double the events the browser parses, and make deduplication a per-socket
 * concern instead of a per-channel one. Reference counting is what keeps the
 * connection alive exactly as long as somebody is listening.
 *
 * Closing is prompt on the last unsubscribe, because the alternative — a delay to
 * absorb remounts — would hold a server slot open for a page the user has left.
 * A remount therefore reconnects, which is correct: the socket reports it as a
 * reconnect and the hooks refresh from REST (M15.27).
 */
export class ChannelHub {
  private readonly entries = new Map<Channel, ChannelEntry>()

  /**
   * Start listening to `channel`, opening its socket if nobody was listening.
   *
   * `options` are applied only when the socket is created; a later subscriber
   * shares the existing connection rather than reconfiguring it, because a socket
   * cannot have two retry policies.
   */
  subscribe(
    channel: Channel,
    subscriber: ChannelSubscriber,
    options: ChannelSocketOptions = {},
  ): ChannelSubscription {
    let entry = this.entries.get(channel)
    if (entry === undefined) {
      const subscribers = new Set<ChannelSubscriber>()
      const socket = new ChannelSocket(
        channel,
        {
          onEvent: (event) => {
            for (const listener of subscribers) listener.onEvent(event)
          },
          onOpen: (isReconnect) => {
            for (const listener of subscribers) listener.onOpen?.(isReconnect)
          },
          onPhase: (phase) => {
            for (const listener of subscribers) listener.onPhase?.(phase)
          },
          onRefusal: (refusal) => {
            for (const listener of subscribers) listener.onRefusal?.(refusal)
          },
          onInvalidFrame: (reason) => {
            for (const listener of subscribers) listener.onInvalidFrame?.(reason)
          },
          onClose: () => {
            for (const listener of subscribers) listener.onClose?.()
          },
        },
        options,
      )
      entry = { socket, subscribers }
      this.entries.set(channel, entry)
      socket.connect()
    }

    entry.subscribers.add(subscriber)

    let released = false
    return {
      channel,
      socket: entry.socket,
      unsubscribe: (): void => {
        // Guarded so a React effect that unsubscribes twice — which StrictMode
        // does — cannot retire a channel another listener is still using.
        if (released) return
        released = true
        const current = this.entries.get(channel)
        if (current === undefined) return
        current.subscribers.delete(subscriber)
        if (current.subscribers.size === 0) {
          current.socket.close()
          this.entries.delete(channel)
        }
      },
    }
  }

  /** How many listeners a channel currently has. */
  subscriberCount(channel: Channel): number {
    return this.entries.get(channel)?.subscribers.size ?? 0
  }

  /** The shared socket for a channel, when one is open. */
  socketFor(channel: Channel): ChannelSocket | null {
    return this.entries.get(channel)?.socket ?? null
  }

  /** Close one channel, whatever its listener count. */
  closeChannel(channel: Channel): void {
    const entry = this.entries.get(channel)
    if (entry === undefined) return
    entry.subscribers.clear()
    entry.socket.close()
    this.entries.delete(channel)
  }

  /** Close every channel. Used on a full application teardown. */
  closeAll(): void {
    for (const entry of this.entries.values()) {
      entry.subscribers.clear()
      entry.socket.close()
    }
    this.entries.clear()
  }
}

/**
 * The application's one hub.
 *
 * A module-level singleton rather than context, because a socket is a process-wide
 * resource and a channel's identity does not depend on where in the tree it is
 * subscribed. It is also what makes the reference counting above meaningful: two
 * subtrees that never meet still share the connection.
 */
export const channelHub = new ChannelHub()
