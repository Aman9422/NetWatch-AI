/**
 * The socket a DOM test gets, so that a REST test cannot open a connection (M15.39).
 *
 * Why this exists at all, stated precisely, because "the integration test stubs the
 * thing it is integrating" is a fair objection:
 *
 * * The live run is **split by environment**. The files that exercise the real
 *   socket are `node`-environment files (`websocket.test.ts`), where the runtime's
 *   own `WebSocket` is the ambient global and every frame is real. The DOM files
 *   exercise the real REST API through the real pages, and the socket is not what
 *   is under test there.
 * * Under vitest's jsdom, a real socket **cannot be used cleanly**, and this was
 *   measured rather than assumed. Node's client builds the `open` event with the
 *   ambient `Event`, which the jsdom environment has replaced with jsdom's own
 *   class, and the runtime's `EventTarget` refuses an event from a foreign realm
 *   before any listener runs. The result is an unhandled `TypeError` on every
 *   connection — a failure in the harness, on a path the application never takes
 *   in a browser, which would fail the run for a reason that is not a defect.
 * * The repair was attempted and abandoned on evidence: neither a prototype
 *   override of `dispatchEvent` nor an **own-property** one was ever called, while
 *   the same socket's `readyState` reached `1` — so the failing dispatch
 *   demonstrably bypasses the instance, and no userland wrapper can intercept it.
 *
 * So this module does one thing: it makes the global constructor produce a socket
 * that cannot reach the network. It is **not a protocol fake** — it parses nothing,
 * emits nothing and fabricates no event, so a page under it can never render data
 * that came from here. A page that needs a live stream gets one only in the
 * `node` files and in the browser run (M15.40).
 *
 * The reason it is installed through `vi.stubGlobal` rather than by assigning to
 * the global is also measured: the environment exposes `WebSocket` as a
 * **getter/setter pair**, and a plain assignment is swallowed by it — after
 * `globalThis.WebSocket = X`, the global still reported the runtime's constructor.
 */

import { vi } from 'vitest'

/** The handshake state a socket reports while it is doing nothing. */
const CONNECTING = 0

/**
 * A `WebSocket`-shaped object that never connects.
 *
 * Shaped to the application's own expectations rather than to the full interface:
 * `ChannelSocket` calls `close`, `send` and reads `readyState`, and assigns the
 * four `on<type>` handlers. Everything else the DOM interface carries is absent on
 * purpose — an inert socket has no `bufferedAmount` to report and no `protocol` to
 * negotiate, and inventing plausible values for them would be exactly the kind of
 * fabrication this module exists to avoid.
 */
export class InertWebSocket {
  /** Always `CONNECTING`: no handshake is in flight and none will complete. */
  readonly readyState: number = CONNECTING

  /** The URL that was asked for, kept for a diagnostic. */
  readonly url: string

  onopen: ((event: Event) => void) | null = null
  onmessage: ((event: MessageEvent<unknown>) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  onclose: ((event: CloseEvent) => void) | null = null

  constructor(url: string | URL) {
    this.url = String(url)
  }

  /** Refuse to send, the way a socket that is not open does. */
  send(): boolean {
    return false
  }

  /** Idempotent teardown, so a page unmount is as quiet as a mount. */
  close(): void {}
}

/**
 * Point the ambient `WebSocket` at {@link InertWebSocket} for this test.
 *
 * Installed per test rather than once, because the live config restores stubbed
 * globals after each one (`unstubGlobals`), so a file that installed it once would
 * silently stop being covered after its first test.
 */
export function installInertWebSocket(): void {
  vi.stubGlobal('WebSocket', InertWebSocket)
}
