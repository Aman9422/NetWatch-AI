/**
 * The retained live-packet buffer (M23.1).
 *
 * Why this is not `useState` inside the page: **stopping capture means leaving
 * Live Traffic.** Start and Stop live on the Dashboard's Capture Control panel, and
 * M15.35 deliberately unmounts a page on a route change so its subscriptions
 * close. A buffer held in page-local state was therefore destroyed at exactly the
 * moment an operator would want to look at it — pressing Stop blanked the table
 * they had just been reading.
 *
 * So the rows live here, at module scope, and outlive the component. Two limits
 * are kept deliberately:
 *
 * * **The socket is still closed on unmount.** Keeping the connection open from a
 *   page you are not looking at would collect traffic for a route that is not
 *   rendered, which is the thing M15.35 exists to prevent. Rows observed while the
 *   page was open are kept; rows observed while it was not are not, and nothing
 *   pretends otherwise.
 * * **The buffer is bounded, and per document.** It is a session-scoped cache, not
 *   storage: a reload starts empty, because nothing here is persisted and a table
 *   that survived a reload would imply a replay buffer the backend does not have
 *   (M15.11).
 *
 * The shape is the smallest one `useSyncExternalStore` needs — `subscribe` and a
 * `getSnapshot` that returns a **stable reference** until something actually
 * changes, which is why the array is replaced rather than mutated.
 */

import type { PacketEventData } from '@/types'
import { normaliseCapacity } from './useBoundedList'

/** How many live packets are retained. Roughly a screenful and a half of scroll. */
export const DEFAULT_PACKET_BUFFER_CAPACITY = 500

/** A bounded, newest-first, subscribable packet buffer. */
export class PacketBuffer {
  private entries: readonly PacketEventData[] = []
  private readonly listeners = new Set<() => void>()
  private limit: number

  constructor(capacity: number = DEFAULT_PACKET_BUFFER_CAPACITY) {
    this.limit = normaliseCapacity(capacity)
  }

  /** How many rows are retained at most. */
  get capacity(): number {
    return this.limit
  }

  /**
   * The retained rows, newest first.
   *
   * A stable reference between mutations, as `useSyncExternalStore` requires: a
   * fresh array on every call would make every render look changed.
   */
  readonly getSnapshot = (): readonly PacketEventData[] => this.entries

  /** Listen for changes. Returns the unsubscribe. */
  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  /** Add one observation at the front, evicting the oldest past the bound. */
  readonly prepend = (packet: PacketEventData): void => {
    const next = [packet, ...this.entries]
    this.entries = next.length > this.limit ? next.slice(0, this.limit) : next
    this.emit()
  }

  /** Remove every retained row. */
  readonly clear = (): void => {
    if (this.entries.length === 0) return
    this.entries = []
    this.emit()
  }

  /**
   * Apply a new bound, trimming immediately if it is smaller.
   *
   * Called by the hook so a caller-supplied `capacity` is honoured rather than
   * silently ignored in favour of the default the module was created with.
   */
  readonly setCapacity = (capacity: number): void => {
    const limit = normaliseCapacity(capacity)
    if (limit === this.limit) return
    this.limit = limit
    if (this.entries.length > limit) {
      this.entries = this.entries.slice(0, limit)
      this.emit()
    }
  }

  private emit(): void {
    for (const listener of this.listeners) listener()
  }
}

/** The one buffer the application uses. */
export const packetBuffer = new PacketBuffer()
