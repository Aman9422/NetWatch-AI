/**
 * Bounded client-side collections (M15.11/M15.36).
 *
 * Two hooks, because live data arrives in two genuinely different ways and one
 * abstraction would have to lie about one of them:
 *
 * * {@link useBoundedList} — an **append-only feed**. Packets are observations:
 *   each is a new row, none replaces another, and the only question is how many
 *   to keep. Newest first, so the table renders from the front.
 * * {@link useBoundedKeyedList} — a **mutable set keyed by id**. Alerts and
 *   incidents arrive as creations *and* as later lifecycle changes, and M15.14 is
 *   explicit that an update must modify the existing row rather than add a second
 *   one. Keyed replacement is the whole point.
 *
 * Bounding is not an optimisation here, it is a correctness requirement. The
 * packets channel is a continuous stream: a page left open for an hour against a
 * busy interface would otherwise hold hundreds of thousands of objects in React
 * state, and every render would copy that array. A fixed capacity makes memory a
 * function of configuration rather than of uptime.
 *
 * Eviction is from the **oldest** end, which is the right end for both hooks: the
 * newest observation is the one an operator is looking at.
 */

import { useCallback, useState } from 'react'

/** Lowest capacity accepted, so a mistyped `0` cannot hide every row. */
export const MIN_BOUNDED_CAPACITY = 1

/** Normalise a capacity to a usable integer. */
function normaliseCapacity(capacity: number): number {
  if (!Number.isFinite(capacity)) return MIN_BOUNDED_CAPACITY
  return Math.max(MIN_BOUNDED_CAPACITY, Math.floor(capacity))
}

/** An append-only, newest-first, capacity-limited feed. */
export interface BoundedList<T> {
  /** The retained items, newest first. */
  readonly items: readonly T[]
  /** How many items are retained. */
  readonly size: number
  /** Add one item at the front. */
  readonly prepend: (item: T) => void
  /**
   * Add a batch at the front.
   *
   * `batch` is read in **arrival order** — its last element is the newest — so a
   * burst that the browser received as an array ends up in the same order it was
   * observed. Passing a newest-first array here would reverse the rendering order.
   */
  readonly prependMany: (batch: readonly T[]) => void
  /** Replace the whole list, e.g. from a REST read. Bounded the same way. */
  readonly replace: (items: readonly T[]) => void
  /** Remove everything. */
  readonly clear: () => void
}

/**
 * Keep the most recent `capacity` values of an append-only feed.
 *
 * @param capacity How many to retain. Rounded up to at least one.
 */
export function useBoundedList<T>(capacity: number): BoundedList<T> {
  const limit = normaliseCapacity(capacity)
  const [items, setItems] = useState<readonly T[]>([])

  const prepend = useCallback(
    (item: T) => {
      setItems((current) => {
        const next = [item, ...current]
        return next.length > limit ? next.slice(0, limit) : next
      })
    },
    [limit],
  )

  const prependMany = useCallback(
    (batch: readonly T[]) => {
      if (batch.length === 0) return
      setItems((current) => {
        // `slice().reverse()` rather than `toReversed()`: the newest of the batch
        // must come first, and the copy avoids mutating the caller's array.
        const newestFirst = batch.slice().reverse()
        const next = [...newestFirst, ...current]
        return next.length > limit ? next.slice(0, limit) : next
      })
    },
    [limit],
  )

  const replace = useCallback(
    (next: readonly T[]) => {
      setItems(next.length > limit ? next.slice(0, limit) : next)
    },
    [limit],
  )

  const clear = useCallback(() => {
    setItems([])
  }, [])

  return { items, size: items.length, prepend, prependMany, replace, clear }
}

/** A keyed, newest-first, capacity-limited set. */
export interface BoundedKeyedList<T> {
  /** The retained items, newest first. */
  readonly items: readonly T[]
  /** How many items are retained. */
  readonly size: number
  /**
   * Insert or replace one item, matched by its key.
   *
   * A key that is already present is **replaced in place** — its position is kept,
   * so a row does not jump to the top of the table merely because its status
   * changed. A new key is prepended.
   */
  readonly upsert: (item: T) => void
  /** Insert or replace a batch, applying the same rule to each. */
  readonly upsertMany: (batch: readonly T[]) => void
  /** Replace the whole set, e.g. after a reconnect. */
  readonly replace: (items: readonly T[]) => void
  /** Remove everything. */
  readonly clear: () => void
}

/**
 * Keep the most recent `capacity` items of a set addressed by a stable key.
 *
 * @param capacity How many to retain.
 * @param keyOf Returns the identity of an item. Must be stable for a given item —
 *   for an alert that is `alert_id`, and for an incident `incident_id`.
 */
export function useBoundedKeyedList<T>(
  capacity: number,
  keyOf: (item: T) => string,
): BoundedKeyedList<T> {
  const limit = normaliseCapacity(capacity)
  const [items, setItems] = useState<readonly T[]>([])

  const upsert = useCallback(
    (item: T) => {
      setItems((current) => {
        const key = keyOf(item)
        const index = current.findIndex((existing) => keyOf(existing) === key)
        if (index === -1) {
          const next = [item, ...current]
          return next.length > limit ? next.slice(0, limit) : next
        }
        const next = current.slice()
        next[index] = item
        return next
      })
    },
    // `keyOf` is a caller-supplied selector; a page passes a module-level function
    // or an inline arrow. Reading it through the dependency list keeps the callback
    // honest without forcing every caller to memoise it.
    [keyOf, limit],
  )

  const upsertMany = useCallback(
    (batch: readonly T[]) => {
      if (batch.length === 0) return
      setItems((current) => {
        let next = current
        for (const item of batch) {
          const key = keyOf(item)
          const index = next.findIndex((existing) => keyOf(existing) === key)
          if (index === -1) {
            next = [item, ...next]
          } else {
            const copy = next.slice()
            copy[index] = item
            next = copy
          }
        }
        return next.length > limit ? next.slice(0, limit) : next
      })
    },
    [keyOf, limit],
  )

  const replace = useCallback(
    (incoming: readonly T[]) => {
      setItems(incoming.length > limit ? incoming.slice(0, limit) : incoming)
    },
    [limit],
  )

  const clear = useCallback(() => {
    setItems([])
  }, [])

  return { items, size: items.length, upsert, upsertMany, replace, clear }
}
