/**
 * Bounded client-side collections (M15.11/M15.36, M15.38).
 *
 * M15.36 asks that the packet table, the alert list and the connection list "must
 * not grow indefinitely". These two hooks are where that promise is kept, so the
 * assertions are about the bound itself: the exact capacity, which end is evicted,
 * and — the part that is easy to get wrong — that eviction is from the *oldest*
 * end rather than the newest, because the newest observation is the one the
 * operator is looking at.
 *
 * The keyed variant carries a second promise from M15.14: a lifecycle change must
 * modify the existing row rather than add a second one. That is asserted by count,
 * not by inspecting the row, because a duplicate row is the actual bug.
 */

import { act, renderHook } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { MIN_BOUNDED_CAPACITY, useBoundedKeyedList, useBoundedList } from '@/hooks'

/** A minimal row with an identity, standing in for a packet or an alert. */
interface Row {
  readonly id: string
  readonly label: string
}

/** Build a row from its id, so the identity is easy to see in an assertion. */
function row(id: string): Row {
  return { id, label: `row ${id}` }
}

describe('useBoundedList', () => {
  it('starts empty', () => {
    const { result } = renderHook(() => useBoundedList<Row>(10))
    expect(result.current.items).toEqual([])
    expect(result.current.size).toBe(0)
  })

  it('prepends, so the newest item is first', () => {
    const { result } = renderHook(() => useBoundedList<Row>(10))
    act(() => {
      result.current.prepend(row('a'))
    })
    act(() => {
      result.current.prepend(row('b'))
    })
    expect(result.current.items.map((item) => item.id)).toEqual(['b', 'a'])
  })

  it('never exceeds its capacity', () => {
    // The property M15.36 names. Without it a page left open against a busy
    // interface holds every packet it has ever seen.
    const { result } = renderHook(() => useBoundedList<Row>(3))
    act(() => {
      for (const id of ['a', 'b', 'c', 'd', 'e', 'f', 'g']) {
        result.current.prepend(row(id))
      }
    })
    expect(result.current.items).toHaveLength(3)
    expect(result.current.size).toBe(3)
  })

  it('evicts the oldest, keeping the newest', () => {
    const { result } = renderHook(() => useBoundedList<Row>(3))
    act(() => {
      for (const id of ['a', 'b', 'c', 'd']) {
        result.current.prepend(row(id))
      }
    })
    expect(result.current.items.map((item) => item.id)).toEqual(['d', 'c', 'b'])
  })

  it('keeps a capacity of one usable rather than hiding every row', () => {
    const { result } = renderHook(() => useBoundedList<Row>(1))
    act(() => {
      result.current.prepend(row('a'))
      result.current.prepend(row('b'))
    })
    expect(result.current.items.map((item) => item.id)).toEqual(['b'])
  })

  it('reads a batch in arrival order and puts its newest first', () => {
    // `prependMany` exists for a burst the browser received as an array. Reading
    // it as newest-first would reverse the rendering order, which is the mistake
    // the arrival-order rule prevents.
    const { result } = renderHook(() => useBoundedList<Row>(10))
    act(() => {
      result.current.prependMany([row('old'), row('middle'), row('new')])
    })
    expect(result.current.items.map((item) => item.id)).toEqual(['new', 'middle', 'old'])
  })

  it('bounds a batch that is larger than the capacity', () => {
    const { result } = renderHook(() => useBoundedList<Row>(2))
    act(() => {
      result.current.prependMany([row('a'), row('b'), row('c'), row('d')])
    })
    expect(result.current.items.map((item) => item.id)).toEqual(['d', 'c'])
  })

  it('does nothing for an empty batch, rather than re-rendering', () => {
    const { result } = renderHook(() => useBoundedList<Row>(5))
    act(() => {
      result.current.prependMany([])
    })
    expect(result.current.items).toEqual([])
  })

  it('does not mutate the caller\'s batch array', () => {
    const batch = [row('a'), row('b')]
    const { result } = renderHook(() => useBoundedList<Row>(5))
    act(() => {
      result.current.prependMany(batch)
    })
    expect(batch.map((item) => item.id)).toEqual(['a', 'b'])
  })

  it('bounds a whole replacement, e.g. a REST read that returned too much', () => {
    const { result } = renderHook(() => useBoundedList<Row>(2))
    act(() => {
      result.current.replace([row('a'), row('b'), row('c')])
    })
    expect(result.current.items.map((item) => item.id)).toEqual(['a', 'b'])
  })

  it('replaces the feed from a REST read, keeping the caller\'s order', () => {
    const { result } = renderHook(() => useBoundedList<Row>(10))
    act(() => {
      result.current.replace([row('newest'), row('older')])
    })
    // `replace` does not reverse: a stored packet list already arrives newest
    // first, and reversing it again would show the oldest row at the top.
    expect(result.current.items.map((item) => item.id)).toEqual(['newest', 'older'])
  })

  it('clears everything', () => {
    const { result } = renderHook(() => useBoundedList<Row>(10))
    act(() => {
      result.current.prepend(row('a'))
    })
    act(() => {
      result.current.clear()
    })
    expect(result.current.items).toEqual([])
  })

  it('normalises a nonsensical capacity instead of hiding every row', () => {
    // A `0` here would be a table that silently never shows anything, which is
    // far harder to diagnose than an obviously wrong bound of one.
    for (const capacity of [0, -5, Number.NaN]) {
      const { result } = renderHook(() => useBoundedList<Row>(capacity))
      act(() => {
        result.current.prepend(row('a'))
      })
      expect(result.current.items).toHaveLength(MIN_BOUNDED_CAPACITY)
    }
  })

  it('floors a fractional capacity', () => {
    const { result } = renderHook(() => useBoundedList<Row>(2.9))
    act(() => {
      for (const id of ['a', 'b', 'c']) result.current.prepend(row(id))
    })
    expect(result.current.items).toHaveLength(2)
  })

  it('keeps the retained rows bounded across a long stream', () => {
    // The shape of the real packets channel: a continuous stream against a fixed
    // bound. Memory is a function of configuration, not of uptime.
    const { result } = renderHook(() => useBoundedList<Row>(50))
    act(() => {
      for (let index = 0; index < 2_000; index += 1) {
        result.current.prepend(row(String(index)))
      }
    })
    expect(result.current.items).toHaveLength(50)
    // And the newest 50 are the ones retained.
    expect(result.current.items[0]?.id).toBe('1999')
    expect(result.current.items[49]?.id).toBe('1950')
  })
})

describe('useBoundedKeyedList', () => {
  const keyOf = (item: Row): string => item.id

  it('starts empty', () => {
    const { result } = renderHook(() => useBoundedKeyedList<Row>(10, keyOf))
    expect(result.current.items).toEqual([])
    expect(result.current.size).toBe(0)
  })

  it('prepends a new key', () => {
    const { result } = renderHook(() => useBoundedKeyedList<Row>(10, keyOf))
    act(() => {
      result.current.upsert(row('a'))
      result.current.upsert(row('b'))
    })
    expect(result.current.items.map((item) => item.id)).toEqual(['b', 'a'])
  })

  it('replaces an existing key in place instead of adding a second row', () => {
    // M15.14: an `alert.updated` event must modify the row it names. A duplicate
    // row is the bug, so the assertion is on the count.
    const { result } = renderHook(() => useBoundedKeyedList<Row>(10, keyOf))
    act(() => {
      result.current.upsert({ id: 'a', label: 'first' })
      result.current.upsert({ id: 'b', label: 'other' })
    })
    act(() => {
      result.current.upsert({ id: 'a', label: 'updated' })
    })
    expect(result.current.items).toHaveLength(2)
    expect(result.current.items.find((item) => item.id === 'a')?.label).toBe('updated')
  })

  it('keeps a changed row in its original position', () => {
    // A row that jumped to the top merely because its status changed would make the
    // table unusable to read while alerts are being acknowledged.
    const { result } = renderHook(() => useBoundedKeyedList<Row>(10, keyOf))
    act(() => {
      result.current.upsert(row('a'))
      result.current.upsert(row('b'))
      result.current.upsert(row('c'))
    })
    act(() => {
      result.current.upsert({ id: 'b', label: 'changed' })
    })
    expect(result.current.items.map((item) => item.id)).toEqual(['c', 'b', 'a'])
  })

  it('never exceeds its capacity', () => {
    const { result } = renderHook(() => useBoundedKeyedList<Row>(3, keyOf))
    act(() => {
      for (const id of ['a', 'b', 'c', 'd', 'e']) result.current.upsert(row(id))
    })
    expect(result.current.items).toHaveLength(3)
    expect(result.current.items.map((item) => item.id)).toEqual(['e', 'd', 'c'])
  })

  it('upserts a batch, replacing matches and prepending newcomers', () => {
    const { result } = renderHook(() => useBoundedKeyedList<Row>(10, keyOf))
    act(() => {
      result.current.upsert(row('a'))
    })
    act(() => {
      result.current.upsertMany([
        { id: 'a', label: 'updated' },
        row('b'),
      ])
    })
    expect(result.current.items).toHaveLength(2)
    expect(result.current.items.find((item) => item.id === 'a')?.label).toBe('updated')
    expect(result.current.items.map((item) => item.id).sort()).toEqual(['a', 'b'])
  })

  it('does nothing for an empty batch', () => {
    const { result } = renderHook(() => useBoundedKeyedList<Row>(5, keyOf))
    act(() => {
      result.current.upsertMany([])
    })
    expect(result.current.items).toEqual([])
  })

  it('bounds a batch that is larger than the capacity', () => {
    const { result } = renderHook(() => useBoundedKeyedList<Row>(2, keyOf))
    act(() => {
      result.current.upsertMany([row('a'), row('b'), row('c')])
    })
    expect(result.current.items).toHaveLength(2)
  })

  it('bounds and replaces the whole set, e.g. after a reconnect', () => {
    // M15.27: after a reconnect a page re-reads REST. That read is authoritative,
    // so it replaces the set rather than merging into it.
    const { result } = renderHook(() => useBoundedKeyedList<Row>(2, keyOf))
    act(() => {
      result.current.upsert(row('stale'))
    })
    act(() => {
      result.current.replace([row('a'), row('b'), row('c')])
    })
    expect(result.current.items.map((item) => item.id)).toEqual(['a', 'b'])
  })

  it('clears everything', () => {
    const { result } = renderHook(() => useBoundedKeyedList<Row>(5, keyOf))
    act(() => {
      result.current.upsert(row('a'))
    })
    act(() => {
      result.current.clear()
    })
    expect(result.current.items).toEqual([])
  })

  it('normalises a nonsensical capacity the same way as the feed', () => {
    const { result } = renderHook(() => useBoundedKeyedList<Row>(0, keyOf))
    act(() => {
      result.current.upsert(row('a'))
    })
    expect(result.current.items).toHaveLength(MIN_BOUNDED_CAPACITY)
  })

  it('stays bounded under a long stream of distinct keys', () => {
    const { result } = renderHook(() => useBoundedKeyedList<Row>(25, keyOf))
    act(() => {
      for (let index = 0; index < 500; index += 1) {
        result.current.upsert(row(String(index)))
      }
    })
    expect(result.current.items).toHaveLength(25)
  })

  it('stays bounded under repeated updates of the same key', () => {
    // Acknowledging the same alert over and over must not accumulate rows.
    const { result } = renderHook(() => useBoundedKeyedList<Row>(5, keyOf))
    act(() => {
      for (let index = 0; index < 200; index += 1) {
        result.current.upsert({ id: 'a', label: `change ${index}` })
      }
    })
    expect(result.current.items).toHaveLength(1)
    expect(result.current.items[0]?.label).toBe('change 199')
  })
})
