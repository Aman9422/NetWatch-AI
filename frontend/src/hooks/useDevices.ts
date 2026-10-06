/**
 * Tracked devices (M15.12).
 *
 * A plain REST listing: M8 publishes no device WebSocket channel, so there is
 * nothing to subscribe to and no polling to justify either — the page offers an
 * explicit refresh, which is the honest cadence for a registry that changes when
 * a device appears on the wire (M15.34).
 *
 * **No risk score is read, because none exists.** M8 discovers and tracks; it
 * does not judge. `status` is an M8 *activity* observation derived from last-seen
 * timing, and the page that renders it must not present it as a verdict
 * (M15.12).
 *
 * The filter is keyed by its **serialised form**, not its object identity. A page
 * naturally builds `{ status: selected }` inline, which is a new object on every
 * render; using it directly as a dependency would re-request the listing on every
 * render, forever.
 */

import { useMemo } from 'react'
import { fetchDevices } from '@/services'
import type { ApiError, PageWindow } from '@/services'
import type { Device, DevicePage, DeviceQuery } from '@/types'
import { useAsyncResource } from './useAsyncResource'

/** Options for {@link useDevices}. */
export interface DeviceListOptions {
  /** Filters to apply. May be built inline; it is compared by value. */
  readonly query?: DeviceQuery
  /** Page window. Compared by value, like the filter. */
  readonly window?: PageWindow
  /** When False nothing is requested. */
  readonly enabled?: boolean
}

/** What {@link useDevices} returns. */
export interface DeviceListResource {
  readonly devices: readonly Device[]
  /** The full page, for its `total` and `has_more`. */
  readonly page: DevicePage | null
  /** The true match count, when the registry could count it. */
  readonly total: number | null
  /** True when a further page exists. */
  readonly hasMore: boolean
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  /** True while a reload is in flight over existing content. */
  readonly isRefreshing: boolean
  /** True when the registry answered with no rows. */
  readonly isEmpty: boolean
  readonly reload: () => void
}

/**
 * Read the device registry.
 *
 * @param options Filters, page window, and whether to read at all.
 */
export function useDevices(options: DeviceListOptions = {}): DeviceListResource {
  const { query, window, enabled = true } = options

  // Serialised so an inline object literal — the common case — does not restart
  // the request on every render. Key order is fixed by constructing the key from
  // the known fields rather than from `Object.keys`.
  const cacheKey = useMemo(
    () =>
      JSON.stringify({
        status: query?.status ?? null,
        ip: query?.ip ?? null,
        mac: query?.mac ?? null,
        limit: window?.limit ?? null,
        offset: window?.offset ?? null,
      }),
    [query, window],
  )

  const resource = useAsyncResource(
    (signal) => fetchDevices(query ?? {}, window, signal),
    [cacheKey],
    {
      enabled,
      isEmpty: (page: DevicePage) => page.devices.length === 0,
    },
  )

  return {
    devices: resource.data?.devices ?? [],
    page: resource.data,
    total: resource.data?.total ?? null,
    hasMore: resource.data?.has_more === true,
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    isEmpty: resource.data !== null && resource.data.devices.length === 0,
    reload: resource.reload,
  }
}
