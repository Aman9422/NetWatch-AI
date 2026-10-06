/**
 * Device service (M8, M15.12).
 *
 * The device registry is an M8 observation of what was seen on the wire: an
 * identity, when it was first and last seen, and how much it sent and received.
 * Nothing here is a verdict, which is why this service exposes no risk or
 * severity field and the page that renders it must not invent one (M15.12).
 *
 * `status` is derived by the backend from last-seen timing (M8.9) — `active`,
 * `inactive` or `unknown` — and is an activity observation rather than a
 * security judgement. It is passed through unchanged.
 */

import { apiGet } from './client'
import { DevicePaths } from './endpoints'
import { withPageWindow, type PageWindow } from './query'
import type { Device, DevicePage, DeviceQuery } from '@/types'

/**
 * `GET /api/v1/devices` — a page of tracked devices (M13.10).
 *
 * `total` is present because the registry can count its rows, so a caller may
 * render "showing 50 of 137" without a second request.
 */
export function fetchDevices(
  query: DeviceQuery = {},
  window?: PageWindow,
  signal?: AbortSignal,
): Promise<DevicePage> {
  return apiGet<DevicePage>(DevicePaths.list, withPageWindow(query, window), { signal })
}

/**
 * `GET /api/v1/devices/{device_id}` — one device.
 *
 * Device ids contain a colon (`mac:aa:bb:...`), which the path builder encodes.
 * A device that has been forgotten since the listing answered produces a `404`,
 * which the caller renders as "no longer known" rather than as a failure.
 */
export function fetchDevice(deviceId: string, signal?: AbortSignal): Promise<Device> {
  return apiGet<Device>(DevicePaths.detail(deviceId), undefined, { signal })
}

/** Convenience: the first page of active devices only. */
export function fetchActiveDevices(
  window?: PageWindow,
  signal?: AbortSignal,
): Promise<DevicePage> {
  return fetchDevices({ status: 'active' }, window, signal)
}
