/**
 * The baseline reset action (M21.11).
 *
 * A thin wrapper over `useAction` rather than a bespoke hook: the reset is a plain
 * POST whose outcome the backend describes, so all it needs is the shared write
 * primitive's progress, failure and result tracking.
 *
 * Two properties are the caller's to honour, and this hook deliberately does not
 * hide them:
 *
 * * **`run` resolves with a discriminated result.** A caller must handle the
 *   failure branch to read the value, so a reset the backend refused cannot be
 *   reported as having succeeded (M15.15).
 * * **`windows_deleted` and `profile_deleted` are reported, not assumed.** The
 *   endpoint answers `200` even when there was nothing to delete, so the page
 *   words its confirmation from those two fields rather than from the status code.
 *   A reset against a device with no windows genuinely deleted nothing, and saying
 *   otherwise would be a false report of an action (M21.10).
 */

import { useAction } from './useAction'
import type { ActionResource } from './useAction'
import { resetBaseline } from '@/services'
import type { BaselineResetResult } from '@/types'

/** What {@link useResetBaseline} returns: an action taking one device key. */
export type ResetBaselineResource = ActionResource<
  readonly [deviceKey: string],
  BaselineResetResult
>

/**
 * Delete one device's baseline so learning restarts.
 *
 * The returned `run` takes the device key, so a single hook instance can reset any
 * row on the page. The operation touches only the two M21 tables — packets,
 * devices, alerts, incidents, connections and reports are unaffected, which the
 * response's `message` states.
 */
export function useResetBaseline(): ResetBaselineResource {
  return useAction(async (deviceKey: string) => resetBaseline(deviceKey))
}
