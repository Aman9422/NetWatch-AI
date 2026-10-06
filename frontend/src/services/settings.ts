/**
 * Settings service (M13.21, M15.23).
 *
 * Three sets exist server-side and this module respects all three without
 * restating them: **readable** keys are listed, **mutable** keys are the only
 * ones `PUT` accepts, and **internal-only** keys are never listed and never
 * readable. The frontend does not decide which is which — `SettingList` reports
 * `mutable` per setting and `mutable_keys` as the whole writable set, and a page
 * renders those rather than holding its own list.
 *
 * Two consequences a page must honour:
 *
 * * **An internal key is answered exactly like an unknown one.** Distinguishing
 *   them would confirm that a credential is stored under that name, which is the
 *   leak the endpoint exists to prevent. The UI shows "not found" and does not
 *   speculate.
 * * **`restart_required` is displayed, not ignored.** Stored settings are read at
 *   application startup, so a successful `PUT` does *not* reconfigure the running
 *   process. The response says so, and the page must say so too instead of
 *   implying the change took effect (M15.23).
 */

import { apiGet, apiPut } from './client'
import { SettingPaths } from './endpoints'
import type { Setting, SettingList, SettingUpdateResult } from '@/types'

/** A writable value: the scalar kinds the settings API accepts. */
export type WritableSettingValue = string | number | boolean

/** A batch of changes, keyed by setting name. */
export type SettingValues = Readonly<Record<string, WritableSettingValue>>

/** `GET /api/v1/settings` — every readable setting, ordered by key (M13.21). */
export function fetchSettings(signal?: AbortSignal): Promise<SettingList> {
  return apiGet<SettingList>(SettingPaths.list, undefined, { signal })
}

/**
 * `GET /api/v1/settings/{key}` — one readable setting.
 *
 * An internal-only key and an unknown key both answer `404`; the caller must not
 * distinguish them, because doing so would confirm what is stored.
 */
export function fetchSetting(key: string, signal?: AbortSignal): Promise<Setting> {
  return apiGet<Setting>(SettingPaths.detail(key), undefined, { signal })
}

/**
 * `PUT /api/v1/settings` — validate and store a batch of changes (M13.21).
 *
 * The whole request is validated before anything is written, so it either applies
 * completely or changes nothing. Two refusals the caller must render rather than
 * retry: an unknown or internal-only key is a `400 INVALID_SETTING`, and a key
 * that is readable but not writable is a `409 IMMUTABLE_SETTING`. Collapsing
 * those into "it failed" would hide a typo behind a policy refusal.
 */
export function updateSettings(
  values: SettingValues,
  signal?: AbortSignal,
): Promise<SettingUpdateResult> {
  return apiPut<SettingUpdateResult>(SettingPaths.list, { body: { values }, signal })
}

/**
 * True when a settings response says the change needs a restart.
 *
 * A named helper rather than an inline `=== true`, because the field is the
 * single most important part of the response: a page that forgot to check it
 * would tell an operator their change was live when it was only stored.
 */
export function requiresRestart(result: SettingUpdateResult): boolean {
  return result.restart_required === true
}
