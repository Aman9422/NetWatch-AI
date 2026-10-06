/**
 * Runtime settings (M15.23).
 *
 * The backend decides which keys exist, which are readable and which are
 * writable, and this hook re-decides none of it. `SettingList` reports `mutable`
 * per setting and `mutable_keys` as the whole writable set; a page renders those
 * and offers no control for a key the backend did not mark writable — an
 * internal-only key is answered exactly like an unknown one, and the frontend
 * must not try to tell them apart (M13.21/M15.23).
 *
 * The one behaviour a page must get right is **`restart_required`**. A successful
 * `PUT` stores the value but does *not* reconfigure the running process, because
 * stored settings are read at startup. {@link SettingsResource.restartRequired}
 * carries that flag so the page can say "stored; restart to apply" instead of
 * implying the change is live.
 *
 * There is no WebSocket channel for settings, so a change made elsewhere reaches
 * this page only on an explicit reload (M15.34).
 */

import { useCallback, useMemo } from 'react'
import { fetchSettings, updateSettings } from '@/services'
import type {
  ApiError,
  SettingValues,
  WritableSettingValue,
} from '@/services'
import type { Setting, SettingList, SettingUpdateResult } from '@/types'
import { useAction } from './useAction'
import { useAsyncResource } from './useAsyncResource'

/** What {@link useSettings} returns. */
export interface SettingsResource {
  readonly settings: readonly Setting[]
  readonly page: SettingList | null
  /** The keys the backend will accept in a write, straight from the response. */
  readonly mutableKeys: readonly string[]
  /** How many stored keys are withheld as internal-only. */
  readonly internalKeyCount: number
  readonly error: ApiError | null
  /** The failure that is blocking the view — see `useAsyncResource`. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  readonly isRefreshing: boolean
  /** True when the backend reports no readable setting at all. */
  readonly isEmpty: boolean
  readonly reload: () => void
  /** True while a save is in flight. */
  readonly isSaving: boolean
  /** The last save refusal, or `null`. */
  readonly saveError: ApiError | null
  /** True when the most recent successful save needs a restart to take effect. */
  readonly restartRequired: boolean
  /**
   * Store a batch of changes.
   *
   * Resolves `null` on success or the refusal. The whole batch is validated
   * before anything is written, so a refusal changes nothing. On success the
   * listing is reloaded, because the store — not this response alone — is the
   * source of truth for what is now stored.
   */
  readonly save: (values: SettingValues) => Promise<ApiError | null>
}

/**
 * Read and write runtime settings.
 *
 * @param options Whether to read at all.
 */
export function useSettings(
  options: { readonly enabled?: boolean } = {},
): SettingsResource {
  const { enabled = true } = options

  const resource = useAsyncResource((signal) => fetchSettings(signal), [], {
    enabled,
    isEmpty: (list: SettingList) => list.settings.length === 0,
  })

  const saveAction = useAction(updateSettings)
  const { reload } = resource

  const save = useCallback(
    async (values: SettingValues): Promise<ApiError | null> => {
      const outcome = await saveAction.run(values)
      if (!outcome.ok) return outcome.error
      // The store is authoritative for what was written, so it is re-read rather
      // than patched from the response — which carries only the changed keys.
      reload()
      return null
    },
    [reload, saveAction],
  )

  const restartRequired = useMemo(() => {
    const last: SettingUpdateResult | null = saveAction.result
    return last?.restart_required === true
  }, [saveAction.result])

  const page = resource.data

  return {
    settings: page?.settings ?? [],
    page,
    mutableKeys: page?.mutable_keys ?? [],
    internalKeyCount: page?.internal_key_count ?? 0,
    error: resource.error,
    blockingError: resource.blockingError,
    isLoading: resource.isLoading,
    isInitialLoading: resource.isInitialLoading,
    isRefreshing: resource.isLoading && !resource.isInitialLoading,
    isEmpty: page !== null && page.settings.length === 0,
    reload,
    isSaving: saveAction.isRunning,
    saveError: saveAction.error,
    restartRequired,
    save,
  }
}

/** Re-exported so a page can name a writable value without a second import. */
export type { WritableSettingValue }
