/**
 * Local AI status and installed models (M23.11).
 *
 * One hook rather than two, because the page needs both at the same moment and
 * neither is meaningful alone: "ready" with no model list is unhelpful, and a model
 * list without the state cannot say whether the runtime answered.
 *
 * **The status read is the authority; the model list is enrichment.** `/ai/status`
 * always answers `200` with a state, so it cannot fail for the reason the feature is
 * disabled or the runtime is down. `/ai/models` *can* fail there, because it is a
 * real inventory request. So this hook exposes the models as a best-effort result
 * and never lets their absence turn a readable state into a blank page.
 *
 * A local model's availability is not a stream, so there is no channel subscription
 * here: the state changes when an operator starts a service or pulls a model, which
 * is slower than a page. An explicit reload is the honest cadence, as
 * `useBaselines` and `useAnomalies` do (M15.34).
 */

import { useMemo } from 'react'
import { fetchAiModels, fetchAiStatus } from '@/services'
import type { ApiError } from '@/services'
import type { AiModel, AiModelList, AiState, AiStatus } from '@/types'
import { useAsyncResource } from './useAsyncResource'

/** What {@link useAiStatus} returns. */
export interface AiStatusResource {
  /** The status payload, or `null` before the first response. */
  readonly status: AiStatus | null
  /** The current state, or `null` before the first response. */
  readonly state: AiState | null
  /** Whether local AI is enabled by configuration. */
  readonly enabled: boolean
  /** The configured model name. */
  readonly configuredModel: string
  /** The models the runtime actually reports. Empty when the listing failed. */
  readonly models: readonly AiModel[]
  /** The listing payload, for its `configured_model_installed` flag. */
  readonly modelList: AiModelList | null
  /**
   * Why the model listing failed, when it did.
   *
   * Separate from `error` because a failed listing does not block the page: the
   * status call already answered, and its state says whether the runtime is up.
   */
  readonly modelsError: ApiError | null
  /** The failure that is blocking the view. */
  readonly blockingError: ApiError | null
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  /** True while a reload is in flight over existing content. */
  readonly isRefreshing: boolean
  readonly reload: () => void
}

/** Stable dependency key, so an inline literal cannot restart the request. */
const STATUS_DEPS = ['ai-status'] as const

/**
 * Read the local AI state and inventory.
 *
 * @param enabled When false nothing is requested — for a page that is not open.
 */
export function useAiStatus(enabled = true): AiStatusResource {
  const statusResource = useAsyncResource(
    (signal) => fetchAiStatus(signal),
    STATUS_DEPS,
    { enabled },
  )

  // The listing is only attempted once the status says the runtime is up. Asking
  // for an inventory from a disabled or unreachable runtime would produce a second
  // failure for the same cause, which the page would have to explain twice.
  const canList = enabled && statusResource.data?.runtime_reachable === true
  const listKey = useMemo(
    () => `ai-models:${String(canList)}`,
    [canList],
  )
  const modelsResource = useAsyncResource(
    (signal) =>
      canList
        ? fetchAiModels(signal)
        : Promise.resolve<AiModelList>({
            count: 0,
            configured_model: '',
            configured_model_installed: false,
            models: [],
            disclaimer: '',
          }),
    [listKey],
    { enabled: canList },
  )

  return {
    status: statusResource.data,
    state: statusResource.data?.state ?? null,
    enabled: statusResource.data?.enabled ?? false,
    configuredModel: statusResource.data?.model ?? '',
    models: modelsResource.data?.models ?? [],
    modelList: modelsResource.data,
    modelsError: modelsResource.error,
    blockingError: statusResource.blockingError,
    isLoading: statusResource.isLoading,
    isInitialLoading: statusResource.isInitialLoading,
    isRefreshing: statusResource.isLoading && !statusResource.isInitialLoading,
    reload: () => {
      statusResource.reload()
      modelsResource.reload()
    },
  }
}
