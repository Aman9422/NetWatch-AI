/**
 * Capture control (M15.9/M15.41).
 *
 * The capture state has **three writers**, and that is the whole reason this hook
 * exists rather than a `useAsyncResource` call:
 *
 * 1. `GET /capture/status` reads it;
 * 2. `POST /capture/start` and `/stop` **return the new status**, which is
 *    authoritative and arrives before any event does;
 * 3. `/ws/system` announces `capture.started`, `capture.stopped` and
 *    `capture.error` — including for a session this browser did not start.
 *
 * A hook that only knew about (1) would show a stale state whenever a session was
 * started from elsewhere, and one that ignored (2) would show the old state for
 * the whole round trip of its own action. Applying all three to one piece of state
 * is the honest model, and it is why `status` is not a `useAsyncResource`.
 *
 * Two things this hook deliberately does **not** do:
 *
 * * it does not decide whether a start or stop is legal — `CAPTURE_ALREADY_RUNNING`
 *   and `CAPTURE_NOT_RUNNING` come back as refusals and are rendered (the backend
 *   owns the transition table, M15.9);
 * * it does not treat "no interface selected yet" as a failure. That is a
 *   documented `400 NO_INTERFACE_SELECTED` precondition (M13.6), so it is reported
 *   as "nothing selected" rather than as an error the operator must clear.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import {
  fetchCaptureStatus,
  fetchInterfaces,
  fetchSelectedInterface,
  selectInterface,
  startCapture,
  stopCapture,
  toApiError,
} from '@/services'
import type { ApiError } from '@/services'
import {
  EventType,
  isCaptureActive,
  isCaptureRunning,
  isCaptureState,
} from '@/types'
import type {
  CaptureStatus,
  Channel,
  ConnectionPhase,
  NetworkInterface,
  UnknownPayload,
} from '@/types'
import { useAction } from './useAction'
import { useAsyncResource } from './useAsyncResource'
import { useChannelEvents } from './useChannelEvents'

/** The code M4 answers with when no interface has been chosen (M13.6). */
export const NO_INTERFACE_SELECTED_CODE = 'NO_INTERFACE_SELECTED'

/**
 * Read the selected interface, treating "none chosen" as a normal answer.
 *
 * Returns `null` in that one case and rethrows anything else, so a genuine
 * failure is still a failure while the documented precondition is not.
 */
export async function readSelectedInterface(signal?: AbortSignal): Promise<string | null> {
  try {
    const selected = await fetchSelectedInterface(signal)
    return selected.name
  } catch (cause) {
    const failure = toApiError(cause)
    if (failure.code === NO_INTERFACE_SELECTED_CODE) return null
    throw failure
  }
}

/**
 * Build a capture status from an event payload, or `null` if it is not one.
 *
 * Validated field by field rather than cast: the payload arrives as an
 * `UnknownPayload`, and a page that rendered `undefined` for a packet count would
 * be showing a number the backend never sent.
 */
export function captureStatusFromPayload(data: UnknownPayload): CaptureStatus | null {
  const status = data.status
  const iface = data.interface
  const count = data.packet_count
  if (!isCaptureState(status)) return null
  if (!(iface === null || typeof iface === 'string')) return null
  if (typeof count !== 'number') return null
  return { status, interface: iface, packet_count: count }
}

/** Options for {@link useCapture}. */
export interface CaptureOptions {
  /** When False nothing is read and the system channel is not subscribed. */
  readonly enabled?: boolean
}

/** What {@link useCapture} returns. */
export interface CaptureResource {
  /** The current status, or `null` before the first read. */
  readonly status: CaptureStatus | null
  /** The raw M4 state string, or `null`. */
  readonly state: string | null
  /** True only when packets are genuinely flowing (`is_running`, M4.20). */
  readonly isRunning: boolean
  /** True while a session exists, including `starting` and `stopping`. */
  readonly isActive: boolean
  /** Every adapter the host offers. Empty until read. */
  readonly interfaces: readonly NetworkInterface[]
  /** The adapter future sessions will use, or `null` when none is chosen. */
  readonly selectedInterface: string | null
  /** True once the selection has been read, so `null` is known to mean "none". */
  readonly hasLoadedSelection: boolean
  readonly isLoading: boolean
  readonly isInitialLoading: boolean
  /** A genuine read failure. Never the documented "no interface selected". */
  readonly error: ApiError | null
  /** Read status, interfaces and selection again. */
  readonly reload: () => void
  readonly isStarting: boolean
  readonly isStopping: boolean
  readonly isSelecting: boolean
  /** The most recent action failure, for an inline message. */
  readonly actionError: ApiError | null
  /**
   * Why capture reported an error, when it did.
   *
   * Comes from `capture.error`, which M14.22 guarantees is a fixed sentence and
   * never an exception text.
   */
  readonly captureErrorReason: string | null
  /** Dismiss the reported error. */
  readonly clearCaptureError: () => void
  /** Start a session. Resolves `null` on success, or the refusal. */
  readonly start: () => Promise<ApiError | null>
  /** Stop the running session. Resolves `null` on success, or the refusal. */
  readonly stop: () => Promise<ApiError | null>
  /** Choose the adapter future sessions use. */
  readonly select: (name: string) => Promise<ApiError | null>
  /** The channel this hook needs; exposed so a page can show its state. */
  readonly channel: Channel
  readonly isConnected: boolean
  readonly phase: ConnectionPhase
}

/**
 * Read and control capture.
 *
 * @param options Whether to read at all.
 */
export function useCapture(options: CaptureOptions = {}): CaptureResource {
  const enabled = options.enabled ?? true

  const [status, setStatus] = useState<CaptureStatus | null>(null)
  const [isLoadingStatus, setIsLoadingStatus] = useState(enabled)
  const [hasLoadedStatus, setHasLoadedStatus] = useState(false)
  const [statusError, setStatusError] = useState<ApiError | null>(null)
  const [captureErrorReason, setCaptureErrorReason] = useState<string | null>(null)

  const requestIdRef = useRef(0)
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  const loadStatus = useCallback(async (signal?: AbortSignal): Promise<void> => {
    const requestId = ++requestIdRef.current
    setIsLoadingStatus(true)
    try {
      const next = await fetchCaptureStatus(signal)
      if (requestId !== requestIdRef.current || !mountedRef.current) return
      setStatus(next)
      setStatusError(null)
      setHasLoadedStatus(true)
    } catch (cause) {
      if (signal?.aborted === true) return
      if (requestId !== requestIdRef.current || !mountedRef.current) return
      setStatusError(toApiError(cause))
      setHasLoadedStatus(true)
    } finally {
      if (requestId === requestIdRef.current && mountedRef.current) {
        setIsLoadingStatus(false)
      }
    }
  }, [])

  // The adapter list and the chosen adapter have exactly one writer each, so they
  // are ordinary resources.
  const interfaces = useAsyncResource(
    (signal) => fetchInterfaces(signal),
    [],
    { enabled },
  )
  const selection = useAsyncResource(
    (signal) => readSelectedInterface(signal),
    [],
    { enabled },
  )

  useEffect(() => {
    if (!enabled) return
    const controller = new AbortController()
    void loadStatus(controller.signal)
    return () => controller.abort()
  }, [enabled, loadStatus])

  // The system channel is where capture transitions are announced, including ones
  // this browser did not cause. Only the capture events are consumed here; the
  // database and service events belong to the System page, which shares this one
  // socket through the hub rather than opening a second.
  const channel = useChannelEvents({
    channel: 'system',
    enabled,
    onEvent: (event) => {
      if (
        event.type === EventType.CAPTURE_STARTED ||
        event.type === EventType.CAPTURE_STOPPED
      ) {
        const next = captureStatusFromPayload(event.data)
        if (next !== null && mountedRef.current) {
          setStatus(next)
          setStatusError(null)
          setHasLoadedStatus(true)
        }
        setCaptureErrorReason(null)
        return
      }
      if (event.type === EventType.CAPTURE_ERROR) {
        const next = captureStatusFromPayload(event.data)
        if (next !== null && mountedRef.current) setStatus(next)
        const reason = event.data.reason
        setCaptureErrorReason(
          typeof reason === 'string' ? reason : 'Capture stopped because of an error.',
        )
      }
    },
    onReconnect: () => {
      // Capture state is state, not a stream, so an outage is repaired by
      // re-reading it (M15.27).
      void loadStatus()
    },
  })

  const startAction = useAction(startCapture)
  const stopAction = useAction(stopCapture)
  const selectAction = useAction(selectInterface)

  const reload = useCallback(() => {
    void loadStatus()
    interfaces.reload()
    selection.reload()
  }, [interfaces, loadStatus, selection])

  const start = useCallback(async (): Promise<ApiError | null> => {
    setCaptureErrorReason(null)
    const outcome = await startAction.run()
    if (!outcome.ok) return outcome.error
    // The POST response is authoritative and arrives before the event does, so it
    // is applied directly rather than waiting for the announcement.
    setStatus(outcome.value)
    setStatusError(null)
    setHasLoadedStatus(true)
    return null
  }, [startAction])

  const stop = useCallback(async (): Promise<ApiError | null> => {
    setCaptureErrorReason(null)
    const outcome = await stopAction.run()
    if (!outcome.ok) return outcome.error
    setStatus(outcome.value)
    setStatusError(null)
    setHasLoadedStatus(true)
    return null
  }, [stopAction])

  const select = useCallback(
    async (name: string): Promise<ApiError | null> => {
      const outcome = await selectAction.run(name)
      if (!outcome.ok) return outcome.error
      selection.reload()
      return null
    },
    [selectAction, selection],
  )

  const clearCaptureError = useCallback(() => {
    setCaptureErrorReason(null)
  }, [])

  const isLoading = isLoadingStatus || interfaces.isLoading || selection.isLoading
  const isInitialLoading =
    (isLoadingStatus && !hasLoadedStatus) ||
    interfaces.isInitialLoading ||
    selection.isInitialLoading

  return {
    status,
    state: status?.status ?? null,
    isRunning: isCaptureRunning(status),
    isActive: isCaptureActive(status),
    interfaces: interfaces.data ?? [],
    selectedInterface: selection.data,
    hasLoadedSelection: selection.data !== null || !selection.isInitialLoading,
    isLoading,
    isInitialLoading,
    error: statusError ?? interfaces.error ?? selection.error,
    reload,
    isStarting: startAction.isRunning,
    isStopping: stopAction.isRunning,
    isSelecting: selectAction.isRunning,
    actionError: startAction.error ?? stopAction.error ?? selectAction.error,
    captureErrorReason,
    clearCaptureError,
    start,
    stop,
    select,
    channel: 'system',
    isConnected: channel.isConnected,
    phase: channel.phase,
  }
}
