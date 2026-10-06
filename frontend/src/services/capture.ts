/**
 * Capture service (M4, M15.9/M15.41).
 *
 * A thin, typed wrapper over the capture endpoints. It holds no state and makes
 * no decisions: which capture transitions are legal belongs to the backend
 * (`app/services/capture_manager.py`), and a refusal comes back as a `409`
 * carrying `CAPTURE_ALREADY_RUNNING` or `CAPTURE_NOT_RUNNING`.
 *
 * The frontend must not implement its own idea of capture state, because a
 * second opinion would drift from the manager the moment a session ended for a
 * reason the UI did not cause — a capture error, or a shutdown.
 */

import { apiGet, apiPost, apiPut } from './client'
import { CapturePaths } from './endpoints'
import type { CaptureStatus, InterfaceSelectionRequest, NetworkInterface } from '@/types'

/** `GET /api/v1/capture/status` — the live capture state. */
export function fetchCaptureStatus(signal?: AbortSignal): Promise<CaptureStatus> {
  return apiGet<CaptureStatus>(CapturePaths.status, undefined, { signal })
}

/**
 * `GET /api/v1/capture/interfaces` — every NIC the host offers.
 *
 * Returns a bare list: this is the one collection with no page window, because it
 * enumerates the machine's own adapters rather than a table that grows (M13.7).
 */
export function fetchInterfaces(signal?: AbortSignal): Promise<readonly NetworkInterface[]> {
  return apiGet<readonly NetworkInterface[]>(CapturePaths.interfaces, undefined, { signal })
}

/**
 * `GET /api/v1/capture/interface` — the selected adapter.
 *
 * Rejects with a `400 NO_INTERFACE_SELECTED` when none has been chosen, which is a
 * precondition to fix rather than a missing resource (M13.6).
 */
export function fetchSelectedInterface(
  signal?: AbortSignal,
): Promise<{ readonly name: string }> {
  return apiGet<{ readonly name: string }>(CapturePaths.interface, undefined, { signal })
}

/** `PUT /api/v1/capture/interface` — choose the adapter future sessions use. */
export function selectInterface(
  name: string,
  signal?: AbortSignal,
): Promise<{ readonly name: string }> {
  const body: InterfaceSelectionRequest = { name }
  return apiPut<{ readonly name: string }>(CapturePaths.interface, { body, signal })
}

/** `POST /api/v1/capture/start` — start capture on the selected interface. */
export function startCapture(signal?: AbortSignal): Promise<CaptureStatus> {
  return apiPost<CaptureStatus>(CapturePaths.start, { signal })
}

/** `POST /api/v1/capture/stop` — stop the active session. */
export function stopCapture(signal?: AbortSignal): Promise<CaptureStatus> {
  return apiPost<CaptureStatus>(CapturePaths.stop, { signal })
}
