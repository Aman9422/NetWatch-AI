/// <reference types="vite/client" />

/**
 * The frontend's environment contract (M15.3).
 *
 * Declaring the shape here means a typo in a variable name is a compile error
 * rather than an `undefined` that silently falls back to a default. Every value
 * is `string | undefined` because Vite only defines what was actually supplied —
 * a missing key is the normal case in a production build.
 *
 * These values are PUBLIC: Vite inlines them into the bundle. Nothing secret may
 * ever be added to this interface (M15.37).
 */
interface ImportMetaEnv {
  /** Base URL of the versioned REST API, e.g. `http://127.0.0.1:8000/api/v1`. */
  readonly VITE_API_BASE_URL?: string
  /** Base URL of the WebSocket channels, e.g. `ws://127.0.0.1:8000`. */
  readonly VITE_WS_BASE_URL?: string
  /** Milliseconds before a REST request is aborted as a timeout. */
  readonly VITE_API_TIMEOUT_MS?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
