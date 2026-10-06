/**
 * Settings — the backend's own keys, and the backend's own rules (M15.23).
 *
 * The page this replaces was fiction with a settings-shaped shell: eleven
 * sections, a sensor name, capture mode, MTU, a BPF filter, Snort rule sets, an
 * AI model and confidence, a PostgreSQL host and port, backup destinations, Slack
 * webhooks, a licence key and expiry, uptime and database size. None of it exists.
 * `PUT` accepts exactly the keys the application declares mutable (five today),
 * and a stored credential is not even listed. So the page is rebuilt around what
 * the API actually answers (M15.23/M15.31).
 *
 * Three rules from the endpoint shape every decision here, and the page
 * deliberately does **not** restate any of them in React:
 *
 * * **Which keys exist, and which are writable, comes from the response.** The
 *   listing reports `mutable` per setting and `mutable_keys` as the whole writable
 *   set, so nothing is hardcoded. Adding a mutable key server-side makes it
 *   editable here with no frontend change — and, more importantly, this page can
 *   never offer a control the backend would refuse.
 * * **Internal-only keys are invisible and indistinguishable from unknown ones.**
 *   A key matching the secret denylist is never listed, and reading it answers
 *   `404` exactly as an unknown key does. The lookup below therefore reports
 *   "not found" without speculating about which of the two it was — guessing
 *   would confirm what is stored, which is the leak the rule prevents.
 * * **A saved value is stored, not applied.** Stored settings are read at
 *   application startup, so `PUT` answers `restart_required: true`. The page says
 *   "stored — restart to apply" rather than implying the change is live. That is
 *   the single most important thing on this screen (M15.23).
 *
 * Validation is not duplicated either. The backend validates each key against its
 * own declaration (type, range, allowed values) and refuses the whole batch with a
 * sentence naming the key; this page shows that sentence. Re-implementing the five
 * rules in TypeScript would create a second source of truth that could disagree
 * with the first.
 *
 * Settings publish no WebSocket channel, so a change made elsewhere arrives only
 * on an explicit reload (M15.34).
 */

import { useMemo, useState } from 'react'
import {
  AlertTriangle, Check, Lock, RefreshCw, RotateCcw, Save, Search,
  Settings as Cog, Sliders,
} from 'lucide-react'
import { AsyncSection, EmptyState, RefreshFailureBanner } from '@/components/AsyncState'
import { useSettings } from '@/hooks'
import { fetchSetting } from '@/services'
import type { ApiError, SettingValues, WritableSettingValue } from '@/services'
import { C, tint } from '@/lib/tokens'
import { UNKNOWN_TEXT, formatTimestamp } from '@/lib/format'
import type { Setting, SettingValue } from '@/types'
import type { ToastMsg } from '../App'

/** A value as it is being edited, before it is converted for the request. */
type Draft = string | number | boolean

/** Turn a stored value into something an input can hold. */
function toDraft(setting: Setting): Draft {
  const value: SettingValue = setting.value
  if (setting.data_type === 'bool') return value === true
  if (typeof value === 'number' || typeof value === 'boolean') return value
  if (value === null) return ''
  if (typeof value === 'string') return value
  // A decoded document has no single-line editor and the write API accepts only
  // scalars, so it is rendered read-only rather than round-tripped through JSON.
  return JSON.stringify(value)
}

/**
 * A value that can only be displayed, never written.
 *
 * `json` settings decode to objects and lists, and `PUT` accepts only
 * `str | int | float | bool` — so a document is shown as text instead of through
 * an editor that could not be saved.
 */
function isDisplayOnly(setting: Setting): boolean {
  return setting.data_type === 'json' || setting.value === null ||
    typeof setting.value === 'object'
}

/** Render any stored value for display, including a decoded document. */
function displayValue(setting: Setting): string {
  const value = setting.value
  if (value === null) return UNKNOWN_TEXT
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'string') return value === '' ? UNKNOWN_TEXT : value
  if (typeof value === 'number') return String(value)
  try {
    return JSON.stringify(value)
  } catch {
    return UNKNOWN_TEXT
  }
}

/**
 * Convert a draft into a writable value for the request body.
 *
 * A numeric setting whose draft parses is sent as a number; one that does not is
 * sent as the typed text so the backend's own validation rejects it and names the
 * problem. Coercing here — or silently dropping it — would hide the operator's
 * mistake behind this client's guess.
 */
function toWritable(setting: Setting, draft: Draft): WritableSettingValue {
  if (typeof draft === 'boolean') return draft
  if (typeof draft === 'number') return draft
  if (setting.data_type === 'int' || setting.data_type === 'float') {
    const parsed = Number(draft)
    return Number.isFinite(parsed) && draft.trim() !== '' ? parsed : draft
  }
  return draft
}

// ─── One setting, editable or not ────────────────────────────────────────────

/** The editor a setting's declared `data_type` calls for. */
function SettingEditor({ setting, draft, onChange, disabled }: {
  setting: Setting
  draft: Draft
  onChange: (value: Draft) => void
  disabled: boolean
}) {
  // A boolean has exactly two states, so it gets a switch rather than a text
  // field an operator could typo. Everything else is taken as typed and validated
  // by the backend.
  if (setting.data_type === 'bool') {
    const checked = draft === true
    return (
      <button type="button" onClick={() => onChange(!checked)} disabled={disabled}
        className="flex items-center gap-2 px-3 py-2 rounded-xl border text-xs font-medium disabled:opacity-50"
        style={{
          backgroundColor: checked ? tint(C.success, 0.12) : C.panel,
          borderColor: checked ? C.success : C.border,
          color: checked ? C.success : C.muted,
        }}>
        <span className="w-1.5 h-1.5 rounded-full"
          style={{ backgroundColor: checked ? C.success : C.dim }} />
        {checked ? 'true' : 'false'}
      </button>
    )
  }

  return (
    <input
      value={String(draft)}
      onChange={event => onChange(event.target.value)}
      disabled={disabled}
      inputMode={setting.data_type === 'int' || setting.data_type === 'float' ? 'decimal' : 'text'}
      className="w-full px-3 py-2 rounded-xl text-xs border mono disabled:opacity-50"
      style={{ backgroundColor: C.panel, borderColor: C.border, color: C.text, outline: 'none' }}
    />
  )
}

/** One row: the key, its declared type, its editor or its value, and its instant. */
function SettingRow({ setting, draft, isChanged, onChange, disabled }: {
  setting: Setting
  draft: Draft
  isChanged: boolean
  onChange: (value: Draft) => void
  disabled: boolean
}) {
  const readOnly = !setting.mutable || isDisplayOnly(setting)
  return (
    <tr className="border-b" style={{ borderColor: '#1a2744' }}>
      <td className="pl-5 py-3 pr-4 align-top">
        <div className="flex items-center gap-2">
          <span className="mono text-xs font-semibold text-white break-all">{setting.key}</span>
          {isChanged && (
            <span className="text-xs px-1.5 py-0.5 rounded-full flex-shrink-0"
              style={{ backgroundColor: tint(C.warning, 0.14), color: C.warning }}>
              unsaved
            </span>
          )}
        </div>
        <div className="text-xs mt-0.5" style={{ color: C.faint }}>
          {readOnly
            ? setting.mutable
              ? `read-only — ${setting.data_type} values cannot be written`
              : 'read-only — the backend does not accept writes to this key'
            : `writable — ${setting.data_type}`}
        </div>
      </td>
      <td className="py-3 pr-4 align-top w-56">
        {readOnly ? (
          <div className="flex items-center gap-2 px-3 py-2 rounded-xl border"
            style={{ backgroundColor: C.bg, borderColor: C.border }}>
            <Lock size={11} style={{ color: C.dim, flexShrink: 0 }} />
            <span className="mono text-xs truncate" style={{ color: C.muted }}
              title={displayValue(setting)}>
              {displayValue(setting)}
            </span>
          </div>
        ) : (
          <SettingEditor setting={setting} draft={draft} onChange={onChange} disabled={disabled} />
        )}
      </td>
      <td className="py-3 pr-4 align-top text-xs whitespace-nowrap" style={{ color: C.faint }}>
        {setting.data_type}
      </td>
      <td className="py-3 pr-5 align-top text-xs whitespace-nowrap" style={{ color: C.faint }}>
        {formatTimestamp(setting.updated_at)}
      </td>
    </tr>
  )
}

/**
 * Read one setting by key.
 *
 * Exists because the endpoint does, and because it demonstrates the rule that
 * matters most here: an internal-only key and a key that was never stored both
 * answer `404`, so the page reports "not found" and does not try to distinguish
 * them. Speculating would confirm which secrets exist (M15.23).
 */
function SettingLookup() {
  const [key, setKey] = useState('')
  const [result, setResult] = useState<Setting | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const [isLoading, setIsLoading] = useState(false)

  const lookup = () => {
    const wanted = key.trim()
    if (wanted === '') return
    setIsLoading(true)
    setResult(null)
    setError(null)
    void fetchSetting(wanted)
      .then(setting => setResult(setting))
      .catch((cause: unknown) => setError(cause as ApiError))
      .finally(() => setIsLoading(false))
  }

  return (
    <div className="rounded-2xl border p-5" style={{ backgroundColor: C.card, borderColor: C.border }}>
      <div className="flex items-center gap-2 mb-1.5">
        <Search size={14} style={{ color: C.accent }} />
        <h2 className="text-sm font-semibold text-white">Read one key</h2>
      </div>
      <p className="text-xs mb-3" style={{ color: C.faint }}>
        An unknown key and a stored internal-only key both answer <span className="mono">404</span>,
        deliberately. This reports "not found" for either rather than guessing which it was.
      </p>
      <form className="flex items-center gap-2"
        onSubmit={event => { event.preventDefault(); lookup() }}>
        <input value={key} onChange={event => setKey(event.target.value)}
          placeholder="Setting key…"
          className="flex-1 px-3 py-2 rounded-xl text-xs border mono"
          style={{ backgroundColor: C.panel, borderColor: C.border, color: C.text, outline: 'none' }} />
        <button type="submit" disabled={isLoading || key.trim() === ''}
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border disabled:opacity-50"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
          <RefreshCw size={12} className={isLoading ? 'animate-spin' : undefined} /> Read
        </button>
      </form>

      {error !== null && (
        <p className="text-xs mt-3" style={{ color: C.muted }}>
          {error.userMessage}
        </p>
      )}

      {result !== null && (
        <div className="mt-3 px-3 py-2 rounded-xl border"
          style={{ backgroundColor: C.panel, borderColor: tint(C.success, 0.3) }}>
          <div className="flex items-center gap-2">
            <Check size={12} style={{ color: C.success }} />
            <span className="mono text-xs font-semibold text-white">{result.key}</span>
            <span className="mono text-xs" style={{ color: C.accent }}>
              {displayValue(result)}
            </span>
          </div>
          <div className="text-xs mt-1" style={{ color: C.faint }}>
            {result.data_type} · {result.mutable ? 'writable' : 'read-only'} · last changed{' '}
            {formatTimestamp(result.updated_at)}
          </div>
        </div>
      )}
    </div>
  )
}
// ─── Page ────────────────────────────────────────────────────────────────────

interface Props {
  showToast: (msg: string, type?: ToastMsg['type']) => void
}

export default function Settings({ showToast }: Props) {
  const resource = useSettings()

  // Edits are held as *overrides* rather than a mirrored copy of the listing, so
  // a reload — which the hook performs after every successful save — needs no
  // synchronising effect: a key that has not been touched simply reads through to
  // whatever the backend last reported.
  const [overrides, setOverrides] = useState<Readonly<Record<string, Draft>>>({})

  const draftFor = (setting: Setting): Draft =>
    Object.prototype.hasOwnProperty.call(overrides, setting.key)
      ? overrides[setting.key]
      : toDraft(setting)

  const changedKeys = useMemo(
    () =>
      resource.settings
        .filter(setting => {
          if (!Object.prototype.hasOwnProperty.call(overrides, setting.key)) return false
          const draft = overrides[setting.key]
          // A boolean compares by value; a text draft compares as the typed string
          // so re-typing the same digits does not count as a change.
          return setting.data_type === 'bool'
            ? draft !== toDraft(setting)
            : String(draft) !== String(toDraft(setting))
        })
        .map(setting => setting.key),
    [resource.settings, overrides],
  )

  const writable = resource.settings.filter(
    setting => setting.mutable && !isDisplayOnly(setting),
  )
  const readOnly = resource.settings.filter(
    setting => !setting.mutable || isDisplayOnly(setting),
  )

  const setDraft = (key: string, value: Draft) => {
    setOverrides(current => ({ ...current, [key]: value }))
  }

  const discard = () => {
    setOverrides({})
  }

  const save = () => {
    const values: Record<string, WritableSettingValue> = {}
    for (const setting of resource.settings) {
      if (!changedKeys.includes(setting.key)) continue
      values[setting.key] = toWritable(setting, draftFor(setting))
    }
    const batch: SettingValues = values

    void resource.save(batch).then(failure => {
      if (failure !== null) {
        showToast(failure.userMessage, 'error')
        // The overrides are kept so the operator can correct the value the backend
        // refused rather than retyping the whole form.
        return
      }
      setOverrides({})
      showToast(
        'Settings stored — the running service is unchanged until it is restarted',
        'info',
      )
    })
  }

  return (
    <div className="space-y-4">
      {/* What this page is, and the one thing an operator must not miss. */}
      <div className="rounded-2xl border p-5" style={{ backgroundColor: C.card, borderColor: C.border }}>
        <div className="flex items-start gap-3">
          <div className="p-2.5 rounded-xl flex-shrink-0" style={{ backgroundColor: tint(C.accent, 0.08) }}>
            <Cog size={18} style={{ color: C.accent }} />
          </div>
          <div className="min-w-0">
            <h1 className="text-sm font-semibold text-white">Runtime settings</h1>
            <p className="text-xs mt-1 max-w-2xl" style={{ color: C.muted }}>
              The backend decides which keys exist and which may be written, and this page shows
              exactly those. A key it does not accept has no control here, and a stored
              internal-only key is not listed at all.
            </p>
            {resource.page !== null && (
              <p className="text-xs mt-1.5" style={{ color: C.faint }}>
                {resource.settings.length} readable key{resource.settings.length === 1 ? '' : 's'} ·{' '}
                {resource.mutableKeys.length} writable
                {resource.internalKeyCount > 0
                  ? ` · ${resource.internalKeyCount} withheld as internal-only`
                  : ''}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* The response's own statement that a write is stored, not applied. */}
      {resource.restartRequired && (
        <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl border"
          style={{ backgroundColor: tint(C.warning, 0.08), borderColor: tint(C.warning, 0.3) }}>
          <AlertTriangle size={14} style={{ color: C.warning, flexShrink: 0, marginTop: 1 }} />
          <div className="min-w-0">
            <p className="text-xs font-semibold" style={{ color: C.warning }}>
              Stored — restart required
            </p>
            <p className="text-xs mt-0.5" style={{ color: C.muted }}>
              The backend accepted the change and reported <span className="mono">restart_required</span>.
              Stored settings are read at application startup, so the running service is still using
              the previous values. Restart NetWatch for the change to take effect.
            </p>
          </div>
        </div>
      )}

      {resource.saveError !== null && (
        <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl border"
          style={{ backgroundColor: tint(C.danger, 0.08), borderColor: tint(C.danger, 0.3) }}>
          <AlertTriangle size={14} style={{ color: C.danger, flexShrink: 0, marginTop: 1 }} />
          <div className="min-w-0">
            <p className="text-xs font-semibold" style={{ color: C.danger }}>
              Nothing was written
            </p>
            <p className="text-xs mt-0.5" style={{ color: C.muted }}>
              {resource.saveError.userMessage}
            </p>
            {resource.saveError.fieldDetails.length > 0 && (
              <ul className="text-xs mt-1 space-y-0.5" style={{ color: C.faint }}>
                {resource.saveError.fieldDetails.map(detail => (
                  <li key={detail} className="mono">{detail}</li>
                ))}
              </ul>
            )}
            <p className="text-xs mt-1" style={{ color: C.faint }}>
              The whole batch is validated before anything is stored, so a refusal changes nothing —
              not even the keys that were valid.
            </p>
          </div>
        </div>
      )}

      {resource.error !== null && resource.settings.length > 0 && (
        <RefreshFailureBanner error={resource.error} onRetry={resource.reload} />
      )}

      <div className="rounded-2xl border overflow-hidden"
        style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b flex-wrap gap-3"
          style={{ borderColor: C.border }}>
          <div>
            <div className="flex items-center gap-2">
              <Sliders size={14} style={{ color: C.success }} />
              <h2 className="text-sm font-semibold text-white">Writable settings</h2>
            </div>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>
              {writable.length === 0
                ? 'The backend reported no writable key.'
                : `${writable.length} key${writable.length === 1 ? '' : 's'} ${'PUT /settings'} accepts`}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button type="button" onClick={resource.reload} disabled={resource.isLoading}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border disabled:opacity-50"
              style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
              <RefreshCw size={12} className={resource.isLoading ? 'animate-spin' : undefined} />
              Refresh
            </button>
            <button type="button" onClick={discard} disabled={changedKeys.length === 0 || resource.isSaving}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border disabled:opacity-40"
              style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
              <RotateCcw size={12} /> Discard
            </button>
            <button type="button" onClick={save} disabled={changedKeys.length === 0 || resource.isSaving}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold disabled:opacity-40"
              style={{ backgroundColor: C.accent, color: '#0F172A' }}>
              <Save size={12} />
              {resource.isSaving
                ? 'Saving…'
                : changedKeys.length === 0
                  ? 'Save changes'
                  : `Save ${changedKeys.length} change${changedKeys.length === 1 ? '' : 's'}`}
            </button>
          </div>
        </div>

        <AsyncSection
          isInitialLoading={resource.isInitialLoading}
          error={resource.blockingError}
          isEmpty={false}
          loadingLabel="Loading settings…"
          errorTitle="Unable to load settings"
          onRetry={resource.reload}
          minHeight={220}
        >
          {resource.settings.length === 0 ? (
            <EmptyState title="No readable settings"
              hint="The backend reported no readable setting at all. Nothing on this page can be shown or changed."
              icon={<Cog size={28} />} />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b" style={{ borderColor: C.border }}>
                    <th className="text-left pl-5 py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Key</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Value</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Type</th>
                    <th className="text-left py-2.5 pr-5 text-xs font-medium" style={{ color: C.dim }}>Last changed</th>
                  </tr>
                </thead>
                <tbody>
                  {writable.map(setting => (
                    <SettingRow
                      key={setting.key}
                      setting={setting}
                      draft={draftFor(setting)}
                      isChanged={changedKeys.includes(setting.key)}
                      onChange={value => setDraft(setting.key, value)}
                      disabled={resource.isSaving}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AsyncSection>
      </div>

      {/* Everything the backend lists but will not accept a write for. */}
      {readOnly.length > 0 && (
        <div className="rounded-2xl border overflow-hidden"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="px-5 py-4 border-b" style={{ borderColor: C.border }}>
            <div className="flex items-center gap-2">
              <Lock size={14} style={{ color: C.dim }} />
              <h2 className="text-sm font-semibold text-white">Read-only settings</h2>
            </div>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>
              Listed by the backend and readable, but not writable through this API. No control is
              offered for any of them.
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b" style={{ borderColor: C.border }}>
                  <th className="text-left pl-5 py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Key</th>
                  <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Value</th>
                  <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Type</th>
                  <th className="text-left py-2.5 pr-5 text-xs font-medium" style={{ color: C.dim }}>Last changed</th>
                </tr>
              </thead>
              <tbody>
                {readOnly.map(setting => (
                  <SettingRow
                    key={setting.key}
                    setting={setting}
                    draft={toDraft(setting)}
                    isChanged={false}
                    onChange={() => undefined}
                    disabled
                  />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <SettingLookup />

      <p className="text-xs px-1" style={{ color: C.faint }}>
        Values are validated by the backend against each key's own declaration, so a value it
        rejects is reported with its own sentence naming the key — this page does not enforce a
        second, possibly divergent, copy of those rules. A value of {UNKNOWN_TEXT} means the store
        holds nothing for that key.
      </p>
    </div>
  )
}
