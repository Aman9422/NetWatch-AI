/**
 * Settings — the backend's keys and the backend's rules (M15.23, M15.38 "Pages").
 *
 * Three rules from M15.23 shape these tests, and each is asserted rather than
 * assumed:
 *
 * * **The response decides what is writable.** `mutable` per setting and
 *   `mutable_keys` as the whole writable set come from the payload, so a page that
 *   hardcoded a key list would fail here.
 * * **A read-only key gets no control.** A key the backend will not accept a write
 *   for is listed with its value and no editor — offering one would be a promise
 *   `PUT` refuses.
 * * **`restart_required` is displayed.** A successful save is *stored*, not
 *   applied, so the page must say so and must not imply the change is live.
 *
 * The lookup tests cover the other half of the same rule: an internal-only key and
 * an unknown key both answer `404`, so the page repeats the backend's sentence and
 * never speculates about which of the two it was.
 */

import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { NETWORK_MESSAGE } from '@/services'
import { UNKNOWN_TEXT } from '@/lib/format'
import type { Setting, SettingList, SettingUpdateResult } from '@/types'
import Settings from '@/pages/Settings'
import { failure, installFetch, networkDownFetch, ok, type RoutedCall } from '@/test/harness'

/** One setting as M13.21 reports it, with everything settable for a given case. */
function setting(overrides: Partial<Setting> = {}): Setting {
  return {
    key: 'capture.interface',
    value: 'eth0',
    data_type: 'str',
    mutable: true,
    updated_at: '2026-01-01T10:00:00+00:00',
    ...overrides,
  }
}

/** A settings listing as `GET /settings` answers. */
function settingList(
  settings: readonly Setting[],
  overrides: Partial<SettingList> = {},
): SettingList {
  return {
    count: settings.length,
    settings,
    mutable_keys: settings.filter(entry => entry.mutable).map(entry => entry.key),
    internal_key_count: 0,
    ...overrides,
  }
}

/** A saved-batch response. Stored settings need a restart, so that is the default. */
function saved(restartRequired = true): SettingUpdateResult {
  return { updated: [setting()], restart_required: restartRequired }
}

/** Render the page with a toast recorder. */
function renderPage() {
  const showToast = vi.fn()
  const view = render(<Settings showToast={showToast} />)
  return { ...view, showToast }
}

describe('Settings requesting', () => {
  it('reads every readable setting on mount', async () => {
    const router = installFetch({ 'GET /settings': () => ok(settingList([setting()])) })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /settings')).toBe(1)
    })
    // The listing takes no filter and no window: the endpoint returns the store.
    expect(router.lastCall('GET /settings')?.query).toBe('')
  })
})

describe('Settings rendering', () => {
  it('offers an editor for a writable key and none for a read-only one', async () => {
    installFetch({
      'GET /settings': () =>
        ok(
          settingList([
            setting({ key: 'capture.interface', value: 'eth0', mutable: true }),
            setting({ key: 'app.version', value: '1.0.0', mutable: false }),
          ]),
        ),
    })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('capture.interface')).toBeInTheDocument()
    })

    const writableRow = screen.getByText('capture.interface').closest('tr')
    expect(writableRow).not.toBeNull()
    expect(within(writableRow as HTMLElement).getByRole('textbox')).toBeInTheDocument()
    expect(within(writableRow as HTMLElement).getByDisplayValue('eth0')).toBeInTheDocument()

    const readOnlyRow = screen.getByText('app.version').closest('tr')
    expect(readOnlyRow).not.toBeNull()
    // No editor at all: the page does not offer a write the backend would refuse.
    expect(within(readOnlyRow as HTMLElement).queryByRole('textbox')).toBeNull()
    expect(within(readOnlyRow as HTMLElement).getByText('1.0.0')).toBeInTheDocument()
    expect(screen.getByText(/does not accept writes to this key/i)).toBeInTheDocument()
  })

  it('shows a decoded document read-only, because only scalars can be written', async () => {
    // `PUT` accepts `str | int | float | bool`, so a `json` setting is displayed
    // rather than round-tripped through an editor that could never be saved.
    installFetch({
      'GET /settings': () =>
        ok(
          settingList([
            setting({
              key: 'detection.thresholds',
              value: { low: 1, high: 9 },
              data_type: 'json',
              mutable: true,
            }),
          ]),
        ),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('detection.thresholds')).toBeInTheDocument()
    })
    expect(screen.getByText(/json values cannot be written/i)).toBeInTheDocument()
    const row = screen.getByText('detection.thresholds').closest('tr')
    expect(within(row as HTMLElement).queryByRole('textbox')).toBeNull()
    expect(screen.getByText('{"low":1,"high":9}')).toBeInTheDocument()
  })

  it('states how many keys are readable, writable and withheld', async () => {
    // All three counts are the backend's, taken from the response.
    installFetch({
      'GET /settings': () =>
        ok(
          settingList(
            [
              setting({ key: 'a.b', mutable: true }),
              setting({ key: 'c.d', mutable: true }),
              setting({ key: 'e.f', mutable: false }),
            ],
            { internal_key_count: 4 },
          ),
        ),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText(/3 readable keys/)).toBeInTheDocument()
    })
    expect(screen.getByText(/2 writable/)).toBeInTheDocument()
    expect(screen.getByText(/4 withheld as internal-only/)).toBeInTheDocument()
  })

  it('renders the unknown marker for a key the store holds nothing for', async () => {
    installFetch({
      'GET /settings': () =>
        ok(settingList([setting({ key: 'capture.interface', value: null, mutable: false })])),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('capture.interface')).toBeInTheDocument()
    })
    expect(screen.getAllByText(UNKNOWN_TEXT).length).toBeGreaterThanOrEqual(1)
  })
})

describe('Settings saving', () => {
  it('sends only the changed key, as a batch', async () => {
    const router = installFetch({
      'GET /settings': () =>
        ok(
          settingList([
            setting({ key: 'capture.interface', value: 'eth0' }),
            setting({ key: 'app.version', value: '1.0.0', mutable: false }),
          ]),
        ),
      'PUT /settings': () => ok(saved()),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByDisplayValue('eth0')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByDisplayValue('eth0'), { target: { value: 'eth1' } })
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Save 1 change' })).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Save 1 change' }))

    await waitFor(() => {
      expect(router.countOf('PUT /settings')).toBe(1)
    })
    expect(router.lastCall('PUT /settings')?.body).toEqual({
      values: { 'capture.interface': 'eth1' },
    })
    // The store is authoritative for what is now stored, so the listing is
    // re-read rather than patched from the response.
    await waitFor(() => {
      expect(router.countOf('GET /settings')).toBe(2)
    })
  })

  it('sends a numeric draft as a number', async () => {
    const router = installFetch({
      'GET /settings': () =>
        ok(settingList([setting({ key: 'capture.snaplen', value: 65535, data_type: 'int' })])),
      'PUT /settings': () => ok(saved()),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByDisplayValue('65535')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByDisplayValue('65535'), { target: { value: '9000' } })
    fireEvent.click(screen.getByRole('button', { name: /^save/i }))

    await waitFor(() => {
      expect(router.countOf('PUT /settings')).toBe(1)
    })
    expect(router.lastCall('PUT /settings')?.body).toEqual({
      values: { 'capture.snaplen': 9000 },
    })
  })

  it('sends an unparseable numeric draft as typed, so the backend rejects it', async () => {
    // Coercing here would hide the operator's mistake behind this client's guess.
    const router = installFetch({
      'GET /settings': () =>
        ok(settingList([setting({ key: 'capture.snaplen', value: 65535, data_type: 'int' })])),
      'PUT /settings': () =>
        failure(400, 'snaplen must be an integer.', [
          { field: 'capture.snaplen', code: 'INVALID_SETTING' },
        ]),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByDisplayValue('65535')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByDisplayValue('65535'), { target: { value: 'lots' } })
    fireEvent.click(screen.getByRole('button', { name: /^save/i }))

    await waitFor(() => {
      expect(router.countOf('PUT /settings')).toBe(1)
    })
    expect(router.lastCall('PUT /settings')?.body).toEqual({
      values: { 'capture.snaplen': 'lots' },
    })
  })

  it('toggles a boolean setting and sends the new value', async () => {
    const router = installFetch({
      'GET /settings': () =>
        ok(settingList([setting({ key: 'detection.enabled', value: false, data_type: 'bool' })])),
      'PUT /settings': () => ok(saved()),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'false' })).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'false' }))

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'true' })).toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button', { name: /^save/i }))

    await waitFor(() => {
      expect(router.countOf('PUT /settings')).toBe(1)
    })
    expect(router.lastCall('PUT /settings')?.body).toEqual({
      values: { 'detection.enabled': true },
    })
  })

  it('offers no save while nothing has changed', async () => {
    installFetch({ 'GET /settings': () => ok(settingList([setting()])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('capture.interface')).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled()
    expect(screen.getByRole('button', { name: /discard/i })).toBeDisabled()
  })

  it('discards an edit and returns the row to the stored value', async () => {
    installFetch({ 'GET /settings': () => ok(settingList([setting({ value: 'eth0' })])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByDisplayValue('eth0')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByDisplayValue('eth0'), { target: { value: 'wlan0' } })
    await waitFor(() => {
      expect(screen.getByDisplayValue('wlan0')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /discard/i }))

    await waitFor(() => {
      expect(screen.getByDisplayValue('eth0')).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled()
  })
})

describe('Settings restart disclosure (M15.23)', () => {
  it('says the change is stored, not live, when the backend asks for a restart', async () => {
    installFetch({
      'GET /settings': () => ok(settingList([setting()])),
      'PUT /settings': () => ok(saved(true)),
    })
    const { showToast } = renderPage()
    await waitFor(() => {
      expect(screen.getByDisplayValue('eth0')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByDisplayValue('eth0'), { target: { value: 'eth1' } })
    fireEvent.click(screen.getByRole('button', { name: /^save/i }))

    await waitFor(() => {
      expect(screen.getByText('Stored — restart required')).toBeInTheDocument()
    })
    expect(screen.getByText(/read at application startup/i)).toBeInTheDocument()
    expect(showToast).toHaveBeenCalledWith(
      'Settings stored — the running service is unchanged until it is restarted',
      'info',
    )
  })

  it('does not claim a restart when the backend did not ask for one', async () => {
    installFetch({
      'GET /settings': () => ok(settingList([setting()])),
      'PUT /settings': () => ok(saved(false)),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByDisplayValue('eth0')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByDisplayValue('eth0'), { target: { value: 'eth1' } })
    fireEvent.click(screen.getByRole('button', { name: /^save/i }))

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled()
    })
    expect(screen.queryByText('Stored — restart required')).toBeNull()
  })

  it('reports a refused batch and keeps the drafts for correction', async () => {
    installFetch({
      'GET /settings': () => ok(settingList([setting()])),
      'PUT /settings': () =>
        failure(400, 'capture.interface is not a known interface.', [
          { field: 'capture.interface', code: 'INVALID_SETTING' },
        ]),
    })
    const { showToast } = renderPage()
    await waitFor(() => {
      expect(screen.getByDisplayValue('eth0')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByDisplayValue('eth0'), { target: { value: 'nope0' } })
    fireEvent.click(screen.getByRole('button', { name: /^save/i }))

    await waitFor(() => {
      expect(screen.getByText('Nothing was written')).toBeInTheDocument()
    })
    // The backend's own sentence names the key, and the refusal changes nothing.
    expect(screen.getByText(/is not a known interface/i)).toBeInTheDocument()
    expect(screen.getByText('capture.interface: INVALID_SETTING')).toBeInTheDocument()
    expect(screen.getByText(/whole batch is validated before anything is stored/i)).toBeInTheDocument()
    // The draft survives, so the operator corrects it rather than retyping the form.
    expect(screen.getByDisplayValue('nope0')).toBeInTheDocument()
    expect(showToast).toHaveBeenCalledWith('capture.interface is not a known interface.', 'error')
  })
})

describe('Settings loading, empty and error states', () => {
  it('shows a busy panel while the first request is in flight', () => {
    installFetch({ 'GET /settings': () => new Promise<Response>(() => {}) })
    renderPage()
    expect(screen.getByText('Loading settings…')).toBeInTheDocument()
  })

  it('shows the empty state when the backend lists no readable setting', async () => {
    installFetch({ 'GET /settings': () => ok(settingList([])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('No readable settings')).toBeInTheDocument()
    })
    expect(screen.getByText(/reported no readable setting at all/i)).toBeInTheDocument()
  })

  it('shows a usable error panel when the backend cannot be reached', async () => {
    vi.stubGlobal('fetch', networkDownFetch())
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Unable to load settings')).toBeInTheDocument()
    })
    expect(screen.getByText(NETWORK_MESSAGE)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('keeps the readable rows when a refresh fails', async () => {
    let failNext = false
    installFetch({
      'GET /settings': () =>
        failNext
          ? failure(500, 'The server failed while handling this request.', [
              { field: 'request', code: 'INTERNAL_ERROR' },
            ])
          : ok(settingList([setting()])),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('capture.interface')).toBeInTheDocument()
    })

    failNext = true
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }))

    await waitFor(() => {
      expect(screen.getByText(/may be out of date/i)).toBeInTheDocument()
    })
    expect(screen.getByText('capture.interface')).toBeInTheDocument()
  })
})

describe('Settings single-key lookup (M15.23)', () => {
  it('reads one key and reports its value and writability', async () => {
    const router = installFetch({
      'GET /settings': () => ok(settingList([setting()])),
      'GET /settings/log_level': () =>
        ok(setting({ key: 'log_level', value: 'INFO', data_type: 'str', mutable: true })),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('capture.interface')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByPlaceholderText('Setting key…'), { target: { value: 'log_level' } })
    fireEvent.submit(screen.getByPlaceholderText('Setting key…').closest('form') as HTMLFormElement)

    await waitFor(() => {
      expect(router.countOf('GET /settings/log_level')).toBe(1)
    })
    expect(screen.getByText('INFO')).toBeInTheDocument()
    expect(screen.getByText(/str · writable · last changed/i)).toBeInTheDocument()
  })

  it('repeats the backend sentence for a 404 without guessing which key it was', async () => {
    // An internal-only key and an unknown key both answer 404 by design, so the
    // page must not speculate — guessing would confirm what is stored.
    installFetch({
      'GET /settings': () => ok(settingList([setting()])),
      'GET /settings/db.password': () =>
        failure(404, 'No setting is stored under that key.', [
          { field: 'key', code: 'SETTING_NOT_FOUND' },
        ]),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('capture.interface')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByPlaceholderText('Setting key…'), {
      target: { value: 'db.password' },
    })
    fireEvent.submit(screen.getByPlaceholderText('Setting key…').closest('form') as HTMLFormElement)

    await waitFor(() => {
      expect(screen.getByText('No setting is stored under that key.')).toBeInTheDocument()
    })
    // The rule is stated on the page, and nothing else is claimed about the key.
    expect(screen.getByText(/both answer/i)).toBeInTheDocument()
    expect(screen.queryByText(/read-only —/i)).toBeNull()
  })

  it('does not offer a read while the key field is empty', async () => {
    installFetch({ 'GET /settings': () => ok(settingList([setting()])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('capture.interface')).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: /^read$/i })).toBeDisabled()
  })

  it('sends no lookup request when the key field is only whitespace', async () => {
    const router = installFetch({ 'GET /settings': () => ok(settingList([setting()])) })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('capture.interface')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByPlaceholderText('Setting key…'), { target: { value: '   ' } })
    fireEvent.submit(screen.getByPlaceholderText('Setting key…').closest('form') as HTMLFormElement)

    // The form is submitted, but a blank key is not a lookup: no second GET fires.
    expect(router.countOf('GET /settings/*')).toBe(0)
  })
})
