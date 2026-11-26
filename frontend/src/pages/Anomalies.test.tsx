/**
 * ML Anomalies — the M22 engine's frontend (M22.13).
 *
 * Two kinds of assertion, and the second is what makes these tests evidence:
 *
 * 1. **What the page asked for.** The router records every request, so the page
 *    window, the classification filter, the status filter, the device key, the
 *    time range and the retrain's exact POST path are checked on the wire rather
 *    than inferred from a render.
 * 2. **What appeared on screen.** Fixtures are shaped like
 *    `app/schemas/anomaly.py`, so a wiring mistake that drops a field fails here.
 *
 * The milestone's own boundaries are asserted too, because they are the easiest
 * thing for a later change to break: **`skipped` is never rendered as normal**, a
 * `decision_score` is shown as a raw number and never as a percentage, a device
 * still collecting history stays visible in the model table, and the disclaimer
 * saying an anomaly is not proof of malice is always on the page.
 */

import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { DEFAULT_PAGE_LIMIT, NETWORK_MESSAGE } from '@/services'
import { UNKNOWN_TEXT } from '@/lib/format'
import type {
  AnomalyModel,
  AnomalyModelPage,
  AnomalyPage,
  AnomalyResult,
  AnomalySummary,
  FeatureContext,
} from '@/types'
import Anomalies from '@/pages/Anomalies'
import { failure, installFetch, networkDownFetch, ok, type RoutedCall } from '@/test/harness'

/** The sentence the page must always carry (M22.13). */
const DISCLAIMER =
  'An anomaly indicates a deviation from previously observed network behavior. ' +
  'It is not confirmation of malicious activity.'

/** The sentence explaining what a decision score is, and is not. */
const DECISION_NOTE =
  'Raw Isolation Forest decision_function output. Lower is more unusual. It is ' +
  'not a probability, not a calibrated confidence, and not comparable between ' +
  'models trained on different devices.'

/** One feature's comparison against the M21 profile. */
function featureContext(overrides: Partial<FeatureContext> = {}): FeatureContext {
  return {
    feature: 'packet_count',
    label: 'Packets per window',
    observed: 1840,
    baseline_median: 38,
    difference: 1802,
    deviation_mads: 42.1,
    far_from_centre: true,
    missing: false,
    truncated: false,
    ...overrides,
  }
}

/** One evaluated observation window. */
function anomaly(overrides: Partial<AnomalyResult> = {}): AnomalyResult {
  return {
    evaluation_id: 7,
    device_key: 'mac:aa:bb:cc:dd:ee:01',
    window_start: '2026-01-01T10:00:00+00:00',
    window_seconds: 60,
    algorithm: 'isolation_forest',
    model_version: 3,
    model_trained_at: new Date(Date.now() - 600_000).toISOString(),
    training_sample_count: 420,
    contamination: 0.02,
    decision_score: -0.1234,
    is_anomaly: true,
    status: 'scored',
    skip_reason: null,
    feature_context: [],
    alert_id: 12,
    created_at: new Date().toISOString(),
    decision_score_note: DECISION_NOTE,
    disclaimer: DISCLAIMER,
    ...overrides,
  }
}

/** A window no model could score, which is *not* a clean bill of health. */
function skipped(overrides: Partial<AnomalyResult> = {}): AnomalyResult {
  return anomaly({
    evaluation_id: 8,
    device_key: 'ip:10.0.0.99',
    model_version: 0,
    model_trained_at: null,
    training_sample_count: 0,
    contamination: null,
    decision_score: null,
    is_anomaly: false,
    status: 'skipped',
    skip_reason: 'insufficient_training_data',
    alert_id: null,
    ...overrides,
  })
}

/** The counted totals the listing sends beside its rows. */
function summary(overrides: Partial<AnomalySummary> = {}): AnomalySummary {
  return {
    evaluations: 1,
    anomalies: 1,
    affected_devices: 1,
    scored: 1,
    skipped: 0,
    ...overrides,
  }
}

/** A page of results as the listing endpoint answers. */
function anomalyPage(
  anomalies: readonly AnomalyResult[],
  overrides: Partial<AnomalyPage> = {},
): AnomalyPage {
  return {
    count: anomalies.length,
    limit: DEFAULT_PAGE_LIMIT,
    offset: 0,
    total: anomalies.length,
    has_more: false,
    anomalies,
    summary: summary(),
    disclaimer: DISCLAIMER,
    ...overrides,
  }
}

/** One device's model lifecycle. */
function model(overrides: Partial<AnomalyModel> = {}): AnomalyModel {
  return {
    device_key: 'mac:aa:bb:cc:dd:ee:01',
    identity_kind: 'mac',
    algorithm: 'isolation_forest',
    state: 'ready',
    state_label: 'Ready',
    state_description: 'A model has been trained and can score new windows.',
    model_version: 3,
    feature_names: ['packet_count', 'byte_count'],
    feature_schema_version: 1,
    training_sample_count: 420,
    training_window_count: 460,
    min_training_windows: 100,
    contamination: 0.02,
    trained_at: new Date(Date.now() - 600_000).toISOString(),
    last_evaluated_at: new Date().toISOString(),
    windows_since_training: 40,
    ready: true,
    last_error: null,
    disclaimer: DISCLAIMER,
    ...overrides,
  }
}

/** A device with too little history to have a model at all. */
function collecting(overrides: Partial<AnomalyModel> = {}): AnomalyModel {
  return model({
    device_key: 'ip:10.0.0.99',
    identity_kind: 'ip',
    state: 'collecting_data',
    state_label: 'Collecting data',
    state_description:
      'Not enough observation windows have accumulated to train a model. This device is not being checked.',
    model_version: 0,
    training_sample_count: 42,
    training_window_count: 42,
    trained_at: null,
    windows_since_training: 0,
    ready: false,
    ...overrides,
  })
}

/** A page of model lifecycles as the listing endpoint answers. */
function modelPage(
  models: readonly AnomalyModel[],
  overrides: Partial<AnomalyModelPage> = {},
): AnomalyModelPage {
  return {
    count: models.length,
    limit: DEFAULT_PAGE_LIMIT,
    offset: 0,
    total: models.length,
    has_more: false,
    models,
    disclaimer: DISCLAIMER,
    ...overrides,
  }
}

/** The retrain endpoint's answer when a new model *was* produced. */
function retrainTrained(overrides: Record<string, unknown> = {}) {
  return {
    device_key: 'mac:aa:bb:cc:dd:ee:01',
    requested: true,
    trained: true,
    state: 'ready' as const,
    state_description: 'A model has been trained and can score new windows.',
    model_version: 4,
    training_sample_count: 460,
    previous_model_retained: false,
    reason: null,
    message: 'Fitted an Isolation Forest on 460 observation windows.',
    disclaimer: DISCLAIMER,
    ...overrides,
  }
}

/** The retrain endpoint's answer when it refused — still a `200`. */
function retrainRefused(overrides: Record<string, unknown> = {}) {
  return {
    device_key: 'ip:10.0.0.99',
    requested: true,
    trained: false,
    state: 'collecting_data' as const,
    state_description:
      'Not enough observation windows have accumulated to train a model.',
    model_version: 0,
    training_sample_count: 42,
    previous_model_retained: false,
    reason: 'insufficient_training_data',
    message: '42 observation windows are available; 100 are required.',
    disclaimer: DISCLAIMER,
    ...overrides,
  }
}

/** Render the page with a toast recorder. */
function renderPage() {
  const showToast = vi.fn()
  const view = render(<Anomalies showToast={showToast} />)
  return { ...view, showToast }
}

/** The results table, scoped so a query cannot match a stat tile instead. */
function resultsTable() {
  return within(screen.getByRole('table'))
}

/**
 * Open the "Device models" tab.
 *
 * The tab button and the card heading carry the same words, so the wait is for the
 * *heading*: a plain text query would match the button that was just clicked and
 * prove nothing about the tab actually having changed.
 */
async function openModelsTab(): Promise<void> {
  await waitFor(() => {
    expect(screen.getByRole('button', { name: /device models/i })).toBeInTheDocument()
  })
  fireEvent.click(screen.getByRole('button', { name: /device models/i }))
  await waitFor(() => {
    expect(
      screen.getByRole('heading', { name: 'Device models', level: 2 }),
    ).toBeInTheDocument()
  })
}

// ─── Requesting ──────────────────────────────────────────────────────────────

describe('Anomalies requesting', () => {
  it('asks for one page of results and one page of models on mount', async () => {
    const router = installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()

    await waitFor(() => {
      expect(router.countOf('GET /anomalies')).toBe(1)
    })
    const listed = router.lastCall('GET /anomalies')
    expect(listed?.params['limit']).toBe(String(DEFAULT_PAGE_LIMIT))
    expect(listed?.params['offset']).toBe('0')

    // The model table is read up front, not lazily on tab click: the page shows
    // "N ready, M collecting" beside the results, so that figure must exist
    // before anyone opens the tab.
    await waitFor(() => {
      expect(router.countOf('GET /anomalies/models')).toBe(1)
    })
  })

  it('sends no filter while every filter is unset', async () => {
    const router = installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /anomalies')).toBe(1)
    })
    const call = router.lastCall('GET /anomalies')
    expect(call?.params['is_anomaly']).toBeUndefined()
    expect(call?.params['status']).toBeUndefined()
    expect(call?.params['device_key']).toBeUndefined()
    expect(call?.params['since']).toBeUndefined()
    expect(call?.params['until']).toBeUndefined()
  })

  it('narrows to anomalies only, restarting at the first page', async () => {
    const router = installFetch({
      'GET /anomalies': () =>
        ok(anomalyPage([anomaly()], { has_more: true, total: 120 })),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /anomalies')).toBe(1)
    })

    // Move off the first page first, so the reset to offset 0 is observable.
    fireEvent.click(screen.getByRole('button', { name: /next/i }))
    await waitFor(() => {
      expect(router.lastCall('GET /anomalies')?.params['offset']).toBe(
        String(DEFAULT_PAGE_LIMIT),
      )
    })

    fireEvent.change(screen.getByDisplayValue('All windows'), {
      target: { value: 'ANOMALIES' },
    })

    await waitFor(() => {
      expect(router.lastCall('GET /anomalies')?.params['is_anomaly']).toBe('true')
    })
    expect(router.lastCall('GET /anomalies')?.params['offset']).toBe('0')
  })

  it('narrows to inliers with the same parameter set to false', async () => {
    const router = installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /anomalies')).toBe(1)
    })

    fireEvent.change(screen.getByDisplayValue('All windows'), {
      target: { value: 'NORMAL' },
    })

    await waitFor(() => {
      expect(router.lastCall('GET /anomalies')?.params['is_anomaly']).toBe('false')
    })
  })

  it('filters by evaluation status, so a skipped window can be inspected', async () => {
    const router = installFetch({
      'GET /anomalies': () => ok(anomalyPage([skipped()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /anomalies')).toBe(1)
    })

    fireEvent.change(screen.getByDisplayValue('Any evaluation status'), {
      target: { value: 'skipped' },
    })

    await waitFor(() => {
      expect(router.lastCall('GET /anomalies')?.params['status']).toBe('skipped')
    })
  })

  it('filters by device key, trimmed, and restarts at the first page', async () => {
    const router = installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /anomalies')).toBe(1)
    })

    fireEvent.change(screen.getByLabelText('Filter by device key'), {
      target: { value: '  mac:aa:bb:cc:dd:ee:01  ' },
    })

    await waitFor(() => {
      expect(router.lastCall('GET /anomalies')?.params['device_key']).toBe(
        'mac:aa:bb:cc:dd:ee:01',
      )
    })
    expect(router.lastCall('GET /anomalies')?.params['offset']).toBe('0')
  })

  it('sends a time range as ISO instants the backend can parse', async () => {
    const router = installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /anomalies')).toBe(1)
    })

    fireEvent.change(screen.getByLabelText('Observation windows starting at or after'), {
      target: { value: '2026-01-01T10:00' },
    })
    await waitFor(() => {
      expect(router.lastCall('GET /anomalies')?.params['since']).toBeDefined()
    })
    // The control reports a zone-less local string; the filter must be a zoned
    // instant, or the backend would interpret the operator's clock as UTC.
    expect(String(router.lastCall('GET /anomalies')?.params['since'])).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    )

    fireEvent.change(screen.getByLabelText('Observation windows starting before'), {
      target: { value: '2026-01-02T10:00' },
    })
    await waitFor(() => {
      expect(router.lastCall('GET /anomalies')?.params['until']).toBeDefined()
    })
  })

  it('clears every filter at once', async () => {
    const router = installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()
    await waitFor(() => {
      expect(router.countOf('GET /anomalies')).toBe(1)
    })

    fireEvent.change(screen.getByLabelText('Filter by device key'), {
      target: { value: 'mac:aa:bb:cc:dd:ee:01' },
    })
    await waitFor(() => {
      expect(router.lastCall('GET /anomalies')?.params['device_key']).toBe(
        'mac:aa:bb:cc:dd:ee:01',
      )
    })

    fireEvent.click(screen.getByRole('button', { name: /clear filters/i }))

    await waitFor(() => {
      expect(router.lastCall('GET /anomalies')?.params['device_key']).toBeUndefined()
    })
  })

  it('reads the detail endpoint for the row that was opened', async () => {
    const router = installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
      'GET /anomalies/7': () => ok(anomaly({ feature_context: [featureContext()] })),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('mac:aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('mac:aa:bb:cc:dd:ee:01').closest('tr') as HTMLElement)

    await waitFor(() => {
      expect(router.countOf('GET /anomalies/7')).toBe(1)
    })
  })
})

// ─── Rendering ───────────────────────────────────────────────────────────────

describe('Anomalies rendering', () => {
  it('renders the device, its verdict, the raw score, the model and the alert', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('mac:aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })

    const table = resultsTable()
    expect(table.getByText('Flagged as unusual')).toBeInTheDocument()
    // The raw decision-function output, at four decimal places — not a percentage.
    expect(table.getByText('-0.1234')).toBeInTheDocument()
    expect(table.getByText('v3')).toBeInTheDocument()
    expect(table.getByText('420 samples')).toBeInTheDocument()
    expect(table.getByText('#12')).toBeInTheDocument()
    expect(table.getByText('just now')).toBeInTheDocument()
  })

  it('shows an inlier as within the learned range, with no anomaly wording', async () => {
    installFetch({
      'GET /anomalies': () =>
        ok(anomalyPage([
          anomaly({ is_anomaly: false, decision_score: 0.0812, alert_id: null }),
        ])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('mac:aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })

    const table = resultsTable()
    expect(table.getByText('Within learned range')).toBeInTheDocument()
    expect(table.queryByText('Flagged as unusual')).toBeNull()
    expect(table.getByText('0.0812')).toBeInTheDocument()
    // No alert was raised, and the cell says so rather than showing an id.
    expect(table.getByText(UNKNOWN_TEXT)).toBeInTheDocument()
  })

  it('renders a skipped window as not evaluated, never as normal', async () => {
    // The single most misleading thing this page could do: a window nothing could
    // score has `is_anomaly: false`, and rendering that as a clean row would
    // report the absence of evidence as evidence of normality.
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([skipped()])),
      'GET /anomalies/models': () => ok(modelPage([collecting()])),
    })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('ip:10.0.0.99')).toBeInTheDocument()
    })

    const table = resultsTable()
    expect(table.getByText('Not evaluated')).toBeInTheDocument()
    expect(table.queryByText('Within learned range')).toBeNull()
    // The score cell is unknown — not a zero, not an empty string.
    expect(table.getAllByText(UNKNOWN_TEXT).length).toBeGreaterThanOrEqual(1)
    expect(table.getByText('no model')).toBeInTheDocument()
  })

  it('states what an anomaly is, and is not', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    const { container } = renderPage()

    await waitFor(() => {
      expect(container.textContent).toMatch(/not confirmation of malicious activity/i)
    })
  })

  it('renders no probability, confidence or risk percentage anywhere', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    const { container } = renderPage()

    await waitFor(() => {
      expect(screen.getByText('mac:aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })

    expect(screen.queryByText(/confidence/i)).toBeNull()
    expect(screen.queryByText(/risk score/i)).toBeNull()
    // The score carries no unit: a `-0.1234%` would be the invented calibration
    // M22.9 forbids.
    expect(container.textContent).not.toMatch(/-0\.1234\s*%/)
  })

  it('counts the page tiles from the backend summary, not from the loaded rows', async () => {
    installFetch({
      'GET /anomalies': () =>
        ok(anomalyPage([anomaly()], {
          // Deliberately larger than the loaded rows: the tiles describe the whole
          // match set, and deriving them from one page would undercount.
          summary: summary({
            evaluations: 1204,
            anomalies: 31,
            affected_devices: 4,
            scored: 1150,
            skipped: 54,
          }),
        })),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('1,204')).toBeInTheDocument()
    })
    expect(screen.getByText('31')).toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument()
    expect(screen.getByText('54')).toBeInTheDocument()
    expect(screen.getByText('1,150 scored by a model')).toBeInTheDocument()
    expect(
      screen.getByText('No verdict issued — not the same as normal'),
    ).toBeInTheDocument()
  })

  it('shows the loaded-row count and the row range above the table', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()], { total: 90 })),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText(/1 loaded · rows 1–1/)).toBeInTheDocument()
    })
  })
})

// ─── Detail view ─────────────────────────────────────────────────────────────

describe('Anomalies detail view', () => {
  /** Render, then open the first row's verdict. */
  async function openDetail(): Promise<void> {
    await waitFor(() => {
      expect(screen.getByText('mac:aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })
    fireEvent.click(
      screen.getByText('mac:aa:bb:cc:dd:ee:01').closest('tr') as HTMLElement,
    )
  }

  it('opens one verdict with its feature context beside the baseline', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
      'GET /anomalies/7': () => ok(anomaly({ feature_context: [featureContext()] })),
    })
    renderPage()
    await openDetail()

    await waitFor(() => {
      expect(screen.getByText('Feature context')).toBeInTheDocument()
    })
    expect(screen.getByText('Isolation Forest decision')).toBeInTheDocument()
    expect(screen.getByText('v3')).toBeInTheDocument()
    expect(screen.getByText('420')).toBeInTheDocument()

    // The context row: observed value, baseline median, difference, deviation.
    expect(screen.getByText('Packets per window')).toBeInTheDocument()
    expect(screen.getByText('1,840')).toBeInTheDocument()
    expect(screen.getByText('38')).toBeInTheDocument()
    expect(screen.getByText('+1,802')).toBeInTheDocument()
    expect(screen.getByText('+42.1σ')).toBeInTheDocument()

    // The alert this verdict produced, named by id.
    expect(screen.getByText(/produced alert #12/i)).toBeInTheDocument()
  })

  it('says the feature table is a comparison, not model attribution', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
      'GET /anomalies/7': () => ok(anomaly({ feature_context: [featureContext()] })),
    })
    renderPage()
    await openDetail()

    await waitFor(() => {
      expect(screen.getByText('Feature context')).toBeInTheDocument()
    })
    expect(
      screen.getByText(/does not report which feature made it so/i),
    ).toBeInTheDocument()
  })

  it('marks an unmeasurable feature as not measured, never as zero', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
      'GET /anomalies/7': () =>
        ok(anomaly({
          feature_context: [
            featureContext({
              feature: 'new_connections',
              label: 'New conversations per window',
              observed: null,
              baseline_median: null,
              difference: null,
              deviation_mads: null,
              far_from_centre: false,
              missing: true,
            }),
          ],
        })),
    })
    renderPage()
    await openDetail()

    await waitFor(() => {
      expect(screen.getByText('New conversations per window')).toBeInTheDocument()
    })
    expect(screen.getByText('not measured')).toBeInTheDocument()
  })

  it('refuses to show a skipped window as a verdict', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([skipped()])),
      'GET /anomalies/models': () => ok(modelPage([collecting()])),
      'GET /anomalies/8': () => ok(skipped()),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('ip:10.0.0.99')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('ip:10.0.0.99').closest('tr') as HTMLElement)

    await waitFor(() => {
      expect(screen.getByText('This window was not evaluated.')).toBeInTheDocument()
    })
    // The reason is spelled out, and the absence of a verdict is explicitly not
    // evidence of normality.
    expect(
      screen.getByText(/not enough historical observation windows/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/is not evidence that the traffic was normal/i),
    ).toBeInTheDocument()
    expect(screen.getByText('no model')).toBeInTheDocument()
  })

  it('keeps the verdict on screen when the detail request fails', async () => {
    // The listing row is already in hand, so a failed detail read must not blank
    // the page: it degrades to the summary plus an error panel for the context.
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
      'GET /anomalies/7': () =>
        failure(404, 'That evaluation is no longer recorded.', [
          { field: 'evaluation_id', code: 'NOT_FOUND' },
        ]),
    })
    renderPage()
    await openDetail()

    await waitFor(() => {
      expect(screen.getByText('Unable to load this result')).toBeInTheDocument()
    })
    expect(screen.getByText('That evaluation is no longer recorded.')).toBeInTheDocument()
    // The verdict already loaded is still shown.
    expect(screen.getByText('-0.1234')).toBeInTheDocument()
  })

  it('returns to the listing', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
      'GET /anomalies/7': () => ok(anomaly()),
    })
    renderPage()
    await openDetail()
    await waitFor(() => {
      expect(screen.getByText('Back to anomaly results')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Back to anomaly results'))

    await waitFor(() => {
      expect(screen.getByText('Evaluated observation windows')).toBeInTheDocument()
    })
  })
})

// ─── Model lifecycle ─────────────────────────────────────────────────────────

describe('Anomalies model lifecycles', () => {
  it('lists a collecting device rather than hiding it', async () => {
    // A device with no model is not being checked. Omitting its row would leave
    // an operator believing it was examined and found unremarkable.
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () => ok(modelPage([model(), collecting()])),
    })
    renderPage()
    await openModelsTab()

    await waitFor(() => {
      expect(screen.getByText('Collecting data')).toBeInTheDocument()
    })
    expect(screen.getByText('ip:10.0.0.99')).toBeInTheDocument()
    expect(screen.getByText('Ready')).toBeInTheDocument()
    // The remaining-window count is the honest figure while a model is forming.
    expect(screen.getByText('58 more window(s) needed')).toBeInTheDocument()
  })

  it('shows every lifecycle state the engine can report', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () =>
        ok(modelPage([
          model({ device_key: 'mac:01', state: 'ready', state_label: 'Ready' }),
          model({ device_key: 'mac:02', state: 'stale', state_label: 'Stale' }),
          model({ device_key: 'mac:03', state: 'training', state_label: 'Training' }),
          model({
            device_key: 'mac:04',
            state: 'collecting_data',
            state_label: 'Collecting data',
          }),
          model({ device_key: 'mac:05', state: 'failed', state_label: 'Failed' }),
          model({ device_key: 'mac:06', state: 'disabled', state_label: 'Disabled' }),
        ])),
    })
    renderPage()
    await openModelsTab()

    const table = within(screen.getByRole('table'))
    for (const label of [
      'Ready', 'Stale', 'Training', 'Collecting data', 'Failed', 'Disabled',
    ]) {
      expect(table.getByText(label)).toBeInTheDocument()
    }
  })

  it('summarises how many models are ready and how many are collecting', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () => ok(modelPage([model(), collecting()])),
    })
    renderPage()
    await openModelsTab()

    await waitFor(() => {
      expect(
        screen.getByText('2 device(s) · 2 in total · 1 ready, 1 collecting data'),
      ).toBeInTheDocument()
    })
  })

  it('shows a failure reason on the row that carries one', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () =>
        ok(modelPage([
          model({
            state: 'failed',
            state_label: 'Failed',
            ready: false,
            last_error: 'Training raised: the training matrix contained a NaN.',
          }),
        ])),
    })
    renderPage()
    await openModelsTab()

    await waitFor(() => {
      expect(
        screen.getByText('Training raised: the training matrix contained a NaN.'),
      ).toBeInTheDocument()
    })
  })

  it('opens a device-level model detail view with its lifecycle and features', async () => {
    const router = installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () => ok(modelPage([model(), collecting()])),
      'GET /anomalies/models/*': () => ok(collecting()),
    })
    renderPage()
    await openModelsTab()

    await waitFor(() => {
      expect(screen.getByText('ip:10.0.0.99')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('ip:10.0.0.99').closest('tr') as HTMLElement)

    // The drill-down re-reads the single row rather than scanning the page.
    await waitFor(() => {
      expect(router.countOf('GET /anomalies/models/ip*')).toBe(1)
    })
    expect(router.lastCall('GET /anomalies/models/ip*')?.path).toBe(
      '/anomalies/models/ip%3A10.0.0.99',
    )

    await waitFor(() => {
      expect(screen.getByText('Features this model uses')).toBeInTheDocument()
    })
    expect(screen.getByText('packet_count')).toBeInTheDocument()
    expect(screen.getByText('byte_count')).toBeInTheDocument()
    expect(screen.getByText('Minimum required')).toBeInTheDocument()
    // The state is stated in words as well as by badge: not being evaluated.
    expect(screen.getByText('This device is not being evaluated.')).toBeInTheDocument()
    expect(screen.getByText(/58 more observation window\(s\)/)).toBeInTheDocument()
  })

  it('reports a device with no model row as an answer, not a failure', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
      'GET /anomalies/models/*': () =>
        failure(404, 'No anomaly model has been recorded for this device yet', [
          { field: 'device_key', code: 'NOT_FOUND' },
        ]),
    })
    renderPage()
    await openModelsTab()

    await waitFor(() => {
      expect(screen.getByText('mac:aa:bb:cc:dd:ee:01')).toBeInTheDocument()
    })
    fireEvent.click(
      screen.getByText('mac:aa:bb:cc:dd:ee:01').closest('tr') as HTMLElement,
    )

    await waitFor(() => {
      expect(screen.getByText('No model for this device')).toBeInTheDocument()
    })
    expect(
      screen.getByText(/not a report that the device's traffic is normal/i),
    ).toBeInTheDocument()
  })
})

// ─── Retraining ──────────────────────────────────────────────────────────────

describe('Anomalies retraining', () => {
  /** Open the models tab and click the first row's retrain button. */
  async function openRetrainDialog(): Promise<void> {
    await openModelsTab()
    fireEvent.click(screen.getByRole('button', { name: /^retrain$/i }))
    await waitFor(() => {
      expect(
        screen.getByText("Retrain this device's anomaly model?"),
      ).toBeInTheDocument()
    })
  }

  it('asks for confirmation before sending the POST', async () => {
    const router = installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
      'POST /anomalies/models/mac*': () => ok(retrainTrained()),
    })
    renderPage()
    await openRetrainDialog()

    // Nothing has been sent yet: the dialog is the confirmation step.
    expect(router.countOf('POST /anomalies/models/mac*')).toBe(0)

    const dialog = within(screen.getByRole('dialog'))
    fireEvent.click(dialog.getByRole('button', { name: /^retrain$/i }))

    await waitFor(() => {
      expect(router.countOf('POST /anomalies/models/mac*')).toBe(1)
    })
    expect(router.lastCall('POST /anomalies/models/mac*')?.path).toBe(
      '/anomalies/models/mac%3Aaa%3Abb%3Acc%3Add%3Aee%3A01/retrain',
    )
  })

  it('reports a produced model as success, reading `trained` from the payload', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
      'POST /anomalies/models/mac*': () => ok(retrainTrained()),
    })
    const { showToast } = renderPage()
    await openRetrainDialog()

    const dialog = within(screen.getByRole('dialog'))
    fireEvent.click(dialog.getByRole('button', { name: /^retrain$/i }))

    await waitFor(() => {
      expect(showToast).toHaveBeenCalledWith(
        expect.stringContaining(
          'Fitted an Isolation Forest on 460 observation windows.',
        ),
        'success',
      )
    })
  })

  it('reports a refused retrain as information, not as success', async () => {
    // The endpoint answers `200` for a refusal, so a page that trusted the status
    // would report a model that was never trained.
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () => ok(modelPage([collecting()])),
      'POST /anomalies/models/ip*': () => ok(retrainRefused()),
    })
    const { showToast } = renderPage()
    await openRetrainDialog()

    const dialog = within(screen.getByRole('dialog'))
    fireEvent.click(dialog.getByRole('button', { name: /^retrain$/i }))

    await waitFor(() => {
      expect(showToast).toHaveBeenCalledWith(
        '42 observation windows are available; 100 are required.',
        'info',
      )
    })
    expect(showToast).not.toHaveBeenCalledWith(expect.anything(), 'success')
  })

  it('reports a refused request as an error, and never as success', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
      'POST /anomalies/models/mac*': () =>
        failure(503, 'The anomaly store is unavailable.', [
          { field: 'database', code: 'SERVICE_UNAVAILABLE' },
        ]),
    })
    const { showToast } = renderPage()
    await openRetrainDialog()

    const dialog = within(screen.getByRole('dialog'))
    fireEvent.click(dialog.getByRole('button', { name: /^retrain$/i }))

    await waitFor(() => {
      expect(showToast).toHaveBeenCalledWith(
        'The anomaly store is unavailable.',
        'error',
      )
    })
    expect(showToast).not.toHaveBeenCalledWith(expect.anything(), 'success')
  })

  it('cancels without sending anything', async () => {
    const router = installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()
    await openRetrainDialog()

    const dialog = within(screen.getByRole('dialog'))
    fireEvent.click(dialog.getByRole('button', { name: /^cancel$/i }))

    await waitFor(() => {
      expect(screen.queryByText("Retrain this device's anomaly model?")).toBeNull()
    })
    expect(router.countOf('POST /anomalies/models*')).toBe(0)
  })

  it('re-reads both listings after a retrain, so the tables are not stale', async () => {
    const router = installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
      'POST /anomalies/models/mac*': () => ok(retrainTrained()),
    })
    renderPage()
    await openRetrainDialog()

    const dialog = within(screen.getByRole('dialog'))
    fireEvent.click(dialog.getByRole('button', { name: /^retrain$/i }))

    await waitFor(() => {
      expect(router.countOf('GET /anomalies/models')).toBeGreaterThanOrEqual(2)
    })
    expect(router.countOf('GET /anomalies')).toBeGreaterThanOrEqual(2)
  })

  it('states that a retrain modifies neither history nor traffic', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()
    await openRetrainDialog()

    expect(
      screen.getByText(
        /Behavioural history, packets, alerts and incidents are not modified/i,
      ),
    ).toBeInTheDocument()
    expect(screen.getByText(/No device is blocked or quarantined/i)).toBeInTheDocument()
  })
})

// ─── Loading, empty and error states ─────────────────────────────────────────

describe('Anomalies loading, empty and error states', () => {
  it('shows a busy panel while the first request is in flight', () => {
    installFetch({
      'GET /anomalies': () => new Promise<Response>(() => {}),
      'GET /anomalies/models': () => ok(modelPage([])),
    })
    renderPage()
    expect(screen.getByText('Loading anomaly results…')).toBeInTheDocument()
  })

  it('says what would populate an empty result set', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () => ok(modelPage([])),
    })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('No windows evaluated yet')).toBeInTheDocument()
    })
    // The preconditions are named rather than left to the reader's imagination.
    expect(screen.getByText(/100 windows by default/i)).toBeInTheDocument()
  })

  it('distinguishes a filter that matched nothing from an empty engine', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () => ok(modelPage([])),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('No windows evaluated yet')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByDisplayValue('All windows'), {
      target: { value: 'ANOMALIES' },
    })

    await waitFor(() => {
      expect(screen.getByText('No results match this filter')).toBeInTheDocument()
    })
    expect(screen.queryByText('No windows evaluated yet')).toBeNull()
  })

  it('offers to clear the filters when one matched nothing', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () => ok(modelPage([])),
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('No windows evaluated yet')).toBeInTheDocument()
    })

    fireEvent.change(screen.getByDisplayValue('All windows'), {
      target: { value: 'NORMAL' },
    })

    await waitFor(() => {
      expect(
        screen.getByText(
          /Clear or change the filters to see every recorded evaluation/i,
        ),
      ).toBeInTheDocument()
    })
  })

  it('shows a usable error panel when the backend cannot be reached', async () => {
    vi.stubGlobal('fetch', networkDownFetch())
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Unable to load anomaly results')).toBeInTheDocument()
    })
    expect(screen.getByText(NETWORK_MESSAGE)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('does not report a failed request as an empty engine', async () => {
    vi.stubGlobal('fetch', networkDownFetch())
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('Unable to load anomaly results')).toBeInTheDocument()
    })
    expect(screen.queryByText('No windows evaluated yet')).toBeNull()
  })

  it('says there is nothing to report when no model row exists yet', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([])),
      'GET /anomalies/models': () => ok(modelPage([])),
    })
    renderPage()
    await openModelsTab()

    await waitFor(() => {
      expect(screen.getByText('No device models yet')).toBeInTheDocument()
    })
    expect(screen.getByText(/nothing being checked/i)).toBeInTheDocument()
  })
})

// ─── Pagination ──────────────────────────────────────────────────────────────

describe('Anomalies pagination', () => {
  it('offers no next page when the engine reported no more rows', async () => {
    installFetch({
      'GET /anomalies': () => ok(anomalyPage([anomaly()], { has_more: false })),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('All anomaly results')).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: /next/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /previous/i })).toBeDisabled()
  })

  it('pages forward by the page size when more rows exist', async () => {
    const router = installFetch({
      'GET /anomalies': (call: RoutedCall) =>
        call.params['offset'] === '0'
          ? ok(anomalyPage([anomaly()], { has_more: true, total: 120 }))
          : ok(anomalyPage([anomaly({ evaluation_id: 9, device_key: 'mac:02' })], {
              offset: DEFAULT_PAGE_LIMIT,
              has_more: false,
              total: 120,
            })),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /next/i })).toBeEnabled()
    })
    fireEvent.click(screen.getByRole('button', { name: /next/i }))

    await waitFor(() => {
      expect(router.lastCall('GET /anomalies')?.params['offset']).toBe(
        String(DEFAULT_PAGE_LIMIT),
      )
    })
  })

  it('pages back to the first window, and no further', async () => {
    const router = installFetch({
      'GET /anomalies': (call: RoutedCall) =>
        call.params['offset'] === '0'
          ? ok(anomalyPage([anomaly()], { has_more: true, total: 120 }))
          : ok(anomalyPage([anomaly({ evaluation_id: 9 })], {
              offset: DEFAULT_PAGE_LIMIT,
              has_more: true,
              total: 120,
            })),
      'GET /anomalies/models': () => ok(modelPage([model()])),
    })
    renderPage()

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /next/i })).toBeEnabled()
    })
    fireEvent.click(screen.getByRole('button', { name: /next/i }))
    await waitFor(() => {
      expect(router.lastCall('GET /anomalies')?.params['offset']).toBe(
        String(DEFAULT_PAGE_LIMIT),
      )
    })

    fireEvent.click(screen.getByRole('button', { name: /previous/i }))

    await waitFor(() => {
      expect(router.lastCall('GET /anomalies')?.params['offset']).toBe('0')
    })
  })
})
