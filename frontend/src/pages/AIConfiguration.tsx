/**
 * AI Configuration (M23.11).
 *
 * The one page an operator visits to answer "is local AI working, and what does it
 * say?". It is a *configuration and test* surface, not an analyst one: nothing here
 * explains an alert, and nothing here writes to a detection, incident or risk
 * record (M23.16).
 *
 * Four decisions are visible in the layout:
 *
 * * **State first, controls second.** `/ai/status` answers `200` with one of four
 *   words, so the page leads with a badge and a sentence rather than an error. A
 *   disabled feature and a stopped runtime look different on purpose — an operator
 *   fixes them differently, so the page must not flatten them.
 * * **The test form is gated, not hidden.** It stays visible when unusable so an
 *   operator can see what it will do once the runtime is running, with the button
 *   disabled and the reason stated.
 * * **The waiting phase is labelled with a measurement.** M23 does not stream, so
 *   the browser learns nothing until the reply is complete and cannot know whether
 *   the model is loading or generating. The page says which is *likely*, based on
 *   elapsed time against the ~9 s cold load measured on the reference machine.
 * * **The disclaimer is not dismissible.** The reply is text a language model
 *   produced; it is rendered as text, never as markup, and the sentence saying what
 *   it is not travels with it.
 */

import { useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertCircle, CheckCircle2, Clock, Cpu, Download, Info, Play, RefreshCw, Server,
} from 'lucide-react'
import { C, tint } from '../lib/tokens'
import { useAiStatus, useAiTest } from '../hooks'
import type { ToastMsg } from '../App'
import type { AiModel, AiModelList, AiState, AiStatus, AiTestResult } from '../types'
import type { ApiError } from '../services'

interface Props {
  showToast: (message: string, type?: ToastMsg['type']) => void
}

/**
 * Past this many milliseconds a cold start is unlikely to be the explanation.
 *
 * Measured, not guessed: a true cold load of `llama3.2:3b` took **9,074 ms** on the
 * reference machine, so ten seconds is that figure rounded up. The label switches
 * when the measurement says it should.
 */
const COLD_LOAD_MS = 10_000

/** How often the elapsed-time label refreshes during a generation. */
const ELAPSED_TICK_MS = 500

/** A colour and icon per state, so the badge reads at a glance. */
const STATE_STYLES: Readonly<
  Record<AiState, { color: string; icon: typeof CheckCircle2 }>
> = {
  ready: { color: C.success, icon: CheckCircle2 },
  disabled: { color: C.faint, icon: Info },
  unreachable: { color: C.warning, icon: AlertCircle },
  model_missing: { color: C.orange, icon: Download },
}

/** Format a byte count as something an operator can compare at a glance. */
function formatSize(bytes: number): string {
  if (!bytes) return '—'
  const gb = bytes / 1_000_000_000
  return gb >= 1 ? `${gb.toFixed(2)} GB` : `${Math.round(bytes / 1_000_000)} MB`
}

/** One labelled fact in the configuration panel. */
function Fact({
  label, value, mono = false,
}: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] font-semibold uppercase tracking-widest"
        style={{ color: C.dim }}>
        {label}
      </div>
      <div className={`text-sm truncate ${mono ? 'mono' : ''}`}
        style={{ color: value ? C.text : C.faint }}
        title={value || undefined}>
        {value || '—'}
      </div>
    </div>
  )
}

/** The state badge plus the sentence explaining it. */
function StatePanel({ status }: { status: AiStatus }) {
  const style = STATE_STYLES[status.state] ?? STATE_STYLES.disabled
  const Icon = style.icon
  return (
    <div className="rounded-2xl border p-5"
      style={{ backgroundColor: C.panel, borderColor: C.border }}>
      <div className="flex items-start gap-3">
        <div className="flex items-center justify-center w-9 h-9 rounded-xl shrink-0"
          style={{ backgroundColor: tint(style.color, 0.15) }}>
          <Icon size={18} style={{ color: style.color }} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-bold" style={{ color: style.color }}>
              {status.state_label}
            </span>
            {status.runtime_version && (
              <span className="text-[10px] mono px-1.5 py-0.5 rounded"
                style={{ backgroundColor: C.card, color: C.muted }}>
                runtime {status.runtime_version}
              </span>
            )}
          </div>
          <p className="text-xs mt-1 leading-relaxed" style={{ color: C.muted }}>
            {status.state_description}
          </p>
          {status.message && (
            <p className="text-xs mt-1.5" style={{ color: C.faint }}>
              {status.message}
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

export default function AIConfiguration({ showToast }: Props) {
  const {
    status, state, models, modelList, modelsError, blockingError, isInitialLoading,
    reload,
  } = useAiStatus()
  const test = useAiTest()

  const [prompt, setPrompt] = useState(
    'In one sentence, what does a port scan typically indicate?',
  )
  const [elapsedMs, setElapsedMs] = useState(0)
  const startedAt = useRef<number>(0)

  // The elapsed label is sampled while a generation is in flight and reset when it
  // finishes, so a second test starts from zero rather than from the first one's
  // duration.
  useEffect(() => {
    if (!test.isRunning) {
      setElapsedMs(0)
      return
    }
    startedAt.current = performance.now()
    const timer = window.setInterval(
      () => setElapsedMs(performance.now() - startedAt.current),
      ELAPSED_TICK_MS,
    )
    return () => window.clearInterval(timer)
  }, [test.isRunning])

  const ready = state === 'ready'
  const canSubmit = ready && !test.isRunning && prompt.trim().length > 0

  /**
   * What the wait is probably for.
   *
   * An inference, not a report: M23 does not stream, so the browser receives
   * nothing until the reply is complete and cannot tell a model load from a slow
   * generation. The threshold is the measured cold load, and the wording says
   * "likely" for that reason.
   */
  const waitPhase = useMemo(() => {
    if (!test.isRunning) return ''
    return elapsedMs < COLD_LOAD_MS
      ? 'Likely loading the model'
      : 'Generating the reply'
  }, [test.isRunning, elapsedMs])

  const submit = async () => {
    const outcome = await test.run(prompt.trim())
    if (!outcome.ok) {
      // The backend's own sentence already distinguishes disabled from unreachable
      // from a timeout, so it is shown unchanged.
      showToast(outcome.error.message, 'error')
      return
    }
    showToast(
      outcome.value.done_reason === 'length'
        ? 'The model stopped at the output limit, so the reply may be cut off.'
        : 'Test generation completed.',
      outcome.value.done_reason === 'length' ? 'info' : 'success',
    )
  }

  return (
    <div className="max-w-5xl mx-auto space-y-5">
      <header className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-white">AI Configuration</h1>
          <p className="text-xs mt-1" style={{ color: C.muted }}>
            The local model runtime this application talks to, and a bounded test of
            it. Infrastructure only — no alert is explained here and no detection,
            incident or risk score is affected.
          </p>
        </div>
        <button
          onClick={reload}
          disabled={isInitialLoading}
          className="flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold disabled:opacity-50"
          style={{ backgroundColor: C.card, color: C.muted }}>
          <RefreshCw size={13} className={isInitialLoading ? 'animate-spin' : ''} />
          Re-check
        </button>
      </header>

      {isInitialLoading && (
        <div className="rounded-2xl border p-8 text-center"
          style={{ backgroundColor: C.panel, borderColor: C.border }}>
          <Clock size={20} className="animate-pulse mx-auto" style={{ color: C.faint }} />
          <p className="text-xs mt-2" style={{ color: C.muted }}>
            Checking the runtime…
          </p>
          <p className="text-[11px] mt-1" style={{ color: C.dim }}>
            The probe has a three-second budget, so this cannot hang.
          </p>
        </div>
      )}

      {/* A failed status request is not a state — it means the backend itself did
          not answer. Saying so is different from claiming the runtime is down,
          which only `/ai/status` can establish. */}
      {blockingError && (
        <div className="rounded-2xl border p-5"
          style={{ backgroundColor: tint(C.danger, 0.08), borderColor: C.danger }}>
          <div className="flex items-center gap-2">
            <AlertCircle size={14} style={{ color: C.danger }} />
            <h2 className="text-sm font-bold" style={{ color: C.danger }}>
              The AI status could not be read
            </h2>
          </div>
          <p className="text-xs mt-1.5 leading-relaxed" style={{ color: C.muted }}>
            {blockingError.message}
          </p>
          <p className="text-[11px] mt-1.5" style={{ color: C.faint }}>
            This is a failed request, not a missing model: nothing here can say what
            the runtime is doing until the backend answers again.
          </p>
          <button
            onClick={reload}
            className="flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold mt-3"
            style={{ backgroundColor: C.card, color: C.muted }}>
            <RefreshCw size={13} />
            Retry
          </button>
        </div>
      )}

      {status && (
        <>
          <StatePanel status={status} />

          <div className="rounded-2xl border p-5"
            style={{ backgroundColor: C.panel, borderColor: C.border }}>
            <div className="flex items-center gap-2 mb-4">
              <Server size={14} style={{ color: C.accent }} />
              <h2 className="text-sm font-bold text-white">Configuration</h2>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <Fact label="Enabled" value={status.enabled ? 'yes' : 'no'} />
              <Fact label="Provider" value={status.provider} mono />
              <Fact label="Model" value={status.model} mono />
              <Fact label="Runtime reachable" value={status.runtime_reachable ? 'yes' : 'no'} />
              <Fact label="Model installed" value={status.model_available ? 'yes' : 'no'} />
              <Fact label="Installed models" value={String(status.installed_model_count)} />
              <Fact label="Runtime version" value={status.runtime_version} mono />
              <Fact label="Probe budget"
                value={status.health_timeout_seconds > 0
                  ? `${status.health_timeout_seconds.toFixed(1)}s`
                  : ''} />
            </div>
            <div className="mt-4 pt-3 border-t" style={{ borderColor: C.card }}>
              <p className="text-[11px] leading-relaxed" style={{ color: C.faint }}>
                <strong style={{ color: C.muted }}>Enabled</strong> here mirrors the
                <span className="mono"> LLM_ENABLED </span> configuration value. The
                database setting named <span className="mono">ai_enabled</span> on the
                Settings page is a different, older switch and does not control this
                runtime.
              </p>
            </div>
          </div>

          <ModelTable status={status} models={models} modelList={modelList}
            modelsError={modelsError} />

          <div className="rounded-2xl border p-5"
            style={{ backgroundColor: C.panel, borderColor: C.border }}>
            <div className="flex items-center gap-2 mb-3">
              <Play size={14} style={{ color: C.accent }} />
              <h2 className="text-sm font-bold text-white">Test generation</h2>
            </div>

            <label htmlFor="ai-prompt" className="block text-[11px] font-semibold mb-1.5"
              style={{ color: C.muted }}>
              Prompt
            </label>
            <textarea
              id="ai-prompt"
              value={prompt}
              onChange={event => setPrompt(event.target.value)}
              rows={3}
              disabled={test.isRunning}
              placeholder="Ask the configured model something short."
              className="w-full px-3 py-2 rounded-xl text-xs mono resize-y outline-none disabled:opacity-60"
              style={{
                backgroundColor: C.card,
                color: C.text,
                border: `1px solid ${C.border}`,
              }}
            />
            <div className="flex items-center justify-between mt-1.5 gap-3 flex-wrap">
              <span className="text-[11px]" style={{ color: C.dim }}>
                {prompt.length} characters. The backend refuses anything longer than
                its configured limit.
              </span>
              {!ready && (
                <span className="text-[11px]" style={{ color: C.faint }}>
                  Unavailable while the state is “{status.state_label.toLowerCase()}”.
                </span>
              )}
            </div>

            <div className="flex items-center gap-3 mt-3 flex-wrap">
              <button
                onClick={() => void submit()}
                disabled={!canSubmit}
                className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold disabled:opacity-40 disabled:cursor-not-allowed"
                style={{ backgroundColor: C.accent, color: C.panel }}>
                {test.isRunning ? (
                  <>
                    <RefreshCw size={13} className="animate-spin" />
                    Working…
                  </>
                ) : (
                  <>
                    <Play size={13} />
                    Send test prompt
                  </>
                )}
              </button>
              {test.isRunning && (
                <span className="text-[11px] flex items-center gap-1.5"
                  style={{ color: C.muted }}>
                  <Clock size={11} />
                  {waitPhase} · {(elapsedMs / 1000).toFixed(1)}s
                </span>
              )}
            </div>
          </div>

          {test.error && (
            <div className="rounded-2xl border p-4"
              style={{ backgroundColor: tint(C.danger, 0.08), borderColor: C.danger }}>
              <div className="text-xs font-bold" style={{ color: C.danger }}>
                The test did not produce a reply
              </div>
              <p className="text-xs mt-1 leading-relaxed" style={{ color: C.muted }}>
                {test.error.message}
              </p>
            </div>
          )}

          {test.result && <ReplyPanel result={test.result} />}
        </>
      )}
    </div>
  )
}

/** The inventory, or an honest statement about why there is none. */
function ModelTable({
  status, models, modelList, modelsError,
}: {
  status: AiStatus
  models: readonly AiModel[]
  modelList: AiModelList | null
  modelsError: ApiError | null
}) {
  return (
    <div className="rounded-2xl border p-5"
      style={{ backgroundColor: C.panel, borderColor: C.border }}>
      <div className="flex items-center gap-2 mb-3">
        <Cpu size={14} style={{ color: C.accent }} />
        <h2 className="text-sm font-bold text-white">Installed models</h2>
        <span className="text-[10px] mono px-1.5 py-0.5 rounded"
          style={{ backgroundColor: C.card, color: C.muted }}>
          {modelList?.count ?? models.length}
        </span>
      </div>

      {modelsError ? (
        <p className="text-xs" style={{ color: C.warning }}>
          The model list could not be read: {modelsError.message}
        </p>
      ) : !status.runtime_reachable ? (
        <p className="text-xs" style={{ color: C.faint }}>
          Not read — the runtime is not answering, so there is no inventory to list.
          This is not the same as an empty inventory.
        </p>
      ) : models.length === 0 ? (
        <p className="text-xs" style={{ color: C.faint }}>
          The runtime is running and reports no models. Install one with the runtime's
          own pull command (in this milestone: ollama pull, followed by the model name);
          this application never downloads one on its own.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr style={{ color: C.dim }}>
                <th className="text-left font-semibold py-1.5 pr-3">Model</th>
                <th className="text-left font-semibold py-1.5 pr-3">Size</th>
                <th className="text-left font-semibold py-1.5 pr-3">Quantization</th>
                <th className="text-left font-semibold py-1.5 pr-3">Family</th>
                <th className="text-left font-semibold py-1.5">Configured</th>
              </tr>
            </thead>
            <tbody>
              {models.map(model => (
                <tr key={model.name} className="border-t" style={{ borderColor: C.card }}>
                  <td className="py-1.5 pr-3 mono" style={{ color: C.text }}>
                    {model.name}
                  </td>
                  <td className="py-1.5 pr-3" style={{ color: C.muted }}>
                    {formatSize(model.size_bytes)}
                  </td>
                  <td className="py-1.5 pr-3 mono" style={{ color: C.muted }}>
                    {model.quantization || '—'}
                  </td>
                  <td className="py-1.5 pr-3" style={{ color: C.muted }}>
                    {model.family || '—'}
                  </td>
                  <td className="py-1.5">
                    {model.name === status.model ? (
                      <span className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                        style={{ backgroundColor: tint(C.success, 0.15), color: C.success }}>
                        in use
                      </span>
                    ) : (
                      <span style={{ color: C.dim }}>—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {modelList?.configured_model && status.runtime_reachable &&
        modelList.configured_model_installed === false && (
          <p className="text-[11px] mt-3" style={{ color: C.orange }}>
            The configured model <span className="mono">{status.model}</span> is not in
            the inventory above. Set <span className="mono"> LLM_MODEL </span> to one of
            these names, or install the configured one.
          </p>
        )}
    </div>
  )
}

/** The generated reply, its metadata and the disclaimer. */
function ReplyPanel({ result }: { result: AiTestResult }) {
  return (
    <div className="rounded-2xl border p-5"
      style={{ backgroundColor: C.panel, borderColor: C.border }}>
      <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
        <h2 className="text-sm font-bold text-white">Generated reply</h2>
        <div className="flex items-center gap-2 flex-wrap text-[10px] mono">
          <span className="px-1.5 py-0.5 rounded"
            style={{ backgroundColor: C.card, color: C.muted }}>
            {result.model}
          </span>
          <span className="px-1.5 py-0.5 rounded"
            style={{ backgroundColor: C.card, color: C.muted }}>
            {result.output_tokens} tok
          </span>
          <span className="px-1.5 py-0.5 rounded"
            style={{ backgroundColor: C.card, color: C.muted }}>
            {(result.duration_ms / 1000).toFixed(1)}s
          </span>
          {result.done_reason === 'length' && (
            <span className="px-1.5 py-0.5 rounded"
              style={{ backgroundColor: tint(C.warning, 0.15), color: C.warning }}>
              cut off at the output limit
            </span>
          )}
        </div>
      </div>

      {/* Rendered as text, never as markup: model output is untrusted. */}
      <pre className="text-xs whitespace-pre-wrap wrap-break-word leading-relaxed rounded-xl p-3"
        style={{ backgroundColor: C.card, color: C.text }}>
        {result.response}
      </pre>

      <p className="text-[11px] mt-3 leading-relaxed flex items-start gap-1.5"
        style={{ color: C.faint }}>
        <Info size={11} className="shrink-0 mt-0.5" />
        {result.disclaimer}
      </p>
    </div>
  )
}
