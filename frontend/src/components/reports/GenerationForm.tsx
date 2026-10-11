/**
 * The report generation form (M17.4–M17.6).
 *
 * Three choices, and the form makes each one explicit rather than implicit:
 *
 * * **A preset or a custom period, never both.** Daily and weekly derive their
 *   bounds from the UTC calendar — the previous completed day, the previous
 *   completed Monday-to-Sunday week — and a custom report names its own. The
 *   backend refuses a request that tries to be both rather than quietly preferring
 *   one (M17.6), so the form never sends both: choosing a preset hides the date
 *   fields, and the chosen preset is what goes on the wire.
 * * **The format is named, not assumed.** PDF is the default because the reader of
 *   a report is a person, but the choice is shown, and CSV is one click away.
 * * **The dates are UTC days and say so.** A `date` input yields a bare calendar
 *   day, which {@link resolveCustomBounds} turns into half-open ISO-8601 UTC bounds
 *   — the last chosen day is *included*, which is what an operator means and what a
 *   half-open period has to be converted to.
 *
 * A request the form already knows is unanswerable — a custom report with no days,
 * or with the last before the first — is refused here, with the same kind of
 * sentence the backend would use, rather than sent to be rejected. Nothing about
 * that replaces the backend's validation: the response is still what decides, and
 * a refusal from it is rendered as itself.
 */

import { useState } from 'react'
import { CalendarRange, FileDown } from 'lucide-react'
import { C, tint } from '@/lib/tokens'
import { REPORT_FORMATS, REPORT_TYPES } from '@/types'
import type { ReportGenerationRequest } from '@/types'
import { resolveCustomBounds } from './reportDisplay'

/** The presets, with the period each one covers, as a short label. */
const TYPE_LABELS: Readonly<Record<string, string>> = {
  daily: 'Previous day',
  weekly: 'Previous week',
  custom: 'Custom range',
}

/** The sentence each preset covers its period with, shown under the choice. */
const TYPE_HINTS: Readonly<Record<string, string>> = {
  daily: 'The previous completed UTC day.',
  weekly: 'The previous completed Monday-to-Sunday UTC week.',
  custom: 'A period you name, in whole UTC days.',
}

/** What the custom pair is called, so a test and the page agree on the label. */
export const CUSTOM_FROM_LABEL = 'First day (UTC, inclusive)'
export const CUSTOM_TO_LABEL = 'Last day (UTC, inclusive)'

/** A request under construction. Mutable, because it is built field by field. */
interface DraftRequest {
  report_type?: string
  format?: string
  title?: string
  since?: string
  until?: string
}

export interface GenerationFormProps {
  /** True while a generation request is in flight. */
  readonly isSubmitting: boolean
  /** Issue a generation request. */
  readonly onSubmit: (request: ReportGenerationRequest) => void
}

export function GenerationForm({ isSubmitting, onSubmit }: GenerationFormProps) {
  const [reportType, setReportType] = useState<string>(REPORT_TYPES[0])
  const [outputFormat, setOutputFormat] = useState<string>(REPORT_FORMATS[0])
  const [title, setTitle] = useState('')
  const [fromDay, setFromDay] = useState('')
  const [toDay, setToDay] = useState('')
  const [problem, setProblem] = useState<string | null>(null)

  const isCustom = reportType === 'custom'

  const submit = (event: React.FormEvent): void => {
    event.preventDefault()
    const request: DraftRequest = { report_type: reportType, format: outputFormat }
    const trimmedTitle = title.trim()
    if (trimmedTitle !== '') request.title = trimmedTitle

    if (isCustom) {
      const bounds = resolveCustomBounds(fromDay, toDay)
      if (bounds.problem !== null) {
        // The backend would refuse this too, but a round trip to be told what the
        // form can already see is a worse experience than saying it here.
        setProblem(bounds.problem)
        return
      }
      if (bounds.since !== null) request.since = bounds.since
      if (bounds.until !== null) request.until = bounds.until
    }

    setProblem(null)
    onSubmit(request)
  }

  return (
    <form
      onSubmit={submit}
      className="rounded-2xl border p-5 space-y-4"
      style={{ backgroundColor: C.card, borderColor: C.border }}
    >
      <div className="flex items-center gap-2">
        <FileDown size={15} style={{ color: C.accent }} />
        <h2 className="text-sm font-semibold text-white">Generate a report</h2>
      </div>

      <fieldset>
        <legend className="text-xs mb-1.5" style={{ color: C.faint }}>
          Period
        </legend>
        <div className="flex items-center gap-2 flex-wrap">
          {REPORT_TYPES.map((type) => {
            const selected = reportType === type
            return (
              <button
                key={type}
                type="button"
                onClick={() => {
                  setReportType(type)
                  setProblem(null)
                }}
                aria-pressed={selected}
                className="px-3 py-2 rounded-xl text-xs font-medium border"
                style={{
                  borderColor: selected ? tint(C.accent, 0.5) : C.border,
                  backgroundColor: selected ? tint(C.accent, 0.12) : C.panel,
                  color: selected ? C.accent : C.muted,
                }}
              >
                {TYPE_LABELS[type] ?? type}
              </button>
            )
          })}
        </div>
        <p className="text-xs mt-1.5" style={{ color: C.faint }}>
          {TYPE_HINTS[reportType] ?? ''}
        </p>
      </fieldset>

      {isCustom && (
        <div className="grid grid-cols-2 gap-3">
          <label className="space-y-1.5">
            <span className="text-xs" style={{ color: C.faint }}>
              {CUSTOM_FROM_LABEL}
            </span>
            <input
              type="date"
              value={fromDay}
              onChange={(event) => {
                setFromDay(event.target.value)
                setProblem(null)
              }}
              className="w-full px-3 py-2 rounded-xl border text-xs"
              style={{ backgroundColor: C.panel, borderColor: C.border, color: C.text }}
            />
          </label>
          <label className="space-y-1.5">
            <span className="text-xs" style={{ color: C.faint }}>
              {CUSTOM_TO_LABEL}
            </span>
            <input
              type="date"
              value={toDay}
              onChange={(event) => {
                setToDay(event.target.value)
                setProblem(null)
              }}
              className="w-full px-3 py-2 rounded-xl border text-xs"
              style={{ backgroundColor: C.panel, borderColor: C.border, color: C.text }}
            />
          </label>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3">
        <fieldset>
          <legend className="text-xs mb-1.5" style={{ color: C.faint }}>
            Format
          </legend>
          <div className="flex items-center gap-2">
            {REPORT_FORMATS.map((format) => {
              const selected = outputFormat === format
              return (
                <button
                  key={format}
                  type="button"
                  onClick={() => setOutputFormat(format)}
                  aria-pressed={selected}
                  className="px-3 py-2 rounded-xl text-xs font-medium mono border"
                  style={{
                    borderColor: selected ? tint(C.info, 0.5) : C.border,
                    backgroundColor: selected ? tint(C.info, 0.12) : C.panel,
                    color: selected ? C.info : C.muted,
                  }}
                >
                  {format}
                </button>
              )
            })}
          </div>
        </fieldset>

        <label className="space-y-1.5">
          <span className="text-xs" style={{ color: C.faint }}>
            Title (optional)
          </span>
          <input
            value={title}
            onChange={(event) => setTitle(event.target.value)}
            placeholder="Defaults to the period"
            className="w-full px-3 py-2 rounded-xl border text-xs"
            style={{
              backgroundColor: C.panel,
              borderColor: C.border,
              color: C.text,
              outline: 'none',
            }}
          />
        </label>
      </div>

      {problem !== null && (
        <p className="text-xs" style={{ color: C.danger }} role="alert">
          {problem}
        </p>
      )}

      <div className="flex items-center justify-between gap-3 flex-wrap">
        <p className="text-xs flex items-start gap-1.5 max-w-xl" style={{ color: C.faint }}>
          <CalendarRange size={12} style={{ flexShrink: 0, marginTop: 2 }} />
          <span>
            The period is half-open: the first instant is included and the last is
            not, so two consecutive reports never count the same record twice. A
            generated report is written to the store and can be downloaded
            afterwards.
          </span>
        </p>
        <button
          type="submit"
          disabled={isSubmitting}
          className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold disabled:opacity-50 shrink-0"
          style={{ backgroundColor: tint(C.accent, 0.15), color: C.accent }}
        >
          <FileDown size={12} className={isSubmitting ? 'animate-pulse' : undefined} />
          {isSubmitting ? 'Generating…' : 'Generate report'}
        </button>
      </div>
    </form>
  )
}
