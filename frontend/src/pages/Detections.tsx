/**
 * Detections — M10's findings and the detector table (M15.20).
 *
 * The distinction this page exists to hold is that **a finding is not an alert**.
 * A finding is a raw observation: it has no severity, no lifecycle and no risk
 * score, and only some findings go on to raise an alert — which is M11's decision,
 * not this page's. So the findings list is not "alerts awaiting triage", it does
 * not offer acknowledge/resolve, and it does not colour a row by how bad it looks.
 * A finding shows what the detector observed and how strong the evidence is.
 *
 * The detector table and the finding list are read together but kept apart: the
 * first says which detectors exist and whether they are being evaluated, the second
 * says what they have seen. A detector with zero findings is not broken, and the
 * diagnostics beside the table are what make that readable.
 *
 * M10 publishes no WebSocket channel, so there is no live path here. Findings are
 * read from REST and refreshed explicitly; the alerts derived from them are what
 * M14 streams (M15.34).
 */

import { useMemo, useState } from 'react'
import {
  Crosshair, RefreshCw, Search, Radar, Activity, AlertTriangle,
  Clock, Server, Network, Hash, RotateCcw, FileText, Bug,
} from 'lucide-react'
import {
  AsyncSection, EmptyState, RefreshFailureBanner,
} from '@/components/AsyncState'
import { KeyValueDocument } from '@/components/KeyValueDocument'
import { useDetection, useDetections } from '@/hooks'
import { DEFAULT_PAGE_LIMIT } from '@/services'
import { C, tint } from '@/lib/tokens'
import {
  UNKNOWN_TEXT, formatConfidence, formatCount, formatTimestamp,
  formatRelative,
} from '@/lib/format'
import type { DetectionFinding, DetectionRule } from '@/types'
import type { ToastMsg } from '../App'

/** How many findings one page shows. */
const PAGE_SIZE = DEFAULT_PAGE_LIMIT

/** A readable label for a rule id, preferring the engine's own name. */
function ruleLabel(rules: readonly DetectionRule[], ruleId: string): string {
  const match = rules.find(rule => rule.rule_id === ruleId)
  return match?.rule_name ?? ruleId
}

// ─── Detector table ──────────────────────────────────────────────────────────

/**
 * The registered detectors.
 *
 * `enabled` is the engine's own switch. This table reports it and does not offer to
 * change it: M10 exposes no endpoint that toggles a detector, so a control here
 * would be a switch that does nothing (M15.20).
 */
function DetectorTable({ rules }: { rules: readonly DetectionRule[] }) {
  return (
    <div className="rounded-2xl border overflow-hidden"
      style={{ backgroundColor: C.card, borderColor: C.border }}>
      <div className="flex items-center gap-2 px-5 py-4 border-b" style={{ borderColor: C.border }}>
        <Radar size={14} style={{ color: C.accent }} />
        <h3 className="text-sm font-semibold text-white">Detectors</h3>
        <span className="text-xs ml-auto" style={{ color: C.faint }}>
          {rules.filter(rule => rule.enabled).length} of {rules.length} enabled
        </span>
      </div>

      {rules.length === 0 ? (
        <EmptyState
          title="No detectors registered"
          hint="The detection engine reported no rules. This is the engine's own answer, not a failed read."
          icon={<Radar size={24} />}
          minHeight={140}
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b" style={{ borderColor: C.border }}>
                <th className="text-left pl-5 py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Rule</th>
                <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Description</th>
                <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Window</th>
                <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Tracked keys</th>
                <th className="text-left py-2.5 pr-5 text-xs font-medium" style={{ color: C.dim }}>State</th>
              </tr>
            </thead>
            <tbody>
              {rules.map(rule => (
                <tr key={rule.rule_id} className="border-b" style={{ borderColor: '#1a2744' }}>
                  <td className="pl-5 py-3 pr-4">
                    <div className="text-xs font-semibold text-white">{rule.rule_name}</div>
                    <div className="mono text-[11px] mt-0.5" style={{ color: C.faint }}>{rule.rule_id}</div>
                  </td>
                  <td className="py-3 pr-4 text-xs max-w-90" style={{ color: C.muted }}>
                    {rule.description}
                  </td>
                  <td className="py-3 pr-4 text-xs mono" style={{ color: C.muted }}>
                    {rule.window_seconds === null ? UNKNOWN_TEXT : `${rule.window_seconds}s`}
                  </td>
                  <td className="py-3 pr-4 text-xs mono" style={{ color: C.muted }}>
                    {formatCount(rule.state_size)}
                  </td>
                  <td className="py-3 pr-5">
                    <span className="flex items-center gap-1.5 text-xs font-medium w-fit"
                      style={{ color: rule.enabled ? C.success : C.dim }}>
                      <span className="w-1.5 h-1.5 rounded-full"
                        style={{ backgroundColor: rule.enabled ? C.success : C.dim }} />
                      {rule.enabled ? 'Evaluating' : 'Disabled'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="px-5 py-3 border-t text-xs" style={{ borderColor: C.border, color: C.faint }}>
        Detector enablement is the engine's configuration; no M3–M14 endpoint changes it, so this
        table reports it rather than offering a control that would do nothing.
      </div>
    </div>
  )
}

// ─── Finding detail ──────────────────────────────────────────────────────────

/** One labelled value. */
function MetaField({ label, value, mono = false, icon }: {
  label: string
  value: string
  mono?: boolean
  icon?: React.ReactNode
}) {
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-1.5 text-xs mb-1" style={{ color: C.faint }}>
        {icon}
        {label}
      </div>
      <div className={`text-sm font-semibold text-white ${mono ? 'mono' : ''} wrap-break-word`}>{value}</div>
    </div>
  )
}

/**
 * One finding in full, read from `GET /detections/{id}`.
 *
 * The single-finding endpoint is used rather than trusting the row that was
 * clicked, because a finding can age out of M10's bounded history between the
 * listing and the click. When that has happened the panel says so — "no longer
 * retained" is the endpoint's honest answer for a finding that is simply gone, not
 * a request failure.
 */
function FindingDetailPanel({ findingId, fallback, onBack }: {
  findingId: string
  fallback: DetectionFinding | null
  onBack: () => void
}) {
  const resource = useDetection(findingId)
  const finding = resource.finding ?? fallback

  return (
    <div className="space-y-4 fade-in-up">
      <button onClick={onBack}
        className="flex items-center gap-2 text-sm font-medium transition-colors"
        style={{ color: C.muted }}
        onMouseEnter={e => (e.currentTarget.style.color = C.accent)}
        onMouseLeave={e => (e.currentTarget.style.color = C.muted)}>
        ← Back to Detections
      </button>

      {resource.isAgedOut && (
        <div className="rounded-2xl border flex flex-col items-center justify-center gap-3 text-center px-6 py-12"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <Bug size={28} style={{ color: C.border }} />
          <p className="text-sm font-medium text-white">No longer retained</p>
          <p className="text-xs max-w-md" style={{ color: C.muted }}>
            The engine answered 404 for finding <span className="mono">{findingId}</span>. M10
            keeps findings in a bounded history, so a finding that was listed a moment ago can
            age out — this is the finding being gone rather than the request having failed.
          </p>
        </div>
      )}

      {!resource.isAgedOut && (resource.isInitialLoading && fallback === null) && (
        <div className="rounded-2xl border" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="flex items-center justify-center gap-3 py-16">
            <RefreshCw size={18} className="animate-spin" style={{ color: C.accent }} />
            <span className="text-xs" style={{ color: C.faint }}>Loading finding…</span>
          </div>
        </div>
      )}

      {!resource.isAgedOut && finding !== null && (
        <>
          <div className="rounded-2xl border p-6" style={{ backgroundColor: C.card, borderColor: C.border }}>
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-2xl shrink-0"
                style={{ backgroundColor: tint(C.purple, 0.1) }}>
                <Crosshair size={24} style={{ color: C.purple }} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap mb-1.5">
                  <span className="text-xs font-semibold px-2.5 py-1 rounded-full"
                    style={{ backgroundColor: tint(C.purple, 0.12), color: C.purple }}>
                    Finding
                  </span>
                  <span className="mono text-xs" style={{ color: C.faint }}>
                    {finding.rule_id}
                  </span>
                </div>
                <h1 className="text-lg font-bold text-white mb-1">{finding.rule_name}</h1>
                <p className="text-sm leading-relaxed" style={{ color: C.muted }}>{finding.description}</p>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-4 mt-6 pt-6 border-t" style={{ borderColor: C.border }}>
              <MetaField label="Observed" value={formatTimestamp(finding.timestamp ?? null)}
                icon={<Clock size={11} />} />
              <MetaField label="Evidence strength" value={formatConfidence(finding.confidence)}
                icon={<Activity size={11} />} />
              <MetaField label="Protocol" value={finding.protocol ?? UNKNOWN_TEXT} mono
                icon={<Network size={11} />} />
              <MetaField label="Finding id" value={finding.finding_id} mono icon={<Hash size={11} />} />
            </div>

            <div className="grid grid-cols-4 gap-4 mt-6">
              <MetaField label="Source" value={finding.source_ip ?? UNKNOWN_TEXT} mono
                icon={<Server size={11} />} />
              <MetaField label="Destination" value={finding.destination_ip ?? UNKNOWN_TEXT} mono
                icon={<Server size={11} />} />
              <MetaField label="Source device" value={finding.source_device_id ?? UNKNOWN_TEXT} mono />
              <MetaField label="Destination device" value={finding.destination_device_id ?? UNKNOWN_TEXT} mono />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="rounded-2xl border overflow-hidden"
              style={{ backgroundColor: C.card, borderColor: C.border }}>
              <div className="flex items-center gap-2 px-5 py-4 border-b" style={{ borderColor: C.border }}>
                <FileText size={13} style={{ color: C.accent }} />
                <h3 className="text-sm font-semibold text-white">Evidence</h3>
              </div>
              <div className="px-5 py-4">
                <KeyValueDocument data={finding.evidence}
                  emptyText="The detector attached no evidence document to this finding." />
              </div>
            </div>

            <div className="rounded-2xl border overflow-hidden"
              style={{ backgroundColor: C.card, borderColor: C.border }}>
              <div className="flex items-center gap-2 px-5 py-4 border-b" style={{ borderColor: C.border }}>
                <Hash size={13} style={{ color: C.accent }} />
                <h3 className="text-sm font-semibold text-white">Metadata</h3>
              </div>
              <div className="px-5 py-4">
                <KeyValueDocument data={finding.metadata}
                  emptyText="The detector recorded no metadata for this finding." />
              </div>
            </div>
          </div>

          <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl border text-xs"
            style={{ backgroundColor: C.panel, borderColor: C.border, color: C.muted }}>
            <AlertTriangle size={13} style={{ color: C.faint, flexShrink: 0, marginTop: 1 }} />
            <span>
              This is an observation, not a verdict. It has no severity, no lifecycle and no risk
              score, and it is not an alert — whether it becomes one is M11's decision.
            </span>
          </div>
        </>
      )}
    </div>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

interface Props {
  showToast: (msg: string, type?: ToastMsg['type']) => void
}

export default function Detections({ showToast }: Props) {
  const [selected, setSelected] = useState<{ id: string; finding: DetectionFinding } | null>(null)
  const [ruleFilter, setRuleFilter] = useState<string>('ALL')
  const [sourceInput, setSourceInput] = useState('')
  const [destinationInput, setDestinationInput] = useState('')
  const [appliedSource, setAppliedSource] = useState('')
  const [appliedDestination, setAppliedDestination] = useState('')
  const [offset, setOffset] = useState(0)

  const query = useMemo(() => {
    const built: {
      rule_id?: string
      source_ip?: string
      destination_ip?: string
    } = {}
    if (ruleFilter !== 'ALL') built.rule_id = ruleFilter
    if (appliedSource !== '') built.source_ip = appliedSource
    if (appliedDestination !== '') built.destination_ip = appliedDestination
    return built
  }, [ruleFilter, appliedSource, appliedDestination])

  const window = useMemo(() => ({ limit: PAGE_SIZE, offset }), [offset])
  const resource = useDetections({ query, window })

  if (selected !== null) {
    return (
      <FindingDetailPanel
        findingId={selected.id}
        fallback={selected.finding}
        onBack={() => setSelected(null)}
      />
    )
  }

  const findings = resource.findings
  const rules = resource.rules
  const diagnostics = resource.diagnostics
  const isFiltered = ruleFilter !== 'ALL' || appliedSource !== '' || appliedDestination !== ''

  const applyAddresses = () => {
    setAppliedSource(sourceInput.trim())
    setAppliedDestination(destinationInput.trim())
    setOffset(0)
  }

  const resetFindings = () => {
    void resource.reset().then(failure => {
      if (failure === null) {
        showToast('Retained findings and counters discarded', 'success')
      } else {
        showToast(failure.userMessage, 'error')
      }
    })
  }

  return (
    <div className="space-y-4">
      {/* Executing counters, as the engine reports them */}
      <div className="grid grid-cols-4 gap-4">
        <div className="rounded-2xl border p-4" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="flex items-center gap-2">
            <Activity size={13} style={{ color: C.accent }} />
            <span className="text-xs font-medium" style={{ color: C.muted }}>Evaluations</span>
          </div>
          <div className="text-2xl font-bold text-white mt-1 leading-none">
            {formatCount(diagnostics?.evaluations ?? null)}
          </div>
          <div className="text-xs mt-1" style={{ color: C.faint }}>Packet evaluations by every detector</div>
        </div>
        <div className="rounded-2xl border p-4" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="flex items-center gap-2">
            <Crosshair size={13} style={{ color: C.purple }} />
            <span className="text-xs font-medium" style={{ color: C.muted }}>Findings raised</span>
          </div>
          <div className="text-2xl font-bold text-white mt-1 leading-none">
            {formatCount(diagnostics?.findings ?? null)}
          </div>
          <div className="text-xs mt-1" style={{ color: C.faint }}>Observations recorded this run</div>
        </div>
        <div className="rounded-2xl border p-4" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="flex items-center gap-2">
            <Radar size={13} style={{ color: C.info }} />
            <span className="text-xs font-medium" style={{ color: C.muted }}>Retained</span>
          </div>
          <div className="text-2xl font-bold text-white mt-1 leading-none">
            {formatCount(diagnostics?.retained_findings ?? null)}
          </div>
          <div className="text-xs mt-1" style={{ color: C.faint }}>
            Held in the bounded history
          </div>
        </div>
        <div className="rounded-2xl border p-4" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <div className="flex items-center gap-2">
            <AlertTriangle size={13} style={{ color: diagnostics?.errors ? C.danger : C.faint }} />
            <span className="text-xs font-medium" style={{ color: C.muted }}>Detector errors</span>
          </div>
          <div className="text-2xl font-bold mt-1 leading-none"
            style={{ color: diagnostics?.errors ? C.danger : '#F8FAFC' }}>
            {formatCount(diagnostics?.errors ?? null)}
          </div>
          <div className="text-xs mt-1" style={{ color: C.faint }}>Exceptions inside detector evaluation</div>
        </div>
      </div>

      {resource.rulesError !== null && (
        <RefreshFailureBanner error={resource.rulesError} onRetry={resource.reload} />
      )}

      <DetectorTable rules={rules} />

      {/* Findings */}
      <form className="flex items-center gap-2 flex-wrap"
        onSubmit={event => { event.preventDefault(); applyAddresses() }}>
        <select value={ruleFilter}
          onChange={e => { setRuleFilter(e.target.value); setOffset(0) }}
          className="px-3 py-2 rounded-xl text-xs border"
          style={{ backgroundColor: C.card, borderColor: C.border, color: C.muted, outline: 'none' }}>
          <option value="ALL">All detectors</option>
          {rules.map(rule => (
            <option key={rule.rule_id} value={rule.rule_id}>{rule.rule_name}</option>
          ))}
        </select>
        <div className="flex items-center gap-2 px-3 py-2 rounded-xl border min-w-45"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <Server size={12} style={{ color: C.faint }} />
          <input value={sourceInput} onChange={e => setSourceInput(e.target.value)}
            placeholder="Source address…"
            className="bg-transparent text-xs flex-1"
            style={{ color: C.text, outline: 'none' }} />
        </div>
        <div className="flex items-center gap-2 px-3 py-2 rounded-xl border min-w-45"
          style={{ backgroundColor: C.card, borderColor: C.border }}>
          <Network size={12} style={{ color: C.faint }} />
          <input value={destinationInput} onChange={e => setDestinationInput(e.target.value)}
            placeholder="Destination address…"
            className="bg-transparent text-xs flex-1"
            style={{ color: C.text, outline: 'none' }} />
        </div>
        <button type="submit"
          className="px-3 py-2 rounded-xl text-xs font-medium border"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
          Apply
        </button>
        {isFiltered && (
          <button type="button"
            onClick={() => {
              setRuleFilter('ALL'); setSourceInput(''); setDestinationInput('')
              setAppliedSource(''); setAppliedDestination(''); setOffset(0)
            }}
            className="px-3 py-2 rounded-xl text-xs font-medium border"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
            Clear
          </button>
        )}
        <button type="button" onClick={resource.reload} disabled={resource.isLoading}
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border"
          style={{ borderColor: C.border, color: C.muted, backgroundColor: C.card }}>
          <RefreshCw size={12} className={resource.isLoading ? 'animate-spin' : undefined} /> Refresh
        </button>
        <button type="button" onClick={resetFindings} disabled={resource.isResetting}
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border disabled:opacity-50"
          style={{ borderColor: tint(C.warning, 0.4), color: C.warning, backgroundColor: tint(C.warning, 0.06) }}
          title="M10.22 development helper: clears in-memory findings and counters. It enables no detector and disables none.">
          <RotateCcw size={12} className={resource.isResetting ? 'animate-spin' : undefined} />
          Reset retained state
        </button>
      </form>

      {resource.error !== null && findings.length > 0 && (
        <RefreshFailureBanner error={resource.error} onRetry={resource.reload} />
      )}

      <div className="rounded-2xl border overflow-hidden"
        style={{ backgroundColor: C.card, borderColor: C.border, boxShadow: '0 4px 24px rgba(0,0,0,0.2)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: C.border }}>
          <div>
            <h2 className="text-sm font-semibold text-white">Observations</h2>
            <p className="text-xs mt-0.5" style={{ color: C.faint }}>
              {findings.length} loaded
              {resource.total === null ? '' : ` of ${formatCount(resource.total)} matching`}
              {` · rows ${offset + 1}–${offset + findings.length}`}
            </p>
          </div>
          <span className="text-xs" style={{ color: C.faint }}>
            Newest first — a finding is not an alert
          </span>
        </div>

        <AsyncSection
          isInitialLoading={resource.isInitialLoading}
          error={resource.blockingError}
          isEmpty={false}
          loadingLabel="Loading findings…"
          errorTitle="Unable to load findings"
          onRetry={resource.reload}
          minHeight={240}
        >
          {findings.length === 0 ? (
            <EmptyState
              title={isFiltered ? 'No findings match the filter' : 'No findings retained'}
              hint={isFiltered
                ? 'Clear the detector or address filter.'
                : 'The detection engine records a finding when an observed pattern matches a rule. Nothing has matched yet.'}
              icon={isFiltered ? <Search size={28} /> : <Crosshair size={28} />}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b" style={{ borderColor: C.border }}>
                    <th className="text-left pl-5 py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Detector</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Observation</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Flow</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Protocol</th>
                    <th className="text-left py-2.5 pr-4 text-xs font-medium" style={{ color: C.dim }}>Evidence strength</th>
                    <th className="text-left py-2.5 pr-5 text-xs font-medium" style={{ color: C.dim }}>Observed</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map(finding => (
                    <tr key={finding.finding_id}
                      onClick={() => setSelected({ id: finding.finding_id, finding })}
                      className="border-b transition-all duration-150 cursor-pointer align-top"
                      style={{ borderColor: '#1a2744' }}
                      onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.025)')}
                      onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
                      <td className="pl-5 py-3 pr-4">
                        <div className="text-xs font-semibold text-white">
                          {ruleLabel(rules, finding.rule_id)}
                        </div>
                        <div className="mono text-[11px] mt-0.5" style={{ color: C.faint }}>
                          {finding.rule_id}
                        </div>
                      </td>
                      <td className="py-3 pr-4 max-w-90">
                        <div className="text-xs" style={{ color: C.muted }}>{finding.description}</div>
                        <div className="mono text-[11px] mt-0.5" style={{ color: C.dim }}>
                          {finding.finding_id}
                        </div>
                      </td>
                      <td className="py-3 pr-4 mono text-xs whitespace-nowrap" style={{ color: C.accent }}>
                        {finding.source_ip ?? UNKNOWN_TEXT}
                        <span style={{ color: C.dim }}> → </span>
                        {finding.destination_ip ?? UNKNOWN_TEXT}
                      </td>
                      <td className="py-3 pr-4 mono text-xs" style={{ color: C.faint }}>
                        {finding.protocol ?? UNKNOWN_TEXT}
                      </td>
                      <td className="py-3 pr-4">
                        <div className="flex items-center gap-2">
                          <div className="w-12 h-1.5 rounded-full overflow-hidden"
                            style={{ backgroundColor: C.panel }}>
                            <div className="h-full rounded-full"
                              style={{
                                width: `${Math.round(Math.max(0, Math.min(1, finding.confidence)) * 100)}%`,
                                backgroundColor: C.purple,
                              }} />
                          </div>
                          <span className="mono text-xs" style={{ color: C.muted }}>
                            {formatConfidence(finding.confidence)}
                          </span>
                        </div>
                        <div className="text-xs mt-0.5" style={{ color: C.faint }}>
                          evidence strength
                        </div>
                      </td>
                      <td className="py-3 pr-5 text-xs whitespace-nowrap" style={{ color: C.muted }}>
                        {formatRelative(finding.timestamp ?? null)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AsyncSection>

        <div className="flex items-center justify-between px-5 py-3 border-t" style={{ borderColor: C.border }}>
          <button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            disabled={offset === 0 || resource.isLoading}
            className="px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            Previous
          </button>
          <span className="text-xs" style={{ color: C.faint }}>
            {offset === 0 && !resource.hasMore ? 'All matching findings' : `Offset ${offset}`}
          </span>
          <button onClick={() => setOffset(offset + PAGE_SIZE)}
            disabled={!resource.hasMore || resource.isLoading}
            className="px-3 py-1.5 rounded-xl text-xs font-medium border disabled:opacity-40"
            style={{ borderColor: C.border, color: C.muted, backgroundColor: C.panel }}>
            Next
          </button>
        </div>
      </div>

      {findings.length > 0 && (
        <p className="text-xs px-1" style={{ color: C.faint }}>
          A finding is M10's raw observation. Alerts are what M11 derives from the findings it
          judges worth raising, and this list is not a queue of them.
        </p>
      )}
    </div>
  )
}
