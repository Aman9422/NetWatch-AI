# NetWatch AI — Working Notes

Scratch/handoff file. The milestone checklist lives at the top; notes below it are
the reasoning worth keeping across a context reset.

---

## Milestone checklist

M12 — Correlation + Risk Scoring

- [x] `app/correlation/` package — window, relationship, identity, confidence,
      rules, event, incident, status, registry, persistence, engine
- [x] `app/risk/` package — bands, inputs, contributions, engine
- [x] `AlertRepository.update_risk_scores` (M12.24) — the one column M12 writes
- [x] Pipeline integration (M12.25) — correlation last, failure-isolated
- [x] Correlation tests — 194 collected
- [x] `verify_m12.py` (M12.33) — all checks pass, clean output
- [x] `benchmark_m12.py` (M12.34) — written, type-clean, phases verified
- [x] `benchmark_m12.py` — full baseline recorded
- [x] Full test suite — **1 271 passed**
- [x] `docs/16_M12_Correlation_Design.md` — 27 sections, verified
- [x] Update `docs/TODO.md` + `docs/Current_Task.md` + `docs/think.md`

M13 — REST API

- [ ] M13.1 Review the existing API surface, define the consistency baseline
- [ ] Everything else — see `docs/Current_Task.md`

---

## M12 notes

### The baseline's real finding: correlation is quadratic in held incidents

`benchmark_m12.py` measured **85 distinct findings/sec, ~11.7 ms per finding**, at
2 000 distinct incidents. The cause is not normalization, deduplication or
scoring — it is the no-match path: with no match, `_find_match` *evaluates every
held incident* against the incoming event before it can conclude there is none.
That is O(held incidents) per event, so N distinct incidents cost O(N²)
relationship evaluations.

The grouped-alert number (595/sec) shows the other side of the same coin: when a
match exists and the matching incident is recent, it is found early in the
candidate scan. Same machinery, ~7× faster, purely because the scan stops early.

This is recorded in the design doc §25 and in `docs/TODO.md` rather than smoothed
over. M12.22's cap bounds how far it can grow; a future milestone needing higher
throughput would index the incident store by identity dimension instead of
scanning it.

### Benchmark bugs worth remembering (they were caught by running it, not by
reading it)

Three real defects surfaced only when the script was executed, and all three were
the kind that would have made the baseline *lie* rather than crash:

1. **Alerts all errored.** `_alert()` did not set `created_at`, and
   `correlate_alert(alert)` with no timestamp cannot date the event —
   `from_alert` refuses an untimed alert rather than guessing. The phase reported
   `incidents created: 0` and `joined: 0`, which looked like "no correlation
   happened". Fixed by setting `created_at=to_utc_datetime(...)`, which also
   exercises the real M11 datetime → epoch conversion.
2. **The query store collapsed to one incident.** Every seeded event shared a
   single `destination_device_id`, and `same_device` is an *anchoring*
   relationship — so every event related to every other and 1 000 events produced
   1 incident. Fixed by making the destination device unique per group.
3. **The distinct-findings phase was measuring the join path.** Every synthetic
   finding shared one `destination_ip`, which anchors on `same_destination` — so
   the "one distinct incident per finding" phase was silently measuring the
   opposite of what it claimed. Fixed by giving each group its own destination
   address.

The lesson worth carrying forward: a benchmark phase needs its *input shape*
checked as carefully as its arithmetic, because a shared identity dimension turns
a no-match measurement into a join measurement with no error to show for it.
`verify_m12.py` had already learned this (its unrelated-source and window
scenarios use separate address spaces for exactly this reason) — the benchmark
was written later and did not inherit the discipline until it was run.

### Two format traps this milestone hit

- An **unclosed code fence** in a long appended markdown file silently swallows
  everything after it. `docs/16_M12_Correlation_Design.md` was appended in parts
  and one closing fence was lost; a balanced-fence check caught it. Any
  multi-part markdown write should end with a fence-count check.
- `replace_in_file` batches: a single non-matching SEARCH block reverts the whole
  batch. Splitting a 7-block edit into three smaller batches was what made it
  land. Keep batches small and their SEARCH context distinctive.

### Verified chain (M12.33)

```text
Detection Finding → Alert → Correlation Engine → Correlated Incident
                                                → Correlation Reasons
                                                → Risk Score → alerts.risk_score
                          (alert confidence ≠ correlation confidence ≠ risk score)
```

Nine expected incidents across six controlled scenarios, plus a live pipeline
scenario. The retention sweep removed every incident and **no alert row** — which
is the M12.22 property, asserted rather than described.

### Design decisions worth not re-litigating

- **No `incidents` table.** M12.24 needed no schema change: `alerts.risk_score`
  already existed (M11 left it at `0` for exactly this) with the right
  `CHECK (0..100)`. Incidents live in bounded, expiring runtime state because
  nothing in M12 reads them from another process. The gap is documented in the
  design doc §2.6 rather than hidden.
- **Rule 5 (`same_destination_activity`) is not in M12.12's example list.** It
  exists because M12.6 makes `same_destination` an anchor and M12's completion
  criteria require same-destination correlation to work — without a rule
  consuming it, an anchor-capable relationship would exist that nothing could
  match on. Reasoning is in the design doc §8.
- **Two gates, not one.** A candidate must share an anchoring relationship *and*
  clear the confidence floor. The first enforces M12.4 ("not merely close in
  time"); the second stops a single weak overlap counting as a real one.
- **Confidence is a noisy-OR**, not a sum or an average — bounded by
  construction, monotonic, and capped at 0.999 so it never claims certainty.
- **The risk formula's seven terms sum to exactly 100**, so a fully-satisfied
  input reaches the top of the range without clamping. `clamp_score` is a guard
  against invalid input, not the mechanism that makes the score bounded.

---

## M13 starting point

`docs/Current_Task.md` now holds the M13 — REST API task. The immediate job is
M13.1: inventory the eight existing routers, confirm the envelope/pagination/error
conventions, and decide — explicitly, before writing routes — how unavailable
subsystems (AI, ML, baselines, report generation) are represented, and which
settings/detection-rule writes are live versus restart-only.

The principal new surface is the **incident API** exposing M12's correlated
incidents. Every filter it needs already exists as an `IncidentQuery` field, and
`CorrelatedIncident.as_dict()` / `.summary()` already serialize the three
confidences separately — M13 wires them up, it does not re-derive them.
