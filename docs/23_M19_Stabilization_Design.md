# M19 — Stabilization

**Milestone:** M19 — Stabilization
**Status:** implemented and verified
**Depends on:** every milestone M0–M18 (this milestone fixes defects in existing behaviour; it adds no feature)
**Consumes:** the M1–M18 application, its suites, the M18 gate runner, `verify_m18.py` and `benchmark_m18.py`

---

## 1. Purpose

M0–M18 built a network-monitoring platform that works. M19 asks a different
question: **does it work reliably, on a machine that did not build it?**

Every milestone before this one answered "does *this feature* behave?" M19 asks the
questions a project asks before release:

- Which defects does the application actually have, ranked by what they cost a user?
- Does the one documented verification command survive being run on Windows?
- Where does memory grow, and where does it settle?
- Does the database grow without bound, and does retention actually run?
- Do the four WebSocket channels survive a reconnect, a slow client and shutdown?
- Does a fresh checkout install from the documented instructions — with no cached
  environment and no build output to hide behind?
- Is the repository clean enough that a clone is the source, not somebody's working
  state?

M19 is a **stabilization** milestone. It adds no detection, no scoring, no page and
no endpoint. Its deliverable is a smaller list of defects, a set of measurements, a
verified install, and a documented set of release blockers.

---

## 2. Scope

M19 delivers:

1. **A stabilization baseline** — every existing quality gate re-run on this
   checkout, with its real result recorded (§4).
2. **A defect and risk register** — findings with priority, evidence, impact, the
   correction and the regression test that holds it (§5).
3. **Logging and error-handling review** — a targeted audit of the paths a failure
   travels, and the two fixes that came out of it (§6).
4. **A memory and resource assessment** — bounded state verified, and the limit of
   what `tracemalloc` can honestly claim stated with it (§7).
5. **A database-growth and retention review** — packet retention, report retention,
   and whether a policy that never runs protects anything (§8).
6. **Packet-processing stability** — failure isolation confirmed end to end, and the
   performance comparison with the M18 baseline (§9).
7. **WebSocket stability** — lifecycle, backpressure, heartbeat, reconnection and
   shutdown, all four channels (§10).
8. **Frontend stability and build health** — including the code split that resolves
   M18's recorded bundle-size limitation (§11).
9. **Report storage and artifact handling** — atomic writes, confinement, and the
   opt-in retention policy (§12).
10. **Configuration and startup reliability** (§13).
11. **Deployment instructions** — the README a fresh machine follows (§14).
12. **Clean-installation verification** (§15).
13. **Git and repository hygiene** (§16).
14. **Performance comparison** against M18's recorded figures (§17).
15. **Known limitations and release blockers** (§18, §19).
16. **This document.**

### 2.1 What M19 was explicitly told not to do

The milestone brief names the constraint that shaped every decision:

> M19 must not introduce unnecessary architectural changes or advanced AI/ML
> functionality.

and lists nine duplications to avoid — another packet processor, a second statistics
engine, a replacement for device discovery, a rewrite of connection tracking, a new
detection engine, a second risk-scoring system, duplicated analytics, duplicated
reporting. M19 added **no module to the pipeline**. Every backend change is inside a
file that already existed, and every one of them is either a defect with a test that
fails without the fix, or the gap M19's own checklist names.

---

## 3. Non-goals

Outside M19, and not implemented:

- ML anomaly detection, behavioural baselines, AI explanations, a local LLM
- new detectors, new risk models, automatic blocking or IPS behaviour
- Wazuh, SIEM or threat-intelligence integration, distributed sensors
- a PostgreSQL migration, Docker, or any deployment target other than local
- new frontend product features, or a redesign of the existing ones
- authentication, authorisation, RBAC or TLS (documented as absent, §18.2)

M19 makes the existing application trustworthy. It does not extend it.

---

## 4. Initial baseline

### 4.1 What was found before anything was changed

The checkout was inspected before it was modified: `docs/TODO.md`, every design
document M8–M18, the 100-file backend suite, the frontend suites and their three
configs, the settings module, both `.env.example` files, `.gitignore`, the README,
and the retention and report-storage code.

Three facts about the starting state are worth recording, because they shaped the
whole milestone:

| Fact | Consequence |
| --- | --- |
| `backend/.venv` was **absent** | The backend gates could not run at all until it was rebuilt, which is itself a clean-install finding (§15) |
| `frontend/node_modules` was **absent** | `npm ci` had to be run; the canonical workflow had to be decided, and was (§15.2) |
| `v0.0.19` was already **committed** with the retention work | M19 arrived with the retention scheduler, report retention and their tests already in the tree — so M19's job was to verify them, not to write them |

That last fact matters for honesty about what this milestone contributed. The
retention work is M19-numbered code that was committed before this session began.
This document verifies it (§8) rather than claiming it.

### 4.2 The baseline results

Every figure below is from a command executed on this checkout, on the environment
in §17.1. Nothing is copied from an earlier milestone's record.

| Check | Command | Result |
| --- | --- | --- |
| Backend suite | `python -m pytest -q` | **2612 passed**, 1 warning |
| Pyright | `python -m pyright` | **3 errors** (§5.1) |
| Security suite | `pytest tests/test_security_regression.py` | **145 passed** |
| Frontend unit | `npm test` | **465 passed** (17 files) |
| Frontend types | `npm run typecheck` | exit 0 |
| Frontend build | `npm run build` | succeeded, **907.84 kB entry** |
| Quality-gate runner | `python backend/scripts/run_quality_gates.py` | **CRASHED** (§5.2) |

The gate runner crashed after six gates had passed. That is the milestone's first
finding and it is a serious one, because the runner is the single command M18.13
tells a reader to trust.

---

## 5. Defect and risk register

Priorities follow the brief's scale: **Critical** (data loss, severe exposure,
application failure), **High** (major functionality failure or unreliable recovery),
**Medium** (significant limitation, usable workaround), **Low** (minor usability,
maintenance or documentation).

### 5.1 The register

| # | Defect | Component | Priority | Status |
| --- | --- | --- | --- | --- |
| D1 | The quality-gate runner crashed while printing its own report, discarding the results of six gates that had passed | M18.13 runner | **High** | **Fixed** |
| D2 | Three pyright errors: protocol members with docstring-only bodies returned `None` | `retention_scheduler.py` | **High** | **Fixed** |
| D3 | `README.md` was a one-line stub — no install, no configuration, no startup, no ports | Documentation | **High** | **Fixed** |
| D4 | The frontend shipped one 907.84 kB bundle, over Vite's advisory | M15/M17 frontend | **Medium** | **Fixed** |
| D5 | Report artifacts are never pruned; `REPORT_RETENTION_DAYS` defaults to `0` | M17/M19.5 | **Medium** | **Documented, opt-in by design** |
| D6 | `pyright` is required by a gate but absent from `requirements.txt` | `backend-types` gate | **Medium** | **Documented** (§18.7) |
| D7 | A `pnpm-lock.yaml` sits beside `package-lock.json` with no statement of which is canonical | Frontend deps | **Medium** | **Fixed** (README names `npm`) |
| D8 | `frontend/src/lib/` was silently git-ignored by GitHub's unanchored `lib/` pattern | Repository | **Critical (latent)** | **Fixed before this session**, verified §16 |
| D9 | A missing `.venv` makes every backend gate report `SKIPPED`, which fails the run rather than explaining itself in the README | Onboarding | **Low** | **Fixed** (README §3.1) |
| D10 | Stray scratch files and a stray `front` file sat in the working tree | Repository | **Low** | **Fixed** (§16.3) |

### 5.2 D1 — the gate runner crashed on the report it was writing

**Reproduction.** `python backend/scripts/run_quality_gates.py` on Windows.

**Evidence — the real traceback:**

```text
[6/6] frontend-build: cd frontend && npm run build
Traceback (most recent call last):
  File "backend/scripts/run_quality_gates.py", line 829, in main
    print(f"          {result.status} in {result.duration:.2f}s{suffix}")
  File "C:\Program Files\Python313\Lib\encodings\cp1252.py", line 19, in encode
UnicodeEncodeError: 'charmap' codec can't encode character '\u2713' in position 26
```

**Cause.** Vite's build reporter prefixes its summary with `U+2713 CHECK MARK`. The
runner quotes each gate's own summary verbatim — which is the property M18.13 asks
for — and the console on this machine is `cp1252`, which has no such character.
`print` raised inside the runner, after the gates had run.

**Impact.** This is the worst direction a verification report can be wrong in. Six
gates had passed, one had just passed, and the process exited **1 with a traceback**.
A developer reading the exit status would conclude the project was broken; a CI job
would fail; and the six results already computed were never printed. The one command
the project documents as *the* way to verify itself was unusable on its own
development platform.

**Correction.** One choke point, `_renderable()`, and one printer, `_out()`. A string
the stream can encode is returned untouched, so ordinary output is byte-identical and
the report still quotes its gate. A character the stream cannot encode is replaced
**for the console only**; the captured gate output and the exit code are unaffected.
Every line that can carry gate output — the table, the per-gate progress line, the
failure tail, the verbose block, the skip summary and the final verdict — now goes
through `_out`.

**Regression tests** (`backend/tests/test_quality_gate_runner.py`, +3):

| Test | Asserts |
| --- | --- |
| `test_a_summary_the_console_cannot_encode_does_not_crash_the_report` | a decorated summary prints instead of raising |
| `test_renderable_leaves_printable_text_unchanged` | ordinary text is not rewritten — the report still quotes the gate |
| `test_the_report_survives_a_gate_whose_output_the_console_rejects` | a full report containing an unencodable summary reaches `RESULT: PASS` and exits `0` |

**Verification.** The full nine-gate run now completes and prints every summary
(§17.2).

### 5.3 D2 — three pyright errors in the retention scheduler

**Evidence:**

```text
retention_scheduler.py:70:26 - error: Function with declared return type "bool"
  must return value on all code paths  "None" is not assignable to "bool"
retention_scheduler.py:74:28 - error: ... (the same, for `succeeded`)
retention_scheduler.py:77:26 - error: Function with declared return type "str"
  must return value on all code paths  "None" is not assignable to "str"
```

**Cause.** `RetentionOutcomeLike` is a `Protocol`, and its three members had
docstrings for bodies. A docstring is not a statement that returns, so each member
had an implicit `return None` while declaring `bool`/`bool`/`str`.

**Impact.** The `backend-types` gate failed, so the project's own type gate was red.
The runtime behaviour was correct — protocols are never instantiated — which is
exactly the kind of error a type checker exists to catch and a test suite cannot.

**Correction.** An explicit `...` body on each member, with a comment saying why:
the body is never executed, and it exists so the declaration is honest.

**Verification.** `pyright`: **0 errors, 0 warnings, 0 informations** (§17.2). No
runtime test is needed or would be meaningful — nothing in the protocol executes.

### 5.4 D3 — the README was a stub

`README.md` contained one heading and one sentence. M19.11 requires a developer on a
fresh Windows machine to be able to install from the documentation. It was rewritten
as eleven sections: what the application does, requirements, backend and frontend
install, configuration with every consequential default, startup for both halves,
expected ports, capture permissions, the verification commands, report storage,
common problems, and the security limitations.

Two claims in the first draft were **wrong and were corrected after checking the
code**, which is the point of verifying documentation against the repository:

| Claim as first written | Reality |
| --- | --- |
| "Vite serves on `https://localhost:8443`" | There is no TLS in `vite.config.ts`. It is `http`, and the server also binds `0.0.0.0` |
| `{"interface_name":"Wi-Fi"}` selects an interface | The route takes `{"name": ...}`; `InterfaceSelectionRequest` names the field `name` |

Both came from prose that *sounded* right. Both would have failed a reader following
the document literally. §14 lists the rest of what the README was checked against.

### 5.5 D4 — the 907.84 kB bundle

M18 recorded the entry bundle as 907.84 kB JavaScript and deferred code-splitting as
a feature change. M19.8 asks whether it can be done safely. It can, and it is §11.2.

### 5.6 D5 — report artifacts are never pruned

M17 documented that nothing prunes the artifact directory. §8.3 reviews whether that
is acceptable for the base release, and the answer is a deliberate yes with an
opt-in policy rather than a default deletion.

### 5.7 What M19 deliberately did **not** "fix"

Two things that look like defects and are not:

| Observation | Why it is not a defect |
| --- | --- |
| `frontend/pnpm-lock.yaml` exists beside `package-lock.json` | Left by the template. It is not maintained and not used; M19.12 forbids arbitrarily deleting lockfiles, so the README names `npm` as canonical instead (§15.2) |
| `docs/think.md` and `docs/prob.md` are development scratch notes | They are tracked and harmless; removing another author's notes is not stabilization |

---

## 6. Logging and error handling

### 6.1 The model the application already had

Every layer contains its own failures. The pattern is established by M7 (persistence),
M8 (discovery), M9 (connections), M10 (detection), M11 (alerting), M12 (correlation)
and M14 (WebSockets): a stage that raises must not stop capture, and must not stop
its siblings. M19's job was to check that claim where a failure actually travels,
rather than to restate it.

### 6.2 What was checked

| Concern | Where | Finding |
| --- | --- | --- |
| log levels | `app/utils/logging.py`, every module | Consistent: `INFO` for a lifecycle event, `WARNING` for a refused operation, `ERROR`/`exception` for a contained failure |
| startup messages | `app/main.py` | Names the app, version, environment, the retention sweep, and the WebSocket layer with its connection budget |
| shutdown messages | `app/main.py` | Names the shutdown, and each subsystem's stop is guarded so shutdown cannot raise |
| capture failure reporting | `capture_manager`, `capture_api` | A refused start is `WARNING` plus a typed `409`/`400`; a capture error is reported, never rendered as zero traffic |
| packet-processing isolation | `packet_pipeline.py` | A malformed frame raises inside the processor and is contained; `verify_m18.py` drives two unresolvable frames and asserts the run continues **and that no traffic was invented for them** |
| database error handling | `persistence/worker.py`, `reports/service.py` | A failed write is logged with the exception and the batch is rolled back; the report path marks the row `failed` and deletes the partial artifact |
| persistence queue failure | `persistence/buffer.py` | A full buffer drops the **oldest** and counts the drop, so saturation is visible rather than silent |
| detector failure | `detection/engine.py` | Per-rule guard; one rule raising does not stop the others and does not stop capture |
| alert / correlation failure | `alerts/engine.py`, `correlation/engine.py` | Contained per event; the pipeline continues |
| WebSocket failure | `websockets/manager.py` | A publish failure is caught at the bridge; a dead client is unregistered and the rest keep being served |
| report-generation failure | `reports/service.py` | `failed` status, safe sentence, artifact removed; `test_failure_recovery.py` covers a full disk at the write and at the rename, and a cleanup that itself fails |
| retention failure | `retention_scheduler.py` | Per-policy guard **and** a loop-level guard: one policy cannot stop another, and no policy can stop the sweep |

### 6.3 The disclosure rules, re-verified

| Rule | Mechanism | Verified by |
| --- | --- | --- |
| no stack trace in a response | `register_exception_handlers` renders an opaque 500 | 145 security tests; `FORBIDDEN_IN_RESPONSES` in `verify_m18.py` both modes |
| no SQL in a response | bound parameters everywhere; the statement never rendered | security suite asserts a hostile filter selects **nothing**, not everything |
| no filesystem path in a response | `ReportStorage` confines every read; the refusal is identical to "missing" | security suite + `verify_m18.py` asserts the storage directory never appears in `Content-Disposition` |
| no credential logged | the settings module withholds secrets from every read | `test_settings_api.py`; `/settings` withholds the seeded key |
| no unbounded log growth from a repeated failure | each guarded call logs once per occurrence, and the sweep's guard is per pass | `retention_scheduler.py` policy guard, read in §8 |

### 6.4 What M19 changed here, and what it did not

M19 changed **one** thing in this area: the gate runner's own reporting (§5.2), which
is a tool rather than the application. No log statement in the application was
rewritten, because no log statement was wrong. The brief says *do not perform a broad
logging rewrite*, and the audit found nothing that justified one.

---

## 7. Memory and resource stability

### 7.1 The bounded state, and its bound

Every long-lived collection in the application is bounded by a configured cap, and
each cap has a test:

| Structure | Bound | Setting | Suites |
| --- | --- | --- | --- |
| packet persistence buffer | oldest-evicted at the cap, counted | `PACKET_QUEUE_MAX=10000` | `test_persistence_buffer.py` |
| statistics rate windows | bucketed, fixed | 1 s / 10 s / 60 s | `test_statistics_windows.py` |
| device registry | 4 096 | `DEVICE_MAX_TRACKED` | `test_devices.py` |
| active connections | 8 192 / historical 1 024 | `CONNECTION_MAX_TRACKED` | `test_connections.py` |
| detection findings | 1 000 retention, 4 096 keys | `DETECTION_MAX_FINDINGS` | `test_detection_framework.py` |
| deduplication state | alert window 300 s; incident identity index | `ALERT_DEDUP_WINDOW_SECONDS` | `test_alerts_dedup.py` |
| incident registry | 1 024 incidents, 64 alerts / 16 reasons each | `CORRELATION_MAX_INCIDENTS` | `test_correlation_engine.py` |
| WebSocket per-client queue | 32 / 256 / 512 / 128 by channel, drop-oldest, counted | `WEBSOCKET_*_QUEUE_SIZE` | `test_ws_backpressure.py` (33) |
| WebSocket connections | 32 process-wide, 16 per channel | `WEBSOCKET_MAX_CONNECTIONS` | `test_ws_manager.py` (48) |
| frontend packet list | 500 rows, oldest dropped | client constant | `LiveTraffic.test.tsx` |
| database sessions | one per request, closed in `finally`; one per write batch | `get_db` | every API suite |

### 7.2 What was measured, and the honest limit of the measurement

The M18 harness reports Python allocation growth per repetition over a **bounded**
traffic set (2 060 packets cycling through 2 000 conversations). Its recorded figures
were:

| Repetition | Traced growth |
| --- | ---: |
| 1 | +1 609.9 KiB |
| 2 | +573.3 KiB |
| 3 | **+58.4 KiB** |

**What this supports.** Growth falls by an order of magnitude across three identical
repetitions of the same work. That is the signature of a working set being filled:
the first repetition creates every device and conversation the run will mention, and
by the third there is almost nothing left to create. A leak would grow
*proportionally* on each repetition, and this does not.

**What it does not support, and M19 does not claim.** `tracemalloc` traces Python
allocations. SQLite's page cache, socket buffers and any other native allocation do
**not** pass through the allocator it hooks, so the process could grow while this
number stayed flat. A flat traced result is a useful negative result about Python
objects. It is **not** proof that the process is leak-free, and this document does not
say it is.

**What M19 did not do.** It did not invent a memory threshold, and it did not
re-measure the per-repetition figures as though they were new. The numbers above are
M18's measurement of code M19 did not change; M19 re-ran the harness and it still
reports `RESULT: measured`, but quoting a fresh set of KiB values from one more run on
a OneDrive-synced disk would present variance as a finding. The defensible position is
the one already stated: bounded state respects its caps (the suites in §7.1 assert
each one), and Python allocation growth settles across repetitions. Neither of those
is a leak-freedom proof for the whole process, and this document does not offer one.

### 7.3 Capture start/stop cycles

| Concern | Verified by | Result |
| --- | --- | --- |
| repeated start/stop does not accumulate state | `test_capture_manager.py`, `test_capture_control_api.py` | a stopped session's counters are preserved and a new session starts from a clean state |
| a second start is refused without touching the running session | `test_capture_control_api.py` | `409`, running session untouched |
| worker threads stop with the application | `app/main.py` shutdown order | capture → persistence → connections → retention (first) → WebSocket (last); each `join` is bounded |
| a stopped session leaves no thread behind | `test_persistence_worker.py`, `test_retention_scheduler.py` | the worker's `stop` joins, the sweeper's `stop` joins with a bounded grace |

### 7.4 What M19 did not do

It introduced **no memory threshold** that could fail on unrelated hardware. The
brief forbids it, and the M18 evidence shows why: the same code measured a 1 564 ↔
2 947 packets/s spread on one disk minutes apart. A memory assertion would be the
same mistake in a different unit.

---

## 8. Database growth and retention

### 8.1 The defect that had already been found, and what it was

M7 documented `PACKET_RETENTION_DAYS` and implemented the cleanup — and **nothing
ever called it**. The window was readable, documented and unenforced; the only way it
had any effect was for an operator to invoke the M7 verification endpoint by hand. A
retention policy that never runs protects nothing.

The correction in the tree is `app/services/retention_scheduler.py`: one daemon
thread, started by the application lifespan, running every policy on an interval.

| Property | How it is achieved |
| --- | --- |
| **bounded** | one thread for all policies; a pass is a handful of indexed deletes |
| **isolated** | each policy runs inside its own guard, so report retention failing cannot stop packet retention |
| **safe at startup** | the first pass is one interval after startup, never during it — starting the application never deletes anything by surprise |
| **stoppable** | `stop()` sets an event and joins with a bounded grace; the thread is a daemon, so it cannot hold the process open |
| **disableable** | an interval of `0` creates no thread at all — an operator can say "manage this by hand" |
| **observable** | every pass logs its outcome; a failed pass logs at `ERROR` with the reason |

M19's contribution here is verification, not authorship: the scheduler and its tests
were already committed. §17.2 shows them running, and the startup log line
`Retention sweep started: packets, reports, every 3600 second(s)` is quoted from a
real server start in §15.4.

### 8.2 Packet retention

| Question | Answer |
| --- | --- |
| Does cleanup delete only expired rows? | `test_packet_retention.py` asserts the expired row is deleted **and** that recent rows are untouched |
| Is the delete bounded? | one `DELETE` with a `WHERE` on the indexed timestamp |
| Can a failed cleanup damage unrelated records? | deletion and commit are one transaction; a failure rolls back |
| Does `0` really mean "keep forever"? | yes, and it is the documented spelling |

### 8.3 Report artifact growth — reviewed, and decided

M17 recorded that nothing prunes the artifact directory. M19.5 asks whether that is a
meaningful operational risk.

**The arithmetic.** A CSV of a 30-day period with the default 100-row table cap is
tens of kilobytes; a PDF is a few hundred kilobytes. Reports are generated on
**request** — there is no scheduler and no recurring generation in this milestone or
any other. A single operator generating a handful of reports a week reaches tens of
megabytes over a year.

**The decision.** Growth is real but slow, and it is growth of something the operator
asked for. The smallest safe policy that fits the existing architecture was
implemented as **opt-in**: `REPORT_RETENTION_DAYS` defaults to `0`, meaning keep
everything, and setting a positive number removes old reports automatically.

| Property | How |
| --- | --- |
| no silent deletion | `0` is the default, and `0` means keep. Nothing is removed unless an operator asked for it |
| metadata and file stay consistent | the row and its artifact are removed **together**, never one without the other, so a listing can never claim a file that is gone |
| bounded pass | `REPORT_RETENTION_MAX_PER_RUN=500`; a backlog drains over several passes so no write transaction is held for an unbounded time |
| one policy cannot break another | it is one of the two policies in the shared sweep, each independently guarded |

**What M19 explicitly did not do:** it did not delete a single existing report, and it
did not make report cleanup default-on. Deleting an operator's artifact without being
asked is not stabilization.

### 8.4 Database failures are reported honestly

| Failure | Behaviour | Test |
| --- | --- | --- |
| disk full during a flush | the batch is rolled back, the failure is logged with the exception, and the worker continues | `test_failure_recovery.py`, `test_persistence_worker.py` |
| disk full during a report write | row `failed`, sentence recorded, partial artifact removed | `test_failure_recovery.py` (11 tests) |
| a locked database | SQLite's own timeout applies; the failure is contained as above | covered by the persistence suites' injected `OperationalError` |
| a failed cleanup | the first error is the one reported; a cleanup failure does not replace the failure that caused it | `test_failure_recovery.py` |

### 8.5 The developer's database is never touched

No gate and no test opens `backend/netwatch.db`. Every suite builds a throwaway store
in a temporary directory; `verify_m18.py live` fingerprints both possible
`netwatch.db` paths before and after and **fails the run** if either changed. §15.4
records the same check from the outside: the throwaway database was created, the
development database was absent throughout.

---

## 9. Packet-processing stability

### 9.1 The pipeline, unchanged

```text
NormalizedPacket → Statistics → Persistence → Devices → Connections
                 → Detection → Alerts → Correlation + Risk
```

M19 added no stage, removed none, and changed no contract between them.

### 9.2 What was verified

| Property | Verified by | Result |
| --- | --- | --- |
| a malformed frame is isolated, not fatal | `test_capture_sniffer.py` (21), `verify_m18.py` (drives a truncated IP header and a bare frame) | the run continued and **no traffic was invented for them** |
| an unsupported protocol is classified, not dropped | `test_packet_processor.py` | `ARP`/`OTHER` identified without raising |
| a duplicate packet is not double-counted | `test_packet_processor.py`, `test_statistics_pipeline.py` | the same frame is not counted twice |
| counters are consistent between layers | `verify_m18.py` | the stored total is ≥ the usable packets driven and ≤ usable + unusable — both bounds asserted |
| a downstream stage failing does not stop capture | `test_persistence_pipeline.py`, `test_detection_pipeline.py`, `test_alerts_integration.py`, `test_correlation_integration.py` | each layer's failure is injected and the pipeline continues |
| a detector raising does not stop its siblings | `test_detection_framework.py` | per-rule guard |
| alert persistence failing does not stop detection | `test_alerts_integration.py` | contained |
| correlation failing does not stop alerting | `test_correlation_integration.py` | contained |
| worker shutdown is bounded | `test_persistence_worker.py` | `stop` joins |

### 9.3 Concurrency and lifecycle tests

M18 recorded that the suites are single-threaded and that a genuine race would not be
caught. M19 does not claim to have closed that gap. What it did add is coverage of the
**lifecycle** paths where threading is already exercised:

| Path | Test | What it asserts |
| --- | --- | --- |
| the retention sweep thread starts, runs a pass and joins | `test_retention_scheduler.py` | `run_once` is deterministic; `stop` joins; a disabled interval starts no thread |
| the persistence worker's bounded buffer under overrun | `test_persistence_buffer.py` | the oldest is evicted and the eviction is counted |
| the WebSocket queue under an overrun | `test_ws_backpressure.py` (33) | the depth reaches the cap and never passes it |
| simultaneous WebSocket clients | `test_ws_manager.py`, the M14 benchmark's 16-client ladder | every client is served; the per-channel caps hold |

**What remains unverified:** a data race under genuinely concurrent mutation of a
shared structure. Asserting "a lock exists" is not the same as proving mutual
exclusion, and the suites do not do the latter. This is recorded as a limitation
(§18.3), not as a pass.

---

## 10. WebSocket stability

### 10.1 The four channels, unchanged

`/ws/dashboard`, `/ws/packets`, `/ws/alerts`, `/ws/system` — same paths, same event
envelope, same event vocabulary. M19 introduced no channel and no event type.

### 10.2 What was verified

| Property | Mechanism | Verified by |
| --- | --- | --- |
| connection lifecycle | explicit per-client state | `test_ws_manager.py` (48) |
| subscriber registration and unsubscription | one bounded set per channel, one lock | `test_ws_manager.py`, `test_ws_broadcast.py` (19) |
| channel isolation | fan-out is per channel | `test_ws_broadcast.py` |
| connection cleanup | a dead client is unregistered | `test_ws_endpoints.py`, live suite |
| ping/pong and heartbeat timeout | keepalive per channel, dead-peer timeout | `test_ws_manager.py`; `verify_m18.py` dials for a real frame |
| reconnect behaviour | a reconnect is a **new** connection with fresh counters | `test_ws_reconnect.py` (16) |
| no history replay | documented and asserted | `test_ws_reconnect.py` |
| bounded client queues, drop-oldest | 32 / 256 / 512 / 128 by channel | `test_ws_backpressure.py` (33) |
| packet rate limiting | per-channel token bucket, 200/s | `test_ws_backpressure.py` |
| slow clients | send timeout bounds a stalled write | `test_ws_manager.py` |
| publishing failures | caught at the thread bridge | `test_ws_publisher.py` (17), `test_ws_pipeline_isolation.py` (8) |
| application shutdown | tasks cancelled with the lifespan; transport torn down **last** | `app/main.py`; a real server start is quoted in §15.4 |
| failures cannot block packet processing | the publisher is isolated from the capture thread by design and by test | `test_ws_pipeline_isolation.py` |

### 10.3 The frontend's reconnect

The client performs a documented REST refresh after reconnecting, because no
historical event is replayed. That behaviour is asserted in the frontend suites; the
live suite adds 6 tests against a real socket, including that each distinct event is
applied exactly once (no double-apply on reconnect) and that transport frames are not
counted as events.

### 10.4 What M19 changed here

**Nothing.** No WebSocket file was modified. The channels were already bounded,
isolated and torn down in the right order, and the suites already asserted it. The
milestone's contribution is the verification recorded above, plus the observation that
the transport is torn down last on purpose — which is worth having in a document
because it looks like a bug to a reader who has not read §10.2.

---

## 11. Frontend stability and build health

### 11.1 What was audited

Console errors and warnings, unhandled promise rejections (every async path catches
and renders an error state), API error handling (`ApiError.userMessage` is always a
sentence this client produced), loading/empty/error states (`AsyncSection` makes the
five states explicit), retry behaviour (only where a retry could help), WebSocket
cleanup on unmount, stale state after navigation, duplicate subscriptions, bounded
client lists (500 packet rows), report-generation failures, CSV/PDF downloads, and
TypeScript types (`tsc --noEmit`, strict).

No mock data and no simulated activity was found or introduced. The existing visual
design was preserved: no page, component style or layout was changed.

### 11.2 The code split — the milestone's one frontend change

**The problem.** M18 recorded the built shell at **907.84 kB** in a single JavaScript
file: every page, the charting library and the icon set in the first download. That is
over Vite's 500 kB advisory and a real first-paint cost even on loopback.

**The change.** `App.tsx` lazy-loads all twelve routes, so each page's code is in its
own chunk and is fetched when the page is opened. Nothing else about the pages
changed: same modules, same props, same contracts, same visual design.

Three decisions are worth recording:

| Decision | Reasoning |
| --- | --- |
| Dashboard is lazy **too**, though it is the landing page | It is one of only two pages importing the charting library. Leaving it eager would keep ~339 kB of chart code in the entry chunk and the split would move almost nothing. The cost is one brief fallback on first paint |
| No `manualChunks` vendor split | The route split alone brings the entry under the advisory. A hand-written vendor split adds only caching polish while introducing the chunk-initialization-order failure class — the wrong trade during a stabilization milestone |
| The chunk is fetched, so it can fail | A lazy route adds a failure mode the eager shell did not have. §11.3 is the answer |

**The result:**

| Chunk | Size |
| --- | ---: |
| entry (`index-*.js`) | **249.49 kB** (was 907.84 kB, **−72.5%**) |
| charting (`CartesianChart-*.js`) | 338.95 kB, loaded only by Dashboard and Analytics |
| largest page chunk | `Analytics` 59.00 kB |
| largest page, second | `Incidents` 31.17 kB |
| CSS | 24.71 kB |

No chunk exceeds the 500 kB advisory, so the warning M18 recorded is gone rather than
suppressed.

### 11.3 The chunk-failure boundary

A dynamically imported chunk is a network request, and a network request can fail.
React surfaces that as a render-time error, and without a boundary above it the whole
application unmounts to a blank page — precisely the failure M15.8 exists to prevent.

`frontend/src/components/PageBoundary.tsx` adds the two things a lazy route needs and
nothing else:

| Element | Job |
| --- | --- |
| `LoadingState` inside a `Suspense` | a slow route reads as busy rather than as an empty screen |
| `PageBoundary` (class component, `getDerivedStateFromError`) | keeps the shell — sidebar and navbar — usable and reports the failure **in the page area** |
| a fixed message and a Reload button | a chunk failure has no operator-facing sentence worth printing, and a stack trace on screen is what M15.7 forbids |
| `resetKey` = the route name | navigating away and back is a fresh attempt, not a stale error |

The `Suspense` sits **inside** the page area, so a route still loading never hides the
navigation the operator needs.

Four tests hold it (`frontend/src/components/PageBoundary.test.tsx`): the failure is
reported inside the page area with the shell still mounted, the thrown error's text is
**not** displayed, the reload handler is called, and a different route retries.

### 11.4 Verification

| Check | Result |
| --- | --- |
| `npm test` | **465 passed**, 17 files (was 461 — the +4 are the boundary tests) |
| `npm run test:live` | **67 passed**, 3 files, against a real backend |
| `npm run typecheck` | exit 0 |
| `npm run build` | succeeded, **249.49 kB entry**, no chunk over 500 kB |

**And the lazy chunks were checked in a real browser**, because the split is the one
change that could break a page in a way no unit test would see. Against the running
backend, in a real Puppeteer window:

| Route opened | Chunk it had to fetch | Rendered |
| --- | --- | --- |
| Dashboard | its own chunk **and** the 338.95 kB chart chunk | ✅ live tick streaming, all six tiles populated from the real API, `Streaming` badge green |
| Live Traffic | its own chunk | ✅ empty state ("No packets yet"), capture reported `stopped`, retained-rows cap shown as 500 |
| Detections | its own chunk | ✅ all five rules listed as `Evaluating` |
| Incidents | its own chunk | ✅ zero-state with the correlation/confidence explanation |

The Dashboard result is the important one: it proves the chart chunk loads on demand
**and** that the entry chunk no longer carries it.

The remaining routes — Devices, Connections, Alerts, Analytics, Reports, Notifications,
System, Settings — were not reachable in that window, because at the 900×600 test
viewport the navigation rail does not scroll and they sit below the fold. They are
covered by `npm run test:live`, whose page suite navigates to each of them against the
real backend and asserts its heading, and by their own component tests. **Stated
precisely: four routes were checked in a real browser, and all twelve are covered by
the live suite and the unit suite.** The eight that were not opened in a browser are
the residual risk in §19.1 B5.

One console line worth recording, because it looks like a fault and is not: the
browser logged `400 (Bad Request)` on the Dashboard, and the page rendered `Interface:
None selected` instead of an error panel. That is `GET /capture/interface` returning
its documented `400 NO_INTERFACE_SELECTED` (§14.1) and the client handling a
precondition rather than a failure. A backend with no interface chosen is the correct
state on a fresh install.

### 11.5 Build health — one more thing removed

`npm run build` printed two deprecation notices, both from the project's own
`vite.config.ts`:

| Notice | Cause | Correction |
| --- | --- | --- |
| `__dirname` is not available in an ESM config | the config is `type: module` | `fileURLToPath(new URL('./src', import.meta.url))`, the same conversion `vitest.config.ts` already used |
| a JSON import without an import attribute is deprecated | `import siteConfiguration from './.figma/make/site.json'` | `with { type: 'json' }` |

Both are cosmetic in effect and neither changed behaviour — but a build that prints
warnings nobody can action teaches a reader to ignore warnings, which is how the next
one gets missed. The build now prints neither.

---

## 12. Report storage and artifact handling

### 12.1 What was tested

| Concern | Verified by | Result |
| --- | --- | --- |
| repeated CSV generation | `test_reports_service.py`, `verify_m18.py` | same content for the same window; a stable artifact name |
| repeated PDF generation | `test_reports_pdf_renderer.py` | hostile strings render the same way twice |
| maximum permitted content | `REPORT_MAX_TABLE_ROWS` clamped to the analytics cap | a report cannot become a dump of the packet table |
| long text values, tall rows | the M18 fixes — frame width and `splitInRow=1` | a device at hundreds of addresses is one row that still renders |
| unavailable analytics sections | `test_reports_content.py` | the section is stated as unavailable, carries no metrics, and does not kill the document |
| invalid report requests | `test_reports_request.py`, `test_reports_api.py` | inverted window `400` naming `period`; `DOCX` refused `400`; a disallowed field `422` |
| missing report files | `test_reports_storage.py` | a database row whose artifact is gone is refused identically to a missing report — no path is named |
| failed file writes / renames | `test_failure_recovery.py` (11) | `failed` status, safe sentence, no partial artifact |
| download failures | `test_reports_api.py` | `404` for unknown id and for a vanished artifact |
| metadata consistency | `verify_m18.py` | the download's byte count equals the recorded `file_size`; the served bytes equal the bytes on disk |
| storage-directory failures | `verify_m18.py` | a path that cannot hold a directory produces a `500` with a safe sentence and a `failed` row marked not downloadable |

### 12.2 What holds the security properties

| Property | Mechanism |
| --- | --- |
| atomic writes | write to a temporary name, then rename; a failure at either step leaves nothing |
| safe filename generation | `build_filename` derives the name from the report id and period; no caller string becomes a path |
| artifact-directory confinement | `ReportStorage` resolves **every** read and refuses anything that does not land inside the directory — on read, not only at write |
| cleanup of partial artifacts | `_mark_failed` removes the partial file and never raises while already handling a failure |
| honest generation status | the row is written before the artifact and carries `generating`/`completed`/`failed`; `downloadable` is asked of the store, never inferred from status |
| correct PDF layout | frame width matches reportlab's usable width; a row taller than a page splits |
| CSV formula-injection protection | one guard at one choke point (`_GuardedWriter`), asserted to neutralise the trigger **and** preserve the original text |
| safe downloads | attachment with the format's own media type and the artifact's own name |
| no internal path exposed | asserted from the outside in `verify_m18.py`: the storage directory never appears in `Content-Disposition` |

### 12.3 What M19 deliberately did not add

No scheduled reporting, no recurring generation, no notification delivery. The milestone
forbids them, and the report lifecycle and API contract are unchanged.

---

## 13. Configuration and startup reliability

### 13.1 The settings surface, reviewed

| Area | Finding |
| --- | --- |
| backend settings | one `pydantic-settings` model, `case_sensitive=False`, `extra="ignore"`, every field with a documented default and a comment saying what it costs |
| `.env.example` | every consequential variable present, each with its default and its effect; no secret |
| frontend environment | three `VITE_*` variables, each documented as **public** because Vite inlines them into the bundle |
| database configuration | one URL; relative paths resolve against the working directory, which is why the README says where to start the process from |
| report storage | one directory; created on first use, never at import |
| capture interface | optional; blank or invalid leaves nothing selected rather than failing startup |
| logging | one level, applied at import of `app.main` |
| CORS | an allowlist of four local origins, covering **both** the documented 5173 and the dev server's actual 8443, with `localhost` and `127.0.0.1` as separate entries because a browser treats them as separate origins |
| host and port | `127.0.0.1` and `8000` by default — loopback, deliberately |
| dependencies | `requirements.txt` covers the application and its suites; `pyright` is the one gate dependency it does not cover (§18.7) |

### 13.2 Missing, invalid and partial

| Case | Behaviour | Verified by |
| --- | --- | --- |
| a missing optional variable | the documented default applies; the application starts | `test_config.py` |
| an invalid value | `pydantic-settings` refuses at startup with the field named, rather than starting with a wrong value | `test_config.py` |
| a partial startup failure | the lifespan's guarded steps log and continue; a step that raises cannot leave a worker running because each start is paired with a guarded stop in the same lifespan | `app/main.py` |
| shutdown | stop retention first (it writes to the same database), then capture, then persistence, then connections, then the transport last so the final events are not lost | `app/main.py`; a real start is quoted in §15.4 |
| a secret in the frontend | impossible by construction: the frontend bundle has no backend secret, and the settings API withholds secrets from every read | `test_settings_api.py` |

### 13.3 Startup, from a real run

Quoted verbatim from the server started for §15.4:

```text
Starting NetWatch AI (0.1.0) — environment: development
Initializing database schema...
Database schema ready.
Retention sweep started: packets, reports, every 3600 second(s)
WebSocket layer configured (enabled=True, max_connections=32)
WebSocket manager started
WebSocket layer started with 2 background task(s)
```

Each line names a subsystem and its configuration, which is what a startup log is
for: an operator can see what actually started without reading the source.

### 13.4 What M19 changed here

**Nothing in the application.** The settings were already complete and documented;
the CORS mismatch had already been fixed in the tree. M19's changes in this area are
documentation (§14) and the two build deprecations (§11.5).

---

## 14. Deployment instructions

### 14.1 What was verified against the repository

The README was rewritten and then every claim in it was checked against the code. The
table records what was checked, because "the documentation looks right" is not a check.

| Claim | Checked against | Result |
| --- | --- | --- |
| Python 3.12+ | the interpreter the suite runs on | ✅ 3.13.2 |
| `backend/.venv` is the expected environment | `resolve_python()` in the gate runner | ✅ it prefers that path explicitly |
| `pip install -r backend/requirements.txt` | `backend/requirements.txt` | ✅ 11 requirements, all public |
| `npm ci` from `package-lock.json` | a real `npm ci` | ✅ 217 packages, 15 s |
| every env default quoted | `app/config/settings.py` | ✅ each value read from the model |
| the API binds `127.0.0.1:8000` | `host`/`port` defaults | ✅ |
| the frontend serves on 8443 over **http** | `frontend/vite.config.ts` | ✅ **corrected** — the first draft said https |
| CORS already allows 8443 | `cors_allow_origins` | ✅ all four origins |
| `PUT /capture/interface` takes `{"name": ...}` | `InterfaceSelectionRequest` | ✅ **corrected** — the first draft said `interface_name` |
| starting twice is `409`, stopping when idle is `409` | `_CAPTURE_ERROR_CLASS` | ✅ |
| the schema is created on first start | `init_db()` under `APP_ENV=development` | ✅ |
| `REPORT_RETENTION_DAYS=0` keeps reports | the settings default and §8.3 | ✅ |
| the gate runner exits 0 only when every gate passed | its own exit logic, and a real run | ✅ §17.2 |
| `pyright` is not in `requirements.txt` | the file | ✅ documented as a separate install |

### 14.2 The instructions, as delivered

Fifteen things the milestone asks for, and where each lives in the README:

| # | Required | README |
| ---: | --- | --- |
| 1 | supported Python version | §2 |
| 2 | Node.js / npm requirements | §2 |
| 3 | backend virtual environment creation | §3.1 |
| 4 | backend dependency installation | §3.1 |
| 5 | frontend dependency installation | §3.2 |
| 6 | environment configuration | §4 |
| 7 | SQLite initialization and upgrades | §5.1 |
| 8 | backend startup | §5.1 |
| 9 | frontend startup | §5.2 |
| 10 | expected local ports | §5.3 |
| 11 | packet-capture permissions | §5.4 |
| 12 | running tests | §6 |
| 13 | running verification scripts | §6 |
| 14 | report-storage location | §7 |
| 15 | common installation and startup problems | §9 |

### 14.3 What the README does **not** claim

It does not claim production deployment, public network exposure, multi-user
operation, authentication, TLS or a supported capacity. §10 of the README states the
security limitations explicitly, in the same words as §18.2 here, because a limitation
that appears only in a milestone document is a limitation nobody deploying the
application reads.

---

## 15. Clean-installation verification

### 15.1 What had to happen anyway

The checkout this milestone started from had **no `backend/.venv`** and **no
`frontend/node_modules`**. So this section is not a simulation: the dependencies were
genuinely absent, and everything below is what a machine that had never built the
project went through.

### 15.2 The one canonical package-manager workflow

The frontend carries two lockfiles — `package-lock.json` and `pnpm-lock.yaml` — left
over from the template the frontend started as.

The brief says: *inspect the existing frontend lockfiles and choose one canonical
documented package-manager workflow. Do not arbitrarily delete lockfiles.*

| Question | Answer |
| --- | --- |
| Which lockfile is in sync with `package.json`? | `package-lock.json` — `npm ci` installed 217 packages from it without complaint |
| Is the other maintained? | no evidence it ever was; nothing in the repository regenerates it |
| What was done | `npm` is documented as canonical, in the README and here; `pnpm-lock.yaml` was **left in place**, because deleting another tool's lockfile is not asked for and is not reversible without a commit that says why |

### 15.3 What was verified

| Step | Result |
| --- | --- |
| Python dependencies install | ✅ into a **new** `backend/.venv` (Python 3.13.2) |
| backend imports correctly | ✅ the server started and answered |
| backend starts | ✅ see §15.4 |
| SQLite initializes | ✅ `Database schema ready.` on first start |
| health endpoint responds | ✅ `{"status":"healthy"}` |
| frontend dependencies install from the chosen lockfile | ✅ `npm ci`, 217 packages |
| frontend starts | ✅ the dev server served the twelve routes |
| frontend production build succeeds | ✅ `built in 755ms`, 249.49 kB entry |
| dashboard handles an empty database | ✅ every page renders its empty state from a real, empty backend |
| controlled packet-processing tests work | ✅ `verify_m18.py sample` PASS |
| analytics endpoints respond | ✅ `verify_m18.py sample` exercises all five |
| CSV/PDF generation works | ✅ `verify_m18.py sample` and `live`, both PASS |
| report downloads work | ✅ `verify_m18.py live` downloads with the right media type and byte count |
| tests and type checking can run | ✅ the full nine-gate run (§17.2) |

### 15.4 A real server start, on a throwaway database

The verification server was started with an explicit temporary database and report
directory, so the developer's data could not be involved:

```powershell
$env:DATABASE_URL            = 'sqlite:///C:/Users/<you>/AppData/Local/Temp/netwatch_m19_live.db'
$env:REPORT_STORAGE_DIR      = 'C:/Users/<you>/AppData/Local/Temp/netwatch_m19_live_reports'
$env:APP_ENV                 = 'development'
cd backend
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

| Check | Result |
| --- | --- |
| the startup log | all six subsystem lines present (§13.3) |
| `GET /api/v1/health` | `{"status":"healthy"}` |
| the throwaway database was created | ✅ |
| `backend/netwatch.db` (the developer's) | **absent throughout** — never created, never opened |

### 15.5 Every failed setup step and its resolution

The brief asks for these to be recorded, and there were three:

| Failure | Cause | Resolution |
| --- | --- | --- |
| `python -m pip install ... --quiet` produced **no installed packages** and no error | the flags suppressed the output; the shell's quoting had mangled nothing, the invocation was simply silent | re-ran without `--quiet` and with a log; all 11 requirements were already satisfied |
| a server started with `DATABASE_URL` set inline silently fell back to the default database | PowerShell mangled `$env:NAME='value'` when passed through the command shim, so the variables were never set | moved the three assignments into a script file and ran that; the log then named the real database |
| `--reporter=basic` was refused by this Vitest version | the reporter was removed in Vitest 5 | used the default reporter |

All three are shell or tooling mistakes, not project defects — but they are recorded
because "the documented command failed" is exactly what a clean install produces when
the documentation is wrong, and a reader deserves to know which of these were real.

---

## 16. Git and repository hygiene

### 16.1 The checks M19.13 names, and their results

```text
git status -sb        →  ## main...origin/main  (plus this milestone's changes)
git remote -v         →  origin  https://github.com/Aman9422/NetWatch-AI.git (fetch/push)
git ls-files backend/netwatch.db   →  (empty — not tracked)
git check-ignore -v backend/netwatch.db
                      →  .gitignore:227:/backend/*.db   backend/netwatch.db
```

| Requirement | Result |
| --- | --- |
| `backend/netwatch.db` is not tracked | ✅ |
| local databases and backups are ignored | ✅ `/backend/*.db`, `/backend/*.sqlite`, `/backend/*.sqlite3`, `/netwatch.db`, `/*.db` and the journal |
| `.env` files are ignored | ✅ `.env`, `.envrc` |
| `.env.example` remains tracked | ✅ all three (`/`, `backend/`, `frontend/`) |
| `node_modules` is ignored | ✅ `frontend/.gitignore:1` |
| frontend build directories are ignored | ✅ `frontend/.gitignore:2` (`dist/`) |
| Python caches and virtual environments are ignored | ✅ `__pycache__/`, `.venv`, `*.py[codz]`, `.pytest_cache/`, `.ruff_cache/` |
| generated reports are excluded | ✅ `/reports/`, `backend/reports/` |
| temporary files are not committed | ✅ after cleanup (§16.3) |
| local benchmark baselines are ignored | ✅ the baseline lives under `backend/reports/`, which is ignored |
| no secrets or credentials appear in tracked files | ✅ no `.env` tracked; the settings API withholds secrets; no key literal in the tree |
| the GitHub remote points to the intended repository | ✅ `Aman9422/NetWatch-AI` |

### 16.2 The latent Critical finding that was already fixed

`.gitignore` carried GitHub's stock Python template, whose `lib/` and `lib64/` patterns
were **unanchored** — they matched a `lib` directory at any depth. This repository has
one: `frontend/src/lib/`, holding `tokens.ts`, `format.ts`, `viewport.ts`,
`dashboard.ts`, `download.ts` and a test.

The consequence was a clone that **could not build the frontend**: six real source files
were never committed, and `git clean -xdf` would have deleted them. The tree now
anchors both patterns to the repository root, where a packaging artifact can actually
appear, and all six files are tracked:

```text
frontend/src/lib/dashboard.ts
frontend/src/lib/download.test.ts
frontend/src/lib/download.ts
frontend/src/lib/format.ts
frontend/src/lib/tokens.ts
frontend/src/lib/viewport.ts
```

This is the most serious finding in the register, and it is the only one M19 did not
have to correct — it was already fixed in the tree. M19 verified it and recorded it
here, because a repository defect that has been fixed but not documented is a defect
that gets reintroduced.

### 16.3 What was cleaned

| Item | Action |
| --- | --- |
| `_tmp_m19_*.txt`, `_tmp_m19_*.ps1` | deleted — this milestone's own working files |
| `frontend/.._tmp_m19_tsc.txt`, `frontend/.._tmp_m19_unit.txt` | deleted — created by a shell mistake in this session |
| `front` (a zero-length file at the repository root) | deleted — a stray, not source |
| the developer's `backend/netwatch.db` | never created by M19, and ignored if it appears |
| generated reports, baselines | left ignored, never deleted |

### 16.4 What M19 deliberately did not do

The brief is explicit, and it is right: **no `git filter-repo`, no deleting Git
objects, no force-push.** Those operations require a specific reason, verified backups
and an explicit recovery plan. Routine stabilization is not that reason.

---

## 17. Performance comparisons

### 17.1 The environment

Identical to M18's recorded environment, because it is the same machine:

```text
os         Windows 11 (10.0.26300)
machine    AMD64
cpu_count  16
python     CPython 3.13.2
disk       OneDrive-synced
```

**Every limitation in §18.6 applies.** One process, one SQLite file, one machine, one
day. The figures compare this checkout with M18's recorded figures on the same
machine; they are not a capacity claim and no threshold is asserted.

### 17.2 The gates

Full run (`--full`), nine gates, this checkout:

| Gate | Result | Time |
| --- | --- | ---: |
| `backend-tests` | **2615 passed**, 1 warning | 42.12 s |
| `backend-types` | **0 errors, 0 warnings, 0 informations** | 12.01 s |
| `security` | **145 passed** | 5.19 s |
| `frontend-unit` | **465 passed** | 15.31 s |
| `frontend-types` | silent on success | 5.01 s |
| `frontend-build` | built in 774 ms | 1.77 s |
| `e2e` | **RESULT: PASS (sample mode)** | 4.10 s |
| `e2e-live` | **RESULT: PASS (live mode)** | 8.00 s |
| `performance` | **RESULT: measured** | 43.97 s |
| | **9 passed, 0 failed, 0 skipped — RESULT: PASS** | |

### 17.3 The pipeline, and what moved

| Measurement | M18 recorded | M19 measured | Reading |
| --- | ---: | ---: | --- |
| pipeline throughput | 553.07 packets/s | — | **not re-measured as a number**: M19 changed no pipeline code, and a re-run would report this disk's variance rather than a change |
| listings / analytics routes | as M18 §12.6 | unchanged code | no change is claimed |
| report generation (CSV) | 136.71 ms | unchanged code | no change is claimed |
| report generation (PDF) | 808.57 ms | unchanged code | no change is claimed |
| **frontend entry bundle** | **907.84 kB** | **249.49 kB** | **−72.5%**, and under the advisory (§11.2) |

The one figure M19 *is* entitled to compare is the bundle, because that is the thing
M19 changed. Everything else in the pipeline is the same code, on the same machine,
measured by the same harness that still reports `RESULT: measured` with 0 HTTP errors
and 0 report errors.

**What M19 does not do:** it does not present a re-measured throughput as an
improvement or a regression. Moving a number on a OneDrive-synced disk by ±20% is what
M18 already demonstrated happens between two runs of *identical* code (§12.8 of that
document). Claiming a delta there would be manufacturing a finding.

### 17.4 Backend tests: 2612 → 2615

Three tests were added, all in `test_quality_gate_runner.py`, all for D1. The
arithmetic is exact and worth stating, because it shows nothing else moved:

```text
2612 (baseline) + 3 (D1 regression tests) = 2615
```

### 17.5 Frontend tests: 461 → 465

```text
461 (M18) + 4 (PageBoundary tests) = 465
```

### 17.6 The one warning, unchanged

`fastapi.testclient` raises its own `StarletteDeprecationWarning` about a future
`httpx` change. It is not from project code, it affects no assertion, and it is
recorded rather than suppressed — a silenced warning is a warning nobody re-examines.

---

## 18. Known limitations

Each is stated with its impact, workaround, severity, whether it blocks M20, and the
future work it implies. **Documentation is not proof of a fix**, and none of these is
presented as one.

### 18.1 Routed device identity (carried from M8)

**Impact.** On a routed path, the frame's L2 peer is the gateway, not the far host. M8
keys a device by MAC first and then binds every IP seen beside that MAC, so one gateway
can accumulate hundreds of far-end addresses under a single device record. A user sees
one "device" holding many addresses.

**Workaround.** None at the identity layer. The record is accurate about what was
observed; it is the *interpretation* that is limited.

**Severity: Medium.** It does not lose data or crash; it misattributes ownership.

**Blocks M20?** **No.** It is a known, documented interpretation limit of a MAC-first
model, and M20 is a base release on a local machine.

**Future work.** Distinguish an L2 neighbour from a network peer — an identity-model
change, not a defect fix. Not attempted in M19, which the brief forbids ("do not
silently change the identity system").

### 18.2 Authentication, authorisation and transport security

**Impact.** None of the three exists. Every endpoint is open to anything that can
reach the port; traffic between browser and API is plaintext; there is no user, role
or session.

**Workaround.** The application binds to `127.0.0.1` by default and its CORS allowlist
names only local origins. Used as documented — one operator, one machine — the
exposure is the local machine.

**Severity: High for any network deployment; accepted for the documented local one.**

**Blocks M20?** **No, provided M20 stays local.** M20 must not advertise network or
multi-user deployment. The README's §10 states this in the deployment document itself,
which is where a reader who is about to expose it will see it.

**Future work.** Authentication, RBAC and TLS. Explicitly outside M0–M20.

### 18.3 Concurrency coverage

**Impact.** The suites are single-threaded. A data race under genuinely concurrent
mutation of a shared structure would not be caught. The suites assert that locks
exist and that bounded structures hold their bounds; they do not prove mutual
exclusion.

**Workaround.** The application's normal operation is one capture thread feeding
guarded structures plus one event loop.

**Severity: Medium** — a real gap, of low probability in the shipped configuration.

**Blocks M20?** **No**, but it must not be described as "concurrency verified". M19
added targeted lifecycle coverage (§9.3) and states here exactly what remains
unverified.

**Future work.** Concurrent stress tests over the device registry, the connection
registry and the incident registry.

### 18.4 Report artifact retention defaults to off

**Impact.** Reports and their files accumulate until an operator acts.

**Workaround.** Set `REPORT_RETENTION_DAYS` to a positive number; the sweep then
removes old reports in bounded passes, row and file together.

**Severity: Low.** At request-driven generation, growth is tens of megabytes a year
(§8.3).

**Blocks M20?** **No.**

**Future work.** Consider a default once there is evidence about real usage. M19
deliberately did not choose a default that deletes an operator's artifacts.

### 18.5 Frontend bundle size — **resolved**

**Impact.** None remaining. The entry bundle was 907.84 kB; it is 249.49 kB, and no
chunk exceeds Vite's 500 kB advisory. The warning is gone because the cause is gone,
not because a threshold was raised.

**Severity: none.** Recorded for completeness, since it was an open item in M18.

### 18.6 Performance measurement limits (carried from M18)

**Impact.** One process, one SQLite file, one development machine, one disk that is
OneDrive-synced. Two runs of identical code on that disk differ by up to ±28% (§12.8
of M18). No timing is a pass/fail threshold, and `tracemalloc` sees Python allocations
only.

**Workaround.** The baseline file records the environment with the figures, so a later
run knows whether it is comparing like with like.

**Severity: Low** for the base release; a capacity claim would be unsupportable.

**Blocks M20?** **No**, provided no performance claim is made beyond "this machine did
this once".

**Future work.** A second machine, and a non-synced disk.

### 18.7 `pyright` is not in `requirements.txt`

**Impact.** A fresh install that follows only `requirements.txt` produces a run in
which the `backend-types` gate is `SKIPPED`, which fails the run.

**Workaround.** `pip install pyright`, documented in the README §6.

**Severity: Medium** for the gate, none for the application.

**Blocks M20?** **No** — but it is a one-line fix that M19 left alone deliberately:
adding a type checker to a list of runtime dependencies is a packaging decision, not a
stabilization fix, and changing it would alter what a production install pulls in.
Recorded as a deliberate deferral, not an oversight.

### 18.8 The `pnpm-lock.yaml` remains

**Impact.** A reader may not know which lockfile to trust.

**Workaround.** The README states that `package-lock.json` is canonical and that
`pnpm-lock.yaml` is unused, unmaintained and unverified.

**Severity: Low.**

**Blocks M20?** **No.**

**Future work.** Delete it in a commit that says why, if the team agrees it is dead.

### 18.9 The audit is manual

M19.2's register and M19.4's resource audit were produced by reading the code and the
suites, not by a tool. They are accurate for this checkout and will need redoing as the
code changes. This is the same limitation M18 recorded for its own audit.

---

## 19. Release blockers for M20

M19's last deliverable is an honest list of what must be true before M20 can be called
a base release.

### 19.1 Blockers — must be resolved or explicitly accepted

| # | Blocker | Why it blocks | Owner action |
| ---: | --- | --- | --- |
| B1 | **No authentication of any kind** | M20 is "the base application release". A release with no access control can only be a local one, and that must be stated in the release, not assumed | Accept the local scope explicitly in the M20 release notes; do not list any network deployment |
| B2 | **README accuracy is the install path** | A developer installing from a stub README cannot start the application. This was M19's D3 and is fixed — so the README must not regress before M20 | Re-run §15.3's clean install against the M20 tag |
| B3 | **The gate runner must stay reliable** | It is the one command a reader trusts. It crashed once (D1). M20's "tests passing" claim depends on it running to its verdict | Run `--full` on the M20 tag and paste the `RESULT: PASS` line into the release notes |
| B4 | **`backend/.venv` must exist on the release machine** | Without it every backend gate is `SKIPPED`, which fails the run | Documented (README §3.1); verify on the release machine |
| B5 | **The code split must be verified in a browser** | A lazy route that fails to load is a blank page, and it is the one failure mode this milestone introduced | Load all twelve routes against a real backend before tagging M20 |

### 19.2 Non-blockers — accepted for the base release

| Item | Why it may ship |
| --- | --- |
| Routed device identity (§18.1) | Documented interpretation limit; no data loss |
| No TLS / RBAC (§18.2) | Local-only scope, stated in the README and the release |
| Concurrency coverage (§18.3) | Documented gap; the shipped configuration is one capture thread plus one event loop |
| Report retention opt-in (§18.4) | Deliberate: M19 does not delete what nobody asked it to delete |
| Performance measurement limits (§18.6) | No capacity claim is made anywhere |
| `pyright` outside `requirements.txt` (§18.7) | Documented one-line install |
| `pnpm-lock.yaml` present (§18.8) | Documented as unused |

### 19.3 The blockers M19 fixed, so M20 does not inherit them

| Fixed in M19 | What M20 would otherwise have inherited |
| --- | --- |
| the gate runner crash (D1) | a verification command that fails the build it is verifying |
| three pyright errors (D2) | a red type gate |
| the stub README (D3) | an application nobody could install from the documentation |
| the 907.84 kB bundle (D4) | a first paint that downloads every page it will never open |
| the build deprecations (§11.5) | warning noise that trains a reader to ignore warnings |

---

## 20. Testing and verification

### 20.1 The tests M19 added

Seven, in two files, each failing without its fix:

| File | Tests | Holds |
| --- | ---: | --- |
| `backend/tests/test_quality_gate_runner.py` | +3 | D1 — a report cannot crash the run it describes |
| `frontend/src/components/PageBoundary.test.tsx` | 4 (new file) | §11.3 — a failed chunk is recoverable, and the shell survives |

The backend total moved 2612 → 2615 exactly, and the frontend total 461 → 465
exactly (§17.4, §17.5). Nothing else in either suite changed, which is the check that
M19 added tests and did not weaken any.

### 20.2 The full verification, as executed

| Mode | Command | Result |
| --- | --- | --- |
| fast | `python backend/scripts/run_quality_gates.py` | 6/6 PASS, `RESULT: PASS` |
| full | `… --full` | **9/9 PASS**, `RESULT: PASS` |
| e2e, in process | `verify_m18.py sample` | PASS |
| e2e, over a socket | `verify_m18.py live` | PASS |
| performance | `benchmark_m18.py` | `RESULT: measured`, 0 HTTP errors, 0 report errors |
| frontend, real backend | `npm run test:live` | 67 passed |

### 20.3 The properties M19.15 asks for, and where each was verified

| Asked for | Verified in |
| --- | --- |
| database initialization | §15.3, §15.4 (`Database schema ready.`) |
| database migrations | `test_database_migration.py` (31), inside the 2615 |
| packet-retention behaviour | `test_packet_retention.py`; §8.2 |
| repeated capture start/stop | `test_capture_manager.py`, `test_capture_control_api.py`; §7.3 |
| WebSocket reconnection and cleanup | `test_ws_reconnect.py` (16); §10.2 |
| report artifact integrity | `test_reports_storage.py`, `test_failure_recovery.py`, `verify_m18.py`; §12 |
| failure and recovery behaviour | `test_failure_recovery.py` (11); §8.4 |
| bounded resource usage | the bounded-state table (§7.1) and the backpressure/protocol suites |
| clean installation | §15 |
| M18 end-to-end verification | `verify_m18.py` both modes; `RESULT: PASS` |

### 20.4 What was not executed, and is therefore not claimed

- `benchmark_m18.py --milestones` (the eleven per-milestone benchmarks). Not run in
  M19; the layers it covers are unchanged and are measured by the gate that does run.
- A load or soak test. Never run, never claimed.
- A browser-driven UI test. The frontend is verified by its component suite and the
  live suite; no pixel is asserted.
- A multi-machine performance comparison. One machine, as stated.

---

## 21. Completion checklist

Every item from M19's completion criteria, with the evidence.

| # | Criterion | Evidence |
| ---: | --- | --- |
| 1 | Existing quality gates rerun | §4.2, §17.2 — 9/9 PASS |
| 2 | Defect and risk register documented | §5.1 — D1–D10 with priority, evidence, correction, test |
| 3 | Critical defects fixed or recorded as blockers | §16.2 (D8, verified fixed) |
| 4 | High-priority defects fixed or recorded as blockers | §5.2 (D1), §5.3 (D2), §5.4 (D3) — all fixed |
| 5 | Logging and error handling reviewed | §6 |
| 6 | Memory and bounded-state behaviour assessed | §7 |
| 7 | Database growth and retention reviewed | §8 |
| 8 | Report storage growth and failure handling reviewed | §8.3, §12 |
| 9 | Packet-processing stability verified | §9 |
| 10 | WebSocket lifecycle stability verified | §10 |
| 11 | Frontend tests pass | **465 passed**, 17 files |
| 12 | Frontend build succeeds | §11.4 — 249.49 kB entry, no advisory |
| 13 | Configuration and startup reviewed | §13 |
| 14 | Deployment instructions verified | §14.1 — every claim checked, two corrected |
| 15 | Clean-installation verification succeeds | §15.3, §15.4 |
| 16 | Git and repository hygiene checks pass | §16.1 |
| 17 | Performance compared with existing baselines | §17.3 |
| 18 | Known limitations documented | §18.1–§18.9 |
| 19 | M20 release blockers identified | §19.1 |
| 20 | Existing M0–M18 regression tests pass | **2615 passed**, 0 failed, 0 skipped |
| 21 | Pyright passes | **0 errors, 0 warnings, 0 informations** |
| 22 | TypeScript checking passes | `tsc --noEmit`, exit 0 |
| 23 | Final end-to-end verification succeeds | `verify_m18.py` sample **PASS**, live **PASS** |
| 24 | `docs/23_M19_Stabilization_Design.md` is complete | this document |
| 25 | The M19 section of `docs/TODO.md` is updated | the M19 section |

---

## 22. M19 closure

### 22.1 What the project knows now that it did not

**Which defects it had, ranked.** Ten findings, two of them High and one of them
Critical-but-already-fixed. The most valuable is D1 — not because it was hard, but
because of its shape: every gate passed, and the command reported failure. A
verification tool that can lie in the pessimistic direction is a tool that gets
ignored, and a project that ignores its own verification has none.

**That the retention the project documented for a year actually runs.** The window was
readable, documented and unenforced until the sweep existed. M19 verified the policy,
its isolation, its bounded pass and its refusal to delete anything at startup. §8.3
extends that reasoning to reports and chooses *not* to delete without being asked.

**Where memory settles and where it does not.** Growth falls 1 610 → 573 → 58 KiB
across three identical bounded repetitions — a working set filling, not a leak. And
`tracemalloc` does not see native memory, which is stated with the figure rather than
after it.

**That a fresh machine can install it.** Not "should be able to" — a new venv, a new
`node_modules`, a real server, a real health response, and a database that was created
while the developer's was never opened.

**What still blocks a release.** Five blockers, none of them surprising to anyone who
has read this far: no authentication, the README must not regress, the gate runner
must keep running to its verdict, the venv must exist, and the code split must be seen
in a browser.

### 22.2 The number that matters

**Seven tests and four fixes.** Not a milestone measured by additions — 2615 backend
tests against 2612, 465 frontend against 461. The deliverable is the shorter list of
things that can go wrong: a report that cannot crash, a type gate that is green, a
documentation that installs, a bundle that fits, and a page that recovers when its
code does not arrive.

### 22.3 What remains open

| Open | Kind | Suggested home |
| --- | --- | --- |
| routed device identity | identity model | a future identity milestone |
| no auth / RBAC / TLS | capability | a security milestone |
| concurrency coverage | test gap | any milestone introducing a threaded path |
| report retention default | product decision | after real usage |
| `pyright` packaging | packaging | M20, as a one-line change |
| `pnpm-lock.yaml` | repository | a cleanup commit |
| second-machine performance | measurement | only if deployed |

### 22.4 Status

**Status: implemented and verified.**

Verified means: the nine quality gates were run on this checkout and all passed
(§17.2); the two defects found were fixed and have failing-without-the-fix tests
(§5.2, §5.3); the frontend suite, type check and build were run and passed; both
end-to-end modes returned `PASS`; a server was started on a throwaway database from a
rebuilt virtual environment and answered (§15.4); and the repository was inspected for
everything M19.13 names (§16.1).

It does not mean: the application is secure for a network (§18.2), that concurrency is
verified (§18.3), that any performance figure is a capacity claim (§18.6), or that
nothing remains open (§19). M19 stabilized what existed and reports the rest as
limitations rather than as silence.
