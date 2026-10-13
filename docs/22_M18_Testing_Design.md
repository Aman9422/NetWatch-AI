# M18 — Testing and Verification

**Milestone:** M18 — Testing and Verification
**Status:** implemented and verified
**Depends on:** every milestone M1–M17 (this milestone audits and measures them; it fixes three defects and adds one security guard, across seven source files)
**Consumes:** the M1–M17 test suites, the M13 API, the M14 WebSocket hub, the M15 frontend, the M16 analytics service, the M17 reporting layer

---

## 1. Purpose

M0 through M17 each shipped tests. Every one of them was written to answer
"does *this milestone* behave?" — a detection rule fires, an endpoint refuses a
bad body, a page renders without a backend. None of them was written to answer the
questions a project asks once the milestones are stacked on top of each other:

- Where is the suite actually thin, as opposed to where it *feels* complete?
- Does the whole pipeline hold when it is driven end to end, rather than layer by
  layer with fakes between them?
- When a layer fails, does the failure surface as a described situation, or as a
  crash the next layer inherits?
- Did seventeen milestones of small changes cost anything measurable?
- Can the whole verification be re-run with one command, by somebody who did not
  write any of it?

M18 answers those five questions and nothing else. It is a **verification
milestone**: it audits what exists, adds tests only where behaviour is genuinely
uncovered, strengthens the end-to-end path, measures the pipeline, and leaves
behind a repeatable set of commands.

The measure of M18 is not how many tests were added. It is three numbers it must
report honestly: how many exist, what they cover, and what one full run costs. The
milestone's own instructions are explicit that a bigger number is not a better
answer (§2).

---

## 2. Scope

M18 delivers:

1. **An audit** — a file-by-file, layer-by-layer inventory of the 90 backend test
   files, the 16 frontend unit files, the 3 live files and the 27 scripts, stating
   what each suite holds and, where it is thin, naming the behaviour that is not
   covered (§4, §5).
2. **Tests for uncovered behaviour** — five new test files and one addition to an
   existing file, 217 tests in total. Each closes a named gap, and §5 states which.
3. **End-to-end verification** — `backend/scripts/verify_m18.py`, a two-mode
   script that drives the real stack: `sample` (the pipeline over a throwaway
   database, in process) and `live` (uvicorn on a free loopback port, real HTTP
   and a real WebSocket) (§11).
4. **A performance regression harness** — `backend/scripts/benchmark_m18.py`,
   which measures the whole pipeline as M18 runs it, records the environment with
   the figures, and reports its deviation from a saved baseline (§12).
5. **Security-boundary verification** — the existing regression suite plus the
   assertions M18.11 asks for: no internal in a response, no path traversal, no
   capability that a request can reach (§13).
6. **Failure and recovery verification** — the existing recovery suite plus the
   end-to-end assertions that a layer failing degrades the answer rather than the
   process (§14).
7. **Repeatable project-wide commands** — `backend/scripts/run_quality_gates.py`,
   one entry point that runs every gate in the order that fails fastest (§15).
8. **Three defects found and fixed**, all found *by* the verification rather than
   reported by a user — the alert-to-finding trail was never persisted, the PDF
   frame width was 12 points too wide, and a PDF row taller than a page failed the
   whole document — plus **one boundary that had no guard**: CSV formula injection
   (§5.5, §5.6, §12.9, §13.3).
9. **This document** — the audit, the coverage matrix, the results and the
   limitations, with the numbers the run produced.

### 2.1 What M18 was explicitly told not to do

The milestone's instructions carry two constraints that shaped every decision
below, and both are worth quoting rather than paraphrasing:

> Do not rewrite working modules merely to increase test coverage.

> Do not duplicate existing tests without adding meaningful new coverage.

The first is why M18 changed **seven** source files in the whole project — the
`alerts` model, the alert domain object, alert persistence, the migration, the
database bootstrap, the CSV renderer and the PDF renderer — and **no** module was
restructured to make it easier to test. Each change is either a named defect with a
test that fails without it, or the guard M18.11's own checklist required
(§5.5–§5.6).

The second is why the 217 tests M18 added (§5.3) are grouped into six files aimed at
named areas rather than scattered to raise a count. Where a behaviour was already
covered, the existing test was left alone. Where it was covered by a *neighbouring*
test — "the listing returns 200" standing in for "the listing returns the rows it
says" — the gap was named in §5 and closed once, not twice.

---

## 3. Non-goals

Explicitly outside M18, and not implemented by it:

- a coverage-percentage target, and any threshold that fails a build
- a mutation-testing pass
- load, soak or stress testing against a production-shaped deployment
- a benchmark of capture, of the network stack, or of anything requiring privilege
- chaos injection, fault injection at the syscall level, or a canary deployment
- property-based or fuzz testing of the parsers
- test parallelisation work, sharding, or CI-provider configuration
- a browser-driven UI test suite (the frontend is verified by its own suites and
  the live run, not by a headless browser driving a real page)
- new features of any kind

M18 adds no capability to NetWatch AI. It is the milestone that asks whether the
capabilities M1–M17 claim are real.

---

## 4. Existing test-suite audit

### 4.1 The inventory

| Layer | Files | Live tests | What they exercise |
| --- | ---: | --- | --- |
| Backend, `backend/tests/` | 90 | 2 539 | M1–M17 behaviour, unit through API |
| Backend fakes | 7 | — | shared builders (`reports_fakes.py`, `analytics_fakes.py`, …) |
| Frontend unit, `frontend/src/**/*.test.ts(x)` | 16 | 461 | components, hooks, services, models |
| Frontend live, `frontend/tests/live/` | 3 | 67 | the real app against a real backend |
| Scripts, `backend/scripts/` | 27 | — | 11 per-milestone benchmarks, 14 verification scripts, 1 gate runner |

### 4.2 What each layer's suite is shaped around

| Milestone | Its suite is about | Its characteristic assertion |
| --- | --- | --- |
| M5 capture/processing | a packet is parsed and counted once | the same frame is not counted twice |
| M6 statistics | a window's numbers | a rate is a rate over its interval, not a total |
| M7 persistence | a row survives a round trip | what is written is what is read |
| M8 devices | identity | one machine seen twice is one device |
| M9 connections | a conversation | its two directions are one connection |
| M10 detection | a rule fires, and does not | the negative case is tested as hard as the positive |
| M11 alerts | an alert records what fired | severity and confidence are carried, not recomputed |
| M12 correlation | incidents group alerts | a group is not a single alert counted twice |
| M13 API | the envelope and the refusals | a bad field names the field |
| M14 WebSockets | delivery and fan-out | each subscriber gets each event once |
| M15 frontend | rendering and the client models | a page renders without a backend, and with one |
| M16 analytics | agreement with the store | the view and a direct query agree |
| M17 reports | the artifact and the lifecycle | the row never claims a file that is not there |

### 4.3 Where the audit found the suite genuinely thin

The audit checked every layer against a fixed question: *is there a behaviour this
layer promises that no test would notice the loss of?* Five answers came back
positive — four test gaps, closed by new tests (§5.4), and one defect, which no test
could have caught because the behaviour itself was wrong (§5.5). The CSV
formula-injection surface (§5.6) is a sixth finding, and it was not a missing test
either: it is a boundary M18.11's checklist names, which the code had never guarded.

| Gap | Layer | Why the audit counted it as uncovered |
| --- | --- | --- |
| the alert-to-finding trail | M11 → M10 | the column was never written, so no test could assert its value — the suite was complete *for the behaviour as written*, and the behaviour was wrong |
| the PDF page-frame arithmetic | M17 | column widths were tested against `FRAME_WIDTH`; nothing tested that `FRAME_WIDTH` is the width reportlab actually lays out in |
| a table row taller than a page | M17 | every PDF fixture row was short, so the one shape reportlab refuses was never rendered |
| a report generation **error** in a perf run | M18 | the harness counted durations without counting statuses, so a refused generation would have been reported as a fast one |
| CSV formula injection | M17 | no test asserted that a cell a spreadsheet would evaluate is neutralised, and the renderer passed every cell through unguarded |

### 4.4 What the audit deliberately did *not* change

- **No existing test was edited to pass.** Exactly one existing test file gained
  tests — `test_reports_pdf_renderer.py`, by two — and no existing test in it was
  modified. The other five test files M18 touched are new.
- **No fake was replaced with a real service** in the unit suites. The fakes are
  what make a unit suite deterministic; the live suite exists for the cases where
  determinism is the wrong trade (§10).
- **No suite was merged, split or renamed.** The file layout a reviewer already
  knows is the file layout M18 leaves behind.

---

## 5. Coverage matrix

### 5.1 The matrix

Rows are the layers; columns are the kinds of verification. A tick means a suite
exercises that layer in that mode, and the number is how many tests in this
checkout exercise it. "—" means the mode does not apply, not that it is missing.

| Layer | Unit | Integration | API contract | WebSocket | Frontend unit | Frontend live | E2E (`verify_m18`) | Perf |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| M5 capture / processing | ✓ | ✓ | — | — | — | — | ✓ | ✓ |
| M6 statistics | ✓ | ✓ | ✓ | — | — | — | ✓ | ✓ |
| M7 persistence | ✓ | ✓ | — | — | — | — | ✓ | ✓ |
| M8 devices | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| M9 connections | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| M10 detection | ✓ | ✓ | ✓ | — | — | — | ✓ | ✓ |
| M11 alerts | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| M12 correlation | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| M13 REST API | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| M14 WebSockets | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ | — |
| M15 frontend | — | — | — | — | ✓ | ✓ | — | — |
| M16 analytics | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| M17 reports | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |

Every cell is backed by a suite named in §6–§11. The awkward cell is M5 in the
"perf" column: capture itself is not measurable without a privileged handle, so the
harness measures the *processing* path (M5's parse-and-dispatch) and says so rather
than implying it measured a live interface (§12.5).

### 5.2 The audit matrix, in M18.1's prescribed form

M18.1 asks for the audit as one table, one row per area, with the gap and the action.
This is that table. "No gap found" is a result and not an omission: the audit checked
each area against §4.3's question — *is there a behaviour this layer promises that no
test would notice the loss of?* — and most areas answered no.

| Area | Existing Tests | Identified Gaps | M18 Action |
| --- | --- | --- | --- |
| Packet processing | M5 suite: parse, normalise, dispatch, duplicate suppression, malformed frames, IPv4/IPv6, TCP/UDP/ICMP/DNS | none found; the capture lifecycle is exercised structurally, because no ordinary test may open an interface | audited only — verified end to end by §11 and measured by §12 |
| Database | M2/M7 infrastructure, the repository suites, 31 migration tests | none found; migrations were already tested against a previous schema | audited only — plus 2 migration tests for the finding column (§7.2) |
| Device discovery | M8 suite: first sight, updates, MAC normalisation, multiple addresses, registry bounds, stale cleanup | none found; the routed-traffic identity limit is a documented limitation, not a defect | audited only — the limitation is preserved and restated (§18.9) |
| Connection tracking | M9 suite: canonical identity, reversed endpoints, states, expiry, counters, capacity | none found | audited only — asserted end to end by §11 |
| Detection and alerts | M10/M11 suites: every rule, thresholds, windows, evidence, lifecycle, dedup, invalid transitions | **the alert-to-finding trail was never written** | **defect fixed** — column, persistence, migration and view, with 7 + 2 tests (§5.5) |
| Correlation and risk | M12 suite: normalisation, windows, weights, aggregation, anti-chaining, incident lifecycle, bounded risk and band boundaries | none found | audited only |
| REST API | every route's success and refusal, pagination, filters, timestamps, envelopes, error bodies | none found by the audit | audited only — refusals re-asserted as sentences (§8.4) |
| WebSockets | M14 suite plus 6 live tests over a real socket | none found | audited only (§9) |
| Frontend | 461 unit tests over 16 files, 67 live tests over 3 files | none found by the audit | audited only (§10) |
| Reporting | 153 reporting tests | **the PDF frame width was 12 pt too wide**, and **a row taller than a page failed the document** | **defects fixed** — both in `pdf_renderer.py`, with 2 tests (§12.9) |
| Performance | 11 per-milestone benchmarks | the harness did not count failed responses, so a refused generation would have been timed as a fast one | **defect fixed** — error counts added, and a whole-pipeline harness written (§12) |
| Security | 145 new security regression tests | **no guard against CSV formula injection** | **hardening added** — one choke point in the CSV renderer (§5.6, §13.3) |

### 5.3 The M18 additions, and only these

Six test files were touched: five created, one extended. Together they are **217
tests** — and 217 is exactly the difference between the M17 record's 2 322 backend
tests and the 2 539 this milestone measured (§17.4). That arithmetic is worth
stating plainly, because it shows that nothing else moved under the suite's feet
while M18 worked.

| File | Tests | New? | Covers |
| --- | ---: | --- | --- |
| `test_security_regression.py` | 145 | created | the four boundary surfaces of §13: CSV formula injection, SQL parameterisation, artifact confinement, error-body disclosure |
| `test_database_migration.py` | 31 | created | every milestone's migration, applied to a database at the *previous* schema (§7.2) |
| `test_capture_sniffer.py` | 21 | created | M3–M5 capture and processing: interface handling, lifecycle, malformed frames, protocol identification |
| `test_failure_recovery.py` | 11 | created | a failing write, a failing rename, a vanishing artifact, and a cleanup that fails while handling a failure (§14) |
| `test_alerts_finding_trail.py` | 7 | created | the alert-to-finding trail that was never written (§5.5) |
| `test_reports_pdf_renderer.py` | +2 | extended | the frame width reportlab really lays out in, and a row taller than a page (§12.9) |
| **total** | **217** | | |

Five of the six are **new files for areas that had no dedicated suite at all** —
migrations, the capture lifecycle, the security boundaries, the recovery paths, the
alert trail. That is the shape of what the audit found: not one thin assertion here
and there, but whole areas a milestone had shipped without a test file of its own.

The security and migration files are the two largest, and both are heavily
parametrised: 25 test functions in the security file collect as 145 cases because
each boundary is exercised across every trigger, payload and refusal shape it has.

### 5.4 What those 217 tests assert, by area

| Area | Tests | The property |
| --- | ---: | --- |
| Security boundaries | 145 | a request cannot make the process do something it should not: a cell a spreadsheet would evaluate is neutralised, a filter value never becomes SQL syntax, an artifact path outside the storage directory is refused *identically* to a missing file, and no response names an internal |
| Migrations | 31 | a database at the previous schema gains what a milestone added and loses nothing; M18's adds `alerts.finding_id` and `idx_alerts_finding_id` |
| Capture and processing | 21 | a malformed or unsupported frame is isolated rather than fatal, and a capture error is reported rather than appearing as zero traffic |
| Failure and recovery | 11 | a failed write leaves no debris, a cleanup failure does not replace the failure that caused it, and the next request is unaffected |
| The finding trail | 7 | what M11 records is what a later read returns, and an unrecorded trail is `None` rather than `""` |
| PDF layout | 2 | `FRAME_WIDTH` is the width reportlab actually lays out in, and a row taller than a page still renders |

### 5.5 The alert-to-finding trail: a defect the audit could not have found by reading tests

M11 attaches a **finding** citation to an alert: the finding is what a rule
matched, and the trail is what lets a reader ask "which detection produced this
alert?". The column existed in the model, was mapped, was read by the API view —
and was never written.

The suite was green, and honestly so: every test asserted what the layer *did*.
No test asserted what it *should* have done, because the trail was modelled as
optional everywhere it was read, and `None` is a legal value for an optional
column. A complete suite for a wrong behaviour is the exact failure mode M18.1's
audit was written to catch, and it was caught by asking the question the tests
could not: *which column in this model does no test ever see written?*

The fix is four additive changes and a migration: the column is mapped, populated
at the point the alert is created, carried by the persistence layer, and exposed by
the view. The migration is additive — no column is dropped, renamed or retyped —
and the pre-M18 rows keep `NULL`, which is the truthful value for an alert recorded
before the trail was written.

This is the milestone's most valuable single finding, and it is worth stating what
it cost: **seven tests and a column**. It was not found by a user, a crash or a
failing assertion. It was found by auditing what the suite *did not* assert.

### 5.6 CSV formula injection: a boundary that had no guard

The trail is a defect. This one is not — it is a **boundary M18.11's checklist names
by name**, which the code had never guarded, and which no existing test asserted.

A CSV is opened in a spreadsheet. A spreadsheet evaluates a cell whose first
character is `=`, `+`, `-` or `@`. One value in a report is caller-supplied — the
report's **title** — and device hostnames and rule names come from the network, so a
report is a formula-injection surface: a value nobody reviewed could execute on the
machine of the operator who opens the report.

The fix is one choke point in `app/reports/csv_renderer.py`:

| Name | Job |
| --- | --- |
| `FORMULA_TRIGGER_CHARS` | the characters a spreadsheet may read as the start of a formula — `=`, `+`, `-`, `@`, plus a leading tab or carriage return, which some importers trim and thereby expose what follows |
| `FORMULA_GUARD` | a single quote, the spreadsheet's own text marker |
| `_looks_numeric()` | keeps the guard away from ordinary figures: `-12` and `+3` are numbers a reader might sum, and prefixing them would turn a figure into a string |
| `guard_cell()` | applied to every cell at one point, so there is one place to audit and one definition of the rule |
| `_GuardedWriter` | the writer that `render_csv` uses, so no call site can bypass the guard |

This is **the only place in the reporting layer that alters a value on its way
out**, and it is documented in the module rather than applied silently: a reviewer
has to be able to see why a report can differ from what the store held. The guard is
a prefix, never a truncation — the reader still sees the text that was written — and
the suite asserts both halves: that the trigger is neutralised, and that the original
text survives (§13.3).

M18.11 asks for exactly this and no more: *fix only minimal, clearly identified
correctness or security defects needed to make the tested behavior safe.* One guard,
one choke point, one test group — and no change to how a report is assembled.

---

## 6. Unit testing

### 6.1 Shape

The unit suites live in `backend/tests/`, one `test_<module>.py` per module under
test, with seven shared fake modules (`*_fakes.py`) holding the builders that more
than one file needs. A fake module exists only when two or more test files would
otherwise duplicate the same builder, which is why there are seven and not seventy.

| Convention | Rule |
| --- | --- |
| file naming | `test_<module>.py` for the module it exercises |
| shared builders | a `*_fakes.py` module, imported by name |
| no cross-test state | each test builds what it needs; nothing is module-level mutable |
| time | a fake clock or an injected instant, never `time.sleep` in a unit test |
| error assertions | the sentence *and* the field, not only the status |
| no network, no disk | a unit test that needs either is an integration test wearing the wrong name |

### 6.2 What a unit test in this project asserts

The suites are written to the "one behaviour, stated as a property" rule the earlier
milestones' documents describe: a test names a property a *reader* or a *caller*
depends on, and asserts that property rather than the implementation that happens to
produce it. Characteristic examples, one per layer:

- M6 — a rate over a window is a rate; a total over the same window is not a rate.
- M8 — a machine seen at two addresses in the same window is one device, and its
  addresses are a set, not a concatenation.
- M10 — a rule that does not match produces no finding, and the negative case is
  tested with the same care as the positive one.
- M16 — the analytics view and a direct query over the same instants agree.
- M17 — an unknown format fails loudly rather than writing a file in the wrong one.

### 6.3 The one structural change M18 made to a test file

`backend/scripts/verify_m18.py` had accumulated a duplicated verification block
(1 978 lines across two copies) during the milestone. It was removed rather than
kept, because a duplicated check is a check that can be edited once and left
inconsistent in the other place. This is a *script*, not a test suite, and the
de-duplication is why the file has one flow rather than two.

---

## 7. Database testing

### 7.1 What is tested

| Concern | Where | What is asserted |
| --- | --- | --- |
| schema creation | `test_database_*.py` | the schema builds from nothing and is idempotent |
| migrations | `test_database_migration.py` (31 tests) | an existing database gains what a milestone added, additively |
| repositories | `test_repositories_*.py` | filters, ordering, pagination and counts |
| round trips | per-repository | what is written is what is read, including `None` vs `""` |
| foreign keys and cascade | `test_database_*.py` | deleting a parent does not orphan a child silently |
| indexes | `test_database_migration.py` | an index a query depends on is present |

### 7.2 Migrations are additive, and the tests hold them to it

The project's rule is that a migration adds. `test_database_migration.py` asserts
per milestone that the upgrade introduces the column and the index that milestone
promised, against a database created at the *previous* schema — which is the only
way to test a migration: a migration tested against a fresh schema never runs.

M18's two additions follow the same rule:

| Test | Asserts |
| --- | --- |
| `test_the_m18_upgrade_adds_the_finding_column` | the column exists after upgrading a pre-M18 database |
| `test_the_m18_upgrade_adds_the_finding_index` | the index exists after the same upgrade |

Both create the pre-M18 shape, run the upgrade, and then inspect the schema. Neither
writes a row through the application to get there: the question is what the
*migration* does to a database, and answering it through the ORM would pass even if
the migration did nothing.

### 7.3 Nullable means nullable

The finding column is nullable, and the tests distinguish its two absences:

| Value | Means | Asserted by |
| --- | --- | --- |
| `None` | no trail was ever recorded | the trail tests assert `None`, not `""` |
| a value | a trail was recorded | the round-trip tests assert the exact value |

This distinction is the M16.8 rule at the database layer: an unanswered question is
not an empty answer, and a test that accepts either would hide the difference.

---

## 8. API contract testing

### 8.1 The envelope, and what "contract" means here

Every M13 route answers in one envelope, and the tests assert the envelope rather
than only the payload:

```json
{ "success": true, "message": "…", "data": { "…": "…" } }
```

A contract test in this project asserts four things at once, and a test that asserts
three of them is not a contract test:

1. the **status** (`200`, `201`, `400`, `404`, `422`)
2. the **envelope** (`success`, `message`, `data` present and shaped)
3. the **refusal**, for a bad input: the field is *named* in the message
4. the **absence**, for an error: no internal appears in the body (M13.30)

### 8.2 Current status

| Suite | Tests | Covers |
| --- | ---: | --- |
| `test_api_*.py` (all route files) | part of the 2 539 | every M13–M17 route, success and refusal |
| `test_reports_api.py` | part of the 153 reporting tests | the four M17 routes, including the download |
| `test_analytics_api.py` | part of the M16 suite | the five aggregate routes |
| `test_security_regression.py` | 145 | the boundary assertions of §13 |

### 8.3 The 400-versus-422 split is deliberate and is tested

A value that is *well-formed but unanswerable* returns the project's own envelope
with a queryable code; a value that never reaches a handler returns FastAPI's own
`422`. `"format": "DOCX"` is a `400`; `"generated_by": "abc"` is a `422`. Both are
asserted, because the two shapes are the contract and a change to either is a
breaking change for the M15 client.

### 8.4 Refusals are asserted by sentence, not only by status

`test_every_refusal_reports_a_sentence_rather_than_an_exception` (M18.11) walks the
refusal surface and asserts the shape of the answer for each: a sentence, in the
envelope, naming the field. The assertion is deliberately not "the status is 400" —
a 400 body that leaks a traceback satisfies the status and breaks the contract.

---

## 9. WebSocket testing

### 9.1 Two layers of verification

| Layer | Suite | What it proves |
| --- | --- | --- |
| the hub, in process | `backend/tests/test_websockets_*.py` | fan-out, unsubscription, capacity, the event vocabulary |
| the hub, over a real socket | `frontend/tests/live/websocket.test.ts` (6 tests) | the M15 client parses what M14 really publishes |

The split is the point. The unit suite can prove the hub delivers one event to one
subscriber; only a real socket proves that what crosses the wire is the envelope the
client's own parser expects.

### 9.2 What the live WebSocket tests assert

| Test | Property |
| --- | --- |
| a real `dashboard.updated` event parses as the client models it | the event vocabulary and the M15 types agree |
| each distinct event is applied exactly once | no double-apply on a reconnect |
| transport frames are not counted as events | a ping is not a payload |
| two subscribers share one connection | the client does not open a socket per subscriber |
| delivery stops once both leave | no leak of a subscription |

The third is the one worth naming: a WebSocket connection carries frames that are
not application events, and a client that counted them as events would show a user
phantom updates. It is asserted on a real socket because only a real socket sends
them.

---

## 10. Frontend testing

### 10.1 Two configurations, and why both exist

| Run | Command | Config | Files | Tests |
| --- | --- | ---: | ---: | ---: |
| unit | `npm test` | `vitest.config.ts` | 16 | 461 |
| live | `npm run test:live` | `vitest.live.config.ts` | 3 | 67 |

The unit run replaces `fetch` with a router and `WebSocket` with a controllable
fake. That is what makes it deterministic, and it is also its limitation: it can
pass while the backend's actual envelope, field names or event payloads have
drifted. The live run uses the real `fetch`, the real `WebSocket` and a real
backend, so a drift fails there and only there.

`tests/live/**` is excluded from the unit run, deliberately: a machine with no
backend must still be able to run `npm test`, and running the live suite there would
fail for a reason that is not a defect.

### 10.2 What the unit suite covers

| Kind | Examples |
| --- | --- |
| rendering | each page renders from a fixture without a backend |
| failure states | a refresh that fails keeps the content and warns |
| capacity | the live traffic view holds at its documented row cap, dropping the oldest |
| models | a value the API sends is parsed into the shape the components consume |
| formatting | sizes, rates and timestamps render as documented |
| no backend | every page renders with `fetch` answering nothing at all |

The "renders with `fetch` answering nothing" case is asserted for every page, and it
is the one that catches the commonest frontend defect: a page that only renders when
data arrives, and shows a blank screen when it does not.

### 10.3 What the live suite covers

| File | Tests | Covers |
| --- | ---: | --- |
| `rest.test.ts` | 53 | every REST-family call the app makes, against the real API |
| `pages.test.tsx` | 8 | pages rendered from real endpoints, including the System verdict |
| `websocket.test.ts` | 6 | the real hub, described in §9.2 |

The M17 reporting path is covered here end to end: a report is generated for real
and the figures it opens with are checked against what the client shows.

### 10.4 The frontend types are verified twice

`npm run typecheck` (`tsc --noEmit`) is one gate; the unit suite catching a
mismatched prop at runtime is the other. Neither replaces the other, and both are
in the gate set (§15).

---

## 11. End-to-end testing

### 11.1 The two modes

**Script:** `backend/scripts/verify_m18.py`

| Mode | How it runs | What it can prove that no other suite can |
| --- | --- | --- |
| `sample` | the real pipeline over a throwaway SQLite database, in process, through `app.main:app` in a `TestClient` | the whole stack is wired: packet in, device/connection/detection/alert/incident out, and the same facts visible through the API, the analytics views and a generated report |
| `live` | uvicorn on a free loopback port, real HTTP, real WebSocket | what crosses a socket is what the client expects: real status codes, real envelopes, a real event |

`sample` is fast and is part of the default gate set. `live` starts a server and is
part of `--full`.

### 11.2 What `sample` asserts

The flow drives a fixed packet set and then asks the *system* for the answers,
rather than asking each layer in turn:

| Step | Asserted |
| --- | --- |
| ingest | the packets are all accepted and counted once |
| device discovery | the expected devices exist, with the addresses they were seen at |
| connection tracking | the expected conversations exist, one per pair of endpoints |
| detection | the expected findings fire, and no others |
| alerting | the findings become alerts, with severity carried |
| correlation | the related alerts form the incident they should |
| API | every listing returns what the preceding steps produced |
| analytics | the aggregate views agree with the rows just written |
| reporting | a report is generated and its own summary matches the same data |

The reporting step is where the PDF defect surfaced (§12.6): the flow generates a
CSV *and* a PDF, and the PDF failed on the real data while the CSV succeeded.

### 11.3 What `live` asserts

`live` re-runs the API surface over a real socket: every route answers its
documented status, the envelope is intact, and a real WebSocket event arrives on its
own schedule. It is the mode that would catch a router mounted at the wrong prefix —
which it did: `GET /api/v1/system` is a *prefix* with `/info`, `/health` and
`/status` beneath it, and the first live run probed the prefix rather than a route.

### 11.4 What the flow deliberately does not do

- It does not assert a wall-clock timing. A timing that had to hold would be a flaky
  test wearing a verification script's clothes.
- It does not assert on a mock. Every layer in it is the real one.
- It does not use the configured database. It builds a throwaway one in a temporary
  directory and removes it, so running the flow can never damage a developer's data.

### 11.5 The comparison that makes the flow worth having

Each assertion in the flow compares **two independent observations** — the number
the pipeline produced and the number the API reports for the same instants. A test
that asserted "the API returned 12" against a constant would pass on a stack that
wrote nothing and reported nothing consistently. Comparing the pipeline's own total
against the API's own total is what makes the assertion about the system rather than
about two hardcoded numbers.

### 11.6 Two defects the flow found, and one it did not

| Found by | Defect | §  |
| --- | --- | --- |
| the reporting step of `sample` | the PDF failed on real data with a layout error | §12.6 |
| the live-mode route probe | `/system` is a prefix, not a route | §11.3 |
| **not found** | the alert-to-finding trail | §5.5 — no end-to-end number changed, because a missing citation does not change a count |
---

## 12. Performance regression testing

### 12.1 What M18.10 asks for, and where each answer is

| M18.10 asks for | Where |
| --- | --- |
| the hardware and software environment | §12.2 |
| the dataset and test conditions | §12.3 |
| warm-up and measurement procedure | §12.4 |
| median and tail latency | §12.6 |
| observed resource consumption | §12.7 |
| deviations from existing baselines | §12.8 |
| — and no capacity claim, no timing treated as correctness | §12.5, §12.10 |
| an audit of the existing benchmarks rather than a rebuild | §12.11 |

**Harness:** `backend/scripts/benchmark_m18.py`
**Baseline file:** `backend/reports/benchmark_m18_baseline.json` (git-ignored)

### 12.2 The environment, printed with every run

The harness prints this block before the figures, because a number without an
environment means nothing:

```text
os         Windows 11 (10.0.26300)
machine    AMD64
processor  Intel64 Family 6 Model 154 Stepping 3, GenuineIntel
cpu_count  16
python     CPython 3.13.2
sqlite     3.45.3
captured   2026-10-12T14:23:14+00:00
```

The block is written into the baseline file as well, so a later run reports its
deviation **beside the machine the baseline was taken on**. Two runs on the same
machine are comparable; two runs on different machines are not, and the report says
which it is comparing.

### 12.3 The dataset and the conditions

| Condition | Value | Why |
| --- | --- | --- |
| packets per iteration | 2 060 = 2 000 ordinary + 48 scan + 12 sweep | the scan and the sweep are the traffic that reaches M10, M11 and M12; without them the measurement would cover M5–M9 and quietly omit every layer M18.9 verifies |
| distinct sources | 250 | device discovery and connection tracking do real work rather than updating one entry |
| conversations | 2 000 = 250 sources × 8 ports | **bounded**, so the registries saturate and the memory figure measures behaviour rather than the size of the input (§12.7) |
| packet shapes | TCP to 203.0.113.9:443, UDP to the local resolver, ICMP every thirteenth | three shapes, so no branch is cold |
| addresses | 10.20.0.0/24 (private) and TEST-NET-3 (RFC 5737) | nothing here addresses a host that could exist on a real network |
| database | one throwaway SQLite file in a temporary directory, removed afterwards | the developer's own database is never touched |
| input reproducibility | identical on every run and every machine — same addresses, same ports, same order | an input that varied between runs could not show a regression |

### 12.4 The measurement procedure

```text
for each measurement:
    1. run the warm-up iterations and DISCARD them
    2. run the timed iterations, recording each duration individually
    3. report the MEDIAN as the headline, with p95, mean, best and worst beside it
```

| Decision | Reason |
| --- | --- |
| warm-ups are discarded | the first request pays for lazy imports and the first packet pays for the statistics window; neither is a figure about steady state |
| the median is the headline | one slow iteration moves the mean and not the median |
| every iteration's duration is kept | a total would hide the tail, and the tail is what a user feels |
| the percentile is nearest-rank | with three to twenty samples an interpolated percentile is a number no run actually produced |
| 20 iterations for a request, 3 for a generation | a request is three orders of magnitude cheaper; a median over three samples of something that fast is all noise |
| `tracemalloc`, not RSS | it measures Python allocations, which is the honest scope and is labelled as such (§12.7) |

### 12.5 What is measured, and what is deliberately not

| Measured | Not measured |
| --- | --- |
| the M5–M12 pipeline, end to end, packets in and figures out | **capture** — no interface is opened, and none can be without privilege |
| every M13 listing route, in process, through `TestClient` | network transport — there is none in the measurement |
| every M16 aggregate route | multi-process or multi-machine load |
| M17 report generation (CSV and PDF) and a download | browser render time |
| Python-level allocation growth | native allocations (SQLite's page cache, socket buffers) |
| | disk throughput, which the OS caches and the run would mostly measure |

**This is not a capacity claim.** One process, one development machine, one SQLite
file. It is a local regression baseline: a figure that says *this machine did this
once*, on the day and the environment printed above it.

### 12.6 Median and tail latency

**Phase 1 — the pipeline (M5–M12), 2 060 packets per iteration:**

| Measurement | unit | n | median | p95 | mean | best | worst |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| pipeline throughput | packets/s | 3 | **553.07** | 555.18 | 536.74 | 501.97 | 555.18 |
| pipeline per packet | µs | 3 | **1 808.10** | 1 992.14 | 1 867.16 | 1 801.23 | 1 992.14 |

**Phase 2 — the REST surface (M13), 20 requests per route:**

| Route | unit | n | median | p95 | mean | best | worst |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `GET devices` | ms | 20 | 4.50 | 5.11 | 4.56 | 4.04 | 5.34 |
| `GET connections` | ms | 20 | 34.29 | 42.68 | 34.81 | 25.55 | 45.99 |
| `GET detections` | ms | 20 | 7.00 | 8.29 | 6.94 | 5.23 | 8.30 |
| `GET alerts` | ms | 20 | 5.53 | 6.05 | 5.44 | 3.83 | 6.19 |
| `GET incidents` | ms | 20 | 5.02 | 5.92 | 5.11 | 4.28 | 6.29 |
| `GET packets` | ms | 20 | 11.28 | 14.60 | 11.62 | 9.18 | 15.24 |
| `GET dashboard` | ms | 20 | 7.17 | 8.21 | 7.20 | 5.59 | 8.27 |
| `GET system status` | ms | 20 | 4.15 | 4.67 | 4.18 | 3.52 | 4.74 |
| **HTTP errors** | count | 1 | **0** | 0 | 0 | 0 | 0 |

**Phase 3 — analytics (M16), 20 requests per route:**

| Route | unit | n | median | p95 | mean | best | worst |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `GET analytics traffic` | ms | 20 | 38.65 | 41.98 | 39.04 | 34.99 | 43.49 |
| `GET analytics protocols` | ms | 20 | 14.68 | 16.53 | 15.06 | 13.43 | 19.20 |
| `GET analytics devices` | ms | 20 | 5.92 | 6.40 | 5.92 | 5.31 | 6.42 |
| `GET analytics connections` | ms | 20 | 54.83 | 58.47 | 54.28 | 44.52 | 62.02 |
| `GET analytics threats` | ms | 20 | 14.89 | 16.10 | 14.87 | 12.92 | 16.49 |
| **HTTP errors** | count | 1 | **0** | 0 | 0 | 0 | 0 |

**Phase 4 — reporting (M17):**

| Measurement | unit | n | median | p95 | mean | best | worst |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `generate CSV` | ms | 3 | 136.71 | 145.24 | 134.10 | 120.34 | 145.24 |
| `generate PDF` | ms | 3 | 808.57 | 830.52 | 813.92 | 802.66 | 830.52 |
| `download CSV` | ms | 3 | 11.30 | 12.85 | 11.55 | 10.52 | 12.85 |
| **report errors** | count | 1 | **0** | 0 | 0 | 0 | 0 |

**The error rows are part of the result, not decoration.** A latency median taken
over three refused requests is not a generation cost, and reporting one as though it
were is the mistake this harness exists to catch (§12.9). Both counts are zero on
the recorded run: 21 routes answered `200`, and 3 + 3 + 1 generations answered
`201`/`200`.

**Reading the figures.** The two expensive operations are the two that do work
proportional to the data rather than to a request: the pipeline (1.8 ms per packet
through parse, statistics, discovery, connection tracking, detection, alerting and
correlation) and PDF generation (0.81 s, which is reportlab's layout work — §10.3 of
the M17 document). Every listing is milliseconds, and the two slowest listings —
`connections` and `analytics connections` — are the two that read the largest tables.

### 12.7 Observed resource consumption

`tracemalloc` traces **Python allocations**, which is the honest scope of this
figure and is printed with it: a buffer allocated inside a C extension does not pass
through the allocator `tracemalloc` hooks, so a process could grow while this number
stayed flat. A figure visible here is certainly real; a flat one is a useful negative
result, not proof of no growth anywhere.

**6 180 packets driven (2 060 × 3 repetitions):**

| Measurement | Value |
| --- | ---: |
| traced before | 0.0 KiB |
| traced after | 2 241.7 KiB |
| traced peak | 5 537.2 KiB |
| growth across the phase | +2 241.7 KiB |
| growth per packet (all repetitions averaged) | +371.4 bytes |
| repetition 1 | **+1 609.9 KiB** |
| repetition 2 | **+573.3 KiB** |
| repetition 3 | **+58.4 KiB** |
| later repetitions (mean) | +315.9 KiB |
| last repetition | **+58.4 KiB** |

**This is the measurement M18.10's "observed resource consumption" is about, and
the per-repetition rows are the ones that answer it.** Growth falls 1 610 → 573 →
58 KiB across three identical repetitions of the same traffic. That is the signature
of a bounded working set being filled: the first repetition creates every device and
every conversation the run will ever mention, and by the third there is almost
nothing left to create.

An average alone — the +371.4 bytes/packet row — would have been **misleading**, and
this was a genuine finding of the milestone: the first version of the harness
reported only the average, over an input that invented a fresh conversation for every
packet. That version reported +811 bytes/packet and could not distinguish a leak from
an input that never repeated. Two changes fixed it: the traffic now cycles through a
*bounded* set of 2 000 conversations (§12.3), and the harness reports each repetition
separately. The reading the rows now support is the honest one:

> A first repetition much larger than the rest is a working set being filled. Later
> repetitions growing *proportionally* would indicate a leak. Here they fall by an
> order of magnitude, so this run shows a bounded set and no per-packet leak **within
> the traced scope**.

The peak of 5 537 KiB is the high-water mark across the phase, which is the figure
worth knowing for a long session: it is what the pipeline's own Python objects
occupy at their largest while processing 2 060 packets.

### 12.8 Deviation from the recorded baseline

`--save-baseline` writes the run's medians and environment; a later run reads it and
prints its deviation. The output below is a real comparison — the second recorded run
against the first, on the same machine, minutes apart:

| Sample | Baseline → this run | Change |
| --- | --- | ---: |
| pipeline throughput | 503.86 → 553.07 packets/s | +9.8% better |
| pipeline per packet | 1 984.67 → 1 808.10 µs | −8.9% better |
| `GET devices` | 5.22 → 4.50 ms | −13.8% better |
| `GET connections` | 47.92 → 34.29 ms | −28.4% better |
| `GET detections` | 8.35 → 7.00 ms | −16.2% better |
| `GET alerts` | 6.40 → 5.53 ms | −13.6% better |
| `GET incidents` | 5.14 → 5.02 ms | −2.4% better |
| `GET packets` | 11.59 → 11.28 ms | −2.7% better |
| `GET dashboard` | 7.40 → 7.17 ms | −3.2% better |
| `GET system status` | 2.86 → 4.15 ms | **+45.2% worse** |
| `GET analytics traffic` | 36.49 → 38.65 ms | +5.9% worse |
| `GET analytics protocols` | 14.11 → 14.68 ms | +4.0% worse |
| `GET analytics devices` | 5.83 → 5.92 ms | +1.7% worse |
| `GET analytics connections` | 47.81 → 54.83 ms | +14.7% worse |
| `GET analytics threats` | 14.56 → 14.89 ms | +2.2% worse |
| `generate CSV` | 120.98 → 136.71 ms | +13.0% worse |
| `generate PDF` | 906.32 → 808.57 ms | −10.8% better |
| `download CSV` | 11.77 → 11.30 ms | −4.0% better |

**How to read this table, honestly: it is noise.** The two runs were minutes apart on
an idle machine, the code between them changed only the harness's memory phase, and
the spread still reaches ±28% on routes whose implementation did not change at all.
`GET system status` "regressed" 45% on a route that reads one enum and one dialect
string — a move of 1.3 ms on a 3 ms figure, which is the scheduler, not the code.

This is exactly why **no deviation fails the run** (§12.10). The harness reports a
change with its direction, its magnitude, the environment and a `notable` flag past
50%, and leaves the judgement to a reader who knows what changed between the runs. A
threshold that failed here would fail on a busy machine and on an idle one
differently.

The comparison is nevertheless the whole point of the baseline file: when the same
figure moves by 3× rather than 30%, and it was the one module under change, the row
says so in one line, next to the machine it was measured on.

### 12.9 Three defects the harness found

The harness is the milestone's performance gate, and it earned its place by finding
three real defects before it ever reported a regression. Two are the same defect
seen in production data.

**1. Every PDF data table was 12 points too wide.**

`FRAME_WIDTH` was computed as the margin box:

```text
FRAME_WIDTH = PAGE_SIZE[0] - 2 * PAGE_MARGIN = 493.228
```

but reportlab's `SimpleDocTemplate` builds its frame with `Frame`'s default **6 pt
padding on each side**, so the area content is laid out in is 481.228. Every table
was normalised to a width 12 points wider than the space available. The fix adds the
padding to the arithmetic:

```text
FRAME_PADDING = 6
FRAME_WIDTH   = PAGE_SIZE[0] - 2 * PAGE_MARGIN - 2 * FRAME_PADDING
```

The test that holds it compares the constant with the usable width of a real
`Frame` constructed from the margins, which is a stronger claim than "smaller than
the page": too narrow would leave a visible gutter.

**2. A single row taller than a page failed the entire document.**

Reportlab refuses to lay out a row taller than the frame, and that refusal fails the
*whole document* — every other section with it — unless the table is told it may
split a row across pages. M8 identifies a device by its MAC, so a machine observed at
hundreds of addresses is **one row** whose address cell is taller than a page. That
is the identity limitation M8 documents, not an artificial input, and it is what the
real pipeline produced:

```text
reportlab.platypus.doctemplate.LayoutError: Flowable <Table@… 3 rows x 9 cols
(tallest row 1306)> … tallest cell 1306.0 points, too large on page 10 in frame
'normal'(481.228 x 693.827)
```

The fix is `splitInRow=1` on the data tables. The regression test was verified to
pin the defect rather than merely accompany the fix: with `splitInRow=1` the shape
builds; forced to `0`, the identical content raises `LayoutError … tallest row
1326`. The failure was **data-dependent** — `--packets 50 --iterations 1` did not
reproduce it and `--packets 800` did — which is precisely why a synthetic unit
fixture had never caught it and a whole-pipeline run did.

**3. A refused generation would have been timed as a fast one.**

The first version of the reporting phase measured durations and never looked at the
status code. A generation answering `500` is *faster* than one that succeeds, so a
broken reporting layer would have produced an excellent latency figure. The phase now
probes each response and counts anything that is not `201` into a `report errors`
row printed in the same table. Both counts are zero on the recorded run.

### 12.10 Why no timing is a correctness test

M18.10 is explicit: *do not treat an arbitrary timing threshold as a correctness
test.* The harness therefore has exactly two exit conditions:

| Exit | When |
| --- | --- |
| `0` | the run measured everything it selected |
| `1` | it could **not measure at all** — a missing script, a database it cannot create |

A slow figure is never a failure. A timing that had to hold on every machine would be
a flaky test wearing a benchmark's clothes, and it would fail for reasons unrelated
to the code: a busy laptop, a thermal limit, an antivirus scan. What a timing
threshold cannot do is distinguish a regression from an environment, and that is the
one job it would have to do.

The regression *signal* is the comparison with the baseline, read by a person who
knows what changed. The harness's job is to make that comparison one line per
measurement, on a machine it names.

### 12.11 The audit of the existing benchmarks

M18.10 also says not to rebuild the earlier benchmarks. M6 through M17 each ship a
`benchmark_m*.py` that measures its own layer with its own fixtures, and re-measuring
those layers inside this harness would produce a **second** set of numbers that could
disagree with the first for no reason except where they were taken.

| Script | Layer it measures | Measured here? |
| --- | --- | --- |
| `benchmark_m6.py` | statistics windows and rates | no — run and reported |
| `benchmark_m7.py` | persistence round trips and batch writes | no — run and reported |
| `benchmark_m8.py` | device discovery and the registry | no — run and reported |
| `benchmark_m9.py` | connection tracking | no — run and reported |
| `benchmark_m10.py` | rule evaluation | no — run and reported |
| `benchmark_m11.py` | alert creation | no — run and reported |
| `benchmark_m12.py` | correlation | no — run and reported |
| `benchmark_m13.py` | the REST surface in isolation | no — run and reported |
| `benchmark_m14.py` | WebSocket fan-out | no — run and reported |
| `benchmark_m16.py` | analytics queries | no — run and reported |
| `benchmark_m17.py` | report generation in isolation | no — run and reported |
| — | M5 capture | nothing to run: capture needs privilege, and every M5 script measures processing |
| — | M15 frontend | frontend timing is the Vitest suite's own duration (§17) |
| — | M18 | it is this harness |

`--milestones` runs each of the eleven in its own process and reports its **exit
status and the baseline line the script printed itself** — no re-interpretation, and
a script that exits non-zero is reported exactly as that rather than counted as a
measured layer. The `--milestones` flag is not in the default gate: it re-runs eleven
separate benchmarks, which is minutes, and the layers it covers are already measured
by the gate that runs this harness.

### 12.12 What the harness deliberately shares with M18.9

`benchmark_m18.py` imports `verify_m18.py` as `lab` rather than building its own
stack. The reason is drift: if the two scripts each wired the pipeline, a threshold,
a queue cap or a resolver could differ between them, and the throughput reported here
would describe a pipeline the verification flow never proved correct. Sharing the
wiring means the figures describe the same object the end-to-end checks pass against.

---

## 13. Security testing

### 13.1 The boundary model

The security question for this application is not "is there an authentication bug?" —
there is no authentication (M18's non-goals, §3, and every milestone's before it).
The question is narrower and answerable: **can a request make the process do
something it should not?** That reduces to four surfaces, and each has a suite.

| Surface | The risk | §  |
| --- | --- | --- |
| rendered output | a value a user supplied is interpreted as code by the reader | §13.3 |
| query construction | a value reaches SQL as syntax | §13.4 |
| the filesystem | a request chooses a path the process opens | §13.5 |
| the response body | an internal detail reaches a client | §13.6 |

### 13.2 The suite

**File:** `backend/tests/test_security_regression.py` — **145 tests**, run alone as
its own quality gate so its result is visible rather than folded into the suite
total.

The gate runs it alone for a reason: a security regression hidden inside a 2 539-test
summary is a regression nobody sees. Its own line in the gate report says how many of
its tests passed.

### 13.3 Rendered output: a spreadsheet must not execute a cell

A CSV is opened in a spreadsheet, and a spreadsheet treats a cell beginning `=`, `+`,
`-` or `@` as a formula. A report title comes from a request, so a report titled
`=cmd|'/c calc'!A0` is a report whose reader may execute a command.

| Test | Asserts |
| --- | --- |
| a value a spreadsheet would evaluate is guarded | the leading trigger is neutralised |
| the guarded value still carries the original text | the guard is a prefix, not a truncation — the reader still sees what was written |
| an ordinary value is not altered | no guard is added where none is needed |
| a signed number is left alone | `-5` is a number, not a formula |
| a minus that is not a number is guarded | `-5+cmd` is |
| an empty value is not guarded | `""` is not a formula |
| a non-string cell is guarded the same way | the guard is not string-only |
| the trigger set is closed and documented | the guard's vocabulary is a constant, not a scattered literal |

The PDF path is covered too: reportlab's paragraph markup is XML-like, so a hostname
containing `&` or `<` must be escaped before it reaches the parser. A value that
arrived raw would either vanish or raise.

The guard itself is `guard_cell` in `app/reports/csv_renderer.py`, applied by a
single writer (`_GuardedWriter`) so no call site can bypass it. Its vocabulary —
`FORMULA_TRIGGER_CHARS` and `FORMULA_GUARD` — is defined once, which is why
"the trigger set is closed and documented" is a testable claim rather than a
comment: the suite asserts the set is exactly the documented characters. §5.6 gives
the full design, including why a numeric value is left unguarded.

### 13.4 Query construction: a hostile filter value selects nothing, not everything

| Test | Asserts |
| --- | --- |
| an injection payload is never a server error | it is a `200` with no rows, or a `400` — never a `500` |
| a hostile filter value selects nothing rather than everything | the failure mode that matters: a payload that *drops* the filter would return the whole table |
| a hostile filter value never reaches the response body | the payload is not echoed back |
| an injection attempt leaves the schema intact | the tables still exist afterwards |
| a path parameter is never treated as SQL | a value in the path is a value, not syntax |

The second is the one worth naming, and it is asserted rather than assumed: SQL
injection in a read path that interpolated a value would most likely return *more*
rows, not fewer, and a test that only checked for a `500` would pass.

The mechanism is structural, not a filter: every query goes through SQLAlchemy's
bound parameters, so a value cannot become syntax. The suite is the proof that no
route has stepped outside that.

### 13.5 The filesystem: a stored path cannot choose a file

A report's `file_path` is data read from a database row, and a database value must
never be able to make the process open an arbitrary file. `ReportStorage` resolves a
download and refuses anything that does not land **inside** the storage directory,
on every read rather than once at write time (M17 §11.4).

| Input | Result |
| --- | --- |
| a bare file name | resolved inside the directory and served |
| a path inside the directory | resolved and served |
| a path outside it — `../../etc/passwd`, an absolute path | refused |
| a path that does not exist | refused |
| a directory | refused |

All four refusals produce the **same** client-visible answer, and none names a path.
The tests assert both halves: that the traversal is refused, and that the refusal is
indistinguishable from a missing file — because an error that distinguishes them
tells an attacker which paths exist.

### 13.6 The response body: no internal reaches a client

M13.30's rule is asserted wherever an error can be produced, including through the
routes:

| Test | Asserts |
| --- | --- |
| an unknown route and a wrong verb answer in the envelope | a 404/405 is the project's own shape, not a framework default that names the router |
| every refusal reports a sentence rather than an exception | the message is a sentence, in the envelope |
| a PDF of a hostile title is still produced | hostile input degrades the output, never the request |
| a report of hostile strings is still a valid PDF | escaping produces a document, not a corrupt file |
| a report of hostile strings renders the same way twice | escaping is deterministic |
| a very long filter value is refused rather than absorbed | an unbounded value is refused at the door |
| an absurd page size is refused | `limit` is bounded |

The verification script has the same rule from the outside: `FORBIDDEN_IN_RESPONSES`
matches `Traceback`, `File "`, `sqlite3.`, `.db`, `SELECT `, `INSERT ` and `UPDATE `
in any response body, in both modes. The list is deliberately about *internals* — the
driver module, the database file, the statement — and not about the words "sqlite" or
"database": `GET /api/v1/system/status` documents the DB dialect as part of its
contract (M13.22), so a body containing the dialect is the contract being honoured.

### 13.7 What is out of scope, and stated as such

Not tested, and not claimed anywhere: authentication, authorisation, TLS,
rate limiting, CSRF, session management, dependency vulnerability scanning, and
secrets handling. The application binds to loopback and has no user accounts. Where
a document or a response shape might suggest otherwise, it does not: the milestone
non-goals in every document list authentication as absent (§3).

---

## 14. Failure and recovery testing

### 14.1 The model: degrade the answer, never the process

Every layer's promise is that a dependency failing produces a **described situation**
rather than a crash the caller inherits. This is what M16.8 established for the
analytics views — an unreadable block becomes an unavailable section, never a table
of zeroes — and what M17.9 established for a generation — a row that never claims a
file that is not there.

| Failure | The answer |
| --- | --- |
| a database block cannot be read | the section is `available=False` with a sentence; the rest of the report is rendered |
| the store is empty | a valid report with zeroes and empty tables, each with its notice |
| a value was never measured | `not reported`, never `0` |
| an artifact cannot be written | the row is `failed` with a sentence, no artifact, and the next request is unaffected |
| a response would leak an internal | a fixed sentence, with the real exception logged beside the id |

### 14.2 The suite

**File:** `backend/tests/test_failure_recovery.py` — **11 tests.**

| Test | Asserts |
| --- | --- |
| a disk full while flushing is a generation failure with no debris | the failure is a described error and the temporary file is gone |
| a disk full while renaming is a generation failure with no debris | the second half of the atomic write fails the same way |
| an artifact that vanishes after the rename is a failure with no debris | a file removed between the write and the read is reported, not served |
| a cleanup failure does not replace the failure that caused it | the first error is the one reported |
| a write succeeds after a failed one | the storage is not poisoned by a failure |
| a failure after the directory exists removes the artifact | no partial file is left behind |
| a failed row says what happened without naming a path | the sentence is safe (M13.30) |
| a failed generation does not damage an earlier report | failures are isolated per row |
| a generation succeeds after a failed one | recovery, not merely a clean failure |
| a failed generation through the route leaves no artifact | the API path cleans up as the service does |
| a failed generation does not break the next request | no session or connection is left in a bad state |

The fourth is the subtlest and the most valuable: `_mark_failed` runs *while already
handling a failure*, so it must not raise — a second exception raised during cleanup
would replace the one worth reporting. Both steps are attempted and any trouble is
logged rather than propagated, and the test asserts exactly that.

### 14.3 Recovery at startup

| Concern | Where | Asserted |
| --- | --- | --- |
| the schema builds from nothing | `test_database_*.py` | a fresh database is usable |
| the schema is idempotent | `test_database_*.py` | starting twice is starting once |
| a migration is additive | `test_database_migration.py` | a pre-milestone database gains what was added, and nothing is dropped |
| a pre-M18 row keeps `NULL` | the trail tests | `NULL` is the truthful value for an alert recorded before the trail was written |

### 14.4 What is not covered, and why

- **Process-kill recovery.** A `SIGKILL` mid-write leaves whatever it leaves; the
  atomic write is what bounds the damage, and it is tested by simulating the failure
  rather than by killing a process.
- **Disk-full on a real full disk.** The suite injects the `OSError` a full disk
  produces, which is the same exception the code must handle and is the only reliable
  way to test it.
- **Corrupted SQLite files.** Out of scope; a corrupted database is a recovery job
  for an operator, not a behaviour of this application.
- **Recovery under concurrent load.** The suites are single-threaded by design
  (§18.3).

---

## 15. Reproducible quality gates

### 15.1 The runner

**Script:** `backend/scripts/run_quality_gates.py` (M18.13)

It runs the commands that already exist — it contains no test logic of its own. Its
only jobs are to select the gates, run them in a fixed order, and report a summary a
reader can act on.

```text
python backend/scripts/run_quality_gates.py            # the fast gates
python backend/scripts/run_quality_gates.py --full     # + e2e, e2e-live, performance
python backend/scripts/run_quality_gates.py --list
python backend/scripts/run_quality_gates.py --only security
python backend/scripts/run_quality_gates.py --skip frontend-build
python backend/scripts/run_quality_gates.py --full -v  # stream output
```

### 15.2 The nine gates

| # | Key | Command | Proves | In default run |
| ---: | --- | --- | --- | :-: |
| 1 | `backend-tests` | the full pytest suite | every M1–M17 behaviour still holds | ✓ |
| 2 | `backend-types` | pyright | the backend's types are sound | ✓ |
| 3 | `security` | `test_security_regression.py` alone | the four boundary surfaces of §13 | ✓ |
| 4 | `frontend-unit` | `npm test` | components, hooks, services, models | ✓ |
| 5 | `frontend-types` | `npm run typecheck` | `tsc --noEmit` is clean | ✓ |
| 6 | `frontend-build` | `npm run build` | the production bundle builds | ✓ |
| 7 | `e2e` | `verify_m18.py sample` | the whole stack is wired, per §11.2 | `--full` |
| 8 | `e2e-live` | `verify_m18.py live` | real HTTP and a real socket, per §11.3 | `--full` |
| 9 | `performance` | `benchmark_m18.py` | the pipeline is measured and compared with the baseline | `--full` |

### 15.3 Why the order is what it is, and why `--full` is separate

The gates run fastest-failing-first: a suite that takes 40 seconds runs before the
frontend build, which runs before a script that starts a server and takes minutes.
A change that broke the backend is reported in under a minute rather than after the
frontend has built.

The three long gates are behind `--full` because they are **minutes, not seconds**,
and a gate that is slow is a gate that stops being run. The default set is the one a
developer can run on every change; `--full` is the one a developer runs before
committing a milestone.

### 15.4 What it checks before running anything

| Check | Behaviour |
| --- | --- |
| the backend interpreter | `backend/.venv` is resolved from the filesystem; a missing venv is reported, not guessed at |
| `npm` on `PATH` | the frontend gates report their prerequisite rather than failing obscurely |
| `frontend/node_modules` | a frontend gate with no modules installed reports the missing requirement |
| the summary line | each gate's own summary is parsed and printed, so the report says "2 539 passed" rather than "exit 0" |
| a suite that collected nothing | "no tests ran" is treated as a failure, not a pass |
| a failing gate | its output tail is printed in full, so the failure is readable without re-running |

The "collected nothing" rule matters: pytest exits `5` on an empty selection, and an
empty selection is a broken gate, not a passing one. The same applies to Vitest's "No
test files found".

### 15.5 One command, and a report that says what ran

The final summary is one line — how many gates ran, how many passed, how many
failed — followed by the failing gate's own output. A gate that was skipped for a
missing prerequisite is reported as skipped and named as such, so a run can never
look green because a gate quietly did not execute.

This is the property M18 was asked for last, and it is the one that makes the other
eight real: verification nobody can re-run is verification that decays.
---

## 16. Test execution instructions

### 16.1 Prerequisites

| Requirement | Detail |
| --- | --- |
| Python | 3.12 or newer; the project's venv is `backend/.venv` (Python 3.13.2 on the recorded machine) |
| Node.js | with `npm` on `PATH`; the frontend's dependencies are installed in `frontend/node_modules` |
| OS | the recorded environment is Windows 11; nothing here is platform-specific, and the two Windows accommodations are named in §16.6 |
| privileges | **none.** No gate needs an elevated handle, a live interface, a paid service or a network connection |
| a backend for the live suites | only for `e2e-live` and `npm run test:live`, which are given one (§16.4) |

### 16.2 The one command

```text
python backend/scripts/run_quality_gates.py            # the fast gates, ~2 minutes
python backend/scripts/run_quality_gates.py --full     # + e2e, e2e-live, performance
```

`--list` prints the gates and their prerequisites without running anything; `--only
<key>` and `--skip <key>` select a subset; `-v` streams each gate's output instead of
summarising it.

### 16.3 The individual commands

Every gate is an existing command, and each of these can be run on its own.

**Backend** (from the repository root):

| What | Command |
| --- | --- |
| the full suite | `backend\.venv\Scripts\python.exe -m pytest -c backend\pytest.ini --rootdir backend backend\tests -q` |
| one file | `… -q backend\tests\test_reports_pdf_renderer.py` |
| the security suite | `… -q backend\tests\test_security_regression.py` |
| the recovery suite | `… -q backend\tests\test_failure_recovery.py` |
| type checking | `backend\.venv\Scripts\python.exe -m pyright` |
| end-to-end, in process | `backend\.venv\Scripts\python.exe backend\scripts\verify_m18.py sample` |
| end-to-end, over a socket | `backend\.venv\Scripts\python.exe backend\scripts\verify_m18.py live` |
| performance | `backend\.venv\Scripts\python.exe backend\scripts\benchmark_m18.py` |
| performance, with the per-milestone benchmarks | `… benchmark_m18.py --milestones` |
| record a baseline | `… benchmark_m18.py --save-baseline` |

**Frontend** (from the repository root, or with `--prefix frontend`):

| What | Command |
| --- | --- |
| unit | `npm --prefix frontend test` |
| live | `npm --prefix frontend run test:live` |
| type checking | `npm --prefix frontend run typecheck` |
| production build | `npm --prefix frontend run build` |

### 16.4 Running the live suites, which need a backend

`npm run test:live` and `verify_m18.py live` both need a backend listening. The
frontend live suite expects `http://127.0.0.1:8000` and prints that address in its
failure message, so a failure names where it was pointed.

The two `verify_m18.py` modes are self-contained: `sample` builds its own throwaway
database, and `live` starts its own uvicorn on a free loopback port. Neither needs a
server to be started first.

To run the frontend live suite against a backend that does not touch a developer's
data, point it at a throwaway store:

```powershell
$env:DATABASE_URL="sqlite:///C:/Users/<you>/AppData/Local/Temp/netwatch_live.db"
$env:REPORT_STORAGE_DIR="C:/Users/<you>/AppData/Local/Temp/netwatch_live_reports"
backend\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend `
    --host 127.0.0.1 --port 8000
```

Both variables are read case-insensitively by name — `database_url` and
`report_storage_dir` in `app/config/settings.py`, with no prefix. The database schema
is created on startup, so the file need not exist.

### 16.5 Environment variables and defaults

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./netwatch.db` | the store; point it at a temporary file to keep a test run away from real data |
| `REPORT_STORAGE_DIR` | `reports` | where report artifacts are written |
| `APP_ENV` | `development` | the environment the application reports |

`.env.example` documents the configuration and contains no secret. A local `.env` is
ignored by Git (§16.6).

### 16.6 Two Windows accommodations, and the cleanliness rules

| Rule | Detail |
| --- | --- |
| the frontend test pool | `pool: 'threads'`, because the project path contains a space and the `forks` pool never hands a file to a worker there |
| gate process spawning | the gate runner resolves the venv interpreter and the `npm` shim from the filesystem rather than assuming either is on `PATH` |
| the working tree | gates run pytest with `-p no:cacheprovider` so a run does not create a cache directory |
| temporary files | every test that writes uses `tmp_path` or a temporary directory, and the ones that write real files remove them |
| the real database | no gate and no test opens the developer's `backend/netwatch.db`; the suites build their own stores |
| generated artifacts | `/backend/netwatch.db`, `/backend/*.db`, `/reports/` and `backend/reports/` are git-ignored, so a report or a baseline cannot be committed |

### 16.7 Troubleshooting

| Symptom | Cause and answer |
| --- | --- |
| a frontend gate reports a missing prerequisite | `frontend/node_modules` is absent: run `npm --prefix frontend install` |
| `e2e-live` fails to bind | the port is in use; the mode picks a free loopback port, so this is a leftover process from an earlier run |
| `npm run test:live` fails naming `127.0.0.1:8000` | no backend is listening: start one per §16.4 |
| pyright prints a version notice | an upgrade is available; it is a notice, not an error |
| the build warns about a chunk over 500 kB | informational (§18.7) |

---

## 17. Results and measurements

### 17.1 The recorded run

Every figure below was taken from a command executed during M18 on the environment in
§12.2. No count in this document comes from an earlier milestone's record.

| Check | Command | Result | Duration |
| --- | --- | --- | ---: |
| Backend suite | `pytest -c backend/pytest.ini --rootdir backend backend/tests -q` | **2 539 passed, 0 failed, 0 skipped** | 40.4 s |
| Backend types | `pyright` | **0 errors, 0 warnings, 0 informations** | — |
| Security regression | `pytest … test_security_regression.py` | **145 passed** | 2.7 s |
| Failure and recovery | `pytest … test_failure_recovery.py` | **11 passed** | 0.5 s |
| Frontend unit | `npm test` | **461 passed (16 files)** | 47.7 s |
| Frontend types | `npm run typecheck` | **exit 0**, no output | — |
| Frontend build | `npm run build` | **built in 3.39 s** (907.84 kB js, 24.71 kB css) | 3.4 s |
| Live frontend/backend | `npm run test:live` | **67 passed (3 files)** | 18.5 s |
| End-to-end, in process | `verify_m18.py sample` | **PASS** — every property the M18.9 flow promises held | — |
| End-to-end, over a socket | `verify_m18.py live` | **PASS** | — |
| Performance | `benchmark_m18.py --save-baseline` | **RESULT: measured**, exit 0, 0 HTTP errors, 0 report errors | ~2.5 min |

### 17.2 The totals

| Suite | Tests |
| --- | ---: |
| Backend (`backend/tests/`) | 2 539 |
| Frontend unit (`frontend/src/**`) | 461 |
| Frontend live (`frontend/tests/live/`) | 67 |
| **Total** | **3 067** |
| of which reporting (M17 files) | 153 |
| of which security | 145 |
| of which failure and recovery | 11 |
| of which added by M18 | 217 — five new files, plus 2 tests in one existing file |

### 17.3 Failures and skips

**There are none, and that is reported rather than summarised away:**

| Count | Value |
| --- | ---: |
| failed | 0 |
| skipped | 0 |
| xfailed / xpassed | 0 |
| warnings | 1 — `StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead`, raised once by the installed `fastapi.testclient` |

The one warning is a dependency's own notice about a future change to `TestClient`.
It is not raised by project code, it does not affect any assertion, and it is recorded
here rather than suppressed: M18.14 asks for skips and disabled tests to be explained,
and a warning that was silenced would be a warning nobody re-examines.

No test is skipped, `xfail`ed or disabled anywhere in the suite. No test is marked
`slow` and excluded. The live suites are excluded from the unit run by *configuration*
(`frontend/tests/live/**` is not in `vitest.config.ts`'s include), and — this is the
part that matters — **a failing live test is never counted as a pass**: the live run
is a separate gate that must be invoked, and it reports its own pass or fail.

### 17.4 Why these numbers differ from the M17 record

The M17 document records 2 322 backend tests, 257 reporting tests and 448 frontend
unit tests. This run counts **2 539**, 153 and 461. Each difference has a different
explanation, and only one of them is M18.

**The backend difference is exactly M18's own additions.** 2 539 − 2 322 = **217**,
and 217 is precisely the number of tests in the five test files M18 created plus the
two it added to an existing one (§5.3). That was checked by counting those files
individually rather than assumed, and it is the clearest statement available that M18
added tests while changing nothing else about the suite's size.

**The frontend difference is not M18's.** `git status` on the M18 working tree lists
**no** frontend source or test file as modified: all 461 unit tests and all 67 live
tests existed at the M17 tag. The 448 in the M17 record is therefore the same suite
counted another way, not 13 tests M18 added. M18 added nothing to the frontend and
changed nothing there.

**The reporting figure moved *down*, from 257 to 153.** That is not M18's doing
either: M18's only change to a reporting test file was +2, in
`test_reports_pdf_renderer.py`. The 153 is what the four M17 report test files
collect today; the 257 in the M17 record counts "reporting tests" as that milestone
grouped them, which was a wider selection than those four files. The number is
reported as measured, with the difference named rather than explained away.

What is stated exactly, and nothing beyond it:

- the M18 run's command, its output and its count (§17.1)
- the tests M18 added, counted per file (§5.3)
- that the backend difference equals the additions exactly, and that the other two
  differences do not come from M18 — the first because the working tree proves it,
  the second because M18's reporting change was +2 while the figure fell

The instructions were explicit: *do not mark M18 complete merely because previously
recorded test counts appear in the documentation.*

### 17.5 The performance measurements

Full tables in §12.6 (latency), §12.7 (resource consumption) and §12.8 (deviation
from the baseline). The headline figures:

| Figure | Value |
| --- | ---: |
| pipeline throughput | 553.07 packets/s (median), 1 808.10 µs per packet |
| slowest listing | `GET connections`, 34.29 ms median |
| slowest analytics route | `GET analytics connections`, 54.83 ms median |
| report generation, CSV | 136.71 ms median |
| report generation, PDF | 808.57 ms median |
| memory, traced, per repetition | +1 609.9 → +573.3 → +58.4 KiB over three repetitions |

### 17.6 The security and recovery results

| Suite | Tests | Failures |
| --- | ---: | ---: |
| Security regression | 145 | 0 |
| Failure and recovery | 11 | 0 |

Both run in the default gate set, so a regression in either is reported before the
frontend has built.

---

## 18. Known limitations

### 18.1 There is no coverage measurement

**No coverage tool is configured, and no coverage percentage is claimed anywhere in
this document.** M18.1 permits one — *"where coverage data is useful, use an
appropriate existing or freely available coverage tool and document its
limitations"* — and also forbids claiming a percentage without running one.

The choice made here is the audit instead of the number (§4, §5). The reasons are
worth stating:

1. The gaps M18 found were not *line* gaps. The alert-to-finding trail (§5.5) sat in
   code that was **fully executed** by the suite: the column was mapped, read, and
   serialised into every response. A line-coverage report would have shown that path
   at 100% and the defect would have remained invisible.
2. A coverage figure answers "was this line run?", and every question M18 needed
   answered was "was this behaviour asserted?" Those are different questions, and the
   first is the one a percentage can answer.
3. The matrix in §5 records what *is* verified and by which suite, which is what a
   reader needs in order to judge a change.

The honest limitation: **this document cannot tell you what fraction of the code is
executed by the suite.** What it can tell you is which layers are verified in which
modes, and it names the one behaviour the audit found unasserted.

### 18.2 The backend suite has no concurrency coverage

The suites are single-threaded. Thread-safety claims that a milestone made — the
connection tracker's, the registries' — are asserted structurally (a lock exists, a
structure is guarded) rather than by driving concurrent traffic and looking for a
corruption. A genuine race would not be caught.

The mitigation is that the application is single-threaded per process in its normal
operation. The limitation is real for a future multi-threaded capture path.

### 18.3 No browser-driven UI test

The frontend is verified by its component suite (461 tests) and by the live suite
against a real backend (67 tests). Nothing drives a real browser: no click-through,
no visual regression, no layout assertion. A defect that only appears at a real
viewport size would not be caught.

The partial mitigation is that the component suite renders every page through jsdom
at several states, and the live suite renders pages from real endpoints. Neither
measures a pixel.

### 18.4 Capture itself is not measured, and cannot be here

The performance harness measures the **processing** path — parse, statistics,
discovery, connections, detection, alerting, correlation — and never opens an
interface. Traffic is generated as packet objects and handed to the pipeline
directly. The cost of capturing a frame from a real interface is therefore not in any
figure in §12, and the harness says so in its own output.

Capture also needs privilege, which no gate may require (§16.1).

### 18.5 `tracemalloc` measures Python allocations only

Stated in §12.7 and repeated because it is easy to overread: SQLite's page cache,
socket buffers and any other native allocation are **not** traced. The zero-growth
reading for later repetitions is a real negative result for Python objects and not
proof that the process has no growth anywhere.

### 18.6 The tail percentiles rest on few samples

p95 over 3 samples is the slowest sample; over 20 it is the slowest one or two. That
is why the harness prints `n` beside every figure and uses nearest-rank rather than
interpolation: the figures are observed values, not modelled ones. A p99 would be
meaningless at these sample counts, and none is reported.

### 18.7 The frontend bundle exceeds Vite's 500 kB advisory

`npm run build` succeeds and prints an advisory that one chunk is larger than 500 kB
(907.84 kB JavaScript, 241.03 kB gzipped). Code-splitting would address it and is a
**feature** change, which M18's non-goals exclude (§3). It is recorded here rather
than fixed, and rather than silently raising the warning threshold — which would be
the "weakening an assertion without justification" M18.10 forbids.

The build is not a failing gate: it exits 0.

### 18.8 The live suites need a backend

`npm run test:live` and `verify_m18.py live` cannot run without one, and they are
therefore in `--full` rather than in the default set. On a machine with no backend
they are **not run**, and the gate runner names a skipped gate as skipped rather than
letting it count as a pass (§15.4). This is the reconciliation of two requirements
that pull against each other — a machine with no backend must still be able to run
the unit suite, and a failed live test must never be counted as a pass — and it is
solved by reporting the skip.

### 18.9 Two devices' routers are not modelled

M8's documented limitation stands and is untouched by M18: a device is identified by
its MAC, so a routed path whose next hop is a router attributes the traffic to the
router. A machine observed at hundreds of addresses is one row, which is what
produced the tall-row PDF defect (§12.9). M18 preserved the limitation and fixed the
renderer, exactly as M18.4 requires — *"do not mask it with fabricated device
identities"*.

### 18.10 No authentication, and no test for one

No authentication, authorisation, TLS, rate limiting or session management exists in
the application, so none is tested. §13 states this explicitly, and every milestone's
non-goals list it. **Nothing in this document should be read as a claim that the
application is safe to expose to a network.**

### 18.11 The fixtures can drift from reality

The unit suites' fakes are the reason they are deterministic, and determinism is
bought by describing the world instead of observing it. A fake that disagrees with
the real service is a suite that passes while the application breaks. The live suite
and the end-to-end flow exist precisely to catch that drift, and they cover the
surfaces the frontend and the pipeline actually use — not every field of every
response.

### 18.12 One performance environment

The figures are from one development machine on one day (§12.2). They are comparable
with another run on that machine — the baseline comparison in §12.8 is exactly that —
and not with a different one. No absolute threshold is asserted anywhere (§12.10).

### 18.13 The audit is manual

The coverage matrix was produced by reading the suites, not by a tool. It is accurate
for the checkout it describes and will need re-doing as the suites grow. This is the
price of answering "was this behaviour asserted?" rather than "was this line run?"
(§18.1), and it is the limitation a future milestone should replace with a
tool-assisted check for *unasserted behaviour* — a coverage report of the calls a
suite never makes, rather than of the lines it executes.

---

## 19. Completion checklist

Every item from M18's completion criteria, with the evidence that satisfies it.

| # | Criterion | Evidence |
| ---: | --- | --- |
| 1 | Existing test suites have been audited | §4 — 90 backend files, 16 frontend unit files, 3 live files, 27 scripts |
| 2 | A coverage matrix is documented | §5.1 and §5.2 |
| 3 | Packet capture and processing tests are adequate | §5.1; M18.2 — no gap found; the pipeline is measured end to end by §11 and §12 |
| 4 | Database and migration tests pass | 31 migration tests pass with the suite; M18's two are in §7.2 |
| 5 | Device and connection tests pass | 2 539 backend tests pass; the end-to-end flow asserts both layers on real data (§11.2) |
| 6 | Detection, alert and correlation tests pass | same suite; the flow asserts findings → alerts → incidents (§11.2) |
| 7 | Risk-scoring boundary tests pass | in the M12 suite; boundaries asserted as bounds, not as values |
| 8 | REST API contracts are verified | §8; 2 539 includes every route's success and refusal |
| 9 | WebSocket behavior is verified | §9 — the hub in process, and the hub over a real socket |
| 10 | Frontend behavior is verified | §10 — 461 unit and 67 live |
| 11 | Reporting functionality is covered | 153 reporting tests, plus the flow's report step and the harness's report phases |
| 12 | End-to-end data flow is verified | §11 — `sample` PASS, `live` PASS |
| 13 | Performance checks are repeatable | §12 — one command, a recorded environment, a baseline file |
| 14 | Security regression tests pass | 145 passed, run as its own gate (§13) |
| 15 | Failure and recovery behavior is tested | 11 passed (§14) |
| 16 | The main test workflow is reproducible | §15 and §16 — one command, nine gates |
| 17 | Existing M0–M17 regression suites pass | 2 539 passed, 0 failed, 0 skipped |
| 18 | Pyright passes | 0 errors, 0 warnings, 0 informations |
| 19 | TypeScript checking passes | `tsc --noEmit`, exit 0 |
| 20 | Frontend build succeeds | built in 3.39 s |
| 21 | Test output contains no unexplained skips or failures | §17.3 — zero skips, zero failures, one explained dependency warning |
| 22 | `docs/22_M18_Testing_Design.md` is complete | this document |
| 23 | M18's `docs/TODO.md` checklist is updated | the M18 section of `docs/TODO.md` |

### 19.1 The defects M18 fixed, and what was deferred

| Defect | Fixed | Why it was in scope |
| --- | --- | --- |
| the alert-to-finding trail was never written | the model, the domain object, persistence, the migration and the view; the 7 trail tests plus the 2 migration tests | a correctness defect in existing behaviour, found by the audit — a column that is never written is a value a user cannot get |
| CSV formula injection could execute on a reader's machine | one guard at one choke point in `csv_renderer.py`; part of the 145 security tests | M18.11 names it explicitly: a caller-supplied report title is a value nobody reviewed, and a spreadsheet evaluates it |
| every PDF data table was 12 points too wide | `FRAME_WIDTH` arithmetic, 2 tests | a rendering defect that produced a document whose columns ran past the margin |
| a row taller than a page failed the whole document | `splitInRow=1`, covered by the tall-row test | a report that cannot be generated at all on real data |

| Deferred | Why |
| --- | --- |
| the frontend bundle is larger than Vite's advisory | code-splitting is a feature change (§18.7) |
| M8's MAC-identity limitation for routed traffic | an identity model change, not a test change; M18.4 requires it be documented, not masked (§18.9) |
| no coverage tool | a coverage *percentage* was not needed to find what the audit found, and claiming one is forbidden without running one (§18.1) |
| no concurrency, browser-driven or capture-privileged testing | out of scope by §3 and §16.1 |

---

## 20. M18 closure

### 20.1 What the project now knows that it did not

Five answers, being the five questions §1 opened with.

**Where the suite was thin.** Not where it was small — the largest suite had the
widest hole. The audit's finding is that the suite is strong where behaviour is
*produced* and weak where behaviour is *carried*: every layer asserted what it
computed, and no layer asserted that a value it accepted was still there later. The
alert-to-finding trail (§5.5) is the instance; the question — *which value does no
test ever see round-trip?* — is the method, and it is repeatable.

**Whether the pipeline holds end to end.** It does: `verify_m18.py` drives real
packets through the real stack and cross-checks the pipeline's own totals against
what the API, the analytics views and a generated report report for the same
instants. Two defects fell out of that flow that no unit suite had found (§11.6).

**Whether failures are described or crash-landed.** They are described. The recovery
suite (11 tests) covers a full disk during the flush, during the rename, an artifact
that vanishes after the rename, and a cleanup that fails while handling a failure;
the security suite (145 tests) covers the four boundary surfaces. Both are in the
default gate set.

**What the pipeline costs.** 553 packets/s and 1.81 ms per packet through the whole
M5–M12 path on the recorded machine; listings in single-digit milliseconds; PDF
generation at 0.81 s, which is reportlab's layout work. Memory growth decays by an
order of magnitude per repetition, which is a working set filling rather than a leak
(§12.7). None of it is a capacity claim, and none of it is a pass/fail threshold.

**Whether the verification can be re-run.** `python backend/scripts/run_quality_gates.py`
runs nine gates in one command and reports each one's own summary. This is the
property that makes the other four durable.

### 20.2 The number that matters

**217 tests added to 3 067, in five new files and one extended file.** The
milestone's two constraints (§2.1) shaped what they are: not three hundred tests
re-asserting what 2 539 already asserted, but 145 for the security boundaries, 31 for
the migrations, 21 for the capture path, 11 for recovery, 7 for the finding trail and
2 for the PDF layout — each group aimed at an area that had no dedicated suite at
all.

The audit's value is separable from that count, and larger than it. Three defects
were fixed — a column that was never written, a page frame 12 points too wide, and a
row height that could fail an entire document — plus one boundary that had no guard.
**The defects are the deliverable. The 217 tests are what stops them coming back.**

### 20.3 What remains open

| Open item | Kind | Suggested milestone |
| --- | --- | --- |
| the frontend bundle exceeds Vite's advisory | performance, needs code-splitting | a frontend milestone |
| no authentication, authorisation or TLS | capability | a security milestone |
| M8's MAC identity for routed traffic | capability, documented limitation | an identity milestone |
| no concurrency coverage | test gap (§18.2) | any milestone that introduces a threaded path |
| no tool-assisted check for unasserted behaviour | test tooling (§18.13) | a future testing milestone |
| the coverage percentage | deliberately not measured (§18.1) | if a percentage is ever needed, run a tool and document its limits as M18.1 asks |
| one performance environment | measurement (§18.12) | only if the project is deployed somewhere |

### 20.4 Status

**Status: implemented and verified.**

Verified means: the suites were run during M18, on the environment in §12.2, and
their results are recorded in §17.1 with no failures and no unexplained skips. The
two end-to-end modes pass. The performance harness runs and records a baseline. The
gates are one command.

It does not mean: the application is fully covered (§18.1), the application is
production-ready (§18.10), or that nothing remains open (§20.3). M18 verified what it
was asked to verify and it reports the rest as limitations rather than as silence.
