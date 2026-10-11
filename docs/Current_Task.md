# NetWatch AI — M17 Reports

**Milestone:** M17 — Report Generation
**Scope:** implement and verify report generation over the real data produced by M4–M16.
**Status:** implemented and verified
**Supersedes:** the M16 task document that previously occupied this file. M16's own
record lives in `docs/20_M16_Analytics_Design.md` and in `docs/TODO.md`.

---

# 1. Purpose

M13 exposed `GET /api/v1/reports` and `GET /api/v1/reports/{id}`, and M15 put a
Reports page in front of them. Those routes could only ever *list* stored metadata:
nothing in the application produced a report, and no route produced a document.

M17 makes the reporting layer real. It resolves a reporting period, reads the M16
analytics views over it, assembles one renderer-agnostic content model, renders it
to CSV or PDF, writes the artifact to disk, records the outcome, and serves the file
back.

M17 is a consumer and a formatter. It must not introduce a second statistics
engine, a second device identity, a second risk score, a new metric, or any
detection logic.

---

# 2. M17 Goal

Build a read-oriented reporting layer that produces:

1. A bounded reporting period
2. A validated report request
3. One renderer-agnostic content model
4. A CSV artifact
5. A PDF artifact
6. A stored, truthful report record
7. Four working HTTP routes

The results must come from real backend data.

No mock data, random values or simulated content may be introduced.

---

# 3. Architecture Position

```text
Packet Capture
      ↓
Packet Processing
      ↓
Traffic Statistics
      ↓
Packet Persistence
      ↓
Devices / Connections
      ↓
Detections
      ↓
Alerts
      ↓
Correlation + Risk
      ↓
────────────────────────
      Analytics (M16)
────────────────────────
      ↓
────────────────────────
      Reports (M17)
────────────────────────
      ↓
M13 REST API
      ↓
M15 Frontend
```

M17 is a consumer of the M16 analytics layer.

It does not replace:

* M6 Traffic Statistics
* M8 Device Discovery
* M9 Connection Tracking
* M10 Detection
* M11 Alert Engine
* M12 Correlation and Risk Scoring
* M16 Analytics

---

# 4. Scope

## M17.1 — Reporting Architecture

Inspect the existing implementation and identify:

* the analytics service and its views
* the existing reports router, service and repository
* the `reports` table and the existing models
* the M2 migration/upgrade path
* the existing Pydantic schemas
* the M15 frontend's expectations

Determine whether the current reporting implementation is complete, partial or
placeholder-based.

Implement one reporting package under `backend/app/reports/` that owns the period,
the request, the content model, the renderers, the storage and the lifecycle.

Reuse existing services and models wherever possible. Do not create duplicate
representations of packets, devices, connections, alerts or incidents, and do not
re-implement an analytics aggregation.

---

# 5. Reporting Periods

Define one period model, used by every generation.

* Convention: `[since, until)` — `since` inclusive, `until` exclusive (M13.26)
* Encoding: ISO-8601 UTC with an explicit offset
* Presets: `daily` is the previous **completed** UTC day; `weekly` is the previous
  completed ISO-8601 Monday-to-Sunday week
* Custom: both bounds required; an inverted, empty or over-long range is refused
* Ceiling: the M16 analytics window ceiling, reused rather than re-declared
* Every period has a name, and the name is what the default title is built from

There must be no path that reports over all of history.

Time-series results inside a report must be bounded, and the bucket rules are
M16's own.

---

# 6. Report Content Model

Define one renderer-agnostic description of what a report says:

* `Metric` — a labelled scalar whose value is already rendered text
* `ReportTable` — declared column names and string rows, with an optional notice
* `ReportSection` — one subject with its metrics, tables and an explicit
  `available` flag
* `ReportContent` — identity, period, summary metrics and body sections

Five body sections, each drawn from an M16 view: traffic, protocols, devices,
connections, threats.

The summary is built from named headline figures lifted out of those sections, so
it cannot disagree with the body it summarises.

Nothing in the content model scores, weights or judges anything.

---

# 7. CSV Generation

Render the content model to a UTF-8, block-structured document written with the
standard `csv` module:

* one marker line per block (`report`, `section:<key>`, `table:<key>`)
* column names taken from the content model, so they cannot disagree with the PDF
* an empty table writes its notice instead of rows
* an unavailable section writes its sentence instead of metrics and tables

---

# 8. PDF Generation

Render the same content model to a paginated PDF with `reportlab`, declared in
`backend/requirements.txt`:

* title, then period, then summary metrics, then one block per section
* table header rows from the content model's declared columns
* text wrapped to the page width so nothing overflows the page
* an empty report states once that the period holds no stored data

The renderer is pure: content in, bytes out. It touches no session, no filesystem
and no clock.
---

# 9. Artifact Storage

One directory, configurable through `settings.report_storage_dir`.

* created on first write, never at import
* one collision-safe naming rule, keyed on the report's own id, so a second
  generation can never overwrite a first one's file
* atomic writes: a temporary file in the same directory, an `fsync`, then
  `os.replace`
* reads confined to the directory on **every** request, so a stored path can never
  make the process open an arbitrary file
* failures reported as a sentence, never as a path

---

# 10. Generation Lifecycle

One metadata row per generation, moving through three states:

| State | Means |
| --- | --- |
| `generating` | the row exists and the artifact is being produced |
| `completed` | the artifact was written and its size recorded |
| `failed` | generation was attempted and did not finish; `error` carries a safe sentence and any partial file was removed |

The row is written **before** the file, so an interrupted generation leaves a row
that truthfully says the file does not exist rather than leaving no trace.

`downloadable` is asked of the storage directory per row rather than inferred from
a status, because a file can be removed by hand while the row still says
`completed`.

The schema change is additive: five columns on `reports` (`period_start`,
`period_end`, `status`, `file_size`, `error`), no column dropped, renamed or
retyped and no row rewritten.

The row limit is `max(1, min(settings.report_max_table_rows, REPORT_ROW_LIMIT))`,
where `REPORT_ROW_LIMIT` is the analytics layer's own group cap, reused rather than
re-declared.

---

# 11. API Requirements

Verify and implement:

```text
GET  /api/v1/reports                stored metadata, newest first
GET  /api/v1/reports/{id}           one report's metadata
POST /api/v1/reports/generate       produce a report and record it
GET  /api/v1/reports/{id}/download  serve the artifact itself
```

The three JSON routes must follow the existing M13 response envelope. The download
route serves bytes as an attachment with the format's own media type.

They must provide:

* validation
* sensible defaults
* explicit maximum limits
* correct empty responses
* consistent error handling
* stable response schemas
* bounded results

Do not expose stack traces, filesystem paths or internal implementation details.

Do not break the TypeScript models already used by M15.

---

# 12. Empty and Unavailable Data

Maintain the project's existing distinction:

```text
0           = known value is zero
empty       = valid query with no records
unknown     = value was not reported
unavailable = backend section could not be read
```

An unavailable section carries no metrics and no tables. An empty section carries
its notice. An unmeasured value is never written as `0`, and a share of a zero total
is `n/a` rather than `0.00%`.

---

# 13. Performance Requirements

Reports must remain suitable for the current local SQLite architecture.

Avoid:

* loading the packet table into Python
* unbounded queries or unbounded periods
* N+1 queries across sections
* re-rendering an artifact to measure it
* a second aggregation of anything the analytics layer already computes

Prefer M16's SQL-side aggregation, and add a database index only when a measured
reporting query pattern justifies one.

Performance measurements must be local development measurements only.

Do not make production-scale claims.

---

# 14. Testing

Add tests for each reporting area.

### Periods

Test presets, the boundary between two consecutive periods, inverted, empty and
over-long custom ranges, and preset-with-bounds refusals.

### Requests

Test format and type normalisation, blank values, unknown values and malformed
timestamps.

### Content

Test the five sections, availability, the summary's headline figures and the
rendering of unknown values.

### CSV

Test the block structure, the marker lines, quoting, notices and empty tables.

### PDF

Test a real document is produced, that it parses, that it carries the content's
columns and cells, and that notices appear in place of empty tables.

### Storage

Test the naming rule, collision safety, atomicity, the containment refusals and the
failure sentences.

### Lifecycle

Test the three states, a failure leaving a truthful row, and `downloadable`
disagreeing with `completed`.

### API

Test defaults, validation, maximum limits, response schemas, empty results, the
`404` paths, the download media type and error handling.

All existing M0–M16 tests must continue to pass.

---

# 15. Type and Contract Verification

Compare the actual running API responses with the schemas already consumed by M15.

Do not assume that existing documentation and implementation are identical.

Three additions were required and are recorded in the TypeScript types: `status`,
`file_size` with the `period_*` pair, and `downloadable`. No existing field changed
name or type, so the M15 build continued to compile unchanged.

Do not use `any` for backend-derived TypeScript data.

---

# 16. Documentation

Create:

```text
docs/21_M17_Reports_Design.md
```

The document contains:

1. Purpose
2. Scope
3. Non-goals
4. Architecture position
5. Data sources
6. Reporting architecture
7. Reporting periods
8. Report content model
9. CSV rendering
10. PDF rendering
11. Storage and artifacts
12. Generation lifecycle
13. API contracts
14. Validation and error handling
15. Performance considerations
16. Testing and verification
17. Known limitations
18. Completion checklist
19. M17 closure

Keep the documentation focused only on M17.

Do not document future ML/AI work as implemented.

---

# 17. M17 Non-Goals

The following are explicitly outside M17:

* ML anomaly detection
* behavioral baselines
* AI explanations
* local LLM / Ollama
* automatic blocking
* IPS functionality
* SIEM integrations
* threat-intelligence integrations
* authentication / RBAC
* notification delivery
* scheduled or recurring reports
* distributed sensors

These belong to later milestones.

---

# 18. Verification

Run:

```text
Backend test suite
Reporting-specific tests
API tests
Pyright/type checking
M15 frontend unit tests
M15 live integration tests against the real backend
Frontend production build
Reporting performance measurements
```

Verify the four report routes against the actual running backend, using real
persisted data.

No mock data may be used to claim successful integration.

---

# 19. Completion Criteria

M17 is complete only when:

* [x] Reporting architecture is implemented
* [x] CSV generation works
* [x] PDF generation works
* [x] Daily reports work
* [x] Weekly reports work
* [x] Custom reports work
* [x] Report history works
* [x] Report download works
* [x] Period filtering is correct and half-open
* [x] Aggregation is bounded
* [x] API validation works
* [x] Empty/unavailable states are handled correctly
* [x] Existing M13 API conventions are preserved
* [x] M15 frontend remains compatible
* [x] Errors expose nothing internal
* [x] Reporting tests pass
* [x] Full regression suite passes
* [x] Pyright/type checking passes
* [x] Performance baseline is recorded
* [x] Manual verification with real data succeeds
* [x] `docs/21_M17_Reports_Design.md` is complete

**Status: implemented and verified.**

---

# 20. Final Implementation Report

**Files created**

```text
backend/app/reports/__init__.py
backend/app/reports/period.py
backend/app/reports/requests.py
backend/app/reports/content.py
backend/app/reports/assembler.py
backend/app/reports/csv_renderer.py
backend/app/reports/pdf_renderer.py
backend/app/reports/renderers.py
backend/app/reports/storage.py
backend/app/reports/errors.py
backend/app/reports/status.py
backend/app/reports/service.py
backend/app/schemas/report.py
backend/tests/reports_fakes.py
backend/tests/test_reports_period.py
backend/tests/test_reports_request.py
backend/tests/test_reports_content.py
backend/tests/test_reports_csv_renderer.py
backend/tests/test_reports_pdf_renderer.py
backend/tests/test_reports_assembler.py
backend/tests/test_reports_storage.py
backend/tests/test_reports_service.py
backend/tests/test_reports_api.py
backend/scripts/verify_m17.py
backend/scripts/benchmark_m17.py
frontend/src/components/reports/reportDisplay.ts
frontend/src/components/reports/ReportStatusBadge.tsx
frontend/src/components/reports/GenerationForm.tsx
frontend/src/components/reports/GenerationOutcome.tsx
frontend/src/components/reports/ReportRow.tsx
frontend/src/components/reports/ReportDetailPanel.tsx
docs/21_M17_Reports_Design.md
```

**Files modified**

```text
backend/app/api/v1/reports.py        the four routes (was list/detail only)
backend/app/api/v1/deps.py           the reporting service and storage providers
backend/app/repositories/report.py   period, status and size columns
backend/app/models/report.py         the five additive columns
backend/app/database/upgrade.py      the additive migration
backend/app/database/init_db.py      the same columns for a fresh database
backend/app/config/settings.py       report_storage_dir, report_max_table_rows
backend/requirements.txt             reportlab
backend/tests/test_api_contract.py   the report contract tests
frontend/src/types/system.ts         the report view's added fields
frontend/src/types/index.ts          the re-exports
frontend/src/services/reports.ts     generate and download
frontend/src/services/endpoints.ts   the report routes
frontend/src/services/client.ts      the download helper
frontend/src/services/index.ts       the re-exports
frontend/src/services/client.test.ts the report client tests
frontend/src/hooks/useReports.ts     generation and refresh
frontend/src/pages/Reports.tsx       the page over the new components
frontend/src/pages/Reports.test.tsx  the page tests
frontend/tests/live/rest.test.ts     six live report tests
docs/TODO.md                         the M17 completion record
docs/Current_Task.md                 this document
```

**Analytics architecture implemented** — one reporting package that owns the
period, the request, the content model, the two renderers, the storage and the
lifecycle, and reads nothing but the M16 analytics service.

**The four routes and their outputs**

| Route | Output |
| --- | --- |
| `GET /api/v1/reports` | `ReportListData` in the M13 envelope: `count`, `total`, `limit`, `offset`, `has_more`, `reports` |
| `GET /api/v1/reports/{id}` | one `ReportView`, or `404 REPORT_NOT_FOUND` |
| `POST /api/v1/reports/generate` | `201` with `GeneratedReportData` — the stored `ReportView` plus the summary the artifact opens with |
| `GET /api/v1/reports/{id}/download` | the bytes, as an attachment with `text/csv; charset=utf-8` or `application/pdf`, or `404 REPORT_NOT_FOUND` |

**Important design decisions** — one period model shared by every generation; one
content model behind two renderers; the period ceiling imported from M16 rather
than re-declared; refusal rather than adjustment; the metadata row written before
the artifact; the file name derived from the row's id; a report's every figure
taken from `AnalyticsService` so it cannot disagree with the dashboard.

**Tests added** — 257 reporting tests across nine files, plus a shared fake set.

**Total test result** — backend `2322 passed`; reporting subset `257 passed`;
frontend unit suite `448 passed` (15 files); frontend live-backend suite
`67 passed` (3 files) against the real application.

**Type-check result** — pyright `0 errors, 0 warnings, 0 informations`;
`tsc --noEmit` clean; production build clean (2 554 modules, `907.84 kB` JS /
`241.03 kB` gzip, built in 3.62 s).

**Performance measurements** — `benchmark_m17.py`, local, in-process client,
10 000 packets / 100 conversations / 20 alerts over 168 h, row limit 100: CSV
generation `104.43 ms p50`, PDF generation `657.25 ms p50`; assembly `74.58 ms`,
CSV encode `0.69 ms`, artifact write `2.98 ms`. Not a production-capacity claim.

**Known limitations** — generation is synchronous and the caller waits for the
file; nothing prunes the artifact directory; a report is a snapshot of the store at
generation time; and every M16 limitation behind its figures is inherited
unchanged. §17 of the design document states all of them.

**M17 is ready to close.**

Nothing in this document claims anything that was not implemented and verified.
