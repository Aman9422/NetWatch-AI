# NetWatch AI — M19 Stabilization

**Milestone:** M19 — Stabilization  
**Scope:** stabilize the existing M0–M18 application, investigate outstanding defects, and prepare a reliable local installation for M20.  
**Status:** not started

---

# 1. Purpose

NetWatch AI has implemented its core packet-processing pipeline, detection and alerting, correlation and risk scoring, REST APIs, WebSockets, frontend, analytics, report generation, and project-wide testing.

M18 audited and verified these capabilities. It also identified outstanding operational concerns, including:

- frontend bundle size above Vite's advisory threshold
- routed-network device identity limitations inherited from M8
- no authentication, authorization, or TLS
- no dedicated concurrency coverage
- report artifacts that are not automatically pruned
- performance measurements from only one development environment

M19 must examine the running application as a whole, resolve critical and high-priority defects, verify resource management, improve operational reliability, and document any limitations that remain.

M19 is a **stabilization milestone, not a feature-development milestone**.

Do not rewrite working modules, introduce new detection logic, or add advanced AI/ML functionality merely to make the project appear more complete.

---

# 2. M19 Goals

M19 must deliver:

1. A fresh baseline from the M18 quality gates
2. A prioritized defect and risk register
3. Reliable startup and shutdown behavior
4. Reviewed application logs and error handling
5. Memory and database-growth assessments
6. WebSocket and packet-processing stability checks
7. Safe report-artifact and temporary-file handling
8. Deployment-instruction verification
9. A clean-installation verification
10. Repository and Git hygiene checks
11. Repeatable stabilization verification
12. A documented list of release blockers for M20

Every change must address an observed defect, a verified operational risk, or a stated stabilization requirement.

---

# 3. Architecture and Scope Boundaries

M19 stabilizes the existing architecture:

```text
Network
   ↓
Packet Capture
   ↓
Packet Processing
   ↓
Statistics + Persistence
   ↓
Devices + Connections
   ↓
Detection + Alerts
   ↓
Correlation + Risk
   ↓
REST API + WebSockets
   ↓
Analytics + Reporting
   ↓
React/TypeScript Frontend
```

Preserve the existing ownership boundaries.

M19 must not create a second packet processor, statistics engine, device registry, detection engine, risk-scoring system, analytics engine, or reporting system.

Use the existing M18 test and verification infrastructure wherever possible.

---

# 4. M19.1 — Establish the Stabilization Baseline

Start by auditing the actual checkout.

Inspect:

- `docs/TODO.md`
- `docs/Current_Task.md`
- milestone design documents from M0–M18
- `backend/tests/`
- `backend/scripts/`
- frontend test and build configurations
- backend settings and environment files
- SQLite initialization, migrations, and retention
- report storage configuration
- `.gitignore`
- README and installation instructions

Run the existing quality gates:

```powershell
python backend/scripts/run_quality_gates.py
```

Inspect the script's supported options and run its full verification mode as documented.

Also run the relevant frontend checks:

```powershell
cd frontend
npm test
npm run test:live
npm run typecheck
npm run build
```

Run live tests with the backend running and correctly configured.

Record actual results, including:

- pass/fail counts
- skipped tests
- warnings
- backend type-check results
- frontend type-check results
- frontend build output
- end-to-end verification results

Do not assume M18's recorded numbers still represent the current checkout.

Do not modify code merely to make a warning disappear. Establish which issues are genuine defects and which are documented limitations.

---

# 5. M19.2 — Defect and Risk Register

Create a prioritized list of stabilization findings.

Use this classification:

| Priority | Meaning |
|---|---|
| Critical | Data loss, severe security exposure, or failure that makes the application unusable |
| High | Major functionality is broken, persistent corruption is possible, or recovery is unreliable |
| Medium | A significant limitation or defect with a usable workaround |
| Low | Minor usability, documentation, or maintenance issue |

For every finding, record:

- description
- affected milestone/component
- reproducible steps
- evidence or test result
- impact
- priority
- proposed correction
- regression test
- final status

Fix reproducible critical and high-priority defects within M19.

Fix medium-priority issues where they can be resolved safely without an architectural redesign. Otherwise, document the limitation and its impact on the M20 release.

Do not invent defects simply to create more changes.

---

# 6. M19.3 — Logging and Error Handling

Review logs across the backend and frontend integration.

Verify that:

- failures contain useful diagnostic context
- log levels distinguish routine operations from warnings and errors
- exceptions are logged without silently losing failures
- user-facing errors remain safe and understandable
- API responses do not expose stack traces, SQL statements, secrets, or internal filesystem paths
- sensitive packet payloads and credentials are not unnecessarily logged
- repeated failures do not produce uncontrolled log growth
- application startup and shutdown messages are meaningful
- failed capture, database, report, and WebSocket operations are observable

Reuse the existing configuration and logging conventions.

Avoid a broad logging rewrite.

Add tests for any corrected behavior, especially where a failure could previously appear as a successful operation or a misleading zero.

---

# 7. M19.4 — Memory and Resource Stability

Review the bounded-state guarantees implemented by M4–M14 and audited by M18.

Check:

- packet-processing buffers
- persistence queues
- statistics windows
- device registry limits
- connection tracking limits
- detector history
- alert history
- incident registry
- WebSocket client queues
- frontend packet and alert lists
- WebSocket event-deduplication state
- open database sessions
- file handles and sockets
- background workers and shutdown hooks

Use the existing bounded, repeatable traffic input from `benchmark_m18.py` where appropriate.

Measure multiple repetitions with the same bounded dataset.

Compare memory growth across repetitions instead of reporting only an average that may hide initialization costs.

Use `tracemalloc` for Python allocations and a suitable process-level measurement when available. State clearly what each measurement includes and excludes.

Verify that:

- bounded collections remain within their configured limits
- clients disconnecting do not leave permanent subscriptions
- shutdown releases worker threads and sockets
- repeated capture start/stop cycles do not create unbounded state
- failed requests do not leak database sessions
- memory growth does not continue proportionally with every repeated bounded workload without explanation

Do not claim that a flat `tracemalloc` result proves all native or operating-system memory is leak-free.

Do not establish arbitrary timing or memory thresholds that fail on unrelated machines.

---

# 8. M19.5 — Database Growth and Persistence Stability

Review the growth behavior of the SQLite database.

Audit:

- packet persistence rate
- packet retention settings
- cleanup scheduling or invocation
- connection-history growth
- alert growth
- report metadata growth
- SQLite indexes
- transaction boundaries
- recovery after database errors
- behavior when the database file is locked
- behavior when storage is unavailable or full

Verify that packet retention uses the configured retention policy and that cleanup does not delete data outside the intended scope.

Measure database file size over a repeatable workload.

Where practical, inspect table row counts and index sizes before and after cleanup.

Review report-artifact growth. M18 documents that generated report files are not automatically pruned.

If this creates a meaningful operational risk, design and implement the smallest safe, configurable retention policy that fits the existing architecture. Do not silently delete user reports or change retention behavior without documenting it and testing it.

Verify that cleanup operations:

- are bounded
- handle failures honestly
- do not interrupt unrelated capture and analysis work
- leave metadata and files in a consistent state
- preserve existing database records outside the cleanup scope

Do not run destructive cleanup tests against the developer's real database.

---

# 9. M19.6 — Packet-Processing Stability

Use the existing M18 benchmark and end-to-end verification harnesses.

Verify the real pipeline:

```text
Normalized Packet
       ↓
Statistics
       ↓
Persistence
       ↓
Device Discovery
       ↓
Connection Tracking
       ↓
Detection
       ↓
Alerting
       ↓
Correlation
```

Review:

- processing exceptions
- malformed packet handling
- duplicate packet counting
- persistence queue saturation
- worker shutdown
- concurrent capture lifecycle operations
- shared-state locking
- detector failures
- alert persistence failures
- correlation failures

Add targeted concurrency or lifecycle tests where M18 identified missing coverage, particularly for shared state and threaded paths.

Do not add a complete concurrency-testing framework or a new application feature.

Run repeatable benchmarks and compare them with M18's local baseline.

Investigate a significant regression before deciding whether to fix it. Account for machine load, Python version, dataset differences, and measurement noise.

Do not present a benchmark from one development machine as a production-capacity claim.

---

# 10. M19.7 — WebSocket Stability

Verify all four existing channels:

```text
/ws/dashboard
/ws/packets
/ws/alerts
/ws/system
```

Review:

- subscriber lifecycle
- channel shutdown
- ping/pong handling
- heartbeat timeout
- reconnect behavior
- event deduplication
- bounded queues
- packet rate limiting
- slow clients
- client disconnects
- publishing failures
- cleanup during application shutdown

Verify that a WebSocket failure cannot block packet processing or cause unrelated services to fail.

Test repeated connect/disconnect cycles and concurrent subscribers where practical.

Confirm that the frontend refreshes its REST resource after reconnect and does not assume that events lost during disconnection will be replayed.

Keep the current event envelope and channel contracts backward-compatible.

Do not add new channels or event types unless a genuine correctness defect requires a narrowly scoped change.

---

# 11. M19.8 — Frontend Stability and Build Health

Audit the existing React/TypeScript frontend.

Review:

- console errors and warnings
- unhandled promise rejections
- loading and retry states
- WebSocket cleanup
- repeated subscriptions
- stale state after navigation
- bounded client lists
- report-generation failures
- file downloads
- API error messages
- TypeScript errors
- production build warnings

The M15 and M17 records identify a JavaScript bundle larger than Vite's 500 kB advisory threshold.

Determine whether code splitting would be a low-risk stabilization improvement. If so, implement it without changing application behavior; otherwise, record it as a non-blocking performance limitation.

Verify that:

- `npm test` passes
- `npm run test:live` passes against the running backend
- `npm run typecheck` passes
- `npm run build` succeeds
- the existing visual design is preserved
- no mock data or simulated network activity has been reintroduced

Do not redesign the frontend during M19.

---

# 12. M19.9 — Report and Artifact Stability

Audit M17 report generation and storage.

Test:

- repeated CSV generation
- repeated PDF generation
- large but permitted report content
- a report row taller than a page
- invalid report requests
- unavailable analytics sections
- missing stored artifacts
- failed writes and renames
- cleanup failures
- download failures
- report metadata consistency

Confirm that:

- generated files are written atomically
- stored paths remain confined to the configured report directory
- partial files are cleaned up safely
- failed generation does not leave a misleading completed record
- PDF content fits within the page layout
- CSV formula-injection protection still works
- downloads serve the actual generated file
- report generation failures are visible to the operator

Retain the existing metadata and file lifecycle contract.

Do not add scheduled reports or notification delivery in M19.

---

# 13. M19.10 — Configuration and Startup Reliability

Review configuration handling for local installation.

Inspect:

- backend settings
- `.env.example`
- frontend environment defaults
- database path configuration
- report storage configuration
- capture-interface selection
- logging configuration
- CORS origins
- host and port defaults
- dependency versions

Verify that:

- missing optional settings receive safe defaults
- invalid settings fail clearly
- local-only deployment defaults remain intact
- configuration changes take effect according to the documented restart behavior
- credentials and secrets are not committed
- frontend configuration does not contain backend secrets
- startup failures do not leave partially initialized services running

Preserve the existing configuration conventions.

Do not introduce new mandatory external services.

---

# 14. M19.11 — Deployment Instructions

Review and test the documented local startup procedure.

The application should be runnable using the existing Python backend and Node-based frontend tooling.

Verify the instructions against the current project structure instead of assuming older commands still work.

Document:

- supported Python version
- supported Node.js/npm environment
- backend virtual environment setup
- dependency installation
- environment configuration
- database initialization and upgrades
- backend startup
- frontend startup
- expected local ports
- packet-capture permission requirements
- test commands
- report storage behavior
- common troubleshooting steps

Keep the instructions appropriate for the project's intended local development deployment.

Do not claim that production deployment or public network exposure is supported.

---

# 15. M19.12 — Clean Installation Verification

Verify a clean installation independently of the developer's existing environment.

Use a disposable copy or a clean checkout so that existing virtual environments, build artifacts, caches, and databases cannot conceal missing dependencies.

Follow the documented setup steps.

Verify that:

1. Python dependencies install correctly.
2. The backend imports and starts.
3. SQLite initializes or upgrades correctly.
4. The API health endpoint responds.
5. The frontend dependencies install from the documented lockfile.
6. The frontend starts and builds.
7. The dashboard handles empty data correctly.
8. A controlled packet-processing test works.
9. Analytics endpoints respond.
10. CSV/PDF report generation and downloads work.
11. Tests and type checks can be executed from the documented commands.

Use the repository's established package manager. Investigate the existing lockfiles and document one canonical installation procedure rather than arbitrarily deleting lockfiles.

Do not use the developer's production-like or working database for the test.

Record every failed setup step and its resolution.

---

# 16. M19.13 — Repository and Git Hygiene

Review the repository after the previous large-database push failure has been resolved.

Verify that:

- `backend/netwatch.db` is not tracked
- local SQLite databases and backups are ignored
- `.env` files are ignored while `.env.example` remains tracked
- `node_modules`, build output, caches and temporary artifacts are ignored
- generated reports are not unintentionally committed
- local benchmark baselines remain ignored when intended
- no credentials or sensitive data are present in tracked files
- the working tree is understood before final commits
- the GitHub remote points to the intended repository

Use commands such as:

```powershell
git status -sb
git remote -v
git ls-files backend/netwatch.db
git check-ignore -v backend/netwatch.db
git ls-files
```

Inspect tracked files for oversized artifacts and investigate any file that should not be in source control.

Do not rerun `git filter-repo`, delete Git objects, or force-push during routine stabilization. Such operations require a specific, verified need and a safe backup plan.

Preserve uncommitted project work.

The final repository should contain source, tests, documentation, configuration examples, and intentional assets—not local runtime databases or generated build output.

---

# 17. M19.14 — Known Limitations and Release Risks

Review the limitations carried forward from M18 and previous milestones.

### Device identity

M8's MAC-first identity can associate multiple remote IP addresses with a routed next-hop device. Do not silently change the identity system in M19.

Document the observable behavior and whether it prevents a specific M20 acceptance criterion.

### Authentication and transport security

Authentication, authorization/RBAC, and TLS are not implemented.

Verify that the local application remains bound to its documented local interface by default. Do not advertise the service as suitable for public exposure or untrusted multi-user deployments.

### Concurrency

M18 did not include broad concurrency testing.

Add targeted tests only for relevant existing shared-state and threaded paths. State clearly what remains unverified.

### Reports and database growth

Review the consequences of keeping packet data and report artifacts over time. Document any remaining cleanup limitations.

### Frontend bundle size

Decide whether the bundle warning is safely addressable in M19 or should remain a documented non-blocking limitation.

For each remaining issue, record:

- impact
- workaround, if any
- whether it blocks the M20 release
- recommended future milestone

Do not claim a limitation is resolved merely because it has been documented.

---

# 18. M19 Non-Goals

The following remain outside M19:

- ML anomaly detection
- behavioral baselines
- AI explanations
- local LLM/Ollama
- new detection rules
- new risk-scoring models
- automatic blocking or IPS
- SIEM integrations
- threat-intelligence integrations
- distributed sensors
- PostgreSQL migration
- Docker adoption
- new frontend product features
- broad architectural refactoring

Authentication/RBAC or TLS may require a separate security milestone if the intended deployment changes. Do not implement them as an unplanned side effect of stabilization.

M19 should improve the reliability of existing functionality while keeping the project understandable and maintainable.

---

# 19. M19.15 — Repeatable Stabilization Verification

Reuse the existing scripts and tests.

Run the appropriate quality gates:

```powershell
python backend/scripts/run_quality_gates.py
```

Inspect the actual options before executing the full live suite.

From the frontend directory, run:

```powershell
npm test
npm run test:live
npm run typecheck
npm run build
```

Also execute the appropriate checks for:

- clean database initialization
- database migration
- report artifact integrity
- repeated capture start/stop
- repeated WebSocket connect/disconnect
- bounded resource use
- the M18 end-to-end flow
- local installation and troubleshooting instructions

Run the existing benchmarks where needed rather than inventing new numbers from unrelated test conditions.

After fixes, rerun the tests that cover the changed behavior and the relevant regression gates.

A final full verification must be run against the final stabilized code.

Record:

- commands
- environment
- results
- test counts
- warnings
- remaining failures
- skipped checks
- measured deviations from available baselines

Do not mark an unexecuted command as passed.

---

# 20. Documentation

Create:

`docs/23_M19_Stabilization_Design.md`

Follow the numbered, detailed format used by the M16–M18 design documents.

Include:

1. Purpose
2. Scope
3. Non-goals
4. Initial baseline
5. Defect and risk register
6. Logging and error handling
7. Memory and resource stability
8. Database and artifact growth
9. Packet-processing stability
10. WebSocket stability
11. Frontend stability
12. Configuration and startup
13. Deployment instructions
14. Clean-installation verification
15. Git and repository hygiene
16. Performance comparison
17. Known limitations
18. Release blockers
19. Testing and verification
20. Completion checklist
21. M19 closure

Update only M19's section of `docs/TODO.md`.

Update `docs/Current_Task.md` only if that is the repository's current-task convention, preserving the separate historical milestone records.

Keep the status as:

**Status: design / in progress**

until implementation and verification are actually complete.

Only then change it to:

**Status: implemented and verified**

---

# 21. Completion Criteria

M19 is complete only when:

- [ ] Existing quality gates have been rerun
- [ ] A defect and risk register is documented
- [ ] Critical and high-priority defects are fixed or explicitly recorded as release blockers
- [ ] Logging and API error behavior have been reviewed
- [ ] Memory and bounded-state behavior have been assessed
- [ ] Database growth and retention have been reviewed
- [ ] Report storage growth and failure handling have been reviewed
- [ ] Packet-processing stability has been verified
- [ ] WebSocket lifecycle stability has been verified
- [ ] Frontend tests and build pass
- [ ] Startup and configuration have been reviewed
- [ ] Deployment instructions work on a clean setup
- [ ] Git and repository hygiene checks pass
- [ ] Performance results have been compared with existing baselines
- [ ] Known limitations and release blockers are documented
- [ ] Existing M0–M18 regression tests pass
- [ ] Pyright/type checking passes
- [ ] TypeScript checking passes
- [ ] Frontend production build succeeds
- [ ] Final end-to-end verification passes
- [ ] `docs/23_M19_Stabilization_Design.md` is complete
- [ ] The M19 section of `docs/TODO.md` is updated

---

# 22. Final Implementation Report

At completion, provide:

1. Initial baseline results
2. Defect and risk register summary
3. Files created
4. Files modified
5. Critical/high-priority fixes
6. Logging and error-handling results
7. Memory and database-growth findings
8. WebSocket and packet-processing stability results
9. Clean-installation result
10. Repository hygiene result
11. Performance comparisons
12. Backend test results
13. Frontend test and build results
14. End-to-end verification result
15. Remaining limitations
16. Explicit M20 release blockers
17. Whether M19 is ready to mark implemented and verified

Do not claim production readiness based solely on successful tests or local benchmarks.

**M19 is complete when the application is more stable, the remaining limitations are understood, and a clean installation can be verified from the documented instructions.**