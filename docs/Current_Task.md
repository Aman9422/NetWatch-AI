# NetWatch AI — M19 Stabilization

**Milestone:** M19 — Stabilization  
**Scope:** stabilize the existing M0–M18 application, resolve critical and high-priority defects, and prepare a reliable local installation for M20.  
**Status:** implemented and verified

> **Closure note (M19).** This milestone is closed. The authoritative record is
> `docs/23_M19_Stabilization_Design.md`; the summary and results are in the M19
> section of `docs/TODO.md`. Ten findings were registered (D1–D10): eight fixed,
> two documented by design. The two High defects were the gate runner crashing on
> its own report under a `cp1252` console (D1) and three pyright errors from
> protocol members with docstring-only bodies (D2); the third High finding was the
> one-line README (D3). The frontend's 907.84 kB bundle became 249.49 kB with the
> chart library in a separate chunk loaded on demand, and a chunk-failure boundary
> was added because a lazy route can fail to arrive. Verified: **9/9 quality gates
> PASS**, 2615 backend tests, 465 frontend tests, 67 live tests, pyright 0/0/0,
> `tsc --noEmit` exit 0, both end-to-end modes PASS, and a server started from a
> freshly built virtual environment on a throwaway database. Five M20 release
> blockers are recorded in §19 of the design document.
>
> The requirement text below is preserved unchanged as the milestone's record;
> the completion criteria are satisfied and evidenced in the design document's
> §21 checklist.

---

# 1. Purpose

NetWatch AI has implemented its core network-monitoring and security-analysis platform.

M0–M18 delivered:

- Network interface management and packet capture
- Packet processing and traffic statistics
- Packet persistence
- Device discovery and connection tracking
- Detection and alert management
- Event correlation and risk scoring
- REST API and WebSockets
- React/TypeScript frontend
- Historical analytics
- CSV/PDF reporting
- Project-wide testing and verification

M18 verified the existing implementation and identified several limitations that need to be considered before release.

M19 focuses on stabilizing the application rather than adding new functionality.

The objective is to make the existing application reliable, resource-conscious, maintainable, and reproducible on a clean local installation.

M19 must not introduce unnecessary architectural changes or advanced AI/ML functionality.

---

# 2. M19 Goals

M19 must deliver:

1. A fresh baseline from the M18 quality gates
2. A prioritized defect and risk register
3. Reliable application startup and shutdown
4. Reviewed logging and error handling
5. Memory and resource stability assessment
6. Database growth and retention review
7. WebSocket reliability verification
8. Packet-processing stability verification
9. Report-storage reliability review
10. Configuration and startup verification
11. Deployment-instruction verification
12. Clean-installation verification
13. Git and repository hygiene
14. Final stabilization testing
15. A documented list of M20 release blockers

Every modification must address an observed defect, a verified operational risk, or a specific stabilization requirement.

---

# 3. Architecture Position

M19 stabilizes the existing architecture:

```text
Network
   ↓
Packet Capture
   ↓
Packet Processing
   ↓
Traffic Statistics + Persistence
   ↓
Device Discovery + Connection Tracking
   ↓
Detection + Alerts
   ↓
Correlation + Risk Scoring
   ↓
REST API + WebSockets
   ↓
Analytics + Reporting
   ↓
React/TypeScript Frontend
```

Preserve the architecture and responsibilities of previous milestones.

Do not:

- create another packet processor
- create a second statistics engine
- replace device discovery
- rewrite connection tracking
- introduce another detection engine
- introduce a second risk-scoring system
- duplicate analytics calculations
- duplicate reporting functionality

Reuse existing services, repositories, schemas, tests and verification scripts.

---

# 4. M19.1 — Establish the Stabilization Baseline

First inspect the actual repository.

Review:

- `docs/TODO.md`
- `docs/Current_Task.md`
- milestone design documents from M0–M18
- `backend/tests/`
- `backend/scripts/`
- frontend tests and configuration
- backend configuration and environment files
- database initialization and migration logic
- packet-retention configuration
- report-storage configuration
- `.gitignore`
- README and installation instructions

Run the existing quality gates:

```powershell
python backend/scripts/run_quality_gates.py
```

Inspect the script's supported options and execute the full verification mode as documented.

From the frontend directory, run:

```powershell
npm test
npm run test:live
npm run typecheck
npm run build
```

Run live tests with the backend running and correctly configured.

Record:

- backend test results
- frontend test results
- live integration results
- skipped tests
- warnings
- Pyright results
- TypeScript results
- frontend build results
- end-to-end verification results

Do not assume that M18's recorded test counts still represent the current checkout.

Do not modify code just to remove warnings without identifying their source.

---

# 5. M19.2 — Defect and Risk Register

Create a prioritized register of stabilization findings.

Use the following classification:

| Priority | Meaning |
|---|---|
| Critical | Data loss, severe security exposure, or application failure |
| High | Major functionality failure or unreliable recovery |
| Medium | Significant limitation with a usable workaround |
| Low | Minor usability, maintenance or documentation issue |

For each finding, record:

- description
- affected milestone/component
- reproducible steps
- evidence or test result
- impact
- priority
- proposed correction
- regression test
- final status

Fix critical and high-priority defects within M19.

Fix medium-priority defects where they can be addressed safely without major architectural changes.

Otherwise, document the limitation and decide whether it blocks M20.

Do not invent defects merely to create code changes.

---

# 6. M19.3 — Logging and Error Handling

Review logging and error handling across the backend.

Verify:

- appropriate log levels
- meaningful startup and shutdown messages
- useful diagnostic context
- capture failure reporting
- packet-processing error isolation
- database error handling
- persistence queue failure handling
- detector and alert failure handling
- correlation failure handling
- WebSocket failure reporting
- report-generation error handling
- cleanup after failures

Ensure that:

- stack traces are not exposed in API responses
- SQL statements and internal filesystem paths are not leaked
- credentials and secrets are not logged
- sensitive packet information is not unnecessarily logged
- repeated failures do not create uncontrolled log growth
- failures do not silently appear as successful operations or zero measurements

Reuse the existing logging configuration.

Do not perform a broad logging rewrite.

Add regression tests for any corrected behavior.

---

# 7. M19.4 — Memory and Resource Stability

Audit existing bounded-state behavior.

Review:

- packet-processing buffers
- persistence queues
- statistics windows
- device registry
- connection tracker
- detection history
- alert history
- incident registry
- WebSocket client queues
- event deduplication state
- frontend packet lists
- frontend alert lists
- database sessions
- open sockets
- file handles
- background workers

Reuse the bounded traffic dataset from:

```text
backend/scripts/benchmark_m18.py
```

Measure multiple repetitions using the same input.

Check whether memory growth settles after the initial working set is populated.

Use `tracemalloc` for Python-level allocations and a process-level memory measurement where available.

Clearly distinguish Python allocations from native and operating-system memory.

Verify that:

- bounded collections respect their configured limits
- disconnecting clients release subscriptions
- repeated capture start/stop cycles do not create unbounded state
- database sessions are released
- WebSocket connections are cleaned up
- worker threads stop correctly
- repeated bounded workloads do not show unexplained proportional memory growth

Do not claim that a flat `tracemalloc` result proves the entire process is leak-free.

Do not introduce arbitrary memory thresholds that fail on unrelated hardware.

---

# 8. M19.5 — Database Growth and Persistence Stability

Review SQLite growth and persistence behavior.

Audit:

- packet persistence throughput
- packet retention
- cleanup operations
- connection history
- alert history
- incident data
- report metadata
- database indexes
- transaction boundaries
- rollback behavior
- locked database handling
- disk-full behavior
- failed database writes

Verify that packet retention follows the existing configured policy.

Check that cleanup does not delete records outside its intended scope.

Measure database size and relevant table counts before and after controlled workloads and retention cleanup.

Review generated report artifact growth. M17 documents that generated report files are not automatically pruned.

Determine whether this creates a meaningful operational risk.

Where justified, implement the smallest safe and configurable artifact-retention policy compatible with the existing architecture.

Do not delete existing reports silently.

Verify that:

- cleanup operations are bounded
- database failures are reported honestly
- failed cleanup does not corrupt unrelated records
- temporary data is cleaned up safely
- database metadata and stored report files remain consistent
- the developer's real database is never modified by tests

Do not add unnecessary database tables or duplicate persistence systems.

---

# 9. M19.6 — Packet-Processing Stability

Review the M4–M12 packet-processing pipeline.

```text
NormalizedPacket
       ↓
Traffic Statistics
       ↓
Packet Persistence
       ↓
Device Discovery
       ↓
Connection Tracking
       ↓
Detection
       ↓
Alert Engine
       ↓
Correlation + Risk
```

Verify:

- malformed packet handling
- unsupported packet handling
- duplicate packet processing
- packet counter consistency
- persistence queue saturation
- worker shutdown
- repeated capture operations
- shared-state synchronization
- detector exceptions
- alert persistence failures
- correlation failures

Add targeted concurrency and lifecycle tests where an actual risk is identified.

Confirm that a failure in an optional downstream stage does not unnecessarily interrupt capture or unrelated stages.

Preserve the existing packet-processing contracts.

Use the M18 benchmark to compare performance.

Record throughput and per-packet overhead under comparable conditions.

Investigate significant regressions before modifying the code.

Do not make production-capacity claims based on the local benchmark.

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

- connection lifecycle
- subscriber registration
- unsubscription
- connection cleanup
- ping/pong
- heartbeat timeout
- reconnect behavior
- event deduplication
- bounded client queues
- drop-oldest behavior
- packet rate limiting
- slow clients
- publishing failures
- application shutdown

Verify that WebSocket failures cannot block packet processing or interrupt unrelated services.

Test repeated connect/disconnect cycles and multiple subscribers where practical.

Confirm that the frontend performs the documented REST refresh after reconnect.

Do not assume historical events are replayed after a disconnection.

Preserve the existing event schema and channel contracts.

Do not introduce additional channels or event types without a verified correctness requirement.

---

# 11. M19.8 — Frontend Stability and Build Health

Audit the existing React/TypeScript frontend.

Review:

- console errors and warnings
- unhandled promise rejections
- API error handling
- loading states
- empty states
- retry behavior
- WebSocket cleanup
- stale state after navigation
- duplicate subscriptions
- bounded client lists
- report-generation failures
- CSV/PDF download behavior
- TypeScript types
- production build

M18/M15 identified that the JavaScript production bundle exceeds Vite's 500 kB advisory threshold.

Investigate whether safe code splitting can improve the build.

If code splitting is low risk, implement it while preserving application behavior.

Otherwise, document the bundle size as a non-blocking limitation.

Verify:

```powershell
npm test
npm run test:live
npm run typecheck
npm run build
```

Ensure that:

- all tests pass
- no TypeScript errors remain
- live backend integration works
- no mock data has been reintroduced
- no fake network activity is generated
- the existing visual design is preserved

Do not redesign the frontend during M19.

---

# 12. M19.9 — Reporting and Artifact Stability

Review M17 reporting.

Test:

- repeated CSV generation
- repeated PDF generation
- maximum permitted report content
- long text values
- tall table rows
- unavailable analytics sections
- invalid report requests
- missing report files
- failed file writes
- failed atomic renames
- download failures
- metadata consistency
- storage-directory failures

Verify:

- atomic report writes
- safe filename generation
- artifact-directory confinement
- cleanup of partial artifacts
- honest generation status
- correct PDF layout
- CSV formula-injection protection
- safe downloads
- correct content types
- no internal filesystem paths exposed

Preserve the existing report lifecycle and API contract.

Do not introduce scheduled reporting or notification delivery in this milestone.

---

# 13. M19.10 — Configuration and Startup Reliability

Review:

- backend settings
- `.env.example`
- frontend environment variables
- database configuration
- report-storage configuration
- capture-interface configuration
- logging configuration
- CORS configuration
- host and port defaults
- Python dependencies
- Node dependencies

Verify:

- missing optional variables receive documented defaults
- invalid configuration fails clearly
- local deployment binds to its intended local interface
- frontend environment variables contain no backend secrets
- backend secrets are not committed
- settings are applied according to the documented restart behavior
- partial startup failures do not leave background workers running
- shutdown releases resources

Reuse existing settings conventions.

Do not add mandatory paid services or external accounts.

---

# 14. M19.11 — Deployment Instructions

Audit the README and installation instructions.

Verify them against the actual current repository.

Document:

1. Supported Python version
2. Node.js/npm requirements
3. Backend virtual environment creation
4. Backend dependency installation
5. Frontend dependency installation
6. Environment configuration
7. SQLite initialization and upgrades
8. Backend startup
9. Frontend startup
10. Expected local ports
11. Packet-capture permissions
12. Running tests
13. Running verification scripts
14. Report-storage location
15. Common installation and startup problems

Make the instructions suitable for a developer installing NetWatch AI on a fresh Windows machine.

Do not claim production deployment or public network exposure is supported.

---

# 15. M19.12 — Clean Installation Verification

Perform a clean installation using a disposable checkout or copy.

Do not rely on the developer's existing virtual environment, build files, cached dependencies or existing database.

Follow the documented installation instructions.

Verify:

- Python dependencies install
- backend imports correctly
- backend starts
- SQLite initializes or upgrades
- health endpoint responds
- frontend dependencies install from the chosen lockfile
- frontend starts
- frontend production build succeeds
- dashboard handles an empty database
- controlled packet-processing tests work
- analytics endpoints respond
- CSV/PDF report generation works
- report downloads work
- tests and type checking can run

Inspect the existing frontend lockfiles and choose one canonical documented package-manager workflow.

Do not arbitrarily delete lockfiles.

Record every failed setup step and its resolution.

Do not use the developer's working database for this verification.

---

# 16. M19.13 — Repository and Git Hygiene

Review the repository after the previous GitHub large-file issue.

Verify that:

- `backend/netwatch.db` is not tracked
- local databases and backups are ignored
- `.env` files are ignored
- `.env.example` remains tracked
- `node_modules` is ignored
- frontend build directories are ignored
- Python caches and virtual environments are ignored
- generated reports are excluded where appropriate
- temporary files are not committed
- local benchmark baselines are ignored where intended
- no secrets or credentials appear in tracked files
- the GitHub remote points to the intended repository

Run:

```powershell
git status -sb
git remote -v
git ls-files backend/netwatch.db
git check-ignore -v backend/netwatch.db
```

Inspect tracked files for oversized artifacts.

Preserve all uncommitted work.

Do not rerun `git filter-repo`, delete Git objects, or force-push as part of routine stabilization.

Those operations require a specific reason, verified backups, and an explicit recovery plan.

The final repository should contain source code, tests, documentation, configuration examples and intentional assets—not local databases or generated build output.

---

# 17. M19.14 — Review Known Limitations

Review the limitations carried forward from M18.

### 17.1 Routed device identity

M8's MAC-first identity can associate multiple remote IP addresses with the same next-hop device.

Do not silently change the identity system.

Document whether this limitation affects the M20 release criteria.

### 17.2 Authentication and transport security

Authentication, authorization/RBAC and TLS are not implemented.

Verify that the local application's documented binding and CORS restrictions remain correct.

Do not advertise public or untrusted multi-user deployment as supported.

Record the security limitations explicitly.

### 17.3 Concurrency

M18 did not provide broad concurrency coverage.

Add targeted tests for relevant existing shared-state and threaded paths.

Document what remains unverified.

### 17.4 Report artifact retention

Review disk growth caused by stored report artifacts.

Determine whether the current behavior is acceptable for the base local release.

### 17.5 Frontend bundle size

Record the current bundle size and determine whether safe code splitting resolves the Vite advisory.

### 17.6 Performance measurement limitations

M18 benchmarks use one development environment.

Preserve that limitation in every performance claim.

For each unresolved limitation, document:

- impact
- workaround
- severity
- whether it blocks M20
- recommended future work

Do not treat documentation as proof that an issue is fixed.

---

# 18. M19 Non-Goals

The following are outside M19:

- ML anomaly detection
- behavioral baseline learning
- AI explanations
- local LLM/Ollama
- new detection algorithms
- new risk-scoring models
- automatic blocking or IPS
- Wazuh integration
- SIEM integrations
- threat-intelligence integration
- distributed sensors
- PostgreSQL migration
- Docker adoption
- new frontend product features
- major architectural redesign

M19 is a stabilization milestone.

Do not add new AI features or external platforms during stabilization.

The AI development phase will follow the M20 base release.

---

# 19. M19.15 — Final Stabilization Verification

Reuse existing tests and verification scripts.

Run:

```powershell
python backend/scripts/run_quality_gates.py
```

Inspect the supported options before executing the full verification mode.

From the frontend directory:

```powershell
npm test
npm run test:live
npm run typecheck
npm run build
```

Also verify:

- database initialization
- database migrations
- packet-retention behavior
- repeated capture start/stop
- WebSocket reconnection and cleanup
- report artifact integrity
- failure and recovery behavior
- bounded resource usage
- clean installation
- M18 end-to-end verification

After changes, rerun tests covering the modified behavior.

Perform one final full verification against the final M19 code.

Record:

- exact commands
- environment
- test results
- failures
- warnings
- skipped checks
- performance comparisons
- unresolved limitations

Do not claim an unexecuted command passed.

---

# 20. Documentation

Create:

```text
docs/23_M19_Stabilization_Design.md
```

Follow the numbered, detailed format of the M16–M18 design documents.

Include:

1. Purpose
2. Scope
3. Non-goals
4. Initial baseline
5. Defect and risk register
6. Logging and error handling
7. Memory and resource stability
8. Database growth and retention
9. Packet-processing stability
10. WebSocket stability
11. Frontend stability
12. Report storage and artifact handling
13. Configuration and startup
14. Deployment instructions
15. Clean-installation verification
16. Git and repository hygiene
17. Performance comparisons
18. Known limitations
19. Release blockers
20. Testing and verification
21. Completion checklist
22. M19 closure

Update only M19's section of `docs/TODO.md`.

Update `docs/Current_Task.md` according to the existing project convention without overwriting previous milestone records.

Keep the status as:

**Status: design / in progress**

until all requirements have actually been completed and verified.

Only then change it to:

**Status: implemented and verified**

---

# 21. Completion Criteria

M19 is complete only when:

- [x] Existing quality gates have been rerun — 9/9 PASS (`--full`)
- [x] A defect and risk register is documented — D1–D10, §5.1
- [x] Critical defects are fixed or formally recorded as blockers — D8 verified
      fixed (the `lib/` anchoring); no other Critical found
- [x] High-priority defects are fixed or formally recorded as blockers — D1, D2,
      D3 all fixed, each with a test or a checked document
- [x] Logging and error handling are reviewed — §6
- [x] Memory and bounded-state behavior are assessed — §7
- [x] Database growth and retention are reviewed — §8
- [x] Report storage growth and failure handling are reviewed — §8.3, §12
- [x] Packet-processing stability is verified — §9
- [x] WebSocket lifecycle stability is verified — §10
- [x] Frontend tests pass — 465 unit, 67 live
- [x] Frontend build succeeds — 249.49 kB entry, no chunk over the advisory
- [x] Configuration and startup are reviewed — §13
- [x] Deployment instructions are verified — §14, two claims corrected
- [x] Clean-installation verification succeeds — §15, from an absent venv
- [x] Git and repository hygiene checks pass — §16
- [x] Performance is compared with existing baselines — §17; only the bundle is
      claimed as a change, because it is the only thing M19 changed
- [x] Known limitations are documented — §18.1–§18.9
- [x] M20 release blockers are identified — §19.1, five blockers
- [x] Existing M0–M18 regression tests pass — 2615 passed, 0 failed, 0 skipped
- [x] Pyright passes — 0 errors, 0 warnings, 0 informations
- [x] TypeScript checking passes — `tsc --noEmit` exit 0
- [x] Final end-to-end verification succeeds — `verify_m18.py` sample PASS, live PASS
- [x] `docs/23_M19_Stabilization_Design.md` is complete
- [x] The M19 section of `docs/TODO.md` is updated

---

# 22. Final Implementation Report

At completion, provide:

1. Initial baseline results
2. Defect and risk register summary
3. Files created
4. Files modified
5. Critical and high-priority fixes
6. Logging and error-handling results
7. Memory and database-growth findings
8. Packet-processing stability results
9. WebSocket stability results
10. Frontend stability results
11. Clean-installation results
12. Repository hygiene results
13. Performance comparisons
14. Backend test results
15. Frontend test and build results
16. End-to-end verification results
17. Remaining limitations
18. Explicit M20 release blockers
19. Whether M19 is ready to mark implemented and verified

Do not claim production readiness based solely on successful tests or local benchmarks.

**M19 is complete when NetWatch AI is stable, its operational limitations are understood, and a clean installation can be verified using the documented instructions.**
