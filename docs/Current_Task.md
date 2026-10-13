# NetWatch AI — M18 Testing

**Milestone:** M18 — Testing  
**Scope:** audit, strengthen, and verify the complete NetWatch AI test suite across M0–M17.  
**Status:** not started

---

# 1. Purpose

NetWatch AI has implemented the core monitoring pipeline, detection and alerting, correlation and risk scoring, REST APIs, WebSockets, frontend integration, analytics, and report generation.

Previous milestones already added extensive unit tests, integration tests, live API tests, performance benchmarks, and verification scripts.

M18 must assess whether the project is adequately tested as a complete application.

The objective is to:

- audit existing test coverage
- identify missing or weak tests
- add meaningful tests for uncovered behavior
- strengthen integration and end-to-end verification
- test failure handling and recovery
- assess performance regressions
- validate security boundaries
- establish repeatable project-wide verification commands

Do not rewrite working modules merely to increase test coverage.

Do not duplicate existing tests without adding meaningful new coverage.

---

# 2. Current Project Status

M0–M17 are implemented.

The existing project includes:

- Python backend using FastAPI
- SQLite persistence
- Scapy packet capture
- packet processing and traffic statistics
- device discovery and connection tracking
- detection rules and alerts
- event correlation and risk scoring
- REST API and WebSocket channels
- React/TypeScript frontend
- analytics
- CSV and PDF reporting

The M17 implementation record reports:

- 2,322 passing backend tests
- 257 reporting-specific tests
- 448 frontend unit tests
- 67 live frontend/backend integration tests
- Pyright with zero errors
- successful TypeScript type checking and production build

Treat these as existing recorded results, not as proof that the current checkout still passes.

**First rerun the actual test suites and establish a fresh baseline.** Counts and results must be taken from commands executed during M18.

---

# 3. M18 Goals

M18 must produce:

1. An inventory of existing tests
2. A milestone-by-milestone coverage audit
3. Additional tests for identified gaps
4. Reliable database and API test isolation
5. Cross-component integration tests
6. End-to-end verification
7. Performance regression checks
8. Defensive security tests
9. Reproducible quality-check commands
10. A completed testing design document

The application must continue to work without paid services or cloud dependencies.

Testing must remain suitable for a local Windows development environment and the current Python, SQLite, FastAPI, React, and TypeScript stack.

---

# 4. M18.1 — Audit the Existing Test Suite

Before adding tests, inspect the repository.

Review:

- `backend/tests/`
- `backend/scripts/`
- `frontend/src/**/*.test.ts`
- `frontend/src/**/*.test.tsx`
- `frontend/tests/live/`
- all existing `pytest` configuration
- all frontend test configurations
- Pyright and TypeScript configurations
- existing benchmark and verification scripts
- `pyproject.toml` or other dependency/configuration files
- CI configuration, if present
- `docs/TODO.md`
- milestone design documents from M0–M17

Identify:

- unit tests
- integration tests
- API tests
- WebSocket tests
- frontend component tests
- live backend/frontend tests
- end-to-end verification scripts
- performance benchmarks
- security tests

Create a coverage matrix showing:

| Area | Existing Tests | Identified Gaps | M18 Action |
|---|---|---|---|
| Packet processing | Audit | Missing cases | Add only where needed |
| Database | Audit | Missing cases | Add only where needed |
| Device discovery | Audit | Missing cases | Add only where needed |
| Connection tracking | Audit | Missing cases | Add only where needed |
| Detection and alerts | Audit | Missing cases | Add only where needed |
| Correlation and risk | Audit | Missing cases | Add only where needed |
| REST API | Audit | Missing cases | Add only where needed |
| WebSockets | Audit | Missing cases | Add only where needed |
| Frontend | Audit | Missing cases | Add only where needed |
| Reporting | Audit | Missing cases | Add only where needed |
| Performance | Audit | Missing cases | Add only where needed |
| Security | Audit | Missing cases | Add only where needed |

Do not claim formal coverage percentages without running a coverage tool.

Where coverage data is useful, use an appropriate existing or freely available coverage tool and document its limitations.

Avoid installing new dependencies when the existing toolchain can perform the task.

---

# 5. M18.2 — Packet Capture and Processing Tests

Audit M3–M5.

Verify that tests adequately cover:

- network interface enumeration
- interface selection
- capture start and stop
- invalid interface handling
- capture lifecycle transitions
- repeated start/stop requests
- graceful shutdown
- capture failures
- malformed packets
- unsupported protocols
- IPv4 and IPv6
- TCP, UDP, ICMP and DNS identification
- missing Ethernet or network-layer information
- packet normalization
- timestamp handling
- processor failure isolation

Test that malformed or unsupported packets do not crash the capture pipeline.

Verify that a capture error is reported rather than silently appearing as zero traffic.

Use packet fixtures and controlled local test data where appropriate.

Do not require elevated privileges for ordinary unit tests.

Live packet-capture tests must be optional, explicitly invoked, and limited to an authorized local interface.

---

# 6. M18.3 — Statistics, Persistence and Database Tests

Audit M6–M7 and the shared database infrastructure.

Verify:

- packet and byte counters
- protocol statistics
- time-window statistics
- top talkers
- bounded statistics state
- packet persistence
- batch writing
- queue capacity behavior
- retention cleanup
- query filtering
- pagination
- session cleanup
- database initialization
- database upgrades
- interrupted or failed writes
- appropriate rollback behavior

Confirm that the database migrations work for both:

1. a fresh database
2. an existing database that requires an upgrade

Test that M17's additive report schema upgrades existing databases correctly without destroying existing records.

Use isolated temporary databases for tests.

Tests must never accidentally delete or modify the developer's real `backend/netwatch.db`.

Keep local database files and backups out of Git.

---

# 7. M18.4 — Device and Connection Tests

Audit M8–M9.

### Device discovery

Test:

- first observation of a device
- updates to existing devices
- MAC address normalization
- multiple IPv4/IPv6 addresses
- missing MAC or IP
- first-seen and last-seen timestamps
- traffic attribution
- device status transitions
- stale device cleanup
- mapping conflicts
- concurrent updates
- registry bounds

Preserve and document the known routed-traffic/next-hop identity limitation. Do not mask it with fabricated device identities.

### Connection tracking

Test:

- canonical bidirectional flow identity
- reversed endpoints
- TCP connection states
- UDP and ICMP tracking
- connection expiration
- active/historical transitions
- byte and packet counters
- device association
- persistence and retrieval
- capacity limits
- thread safety
- invalid or incomplete packet information

Verify that M8 and M9 state remains consistent with the normalized packets and existing persistence rules.

---

# 8. M18.5 — Detection, Alerting and Correlation Tests

Audit M10–M12.

### Detection engine

Verify:

- every implemented detection rule
- threshold boundaries
- time windows
- repeated observations
- false-positive-prone conditions
- detector exceptions
- bounded detector state
- evidence construction
- confidence values
- failure isolation

Test legitimate and suspicious patterns separately so that ordinary activity is not automatically treated as malicious.

### Alert engine

Verify:

- finding-to-alert mapping
- severity and confidence separation
- alert evidence
- deduplication windows
- acknowledgement
- resolution
- dismissal
- false-positive lifecycle action
- invalid transitions
- repeated actions
- persistence and query behavior

### Correlation and risk scoring

Verify:

- event normalization
- correlation-window boundaries
- relationship weights
- confidence aggregation
- anti-chaining rules
- event deduplication
- incident creation and updates
- incident lifecycle restrictions
- bounded risk values
- risk-band boundaries
- explanation of contributing risk factors
- missing and unavailable context

Confirm that findings, alerts, incidents, severity, confidence and risk remain separate concepts.

M18 must test the existing behavior. It must not introduce a new detection or risk-scoring model.

---

# 9. M18.6 — REST API and Database Contract Tests

Audit M13 and the endpoints added by M16–M17.

Cover:

- HTTP methods and route registration
- request validation
- response schemas
- pagination limits
- invalid filters
- malformed timestamps
- inclusive and exclusive time boundaries
- error response envelopes
- missing resources
- unavailable data sections
- database failures
- incorrect lifecycle transitions
- report generation failures
- report download behavior
- safe error messages

Test all API groups, including:

- capture and interface management
- packets and statistics
- devices and connections
- detections and alerts
- evidence and incidents
- analytics
- dashboard
- settings and system
- notifications
- reporting

Verify the five M16 analytics endpoints and all four M17 report routes.

Use the actual running backend for live API verification where appropriate.

Compare real API responses with their Pydantic schemas and frontend TypeScript models.

Do not assume that documentation, OpenAPI schemas and runtime behavior are identical.

---

# 10. M18.7 — WebSocket Tests

Audit M14 and the frontend integration from M15.

Verify:

- each supported channel
- event envelope validation
- event schema compatibility
- subscriber registration and removal
- shared connections
- reconnect behavior
- REST refresh after reconnect
- duplicate event rejection
- bounded deduplication state
- per-channel buffering
- drop-oldest backpressure
- packet rate limiting
- heartbeat and timeout behavior
- invalid client messages
- client disconnects
- publisher failure isolation

Confirm that publishing failures cannot interrupt packet processing, detection, alerting, or correlation.

Test packet rate limiting without assuming the frontend receives every captured packet.

Do not introduce external network dependencies into ordinary unit tests.

---

# 11. M18.8 — Frontend Tests

Audit the existing React/TypeScript tests.

Test:

- loading states
- successful data display
- empty states
- API failures
- unavailable data sections
- retry actions
- API validation errors
- WebSocket connection status
- reconnect behavior
- duplicate event handling
- bounded lists
- alert lifecycle actions
- incident lifecycle actions
- analytics charts and filters
- report generation forms
- daily, weekly and custom reporting periods
- CSV/PDF download actions
- report history
- safe rendering of unexpected server values

Verify that:

- no mock data is activated in the live application
- no random generators simulate network activity
- no frontend component bypasses the shared API service layer
- TypeScript types match actual backend responses
- report files are downloaded from the backend, not fabricated browser URLs

Keep existing UI design changes outside M18 unless a test exposes a genuine defect that prevents correct application behavior.

---

# 12. M18.9 — End-to-End Testing

Build on the existing M13, M15, M16 and M17 verification scripts.

Verify the complete data flow:

```text
Authorized Local Traffic
          ↓
Packet Capture
          ↓
Normalization
          ↓
Statistics + Persistence
          ↓
Device Discovery + Connections
          ↓
Detection Findings
          ↓
Alerts
          ↓
Correlated Incidents + Risk
          ↓
REST API + WebSockets
          ↓
Frontend Displays Live Data
          ↓
Analytics
          ↓
CSV/PDF Reports
          ↓
Report History + Download
```

Create or strengthen a repeatable end-to-end verification procedure that confirms:

- real packets reach the pipeline
- statistics and persistence reflect processed packets
- device and connection state updates
- controlled suspicious test patterns produce the expected findings
- alerts and incidents are created by their actual engines
- the API exposes the resulting state
- WebSocket messages match the API's current state where applicable
- the frontend renders the real responses
- analytics queries return the expected aggregate values
- reports contain values consistent with the analytics responses
- generated CSV/PDF files can actually be retrieved

Use controlled local traffic and isolated temporary databases.

Existing fixtures may be used for unit and integration tests, but do not use mock-generated events to claim successful real-pipeline verification.

Live capture tests must be optional and authorized.

---

# 13. M18.10 — Performance Regression Testing

Audit benchmarks already created by earlier milestones.

Review existing measurements from:

- packet processing
- statistics
- persistence
- device discovery
- connection tracking
- detection
- alerts
- correlation and risk scoring
- REST API
- WebSockets
- analytics
- report generation

Do not rebuild every benchmark if the current scripts already measure the relevant behavior.

Establish reproducible test inputs and record the environment.

Measure relevant operations such as:

- packets processed per second
- per-packet processing overhead
- bounded queue behavior
- persistence throughput
- important API response times
- analytics query response times
- report generation and download costs
- memory growth under sustained traffic
- WebSocket behavior under controlled client load

Compare with the existing local baselines where comparable measurements are available.

Record:

- hardware/software environment
- dataset and test conditions
- warm-up and measurement procedure
- median and tail latency where appropriate
- observed resource consumption
- deviations from the existing baseline

Do not claim production-scale capacity.

Do not treat an arbitrary timing threshold as a correctness test on every machine.

Performance regressions must be measured and reported, not hidden by disabling tests or weakening assertions without justification.

---

# 14. M18.11 — Security Testing

Perform defensive security tests against the local NetWatch application and its test environment.

Focus on:

- input validation
- malformed packet handling
- unsafe file paths
- report download path traversal
- report filename handling
- CSV formula injection
- PDF rendering of untrusted text
- SQL parameterization
- filesystem containment
- secret and credential exposure
- error message disclosure
- unsafe configuration defaults
- unexpected HTTP methods
- WebSocket message validation
- resource exhaustion from excessive requests or oversized inputs
- cleanup of temporary files
- local database and generated-artifact permissions

Verify that user-controlled values cannot cause arbitrary file reads or writes through the report functionality.

Check that secrets, internal paths, SQL statements and tracebacks are not exposed through API responses or generated reports.

Do not run destructive security tests against external targets.

Do not send uncontrolled flood traffic or run invasive scans against public infrastructure.

Document that authentication/RBAC is not implemented yet, and do not claim security appropriate for public or multi-user deployment.

Fix only minimal, clearly identified correctness or security defects needed to make the tested behavior safe. Record larger architectural changes for M19 or a separately scoped milestone.

---

# 15. M18.12 — Failure and Recovery Testing

Test the application under controlled failure conditions.

Include:

- a missing or invalid capture interface
- malformed packets
- database write failures
- database read failures
- disk write failures
- full or unavailable report storage
- failed CSV/PDF generation
- missing report files
- failed WebSocket connections
- disconnected clients
- unavailable API responses
- invalid settings
- service shutdown during activity

Verify that:

- errors are surfaced honestly
- resources are released
- state is not silently corrupted
- partial report artifacts are cleaned up
- unavailable values do not become misleading zeroes
- a failure in one subsystem does not unnecessarily break unrelated components

Use dependency injection, test doubles and temporary files where appropriate to reproduce failures deterministically.

---

# 16. M18.13 — Reproducible Quality Gates

Provide one documented, repeatable test workflow.

Audit the existing scripts and package commands before adding new ones.

The final verification process must include:

1. Backend unit and integration tests
2. Database/API contract tests
3. WebSocket tests
4. Reporting tests
5. Frontend unit tests
6. Live frontend/backend tests
7. End-to-end verification
8. Python type checking
9. TypeScript type checking
10. Frontend production build
11. Selected performance checks
12. Security regression tests

Use the existing package scripts wherever possible.

If a new project-level test runner or script would simplify verification, add it only when it can execute the existing checks reliably without duplicating their logic.

Tests that require elevated privileges or live packet capture must be clearly separated from the normal unit-test command.

Document the expected environment variables and prerequisites for each test group.

A failed live test must not be silently skipped and counted as a pass.

---

# 17. M18.14 — Test Quality and Maintenance

Review the quality of existing tests.

Check for:

- tests that assert implementation details instead of behavior
- duplicate tests with no independent value
- weak assertions
- nondeterministic timing
- hidden dependence on network connectivity
- dependence on the developer's real SQLite database
- tests that change the working tree unexpectedly
- resource leaks
- background threads that remain running
- unclosed sockets
- temporary artifacts left behind
- overly broad exception assertions
- skipped or disabled tests without explanation

Improve test clarity and determinism where needed.

Do not delete a useful test merely because it is slow.

If a test is flaky, identify and document the root cause rather than increasing retry counts until it passes.

---

# 18. M18.15 — Documentation

Create:

`docs/22_M18_Testing_Design.md`

Use the same numbered, detailed format as the M15–M17 milestone documents.

Include:

1. Purpose
2. Scope
3. Non-goals
4. Existing test-suite audit
5. Coverage matrix
6. Unit testing
7. Database testing
8. API contract testing
9. WebSocket testing
10. Frontend testing
11. End-to-end testing
12. Performance regression testing
13. Security testing
14. Failure and recovery testing
15. Reproducible quality gates
16. Test execution instructions
17. Results and measurements
18. Known limitations
19. Completion checklist
20. M18 closure

Record actual commands, outputs, test counts, failures and skips.

Do not invent coverage percentages or test results.

Keep the document focused on M18.

Update only the M18 section of `docs/TODO.md` as appropriate. Do not rewrite previous milestone records.

Keep the status as:

**Status: design / in progress**

until all completion criteria are verified.

Only then mark it:

**Status: implemented and verified**

---

# 19. M18 Non-Goals

The following are not part of M18:

- new detection algorithms
- ML anomaly detection
- behavioral baselines
- AI explanations
- local LLM/Ollama
- new risk-scoring models
- new dashboard functionality
- new reporting features
- authentication/RBAC implementation
- SIEM integrations
- distributed sensors
- Docker deployment
- PostgreSQL migration
- major architectural refactoring

M18 is primarily a testing and verification milestone.

Do not add application features merely to increase the number of modified files.

---

# 20. Verification

Before closing M18, run the relevant project checks from a clean, documented environment.

At minimum:

```text
Full backend test suite
Backend type checking
Frontend unit suite
Frontend TypeScript type checking
Frontend production build
Live API integration tests
Live WebSocket tests
Reporting tests
End-to-end verification
Performance regression checks
Security regression tests
```

Also verify:

- the database migrations work
- `.env.example` contains the necessary configuration without secrets
- local `.env` files and runtime databases are ignored by Git
- generated reports and temporary test files do not accidentally enter the repository
- existing M0–M17 behavior remains compatible

If a test fails, investigate and report the failure.

Do not mark M18 complete merely because the test command was started or because previously recorded test counts appear in the documentation.

---

# 21. Completion Criteria

M18 is complete only when:

- [ ] Existing test suites have been audited
- [ ] A coverage matrix is documented
- [ ] Packet capture and processing tests are adequate
- [ ] Database and migration tests pass
- [ ] Device and connection tests pass
- [ ] Detection, alert and correlation tests pass
- [ ] Risk-scoring boundary tests pass
- [ ] REST API contracts are verified
- [ ] WebSocket behavior is verified
- [ ] Frontend behavior is verified
- [ ] Reporting functionality is covered
- [ ] End-to-end data flow is verified
- [ ] Performance checks are repeatable
- [ ] Security regression tests pass
- [ ] Failure and recovery behavior is tested
- [ ] The main test workflow is reproducible
- [ ] Existing M0–M17 regression suites pass
- [ ] Pyright passes
- [ ] TypeScript checking passes
- [ ] Frontend build succeeds
- [ ] Test output contains no unexplained skips or failures
- [ ] `docs/22_M18_Testing_Design.md` is complete
- [ ] M18's `docs/TODO.md` checklist is updated

---

# 22. Final Implementation Report

At completion, provide:

1. Existing test suites audited
2. Coverage matrix summary
3. Files created
4. Files modified
5. New tests added and the gaps they address
6. Backend test result
7. Frontend test result
8. Live integration result
9. Type-checking and build results
10. End-to-end verification result
11. Performance regression measurements
12. Security test results
13. Known gaps and deferred defects
14. Any failures or skipped tests
15. Whether M18 is ready to mark implemented and verified

Do not claim complete coverage of the application unless the evidence supports it.

Do not claim production readiness based solely on successful tests.

**The milestone is complete only when the actual project has passed the required checks and the results have been documented.**