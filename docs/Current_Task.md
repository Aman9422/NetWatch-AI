# M21 — Behavioral Baseline Engine

**Project:** NetWatch AI  
**Milestone:** M21  
**Suggested version:** v0.0.21  
**Base version:** v0.0.20  
**Status:** Planned  
**Primary objective:** Implement a persistent, per-device behavioral baseline learning engine.

---

## 1. Context and instructions

M0–M20 are complete. The base application has been released as `v0.0.20`.

Before modifying anything:

1. Inspect the current repository, source code, database models, packet-processing pipeline, device registry, connection tracker, statistics services, API conventions, frontend architecture, configuration, tests, and documentation.
2. Confirm the current branch and working-tree status.
3. Review the M20 release documentation and existing architecture.
4. Understand how normalized packets and device identities move through the application.
5. Reuse existing services and patterns wherever possible.

Do not assume that an earlier milestone's proposed architecture matches the exact current implementation. Inspect the actual code before deciding where to integrate the new functionality.

**Preserve all completed M0–M20 functionality.** Do not rewrite working modules unnecessarily. Do not remove existing APIs, tests, frontend pages, or database records.

This project must remain free and locally hosted. Do not introduce paid APIs, cloud AI services, external hosted databases, or mandatory third-party services.

## 2. Objective

Build a Behavioral Baseline Engine that learns what normal network activity looks like for each discovered device.

The engine should observe network activity over time, extract meaningful behavioral features, aggregate them into time windows, and maintain statistical profiles.

For example:

- How many packets does a device normally transmit?
- How much data does it normally transfer?
- Which protocols does it regularly use?
- How many unique peers does it normally communicate with?
- How many destination ports does it normally contact?
- How frequently does it establish connections?

The engine should gradually develop an understanding of each device's observed behavior.

The resulting profiles will become an input to M22, which will implement ML-based anomaly detection.

**Important:** M21 implements behavioral learning only. It does not yet identify anomalies or generate security alerts.

## 3. Scope boundaries

### Implement in M21

1. Behavioral feature extraction.
2. Per-device behavioral aggregation.
3. Time-window-based collection.
4. Persistent baseline storage using SQLite.
5. Statistical baseline calculations.
6. Baseline learning and maturity states.
7. Baseline history management and retention.
8. REST APIs for baseline information.
9. A frontend page for inspecting learned baselines.
10. Baseline tests, documentation, and quality-gate integration.

### Do not implement in M21

- ML anomaly detection.
- Isolation Forest, One-Class SVM, Autoencoders, or other anomaly-detection models.
- Anomaly scoring or automatic suspicious-activity classification.
- Automatic security alerts based on baseline deviations.
- A locally hosted LLM.
- LLM-based log analysis.
- AI Security Analyst.
- Wazuh integration.
- Automatic traffic blocking or IPS functionality.
- External cloud-based learning services.

These belong to later milestones.

## 4. Behavioral feature extraction

Integrate with the existing normalized packet-processing and device-discovery pipeline.

Do not introduce another packet-capture implementation. Do not independently capture traffic.

Extract features using information actually available in the current application.

Start with these per-device behavioral metrics:

| Feature | Description |
|---|---|
| Packet count | Number of observed packets |
| Byte count | Total observed bytes |
| TCP packets | TCP packet count |
| UDP packets | UDP packet count |
| ICMP packets | ICMP packet count |
| DNS packets | DNS packet count |
| Unique peers | Number of distinct observed communication peers |
| Unique destination ports | Number of distinct destination ports |
| New connections | Number of newly observed connections, when reliably available |

Add inbound/outbound metrics only if the current architecture can determine direction accurately. Do not guess packet direction.

Do not invent metrics when the underlying information is unavailable. Document unavailable or unsupported features.

### Device identity

The existing M8 implementation uses MAC-based device identity with IP history.

Use the existing device identity model wherever possible.

Requirements:

- A device changing its IP address should retain its baseline when its stable MAC identity remains the same.
- Do not accidentally combine unrelated devices.
- Do not treat a router's MAC address as proof that every remote IP behind it is the same physical device.
- Handle missing, invalid, multicast, and broadcast identities safely.
- Use a clearly documented fallback policy when a stable identity cannot be established.

The baseline engine must not depend on the `devices` database table being populated. M20 documents that the live device registry is held in memory.

## 5. Time-window aggregation

Use a configurable aggregation interval, with a default of **60 seconds**.

For every device, collect behavioral feature values over each interval.

Requirements:

1. Aggregate metrics in memory before writing them to SQLite.
2. Do not perform an individual database write for every captured packet.
3. Flush aggregated windows through a controlled background process.
4. Flush pending data during graceful application shutdown.
5. Keep memory usage bounded.
6. Do not block packet capture while baseline data is written.
7. Handle malformed packets and missing fields without interrupting packet processing.
8. Isolate baseline-engine failures from the existing capture and detection pipeline.
9. Record appropriate internal errors and counters when data cannot be processed or persisted.

Only persist useful observation windows. Do not silently convert missing data into zero-valued behavior.

## 6. Statistical baseline calculation

For each device, calculate a statistical profile from its collected behavioral samples.

Use robust statistical measurements:

- Sample count.
- Mean.
- Median.
- Median Absolute Deviation (MAD).
- Standard deviation, where useful.
- 95th percentile.
- Minimum and maximum.
- First observed timestamp.
- Latest observed timestamp.

Calculate these statistics for the supported numeric behavioral features.

Use an implementation that is computationally reasonable and memory-bounded.

Document how the statistics are calculated and how missing observations are handled.

The baseline should not be influenced by an unbounded accumulation of raw packet data. Keep the design based on aggregated behavioral windows.

## 7. Learning lifecycle and maturity

Implement clear baseline learning states.

Suggested states:

- `learning`: insufficient observations to produce a useful profile.
- `provisional`: the minimum sample requirement has been reached, but the profile is still developing.
- `established`: sufficient observations have been collected for a mature statistical profile.

Choose and document sensible default sample thresholds. Make them configurable where appropriate.

The frontend must clearly show the current learning state and sample count.

Important requirements:

- A new device must not receive a fabricated baseline.
- A baseline must not be marked established merely because the device exists.
- Missing data must not be interpreted as zero traffic.
- Baseline maturity must be based on actual collected observations.
- A restarted backend must not unnecessarily discard previously persisted baselines.
- A baseline must be resettable without deleting unrelated packet, device, alert, or incident data.

Do not present an established baseline as proof that the device is safe. It only describes its previously observed behavior.

## 8. Persistent storage

Extend the existing SQLAlchemy and SQLite architecture.

Design suitable database models for:

1. Per-device baseline metadata and learning state.
2. Aggregated behavioral observation windows.
3. Statistical profile information, if required by the design.

Use appropriate indexes and uniqueness constraints.

Requirements:

- Stable device identity.
- Timestamps stored consistently using the project's UTC conventions.
- Transaction-safe writes.
- Database migrations or the repository's established schema-initialization approach.
- Bounded historical retention.
- Configurable retention settings.
- Safe handling of duplicate windows.
- No raw packet payload storage in the baseline tables.

Start with a documented default history-retention period, such as seven days, and make it configurable.

Preserve baseline profile continuity across application restarts when a stable device identity is available.

## 9. Backend service architecture

Create a dedicated behavioral baseline module or service following the repository's existing organization.

Separate responsibilities where appropriate:

- Feature extraction.
- Per-device aggregation.
- Baseline sample persistence.
- Statistical calculations.
- Learning-state management.
- Retention and lifecycle management.

Use existing application startup and shutdown mechanisms.

Do not introduce unnecessary threads, processes, event brokers, or services.

The baseline engine must operate as an additional component in the current monitoring pipeline. Existing packet capture, statistics, persistence, detection, alerting, and correlation must continue working as before.

## 10. REST API

Add versioned endpoints following the existing `/api/v1` conventions.

Suggested endpoints:

```http
GET  /api/v1/baselines
GET  /api/v1/baselines/{device_key}
POST /api/v1/baselines/{device_key}/reset
```

Implement:

- Paginated baseline listing.
- Individual device baseline details.
- Current learning state.
- Sample count and observation timestamps.
- Statistical values for supported features.
- Clear behavior when a baseline does not exist.
- Input validation.
- Existing standardized response envelopes.
- Correct HTTP status codes and error responses.

The reset operation must delete only the selected device's baseline history and profile, then allow learning to restart.

Do not expose internal database paths, stack traces, or private implementation details.

Verify every endpoint against the running backend. Do not assume response shapes from frontend expectations.

## 11. Frontend — Behavioral Baselines

Add a dedicated **Behavioral Baselines** page to the existing React/TypeScript application.

Follow the existing design system, navigation, reusable components, API client, loading states, error handling, and page-boundary architecture.

The page should display:

- Discovered device identity.
- Baseline learning status.
- Number of collected samples.
- First and latest observation times.
- Packet and byte statistics.
- Protocol behavior.
- Peer and destination-port statistics when available.
- Statistical baseline summaries.

Add a device-level detail view so the user can inspect its behavioral profile.

Provide a baseline reset action with a clear confirmation step.

Handle these states properly:

- No devices discovered.
- Device discovered but no observations collected.
- Learning in progress.
- Provisional baseline.
- Established baseline.
- API unavailable.
- Baseline data unavailable.
- Failed baseline retrieval.

Do not use mock data in the completed integration.

The page must explain that a baseline describes previously observed behavior and is not itself an anomaly verdict.

## 12. Performance and reliability

Baseline collection must not destabilize the existing application.

Verify:

- Packet capture continues during baseline collection.
- Packet-processing errors do not increase because of baseline failures.
- SQLite writes remain controlled and batched.
- Aggregation structures are bounded.
- Retention removes expired observation windows correctly.
- Graceful shutdown flushes pending data.
- Database failures do not silently corrupt profile information.
- Multiple devices can be tracked independently.
- Restarting the application preserves stored baseline history.
- Existing detection and alerting continue to work.

Measure relevant performance before and after enabling the baseline engine using the available project benchmarks.

Record actual measurements. Do not invent improvements or claim production-scale performance based on a local test.

## 13. Testing

Add comprehensive backend and frontend tests.

### Backend tests

Test at least:

1. Feature extraction from normalized packets.
2. Feature extraction with missing or malformed fields.
3. Correct per-device aggregation.
4. Separation of two different devices.
5. IP changes for an existing MAC identity.
6. Aggregation-window boundaries.
7. Duplicate-window protection.
8. Statistical calculations.
9. Learning-state transitions.
10. Empty and insufficient observation histories.
11. Persistent baseline recovery after application restart.
12. Baseline reset.
13. Historical retention.
14. Graceful shutdown flushing.
15. Database write failures.
16. Bounded aggregation behavior.
17. REST endpoint response envelopes.
18. Pagination and validation.
19. Missing baseline responses.
20. Regression of existing capture, statistics, detection, alert, and incident functionality.

### Frontend tests

Test:

- Baseline list rendering.
- Loading and error states.
- Learning, provisional, and established states.
- Device detail rendering.
- Empty baseline data.
- Reset confirmation and successful reset.
- Reset failures.
- Correct API integration.
- Navigation to the new page.

### Integration tests

Demonstrate the complete workflow:

```text
Start backend
    ↓
Start authorized packet capture
    ↓
Observe normalized packets
    ↓
Identify devices
    ↓
Extract behavioral features
    ↓
Aggregate observation windows
    ↓
Persist baseline samples
    ↓
Calculate statistical profiles
    ↓
Retrieve profiles through REST API
    ↓
Display profiles in the frontend
    ↓
Reset one device's baseline
    ↓
Verify that learning starts again
```

Use controlled local traffic and do not generate traffic against systems without authorization.

## 14. Quality gates

Update the existing quality-gate system to include any new required checks.

Run the complete existing verification process, including:

```powershell
python backend/scripts/run_quality_gates.py --full
```

Also run the applicable frontend commands:

```powershell
cd frontend
npm test
npm run test:live
npm run typecheck
npm run build
```

Run all existing backend tests and the new M21 tests.

Record the actual test counts and results.

Do not skip, suppress, or exclude failing tests to obtain a passing result.

Preserve all M0–M20 quality gates.

## 15. Documentation

Create:

```text
docs/25_M21_Behavioral_Baseline_Engine.md
```

Document:

- M21 purpose and scope.
- Architecture and data flow.
- Behavioral features.
- Device identity handling.
- Aggregation interval.
- Statistical calculations.
- Learning lifecycle.
- Database schema.
- Retention configuration.
- API endpoints and response examples.
- Frontend implementation.
- Testing and verification.
- Performance measurements.
- Known limitations.
- Deferred functionality for M22 and later.

Update the main README where appropriate.

Update `docs/TODO.md` to record M21 completion and the remaining roadmap.

Do not rewrite the M20 release report. It must remain an accurate historical record of the v0.0.20 base release.

## 16. Git and version control

Inspect Git status before making changes.

- Preserve the M20 `v0.0.20` tag.
- Do not rewrite existing history.
- Do not force-push.
- Do not commit databases, virtual environments, generated reports, temporary files, secrets, or credentials.
- Follow the repository's existing commit conventions.
- Verify tracked files before committing.

Use `v0.0.21` only after confirming the existing tag convention and successful M21 acceptance checks.

Do not create a release tag while required tests are failing.

## 17. M21 acceptance criteria

M21 is complete only when:

- [ ] The behavioral baseline engine is implemented.
- [ ] Existing normalized packet processing is reused.
- [ ] Behavioral features are extracted correctly.
- [ ] Per-device aggregation works.
- [ ] Statistical profiles are calculated correctly.
- [ ] Learning states work correctly.
- [ ] Baseline data persists across restarts.
- [ ] Stable device identity is handled correctly.
- [ ] Historical retention works.
- [ ] Reset functionality works.
- [ ] Backend REST endpoints work.
- [ ] The Behavioral Baselines frontend page works.
- [ ] Frontend uses real backend data.
- [ ] Performance and bounded-state behavior are verified.
- [ ] New backend tests pass.
- [ ] New frontend tests pass.
- [ ] Existing M0–M20 regression suites pass.
- [ ] Full quality gates pass.
- [ ] README and architecture documentation are updated.
- [ ] `docs/25_M21_Behavioral_Baseline_Engine.md` is complete.
- [ ] `docs/TODO.md` is updated.
- [ ] Git repository contains no accidental generated data or secrets.

## 18. Final milestone report

At completion, provide a detailed report containing:

1. What was implemented.
2. Architecture and file changes.
3. Database changes.
4. Behavioral features collected.
5. Statistical methods used.
6. Learning-state thresholds.
7. API endpoints and verified response examples.
8. Frontend changes.
9. Test counts and quality-gate results.
10. Performance measurements.
11. Known limitations.
12. Deferred M22 functionality.
13. Git status and version/tag information.

Clearly distinguish implemented functionality from planned functionality.

**Do not claim that NetWatch AI now detects anomalies using ML.** M21 builds the behavioral knowledge that M22 will use to implement anomaly detection.

---

**Milestone completion definition:** NetWatch AI can continuously learn and persist statistical behavioral profiles for observed devices, display those profiles through its backend and frontend, and preserve the reliability of the existing M20 application.