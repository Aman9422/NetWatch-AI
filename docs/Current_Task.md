# NetWatch AI — Current Task

**Current Phase:** Base Application Implementation
**Current Milestone:** M11 — Alert Engine
**Status:** ✅ COMPLETE (next: M12 — Correlation + Risk Scoring)

---

# Current Objective

Build the Alert Engine for NetWatch AI.

M10 detects suspicious network behavior and produces structured Detection Findings.

M11 converts those findings into security Alerts that can be:

- Stored
- Investigated
- Updated through a defined lifecycle
- Linked to evidence
- Associated with devices
- Associated with relevant packets/connections
- Deduplicated where appropriate
- Queried by later application layers

The main flow becomes:

    Network
       ↓
    Packet Capture
       ↓
    Packet Processing
       ↓
    Statistics / Devices / Connections
       ↓
    Detection Engine
       ↓
    Detection Finding
       ↓
    Alert Engine
       ↓
    Security Alert
       ↓
    Alert Evidence
       ↓
    Existing Database

---

# M11 Development Rule

M11 is responsible only for alert management.

Do NOT implement:

- New detection algorithms
- Behavioral baselines
- ML anomaly detection
- AI analysis
- Correlation engine
- Risk scoring
- Automatic blocking
- WebSockets
- Frontend integration
- External SIEM integrations
- Advanced incident response

M10 detects.

M11 alerts.

M12 will correlate findings and calculate risk.

---

# M11.1 — Review Existing Components

Review:

- M10 DetectionFinding
- M5 NormalizedPacket
- M8 Device information
- M9 Connection information
- M7 packet persistence
- Existing `alerts` database model
- Existing `alert_evidence` database model
- Existing repositories
- Existing configuration conventions

Do not duplicate functionality from previous milestones.

---

# M11.2 — Alert Service

Create a dedicated alert service.

Suggested component:

    AlertService

Suggested responsibilities:

    create_alert(finding)
    get_alert(alert_id)
    list_alerts(...)
    update_alert(...)
    acknowledge_alert(...)
    resolve_alert(...)
    dismiss_alert(...)
    add_evidence(...)
    deduplicate(...)

Keep alert business logic out of API route handlers.

---

# M11.3 — Alert Model

Create/verify the normalized runtime alert representation.

Suggested fields:

    alert_id
    rule_id
    title
    description
    severity
    confidence
    status
    created_at
    updated_at
    source_ip
    destination_ip
    source_device_id
    destination_device_id
    protocol
    connection_id
    finding_id
    evidence_count

Use only information supported by the Detection Finding and existing application state.

Do not add risk score yet.

---

# M11.4 — Alert Severity

Define alert severity independently from confidence.

Initial levels:

    low
    medium
    high
    critical

Severity should be determined using an explicit documented mapping from detection rules/findings.

Do not allow a detector to silently invent arbitrary severity values.

Do not use severity as a risk score.

---

# M11.5 — Alert Confidence

Preserve detection confidence from M10 where available.

Keep:

    severity
    confidence

as separate concepts.

Example:

    Severity: high
    Confidence: 0.92

This does NOT mean the alert has a risk score of 92.

Risk scoring belongs to M12.

---

# M11.6 — Alert Status / Lifecycle

Define an explicit lifecycle.

Initial statuses:

    open
    acknowledged
    resolved
    dismissed
    false_positive

Suggested flow:

    open
      ↓
    acknowledged
      ↓
    resolved

Alternative outcomes:

    open → dismissed
    open → false_positive
    acknowledged → false_positive
    acknowledged → resolved

The lifecycle must be validated.

Do not allow arbitrary invalid state transitions.

---

# M11.7 — Alert Creation

When a detection finding satisfies alert-generation conditions:

    Detection Finding
          ↓
      Alert Engine
          ↓
      Create Alert
          ↓
      Create Evidence

The original finding should remain identifiable.

Do not modify the detection result merely to create an alert.

---

# M11.8 — Detection-to-Alert Mapping

Define which M10 findings create alerts.

Initial rule mapping should cover the implemented M10 detectors:

    Port Scan
    SYN Flood
    ICMP Flood
    Internal Scan
    High Bandwidth

Document:

    rule_id
    alert title
    alert description
    severity
    confidence source

Do not create alerts for functionality that does not exist.

---

# M11.9 — Alert Deduplication

Prevent repeated identical findings from creating an uncontrolled number of alerts.

Define an explicit deduplication key.

Possible components:

    rule_id
    source
    destination
    protocol
    related device
    related connection
    time window

The exact key must be documented.

Deduplication must not merge clearly separate incidents.

---

# M11.10 — Deduplication Window

Use a configurable deduplication interval.

Example:

    Same rule
       +
    Same source
       +
    Same target
       +
    Within configured window
       ↓
    Existing Alert

After the deduplication window expires, a new alert may be created.

Do not use an unlimited deduplication window.

---

# M11.11 — Alert Evidence

Create structured alert evidence.

Evidence should answer:

    Why was this alert created?

Possible evidence types:

    detection finding
    packet reference
    connection reference
    traffic statistic
    device information

Each evidence record should contain only data that actually supports the alert.

Do not copy entire packet payloads into evidence.

---

# M11.12 — Evidence Model

Review the existing `alert_evidence` database model.

Map runtime evidence to the existing schema.

Support relationships such as:

    Alert
      ├── Finding evidence
      ├── Packet evidence
      ├── Connection evidence
      └── Device evidence

Do not redesign the database unless a genuine missing requirement is discovered.

---

# M11.13 — Packet Evidence

Where appropriate, link an alert to relevant persisted packets.

Use M7 packet persistence.

Do not duplicate packet records.

An evidence record should reference the relevant packet rather than copying the packet into the alert.

---

# M11.14 — Connection Evidence

Where appropriate, link alerts to M9 connection information.

Example:

    Port Scan Finding
         ↓
    Relevant Connections
         ↓
    Alert Evidence

Do not create another connection store.

---

# M11.15 — Device Association

Associate alerts with devices when the M8 registry provides the required identity.

Possible associations:

    Source device
    Destination device

If a device cannot be resolved:

    leave association empty

Do not invent devices.

---

# M11.16 — Alert Persistence

Persist alerts using the existing database architecture.

Use:

    AlertRepository
    AlertEvidenceRepository

where appropriate.

Follow existing session/transaction patterns.

---

# M11.17 — Alert Repository

Support operations such as:

    create
    get_by_id
    list
    update_status
    update_alert
    count
    find_duplicate_candidate

Do not put detection logic into the repository.

---

# M11.18 — Alert Queries

Support queries such as:

    Recent alerts
    Open alerts
    Alerts by severity
    Alerts by status
    Alerts by rule
    Alerts by source IP
    Alerts by destination IP
    Alerts by device
    Alerts by time range

Use bounded results and deterministic ordering.

---

# M11.19 — Alert Lifecycle Validation

Define valid transitions.

Example:

    open → acknowledged
    open → resolved
    open → dismissed
    open → false_positive

    acknowledged → resolved
    acknowledged → dismissed
    acknowledged → false_positive

Invalid transitions must be rejected.

Example:

    resolved → open

should not silently succeed unless an explicit reopen operation is deliberately designed.

---

# M11.20 — Alert Updates

Allow controlled status updates.

At minimum support:

    acknowledge
    resolve
    dismiss
    mark_false_positive

Record:

    updated_at

Do not add user/authentication fields unless already supported by the project's current architecture.

---

# M11.21 — Finding-to-Alert Error Isolation

A single alert-processing failure must not stop detection processing.

Example:

    Finding 1 → Alert created
    Finding 2 → Persistence error
    Finding 3 → Alert created

Failures must be:

- Counted
- Logged
- Isolated

Do not crash the capture or detection pipeline.

---

# M11.22 — Alert Processing Pipeline

Extend the architecture:

    NormalizedPacket
          ↓
    Detection Engine
          ↓
    Detection Findings
          ↓
    Alert Engine
          ↓
    Alerts
          ↓
    Alert Evidence

The alert engine consumes M10 findings.

It must not independently inspect raw packets to reimplement detection logic.

---

# M11.23 — Thread Safety

Alert processing may occur concurrently with:

- Detection
- Persistence
- Queries
- Status updates

Protect shared alert/deduplication state where necessary.

Database transactions must remain safe.

Avoid unnecessary global locks.

---

# M11.24 — Alert Configuration

Add configuration where appropriate.

Potential settings:

    ALERTS_ENABLED
    ALERT_DEDUP_WINDOW_SECONDS
    ALERT_MAX_EVIDENCE_PER_ALERT

Use project configuration conventions.

Do not hard-code operational limits unnecessarily.

---

# M11.25 — Tests — Alert Model

Test:

- Valid alert creation
- Required fields
- Optional fields
- Severity values
- Confidence values
- Status values
- Timestamp behavior
- Finding association

---

# M11.26 — Tests — Alert Creation

Test:

- Finding creates alert
- Unsupported finding does not create alert
- Correct rule mapping
- Correct severity
- Correct confidence
- Correct device association
- Correct connection association

---

# M11.27 — Tests — Deduplication

Test:

- Identical finding within dedup window
- Identical finding outside window
- Different source
- Different destination
- Different rule
- Different connection
- Multiple independent alerts

Verify that legitimate separate events are not incorrectly merged.

---

# M11.28 — Tests — Alert Lifecycle

Test:

    open → acknowledged
    open → resolved
    open → dismissed
    open → false_positive
    acknowledged → resolved
    acknowledged → dismissed
    acknowledged → false_positive

Also test invalid transitions.

---

# M11.29 — Tests — Evidence

Test:

- Finding evidence
- Packet evidence
- Connection evidence
- Device evidence
- Multiple evidence records
- Missing evidence
- Evidence count

Verify that packet payloads are not duplicated.

---

# M11.30 — Tests — Repository / Database

Test:

- Create alert
- Retrieve alert
- List alerts
- Filter alerts
- Update status
- Persist evidence
- Retrieve evidence
- Deduplication lookup
- Transaction rollback

Use a test database.

---

# M11.31 — Integration Tests

Verify:

    Detection Engine
          ↓
    Detection Finding
          ↓
    Alert Engine
          ↓
    Alert Repository
          ↓
    SQLite

Use controlled findings from M10.

Verify:

- Correct alerts are created.
- Severity is correct.
- Confidence is preserved.
- Evidence is stored.
- Duplicate findings are handled.
- Detection continues after alert failure.

---

# M11.32 — Manual Verification

Use controlled authorized/lab detection scenarios.

Trigger the existing M10 rules using safe test conditions.

For each resulting finding verify:

    Detection Finding
         ↓
    Alert Created
         ↓
    Severity
         ↓
    Confidence
         ↓
    Evidence
         ↓
    Database Record

Then verify alert lifecycle operations:

    Open
      ↓
    Acknowledge
      ↓
    Resolve

Also verify false-positive/dismissed workflows.

---

# M11.33 — Performance Baseline

Measure:

- Findings processed per second
- Alerts created per second
- Deduplication lookup time
- Database write latency
- Evidence write overhead
- Memory usage
- Query response time

Do not claim production-scale alert throughput.

---

# M11 Completion Criteria

M11 is complete when:

- AlertService exists.
- Runtime Alert model exists.
- Detection-to-alert mapping exists.
- Severity is implemented.
- Confidence is preserved separately.
- Alert lifecycle works.
- Invalid lifecycle transitions are rejected.
- Alert evidence works.
- Packet references work where applicable.
- Connection references work where applicable.
- Device association works where available.
- Alert persistence works.
- Alert repository works.
- Deduplication works.
- Query/filter functionality works.
- Alert-processing errors are isolated.
- Thread safety is implemented where needed.
- Unit tests pass.
- Database tests pass.
- Integration tests pass.
- Manual verification succeeds.
- Performance baseline is recorded.
- No correlation, risk scoring, ML/AI, WebSockets, or frontend work is introduced.

---

# Completion Record

M11 is complete. The alert layer turns M10 findings into persisted alerts with a
severity, a validated lifecycle, a deduplication identity and reference-based
evidence. Every item in the M11 Completion Criteria above is met.

| Area | Where |
| --- | --- |
| Alert service (M11.2) | `app/alerts/service.py` (`AlertService`) |
| Runtime alert model (M11.3) | `app/alerts/alert.py` |
| Severity (M11.4) | `app/alerts/severity.py` |
| Confidence handling (M11.5) | `app/alerts/persistence.py` (`confidence_to_percent`) |
| Lifecycle + validation (M11.6/M11.19) | `app/alerts/status.py` |
| Detection-to-alert mapping (M11.8) | `app/alerts/mapping.py` |
| Deduplication key + window (M11.9/M11.10) | `app/alerts/dedup.py` |
| Evidence + builder + resolvers (M11.11-M11.15) | `app/alerts/evidence.py`, `evidence_builder.py`, `resolvers.py` |
| Persistence + repositories (M11.16/M11.17) | `app/alerts/persistence.py`, `app/repositories/alert.py`, `app/repositories/alert_evidence.py` |
| Queries / filters (M11.18) | `app/alerts/queries.py` |
| Error isolation + pipeline (M11.21/M11.22) | `app/alerts/engine.py`, `app/services/packet_pipeline.py` |
| Thread safety (M11.23) | `AlertService` write lock + per-call sessions |
| Configuration (M11.24) | `app/config/settings.py` (the `ALERT*` settings) |
| API (M11.18/M11.19) | `app/api/v1/alerts.py` |
| Schema upgrade (M11.6) | `app/database/upgrade.py` (`upgrade_alert_status_constraint`) |
| Design | `docs/15_M11_Alert_Engine_Design.md` |

**Verification:** full suite **1077 passed**; pyright **0 errors, 0 warnings**; the
M11 alert suite is **218 tests**. `scripts/verify_m11.py` sample mode passes every
check (all five mapped rules → alerts at the mapped severity, confidence
preserved, evidence stored with no payload copied, deduplication window honoured,
lifecycle applied and a reopen rejected). `scripts/benchmark_m11.py` recorded the
local baseline (documented in the design doc and `docs/TODO.md`).

**Live verification:** the application boots against an isolated SQLite database
(`uvicorn app.main:app`), `init_db` upgrades the schema, `/api/v1/health`,
`/api/v1/alerts`, `/api/v1/alerts/summary`, `/api/v1/alerts/diagnostics`,
`/docs` and `/openapi.json` all answer, a missing alert and an unknown severity
return 404 and 400, and a seeded alert walked the real HTTP lifecycle
`open → acknowledged → resolved` with the counters reporting `transitions: 2`
before a reopen was rejected with 409.

**Schema note:** the M2 `alerts.status` CHECK is widened to the M11 vocabulary
(plus the legacy `new`/`investigating`) by rebuilding the table in
`app/database/upgrade.py`, which `init_db` runs on startup.

---

# Next Task

**M12 — Correlation + Risk Scoring (not started).**

M12 will consume the findings (M10) and alerts (M11) already produced to
implement correlation, risk scoring, historical context, a behavioural
contribution and an ML contribution placeholder. M11 deliberately leaves no risk
field anywhere; risk is M12's concern.

Beginning M12 follows the project's usual pattern: review the M11 `Alert` and the
M10 `DetectionFinding` first, then define the correlation window, the grouping
rules and the risk model before implementing anything.

---

# Architecture Boundary

M10 produces:

    Detection Findings

M11 produces:

    Alerts
       └── Alert Evidence

M12 will consume alerts/findings to implement:

    Correlation
    Risk Scoring
    Historical Context
    Behavioral Contribution
    ML Contribution

M11 itself must not implement those systems.
