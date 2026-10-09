# NetWatch AI — M16 Analytics

**Milestone:** M16 — Analytics  
**Scope:** implement and verify the backend analytics layer using the real data produced by M4–M12.  
**Status:** not started

---

# 1. Purpose

M15 connected the React/TypeScript frontend to the M13 REST API and M14 WebSocket channels. The frontend already consumes the following analytics endpoints:

- `GET /api/v1/analytics/traffic`
- `GET /api/v1/analytics/protocols`
- `GET /api/v1/analytics/devices`
- `GET /api/v1/analytics/connections`
- `GET /api/v1/analytics/threats`

M16 now implements and hardens the backend analytics behind these endpoints.

The analytics layer must transform existing NetWatch data into useful historical, statistical and security summaries without introducing a second detection or risk engine.

---

# 2. M16 Goal

Build a read-oriented analytics layer for:

1. Traffic analytics
2. Protocol analytics
3. Device analytics
4. Connection analytics
5. Threat analytics

The results must come from real backend data.

No mock data, random values or simulated activity may be introduced.

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
      Analytics
────────────────────────
      ↓
M13 REST API
      ↓
M15 Frontend
````

M16 is a consumer of existing backend data.

It does not replace:

* M6 Traffic Statistics
* M8 Device Discovery
* M9 Connection Tracking
* M10 Detection
* M11 Alert Engine
* M12 Correlation and Risk Scoring

---

# 4. Scope

## M16.1 — Analytics Architecture

First inspect the existing implementation.

Identify:

* current analytics router
* analytics service/module
* existing repositories
* packet persistence
* statistics manager
* device registry/data
* connection data
* detection findings
* alerts
* incidents
* existing Pydantic schemas
* M13 analytics response models
* M15 frontend expectations

Determine whether the current analytics implementation is complete, partial or placeholder-based.

Reuse existing services and models wherever possible.

Do not create duplicate representations of packets, devices, connections, alerts or incidents.

---

# 5. Traffic Analytics

Implement analytics based on persisted packet and traffic data.

Support useful values such as:

* total packets
* total bytes
* packet rate
* byte rate
* traffic over time
* top source addresses
* top destination addresses
* inbound/outbound traffic where supported
* packet count by time bucket
* byte count by time bucket

Time-series results must be bounded.

Do not return an unlimited number of data points.

Define clear:

* default time range
* maximum time range
* bucket size
* maximum returned points

Use existing M6 statistics where appropriate instead of creating a second traffic-statistics engine.

---

# 6. Protocol Analytics

Calculate protocol distribution from actual packet data.

Support:

* packet count by protocol
* byte count by protocol
* protocol percentage
* top protocols
* protocol distribution over time where useful

Handle:

* empty data
* unknown protocols
* zero totals
* missing values

Percentages must be calculated from the actual selected dataset.

---

# 7. Device Analytics

Use the existing M8 device model and data.

Provide analytics such as:

* total devices
* active devices
* inactive devices
* unknown-state devices
* packets per device
* bytes per device
* top talkers
* first seen
* last seen
* device activity over time where supported

Do not create a second device identity mechanism.

Do not add device risk scoring in M16.

Preserve the existing M8 limitation where routed traffic can cause the next-hop MAC to represent multiple remote IP addresses.

---

# 8. Connection Analytics

Use M9 connection data.

Provide:

* total connections
* active connections
* connections by protocol
* connections by status
* top source devices/addresses
* top destination devices/addresses
* connection duration statistics where available
* connection activity over time where practical

Do not modify M9 connection-tracking behavior.

Do not introduce connection risk scoring.

---

# 9. Threat Analytics

Use the existing M10, M11 and M12 data.

Analytics may include:

### Findings

* total findings
* findings by rule
* findings by severity
* findings by confidence
* findings over time

### Alerts

* total alerts
* alerts by severity
* alerts by lifecycle status
* alerts over time
* top alert/detection rules

### Incidents

* total incidents
* incidents by status
* incidents by risk band
* incident activity over time
* relationship between alerts and incidents where the existing references support it

Keep these concepts separate:

```text
Finding
Alert
Incident
Severity
Confidence
Risk
```

Do not calculate a new risk score.

Use the M12 risk information where it already exists.

Do not introduce ML or AI scoring in M16.

---

# 10. Time and Aggregation

Follow the M13 time conventions.

HTTP time filters use ISO-8601 UTC.

Where applicable:

* `since` = inclusive
* `until` = exclusive

Use explicit and predictable aggregation rules.

Examples of supported behavior may include:

```text
short range  → smaller buckets
long range   → larger buckets
```

Do not make the behavior arbitrary.

Document the selected aggregation rules.

All returned timestamps must follow the existing API convention.

---

# 11. API Requirements

Verify and implement:

```text
GET /api/v1/analytics/traffic
GET /api/v1/analytics/protocols
GET /api/v1/analytics/devices
GET /api/v1/analytics/connections
GET /api/v1/analytics/threats
```

All endpoints must follow the existing M13 response envelope.

They must provide:

* validation
* sensible defaults
* explicit maximum limits
* correct empty responses
* consistent error handling
* stable response schemas
* bounded results

Do not expose stack traces or internal implementation details.

Do not break the TypeScript models already used by M15.

---

# 12. Empty and Unavailable Data

Maintain the project's existing distinction:

```text
0        = known value is zero
empty    = valid query with no records
unknown  = value was not reported
unavailable = backend section could not be read
```

Do not silently convert unavailable or unknown information into `0`.

---

# 13. Performance Requirements

Analytics must remain suitable for the current local SQLite architecture.

Avoid:

* loading the entire packet database into Python unnecessarily
* unbounded queries
* N+1 queries
* repeated expensive aggregation
* unnecessary duplicate calculations

Prefer SQL-side aggregation where appropriate.

Add database indexes only when justified by the analytics query patterns.

Performance measurements must be local development measurements only.

Do not make production-scale claims.

---

# 14. Testing

Add tests for each analytics area.

### Traffic

Test:

* empty data
* normal data
* time filtering
* aggregation
* bucket limits
* source/destination ranking
* packet totals
* byte totals

### Protocols

Test:

* empty data
* multiple protocols
* percentages
* unknown protocol
* zero totals

### Devices

Test:

* no devices
* active/inactive/unknown states
* traffic attribution
* top talkers
* timestamps

### Connections

Test:

* no connections
* protocol aggregation
* status aggregation
* active connections
* duration where supported

### Threats

Test:

* findings
* rules
* severity
* confidence
* alerts
* alert lifecycle
* incidents
* incident risk bands
* incident status
* time filtering

### API

Test:

* defaults
* validation
* maximum limits
* response schemas
* empty results
* error handling

All existing M0–M15 tests must continue to pass.

---

# 15. Type and Contract Verification

Compare the actual running API responses with the schemas already consumed by M15.

Do not assume that existing documentation and implementation are identical.

If a schema mismatch is found:

1. identify the actual backend contract
2. determine the correct source of truth
3. update the implementation consistently
4. add a regression test
5. document the change

Do not use `any` for backend-derived TypeScript data.

---

# 16. Documentation

Create:

```text
docs/13_M16_Analytics_Design.md
```

The document should contain:

1. Purpose
2. Scope
3. Non-goals
4. Architecture position
5. Data sources
6. Analytics architecture
7. Traffic analytics
8. Protocol analytics
9. Device analytics
10. Connection analytics
11. Threat analytics
12. Time-window and aggregation rules
13. API contracts
14. Validation and error handling
15. Performance considerations
16. Testing and verification
17. Known limitations
18. Completion checklist
19. M16 closure

Keep the documentation focused only on M16.

Do not document future ML/AI work as implemented.

---

# 17. M16 Non-Goals

The following are explicitly outside M16:

* ML anomaly detection
* behavioral baselines
* AI explanations
* local LLM/Ollama
* automatic blocking
* IPS functionality
* SIEM integrations
* threat-intelligence integrations
* authentication/RBAC
* report generation
* notification delivery
* distributed sensors

These belong to later milestones.

---

# 18. Verification

Run:

```text
Backend test suite
Analytics-specific tests
API tests
Pyright/type checking
M15 frontend unit tests
M15 live integration tests where affected
Production/frontend build where affected
Analytics performance measurements
```

Verify the five analytics endpoints against the actual running backend.

Use real captured/persisted data for manual verification.

No mock data may be used to claim successful integration.

---

# 19. Completion Criteria

M16 is complete only when:

* [ ] Analytics architecture is implemented
* [ ] Traffic analytics work
* [ ] Protocol analytics work
* [ ] Device analytics work
* [ ] Connection analytics work
* [ ] Threat analytics work
* [ ] Time filtering works
* [ ] Aggregation is bounded
* [ ] API validation works
* [ ] Empty/unavailable states are handled correctly
* [ ] Existing M13 API conventions are preserved
* [ ] M15 frontend remains compatible
* [ ] Analytics tests pass
* [ ] Full regression suite passes
* [ ] Pyright/type checking passes
* [ ] Performance baseline is recorded
* [ ] Manual verification with real data succeeds
* [ ] `docs/13_M16_Analytics_Design.md` is complete

Only after all items are verified should the document status be changed to:

**Status: implemented and verified**

---

# 20. Final Implementation Report

At completion, provide:

* files created
* files modified
* analytics architecture implemented
* five analytics endpoints and their outputs
* important design decisions
* tests added
* total test result
* type-check result
* performance measurements
* known limitations
* confirmation whether M16 is ready to close

Do not claim anything that was not actually implemented or verified.

```

