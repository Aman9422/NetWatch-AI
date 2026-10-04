# NetWatch AI — Current Task

**Current Phase:** Base Application Implementation
**Current Milestone:** M13 — REST API
**Status:** ✅ Complete — implemented, verified, tested and baselined

---

# Current Objective

Build and consolidate the REST API layer for NetWatch AI.

M10 provides detection findings.
M11 provides alerts and evidence.
M12 provides correlated incidents and risk scores.

M13 exposes the implemented backend capabilities through a consistent, documented REST API for:

- Capture
- Packets
- Statistics
- Devices
- Connections
- Detection findings
- Alerts
- Evidence
- Correlated incidents
- Baselines
- Analytics
- Reports
- Settings
- System status
- Notifications
- Dashboard data

The REST API becomes the main HTTP interface consumed later by the frontend.

---

# M13 Architecture

The API layer should remain thin.

Preferred flow:

    HTTP Request
         ↓
    API Route
         ↓
    Request Validation
         ↓
    Service / Manager
         ↓
    Repository / Runtime State
         ↓
    Response Schema
         ↓
    HTTP Response

Do not place business logic directly inside route handlers.

---

# M13 Development Rule

Do NOT implement:

- New detection logic
- New alert logic
- New correlation logic
- New risk-scoring logic
- ML
- AI
- WebSockets
- Frontend code
- Automatic blocking
- External SIEM integrations
- Authentication/RBAC unless explicitly introduced as a separate requirement

M13 exposes existing functionality.

It does not redesign earlier milestones.

---

# M13.1 — Review Existing API Surface

Review all currently implemented API endpoints from:

- M3
- M4
- M6
- M8
- M9
- M10
- M11
- M12

Identify:

- Existing routes
- Existing response envelopes
- Existing error codes
- Existing schemas
- Existing duplicated routes
- Inconsistent naming
- Inconsistent validation

Do not break working functionality unnecessarily.

---

# M13.2 — API Structure

Use a consistent structure such as:

    app/api/v1/
        __init__.py
        capture.py
        packets.py
        statistics.py
        devices.py
        connections.py
        detection.py
        alerts.py
        evidence.py
        incidents.py
        baselines.py
        analytics.py
        reports.py
        settings.py
        system.py
        notifications.py
        dashboard.py

The exact file organization may follow existing project conventions.

---

# M13.3 — API Versioning

Maintain:

    /api/v1/

as the base route.

Do not introduce `/api/v2/`.

Do not expose unversioned production routes unless required for health/system operation.

---

# M13.4 — Response Envelope

Standardize successful responses.

Example:

    {
      "success": true,
      "data": {...}
    }

For collections:

    {
      "success": true,
      "data": {
        "items": [...],
        "total": 100,
        "limit": 50,
        "offset": 0
      }
    }

Use the project's existing response conventions where they already exist.

Do not create multiple incompatible response formats.

---

# M13.5 — Error Envelope

Standardize API errors.

Example:

    {
      "success": false,
      "error": {
        "code": "RESOURCE_NOT_FOUND",
        "message": "Connection not found"
      }
    }

Avoid exposing:

- Stack traces
- Internal filesystem paths
- Database internals
- Sensitive implementation details

Error messages should be useful to an API consumer.

---

# M13.6 — HTTP Status Codes

Use appropriate status codes.

Examples:

    200 OK
    201 Created
    204 No Content
    400 Bad Request
    404 Not Found
    409 Conflict
    422 Validation Error
    500 Internal Server Error

Use existing milestone-specific behavior where it is already defined.

Do not arbitrarily change established error semantics without documenting the reason.

---

# M13.7 — Capture API

Consolidate:

    GET  /api/v1/capture/interfaces
    GET  /api/v1/capture/interface
    PUT  /api/v1/capture/interface
    GET  /api/v1/capture/status
    POST /api/v1/capture/start
    POST /api/v1/capture/stop

Expose:

- Selected interface
- Capture state
- Packet count
- Session information

Do not expose raw internal objects directly.

---

# M13.8 — Packet API

Expose persisted packet information.

Suggested endpoints:

    GET /api/v1/packets
    GET /api/v1/packets/{packet_id}

Support filters such as:

    source_ip
    destination_ip
    protocol
    source_port
    destination_port
    interface
    start_time
    end_time

Support pagination/limits.

Do not return packet payloads unless explicitly supported.

Respect M7's payload-storage policy.

---

# M13.9 — Statistics API

Expose M6 statistics.

Suggested endpoints:

    GET /api/v1/statistics/traffic
    GET /api/v1/statistics/protocols
    GET /api/v1/statistics/top-talkers
    GET /api/v1/statistics/ports

Expose current runtime statistics.

Do not recalculate statistics inside API routes.

---

# M13.10 — Device API

Expose M8 device information.

Suggested endpoints:

    GET /api/v1/devices
    GET /api/v1/devices/{device_id}

Support filters:

    status
    ip
    mac
    limit

Return:

- Identity
- IP addresses
- MAC address where available
- First seen
- Last seen
- Packet count
- Byte count
- Status

Do not calculate risk here.

---

# M13.11 — Connection API

Consolidate M9 connection endpoints.

Suggested endpoints:

    GET /api/v1/connections
    GET /api/v1/connections/active
    GET /api/v1/connections/{connection_id}

Support filters:

    protocol
    source_ip
    destination_ip
    source_port
    destination_port
    device_id
    state

Use bounded responses.

---

# M13.12 — Detection API

Expose M10 detection findings.

Suggested endpoints:

    GET /api/v1/detections
    GET /api/v1/detections/{finding_id}

Support filters:

    rule_id
    source_ip
    destination_ip
    device_id
    protocol
    start_time
    end_time

Do not allow API routes to trigger detector logic directly.

---

# M13.13 — Alert API

Expose M11 alerts.

Suggested endpoints:

    GET  /api/v1/alerts
    GET  /api/v1/alerts/{alert_id}
    POST /api/v1/alerts/{alert_id}/acknowledge
    POST /api/v1/alerts/{alert_id}/resolve
    POST /api/v1/alerts/{alert_id}/dismiss
    POST /api/v1/alerts/{alert_id}/false-positive

Support filters:

    severity
    status
    rule_id
    source_ip
    destination_ip
    device_id
    start_time
    end_time

Use the existing M11 lifecycle validation.

Do not duplicate lifecycle rules inside routes.

---

# M13.14 — Evidence API

Expose alert evidence where appropriate.

Suggested endpoints:

    GET /api/v1/alerts/{alert_id}/evidence
    GET /api/v1/evidence/{evidence_id}

Evidence should reference the underlying resource rather than duplicating packet payloads.

---

# M13.15 — Incident API

Expose M12 correlated incidents.

Suggested endpoints:

    GET /api/v1/incidents
    GET /api/v1/incidents/{incident_id}
    GET /api/v1/incidents/open

Support filters:

    status
    source
    device_id
    connection_id
    rule_id
    min_risk_score
    max_risk_score
    start_time
    end_time

Expose:

- Incident identity
- Member alerts/findings
- Correlation reasons
- Correlation confidence
- Risk score
- Risk band
- Timestamps
- Lifecycle status

Do not recalculate risk in the API layer.

---

# M13.16 — Incident Lifecycle API

Support controlled incident updates using the M12 transition rules.

Suggested endpoints:

    POST /api/v1/incidents/{incident_id}/investigate
    POST /api/v1/incidents/{incident_id}/resolve
    POST /api/v1/incidents/{incident_id}/dismiss

Invalid transitions must return a controlled error.

Do not allow routes to bypass M12 lifecycle validation.

---

# M13.17 — Baseline API

The roadmap reserves a baseline API.

For the current base application:

- Expose only functionality that actually exists.
- If behavioral baselines are not implemented, return an appropriate unavailable/not-implemented response rather than fake data.

Do not implement the behavioral baseline engine as part of M13.

---

# M13.18 — Analytics API

Expose currently available analytics/statistics.

Suggested routes:

    GET /api/v1/analytics/traffic
    GET /api/v1/analytics/protocols
    GET /api/v1/analytics/devices
    GET /api/v1/analytics/connections
    GET /api/v1/analytics/threats

Only expose data backed by implemented services.

Do not create simulated analytics.

---

# M13.19 — Dashboard API

Create a consolidated dashboard endpoint if useful.

Suggested:

    GET /api/v1/dashboard/summary

Possible data:

    capture status
    packets observed
    traffic rate
    device count
    active connections
    open alerts
    active incidents
    recent detections

The dashboard endpoint should aggregate existing services.

It must not duplicate business logic.

---

# M13.20 — Reports API

Expose report functionality only to the extent currently implemented.

Suggested:

    GET /api/v1/reports
    GET /api/v1/reports/{report_id}

Do not implement PDF/CSV generation here unless already part of the current report milestone.

M17 owns report generation.

---

# M13.21 — Settings API

Expose safe application settings.

Suggested:

    GET /api/v1/settings
    PUT /api/v1/settings

Do not expose sensitive secrets.

Separate:

    readable settings
    mutable settings
    internal-only configuration

Validate all changes.

---

# M13.22 — System API

Expose system state.

Suggested:

    GET /api/v1/system/status
    GET /api/v1/system/health
    GET /api/v1/system/info

Possible information:

- Application version
- Environment
- Capture state
- Database state
- Service state
- Basic runtime metrics

Do not expose secrets or internal security-sensitive configuration.

---

# M13.23 — Notifications API

Expose notification records if the existing notification model/service exists.

Suggested:

    GET /api/v1/notifications
    GET /api/v1/notifications/{notification_id}

If notification integrations are not implemented, do not fake external notifications.

---

# M13.24 — Pagination

Standardize collection pagination.

At minimum support:

    limit
    offset

or another consistent strategy already used by the project.

Requirements:

- Default page size
- Maximum page size
- Validation
- Deterministic ordering

Do not allow unlimited result sets by default.

---

# M13.25 — Filtering and Validation

Validate:

- IP addresses
- Ports
- Protocols
- Enumerated states
- Severity values
- Time ranges
- Risk-score ranges
- Pagination parameters

Invalid values should return controlled validation errors.

Never silently convert bad values into unrelated valid values.

---

# M13.26 — Time Handling

Standardize API timestamps.

Prefer a documented format such as ISO-8601 UTC for API responses.

Internally existing modules may use:

    epoch seconds
    datetime

Conversion should happen at the API boundary.

Do not create multiple competing timestamp conventions.

---

# M13.27 — OpenAPI Documentation

Ensure all M13 endpoints are visible in:

    /docs
    /redoc
    /openapi.json

Document:

- Parameters
- Query filters
- Request bodies
- Response schemas
- Error responses
- Status codes

Use Pydantic schemas rather than arbitrary dictionaries where practical.

---

# M13.28 — Dependency Injection

Use FastAPI dependency injection where useful for:

- Services
- Managers
- Configuration
- Database sessions

Avoid creating new singleton instances inside route functions.

Existing process-level services should be reused according to the current architecture.

---

# M13.29 — API Error Isolation

An API failure must not crash:

- Packet capture
- Packet processing
- Statistics
- Device tracking
- Connection tracking
- Detection
- Alerting
- Correlation

The API should translate internal failures into controlled HTTP responses.

---

# M13.30 — Security Boundary

M13 is currently a local application API.

Do not add authentication/RBAC unless explicitly required.

However:

- Do not expose secrets.
- Validate all input.
- Avoid arbitrary filesystem access.
- Avoid arbitrary SQL through query parameters.
- Bound result sizes.
- Avoid returning internal exception traces.

Document the local-development security assumption.

---

# M13.31 — Tests — Capture

Test:

    interfaces
    selected interface
    status
    start
    stop

Verify:

- Validation
- HTTP status codes
- Response schema
- Existing M4 behavior remains intact

---

# M13.32 — Tests — Data APIs

Test:

- Packets
- Statistics
- Devices
- Connections
- Detections

Verify:

- Filters
- Pagination
- Empty results
- Results with data
- Unknown resource
- Validation
- Response schemas

---

# M13.33 — Tests — Alerts and Incidents

Test:

- Alert listing
- Alert retrieval
- Alert lifecycle endpoints
- Evidence retrieval
- Incident listing
- Incident retrieval
- Incident lifecycle
- Risk score exposure
- Correlation reasons
- Invalid transitions

Ensure API actions use the underlying service rules.

---

# M13.34 — Tests — Common API Behavior

Test:

- Standard response envelope
- Standard error envelope
- 404 handling
- 400 validation
- 409 conflicts
- 422 validation
- 500 internal error handling
- Pagination boundaries
- Time-range validation
- Deterministic ordering
- OpenAPI generation

---

# M13.35 — Integration Tests

Verify complete HTTP flows such as:

    Capture
      ↓
    Packet Processing
      ↓
    Statistics / Devices / Connections
      ↓
    Detection
      ↓
    Alert
      ↓
    Correlation
      ↓
    Incident
      ↓
    REST API

Use controlled local/lab data.

---

# M13.36 — Manual Verification

Start the FastAPI application and verify:

    /docs
    /redoc
    /openapi.json

Then test the main API groups:

    capture
    packets
    statistics
    devices
    connections
    detections
    alerts
    incidents
    dashboard
    system

Verify that responses contain real backend data rather than mock data.

---

# M13.37 — Performance Baseline

Measure:

- Simple endpoint latency
- List endpoint latency
- Filtered query latency
- Paginated query latency
- Dashboard summary latency
- JSON serialization cost
- Database query time

Test representative result sizes.

Do not claim production-scale API throughput.

---

# M13 Completion Criteria

M13 is complete when:

- API structure is consolidated under `/api/v1`.
- Existing APIs follow consistent conventions.
- Capture API works.
- Packet API works.
- Statistics API works.
- Device API works.
- Connection API works.
- Detection API works.
- Alert API works.
- Evidence API works.
- Incident API works.
- Dashboard summary API works.
- Analytics API exposes implemented data.
- Reports API exposes implemented report data only.
- Settings API is validated and does not expose secrets.
- System API works.
- Notifications API works where implemented.
- Pagination is standardized.
- Filtering is validated.
- Time handling is consistent.
- Error responses are standardized.
- OpenAPI documentation is complete.
- API failures are isolated from backend processing.
- Unit/API tests pass.
- Integration tests pass.
- Manual verification succeeds.
- Performance baseline is recorded.

---

# M13 Completion Record

M13 is complete: the consolidated `/api/v1` surface is implemented, verified,
tested and baselined.

**What shipped**

* 16 API groups under `/api/v1` — capture, packets, statistics, devices,
  connections, detections, alerts, evidence, incidents, baselines, analytics,
  reports, settings, system, notifications and dashboard.
* A shared API layer — `app/api/common/` (envelope, errors, pagination,
  validation) — and `app/api/v1/deps.py` for dependency injection.
* One response envelope, one error envelope, one pagination contract, one
  validation path, and ISO-8601 UTC at the boundary.

**Verification**

* Full suite: **1639 passed**. pyright: **0 errors, 0 warnings, 0 informations**.
  The API suite is **534 tests**.
* `backend/scripts/verify_m13.py` — `sample` mode drives controlled packets
  through the real M4→M12 pipeline over a throwaway SQLite file and then serves
  the real application. Every documented surface answered, all 16 groups appear
  in `/openapi.json`, the success and error envelopes hold, an unknown route is a
  404, an out-of-range page a 422, an unknown severity a 400, a malformed
  timestamp a 400, the alert and incident lifecycle verbs reach the M11/M12 rules
  and a terminal state refuses a further move, `/settings` withholds a seeded
  secret key, and the unbuilt capabilities answer 501 rather than inventing data.
  `live` mode starts the application under uvicorn and exercises the documented
  URLs over real HTTP.
* `backend/scripts/benchmark_m13.py` — the M13.37 baseline. The figures are
  recorded in `docs/TODO.md`.

**Boundaries held**

No new detection, alert, correlation or risk-scoring logic; no ML/AI; no
WebSockets; no frontend code; no automatic blocking; no external SIEM
integration; no authentication/RBAC; no report generation. M13 exposed what
M3–M12 implemented and did not redesign them.

**One observation to re-measure**

The filtered `/packets` measurement had `destination_port=443` costing more than
the unfiltered page (24.4 ms against 10.8 ms over a 10,000-row store). It is
recorded as observed rather than explained. If the store grows, that filter is
the first thing to re-measure.

**Next**

M14 — WebSockets, layered on this surface.

---

# Architecture Boundary

M13 exposes:

    Existing NetWatch Services
            ↓
        REST API
            ↓
        HTTP Clients
            ↓
    Future React Frontend

M13 does not implement:

    WebSockets
    Frontend
    ML
    AI
    New Detection
    New Correlation
    Automatic Response

M14 will implement WebSockets.
M15 will connect the React frontend.
