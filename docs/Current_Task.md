# NetWatch AI — Current Task

**Current Phase:** Base Application Implementation
**Current Milestone:** M15 — Frontend Integration
**Status:** ✅ COMPLETE — implemented and verified

Milestone record: `docs/19_M15_Frontend_Integration.md`
(architecture, feature matrix, manual verification, defects found and fixed,
performance baseline, known limitations).

---

# Current Objective

Connect the existing NetWatch AI React/TypeScript frontend to the real backend.

M13 provides the REST API.

M14 provides WebSocket real-time events.

M15 replaces the Figma Make mock/simulated data with real backend data.

The main architecture becomes:

    React Frontend
         ↓
    API Service Layer
         ↓
    FastAPI REST API
         ↓
    NetWatch Backend

    React Frontend
         ↑
    WebSocket Hooks
         ↑
    FastAPI WebSockets
         ↑
    Real-Time Backend Events

The frontend must become a real client of the NetWatch backend.

---

# M15 Development Rule

Do NOT implement:

- New backend detection logic
- New alert logic
- New correlation logic
- New risk scoring
- ML
- AI
- New packet processing
- New database features
- New WebSocket backend functionality
- External SIEM integrations

M15 is frontend integration only.

Use the backend capabilities already implemented by M3–M14.

---

# M15.1 — Review Existing Figma Make Frontend

Review the existing frontend before changing it.

Current major pages:

    Dashboard
    Live Traffic
    Devices
    Alerts
    Analytics
    Reports
    Settings

Review:

- Existing component structure
- Existing routing
- Existing mock data
- Existing timers
- `Math.random()`
- `setInterval`
- Static arrays
- Simulated packet generation
- Simulated device generation
- Simulated alert generation
- Existing charts
- Existing UI states

Do not destroy the original visual design unnecessarily.

The Figma design is the UI baseline.

---

# M15.2 — Preserve Original Figma Design

Keep the existing visual structure where practical.

Preserve:

- Layout
- Navigation
- Typography
- Cards
- Tables
- Charts
- Drawers
- Status indicators
- Icons
- Existing responsive behavior

Backend integration must not require redesigning the interface unless a real backend limitation requires it.

---

# M15.3 — Frontend Environment Configuration

Create/verify frontend environment configuration.

Expected variables:

    VITE_API_BASE_URL
    VITE_WS_BASE_URL

Example:

    VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
    VITE_WS_BASE_URL=ws://127.0.0.1:8000

Do not place backend secrets in Vite environment variables.

Remember:

    VITE_* variables are client-visible.

---

# M15.4 — API Service Layer

Create a dedicated API service layer.

Suggested structure:

    src/services/
        api.ts
        capture.ts
        packets.ts
        statistics.ts
        devices.ts
        connections.ts
        detections.ts
        alerts.ts
        incidents.ts
        analytics.ts
        dashboard.ts
        reports.ts
        settings.ts
        system.ts
        notifications.ts

The exact structure may follow existing conventions.

Components should not make raw `fetch()` calls throughout the application.

---

# M15.5 — API Client

Create a shared HTTP client.

Responsibilities:

- Base URL
- Request handling
- JSON parsing
- Error handling
- Response envelope handling
- HTTP status handling
- Timeout handling where appropriate

The client should understand the project's standard response envelope:

    success
    message
    data
    errors

Do not duplicate response parsing in every page.

---

# M15.6 — TypeScript Models

Create TypeScript types corresponding to backend response schemas.

Suggested types:

    CaptureStatus
    Packet
    TrafficStatistics
    ProtocolStatistics
    Device
    Connection
    DetectionFinding
    Alert
    AlertEvidence
    Incident
    RiskScore
    DashboardSummary
    Report
    Setting
    SystemStatus
    Notification
    ApiError

Do not use `any` for backend data unless genuinely unavoidable.

---

# M15.7 — API Error Handling

Create a consistent frontend API error model.

Handle:

    network unavailable
    timeout
    400
    404
    409
    422
    500
    501

Show user-friendly error messages.

Do not expose backend stack traces.

---

# M15.8 — Loading / Empty / Error States

Every data-driven page must support:

    Loading
    Success
    Empty
    Error

Example:

    Loading devices...
          ↓
    Devices loaded
          or
    No devices observed
          or
    Unable to load devices

Do not leave blank screens when an API fails.

---

# M15.9 — Dashboard Integration

Replace simulated dashboard data.

Use:

    GET /api/v1/dashboard/summary

and real-time:

    /ws/dashboard

Connect:

- Packet count
- Packets/sec
- Bytes/sec
- Device count
- Active connections
- Open alerts
- Active incidents
- Capture state
- Interface

Do not calculate backend metrics independently in React.

---

# M15.10 — Live Traffic Integration

Replace mock packet generation.

Use:

    /ws/packets

Receive:

    packet.observed

Display real normalized packet data.

Possible fields:

    packet_id
    timestamp
    interface
    source_ip
    destination_ip
    protocol
    source_port
    destination_port
    length
    packet_type

Do not display packet payloads because M7/M14 intentionally do not expose them.

---

# M15.11 — Live Traffic Rate Control

The frontend must not assume every captured packet reaches the browser.

M14 intentionally limits packet WebSocket events.

The frontend should therefore:

- Handle event gaps
- Avoid assuming sequential packet IDs
- Avoid treating dropped packets as backend failure
- Keep rendering bounded

Use a bounded client-side packet list.

Do not keep unlimited packets in React state.

---

# M15.12 — Devices Integration

Replace mock devices.

Use:

    GET /api/v1/devices

Connect:

- Device identity
- IP addresses
- MAC
- First seen
- Last seen
- Packet count
- Byte count
- Status

Do not display a risk score because M8 does not provide one.

---

# M15.13 — Connections Integration

Connect the existing connection views to:

    GET /api/v1/connections
    GET /api/v1/connections/active
    GET /api/v1/connections/{id}

Use real:

- Source
- Destination
- Ports
- Protocol
- Packet counts
- Byte counts
- State
- Timestamps
- Device associations

Do not create frontend-side connection tracking.

---

# M15.14 — Alerts Integration

Replace mock alerts.

Use:

    GET /api/v1/alerts

Connect real alert data.

Use:

    /ws/alerts

for:

    alert.created
    alert.updated
    alert.acknowledged
    alert.resolved
    alert.dismissed
    alert.false_positive

The frontend must update existing alert rows when appropriate rather than blindly creating duplicates.

---

# M15.15 — Alert Actions

Connect:

    POST /api/v1/alerts/{id}/acknowledge
    POST /api/v1/alerts/{id}/resolve
    POST /api/v1/alerts/{id}/dismiss
    POST /api/v1/alerts/{id}/false-positive

Use backend lifecycle validation.

The frontend must not implement its own transition rules.

---

# M15.16 — Alert Evidence

Connect:

    GET /api/v1/alerts/{alert_id}/evidence
    GET /api/v1/evidence/{evidence_id}

Display references to:

- Packets
- Connections
- Findings
- Devices

Do not copy packet payloads.

---

# M15.17 — Incident Integration

Connect:

    GET /api/v1/incidents
    GET /api/v1/incidents/open
    GET /api/v1/incidents/{incident_id}

Display:

- Title
- Status
- Risk score
- Risk band
- Correlation confidence
- Alert confidence
- Severity
- Correlation reasons
- Related alerts
- Related findings
- Devices
- Connections
- Timeline

Keep:

    risk_score
    alert_confidence
    correlation_confidence

visually separate.

---

# M15.18 — Incident WebSocket Events

Handle from:

    /ws/alerts

Events:

    incident.created
    incident.updated
    incident.status_changed

Update the UI without requiring a full page refresh.

---

# M15.19 — Incident Lifecycle Actions

Connect:

    POST /api/v1/incidents/{id}/investigate
    POST /api/v1/incidents/{id}/resolve
    POST /api/v1/incidents/{id}/dismiss

Use backend validation.

Show errors when a lifecycle transition is rejected.

---

# M15.20 — Detection Integration

Connect:

    GET /api/v1/detections
    GET /api/v1/detections/{id}
    GET /api/v1/detections/rules

Display findings separately from alerts.

Do not represent every detection finding as an alert.

---

# M15.21 — Analytics Integration

Connect the real analytics APIs:

    GET /api/v1/analytics/traffic
    GET /api/v1/analytics/protocols
    GET /api/v1/analytics/devices
    GET /api/v1/analytics/connections
    GET /api/v1/analytics/threats

Replace static chart data.

Charts must render from backend responses.

---

# M15.22 — Reports Integration

Connect existing report metadata endpoints:

    GET /api/v1/reports
    GET /api/v1/reports/{id}

If report generation returns:

    501 FEATURE_NOT_IMPLEMENTED

the UI must display an appropriate unavailable state.

Do not create fake downloadable reports.

M17 owns report generation.

---

# M15.23 — Settings Integration

Connect:

    GET /api/v1/settings
    GET /api/v1/settings/{key}
    PUT /api/v1/settings

Respect backend restrictions.

Do not expose internal-only settings.

When the backend reports:

    restart_required

display that information clearly.

---

# M15.24 — System Integration

Connect:

    GET /api/v1/system/status
    GET /api/v1/system/health
    GET /api/v1/system/info

Display service state appropriately.

Do not invent frontend health metrics.

---

# M15.25 — Notifications Integration

Connect:

    GET /api/v1/notifications
    GET /api/v1/notifications/{id}

Use real stored notifications.

Do not imply that external notification delivery exists.

---

# M15.26 — WebSocket Service Layer

Create a reusable WebSocket client layer.

Suggested:

    src/services/websocket.ts

and/or:

    src/hooks/useWebSocket.ts

Responsibilities:

- Connect
- Disconnect
- Reconnect
- Parse event envelope
- Validate event type
- Expose connection state
- Handle errors
- Avoid duplicate connections

---

# M15.27 — WebSocket Reconnection

Handle:

    connected
    disconnected
    reconnecting
    reconnected

Do not replay unlimited historical events.

After reconnect:

    REST API
        ↓
    Refresh current state
        ↓
    WebSocket
        ↓
    Continue live updates

This follows the M14 design.

---

# M15.28 — WebSocket Channel Usage

Use separate connections where required:

    /ws/dashboard
    /ws/packets
    /ws/alerts
    /ws/system

Do not multiplex channels unless the frontend architecture explicitly needs it.

---

# M15.29 — WebSocket Event Deduplication

Use:

    event_id

where appropriate.

The frontend should avoid applying the same event twice.

Do not assume event sequences are gap-free because M14 can intentionally drop packet events.

---

# M15.30 — Dashboard Real-Time Updates

Dashboard should combine:

    Initial REST state
          +
    WebSocket updates

The REST API is the source for current state.

WebSockets are the real-time update mechanism.

Do not attempt to reconstruct all historical state from WebSocket events.

---

# M15.31 — Remove Mock Data

Remove or disable:

- `Math.random()`
- Mock packets
- Mock devices
- Mock alerts
- Mock dashboard metrics
- Simulated traffic
- Fake timers
- Fake API responses
- Mock chart datasets

Do not simply hide mock data while continuing to use it.

---

# M15.32 — React State Architecture

Define where backend data lives.

Use an appropriate strategy such as:

    Page state
    Custom hooks
    Shared context
    Query/cache layer

Do not introduce a large state-management library unless it provides real benefit.

Avoid unnecessary global state.

---

# M15.33 — Custom Hooks

Create reusable hooks where appropriate.

Examples:

    useDashboard()
    usePackets()
    useDevices()
    useConnections()
    useAlerts()
    useIncidents()
    useWebSocket()
    useSystemStatus()

Hooks should contain data-access behavior, while components focus on presentation.

---

# M15.34 — Refresh Strategy

Do not poll every endpoint continuously.

Use:

    REST
      ↓
    Initial/explicit data loading

and:

    WebSocket
      ↓
    Real-time updates

Use polling only where the backend currently has no WebSocket event for the required data.

---

# M15.35 — Frontend Routing

Review routing for:

    dashboard
    live traffic
    devices
    alerts
    analytics
    reports
    settings

Ensure route transitions do not create duplicate API/WebSocket subscriptions.

Cleanup must occur when components unmount.

---

# M15.36 — Frontend Performance

Keep frontend rendering bounded.

Particularly:

    Packet table
    Alert list
    Connection list

must not grow indefinitely.

Use:

- Bounded arrays
- Virtualization where necessary
- Memoization where justified
- Stable React keys

Do not optimize before measuring.

---

# M15.37 — Security Boundary

Do not place secrets in:

- React source
- `.env`
- WebSocket messages
- API request logs

Remember that Vite environment variables are client-visible.

Keep the existing local-development assumption.

---

# M15.38 — Tests

Create frontend tests for:

### API

- Successful response
- API error
- Network failure
- Validation failure

### Components

- Loading
- Empty
- Error
- Success

### WebSocket

- Connect
- Disconnect
- Reconnect
- Event parsing
- Event routing
- Duplicate event
- Invalid event
- Connection failure

### Pages

- Dashboard
- Live Traffic
- Devices
- Alerts
- Analytics
- Reports
- Settings

---

# M15.39 — Integration Tests

Test the real frontend against the backend.

Verify:

    FastAPI REST
        ↓
    React API service
        ↓
    Page data

and:

    FastAPI WebSocket
        ↓
    React WebSocket hook
        ↓
    UI update

Test the complete local application.

---

# M15.40 — Manual Verification

Start:

    FastAPI backend
    React frontend

Verify:

1. Dashboard loads real backend data.
2. Packet stream displays real normalized packets.
3. Devices display real observed devices.
4. Connections display real conversations.
5. Alerts display real alerts.
6. Incident data displays real correlation/risk information.
7. WebSocket events update the UI.
8. Disconnect/reconnect works.
9. REST data refresh works.
10. No mock data remains active.

---

# M15.41 — Manual Feature Matrix

Verify each major page:

    Dashboard         REST + WebSocket
    Live Traffic      WebSocket
    Devices           REST
    Alerts            REST + WebSocket
    Analytics         REST
    Reports           REST metadata
    Settings          REST
    System            REST
    Notifications     REST

Record any feature that remains unavailable because its backend milestone has not been implemented.

---

# M15.42 — Performance Baseline

Measure:

- Initial page load
- Dashboard API load time
- Packet event render rate
- Alert event render latency
- WebSocket reconnect time
- React memory usage during sustained packet streaming
- Maximum bounded packet rows
- Maximum bounded alert rows

Do not claim production-scale frontend performance.

---

# M15 Completion Criteria

M15 is complete when:

- Figma Make frontend has been reviewed.
- Original visual design is preserved where practical.
- API service layer exists.
- TypeScript backend types exist.
- API errors are handled consistently.
- Dashboard uses real data.
- Live Traffic uses real WebSocket packets.
- Devices use real data.
- Connections use real data.
- Detections use real data.
- Alerts use real data.
- Alert lifecycle actions work.
- Evidence works.
- Incidents use real data.
- Incident lifecycle actions work.
- Incident WebSocket events work.
- Analytics use real data.
- Reports use real metadata only.
- Settings use real backend data.
- System status uses real backend data.
- Notifications use real data.
- WebSocket reconnect works.
- WebSocket event deduplication works.
- Mock data is removed.
- Loading/empty/error states exist.
- Frontend state is bounded.
- Frontend tests pass.
- Backend/frontend integration tests pass.
- Manual end-to-end verification succeeds.
- Performance baseline is recorded.

---

# Current Immediate Task

**M15 is complete and verified.** The record — architecture, the M15.41 feature
matrix, the M15.40 manual verification, the defects the manual run found and their
fixes, the M15.42 performance baseline, and the known limitations — is
`docs/19_M15_Frontend_Integration.md`.

Every step of the original M15.1 plan was carried out: the Figma Make frontend was
reviewed; every mock-data source, simulated timer and generator was found and
removed; each page was mapped to its M13 REST endpoint and/or M14 WebSocket
channel; the API service layer, the TypeScript wire models, the WebSocket
service/hook layer, the four async states and the bounded client-side state were
defined and built; the Vite environment configuration was added; and the service,
component, WebSocket, page and live-integration suites were written.

**The immediate task is now M16 — Analytics**: back the remaining chart data with
the real analytics services (`GET /api/v1/analytics/*`, already implemented in
M13) and add the time-range filtering the roadmap asks for.

**One item is handed back and should be decided before it is forgotten:** device
identity on a routed path (`docs/19_M15_Frontend_Integration.md` §12 and §15). A
device record can end up keyed to the next hop — the gateway — and therefore hold
every far-end address it carried, because identity is MAC-first and the MAC is
taken from the captured frame. It is visible on the Devices page, it is not a
frontend defect, and correcting it is an M8 design decision.

---

# Architecture Boundary

M13 provides:

    REST API
        ↓
    Frontend API Services

M14 provides:

    WebSocket Events
        ↓
    Frontend WebSocket Services/Hooks

M15 provides:

    API + WebSocket
          ↓
    React Application
          ↓
    Real NetWatch UI

M15 does not implement new backend intelligence.

---
