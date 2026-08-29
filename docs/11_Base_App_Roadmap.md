# NetWatch AI — Base Application Roadmap

**Project:** NetWatch AI
**Roadmap:** Base Application v1
**Status:** Ready for Implementation

---

# 1. Purpose

This roadmap defines the implementation sequence for the first fully functional version of NetWatch AI.

The objective is to transform the existing Figma-generated frontend prototype into a working local network monitoring and security analytics application.

The base application should establish the complete core pipeline:

```text
Network Interface
      ↓
Packet Capture
      ↓
Packet Processing
      ↓
Feature Extraction
      ↓
Statistics / Device Discovery
      ↓
Detection
      ↓
Database
      ↓
FastAPI
      ↓
REST + WebSocket
      ↓
React Dashboard
```

Advanced AI capabilities, large-scale integrations, distributed sensors, and enterprise functionality are deliberately excluded from the initial base implementation.

---

# 2. Base Application Definition

The base application is considered complete when a user can:

1. Start NetWatch AI.
2. Select a network interface.
3. Start packet capture.
4. Capture real network packets.
5. Normalize packet metadata.
6. Store relevant packet information.
7. Calculate real-time traffic statistics.
8. Discover and track devices.
9. Display real data in the Figma-designed dashboard.
10. Detect initial suspicious behaviors.
11. Generate alerts.
12. View alert evidence.
13. Receive real-time WebSocket updates.
14. Stop packet capture safely.

---

# 3. Development Strategy

Development will proceed from the lowest-level system components upward.

```text
Foundation
   ↓
Database
   ↓
Capture
   ↓
Processing
   ↓
Statistics
   ↓
Devices
   ↓
Detection
   ↓
API
   ↓
WebSocket
   ↓
Frontend Integration
   ↓
Testing
```

This prevents the frontend from being connected to incomplete backend components.

---

# 4. Phase 0 — Repository Preparation

## Objective

Create the final repository structure before implementation.

### Tasks

* Create Git repository.
* Create `.gitignore`.
* Create `.env.example`.
* Create backend directory.
* Create frontend directory.
* Place Figma Make export under `frontend/`.
* Create docs directory.
* Create tests directory.
* Create sample-data directory.
* Create README skeleton.

### Expected Result

```text
NetWatch-AI/
├── backend/
├── frontend/
│   └── figma-design/
├── docs/
├── tests/
├── sample_data/
├── screenshots/
├── scripts/
├── README.md
├── .gitignore
└── .env.example
```

---

# 5. Phase 1 — Backend Foundation

## Objective

Create a working FastAPI backend.

### Tasks

* Create Python virtual environment.
* Create dependency configuration.
* Install FastAPI.
* Install Uvicorn.
* Create application entry point.
* Create configuration module.
* Create health endpoint.
* Configure logging.
* Configure environment variables.
* Create initial API structure.

### Initial endpoint

```text
GET /api/v1/health
```

### Expected Result

```json
{
  "status": "healthy"
}
```

---

# 6. Phase 2 — Database Foundation

## Objective

Create the initial SQLite database.

### Tasks

* Configure SQLAlchemy.
* Create database connection.
* Enable foreign keys.
* Create database models.
* Create database initialization.
* Create repository layer.
* Add initial indexes.
* Add development seed data where required.

### Initial tables

```text
devices
packets
connections
alerts
alert_evidence
detection_rules
behavioral_baselines
traffic_statistics
protocol_statistics
ai_insights
reports
settings
system_status
notifications
```

### Expected Result

FastAPI can successfully connect to SQLite and perform basic CRUD operations.

---

# 7. Phase 3 — Network Interface Manager

## Objective

Allow the application to discover available network interfaces.

### Tasks

* Detect interfaces.
* Normalize interface information.
* Expose interfaces through the API.
* Add selected-interface configuration.
* Handle unavailable interfaces.

### API

```text
GET /api/v1/capture/interfaces
```

### Expected Result

The Settings page can display actual interfaces on the host machine.

---

# 8. Phase 4 — Packet Capture Engine

## Objective

Capture real packets from an authorized interface.

### Technology

Scapy

### Tasks

* Create capture manager.
* Start capture.
* Stop capture.
* Track capture state.
* Handle capture exceptions.
* Support interface selection.
* Maintain packet counters.
* Prevent duplicate capture sessions.

### API

```text
GET  /api/v1/capture/status
POST /api/v1/capture/start
POST /api/v1/capture/stop
```

### Expected Result

The system can start and stop real packet capture.

---

# 9. Phase 5 — Packet Processing

## Objective

Convert raw Scapy packets into normalized internal data.

### Tasks

* Parse Ethernet information.
* Parse IP information.
* Parse TCP.
* Parse UDP.
* Parse ICMP.
* Extract ports.
* Extract packet length.
* Extract TTL.
* Extract TCP flags.
* Add timestamp.
* Handle unsupported packets.
* Handle malformed packets.

### Expected Result

A captured packet becomes a normalized internal object.

---

# 10. Phase 6 — Packet Persistence

## Objective

Store required packet metadata in SQLite.

### Tasks

* Create packet repository.
* Insert normalized packets.
* Implement batch writes where practical.
* Add packet indexes.
* Add packet retention mechanism.
* Avoid storing full payloads by default.

### Expected Result

Captured network activity can be queried through the database.

---

# 11. Phase 7 — Statistics Engine

## Objective

Generate real-time network metrics.

### Metrics

* Packets/sec
* Bytes/sec
* Active connections
* Active devices
* Protocol distribution
* Top talkers
* Top ports
* Average packet size

### Tasks

* Create in-memory counters.
* Create time-window aggregation.
* Store historical summaries.
* Expose dashboard metrics.

### Expected Result

Dashboard statistics represent actual network activity.

---

# 12. Phase 8 — Device Discovery

## Objective

Build the first real device inventory.

### Tasks

* Detect source/destination devices.
* Match existing devices.
* Create new devices.
* Update last-seen time.
* Track packet counts.
* Track traffic volume.
* Track online/offline status.

### API

```text
GET /api/v1/devices
GET /api/v1/devices/{device_id}
```

### Expected Result

The Devices page displays actual observed devices.

---

# 13. Phase 9 — Connection Tracking

## Objective

Aggregate packets into useful connection/session information.

### Tasks

* Identify flows.
* Track source/destination.
* Track ports.
* Track protocol.
* Count packets.
* Count bytes.
* Track connection start/end.
* Track connection status.

### Expected Result

The application can display meaningful connection-level information instead of only individual packets.

---

# 14. Phase 10 — Base Detection Engine

## Objective

Introduce the first security detections.

### Initial detectors

1. Port Scan
2. SYN Flood
3. ICMP Flood
4. Internal Network Scan
5. High Bandwidth Usage

DNS anomaly and suspicious-port detection may be added after the first five are stable.

### Tasks

* Create detection context.
* Create rule interface.
* Create temporary detection state.
* Implement first detectors.
* Create standardized detection results.
* Create detection logging.

### Expected Result

Real network activity can generate detection results.

---

# 15. Phase 11 — Alert Engine

## Objective

Convert detection results into persistent security alerts.

### Tasks

* Create alert service.
* Create alert records.
* Store detection evidence.
* Assign severity.
* Calculate initial confidence.
* Implement alert status.
* Implement deduplication.
* Link alerts to devices.
* Link alerts to packets/connections.

### Alert States

```text
new
acknowledged
investigating
resolved
false_positive
```

### Expected Result

The Alerts page shows real security findings.

---

# 16. Phase 12 — Correlation and Risk Scoring

## Objective

Combine multiple detection signals into meaningful findings.

### Tasks

* Create correlation window.
* Group related events.
* Implement duplicate suppression.
* Implement initial risk scoring.
* Separate risk from confidence.
* Add asset context.

### Expected Result

Multiple related detections can become one higher-quality security finding.

Example:

```text
Port Scan
   +
High SYN Rate
   +
Failed Connections
       ↓
Correlated Finding
       ↓
Risk Score
```

---

# 17. Phase 13 — REST API

## Objective

Expose real backend data to the frontend.

Implement priority endpoints:

```text
/dashboard
/capture/*
/packets
/devices/*
/alerts/*
/analytics/*
/detection-rules/*
/settings/*
/system/*
```

### Tasks

* Create API routers.
* Create Pydantic schemas.
* Connect services.
* Connect repositories.
* Add validation.
* Add error handling.
* Add pagination.

### Expected Result

The frontend can retrieve real backend data.

---

# 18. Phase 14 — WebSocket Service

## Objective

Provide real-time updates.

### Channels

```text
/ws/dashboard
/ws/packets
/ws/alerts
/ws/system
```

### Tasks

* Create WebSocket manager.
* Create event types.
* Publish dashboard metrics.
* Publish new packets.
* Publish new alerts.
* Publish system status.
* Handle disconnects.
* Handle reconnects.

### Expected Result

The frontend updates without page refreshes.

---

# 19. Phase 15 — Figma Frontend Integration

## Objective

Replace mock Figma data with real backend data.

### First

Keep the existing UI.

Do not redesign it.

### Replace

```text
Math.random()
Static arrays
Mock packets
Fake devices
Fake alerts
Simulated timers
```

with:

```text
REST API
WebSocket
Real database data
Real network telemetry
```

---

# 20. Dashboard Integration

Connect:

```text
GET /dashboard
GET /dashboard/traffic
GET /dashboard/protocols
GET /dashboard/top-talkers
```

WebSocket:

```text
/ws/dashboard
```

### Expected Result

Dashboard KPIs and charts show live network information.

---

# 21. Live Traffic Integration

Connect:

```text
GET /packets
GET /packets/{id}
```

WebSocket:

```text
/ws/packets
```

### Expected Result

The Live Traffic page displays captured packets in real time.

---

# 22. Device Integration

Connect:

```text
GET /devices
GET /devices/{id}
GET /devices/{id}/traffic
GET /devices/{id}/connections
GET /devices/{id}/alerts
```

### Expected Result

Device inventory contains real devices.

---

# 23. Alert Integration

Connect:

```text
GET /alerts
GET /alerts/{id}
GET /alerts/{id}/evidence
```

and state-management endpoints:

```text
POST /alerts/{id}/acknowledge
POST /alerts/{id}/investigate
POST /alerts/{id}/resolve
POST /alerts/{id}/false-positive
```

WebSocket:

```text
/ws/alerts
```

### Expected Result

New alerts appear in the UI immediately.

---

# 24. Settings Integration

Connect:

```text
GET /settings
PUT /settings
GET /detection-rules
PUT /detection-rules/{id}
```

### Expected Result

Settings displayed in the UI affect backend behavior.

---

# 25. Phase 16 — Base Analytics

## Objective

Use real stored data for analytics.

Implement:

* Traffic history
* Protocol trends
* Top ports
* Top talkers
* Device traffic
* Threat trends

### Expected Result

Analytics are based on actual recorded data rather than generated datasets.

---

# 26. Phase 17 — Basic Reporting

## Objective

Generate actual reports.

### Initial formats

* CSV
* PDF

### Initial report content

* Traffic summary
* Devices
* Protocol statistics
* Alerts
* Threat summary

### Expected Result

A report can be generated from real database data.

---

# 27. Phase 18 — Testing

Testing should occur throughout development rather than only at the end.

### Required tests

* Packet parsing
* Feature extraction
* Database
* Device discovery
* Detection rules
* Alert generation
* Risk scoring
* API
* WebSocket
* Frontend
* End-to-end workflows

---

# 28. Phase 19 — Base Application Stabilization

Before adding AI or advanced ML:

### Verify

```text
Packet Capture          ✓
Packet Processing       ✓
Database                ✓
Statistics              ✓
Devices                 ✓
Connections             ✓
Detection               ✓
Alerts                  ✓
REST API                ✓
WebSockets              ✓
React Integration       ✓
Reports                 ✓
Tests                   ✓
```

Only after these are stable should advanced ML and AI development begin.

---

# 29. Base Application Definition of Done

The Base Application is considered complete when the following workflow works:

```text
Start NetWatch AI
       ↓
Select Interface
       ↓
Start Capture
       ↓
Real Packets Captured
       ↓
Packets Normalized
       ↓
Statistics Updated
       ↓
Devices Discovered
       ↓
Connections Tracked
       ↓
Detection Runs
       ↓
Alert Generated
       ↓
Evidence Stored
       ↓
Risk Calculated
       ↓
REST / WebSocket
       ↓
React Dashboard
       ↓
Analyst Investigates Alert
       ↓
Report Generated
```

---

# 30. What Is NOT Part of the Base Application

Do not block Base Application completion on:

* Local LLM
* Advanced ML
* Threat intelligence
* MITRE automation
* Suricata
* Zeek
* Distributed sensors
* PostgreSQL
* Docker
* Slack
* Discord
* Autonomous blocking
* Enterprise authentication

These belong to later stages.

---

# 31. Base Application Milestones

```text
M0  Repository Setup
M1  FastAPI Foundation
M2  Database Foundation
M3  Network Interface Manager
M4  Packet Capture
M5  Packet Processing
M6  Packet Persistence
M7  Statistics Engine
M8  Device Discovery
M9  Connection Tracking
M10 Base Detection
M11 Alert Engine
M12 Correlation + Risk
M13 REST API
M14 WebSockets
M15 Frontend Integration
M16 Analytics
M17 Reports
M18 Testing
M19 Stabilization
M20 Base Application Release
```

---

# 32. Implementation Order

The actual implementation order should remain:

```text
1. Repository
2. Python Environment
3. FastAPI
4. Database
5. Configuration
6. Network Interfaces
7. Packet Capture
8. Packet Processing
9. Packet Storage
10. Statistics
11. Devices
12. Connections
13. Detection
14. Alerts
15. Correlation
16. Risk Scoring
17. REST API
18. WebSockets
19. React Integration
20. Analytics
21. Reports
22. Tests
23. Stabilization
```

---

# 33. Result of Base Application

At the end of this roadmap, NetWatch AI should be a functioning local application rather than only a UI prototype.

The resulting architecture:

```text
                         NETWORK
                            |
                            v
                    Scapy Capture
                            |
                            v
                  Packet Processing
                            |
                            v
                  Feature Extraction
                            |
              +-------------+-------------+
              |             |             |
              v             v             v
         Statistics      Devices      Detection
              |             |             |
              +-------------+-------------+
                            |
                            v
                      Alert Engine
                            |
                            v
                       Risk Score
                            |
                            v
                         SQLite
                            |
                    +-------+-------+
                    |               |
                    v               v
                 REST API       WebSocket
                    |               |
                    +-------+-------+
                            |
                            v
                      React UI
```

This is the **first major release target**.

Advanced ML and local AI are built on top of this foundation rather than being prerequisites for the base application.
