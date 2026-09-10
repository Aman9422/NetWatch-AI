# NetWatch AI — Master TODO

## Project Status

**Current Stage:** Base Application Implementation
**Base Application:** In Progress
**Current Milestone:** M3 — Network Interface Manager (M0–M2 complete)

---

# M0 — Repository Setup

* [x] Create repository structure
* [x] Extract Figma Make project into `frontend/`
* [x] Create `.gitignore`
* [x] Create `.env.example`
* [x] Create `tests/`
* [x] Create `sample_data/`
* [x] Create `scripts/`
* [x] Verify documentation structure

---

# M1 — FastAPI Foundation

* [x] Create Python virtual environment — `backend/.venv` (Python 3.13.2)
* [x] Create backend package structure
* [x] Create FastAPI application
* [x] Add Uvicorn — 0.52.4 (plain, not `[standard]`)
* [x] Add configuration management
* [x] Add logging
* [x] Add `/api/v1/health`
* [x] Verify Swagger documentation
* [x] Verify ReDoc

---

# M2 — Database Foundation ✅ COMPLETE

* [x] Install SQLAlchemy
* [x] Configure SQLite
* [x] Create database session
* [x] Enable foreign keys
* [x] Create models
* [x] Create repositories
* [x] Create indexes
* [x] Create database initialization
* [x] Add seed data
* [x] Test CRUD operations

---

# M3 — Network Interface Manager ✅ COMPLETE

* [x] Detect network interfaces
* [x] Normalize interface information
* [x] Create interface service
* [x] Create `/capture/interfaces`
* [x] Create interface validation
* [x] Test available interfaces
* [x] Handle unavailable interfaces

---

# M4 — Packet Capture

* [ ] Install Scapy
* [ ] Create capture manager
* [ ] Start capture
* [ ] Stop capture
* [ ] Track capture state
* [ ] Track packet count
* [ ] Handle capture errors
* [ ] Prevent duplicate capture sessions
* [ ] Test authorized lab traffic

---

# M5 — Packet Processing

* [ ] Create packet parser
* [ ] Parse Ethernet
* [ ] Parse IPv4/IPv6
* [ ] Parse TCP
* [ ] Parse UDP
* [ ] Parse ICMP
* [ ] Extract ports
* [ ] Extract TTL
* [ ] Extract TCP flags
* [ ] Extract packet length
* [ ] Add timestamp
* [ ] Create normalized packet model
* [ ] Handle malformed packets

---

# M6 — Packet Persistence

* [ ] Create packet repository
* [ ] Store normalized packet metadata
* [ ] Add batch write strategy
* [ ] Add packet indexes
* [ ] Implement retention
* [ ] Avoid payload storage by default
* [ ] Test packet queries

---

# M7 — Statistics Engine

* [ ] Packet rate
* [ ] Byte rate
* [ ] Bandwidth
* [ ] Active devices
* [ ] Active connections
* [ ] Protocol statistics
* [ ] Top talkers
* [ ] Top ports
* [ ] Average packet size
* [ ] Time-window aggregation
* [ ] Historical statistics
* [ ] Dashboard statistics service

---

# M8 — Device Discovery

* [ ] Detect devices
* [ ] Create device records
* [ ] Match existing devices
* [ ] Update last seen
* [ ] Track packet count
* [ ] Track byte count
* [ ] Track device status
* [ ] Calculate initial trust context
* [ ] Device API
* [ ] Device tests

---

# M9 — Connection Tracking

* [ ] Identify flows
* [ ] Track source/destination
* [ ] Track ports
* [ ] Track protocol
* [ ] Track packet counts
* [ ] Track byte counts
* [ ] Track start/end time
* [ ] Track connection status
* [ ] Connection tests

---

# M10 — Base Detection

## Port Scan

* [ ] Create rule interface
* [ ] Create detection context
* [ ] Implement port scan detector
* [ ] Configurable threshold
* [ ] Time window
* [ ] SYN ratio
* [ ] Failed connection ratio
* [ ] Unit tests

## SYN Flood

* [ ] Implement detector
* [ ] SYN rate calculation
* [ ] Incomplete connection tracking
* [ ] Unit tests

## ICMP Flood

* [ ] Implement detector
* [ ] Configurable threshold
* [ ] Unit tests

## Internal Scan

* [ ] Implement detector
* [ ] Unique destination calculation
* [ ] Unit tests

## High Bandwidth

* [ ] Implement detector
* [ ] Baseline/threshold comparison
* [ ] Unit tests

---

# M11 — Alert Engine

* [ ] Create alert service
* [ ] Create alert schema
* [ ] Store alerts
* [ ] Store evidence
* [ ] Assign severity
* [ ] Calculate confidence
* [ ] Link alert to device
* [ ] Link alert to packets
* [ ] Alert lifecycle
* [ ] Alert deduplication
* [ ] False-positive state
* [ ] Alert tests

---

# M12 — Correlation + Risk Scoring

* [ ] Create correlation engine
* [ ] Correlation time window
* [ ] Group related events
* [ ] Deduplicate related findings
* [ ] Add rule contribution
* [ ] Add behavioral contribution
* [ ] Add ML contribution placeholder
* [ ] Add asset context
* [ ] Add historical context
* [ ] Create risk scoring engine
* [ ] Separate risk and confidence
* [ ] Test risk boundaries

---

# M13 — REST API

* [ ] Dashboard API
* [ ] Capture API
* [ ] Packet API
* [ ] Device API
* [ ] Alert API
* [ ] Evidence API
* [ ] Detection Rule API
* [ ] Baseline API
* [ ] Analytics API
* [ ] Settings API
* [ ] System API
* [ ] Reports API
* [ ] Notifications API
* [ ] Input validation
* [ ] Pagination
* [ ] Error handling

---

# M14 — WebSockets

* [ ] WebSocket manager
* [ ] `/ws/dashboard`
* [ ] `/ws/packets`
* [ ] `/ws/alerts`
* [ ] `/ws/system`
* [ ] Connection handling
* [ ] Disconnect handling
* [ ] Reconnection support
* [ ] Event schemas
* [ ] WebSocket tests

---

# M15 — Frontend Integration

* [ ] Review Figma Make code
* [ ] Remove mock packet generation
* [ ] Remove mock devices
* [ ] Remove mock alerts
* [ ] Remove simulated dashboard metrics
* [ ] Create API service layer
* [ ] Create TypeScript types
* [ ] Create WebSocket hook
* [ ] Connect Dashboard
* [ ] Connect Live Traffic
* [ ] Connect Devices
* [ ] Connect Alerts
* [ ] Connect Analytics
* [ ] Connect Reports
* [ ] Connect Settings
* [ ] Add error states
* [ ] Add loading states
* [ ] Add empty states

---

# M16 — Analytics

* [ ] Real traffic charts
* [ ] Protocol analytics
* [ ] Top ports
* [ ] Top talkers
* [ ] Device traffic
* [ ] Threat trends
* [ ] Connection trends
* [ ] Time-range filtering

---

# M17 — Reporting

* [ ] CSV generation
* [ ] PDF generation
* [ ] Daily report
* [ ] Weekly report
* [ ] Custom report
* [ ] Report history
* [ ] Report download
* [ ] Report tests

---

# M18 — Testing

* [ ] Packet parser tests
* [ ] Feature extraction tests
* [ ] Database tests
* [ ] Device tests
* [ ] Connection tests
* [ ] Detection tests
* [ ] Alert tests
* [ ] Correlation tests
* [ ] Risk scoring tests
* [ ] API tests
* [ ] WebSocket tests
* [ ] Frontend tests
* [ ] End-to-end tests
* [ ] Performance tests
* [ ] Security tests

---

# M19 — Stabilization

* [ ] Fix critical bugs
* [ ] Fix high-priority bugs
* [ ] Review logs
* [ ] Review memory usage
* [ ] Review database growth
* [ ] Review WebSocket stability
* [ ] Review packet processing performance
* [ ] Verify error handling
* [ ] Verify deployment instructions
* [ ] Verify clean installation

---

# M20 — Base Application Release

* [ ] Full end-to-end workflow verified
* [ ] Real packet capture verified
* [ ] Dashboard uses real data
* [ ] Detection verified in lab
* [ ] Alerts verified
* [ ] Reports verified
* [ ] API verified
* [ ] WebSockets verified
* [ ] Tests passing
* [ ] README updated
* [ ] Screenshots updated
* [ ] Demo recording created
* [ ] GitHub repository cleaned
* [ ] Version tagged

---

# Later — Advanced Features

These are intentionally excluded from the Base Application milestone.

* [ ] Behavioral baselines
* [ ] Advanced ML anomaly detection
* [ ] Local LLM
* [ ] AI analyst
* [ ] MITRE ATT&CK
* [ ] PCAP analysis
* [ ] Threat intelligence
* [ ] Suricata integration
* [ ] Zeek integration
* [ ] Authentication
* [ ] RBAC
* [ ] PostgreSQL
* [ ] Docker
* [ ] Distributed sensors
* [ ] Notification integrations
* [ ] Advanced incident response
