# NetWatch AI — Master TODO

## Project Status

**Current Stage:** Base Application Implementation
**Base Application:** In Progress
**Current Milestone:** M7 — Packet Persistence ✅ COMPLETE (next: M9 — Connection Tracking)

> Note: `docs/11_Base_App_Roadmap.md` numbers these M6 Persistence /
> M7 Statistics / M8 Device Discovery. In practice the Statistics Engine shipped
> as **M6** and **M7 (Packet Persistence) was deferred**, so Device Discovery
> shipped first as **M8** and Packet Persistence shipped afterwards as **M7**.
> With M5-M8 all complete, the next milestone is M9; M9 and later keep their
> roadmap numbers.

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

# M4 — Packet Capture ✅ COMPLETE

* [x] Install Scapy — 2.7.0 (pinned `scapy>=2.6.0` in `requirements.txt`)
* [x] Create capture manager — `app/services/capture_manager.py`
* [x] Start capture — `POST /api/v1/capture/start`
* [x] Stop capture — `POST /api/v1/capture/stop`
* [x] Track capture state — `stopped/starting/running/stopping/error`
* [x] Track packet count — live counter, preserved on stop
* [x] Handle capture errors — controlled `CaptureError` family
* [x] Prevent duplicate capture sessions — HTTP 409
* [x] Test authorized lab traffic — 1112 packets / 3s on `Wi-Fi`

---

# M5 — Packet Processing ✅ COMPLETE

* [x] Create packet parser — `app/processing/processor.py` (`PacketProcessor`)
* [x] Parse Ethernet — source/destination MAC, normalized
* [x] Parse IPv4/IPv6 — addresses + IP version + protocol number
* [x] Parse TCP — ports + flags
* [x] Parse UDP — ports
* [x] Parse ICMP — identified
* [x] Extract ports — TCP/UDP source + destination
* [ ] Extract TTL — deferred (not required by the M5 spec; to be populated in
      M6 persistence — the `Packet.ttl` column already exists)
* [x] Extract TCP flags — compact string form (e.g. `PA`, `S`)
* [x] Extract packet length — from the captured frame
* [x] Add timestamp — capture time (epoch seconds)
* [x] Create normalized packet model — `app/schemas/packet.py`
* [x] Handle malformed packets — controlled `PacketProcessingError`, isolated
      so one bad packet never stops capture

**Notes:** DNS identified (over UDP/TCP); ARP and unknown packets classified as
`ARP`/`OTHER` without crashing. Verification script: `backend/scripts/verify_m5.py`.
Full suite: 106 passed, pyright 0 errors. Real capture: 2496 normalized / 0 errors.

---

# M6 — Traffic Statistics Engine ✅ COMPLETE

* [x] Statistics manager — `app/statistics/manager.py` (`TrafficStatisticsManager`)
* [x] Packet count — total and per protocol
* [x] Byte count — total, per protocol and per direction
* [x] Protocol statistics — TCP/UDP/ICMP/DNS/ARP/IPv4/IPv6/Other + percentage
* [x] Source statistics — top source IPs
* [x] Destination statistics — top destination IPs
* [x] Port statistics — source and destination ports
* [x] Traffic direction — inbound / outbound / local / unknown
* [x] Time windows — 1s, 10s, 60s
* [x] Throughput — packets/sec, bytes/sec, bits/sec
* [x] Top talkers — sources, destinations, conversations (by packets or bytes)
* [x] Thread safety — per-structure locking, lock-free reads where possible
* [x] Memory management — bounded counters + bucketed rate windows
* [x] Pipeline integration — a statistics failure never stops capture
* [x] Statistics API — `GET /api/v1/statistics/{traffic,protocols,top-talkers,ports}`
* [x] Reset — `POST /api/v1/statistics/reset`
* [x] Unit tests — `test_statistics.py`, `test_statistics_windows.py` (M6.18)
* [x] API tests — `test_statistics_api.py` (M6.19)
* [x] Integration test — `test_statistics_pipeline.py` (M6.20)
* [x] Manual verification — `backend/scripts/verify_m6.py` (M6.21)
* [x] Performance baseline — `backend/scripts/benchmark_m6.py` (M6.22)

**Verification:** full suite 186 passed; pyright 0 errors.
**Baseline (this machine):** ~12,000 packets/sec, ~84 us/packet, 0.25 MiB heap
(bounded), API 1-3 ms. Not a production-capacity claim.

---

# M7 — Packet Persistence ✅ COMPLETE

> Deferred: the Statistics Engine shipped as M6 and Device Discovery shipped as
> M8, so Packet Persistence kept the M7 number. It shipped after M8 and is the
> last stage of the shared M5/M6/M7/M8 packet pipeline.

* [x] Review the M2 `packets` model + define the mapping (M7.1/M7.2) —
      `app/persistence/mapping.py`
* [x] Create packet repository (M7.3) — `app/repositories/packet.py`
* [x] Store normalized packet metadata (M7.4)
* [x] Avoid payload storage by default (M7.5) — `payload_length` stays NULL
* [x] Add batch write strategy (M7.6) — configurable `batch_size` + `flush_interval`
* [x] Flush behaviour (M7.7) — size, interval, stop, shutdown, explicit
* [x] Persistence worker (M7.8) — background thread, off the capture path
* [x] Bounded queue / buffer (M7.9) — oldest-eviction, counted
* [x] Database transactions (M7.10) — per-batch commit, rollback on failure
* [x] Persistence error isolation (M7.11) — a DB failure never stops capture
* [x] Packet indexes (M7.12) — added `source_port`, `destination_port`
* [x] Implement retention (M7.13) — `PACKET_RETENTION_DAYS`
* [x] Retention cleanup (M7.14) — `app/persistence/retention.py`
* [x] Packet query service (M7.15) — `app/services/packet_query.py`
* [x] Internal packet API (M7.16) — `GET /api/v1/packets`; dev/testing only
* [x] Pipeline integration (M7.17) — independent of statistics + device discovery
* [x] Capture stop / shutdown handling (M7.18) — flush on stop and on shutdown
* [x] Unit tests (M7.19) — mapping, buffer, worker, facade, retention
* [x] Database tests (M7.20) — repository + query service
* [x] Integration test (M7.21) — `tests/test_persistence_pipeline.py`
* [x] Manual verification (M7.22) — `backend/scripts/verify_m7.py` (sample mode)
* [x] Retention verification (M7.23) — `verify_m7.py` retention check
* [x] Performance baseline (M7.24) — `backend/scripts/benchmark_m7.py`

**Verification:** full suite 453 passed; pyright 0 errors. `verify_m7.py` sample
mode: 4/4 packets persisted with the expected values, no payload stored, and
retention deleted only the expired row while keeping recent ones.
**Baseline (this machine, `--packets 100000`, OneDrive-synced disk):** mapping +
buffering ~220,000-585,000 packets/sec; SQLite write ~4,900-6,650 packets/sec
(~150-205 us/packet) — the per-commit cost dominates on this disk. Larger batches
raised throughput and latency together (batch 1000: 6,646/s @ 150 ms; batch 100:
4,867/s @ 20 ms). Buffer footprint bounded at 50,000 rows ≈ 24.8 MiB. Not a
production-capacity claim.
**Design decisions:** field mapping and payload policy are documented in
`app/persistence/mapping.py`; the persistence architecture is in
`docs/Current_Task.md` (M7).

> Deliberately out of scope for M7: detection, alerts, behavioural baselines,
> correlation, risk scoring, ML/AI, WebSockets, frontend integration and
> external SIEM integrations. M7 only stores and queries packet metadata.

---

# M8 — Device Discovery & Device Tracking ✅ COMPLETE

* [x] Device identity rules — `app/devices/identity.py` (M8.2/M8.7/M8.8)
* [x] MAC normalization — every spelling resolves to one canonical form (M8.7)
* [x] IP normalization — IPv4 + IPv6, canonicalized (M8.8)
* [x] Endpoint extraction — `app/devices/endpoints.py` (M8.5)
* [x] Device record — `app/devices/device.py` (`ObservedDevice`) (M8.3/M8.4)
* [x] Detect devices from normalized packets (M8.1)
* [x] MAC-based identity with IP fallback (M8.2)
* [x] Match existing devices + update last seen (M8.4)
* [x] Track packet count + byte count, per direction (M8.5)
* [x] Multiple IP addresses per device (M8.6)
* [x] Device status — active / inactive / unknown (M8.9)
* [x] Local device identification from the M3/M4 interfaces (M8.10)
* [x] Hostname support — off by default, never blocks capture (M8.11)
* [x] Vendor interface — no OUI database shipped in M8 (M8.12)
* [x] Device lifecycle + configurable expiration (M8.13/M8.14)
* [x] Device registry — MAC/IP mappings, conflict + upgrade rules (M8.16)
* [x] Thread safety — registry lock + bounded capacity (M8.15)
* [x] Pipeline integration — a discovery failure never stops capture (M8.17)
* [x] Device API — `GET /api/v1/devices`, `GET /api/v1/devices/{device_id}` (M8.18/M8.19)
* [x] Unit tests — `tests/test_device_identity.py`, `tests/test_devices.py` (M8.20)
* [x] API tests — `tests/test_devices_api.py` (M8.21)
* [x] Integration test — `tests/test_devices_pipeline.py` (M8.22)
* [x] Manual verification — `backend/scripts/verify_m8.py` (M8.23)
* [x] Performance baseline — `backend/scripts/benchmark_m8.py` (M8.24)

**Verification:** full suite 316 passed; pyright 0 errors.
**Baseline (this machine):** ~53,800 packets/sec, ~18.6 us/packet, 2,048 devices
discovered, registry 1.47 MiB (bounded by the 4,096-device cap), API 3.62 ms
(list) / 0.89 ms (detail). Not a production-capacity claim.
**Design:** `docs/12_M8_Device_Discovery_Design.md`.

> Deliberately out of scope for M8: trust/risk scoring (removed from the old
> "Device Discovery" checklist), detection, alerts, baselines and ML.

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
