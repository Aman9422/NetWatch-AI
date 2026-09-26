# NetWatch AI — Master TODO

## Project Status

**Current Stage:** Base Application Implementation
**Base Application:** In Progress
**Current Milestone:** M11 — Alert Engine ✅ COMPLETE (next: M12 — Correlation + Risk Scoring)

> Note: `docs/11_Base_App_Roadmap.md` numbers these M6 Persistence /
> M7 Statistics / M8 Device Discovery. In practice the Statistics Engine shipped
> as **M6** and **M7 (Packet Persistence) was deferred**, so Device Discovery
> shipped first as **M8** and Packet Persistence shipped afterwards as **M7**.
> With M5-M9 all complete, the next milestone is M10; M10 and later keep their
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

# M9 — Connection Tracking ✅ COMPLETE

* [x] Review M5 `NormalizedPacket`, the M8 device registry and the M2
      `connections` model; define identity, direction, state and expiration (M9.1) —
      `docs/13_M9_Connection_Tracking_Design.md`
* [x] `ConnectionTracker` service, no direct Scapy dependency (M9.2) —
      `app/connections/manager.py`
* [x] Deterministic 5-tuple identity for TCP/UDP/ICMP (M9.3) —
      `app/connections/identity.py`
* [x] Bidirectional conversation handling (M9.4)
* [x] Canonical bidirectional key + preserved direction (M9.5)
* [x] Runtime `Connection` model, only observed values populated (M9.6) —
      `app/connections/connection.py`
* [x] First seen / last seen (M9.7)
* [x] Packet, byte and directional counters (M9.8)
* [x] TCP tracking — ports, flags, counters, timestamps (M9.9)
* [x] TCP state logic — observed/established/closing/closed, no full state machine
      (M9.10) — `app/connections/tcp.py`, `app/connections/state.py`
* [x] UDP tracking — active/inactive/unknown, never TCP-style states (M9.11)
* [x] ICMP tracking — portless bidirectional conversation (M9.12)
* [x] IPv4 + IPv6, canonicalized addresses (M9.13)
* [x] Device association via the M8 registry; unknown stays unknown (M9.14)
* [x] Configurable per-protocol expiration (M9.15)
* [x] Active vs historical state — non-destructive retirement (M9.16)
* [x] Persistence to the existing `connections` table, aggregates only (M9.17) —
      `app/connections/persistence.py`, `app/connections/mapping.py`
* [x] Memory management — bounded active/historical caps, documented cleanup (M9.18) —
      `app/connections/registry.py`
* [x] Thread safety — one registry `RLock`, lock-free records (M9.19)
* [x] Pipeline integration, failure-isolated (M9.20) —
      `app/services/packet_pipeline.py`, `app/services/capture_manager.py`
* [x] Connection queries with filtering and limits, no detection logic (M9.21)
* [x] Internal read-only verification API (M9.22) — `app/api/v1/connections.py`
* [x] Unit tests — `tests/test_connection_identity.py`, `tests/test_connections.py` (M9.23)
* [x] Integration test — `tests/test_connections_pipeline.py` (M9.24)
* [x] Database tests — `tests/test_connection_persistence.py` (M9.25)
* [x] Manual verification — `backend/scripts/verify_m9.py` (M9.26)
* [x] Performance baseline — `backend/scripts/benchmark_m9.py` (M9.27)

**Verification:** full suite 669 passed; pyright 0 errors, 0 warnings.
**Baseline (this machine, `--packets 200000 --flows 20000`):** ~30,600 packets/sec,
~32.7 us/packet, ~20,000 new conversations/sec; single-connection lookup 0.42 us;
100-connection listing 5.4 ms (dominated by building 100 pydantic views); an idle
sweep retires 20,000 conversations in 27.4 ms (1.37 us each); registry footprint
4.79 MiB at 5,000 conversations, bounded by the 8,192-active / 1,024-historical
caps; API 8.14 ms (list) / 7.92 ms (active) / 1.57 ms (detail). Not a
production-capacity claim.
**Design:** `docs/13_M9_Connection_Tracking_Design.md`.

> Deliberately out of scope for M9: threat detection, detection rules, alerts,
> behavioural baselines, correlation, risk scoring, ML/AI, automatic blocking,
> WebSockets, frontend integration and SIEM integrations. M9 only groups
> normalized packets into network conversations.

---

# M10 — Base Detection ✅ COMPLETE

* [x] Review M5 `NormalizedPacket`, M6 rates, M8 devices, M9 connections and the
      existing configuration; define the detection context, rule interface,
      finding schema and error isolation (M10.1) —
      `docs/14_M10_Detection_Engine_Design.md`
* [x] Detection package structure (M10.2) — `app/detection/` + `rules/`
* [x] Common rule interface (M10.3) — `app/detection/base.py` (`DetectionRule`)
* [x] Detection context, no global application state (M10.4) —
      `app/detection/context.py` (`DetectionContext`, `DetectionWindow`)
* [x] Normalized finding model, no severity or risk score (M10.5/M10.15) —
      `app/detection/finding.py` (`DetectionFinding`, `threshold_confidence`)
* [x] Detection engine — registration, evaluation, failure isolation,
      diagnostics (M10.6/M10.17) — `app/detection/engine.py`
* [x] Rule configuration in `Settings`, sensible documented defaults (M10.7) —
      `app/detection/rules/__init__.py` (`build_default_rules`)
* [x] Port Scan detector — distinct destination ports in a window, threshold +
      SYN ratio (M10.8) — `app/detection/rules/port_scan.py`
* [x] SYN Flood detector — SYN rate per destination, pure-SYN only, minimum of
      two SYNs (M10.9) — `app/detection/rules/syn_flood.py`
* [x] ICMP Flood detector — ICMP rate per destination, normal ping stays silent
      (M10.10) — `app/detection/rules/icmp_flood.py`
* [x] Internal Scan detector — distinct internal destinations, external traffic
      ignored by construction (M10.11) — `app/detection/rules/internal_scan.py`
* [x] High Bandwidth detector — consumes the M6 rate, minimum interval between
      findings (M10.12) — `app/detection/rules/high_bandwidth.py`
* [x] Explicit detection windows, inclusive start / exclusive end (M10.13) —
      `DetectionWindow`
* [x] Evidence on every finding, drawn from observed data (M10.14)
* [x] Descriptive false-positive-aware wording (M10.16)
* [x] Minimal rule-level suppression only, no alert deduplication (M10.18)
* [x] Bounded detector state (M10.19) — `WindowedCounter`, `WindowedDistinct`
* [x] Thread safety — engine lock + per-rule locks, rules evaluated off the table
      lock (M10.20)
* [x] Pipeline integration, detection runs last and is failure-isolated (M10.21) —
      `app/services/packet_pipeline.py`, `app/services/capture_manager.py`
* [x] Internal read-only verification API + queries (M10.22) —
      `app/api/v1/detections.py`, `app/detection/history.py`
* [x] Framework tests (M10.23) — `tests/test_detection_framework.py`
* [x] Port scan tests (M10.24) — `tests/test_detection_port_scan.py`
* [x] SYN flood tests (M10.25) — `tests/test_detection_syn_flood.py`
* [x] ICMP flood tests (M10.26) — `tests/test_detection_icmp_flood.py`
* [x] Internal scan tests (M10.27) — `tests/test_detection_internal_scan.py`
* [x] High bandwidth tests (M10.28) — `tests/test_detection_high_bandwidth.py`
* [x] Pipeline integration tests (M10.29) — `tests/test_detection_pipeline.py`
* [x] API tests (M10.22) — `tests/test_detections_api.py`
* [x] Manual verification (M10.30) — `backend/scripts/verify_m10.py`
* [x] Performance baseline (M10.31) — `backend/scripts/benchmark_m10.py`

**Verification:** detection suite 190 passed (framework 55, port scan 18,
SYN flood 19, ICMP flood 16, internal scan 16, high bandwidth 12, pipeline 19,
API 33; fakes shared). `verify_m10.py` sample mode: all five detectors fired with
evidence, 0 rule failures.
**Baseline (this machine, `--packets 100000 --flows 10000`):** ~107,600
packets/sec, ~9.29 us/packet with detection enabled (~0.03 us/packet with the
engine disabled, so ~9.26 us/packet of detection overhead); per-detector cost
0.9-3.5 us/packet (internal scan most expensive); detector state bounded
(2 subjects tracked); API 4.91 ms (`/detections` limit 100) / 1.23 ms
(`/detections/rules`). Not a production-capacity claim.
**Design:** `docs/14_M10_Detection_Engine_Design.md`.

> Deliberately out of scope for M10: alerts, alert lifecycle, alert deduplication,
> correlation, risk scoring, behavioural baselines, ML/AI anomaly detection,
> automatic blocking, WebSockets, frontend integration and SIEM integrations.
> A detection finding is an observation, not an alert; M11 converts findings into
> alerts.

---

# M11 — Alert Engine ✅ COMPLETE

* [x] Review the M10 `DetectionFinding`, the M2 `alerts` / `alert_evidence`
      models, the repositories and the config; define the runtime alert model,
      severity mapping, confidence handling, lifecycle, dedup key/window and
      evidence mapping (M11.1) — `docs/15_M11_Alert_Engine_Design.md`
* [x] Alert service (M11.2) — `app/alerts/service.py` (`AlertService`)
* [x] Runtime alert model, frozen value (M11.3) — `app/alerts/alert.py`
* [x] Alert severity, independent of confidence (M11.4) — `app/alerts/severity.py`
* [x] Confidence preserved separately from severity (M11.5)
* [x] Alert lifecycle statuses + validated transitions (M11.6/M11.19) —
      `app/alerts/status.py`
* [x] Alert creation from a finding, finding remains identifiable (M11.7)
* [x] Detection-to-alert rule mapping for the five M10 detectors (M11.8) —
      `app/alerts/mapping.py`
* [x] Alert deduplication key (M11.9) — `app/alerts/dedup.py`
* [x] Bounded, configurable deduplication window (M11.10)
* [x] Alert evidence, bounded and reference-based (M11.11) — `app/alerts/evidence.py`
* [x] Evidence model mapped onto the existing `alert_evidence` table (M11.12)
* [x] Packet evidence references persisted packets, no duplication (M11.13)
* [x] Connection evidence references M9 conversations (M11.14)
* [x] Device association from the M8 registry, never invented (M11.15)
* [x] Alert persistence via the existing schema (M11.16) — `app/alerts/persistence.py`
* [x] Alert repository (M11.17) — `app/repositories/alert.py`
* [x] Alert queries / filters, bounded and ordered (M11.18) — `app/alerts/queries.py`
* [x] Invalid lifecycle transitions rejected (M11.19)
* [x] Controlled status updates + `updated_at` (M11.20)
* [x] Finding-to-alert error isolation (M11.21)
* [x] Alert processing pipeline consumer (M11.22) — `app/alerts/engine.py`
* [x] Thread safety — atomic check-and-insert, per-call sessions (M11.23)
* [x] Alert configuration (M11.24) — `app/config/settings.py`
* [x] Tests — alert model (M11.25) — `tests/test_alerts_model.py`
* [x] Tests — alert creation (M11.26) — `tests/test_alerts_creation.py`
* [x] Tests — deduplication (M11.27) — `tests/test_alerts_dedup.py`
* [x] Tests — lifecycle (M11.28) — `tests/test_alerts_lifecycle.py`
* [x] Tests — evidence (M11.29) — `tests/test_alerts_evidence.py`
* [x] Tests — repository / database (M11.30) — `tests/test_alerts_repository.py`
* [x] Integration tests (M11.31) — `tests/test_alerts_integration.py`
* [x] Manual verification (M11.32) — `backend/scripts/verify_m11.py`
* [x] Performance baseline (M11.33) — `backend/scripts/benchmark_m11.py`

**Verification:** full suite 1077 passed; pyright 0 errors, 0 warnings. The M11
alert suite is 218 tests. `verify_m11.py` sample mode: all five mapped rules
produced an alert at the mapped severity with confidence preserved, rule +
behavioural + packet evidence stored (no payload copied), a repeat inside the
window folded in while one outside it created a new alert, and the lifecycle
applied `open → acknowledged → resolved` and rejected a reopen.
**Baseline (this machine, OneDrive-synced disk):** create path ~143 alerts/sec
(~6,995 us/alert — dominated by the per-alert SQLite commit on this disk);
deduplication path ~602 lookups/sec (~1,661 us/finding); evidence write overhead
~881 us/alert; heap after 500 alerts ~0.13 MiB (stored alerts live in SQLite);
API avg ~15 ms (`/alerts?limit=100`), ~3.8 ms (`/summary`), ~4.3 ms
(`/diagnostics`), ~5 ms (detail). Not a production-capacity claim.
**Schema note:** M11 widens the M2 `alerts.status` CHECK to the M11 vocabulary
(`open`/`acknowledged`/`resolved`/`dismissed`/`false_positive`) plus the legacy
`new`/`investigating` names, rebuilding the table in `app/database/upgrade.py`.
**Design:** `docs/15_M11_Alert_Engine_Design.md`.

> Deliberately out of scope for M11: correlation, risk scoring, behavioural
> baselines, ML/AI anomaly detection, automatic blocking, WebSockets, frontend
> integration and SIEM integrations. M10 detects; M11 alerts; M12 correlates and
> scores risk.

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
