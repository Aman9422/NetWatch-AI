# NetWatch AI — Master TODO

## Project Status

**Current Stage:** Base Application Implementation
**Base Application:** In Progress
**Current Milestone:** M14 — WebSockets ✅ COMPLETE (next: M15 — Frontend Integration)

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

# M12 — Correlation + Risk Scoring ✅ COMPLETE

* [x] Review the M10 `DetectionFinding`, the M11 `Alert` / `AlertEvidence`, the
      M8 devices, the M9 connections, the M7 packets, the existing models and
      config; define the correlation event, identity, incident and risk models
      (M12.1) — `docs/16_M12_Correlation_Design.md`
* [x] Correlation engine (M12.2) — `app/correlation/engine.py` (`CorrelationEngine`)
* [x] Normalized correlation event, references rather than packet copies (M12.3) —
      `app/correlation/event.py` (`CorrelationEvent`, `from_finding`, `from_alert`)
* [x] Explicit correlation identity dimensions (M12.4) — `app/correlation/identity.py`
* [x] Bounded, configurable correlation time window, inclusive edges (M12.5) —
      `app/correlation/window.py` (`CorrelationWindow`)
* [x] Documented relationships + which of them may anchor alone (M12.6) —
      `app/correlation/relationship.py` (6 weights, threshold 0.55)
* [x] Correlation confidence, separate from alert confidence and risk (M12.7) —
      `app/correlation/confidence.py` (noisy-OR, capped at 0.999)
* [x] Normalized `CorrelatedIncident` model, all fields derived (M12.8) —
      `app/correlation/incident.py`
* [x] Incident lifecycle + validated transitions, terminal states (M12.9) —
      `app/correlation/status.py`
* [x] Alert grouping — correlation references alerts, never replaces them (M12.10)
* [x] Correlation deduplication, distinct from M11's (M12.11) — the registry's
      bounded event-identity index
* [x] Five explicit correlation rules (M12.12) — `app/correlation/rules.py`
* [x] Risk scoring engine (M12.13) — `app/risk/engine.py` (`RiskScoringEngine`)
* [x] Bounded 0–100 score + four documented display bands (M12.14/M12.27) —
      `app/risk/bands.py`
* [x] Closed risk input model, no invented facts (M12.15) — `app/risk/inputs.py`
* [x] Risk and confidence kept structurally separate (M12.16)
* [x] Deterministic contribution model: seven bounded terms summing to 100 (M12.17) —
      `app/risk/contributions.py`
* [x] ML contribution placeholder = 0 / unavailable, future-proof (M12.18)
* [x] Asset context from M8 identity only, no invented criticality (M12.19)
* [x] Historical context, bounded and opt-in (M12.20)
* [x] Risk boundaries — 0 <= score <= 100 for every input including invalid (M12.21)
* [x] Bounded correlation state + safe expiration (M12.22) —
      `app/correlation/registry.py` (`IncidentRegistry`)
* [x] Thread safety — one lock across the read-decide-write step (M12.23)
* [x] Persistence onto the existing `alerts.risk_score` column, no new schema
      (M12.24) — `app/correlation/persistence.py`, `AlertRepository.update_risk_scores`
* [x] Pipeline integration, correlation last and failure-isolated (M12.25) —
      `app/services/packet_pipeline.py`, `app/services/capture_manager.py`
* [x] Internal bounded queries with deterministic ordering (M12.26)
* [x] Tests — correlation identity (M12.28/M12.29) —
      `tests/test_correlation_identity.py`, `tests/test_correlation_rules.py`
* [x] Tests — correlation engine + boundaries + dedup + lifecycle —
      `tests/test_correlation_engine.py`
* [x] Tests — risk scoring (M12.30) — `tests/test_risk_scoring.py`
* [x] Tests — risk/confidence separation (M12.31) — in `tests/test_risk_scoring.py`
* [x] Integration tests (M12.32) — `tests/test_correlation_integration.py`
* [x] Manual verification (M12.33) — `backend/scripts/verify_m12.py`
* [x] Performance baseline (M12.34) — `backend/scripts/benchmark_m12.py`

**Verification:** full suite 1271 passed; the M12 suite is 194 tests
(`test_correlation_engine` 40, `test_risk_scoring` 40, `test_correlation_identity`
29, `test_correlation_rules` 22, `test_correlation_persistence` 11,
`test_correlation_integration` 10; fakes shared). `verify_m12.py` sample mode:
two related alerts from one source formed **one** incident preserving both
alerts, `matched:scan_sequence` plus the shared source were recorded as explicit
reasons, same-source / same-destination / same-device / same-connection each
correlated, unrelated sources and out-of-window events stayed separate, a repeat
was deduplicated without growing the incident, every score was inside 0–100 and
reached `alerts.risk_score` with M11's severity and status untouched, the
retention sweep cleared incidents without deleting a single alert, the lifecycle
rejected a reopen, and the ML contribution was refused.
**Baseline (this machine, OneDrive-synced disk, defaults):** 85 distinct findings
correlated/sec (**11,726 us per finding** — the no-match path evaluates every
held incident, so N distinct incidents cost O(N²) evaluations and this term
dominates correlation cost); 595 alerts/sec (~1,680 us) when a match is found
early; deduplication 249,893/sec (4.0 us/lookup); risk calculation
33,776 scores/sec (29.6 us/score); incident → risk inputs 3.0 us; incident
queries 0.03–0.27 ms; 2,264 bytes of heap per held incident; the store's cap held
under overrun (1,792 evicted) and a 256-incident retention sweep took 0.18 ms.
Not a production-capacity claim.
**Schema note:** no new tables and no new columns. `alerts.risk_score` — which
M11 deliberately left at `0` for exactly this milestone, with a
`CHECK (risk_score BETWEEN 0 AND 100)` — is the one column M12 writes.
**Design:** `docs/16_M12_Correlation_Design.md`.

> Deliberately out of scope for M12: new detectors, new alert types, behavioural
> baselines, ML/AI anomaly detection, automatic blocking, WebSockets, frontend
> integration, the REST API and SIEM integrations. M12 groups and prioritises;
> it never acts.

---

# M13 — REST API ✅ COMPLETE

* [x] Audit the existing M3–M12 routes, envelopes, error codes and schemas before
      adding anything; fold duplicates and unify naming under `/api/v1` (M13.1)
* [x] Consolidated router layout (M13.2) — `app/api/v1/` (`capture`, `packets`,
      `statistics`, `devices`, `connections`, `detections`, `alerts`, `evidence`,
      `incidents`, `baselines`, `analytics`, `reports`, `settings`, `system`,
      `notifications`, `dashboard`) over shared `app/api/common/`
* [x] Versioned base `/api/v1`; no `/api/v2` and no unversioned production route (M13.3)
* [x] Standard success envelope (M13.4) — `{success, message, data}` with
      `count`/`total`/`limit`/`offset`/`has_more` for collections —
      `app/api/common/envelope.py`
* [x] Standard error envelope, no stack traces or filesystem paths (M13.5) —
      `app/api/common/errors.py`
* [x] HTTP status semantics (M13.6) — 200/201/204/400/404/409/422/500/501, with
      409 for a conflicting state and 501 where a capability is not built
* [x] Capture API (M13.7) — `interfaces`, `interface` (GET/PUT), `status`,
      `start`, `stop`; selected interface, state and packet count exposed
* [x] Packet API (M13.8) — list + detail with `source_ip`, `destination_ip`,
      `protocol`, `source_port`, `destination_port`, `since`, `until`; no payload
      is ever returned (M7.5)
* [x] Statistics API (M13.9) — `traffic`, `protocols`, `top-talkers`, `ports`,
      read from the M6 manager rather than recomputed in a route
* [x] Device API (M13.10) — list + detail with `status`/`ip`/`mac`/`limit`; no
      risk is calculated here
* [x] Connection API (M13.11) — list, `active`, detail, with
      protocol/endpoint/port/device/state filters
* [x] Detection API (M13.12) — findings + `rules`; a route never triggers a detector
* [x] Alert API (M13.13) — list, detail and the
      `acknowledge`/`resolve`/`dismiss`/`false-positive` verbs, all delegating to
      the M11 lifecycle rather than restating it
* [x] Evidence API (M13.14) — `/alerts/{id}/evidence` and `/evidence/{id}`;
      evidence references its resource and never duplicates a packet payload
* [x] Incident API (M13.15) — list, detail, `open`, exposing members,
      correlation reasons, confidence, risk score and band, never recomputed
* [x] Incident lifecycle API (M13.16) — `investigate`/`resolve`/`dismiss` through
      the M12 transition table; an invalid move is a controlled 409
* [x] Baseline API (M13.17) — refuses with `501 FEATURE_NOT_IMPLEMENTED` rather
      than returning invented data; no baseline engine was written in M13
* [x] Analytics API (M13.18) — `traffic`, `protocols`, `devices`, `connections`,
      `threats`, each backed by an implemented service
* [x] Dashboard API (M13.19) — `GET /dashboard/summary` aggregating the same
      services the individual routes read, with no duplicated business logic
* [x] Reports API (M13.20) — stored report metadata only; generation stays in M17
      and an unbuilt capability answers 501
* [x] Settings API (M13.21) — readable / mutable / internal-only split, validated
      writes, secrets withheld from every read
* [x] System API (M13.22) — `status`, `health`, `info`, with no secret in any payload
* [x] Notifications API (M13.23) — stored notification records only; no external
      notification is faked
* [x] Pagination (M13.24) — `limit`/`offset` with a documented default and
      maximum, validated, deterministic ordering and no unbounded default —
      `app/api/common/pagination.py`
* [x] Filter and parameter validation (M13.25) — addresses, ports, protocols,
      enumerations, severities, time ranges, risk ranges and paging; a bad value
      is refused, never silently converted into a valid one —
      `app/api/common/validation.py`
* [x] Time handling (M13.26) — ISO-8601 UTC at the API boundary, converted at the
      edge from the epoch seconds and `datetime`s the services hold
* [x] OpenAPI documentation (M13.27) — every route visible in `/docs`, `/redoc`
      and `/openapi.json` with parameters, filters, bodies, response models and
      error responses; Pydantic schemas rather than loose dictionaries
* [x] Dependency injection (M13.28) — services, managers, config and sessions
      resolved through `Depends`; no singleton is constructed inside a handler —
      `app/api/v1/deps.py`
* [x] API error isolation (M13.29) — an API failure cannot stop capture,
      processing, statistics, device tracking, connection tracking, detection,
      alerting or correlation
* [x] Security boundary (M13.30) — no secrets, all input validated, no arbitrary
      filesystem or SQL access through query parameters, bounded result sizes and
      no internal exception trace; the local-development assumption is documented
* [x] Tests — capture (M13.31) — interfaces, selection, status, start, stop,
      validation and a duplicate session's 409
* [x] Tests — data APIs (M13.32) — packets, statistics, devices, connections,
      detections: filters, paging, empty and populated results, unknown ids
* [x] Tests — alerts, evidence and incidents (M13.33) — listing, detail, the
      lifecycle verbs, evidence retrieval, risk exposure, correlation reasons and
      invalid transitions
* [x] Tests — common API behaviour (M13.34) — success and error envelopes, 404,
      400, 409, 422, paging boundaries, time-range validation, deterministic
      ordering and OpenAPI generation
* [x] Integration tests (M13.35) — capture → processing → statistics/devices/
      connections → detection → alert → correlation → incident → REST, over
      controlled local lab data
* [x] Manual verification (M13.36) — `backend/scripts/verify_m13.py`
      (`sample` drives the real pipeline then serves the real app; `live` starts
      the app under uvicorn and issues real HTTP requests)
* [x] Performance baseline (M13.37) — `backend/scripts/benchmark_m13.py`

**Verification:** full suite **1639 passed**; pyright **0 errors, 0 warnings,
0 informations**. The API suite is **534 tests** (`test_api_contract`,
`test_api_validation`, `test_api_integration`, plus one file per group: packets,
statistics, devices, connections, detections, alerts, evidence, incidents,
baselines, analytics, reports, settings, system, notifications, dashboard; fakes
shared in `tests/m13_fakes.py`). `verify_m13.py` ran green in **both** modes —
`sample` (the real M4–M12 pipeline behind the real application) and `live`
(uvicorn on a loopback port answering real HTTP requests). Sample mode: every
documented surface answered, all 16 groups present in the OpenAPI document,
every response
carried the standard envelope, an unknown route was a 404, an out-of-range page a
422, an unknown severity a 400, a malformed timestamp a 400, an unknown protocol
label selected nothing, `capture/start` twice was 200 then 409, capture reported
the packets the pipeline really processed, the alert and incident lifecycle verbs
persisted through the M11/M12 rules and a terminal state refused a further move,
`/settings` withheld the seeded secret key, and the unbuilt capabilities
(baselines, report generation) answered 501 instead of inventing data.
**Baseline (this machine, OneDrive-synced disk, `--packets 10000`, 30 iterations,
in-process client):** simple endpoints 0.85-1.77 ms (`/system/info` 0.85,
`/system/health` 1.77, `/capture/status` 1.10, `/statistics/traffic` 1.19); list
endpoints 4.2-10.8 ms (a 100-row `/packets` page 10.8 ms, an empty `/alerts`
4.2 ms, an empty `/notifications` 7.1 ms); filtered `/packets` 6.6-24.4 ms (one
address 6.6 ms, `protocol=TCP` 19.7 ms, `destination_port=443` 24.4 ms — the
widest filter measured *slower* than the unfiltered page, which is worth a look
if the store grows); pagination flat in the offset, 6.6 ms at `limit=10` rising
to 44.7 ms at `limit=1000`; `/dashboard/summary` 6.2 ms; JSON rendering 0.16 ms
for the page data and 0.08 ms for the envelope; the same list and count measured
straight on `PacketQueryService` 2.6 ms / 0.39 ms. Across 1,000 / 5,000 / 10,000
rows the 100-row page stayed flat at 9.9-10.9 ms, so the indexed page is
store-size independent over this range. Not a production-capacity claim: it is
one process, one SQLite file, with the transport replaced by a function call.
**Security note:** M13 is a local application API with no authentication by
design; it does not expose secrets, validates every input, offers no arbitrary
filesystem or SQL surface and bounds every result set.
**Design:** `docs/17_M13_REST_API_Design.md`.

> Deliberately out of scope for M13: new detection, alert, correlation or
> risk-scoring logic, ML/AI, WebSockets, frontend code, automatic blocking,
> external SIEM integrations, authentication/RBAC, and PDF/CSV report generation
> (M17). M13 exposes what M3–M12 already implemented; it does not redesign them.

---

# M14 — WebSockets ✅ COMPLETE

* [x] Review M13's REST surface, the M6–M12 data each event needs and what already
      exists to serialize with (M14.1) — `docs/18_M14_WebSocket_Design.md` §3
* [x] `WebSocketManager` — accept, admit, register, broadcast, disconnect,
      shutdown (M14.2) — `app/websockets/manager.py`
* [x] Four endpoints, mounted unversioned at `/ws/dashboard`, `/ws/packets`,
      `/ws/alerts` and `/ws/system` (M14.3) — `app/websockets/routes.py`
* [x] Connection lifecycle with an explicit per-client state (M14.4) —
      `app/websockets/connection.py` (`ClientConnection`)
* [x] Connection registry — a bounded set per channel, one lock, snapshot reads
      (M14.5) — `app/websockets/manager.py`
* [x] Channel separation — one channel per data type, isolated fan-out (M14.6) —
      `app/websockets/channels.py`
* [x] Event envelope — a single `WebSocketEvent` for every event, ISO-8601 UTC,
      monotonic sequence, closed type vocabulary (M14.7) —
      `app/websockets/event.py`
* [x] Packet events, projected with no packet payload on the wire (M14.8) —
      `app/websockets/builders.py`, `app/websockets/payloads.py`
* [x] Dashboard events on a tick, read from the same services the REST route reads
      (M14.9) — `app/websockets/dashboard.py`
* [x] Alert events — created, updated and lifecycle (M14.10) —
      `app/websockets/events.py`
* [x] System events — capture, service and database state (M14.11)
* [x] Incident events — created, updated and lifecycle (M14.12)
* [x] Event publisher with `enabled` and a null publisher, so an unwired pipeline
      costs one boolean (M14.13) — `app/websockets/publisher.py`
* [x] Failure isolation — publishing never raises into the capture thread (M14.14)
* [x] Backpressure — one bounded queue per connection, drop-oldest, counted (M14.15)
* [x] Packet rate control — a per-channel token bucket so a busy wire cannot flood
      a subscriber (M14.16) — `app/websockets/policy.py`
* [x] Serialization — encoded once per event, size-checked before it is queued
      (M14.17)
* [x] Disconnect handling — a dead client is unregistered and the others keep
      being served (M14.18)
* [x] Reconnection — a reconnect is a new connection with fresh counters and no
      history replay (M14.19)
* [x] Startup and shutdown — background tasks started and cancelled with the app
      lifespan (M14.20) — `app/main.py`
* [x] Thread/async safety — one `call_soon_threadsafe` bridge from the capture
      thread onto the event loop, and the queue touched only on the loop (M14.21)
* [x] Security boundary — no client input trusted, no secret or internal path on
      the wire (M14.22)
* [x] Client input policy — client frames are answered or refused, never used to
      widen what the server sends (M14.23)
* [x] Heartbeat — keepalive ping with a dead-peer timeout (M14.24) —
      `app/websockets/heartbeat.py`
* [x] Tests — manager (M14.25) — `tests/test_ws_manager.py` (48)
* [x] Tests — event schema (M14.26) — `tests/test_ws_event_schema.py` (67)
* [x] Tests — broadcast and channel isolation (M14.27) —
      `tests/test_ws_broadcast.py` (19)
* [x] Tests — backpressure and rate control (M14.28) —
      `tests/test_ws_backpressure.py` (33)
* [x] Tests — reconnection (M14.29) — `tests/test_ws_reconnect.py` (16)
* [x] Tests — pipeline isolation (M14.30) —
      `tests/test_ws_pipeline_isolation.py` (8)
* [x] Tests — endpoints over real ASGI WebSocket (M14.31) —
      `tests/test_ws_endpoints.py` (16)
* [x] Tests — the publisher contract (M14.13) —
      `tests/test_ws_publisher.py` (17)
* [x] Manual verification (M14.32) — `backend/scripts/verify_m14.py`; `sample`
      attaches a client to every channel while controlled packets go through the
      real M4→M12 pipeline, `live` serves uvicorn and speaks real WebSocket
* [x] Performance baseline (M14.33) — `backend/scripts/benchmark_m14.py` with
      `backend/scripts/m14_bench_harness.py`

**Verification:** full suite **1863 passed** (the M14 suite is **224 tests** across
the files above — 1639 + 224 = 1863); pyright **0 errors, 0 warnings,
0 informations** over **268 files**. Both `verify_m14.py` modes ran green: `sample`
drove the real M4→M12 pipeline with a client on every channel and saw the packet,
dashboard, alert, incident and keepalive events it expected; `live` spoke real
WebSocket over real HTTP to all four channels under uvicorn.

**Baseline (this machine, OneDrive-synced disk, in-process client,
`--packets 2000 --iterations 50 --clients 4 --window 1.0`):**

*Connection setup* — one socket opened and closed: `/ws/alerts` 0.93 ms p50,
`/ws/system` 0.94, `/ws/packets` 0.96, `/ws/dashboard` 1.11 (824–1,053 handshakes/s).

*Packet path ladder* — the same 2,000-packet burst through the same M4–M12 stack at
five publishing configurations, so each step is a measured difference rather than an
inference. This is the figure M14.33 asks for:

| configuration | packets/s | µs/packet | overhead vs M14 absent |
| --- | --- | --- | --- |
| 1. publish call replaced (M14 absent) | 2,947 | 339.27 | — |
| 2. null publisher — event built, then discarded | 2,418 | 413.59 | +74.32 µs |
| 3. publisher, layer disabled | 2,678 | 373.35 | +34.08 µs |
| 4. publisher, enabled, no subscriber | 2,304 | 434.03 | +94.75 µs |
| 5. publisher, enabled, one subscriber | 2,015 | 496.40 | +157.12 µs |

The two halves deserve reading separately: **building** a `packet.observed` for every
packet on the wire costs roughly **74 µs/packet**, and **delivering** it to one
subscriber costs roughly **158 µs/packet** over having no layer at all. Rung 3
measured *cheaper* than rung 2, which is not a finding — a step of a few tens of
microseconds is the same order as this disk's run-to-run variance (an earlier run of
the identical ladder measured a 1,564 packets/s baseline where the recorded run
measured 2,947), so the ladder's trend is quotable and no single step is. The M4–M12
work dominates either way: ~339 µs/packet with M14 absent, against ~481 µs/packet of
CPU measured across the whole ladder.

*Broadcast latency* (publish → the client has it; p50 / payload size): `/ws/dashboard`
0.213 ms / 395 B, `/ws/system` 0.218 ms / 243 B, `/ws/alerts` 0.235 ms / 799 B,
`/ws/packets` 0.395 ms / 443 B.

*Channel throughput* (unthrottled publisher, one client, 1 s window): alerts
delivered 5,289/s; system 8,914/s delivered from 10,991/s offered, the 2,077
difference being its 128-slot queue under a publisher that outran the sender;
dashboard 1,047/s, where the limit is the publisher rather than the channel because
the tick's own sampler is the cost; and packets 397/s delivered from 6,748/s offered
against its **200/s ceiling** — the token bucket working as designed, not a transport
limit.

*Bounded queue under an overrun* (2,000 events at a client that never drains): depth
peaked at 32/32 (dashboard), 204/256 (packets), 512/512 (alerts) and 128/128 (system)
— at the cap and never past it, with drop-oldest counted. The benchmark asserts this
rather than printing it.

*Simultaneous clients* — 16 held at once (4 per channel), every one served: connect
2.07–2.69 ms p50, fan-out to all four 0.89–1.43 ms p50.

*Process* — RSS 134.4 → 166.3 MiB (+31.9) across the ladder; CPU 4.81 s for 10,000
packets (481 µs/packet, the whole M4–M12 stack plus M14).

Not a production-capacity claim: one process, one event loop, with the socket
replaced by an in-process transport, so the absolute numbers are far better than a
deployed service would see. What they are good for is comparing channels against each
other, comparing the layer against having no layer, and re-measuring after a change —
the packet pool is generated, so two runs of the script are comparable.

**Design:** `docs/18_M14_WebSocket_Design.md`.

> Deliberately out of scope for M14: frontend code, new detection, alert, correlation
> or risk-scoring logic, ML/AI, automatic blocking, authentication/RBAC, and external
> SIEM or notification integrations. M14 carries what M3–M13 already produce; it does
> not redesign them. M15 consumes this surface from the React frontend.

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
