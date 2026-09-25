# NetWatch AI — M10 Base Detection Design

**Milestone:** M10 — Base Detection
**Status:** Implemented
**Depends on:** M5 (NormalizedPacket), M6 (traffic statistics), M8 (device discovery), M9 (connection tracking), M2 (`detection_rules` table, unused here)

---

# 1. Purpose

M10 turns the normalized traffic already produced by M5 and aggregated by M6/M8/M9
into **detection findings**.

A *finding* is one observation produced by one detector: a source contacted this
many distinct ports, a destination received this SYN rate, a source reached this
many internal hosts, or the observed traffic volume crossed a threshold.

```text
Network            Packet Capture        Packet Processing
    ↓                     ↓                      ↓
                                               NormalizedPacket
                                                    ├── Statistics (M6)
                                                    ├── Persistence (M7)
                                                    ├── Devices (M8)
                                                    ├── Connections (M9)
                                                    └── Detection (M10)
                                                            ↓
                                                    Detection Findings
```

M10 produces findings. It does **not** produce alerts. The M11 alert engine
converts findings into alerts; M12 adds correlation and risk scoring.

## 1.1 Scope boundary

M10 implements rule-based detection only. It does **not** implement alert
lifecycle, alert deduplication, a correlation engine, risk scoring, behavioural
baselines, ML/AI anomaly detection, automatic blocking, WebSockets, frontend
integration, SIEM integrations or incident response. A **finding is not an
alert**: no severity, no risk score, no assignment and no lifecycle exists
anywhere in this package.

---

# 2. M10.1 — Review of the existing components

## 2.1 `NormalizedPacket` (M5) — `app/schemas/packet.py`

The M10 input. Detectors read:

| Field | Use in M10 |
| --- | --- |
| `timestamp` | observation time; anchors every time window |
| `length` | byte volume (statistics path) |
| `source_ip`, `destination_ip` | what a detector keys on |
| `source_port`, `destination_port` | port-scan identity |
| `protocol` | report label; ICMP detection |
| `packet_type` | fallback protocol classification (`DNS` → UDP) |
| `tcp_flags` | handshake evidence (`S` = pure SYN) |
| `source_mac`, `destination_mac` | **ignored** — M10 identifies endpoints by IP |
| `interface`, `packet_id` | **ignored** |

M10 never imports Scapy.

## 2.2 Traffic statistics (M6) — `app/statistics/manager.py`

M10 does **not** re-aggregate packets. The high-bandwidth detector consumes the
bytes-per-second rate M6 already maintains, through a narrow
`TrafficRatesSource` protocol (`get_rates(window) -> (packets_per_second,
bytes_per_second)`). The engine reads it through a throttled `RatesFeed`, so the
rate is recomputed at most once per half second rather than per packet (M10.12).

## 2.3 Device discovery (M8) — `app/devices/`

M10 reuses the M8 registry as the **only** device authority. A finding is
enriched with `source_device_id` / `destination_device_id` by resolving each
address against `DeviceRegistry.get_by_ip`. An unresolved address stays `None`;
M10 never creates a device.

## 2.4 Connection tracking (M9) — `app/connections/`

M10 does **not** reuse the M9 conversation registry directly. The M9 detectors
observe genuinely connection-level behaviour (distinct ports, distinct internal
destinations, SYN rate) themselves, using bounded windowed state, because a
finding must be raised *as the behaviour happens* rather than only when a
conversation is later retired. M9's tracker still consumes the same packets
independently; the two consumers do not interact.

## 2.5 What M10 must not duplicate

| Already provided | Provided by | M10 relation |
| --- | --- | --- |
| packet normalization | M5 | consumed, never reimplemented |
| rate + volume aggregation | M6 | reused via `TrafficRatesSource` |
| packet rows | M7 | not touched |
| device registry | M8 | reused via `DeviceRegistry.get_by_ip` |
| conversation aggregation | M9 | not reused; detectors key on packets directly |

The M2 `detection_rules` table is deliberately **not** used: M10 configuration
lives in `Settings`, and runtime rule enable/disable lives in the engine. A
persisted rule-editing surface belongs to M13.

---

# 3. Layer map (M10.2)

```text
app/detection/
    context.py      DetectionContext + DetectionWindow — the only rule input (M10.4)
    base.py         DetectionRule — the common detector interface (M10.3)
    finding.py      DetectionFinding + confidence helper (M10.5/M10.15)
    state.py        WindowedCounter, WindowedDistinct — bounded rule state (M10.19)
    networks.py     InternalNetworkClassifier — what counts as "internal" (M10.11)
    rates.py        RatesFeed — throttled, failure-isolated rate reads (M10.12)
    history.py      FindingHistory — bounded retained findings (M10.22)
    engine.py       DetectionEngine — the orchestrator (M10.6)
    rules/
        signals.py        is_connection_attempt / is_handshake_open / is_icmp
        port_scan.py      PortScanRule (M10.8)
        syn_flood.py      SynFloodRule (M10.9)
        icmp_flood.py     IcmpFloodRule (M10.10)
        internal_scan.py  InternalScanRule (M10.11)
        high_bandwidth.py HighBandwidthRule (M10.12)
        __init__.py       build_default_rules(settings, classifier)
    __init__.py     package exports + get_detection_engine() singleton

app/schemas/detection.py   DetectionFindingView + rule/diagnostics wire models
app/api/v1/detections.py   internal read-only verification endpoints (M10.22)
```

Dependency direction is strictly downward. Nothing in `app/detection/` imports
Scapy, FastAPI, the database or the M9 tracker.

---

# 4. M10.3 — Detection rule interface

```python
class DetectionRule(ABC):
    rule_id: ClassVar[str] = ""       # stable id, used by config/diagnostics/API
    rule_name: ClassVar[str] = ""     # human-readable name
    description: ClassVar[str] = ""   # one-line behaviour description

    def __init__(self, *, enabled: bool = True, window_seconds: float | None = None)
    @property
    def enabled(self) -> bool
    def enable(self) / disable(self)
    @property
    def window_seconds(self) -> float | None
    @abstractmethod
    def evaluate(self, context: DetectionContext) -> DetectionFinding | None
    def state_size(self) -> int       # subjects currently held (M10.19)
    def reset(self) -> None           # discard accumulated observations
```

A rule:

* has a **stable** `rule_id` so configuration, diagnostics and the API can name
  it without depending on its class;
* receives exactly one context and returns one finding or `None`;
* owns its own bounded, lock-protected state;
* does no database, socket or API work, and takes its thresholds as constructor
  arguments rather than reading the environment itself.

A rule never raises for ordinary input: a packet it cannot reason about yields
`None`. It may raise for a genuinely unexpected failure, and the engine isolates
that failure (M10.17).

---

# 5. M10.4 — Detection context

```python
@dataclass(frozen=True)
class DetectionContext:
    timestamp: float
    packet: NormalizedPacket | None = None
    packets_per_second: float | None = None
    bytes_per_second: float | None = None
    rate_window_seconds: float | None = None
    total_packets: int | None = None
    total_bytes: int | None = None
    device_resolver: DeviceResolver | None = None
```

The context is the **only** input a rule receives. It is deliberately narrow: it
carries no connection registry, no database handle and no writer, so a detector
cannot quietly reach for another subsystem. It is a frozen dataclass rather than
a Pydantic model because it never crosses the API boundary and carries a
callable.

Convenience accessors (`source_ip`, `destination_ip`, `destination_port`,
`protocol`, `packet_length`, `window(seconds)`, `resolve_device(ip)`) keep rules
readable. `resolve_device` treats a resolver failure as "unknown" rather than
propagating — a missing association degrades a finding, it never stops one.

## 5.1 `DetectionWindow` (M10.13)

An explicit window with an inclusive `start` and exclusive `end`, so two adjacent
windows never both claim one instant. `context.window(seconds)` returns the window
of `seconds` ending at the observation.

---

# 6. M10.5 / M10.15 — Detection finding

```python
class DetectionFinding(BaseModel):
    finding_id: str                                    # fnd-<uuid4>, opaque
    rule_id: str
    rule_name: str
    timestamp: float                                   # epoch seconds
    source_ip: str | None
    destination_ip: str | None
    source_device_id: str | None
    destination_device_id: str | None
    protocol: str | None
    description: str
    evidence: dict[str, int | float | str | bool]
    confidence: float                                   # [0.0, 1.0]
    metadata: dict[str, int | float | str | bool]
```

**No severity or risk score exists here.** Severity belongs to M11 and risk
scoring to M12. `confidence` states how strongly the detector's *own* evidence
supports its rule condition, which is a different quantity from risk.

* `threshold_confidence(measured, threshold, floor=0.5)` returns a value bounded
  to `[floor, 1.0]`: exactly at the threshold scores `floor`, at or beyond twice
  the threshold scores `1.0`.
* `finding_id` is an opaque unique id, not a content hash, so a later milestone
  cannot mistake it for a deduplication key: the same behaviour seen twice is two
  findings.
* `with_devices(...)` enriches in a `None`-never-overwrites a value direction.
* `to_view()` projects onto `DetectionFindingView` for the API.

---

# 7. M10.6 / M10.17 — Detection engine

```text
Detection Context
      ↓
Detection Engine
      ↓
┌──────────┬──────────┬──────────┬──────────┬──────────┐
↓          ↓          ↓          ↓          ↓
Port      SYN        ICMP       Internal   Bandwidth
Scan      Flood      Flood       Scan       Spike
↓          ↓          ↓          ↓          ↓
└──────────┴──────────┴──────────┴──────────┴──────────┘
                     ↓
             Detection Findings
```

The engine owns *what* is evaluated and *how a failure is contained*; it owns no
detection logic. It:

* holds registered rules and their enabled/disabled state,
* builds one context per evaluation,
* evaluates every enabled rule,
* **isolates per-rule failures** — a rule that raises is counted and logged, and
  the remaining rules still run,
* enriches findings with M8 device associations,
* retains findings in a bounded history,
* tracks execution diagnostics.

It never raises into its caller: `process_packet` catches everything, counts it
and logs it, so capture, processing, statistics, persistence, device discovery
and connection tracking are never affected by a detection failure.

## 7.1 Registration and enable/disable

`register`, `register_many`, `unregister`, `get_rule`, `get_rules`,
`enable(rule_id)`, `disable(rule_id)`, and a whole-engine `set_enabled(bool)`.
A duplicate `rule_id`, or a rule with no id, raises `ValueError`. Enabling an
unknown rule raises `KeyError`. The engine never silently resolves either.

## 7.2 Diagnostics

Per-engine: `evaluations`, `findings`, `errors`, `enabled_rules`,
`registered_rules`, `retained_findings`. Per-rule (`get_rule_counters()`):
`evaluations`, `findings`, `errors`, `last_error_at`.

---

# 8. M10.19 / M10.20 — Detection state and thread safety

Rule state lives in two bounded structures in `app/detection/state.py`:

* `WindowedCounter` — integer counts per key inside a sliding window;
* `WindowedDistinct` — distinct values per key inside a sliding window.

Both enforce a **key cap** (so a spoofed flood cannot exhaust memory) and, for
`WindowedDistinct`, a **values-per-key cap**. Both evict by window age, so old
observations do not accumulate. This is how M10.19's "state must be bounded and
periodically cleaned" requirement is met without keeping packet history.

Thread safety (M10.20):

* the engine guards the rule table and every counter with one `threading.Lock`,
  and evaluates rules **outside** the table lock, so a slow detector cannot block
  an `enable`/`disable` call;
* each rule that keeps mutable state guards it with its own lock;
* the read-then-clear decision that produces a finding is taken under the rule
  lock, so two concurrent evaluations cannot both emit a finding for one window;
* a detector never touches shared state belonging to another service.

---

# 9. M10.7 — Rule configuration

Thresholds are configuration, never hard-coded in detector logic. Defaults come
from `Settings` (documented in `app/config/settings.py`) and are applied by
`build_default_rules(settings, classifier=...)`:

| Setting | Default | Detector |
| --- | --- | --- |
| `DETECTION_ENABLED` | `true` | master switch for the pipeline consumer |
| `DETECTION_MAX_FINDINGS` | `1000` | retained-findings cap |
| `DETECTION_MAX_STATE_KEYS` | `4096` | subjects per detector |
| `DETECTION_MAX_VALUES_PER_KEY` | `4096` | distinct values per subject |
| `PORT_SCAN_TIME_WINDOW_SECONDS` | `10.0` | Port Scan |
| `PORT_SCAN_UNIQUE_PORT_THRESHOLD` | `20` | Port Scan |
| `PORT_SCAN_SYN_RATIO_THRESHOLD` | `0.5` | Port Scan |
| `SYN_FLOOD_TIME_WINDOW_SECONDS` | `5.0` | SYN Flood |
| `SYN_FLOOD_RATE_THRESHOLD` | `200.0` | SYN Flood (SYN/s) |
| `ICMP_FLOOD_TIME_WINDOW_SECONDS` | `5.0` | ICMP Flood |
| `ICMP_FLOOD_RATE_THRESHOLD` | `100.0` | ICMP Flood (ICMP/s) |
| `INTERNAL_SCAN_TIME_WINDOW_SECONDS` | `10.0` | Internal Scan |
| `INTERNAL_SCAN_UNIQUE_DESTINATION_THRESHOLD` | `15` | Internal Scan |
| `HIGH_BANDWIDTH_TIME_WINDOW_SECONDS` | `5.0` | High Bandwidth |
| `HIGH_BANDWIDTH_BYTES_PER_SECOND_THRESHOLD` | `1000000.0` | High Bandwidth |

`build_default_rules` reads an explicit `Settings` object and never calls
`get_settings()` behind the caller's back, so a test that passes its own settings
gets exactly that configuration.

---

# 10. M10.8 — Port Scan detector

A host opening contact with an unusually large number of **distinct destination
ports** inside a window has the shape of a port scan.

```text
Source Device/IP  →  Time Window  →  Unique Destination Ports
                  →  Configurable Threshold  →  Finding
```

Two deliberate choices keep it honest:

* **Only genuine connection attempts count** (`is_connection_attempt`): a TCP pure
  `SYN`, or a datagram sent from an ephemeral source port. Counting every packet
  that names a destination port would flag a busy server, because each reply it
  sends carries a fresh ephemeral destination port.
* **`PORT_SCAN_SYN_RATIO_THRESHOLD` characterises, it does not gate.** The SYN
  share separates a SYN scan from a UDP or mixed scan; the ratio selects the
  wording and the reported scan type, and the finding is raised either way once
  the port threshold is met.

The finding names only the source, because a scan spans destinations. Evidence
reports `unique_destination_ports`, the threshold, `connection_attempts`,
`syn_attempts`, `syn_ratio` and the observation window. On firing, the source's
state is discarded so one window cannot emit a stream of identical findings — the
only suppression M10 implements (M10.18).

---

# 11. M10.9 — SYN Flood detector

A destination receiving an unusually high rate of TCP SYNs.

* Keys on the **destination** (the party being flooded).
* Measures SYN packets per second against `SYN_FLOOD_RATE_THRESHOLD`.
* Only pure SYNs count (SYN **without** ACK); a SYN+ACK is a reply, and counting
  it would let ordinary server traffic inflate the rate.
* Requires at least **two** observed SYNs in the window before it will fire,
  whatever the configured rate, so a single ordinary packet is never reported.

The finding names the destination, and names the source only when exactly one
source was actually observed (reporting one arbitrary source out of a spoofed
flood would be misleading); the distinct-source count is reported as evidence.

---

# 12. M10.10 — ICMP Flood detector

A destination receiving an unusually high rate of ICMP packets, measured against
`ICMP_FLOOD_RATE_THRESHOLD`.

* Keys on the destination.
* Requires at least two ICMP packets before firing, so ordinary ping activity is
  never treated as malicious.
* Reports the distinct-source count and names a single source only when exactly
  one was observed.

Nothing here blocks, drops or rate-limits traffic, and nothing here scores risk.

---

# 13. M10.11 — Internal Network Scan detector

A source reaching out to an unusually large number of **internal destinations**
inside a window.

* Keys on the source; counts distinct *internal* addresses it contacted.
* **What counts as internal** is decided in `app/detection/networks.py`
  (`InternalNetworkClassifier`): addresses that are not globally routable, plus
  the host's own addresses (supplied by the M3/M4 interface manager). An external
  destination is never counted, so a client talking to many public services
  cannot be mistaken for a network sweep — the detector is silent on external
  traffic by construction.
* The source is **not** required to be internal: a host sweeping the local network
  from outside it is exactly the behaviour worth observing.
* Only genuine connection attempts count, which stops a server answering many
  internal clients from looking like a scanner.

The finding names only the source, and its state is cleared on firing (M10.18).

---

# 14. M10.12 — High Bandwidth / Traffic Spike detector

Unusually high observed traffic volume, using the rate M6 already measures.

* Consumes M6's **one-second** rate window through `RatesFeed` and compares it
  with `HIGH_BANDWIDTH_BYTES_PER_SECOND_THRESHOLD`.
* Does **not** re-aggregate packets and keeps no byte history of its own.
* The detector's own window is the **minimum interval between findings**: a spike
  lasting a minute is one condition, not sixty thousand findings.

This is a traffic-volume observation, not a security verdict — saturating a link
is often a backup, a download or a video call — so the finding reports that
volume was high and leaves interpretation to the alert and correlation layers.

---

# 15. M10.14 — Evidence

Every finding carries enough evidence to explain why it was produced, drawn from
actual observed data. Nothing is fabricated: counts, IPs, devices and timestamps
come from the packets and statistics that were actually seen. Example evidence:

```text
unique_destination_ports = 37
unique_port_threshold    = 20
connection_attempts      = 41
observation_window_seconds = 10.0
```

---

# 16. M10.16 — False-positive awareness

Detectors never assume "threshold exceeded = confirmed attack". Descriptions are
descriptive of observed behaviour:

```text
Possible SYN port scan detected from 192.168.1.10
Possible SYN flood detected against 192.168.0.99
Possible ICMP flood detected against 192.168.0.100
Possible internal network scan detected from 192.168.1.50
Possible traffic spike detected (5.00 MB/s observed)
```

The alert engine and later correlation/risk layers add further context.

---

# 17. M10.21 — Pipeline integration

```text
Scapy
  ↓
CaptureManager
  ↓
PacketProcessor
  ↓
NormalizedPacket
  ├── TrafficStatisticsManager (M6)
  ├── PacketPersistence        (M7)
  ├── DeviceDiscoveryManager   (M8)
  ├── ConnectionTracker        (M9)
  └── DetectionEngine          (M10)
```

* Detection runs **last**, after every other consumer, so the rates M6 maintains
  and the devices M8 has attributed are already updated for this packet.
* Its failure is isolated in its own `try/except`: a detection error is counted
  (`get_detection_error_count()` on the pipeline and the capture manager) and
  logged, while capture, processing, statistics, persistence, device discovery
  and connection tracking continue.
* The engine itself already isolates per-rule failures, so the pipeline counter
  normally stays zero; it exists so a failure that escaped the engine is still
  visible from the capture layer.
* On capture stop, the built-in `stop()` path is unchanged for detection: nothing
  is flushed, because M10 persists no finding.

---

# 18. M10.18 / M10.22 — Deduplication boundary and queries

## 18.1 Deduplication boundary (M10.18)

M10 implements **no** full alert deduplication. It implements only the minimal
rule-level suppression each detector needs to avoid emitting an excessive number
of identical findings from one observation window:

* Port Scan, SYN Flood, ICMP Flood and Internal Scan clear the subject's state on
  firing, so a window produces one finding rather than one per subsequent packet;
* High Bandwidth fires at most once per configured window while the rate stays
  above the threshold.

Full finding/alert deduplication belongs to M11.

## 18.2 Queries (M10.22)

`FindingHistory.query(...)` supports the queries M10 promises, newest first:

```text
rule_id, source_ip, destination_ip, device_id, since (inclusive), until (exclusive), limit
```

The history is bounded (`DETECTION_MAX_FINDINGS`, default 1000) and drops the
oldest, so a rule that fires continuously cannot grow memory without limit.

## 18.3 API

M13 owns the complete REST API, so M10 exposes only what verification needs,
following the project's existing envelope and error conventions:

```text
GET  /api/v1/detections                  filtered, bounded, newest-first list
GET  /api/v1/detections/rules            registered detectors + diagnostics
POST /api/v1/detections/reset            discard findings and detector state (dev helper)
```

This is deliberately **not** the alert API (M11) and not the master REST API
(M13). A finding is read-only: it cannot be acknowledged, suppressed or
escalated. An unusable `since`/`until` filter is rejected with `400` naming the
field the caller got wrong; `limit` is bounded to `[1, 1000]`.

---

# 19. Error handling

| Condition | Behaviour |
| --- | --- |
| Rule raises during evaluation | counted (`errors`, per-rule `errors`, `last_error_at`), logged, remaining rules continue |
| Rule declares no id / duplicate id | `ValueError` at registration |
| Enable/disable of an unknown rule | `KeyError` |
| Context with no packet | detector returns `None` (no observation invented) |
| Missing address / port / flags | detector returns `None`; nothing is fabricated |
| M6 rate source failure | reported as `None`, counted in `RatesFeed.error_count`, detection continues on rules that need no rate |
| Device resolver failure | treated as "unknown"; the finding is degraded, never dropped |
| Invalid API timestamp | `400` with field and code `INVALID_FILTER` |
| Unexpected exception in `process_packet` | counted, logged, never raised |

---

# 20. Test plan (M10.23 - M10.29)

| Area | File |
| --- | --- |
| rule registration, enable/disable, context, finding validation, engine execution, multiple rules, failure isolation, empty/invalid context, diagnostics | `tests/test_detection_framework.py` |
| port scan: threshold boundaries, repeated ports, multiple sources, windows, SYN evidence, cleanup, low-volume silence | `tests/test_detection_port_scan.py` |
| SYN flood: boundaries, destinations, windows, normal traffic, cleanup | `tests/test_detection_syn_flood.py` |
| ICMP flood: boundaries, normal ping, windows, cleanup | `tests/test_detection_icmp_flood.py` |
| internal scan: boundaries, internal filtering, external traffic, multiple sources, cleanup | `tests/test_detection_internal_scan.py` |
| high bandwidth: boundaries, windows, normal traffic, statistics-input failure | `tests/test_detection_high_bandwidth.py` |
| pipeline: capture → processor → statistics + devices + connections → detection | `tests/test_detection_pipeline.py` |
| API envelope, filters, validation, rules/diagnostics, reset, verbs | `tests/test_detections_api.py` |
| shared test doubles | `tests/detection_fakes.py` |
| manual verification | `scripts/verify_m10.py` |
| performance baseline | `scripts/benchmark_m10.py` |

---

# 21. Manual verification (M10.30)

`scripts/verify_m10.py` has two modes:

* **sample** (default) — pushes synthetic packets through a full `PacketPipeline`
  covering all five detectors, with *lab* thresholds (lower than the shipped
  defaults) so a handful of packets demonstrates each one. It prints every finding
  with its evidence and asserts that all five detectors fired, every finding
  carries evidence, confidence is within `[0.0, 1.0]`, and no rule failure was
  recorded. It requires no admin rights or Npcap.
* **live** — captures real traffic through `CaptureManager` → pipeline →
  detection for a few seconds and prints the findings raised. Authorized/local
  traffic only.

The verified chain is:

```text
Observed behaviour → Detection condition → Detection finding → Evidence
```

---

# 22. Performance baseline (M10.31)

`scripts/benchmark_m10.py` measures the detection layer in isolation:

* packets evaluated per second with detection enabled and disabled, and the
  per-packet overhead;
* each detector's own per-packet rule execution time;
* findings produced and bounded detector state size;
* Python memory held by the engine and its rules (`tracemalloc`);
* API response times for `/detections` and `/detections/rules`.

It is a **local, single-machine** baseline for the M10 detection code only. It
excludes real capture, the M5 normalization step, the M6/M8/M9 consumers, the M7
packet write, the network stack, JSON serialization at the wire and any database.
It is **not** a production-capacity claim.

---

# 23. Deliberate non-goals

* No alerts, alert lifecycle or alert deduplication (M11).
* No correlation engine, risk scoring or historical/behavioural context (M12).
* No ML/AI anomaly detection, no behavioural baselines, no automatic blocking.
* No WebSocket or frontend-facing surface (M13+ consolidates the REST API).
* No new database tables or columns; the M2 `detection_rules` table is unused.
* No rules that read the environment directly, and no rule reads global
  application state; thresholds arrive as constructor arguments.
* No claim of production-scale detection throughput — the benchmark records a
  *local* baseline only.
