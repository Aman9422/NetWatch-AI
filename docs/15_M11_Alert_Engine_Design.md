# NetWatch AI — M11 Alert Engine Design

**Milestone:** M11 — Alert Engine
**Status:** Implemented
**Depends on:** M10 (DetectionFinding), M9 (connections), M8 (devices), M7 (persisted packets), M2 (`alerts` and `alert_evidence` tables, `detection_rules` catalogue)

---

# 1. Purpose

M11 turns the **observations** M10 produces into **alerts**: a conclusion about
behaviour, with a severity, a lifecycle, a deduplication identity, and the
evidence that justifies it.

A *finding* says what the packets showed. An *alert* says that the behaviour is
worth a human's attention, how serious it is, and what supported it.

```text
Detection Finding (M10)
        ↓
    Alert Engine (M11)
        ↓
    Alert + Alert Evidence
        ↓
   Existing database (M2)
```

## 1.1 Scope boundary

M11 implements **alert management only**. It does **not** implement new detection
algorithms, behavioural baselines, ML/AI anomaly detection, a correlation engine,
risk scoring, automatic blocking, WebSockets, frontend integration, external SIEM
integrations or advanced incident response.

M10 **detects**; M11 **alerts**; M12 will **correlate and score risk**.

The alert layer holds **no risk field anywhere**. Severity and confidence are
separate concepts (M11.4/M11.5): `severity=high, confidence=0.92` means "this
class of behaviour matters, and the evidence for it is strong" — it is **not** a
risk score of 92.

---

# 2. M11.1 — Review of the existing components

## 2.1 `DetectionFinding` (M10) — `app/detection/finding.py`

The M11 input. M11 reads:

| Field | Use in M11 |
| --- | --- |
| `finding_id` | link back to the observation (M11.7); stored in rule evidence |
| `rule_id` | selects the mapping entry (M11.8) and the dedup key (M11.9) |
| `rule_name` | carried into the rule evidence record |
| `timestamp` | observation time: `created_at`/`updated_at` and the dedup window anchor |
| `description` | the alert description and the behavioural evidence |
| `confidence` | the alert confidence, verbatim (M11.5) |
| `source_ip` / `destination_ip` | endpoints; packet/connection resolution |
| `source_device_id` / `destination_device_id` | device association (M11.15) |
| `protocol` | dedup key component; connection resolution |
| `evidence` | nested verbatim under `measured` in behavioural evidence (M11.11) |

A finding carries **no severity and no risk score**. Severity is assigned by the
mapping (M11.4); nothing in M11 modifies the finding to create an alert (M11.7).

## 2.2 Persisted packets (M7) — `app/repositories/packet.py`

M11 never duplicates packet records. Packet evidence stores the `packets.id` it
references plus a small readable digest (M11.13). Resolution goes through the M7
`PacketRepository.list(...)`, bounded by address, protocol and a window around
the observation.

## 2.3 Connection information (M9) — `app/connections/manager.py`

M11 does not create another connection store. Connection evidence references the
M9 `connection_id` (stable for the conversation's life) plus a short digest, and
resolution reads the live `ConnectionTracker.list_connections(...)` (M11.14).

## 2.4 Device information (M8) — `app/devices/registry.py`

M11 reuses the M8 registry as the **only** device authority. A finding that
resolved a device id gets a `device` evidence record naming that M8 identity. An
unresolved address stays empty — M11 never invents a device (M11.15).

## 2.5 The M2 `alerts` and `alert_evidence` tables

The runtime alert is mapped onto the existing M2 `alerts` columns by
`app/alerts/persistence.py`. The M2 `alert_evidence` table — with its
`evidence_type` vocabulary of `packet`, `connection`, `behavioral`, `rule` and
`device` (and the documented-but-unused `ml`) — is used as designed. No table is
redesigned.

| Already provided | Provided by | M11 relation |
| --- | --- | --- |
| normalized findings | M10 | consumed; the only alert source (M11.22) |
| packet rows | M7 | referenced by packet evidence (M11.13) |
| conversations | M9 | referenced by connection evidence (M11.14) |
| device registry | M8 | reused for device association (M11.15) |
| `alerts` / `alert_evidence` tables | M2 | persisted to; not redesigned (M11.12/M11.16) |
| `detection_rules` catalogue | M2 | resolves the alert's rule foreign key (best-effort) |

---

# 3. Layer map (M11.2)

```text
app/alerts/
    severity.py        AlertSeverity + ordering (M11.4)
    status.py          AlertStatus, transition table, validation (M11.6/M11.19)
    mapping.py         the documented rule → alert table (M11.8)
    dedup.py           the deduplication key + bounded window (M11.9/M11.10)
    alert.py           the runtime Alert value model (M11.3)
    evidence.py        evidence descriptors + the bounded collection (M11.11/M11.12)
    evidence_builder.py  what evidence an alert carries, in priority order (M11.11)
    resolvers.py       finding → M7/M9/M2 records, bounded + optional (M11.13-M11.15)
    persistence.py     runtime alert → `alerts` columns (M11.12)
    timestamps.py      epoch ⇄ naive-UTC datetime (the one conversion point)
    service.py         the write path: findings in, alerts out (M11.21/M11.22)
    queries.py         the read path: listings, detail, aggregations (M11.18)
    engine.py          the pipeline consumer (M11.21)
    __init__.py        package exports + get_alert_engine() singleton (M11.23)

app/repositories/alert.py           the `alerts` table (M11.16-M11.18)
app/repositories/alert_evidence.py  the `alert_evidence` table (M11.16)
app/schemas/alert.py                read-only wire schemas (M11.18)
app/api/v1/alerts.py                internal alert endpoints (M11.18/M11.19)
app/database/upgrade.py             the M11 `alerts.status` CHECK upgrade (M11.6)
```

Dependency direction is strictly downward. Nothing in `app/alerts/` imports
Scapy or FastAPI. The pure modules (severity, status, mapping, dedup) are
importable in isolation with no database or environment side effect.

---

# 4. M11.3 — Runtime Alert model

```python
class Alert(BaseModel):            # frozen: an alert is a value
    rule_id: str                   # stable detector id, e.g. "port_scan"
    title: str
    description: str = ""
    severity: AlertSeverity
    confidence: float = 0.0        # 0..1 float, from M10 (M11.5)
    status: AlertStatus = OPEN
    alert_id: int | None = None    # database PK; None until persisted
    created_at / updated_at / resolved_at: datetime | None
    source_ip / destination_ip: str | None
    source_device_id / destination_device_id: str | None
    protocol / connection_id / finding_id: str | None
    evidence_count: int = 0        # derived, never assigned by a detector
    correlation_key: str | None    # the dedup key (M11.9)
```

Three deliberate properties:

* **Frozen.** An alert is never mutated in place. A lifecycle change produces a
  copy through `Alert.with_status(...)`, which validates the move — an
  assignment cannot bypass the transition table.
* **`evidence_count` is derived.** It is the number of evidence rows the alert
  actually has; the service computes it from persisted evidence. A detector
  cannot inflate it.
* **`risk_score` does not exist.** Risk needs the historical context M12 owns.

`Alert.from_record(row, evidence_count=...)` rebuilds the runtime alert from a
persisted row: the rule id, protocol and connection id are recovered from
`correlation_key` (the M2 table has no columns for them), confidence comes back
as the 0..1 float the integer column represents, and a legacy M2 status is read
as its M11 equivalent.

---

# 5. M11.4 — Severity

`AlertSeverity` is `low < medium < high < critical`, fixed per rule. `severity.py`
owns the vocabulary, the rank ordering, `at_least(...)` and
`values_at_or_above(...)`, so the "high and above" filter is expressed in one
place.

Severity is **never invented by a detector**: it comes only from the mapping
(M11.8). Severity is **not** a risk score.

---

# 6. M11.5 — Confidence

`confidence` is a 0..1 float — the value M10 measured — kept strictly separate
from severity. The M2 `alerts.confidence` column stores an integer percent, so
the conversion `round(value * 100)` happens only at the persistence boundary
(`app/alerts/persistence.py`), is documented, and is the only lossy step in the
alert path. `0.923` is stored as `92` and read back as `0.92`.

When a finding is missing a usable confidence the service falls back to
`app.detection.finding.MIN_CONFIDENCE`. Confidence is never invented and never
presented as a risk score: the wire schema exposes the float, not the percentage.

---

# 7. M11.6 / M11.19 — Lifecycle

```text
open ──► acknowledged ──► resolved
 │            │
 │            ├──────────► dismissed
 │            └──────────► false_positive
 ├────────────► resolved / dismissed / false_positive
```

`resolved`, `dismissed` and `false_positive` are **terminal**. Reopening a closed
alert is deliberately **not** supported — it would mean editing a recorded
conclusion or adding a state, neither of which is in M11's scope. The absence is
explicit and tested.

`app/alerts/status.py` owns the transition table (`VALID_TRANSITIONS`) and
`validate_transition(...)`, which raises `InvalidStatusTransition` for a move that
is not allowed. Validation happens **before any write**, so an invalid move leaves
the stored alert exactly as it was. A move to the state it is already in is
accepted as an explicit no-op.

The M2 `alerts.status` CHECK allowed `('new', 'acknowledged', 'investigating',
'resolved', 'false_positive')`. M11 writes `open` and `dismissed`, which the M2
constraint rejects, so `app/database/upgrade.py` rebuilds the table's status CHECK
to the M11 vocabulary plus the two legacy names (kept so pre-M11 rows stay valid).
The upgrade recognises a current schema as a no-op and, when it does run, copies
the existing DDL and replaces only the status CHECK.

---

# 8. M11.8 — Detection-to-alert mapping

`app/alerts/mapping.py` is the **only** place that decides what a finding means as
an alert. A rule not listed produces no alert at all.

| rule_id | alert title | severity | confidence source |
| --- | --- | --- | --- |
| `port_scan` | Port Scan | high | M10 finding (0..1) |
| `syn_flood` | SYN Flood | critical | M10 finding (0..1) |
| `icmp_flood` | ICMP Flood | medium | M10 finding (0..1) |
| `internal_scan` | Internal Scan | high | M10 finding (0..1) |
| `high_bandwidth` | High Bandwidth | high | M10 finding (0..1) |

The five entries cover exactly the five detectors M10 implements — a table entry
for an unimplemented detector would be a promise M11 cannot keep. Severity is
aligned with the M2 `detection_rules` catalogue so the two cannot drift apart.
---

# 9. M11.9 / M11.10 — Deduplication

A detector may report the same behaviour repeatedly — a port scan is observed once
per packet burst — so an alert is raised once per distinct incident and later
observations inside the window are folded into it.

**The deduplication key** (M11.9), exactly:

```text
rule_id | source_ip | destination_ip | protocol | device_id | connection_id
```

with `-` for every absent component, joined in that fixed order with `|` as the
separator (`|` cannot occur in an IP, a protocol label, a device id or a
connection id, so the key cannot be forged). It is stored in the M2
`alerts.correlation_key` column — the column M2 documents as "optional key used to
deduplicate related alerts" — which is also how the string rule id, the protocol
and the connection id survive in a table that has no columns for them.

Three deliberate properties:

* **Time is not a component.** Time is expressed by the *window*; the key
  describes the incident and the window describes how long it lasts.
* **The connection component is `-` on the engine's own path.** A detection
  finding carries no connection reference (M10 anchors findings to addresses), so
  only a caller that resolved a conversation supplies it — which is what makes
  M11.27's "different connection" case distinguishable.
* **The device component is a single value** (the source device, falling back to
  the destination): every M10 detector reports a source-initiated behaviour, so the
  destination device is implied by the same addresses.

**The window** (M11.10) is bounded and configurable, never unlimited:
`MAX_DEDUP_WINDOW_SECONDS = 86_400` is the ceiling, so a misconfigured value
cannot silently swallow every future incident. Once the window expires a new
alert is created, so a source that keeps scanning all day produces one alert per
window rather than one alert forever. The window is anchored to the **observation
time** (`finding.timestamp`), not the wall clock, or an alert would age out at a
rate that depends on when it happened to be processed.

---

# 10. M11.11 - M11.15 — Evidence

Evidence is supporting information, not a second copy of the data. Two rules shape
it:

* **References, never copies (M11.13).** A packet evidence record stores the
  `packets.id` it points at plus a small readable digest. Rewriting a packet's
  fields into the alert would create a second, divergent record, and a retention
  sweep that deletes the packet would leave a convincing-looking ghost behind.
* **Bounded (M11.12).** An alert carries at most
  `alert_max_evidence_per_alert` records. A flood touching a thousand
  conversations must not turn one alert into a thousand rows.

`AlertEvidenceRecord` validates that an evidence document is not empty (a record
that says nothing is not evidence, and would inflate the derived
`evidence_count`) and that only packet evidence may reference a packet row.
`serialize_evidence_data` writes deterministic JSON (sorted keys, no incidental
whitespace) so the same evidence always serialises identically.

`build_evidence(...)` fixes the **order** of the records, which is priority
because `EvidenceCollection` drops whatever arrives after the cap:

1. the **rule** record — the detector and the finding that raised the alert;
2. the **behavioural** record — the numbers the detector measured, nested verbatim;
3. **device** records — which hosts were involved (M11.15);
4. **connection** records — the conversations carrying the behaviour (M11.14);
5. **packet** records — the individual frames, last (M11.13).

A cap that bites therefore discards packet references first and the justification
for the alert never. Dropped records are **counted**, never hidden.

`FindingResolvers` looks related records up. Every source is injected and
optional, and resolution never fails an alert (M11.26): a database error, an
unparseable address or an unexpected source object yields no evidence rather than
an exception. Packet lookup is bounded by address, protocol and a window around
the observation; conversation lookup is bounded by the finding's addresses and
protocol; the rule foreign key is best-effort — a detector with no catalogue row
still produces an alert, with only its `rule_id` foreign key left `NULL`.

The `evidence_type` values are exactly the ones the M2 `alert_evidence` column
documents: `rule`, `behavioral`, `packet`, `connection`, `device`. `ml` is
documented there too but nothing in M11 writes it.

---

# 11. M11.12 / M11.16 — Persistence

`app/alerts/persistence.py` is the one boundary where the runtime model meets the
M2 table. Every difference is resolved there:

| Model | Column | Mapping |
| --- | --- | --- |
| `confidence: float 0..1` | `confidence: INT` | `round(value * 100)`, clamped |
| `severity: AlertSeverity` | `severity: TEXT` | `.value` |
| `status: AlertStatus` | `status: TEXT` | `.value` (M11 vocabulary) |
| `rule_id: str` | `rule_id: INT FK` | resolved catalogue row id, else `NULL` |
| — | `risk_score: INT` | written `0`; **M11 does not score risk** |
| — | `device_id: INT FK` | written `NULL`; M8 owns devices, none is invented |
| `created_at` | `created_at` | supplied (observation time), not defaulted |
| `resolved_at` | `resolved_at` | set when a terminal state is reached (M11.20) |

The service writes the alert **and its evidence in one transaction**: it flushes
to assign the primary key, stages the evidence rows, then commits — so an alert is
never stored without the evidence that justified it. A failed evidence batch is
rolled back, never leaving an alert with partial evidence.

---

# 12. M11.2 / M11.21 / M11.22 — Alert service

`AlertService` is the write path and the only component that decides *whether* a
finding becomes an alert. It:

* looks the finding's rule up in the mapping and refuses unknown ones (M11.8);
* builds the dedup key and checks the bounded window (M11.9/M11.10);
* builds the bounded evidence set (M11.11-M11.15);
* writes the alert and evidence in one transaction (M11.16);
* applies validated lifecycle transitions (M11.19/M11.20).

```python
process_finding(finding) -> AlertOutcome     # never raises
process_findings(findings) -> [AlertOutcome]
set_status(alert_id, status, *, updated_at=None) -> Alert | None
get_counters() / reset_counters()
set_enabled(...) / set_resolvers(...)
```

`AlertOutcome` is always **returned, never raised**, so the pipeline has nothing
to catch. Exactly one of its flags describes the result: `created`, `duplicate`,
`unsupported`, `error`. **A single alert-processing failure must not stop
detection processing (M11.21)**: the failure is counted (`errors`) and logged, and
the next finding is processed normally.

`set_status` is the one operation that *reports* its failure rather than
swallowing it, because a lifecycle change is a direct user action: it raises
`InvalidStatusTransition` for a forbidden move and returns `None` when no alert
has that id.

The service owns the master enable switch; when disabled, findings are accepted
and counted but no alert is produced.

---

# 13. M11.17 / M11.18 — Repository and queries

`AlertRepository` owns every statement that touches `alerts` and is deliberately
dumb: it stores and retrieves, and never decides what an alert *is*, assigns a
severity, opens a transition or scores anything.

```text
get / get_by_severity / get_by_status / get_by_device / get_by_rule
get_unresolved / get_high_priority
find_duplicate_candidate(correlation_key, cutoff=...)
list_alerts(...) / count_alerts(...)
count_by_severity(...) / count_by_status()
insert(...) / update_status(...) / touch_correlation_key(...)
```

`get_unresolved` was **corrected** in M11: the M2 version excluded only
`resolved` and `false_positive`, so a **dismissed** alert still counted as
unresolved. Every M11 terminal state is excluded now.

`AlertEvidenceRepository` follows the same *stage then commit* split as M7:
`stage(...)` for the transaction the service owns, `write_many(...)` for a batch
with rollback, and `count_by_type` / `count_for_alerts` so a listing fetches
evidence counts **once per page** rather than once per alert.

The repository does **not** import `app.alerts.status` (the alert package imports
the repository, so that would be a cycle): the persisted status and severity
vocabularies are literals here, asserted against the runtime tables by the
repository tests — the same arrangement as the model's CHECK constraint.

`AlertQueries` answers read-only questions with bounded results and deterministic
ordering (newest first):

```text
Recent alerts        Open alerts          Alerts by severity / status
Alerts by rule       Alerts by source/destination IP
Alerts by device     Alerts by time range
summary() -> { total, by_severity, by_status }
```

A caller filters with **epoch seconds** (how a finding expresses time) and the API
speaks **ISO-8601 UTC** (how M3-M10 expose time); both directions are handled by
`timestamps.py`, so a filter is never silently off by a timezone.

---

# 14. M11.23 — Thread safety

Alert processing runs concurrently with detection, persistence, queries and status
updates.

* **The check-and-insert is atomic.** Deduplication is a read followed by a
  write, so two threads evaluating findings for the same incident could both find
  "no duplicate" and both insert. A single `threading.Lock` spans the whole
  operation — which the database alone cannot guarantee at SQLite's isolation
  level.
* **Every operation opens its own session.** The service is called from the
  capture thread and the API's thread pool, and a SQLAlchemy session is not
  thread-safe, so a session is never shared or cached.
* **Counters are guarded by their own lock**, so a diagnostics read never blocks
  the write path.
* Resolution uses per-lookup sessions (`SessionPacketSource`, `SessionRuleSource`),
  so the long-lived resolver object holds no database state.

No global lock is held across the database work beyond the dedup check-and-insert;
detection, statistics, persistence and connection tracking keep running on their
own state.

---

# 15. M11.24 — Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `ALERTS_ENABLED` | `true` | master switch for the pipeline consumer |
| `ALERT_DEDUP_WINDOW_SECONDS` | `300.0` | dedup window (bounded by `MAX_DEDUP_WINDOW_SECONDS`) |
| `ALERT_MAX_EVIDENCE_PER_ALERT` | `64` | hard cap on evidence records per alert |
| `ALERT_PACKET_EVIDENCE_ENABLED` | `true` | whether packet references are resolved |
| `ALERT_PACKET_EVIDENCE_MAX_PACKETS` | `5` | most packet references per alert |
| `ALERT_PACKET_EVIDENCE_WINDOW_SECONDS` | `5.0` | half-width of the searched packet window |
| `ALERT_CONNECTION_EVIDENCE_MAX` | `5` | most conversation references per alert |
| `ALERT_DEFAULT_PAGE_SIZE` | `100` | default listing page size |
| `ALERT_MAX_PAGE_SIZE` | `1000` | maximum listing page size |

Operational limits are configuration, never hard-coded, and every bound has a
sensible documented default.

---

# 16. M11.21 / M11.22 — Pipeline integration

```text
Scapy → CaptureManager → PacketProcessor → NormalizedPacket
    ├── TrafficStatisticsManager (M6)
    ├── PacketPersistence        (M7)
    ├── DeviceDiscoveryManager   (M8)
    ├── ConnectionTracker        (M9)
    ├── DetectionEngine          (M10) ──► DetectionFinding(s)
    └── AlertEngine              (M11) ◄── consumes those findings
```

The alert engine sits **after** detection and consumes the findings the engine
produced for the packet — it never re-inspects raw packets to reimplement
detection logic. Alerting is reached only when detection produced something, so
the disabled or silent path costs nothing. An alert failure is isolated in its own
`try/except` (counted by `get_alert_error_count()` on the pipeline and the capture
manager and logged), while capture, processing, statistics, persistence, device
discovery, connection tracking and detection continue. On capture stop there is
nothing to flush for alerts — each alert is committed as it is created.

---

# 17. M11.18 / M11.19 — API

M13 owns the complete REST API, so M11 exposes only what verification needs,
following the project's envelope and error conventions:

```text
GET  /api/v1/alerts                    filtered, bounded, newest-first list
GET  /api/v1/alerts/summary            counts by severity and status
GET  /api/v1/alerts/diagnostics        engine counters + stored totals (M11.31)
GET  /api/v1/alerts/{id}               one alert with its evidence
GET  /api/v1/alerts/{id}/evidence      one alert's evidence, optionally by type
POST /api/v1/alerts/{id}/status        validated lifecycle transition
```

Two rules the endpoints keep: **reads never mutate** (only the status POST changes
anything), and **a rejected filter is never ignored** (an unknown severity or an
empty rule key returns `400`, so a typo can never look like "no alerts"). An
illegal transition returns `409` naming the states that *are* reachable, and the
stored alert is left untouched. `summary` is registered before `/{alert_id}` so it
can never be parsed as an id.

---

# 18. Error handling

| Condition | Behaviour |
| --- | --- |
| Finding from an unmapped rule | no alert; counted `unsupported_findings` (M11.8) |
| Unexpected failure creating an alert | counted `errors`, logged, capture continues (M11.21/M11.26) |
| Invalid lifecycle move | `InvalidStatusTransition`; the stored alert is untouched (M11.19) |
| Unknown target status | `ValueError` (a typo is never stored as a status) |
| Transition on a missing alert | `None` → API `404` |
| Dodgy query filter (severity / rule key) | `400` `INVALID_FILTER` |
| Illegal transition | `409` `INVALID_TRANSITION` |
| Resolution failure (packet / connection / rule) | no evidence / `NULL` FK; the alert is still created (M11.26) |
| Missing dedup window / non-positive | `ValueError` at service construction (startup, not first finding) |

---

# 19. Manual verification (M11.32)

`scripts/verify_m11.py` has two modes:

* **sample** (default) — pushes synthetic packets through a full `PacketPipeline`
  (Processor → Statistics → Devices → Connections → Persistence → DetectionEngine
  → AlertEngine) backed by an isolated temporary SQLite database, then prints
  every finding, every alert and its evidence. No admin rights or Npcap needed. It
  asserts that all five mapped rules became alerts at the mapped severity, that
  confidence survived and is within `[0.0, 1.0]`, that each alert links back to its
  finding, that rule/behavioural evidence exists and packet evidence references a
  real packet without copying a payload, that a repeat inside the window folds in
  while one outside it or from elsewhere does not, and that the lifecycle applies
  `open → acknowledged → resolved` and rejects a reopen.
* **live** — captures real traffic through `CaptureManager` → the same pipeline
  for a few seconds and prints the alerts. Authorized/local traffic only.

The verified chain:

```text
Detection Finding → Alert Created → Severity → Confidence → Evidence → DB record
                                     lifecycle: open → acknowledge → resolve
```

---

# 20. Performance baseline (M11.33)

`scripts/benchmark_m11.py` measures the alert layer in isolation:

* findings processed per second and alerts created per second;
* the deduplication lookup cost (the repeated-observation path);
* alert write latency through the repository to SQLite;
* evidence write overhead (minimal ~2 records vs populated ~7 records per alert);
* Python memory held by the service (`tracemalloc`);
* API response times for the read-only alert endpoints.

**Local baseline (this machine, OneDrive-synced disk):** create path ~143
findings/sec (~6,995 us/alert — dominated by the per-alert SQLite commit on this
disk); deduplication path ~602 lookups/sec (~1,661 us/finding) with 50 incidents
folding 2,950 repeats; evidence write overhead ~881 us/alert for 5 extra packet
references; heap after 500 alerts ~0.13 MiB, peak ~0.17 MiB (stored alerts live in
SQLite, so the Python heap does not grow with the alert count); API avg ~15 ms
(`/alerts?limit=100`), ~3.8 ms (`/summary`), ~4.3 ms (`/diagnostics`), ~5 ms
(detail). This is **not** a production-capacity claim: it excludes real capture,
the M5-M10 consumers, the network stack and JSON serialisation at the wire, and
alert writes are the most database-bound part of the pipeline.

---

# 21. Deliberate non-goals

* No new detection algorithms, baselines, ML/AI anomaly detection or automatic
  blocking.
* No correlation engine, risk scoring or historical/behavioural context (M12).
* No WebSocket or frontend-facing surface (M13+ consolidates the REST API).
* No new database tables or columns; the M2 `alerts` / `alert_evidence` tables are
  used as designed, with the one status CHECK widened because the M11 lifecycle
  genuinely requires it.
* No risk field anywhere — M11 states severity and confidence only.
* No claim of production-scale alert throughput — the benchmark records a *local*
  baseline only.
---

# 22. Test plan (M11.25 - M11.31)

| Area | File |
| --- | --- |
| alert model: required/optional fields, severity values, confidence bounds and the float⇄percent round-trip, status values, timestamps, finding association | `tests/test_alerts_model.py` |
| creation: finding creates an alert, unmapped finding does not, correct rule mapping, severity, confidence, device and connection association | `tests/test_alerts_creation.py` |
| deduplication: identical finding inside/outside the window, different source/destination/rule/connection, multiple independent alerts not merged | `tests/test_alerts_dedup.py` |
| lifecycle: every valid transition, the invalid ones rejected, same-state no-op, terminal states closed | `tests/test_alerts_lifecycle.py` |
| evidence: finding/packet/connection/device evidence, multiple records, missing evidence, evidence count, no payload duplication | `tests/test_alerts_evidence.py` |
| repository / database: create, retrieve, list, filter, update status, persist/retrieve evidence, dedup lookup, transaction rollback | `tests/test_alerts_repository.py` |
| API: envelope, filters, validation, detail, evidence, lifecycle endpoint, diagnostics, verbs | `tests/test_alerts_api.py` |
| integration: capture → ... → DetectionEngine → AlertEngine → AlertRepository → SQLite; severity/confidence preserved, evidence stored, duplicates handled, detection continues after an alert failure | `tests/test_alerts_integration.py` |
| shared test doubles | `tests/alert_fakes.py` |
| manual verification | `scripts/verify_m11.py` |
| performance baseline | `scripts/benchmark_m11.py` |

The M11 alert suite is **218 tests** (collected; the project-wide suite is 1077
as of M11).
