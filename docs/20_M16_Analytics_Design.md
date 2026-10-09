# M16 — Analytics

**Milestone:** M16 — Analytics
**Status:** implemented and verified
**Depends on:** M6 (traffic statistics), M7 (packet persistence), M8 (device discovery), M9 (connection tracking), M10 (detection), M11 (alert engine), M12 (correlation and risk), M13 (REST API), M15 (frontend integration)
**Consumes:** `requests` from the M15 frontend, over the M13 endpoints

---

## 1. Purpose

M15 connected the React/TypeScript frontend to the M13 REST API and the M14
WebSocket channels. The frontend consumes five analytics endpoints:

```text
GET /api/v1/analytics/traffic
GET /api/v1/analytics/protocols
GET /api/v1/analytics/devices
GET /api/v1/analytics/connections
GET /api/v1/analytics/threats
```

Before M16 those five routes existed but only returned the *live* half of each
answer: counters read from the M6 statistics manager, the M8 device registry, the
M9 connection tracker, the M10 detection engine, the M11 alert store and the M12
correlation registry. Nothing was asked of the persisted data, so a client could
not ask a single historical question — "how much traffic crossed this network
between 09:00 and 10:00" had no answer, because the live counters reset with the
process and no route read the packet table.

M16 adds that second half. Each route now answers over an explicit, bounded time
window and reports **the stored figures beside the live ones**, without changing
the M13 fields the M15 frontend already types.

The governing constraint is that analytics is a *consumer*. It reads what M6–M12
already produced and derives only presentation arithmetic from it — a rate, a
share, an average, a sort. It introduces no second statistics engine, no second
device identity, no second risk score and no new detection logic.

---

## 2. Scope

M16 delivers:

1. **A time model** — one module that decides what an analytics window is, so all
   five routes agree on bounds, bucket size and bucket alignment.
2. **A query layer** — SQL-side aggregation over the `packets`, `connections` and
   `alerts` tables, bounded in every dimension.
3. **A service layer** — the five views, each assembling its live half from the
   owning runtime service and its persisted half from the query layer.
4. **Five hardened endpoints** — validation, sensible defaults, explicit maximum
   limits, stable schemas and consistent error handling on the M13 envelope.
5. **Availability reporting** — per-block `{available, error, data}` sections, so
   a failed database read is neither fatal nor silently reported as zero.
6. **Tests** — 254 analytics tests across five files, plus the full M0–M15
   regression suite, a local performance baseline and a two-mode verification
   script run against real pipeline data.

---

## 3. Non-goals

Explicitly outside M16, and not implemented by it:

- ML anomaly detection, behavioural baselines, AI explanations
- local LLM / Ollama integration
- automatic blocking, IPS functionality
- SIEM or threat-intelligence integrations
- authentication, RBAC
- report generation, notification delivery
- distributed sensors
- device or connection risk scoring
- any change to M6, M8, M9, M10, M11 or M12 behaviour

Where an M16 document mentions future ML/AI work, it is named as out of scope
rather than described as present.

---

## 4. Architecture position

```text
Packet Capture
      ↓
Packet Processing
      ↓
Traffic Statistics (M6)   ─────────────┐
      ↓                                │
Packet Persistence (M7) → packets      │
      ↓                                │
Devices (M8) / Connections (M9) → connections
      ↓                                │  (in-process
Detections (M10)                       │   services read
      ↓                                │   directly)
Alerts (M11) → alerts                  │
      ↓                                │
Correlation + Risk (M12)  ─────────────┤
                                       │
───────────────────────────────────────┴──────
                    Analytics (M16)
───────────────────────────────────────────────
                         ↓
                  M13 REST API
                         ↓
                  M15 Frontend
```

M16 sits between the producing milestones and the API. It holds **no state of its
own**: nothing is cached, no table is written, no in-memory registry is
maintained. Every answer is computed from data that already exists, which is what
makes an analytics response reproducible from the store alone.

The two halves of every response arrive by different routes, and that difference
drives the failure model in §14:

| Half | Source | Failure mode |
| --- | --- | --- |
| live | in-process service (M6/M8/M9/M10/M12) | the service answers, or the request fails with it |
| persisted | SQLite (`packets`, `connections`, `alerts`) | can fail alone — locked file, full disk, dropped connection |

---

## 5. Data sources

### 5.1 Persisted (SQLite)

| Table | Owner | M16 reads | Filter column | Index used |
| --- | --- | --- | --- | --- |
| `packets` | M7 | counts, byte sums, protocol/address/port groupings, time series | `timestamp` | `idx_packets_timestamp` |
| `connections` | M9 | counts, state and protocol groupings, durations, time series | `start_time` | `idx_connections_start_time` |
| `alerts` | M11 | counts, severity/status/risk/confidence groupings, rule ranking, time series | `created_at` | `idx_alerts_created_at` |

No new table is introduced. No new index is added: every analytics filter is on a
column M7, M9 and M11 already index, and the grouped columns (`protocol`,
`source_ip`, `destination_ip`, `source_port`, `destination_port`, `severity`,
`status`) are indexed too. Adding an index for a `GROUP BY` that runs over rows
already narrowed by an indexed `WHERE` would cost write throughput and buy
nothing — see §15.

### 5.2 Live (in-process)

| Source | Owner | M16 reads |
| --- | --- | --- |
| `TrafficStatisticsManager` | M6 | totals, rates, protocol distribution, direction statistics, top talkers and ports |
| `DeviceDiscoveryManager` | M8 | device views: identity, addresses, activity state, `first_seen` / `last_seen` |
| `ConnectionTracker` | M9 | active / historical / tracked counters, connection views |
| `DetectionEngine` | M10 | retained findings, per-detector execution diagnostics |
| `AlertQueries` | M11 | alert summary by severity and status |
| `CorrelationEngine` | M12 | incident list, risk bands, `highest_risk_score` |

### 5.3 What M16 does *not* read

- The M5 packet processor, M6 rate windows and M7 persistence internals are not
  queried; the *tables* they wrote are.
- No second copy of a packet, device, connection, alert or incident is created. A
  device in a ranking is the M8 view; an incident's risk band is M12's band.

---

## 6. Analytics architecture

```text
app/api/v1/analytics.py      route: resolve the window, call one service method,
                             wrap in the M13 envelope
        ↓
app/analytics/service.py     AnalyticsService: assemble the live + stored halves
                             of one view
        ↓
    ┌───────────────────────┬──────────────────────────┬────────────────────┐
    │ live_view.py          │ *_view.py (persisted)     │ window.py          │
    │ read M6/M8/M9/M10/M12 │ traffic_view             │ bounds, buckets,   │
    │ views, order them     │ protocol_view            │ alignment          │
    │                       │ device_view              │                    │
    │                       │ connection_view          │ metrics.py         │
    │                       │ alert_view, threat_view  │ rank metric vocab  │
    │                       │                          │                    │
    │                       │ *_queries.py             │ sections.py        │
    │                       │ SQL aggregation          │ availability       │
    └───────────────────────┴──────────────────────────┴────────────────────┘
```

### 6.1 Modules

| Module | Responsibility |
| --- | --- |
| `app/analytics/window.py` | the only definition of a window, its bounds, its bucket size and its alignment; also the SQL twin of bucket alignment |
| `app/analytics/metrics.py` | the shared ranking vocabulary: `packets` / `bytes`, the default, and the 100-row group cap |
| `app/analytics/sections.py` | `read_section`: runs a database-derived block and returns `{available, error, data}`, never raising |
| `app/analytics/packet_queries.py` | `PacketAnalytics` — totals, series, protocols, distinct protocols, top sources / destinations / ports, row count |
| `app/analytics/connection_queries.py` | `ConnectionAnalytics` — totals, status and protocol counts, duration statistics, series |
| `app/analytics/alert_queries.py` | `AlertAnalytics` — totals, severity / status / risk band / confidence breakdowns, rule ranking, series |
| `app/analytics/*_view.py` | `build_stored_*` — turn query results into response models; `build_findings_summary`, `build_incident_linkage` for the in-memory threat blocks |
| `app/analytics/distributions.py` | the 0-100 confidence tiling and other shared banding helpers |
| `app/analytics/live_view.py` | read and order the in-process views (device status counts, severity counts, incident breakdown, rule stats, rankings) |
| `app/analytics/service.py` | `AnalyticsService` — one method per view, live + stored, collaborators injected |
| `app/schemas/analytics.py` | the wire contract: the M13 models extended with `period` and the section blocks |

### 6.2 Design decisions

1. **One window module, not five.** Bucket choice, bound validation and alignment
   live in `window.py`. A second endpoint that decided its own bucket size would
   eventually disagree with the first, and two responses would describe the same
   trend in different buckets.

2. **The Python and SQL bucket rules are written twice on purpose.**
   `bucket_start` decides which buckets a response *lists*; `bucket_expression`
   decides which rows SQLite *groups* into them. Splitting them across two modules
   is how the agreement would be lost, so they sit side by side in one file and a
   test asserts they agree.

3. **Two failure models, two mechanisms.** A live figure is read directly; a
   persisted figure goes through `read_section`. Mixing them — wrapping the live
   read in the same guard — would hide a broken runtime service behind an
   "unavailable section", which is the opposite of useful.

4. **The period is reported, not implied.** Every response carries the window its
   stored block was read over, including `defaulted`, so a client never infers a
   window from timestamps it did not send.

5. **Routes stay thin.** Each handler resolves its window, calls exactly one
   service method and wraps the result. No route decides what a number means.

---

## 7. Traffic analytics

**Route:** `GET /api/v1/analytics/traffic`
**Model:** `AnalyticsTraffic`
**Persisted block:** `stored` → `TrafficSection` / `StoredTrafficData`

### 7.1 Live half (unchanged from M13)

| Field | Source |
| --- | --- |
| `total_packets`, `total_bytes` | M6 snapshot |
| `packets_per_second`, `bytes_per_second`, `bits_per_second` | M6 snapshot, or `get_rates(window)` when a non-default `window` is sent |
| `average_packet_bytes` | `total_bytes / total_packets` from the snapshot, `0` when none |
| `protocol_count`, `protocols`, `directions` | M6 snapshot |
| `top_sources`, `top_destinations` | `get_top_talkers(limit, by)` |
| `top_ports` | `get_top_ports(limit, by, direction="destination")` |
| `stored_packet_count` | the packet table's row count, read *through* the stored section |

The snapshot is read **once**, so the totals, the rates and the protocol list all
describe the same instant.

### 7.2 Persisted half

Read from the `packets` table inside the resolved window:

| Field | Meaning |
| --- | --- |
| `total_packets` | rows in the window |
| `total_bytes` | sum of `packet_length` in the window |
| `packets_per_second` / `bytes_per_second` | totals ÷ window seconds |
| `average_packet_bytes` | `total_bytes / total_packets`, **`null`** when the window holds no packet |
| `first_timestamp` / `last_timestamp` | oldest and newest stored instant, **`null`** when empty |
| `distinct_protocols` | distinct `protocol` values in the window |
| `packets_without_source_port` / `packets_without_destination_port` | rows carrying no port — ICMP and ARP genuinely have none, so these are reported rather than hidden |
| `stored_packet_count` | unwindowed row count (M13's figure, kept for the M15 type) |
| `series` | one `SeriesPoint` per bucket: `{start, packets, bytes}` |
| `top_sources`, `top_destinations`, `top_ports` | `TopEntry` rankings, `limit` rows, ordered by `by` |
| `protocols` | `ProtocolStat` list, ordered by `by` |

### 7.3 Why live and stored are both reported

They are deliberately different figures. The live counters describe *this process*
and reset when it restarts; the stored rows describe *what was captured and
persisted* and survive. Reporting one as a stand-in for the other would be a
silent lie in either direction, so both are present and named.

A stored bucket with zero packets means the store holds no packet in that
interval — it is not a claim that no traffic crossed the network, because capture
may have been stopped. That is why the block is called `stored`.

---

## 8. Protocol analytics

**Route:** `GET /api/v1/analytics/protocols`
**Model:** `AnalyticsProtocols`
**Persisted block:** `stored` → `ProtocolsSection` / `StoredProtocolsData`

### 8.1 Live half

The M6 manager's own `ProtocolStat` entries, with their own shares. M16 decides
only the **ordering**, and the name tie-break makes that ordering total: two
protocols with equal counts always appear in the same relative order, so a client
can diff two responses meaningfully.

### 8.2 Persisted half

`GROUP BY protocol` over the window's packets:

| Field | Meaning |
| --- | --- |
| `count` | protocols returned in this list |
| `distinct_protocols` | distinct protocols present in the window |
| `truncated` | true when `distinct_protocols > count` |
| `total_packets` / `total_bytes` | the window's totals — the denominator for every share |
| `rank_by` | the metric the list is ordered by |
| `protocols` | `ProtocolStat` entries: `{protocol, packets, bytes, percentage}` |

### 8.3 The percentage rule

**Percentages are shares of the window's own total packet count** — the whole
population the query selected — **not** of the returned rows.

Consequences, all tested:

- When the list is *not* truncated, the shares sum to 100 (within float rounding).
- When the list *is* truncated, `truncated` is true and the shares deliberately do
  **not** sum to 100: the returned rows are a subset, but the denominator is the
  window. Reporting shares of the returned subset would make a truncated list look
  like a complete one.
- With zero packets in the window, every share is 0 and no division by zero occurs.
- An unknown protocol is a protocol: it is grouped under whatever string the
  packet carries, exactly as M7 stored it. M16 invents no "unknown" bucket.

---

## 9. Device analytics

**Route:** `GET /api/v1/analytics/devices`
**Model:** `AnalyticsDevices`
**Windowed block:** `windowed` → `DeviceWindowSection` / `DeviceWindowData`

### 9.1 Live half

Read from the M8 manager's own views:

| Field | Meaning |
| --- | --- |
| `total` | devices in the registry |
| `by_status` | `active` / `inactive` / `unknown`, as M8 computed them |
| `rank_by` | `packets` or `bytes` |
| `top` | `RankedDevice` rows: identity, addresses, hostname, status, `first_seen`, `last_seen`, packets, bytes |

`first_seen` and `last_seen` are M8's own observation bounds, added by M16.4 to
the ranked row. Both are `null` for a record the registry has not dated — never
epoch 0.

### 9.2 The windowed block

`windowed` re-filters the *same* M8 views by `last_seen`: a device is listed when
it was observed at least once inside the period. Its shape is the registry's shape
restricted to the window:

| Field | Meaning |
| --- | --- |
| `total` | devices last seen inside the period |
| `by_status` | their activity states |
| `rank_by` | the metric the ranking is ordered by |
| `top` | their ranked rows |

### 9.3 What M16 deliberately does not do

- **No second identity mechanism.** A device id here is the M8 device id,
  produced by M8's own rule.
- **No risk score.** M8 computes none, so none appears — not even as a zero, which
  would read as "scored, and safe".
- **No history reconstruction.** The registry holds only the *current* record per
  device. `windowed` therefore answers "which devices were last seen in this
  window", not "what was observed during this window". The distinction is stated
  in the schema docstring and repeated in §17.
- **The M8 routed-traffic limitation is preserved.** Where traffic is routed, the
  next-hop MAC can represent several remote IP addresses, so one device id may
  carry many addresses. M16 neither hides nor "fixes" that; it reports M8's
  addresses as M8 recorded them.

---

## 10. Connection analytics

**Route:** `GET /api/v1/analytics/connections`
**Model:** `AnalyticsConnections`
**Persisted block:** `stored` → `ConnectionsSection` / `StoredConnectionsData`

### 10.1 Live half

The M9 tracker's own counters, so they agree exactly with `/connections`:

| Field | Meaning |
| --- | --- |
| `active` | conversations M9 is still tracking |
| `historical` | retired conversations |
| `tracked` | active + historical |
| `rank_by` | default `bytes` |
| `top` | `RankedConnection` rows over **tracked** conversations |

The ranking deliberately **includes retired conversations**: the busiest
conversation of a session is frequently one that has already closed, and omitting
it would answer a narrower question than "which conversations carried the most
traffic".

### 10.2 Persisted half

Read from the `connections` table, selecting on `start_time` — M9's own rule for
the same filter, so a conversation still in progress is never dropped from its own
window.

| Field | Meaning |
| --- | --- |
| `total` | conversations whose `start_time` falls in the window |
| `active` | those still marked `active` — a different figure from the live tracker counter |
| `first_timestamp` / `last_timestamp` | oldest and newest `start_time` in the window |
| `by_protocol` | count per protocol; **not** zero-filled |
| `by_status` | count per state; **every state M9 can write is named**, even at zero |
| `duration` | `DurationStats` over the conversations that ended |
| `series` | one `ConnectionSeriesPoint` per bucket: `{start, connections}` |
| `top_sources` / `top_destinations` | `TopEntry` rankings from the window's rows |

### 10.3 Duration statistics

`duration` describes only conversations carrying an `end_time`:

| Field | Meaning |
| --- | --- |
| `samples` | how many ended conversations the statistics cover |
| `min_seconds`, `mean_seconds`, `max_seconds` | the statistics, **all `null` when `samples` is 0** |

A conversation still running has no lifetime yet. Counting it as zero would drag
the mean toward zero and claim something untrue, so it is excluded and `samples`
is how a client knows how much of the window the statistics actually cover. With
no sample, `0.0` would be a claim that a conversation lasted no time at all,
which is why the statistics are `null` rather than `0`.

### 10.4 What M16 does not do

- It does not modify M9's tracking behaviour, identity rule or retirement policy.
- It introduces **no connection risk score**, and no connection-side severity.

---

## 11. Threat analytics

**Route:** `GET /api/v1/analytics/threats`
**Model:** `AnalyticsThreats`
**Persisted block:** `stored` → `AlertsSection` / `StoredAlertsData`
**Added blocks:** `findings` → `FindingsSummary`, `incident_links` → `IncidentLinkage`

Threat analytics reports **four orthogonal views**, never collapsed into one
"threat" number — because no milestone produces such a number:

| View | Owner | What it is |
| --- | --- | --- |
| findings | M10 | what the detectors *observed*, with no judgement |
| alerts | M11 | the evidence-based judgement: severity, lifecycle status, confidence |
| incidents | M12 | the bounded prioritisation metric: lifecycle state, risk band |
| stored alerts | M11 table | the same alerts, read over an explicit window |

### 11.1 Live findings (M10)

| Field | Meaning |
| --- | --- |
| `findings_retained` | findings currently in M10's bounded in-memory history |
| `detections_evaluated`, `detections_findings`, `detections_errors` | M10's lifetime execution counters |
| `rules` | per-detector execution counters: `{rule_id, rule_name, enabled, evaluations, findings, errors}` |

`rules` counts what a detector *did*; a finding has no severity (M10.5), which is
why no severity appears on this block.

### 11.2 Live alerts (M11)

| Field | Meaning |
| --- | --- |
| `alerts_total` | alerts in the store |
| `alerts_open` | those in a state that still needs attention |
| `alerts_by_severity` | M11's judgement |
| `alerts_by_status` | M11's lifecycle states |

### 11.3 Live incidents (M12)

The incident registry is read **once** and both breakdowns come from that single
snapshot, so the status total and the risk-band total cannot describe different
instants:

| Field | Meaning |
| --- | --- |
| `incidents_total`, `incidents_active` | incident counts |
| `incidents_by_status` | M12's lifecycle states |
| `incidents_by_risk_band` | M12's risk bands |
| `highest_risk_score` | the worst current M12 score |

### 11.4 The windowed findings summary

`findings` is the retained M10 observations *summed over the period* — distinct
from the `rules` block on the same response. One is a lifetime tally of engine
execution; the other is what it saw inside a window.

| Field | Meaning |
| --- | --- |
| `retained` | findings in M10's bounded history |
| `in_window` | retained findings that fall inside the period |
| `mean_confidence` | mean confidence of those, **`null`** when the window holds none |
| `by_confidence_range` | the same findings tiled into the project's one documented 0-100 banding |
| `by_rule` | per-detector counts: `{rule_id, rule_name, findings}` |

A finding's `0.0..1.0` confidence is scaled to `0..100` **only** to place it in
that shared tiling; the scaling is a presentation step, not a new metric.

### 11.5 The stored alert block

| Field | Meaning |
| --- | --- |
| `total` | alerts created inside the window |
| `without_rule_key` | alerts carrying no correlation key, so they appear in no `rules` entry — reported separately so the ranking's coverage is visible rather than silently short |
| `first_timestamp` / `last_timestamp` | oldest and newest `created_at` in the window |
| `by_severity` | **M11's judgement** |
| `by_status` | M11's lifecycle state |
| `by_confidence_range` | how strongly M11 believed its evidence |
| `by_risk_band` | **M12's prioritisation metric** |
| `rules` | `{rule_key, alerts}` per detector |
| `series` | one `AlertSeriesPoint` per bucket: `{start, alerts}` |

Every vocabulary is named **in full even when it holds no rows**, so a client
renders fixed rows rather than discovering a missing key.

### 11.6 Keeping the concepts separate

```text
Finding    — an observation by M10. Has no severity, no risk.
Alert      — M11's judgement on evidence. Has severity, confidence, lifecycle status.
Incident   — M12's grouping of correlated alerts. Has a lifecycle state and a risk band.
Severity   — M11's vocabulary. How bad the evidence says it is.
Confidence — M11's vocabulary. How strongly the evidence supported it, 0.0..1.0.
Risk       — M12's vocabulary. A bounded prioritisation score, banded by M12.
```

M16 calculates **no new risk score**. `incidents_by_risk_band` and the stored
alerts' `by_risk_band` both read M12's persisted value and band it with the one
table M12 defines. No ML, no AI, no probabilistic scoring is introduced.

**One caveat, reported rather than hidden.** M11 writes `risk_score = 0` and
leaves it there until M12 correlates the alert. An alert that no incident has
reached is therefore banded `minimal` — the truthful reading of its *stored*
score, but it means "not yet scored", not "assessed as minimal". The live
incident block is where a scored judgement is reported. This is documented on
`StoredAlertsData` and mirrored in the M15 TypeScript type.

### 11.7 Alert-to-incident linkage

`incident_links` reports the relationship M12 already holds, rather than deriving
one:

| Field | Meaning |
| --- | --- |
| `incidents_total` | incidents in the registry |
| `incidents_with_alerts` | those naming at least one alert |
| `alerts_in_incidents` | **distinct** alert ids across all incidents |

`alerts_in_incidents` counts *alerts*, not *links*: an alert that two incidents
reference is counted once.

---

## 12. Time-window and aggregation rules

All five routes share one time model, defined in `app/analytics/window.py`. The
rules below are the whole of it; no endpoint adds a rule of its own.

### 12.1 Bounds

| Rule | Value |
| --- | --- |
| Convention | `[since, until)` — `since` **inclusive**, `until` **exclusive** |
| Encoding | ISO-8601 UTC, explicit `+00:00` offset (M13.26) |
| `since` default | one hour before `until` |
| `until` default | *now* |
| Both omitted | the default one-hour window, and `period.defaulted = true` |
| Maximum span | 30 days (`MAX_WINDOW_SECONDS = 2 592 000 s`) |
| Empty range | refused (`since == until`) |
| Inverted range | refused (`since > until`) |

A naive timestamp is read as UTC, never as local time. Bounds are converted to the
naive UTC `DateTime` the stores actually persist before being compared to a
column, so a query cannot be silently shifted by the caller's timezone.

**Why refuse rather than clamp.** A range longer than the ceiling, or an inverted
one, is a request that *cannot be honoured as asked*. Clamping it to the ceiling
would answer a different question than the caller asked, and look like a valid
answer while doing so. Refusing it names the problem instead.

### 12.2 Buckets

| Rule | Value |
| --- | --- |
| Documented sizes (seconds) | 10, 30, 60, 300, 900, 1800, 3600, 21600, 43200, 86400 |
| Default selection | the **smallest** documented size whose point count fits |
| Point ceiling | `MAX_BUCKETS = 240` |
| Statement ceiling | `MAX_SERIES_POINTS = 248` |
| Alignment | **epoch-aligned** — a bucket starts at a second that is an exact multiple of its size |

The sequence follows the short-range/small-bucket, long-range/large-bucket rule,
but from **one fixed table** rather than an invented formula per endpoint:

| Window | Resolved bucket | Points |
| --- | --- | --- |
| 5 minutes | 10 s | 31 |
| 30 minutes | 10 s | 181 |
| 60 minutes (default) | 30 s | 121 |
| 24 hours | 900 s | 97 |
| 30 days (ceiling) | 21 600 s | 121 |

These are the figures the verification and benchmark runs actually produced.

**Why epoch-aligned.** A bucket boundary depends only on the bucket size, never on
the caller's `since`. Two requests describing overlapping periods therefore
describe *the same* buckets, and a client can diff or concatenate two series
meaningfully. A `since`-relative bucket would make the same second fall in
different buckets in different responses.

**Partial edges are expected.** The first and last buckets of a window are
frequently partial — a 20-minute window with 15-minute buckets holds two whole
buckets plus two edges. A partial bucket carries the packets that fall in it; the
bucket is a time interval, not a claim about its length.

### 12.3 Every series is bounded — by construction

There is **no code path that returns an unbounded time series**:

- A window always has bounds, because the defaults fill in what the caller omitted.
- The window length is capped at 30 days.
- The bucket is chosen so the point count fits `MAX_BUCKETS`; an explicitly
  requested bucket that would not fit is **refused**, not silently widened.
- The series statement additionally carries its own `LIMIT` of
  `MAX_SERIES_POINTS`, so it is bounded even if the resolution above it ever
  changed.

Since the largest documented bucket spans a day and the longest allowed window is
30 days, the default selection is total: thirty points always fit.

### 12.4 Aggregation rules

| Rule | Statement |
| --- | --- |
| Totals | summed by SQLite over the window's rows, never by loading rows into Python |
| Shares | taken against the window's own total population, not the returned rows |
| Averages | computed from the summed totals; `null`, never `0`, when the population is empty |
| Durations | computed only over conversations that ended; `null` when none ended |
| Rankings | ordered by the requested metric, with the name as tie-break so the order is total |
| Timestamps | rendered ISO-8601 UTC, matching the M13 convention |

### 12.5 Rate and limit defaults

| Parameter | Default | Maximum | Applies to |
| --- | --- | --- | --- |
| `window` (rate label) | `1s` | one of `1s`, `10s`, `60s` | `analytics/traffic` |
| `limit` | 10 | 100 | `analytics/traffic`, `analytics/devices`, `analytics/connections` |
| `by` | `packets` (`bytes` for connections) | one of `packets`, `bytes` | all five |
| `bucket_seconds` | chosen from the table | one of the documented sizes | all five |

The `limit` ceiling is the analytics layer's own group cap (`MAX_GROUPS = 100`),
reused rather than re-declared, so a ranking cannot end up with two different
answers to "how long may a ranking be".

---

## 13. API contracts

All five endpoints follow the M13 envelope:

```json
{
  "success": true,
  "message": "Traffic analytics retrieved",
  "data": { "...": "..." }
}
```

### 13.1 Query parameters (common)

| Name | Type | Required | Notes |
| --- | --- | --- | --- |
| `since` | string | no | ISO-8601 UTC, inclusive |
| `until` | string | no | ISO-8601 UTC, exclusive |
| `bucket_seconds` | int ≥ 1 | no | one of the documented sizes |

### 13.2 `GET /api/v1/analytics/traffic`

| Parameter | Type | Default |
| --- | --- | --- |
| `window` | `1s` \| `10s` \| `60s` | `1s` |
| `limit` | int 1..100 | 10 |
| `by` | `packets` \| `bytes` | `packets` |

Response `data`: the M13 traffic fields (§7.1) plus

```json
{
  "period": { "since": "...", "until": "...", "seconds": 3600.0,
              "bucket_seconds": 30, "buckets": 121, "max_buckets": 240,
              "defaulted": true },
  "stored": {
    "available": true,
    "error": null,
    "data": {
      "total_packets": 0, "total_bytes": 0,
      "packets_per_second": 0.0, "bytes_per_second": 0.0,
      "average_packet_bytes": null,
      "first_timestamp": null, "last_timestamp": null,
      "distinct_protocols": 0,
      "packets_without_source_port": 0, "packets_without_destination_port": 0,
      "stored_packet_count": 0,
      "series": [ { "start": "...", "packets": 0, "bytes": 0 } ],
      "top_sources": [], "top_destinations": [], "top_ports": [],
      "protocols": []
    }
  }
}
```

### 13.3 `GET /api/v1/analytics/protocols`

| Parameter | Type | Default |
| --- | --- | --- |
| `by` | `packets` \| `bytes` | `packets` |

Response `data`: M13's `count` / `total_packets` / `total_bytes` / `rank_by` /
`protocols`, plus `period` and `stored` (`StoredProtocolsData`).

### 13.4 `GET /api/v1/analytics/devices`

| Parameter | Type | Default |
| --- | --- | --- |
| `by` | `packets` \| `bytes` | `packets` |
| `limit` | int 1..100 | 10 |

Response `data`: M13's `total` / `by_status` / `rank_by` / `top`, plus `period`
and `windowed` (`DeviceWindowData`).

### 13.5 `GET /api/v1/analytics/connections`

| Parameter | Type | Default |
| --- | --- | --- |
| `by` | `packets` \| `bytes` | **`bytes`** |
| `limit` | int 1..100 | 10 |

Response `data`: M13's `active` / `historical` / `tracked` / `rank_by` / `top`,
plus `period` and `stored` (`StoredConnectionsData`).

### 13.6 `GET /api/v1/analytics/threats`

No endpoint-specific parameters beyond the common three.

Response `data`: M13's alert, detection and incident blocks, plus

```json
{
  "period": { "...": "..." },
  "stored":    { "available": true, "error": null, "data": { "...": "..." } },
  "findings":  { "retained": 0, "in_window": 0, "mean_confidence": null,
                 "by_confidence_range": {}, "by_rule": [] },
  "incident_links": { "incidents_total": 0, "incidents_with_alerts": 0,
                      "alerts_in_incidents": 0 }
}
```

### 13.7 Why the M15 TypeScript models still work

The M16 additions are **purely additive**:

- Every M13 field keeps its name, its type and its source.
- `avg_packet_bytes`-style division already happened in the backend and still does.
- `period`, `stored`, `windowed`, `findings` and `incident_links` are new keys.
  TypeScript interfaces ignore keys they do not declare, so an M15 build that
  predates them continues to type-check and render.
- `stored_packet_count` keeps its M13 meaning — the unwindowed row count — so the
  existing M15 integer type is unchanged. It is now read *through* the stored
  section rather than beside it, so a packet table that cannot be read reports
  itself unavailable instead of failing the whole request.
- No `any` is used for any backend-derived value. The M16 additions are typed in
  `frontend/src/types/analytics.ts` and re-exported from the barrel.

The M15 page (`frontend/src/pages/Analytics.tsx`) and its tests were run unchanged
against the M16 backend; see §16.

---

## 14. Validation and error handling

### 14.1 Two kinds of refusal

| Kind | Status | Envelope | Example |
| --- | --- | --- | --- |
| A window that cannot be honoured | `400` | M13 error with `INVALID_FILTER` | inverted range, unknown bucket, span over 30 days |
| A parameter outside its declared bounds | `422` | FastAPI request validation | `limit=0`, `limit=101`, `by=notametric`, `bucket_seconds=0` |

The difference is deliberate. A bound failure is an *answer about the data* — the
question is well-formed but unanswerable — so it comes back in the project's own
error envelope with a queryable code. A parameter failure never reaches a handler
at all, so it is FastAPI's own `422`, which is what M13 already documents for
every other endpoint.

`INVALID_FILTER` is produced by `analytics_window()`, which converts the
`ValueError` raised by `resolve_window` (and by the M13 timestamp parser) into the
M13 error. FastAPI validation runs first, so `bucket_seconds=0` is a `422` while
`bucket_seconds=7` is a `400` — one is out of range, the other is a well-formed
value that is not a supported resolution.

### 14.2 The refusal cases, each covered by a test

| Request | Result |
| --- | --- |
| `since` after `until` | `400 INVALID_FILTER` |
| `since` equal to `until` | `400 INVALID_FILTER` |
| span greater than 30 days | `400 INVALID_FILTER` |
| `bucket_seconds` not in the documented sizes | `400 INVALID_FILTER` |
| `bucket_seconds` that would exceed 240 points | `400 INVALID_FILTER` |
| malformed `since` / `until` | `400 INVALID_FILTER` |
| `limit` below 1 or above 100 | `422` |
| `by` not a rank metric | `422` |
| `bucket_seconds` below 1 | `422` |
| `window` not a rate label | `422` |

### 14.3 Error bodies expose nothing internal

An error body names the field and the rule, and nothing else: no table name, no
column, no SQL, no stack trace, no exception text. This is M13.30's rule, and M16
routes honour it — including the unavailable-section message, which is one fixed
sentence:

```text
This section could not be read from the database
```

### 14.4 Empty versus unavailable versus unknown

This is the distinction M16.8 exists for, and M16 preserves it exactly:

| Answer | Meaning | Representation |
| --- | --- | --- |
| `0` | the value is known and is zero | a number |
| empty | a valid query, and the store holds no matching record | `available: true`, zeroes, `first_timestamp: null` |
| unknown | the value was never reported | `null` |
| unavailable | the block could not be read at all | `available: false`, `error: "<fixed sentence>"`, `data: null` |

Nothing converts unavailable or unknown into `0`:

- A failed read produces `available: false` with `data: null`. It never produces a
  zeroed payload, which would read as a measurement.
- A statistic that has no observation — an average over no packets, a duration
  over conversations that have not ended, a mean confidence over no findings — is
  `null`, because `0` would be a claim rather than an absence.
- A timestamp that was never observed is `null`, not epoch 1970.
- An available section holding zeroes says "the store holds nothing in this
  window", which is a real and reportable fact.

The same rule governs recovery: a failed statement leaves the SQLAlchemy session
needing a rollback, so `read_section` rolls it back before reporting. Without
that, one unavailable block would silently make the following ones unavailable
too, and a client would be told three services were broken when one was.

---

## 15. Performance considerations

### 15.1 Where the work happens

Aggregation is done **in SQLite**, not in Python:

| Question | How it is answered |
| --- | --- |
| totals and byte sums | `COUNT` / `SUM` over the window's rows |
| time series | `GROUP BY` the bucket expression, computed in SQL |
| protocol, address, port, severity, status, band breakdowns | `GROUP BY` the column |
| top-N | `ORDER BY` the requested metric with a `LIMIT` |
| distinct protocol count | `COUNT(DISTINCT protocol)` |
| duration statistics | `MIN` / `AVG` / `MAX` over `end_time - start_time` |
| row count | `COUNT` |

No query loads the packet table into Python. The only rows that cross into Python
are the ones a response actually carries: at most `MAX_BUCKETS` series points and
at most `limit` ranking entries per list.

### 15.2 What the design avoids

| Anti-pattern | How M16 avoids it |
| --- | --- |
| unbounded queries | a window always has bounds; the span is capped at 30 days |
| unbounded series | the bucket is chosen to fit 240 points; a requested bucket that would not fit is refused; the statement carries its own `LIMIT` |
| N+1 queries | each block is one statement; the incident registry is read once and both breakdowns come from that single snapshot; the M6 snapshot is read once per request |
| repeated expensive aggregation | a request resolves its window once and passes it to every block |
| a second traffic-statistics engine | totals and live rates come from M6, not from a re-aggregation of the same packets |
| loading rows to count them | `COUNT` / `SUM` in SQL |

### 15.3 Indexes

**No index was added by M16.** Every analytics filter is on a column an earlier
milestone already indexed:

| Query | Filter | Index |
| --- | --- | --- |
| packets by window | `timestamp` | `idx_packets_timestamp` |
| packet source ranking | `source_ip` | `idx_packets_source_ip` |
| packet destination ranking | `destination_ip` | `idx_packets_destination_ip` |
| packet protocol breakdown | `protocol` | `idx_packets_protocol` |
| packet port rankings | `source_port`, `destination_port` | `idx_packets_source_port`, `idx_packets_destination_port` |
| conversations by window | `start_time` | `idx_connections_start_time` |
| conversation rankings | `source_ip`, `destination_ip` | `idx_connections_source_ip`, `idx_connections_destination_ip` |
| alerts by window | `created_at` | `idx_alerts_created_at` |
| alert breakdowns | `severity`, `status` | `idx_alerts_severity`, `idx_alerts_status` |

An index on a `GROUP BY` column (`protocol`, `severity`, `status`, `risk_score`,
`confidence`) would be redundant: SQLite reaches that column only after the
`WHERE` on the indexed timestamp column has already narrowed the candidate set,
and the grouping itself is unavoidable. Adding one would cost write throughput on
the capture path — which matters, because those tables are written continuously —
and buy a scan that is already small.

### 15.4 Measured baseline

Produced by `backend/scripts/benchmark_m16.py`. The store is seeded with 10 000
packets, 100 conversations and 20 alerts spanning 60 minutes; each measurement is
20 timed calls after 3 discarded warm-ups. Times are milliseconds.

Environment, as the script reports it:

```text
python    : 3.13.2 (AMD64)
platform  : Windows 11
sqlite    : 3.45.3
transport : in-process client (TestClient), so no network stack
store     : one local SQLite file, single process, single machine, unwritten
```

**The five routes over the whole seeded window:**

| Measurement | p50 | mean | p95 | max | what it returned |
| --- | ---: | ---: | ---: | ---: | --- |
| `analytics/traffic` | 28.20 | 28.26 | 29.52 | 29.77 | 10 000 stored packets, 125 points |
| `analytics/protocols` | 9.08 | 9.17 | 10.22 | 10.30 | 3 protocols of 3 |
| `analytics/devices` | 2.72 | 2.74 | 3.14 | 3.30 | registry read, 0 in period |
| `analytics/connections` | 8.37 | 8.40 | 8.80 | 9.09 | 100 stored, 66 durations |
| `analytics/threats` | 8.32 | 8.37 | 8.75 | 8.99 | 20 alerts stored |

Median across all five: **8.58 ms**. With no bounds (the one-hour default):
**8.48 ms** — the default window is not cheaper by much, because the cost of
`analytics/traffic` is dominated by scanning the window's rows, and the seeded
traffic sits inside an hour.

**One route as the window lengthens:**

| Window | p50 | mean | p95 | max | resolved | stored |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| 5 minutes | 9.14 | 9.12 | 9.85 | 9.98 | 10 s buckets | 830 |
| 60 minutes | 28.40 | 29.10 | 30.45 | 42.36 | 30 s buckets | 9 997 |
| 1440 minutes | 28.25 | 31.20 | 28.94 | 91.73 | 900 s buckets | 10 000 |

**Aggregate queries, no HTTP:**

| Measurement | p50 | what it covered |
| --- | ---: | --- |
| `PacketAnalytics.totals` | 3.13 | 10 000 packets |
| `PacketAnalytics.series` | 5.58 | 121 buckets |
| `PacketAnalytics.protocols` | 2.51 | 3 groups |
| `PacketAnalytics.distinct_protocols` | 1.22 | 3 distinct |
| `PacketAnalytics.top_sources` | 6.20 | 10 of 100 max |
| `PacketAnalytics.top_destination_ports` | 2.33 | 10 ports |
| `PacketAnalytics.stored_count` | 0.14 | 10 000 rows |
| `ConnectionAnalytics.totals` | 0.41 | 100 conversations |
| `ConnectionAnalytics.duration_stats` | 0.48 | 66 samples |
| `ConnectionAnalytics.count_by_status` | 0.27 | 3 states |
| `ConnectionAnalytics.series` | 0.73 | 100 buckets |
| `AlertAnalytics.totals` | 0.42 | 20 alerts |
| `AlertAnalytics.count_by_risk_band` | 0.39 | 4 bands |
| `AlertAnalytics.count_by_confidence_range` | 0.40 | 4 ranges |
| `AlertAnalytics.top_rules` | 0.51 | 4 rules |
| `AlertAnalytics.series` | 0.49 | 20 buckets |

Median across all 16: **0.53 ms**. **Window resolution** costs **0.00 ms** at
every shape tested (default, 60 m, the 30-day ceiling, an explicit 10 s bucket) —
it is arithmetic on the bounds, not a query.

**How cost moves with the store:**

| Rows | `traffic` p50 | `traffic` p95 | `totals` p50 | `series` p50 |
| ---: | ---: | ---: | ---: | ---: |
| 10 000 | 28.61 | 29.20 | 3.02 | 5.58 |
| 50 000 | 138.60 | 146.67 | 18.05 | 35.02 |
| 100 000 | 281.81 | 297.48 | 35.42 | 67.10 |

Growth is linear in the rows scanned, which is what a full-window aggregate over
an index-ordered table should be. It is not sub-linear, and M16 makes no claim
that it is.

### 15.5 What these numbers are and are not

They are **local development measurements**: one machine, one process, one SQLite
file, an in-process client. They exist so that a change to the analytics layer can
be compared against a recorded baseline, and so that the five routes can be
compared against each other.

They are **not** a capacity claim. No load generator, no concurrency, no
production hardware and no production data size is involved. Nothing here
supports a statement about how many clients or how many packets per second a
deployment would sustain.

The benchmark also excludes the capture path entirely — normalization, M6
statistics, M7 persistence, M8 discovery, M9 tracking, M10 detection, M11
alerting and M12 correlation each have their own milestone baseline. The
in-memory views (the M8 registry, M9 tracker, M10 engine, M12 registry) are empty
in the benchmark, so the live halves measure a fresh process.

---

## 16. Testing and verification

### 16.1 Analytics tests

254 tests across five files:

| File | Tests | Covers |
| --- | ---: | --- |
| `tests/test_analytics_window.py` | 30 | bounds, defaults, the ceiling, bucket selection, epoch alignment, the Python/SQL bucket agreement |
| `tests/test_analytics_queries.py` | 41 | the SQL layer directly: totals, series, groupings, rankings, duration statistics, empty windows |
| `tests/test_analytics_views.py` | 53 | the `build_*` functions: response shapes, percentages, truncation, `null` versus `0`, banding |
| `tests/test_analytics_service.py` | 37 | `AnalyticsService`: live + stored assembly, the period, ranking order, unavailable sections, rollback |
| `tests/test_analytics_api.py` | 93 | the five routes over HTTP: defaults, validation, limits, schemas, empty results, error handling |

Each area named in the milestone's test plan is present:

| Area | Tests |
| --- | --- |
| Traffic — empty data, normal data, time filtering, aggregation, bucket limits, source/destination ranking, packet and byte totals | yes |
| Protocols — empty, multiple protocols, percentages, unknown protocol, zero totals | yes |
| Devices — no devices, active/inactive/unknown, traffic attribution, top talkers, timestamps | yes |
| Connections — none, protocol aggregation, status aggregation, active, duration | yes |
| Threats — findings, rules, severity, confidence, alerts, lifecycle, incidents, risk bands, status, time filtering | yes |
| API — defaults, validation, maximum limits, schemas, empty results, error handling | yes |

### 16.2 Full regression

```text
2083 passed, 1 warning in 19.80s
```

The single warning is `StarletteDeprecationWarning: Using httpx with
starlette.testclient is deprecated`, raised from the installed FastAPI package —
not from project code.

All existing M0–M15 tests pass; M16 changed no M0–M15 behaviour, only added
alongside it.

### 16.3 Type checking

```text
0 errors, 0 warnings, 0 informations
```

Pyright over the whole backend, including the analytics modules and the two M16
scripts.

### 16.4 End-to-end verification, part 1 — sample mode

`backend/scripts/verify_m16.py sample` builds the **real** stack — M6 statistics,
M7 persistence, M8 discovery, M9 tracking, M10 detection, M11 alerting, M12
correlation, driven through `PacketPipeline.process` — over an isolated throwaway
SQLite database, drives controlled packets through it, then serves the real
FastAPI application with its dependencies overridden onto that same stack.

The one substitution is the sniffer, which is dispensed with entirely: the packets
are handed to the pipeline at the same seam the capture callback uses. Everything
downstream runs for real. **No mock data, no fixtures, no hand-built payloads.**

Result:

```text
packets  : 14 driven through the real pipeline (9 TCP SYNs, 5 UDP sweeps)
after capture: processed=14 findings=2 incidents=1
stage errors: processing=0 persistence=0 statistics=0 devices=0
              connections=0 detection=0 alerts=0 correlation=0
stored bounds: 2026-10-08T04:54:35.146360+00:00 .. 2026-10-08T04:54:35.146360+00:00
Sample mode complete - all checks passed.
```

What it proves, against the completion criteria:

| Check | Result |
| --- | --- |
| all five routes answer `200` in the M13 envelope | yes |
| every response carries a resolved `period` | yes, `bucket_seconds=30`, `buckets=121`, `defaulted=True` |
| the default window is the documented hour | yes, `seconds≈3600` |
| stored totals equal a direct SQL read of the same table | yes — 14 packets, 696 bytes, both |
| `since` is inclusive at the newest stored instant | yes — 14 packets selected |
| `until` is exclusive at the newest stored instant | yes — 0 packets selected |
| an empty window is *available* with zeroes and no invented instant | yes, on all five routes |
| the empty window is not confused with an unreadable one | yes — `available=true`, `error=null` |
| device analytics report the real registry (2 devices, `inactive`) | yes |
| device rankings carry `first_seen` / `last_seen` and no risk score | yes |
| stored conversations equal the table's count in the window | yes — 14 |
| the status breakdown sums to the stored total | yes — 14 |
| duration statistics are `null` with `samples=0`, not zero | yes |
| alerts and incidents were produced by real detections | yes — 2 alerts, 1 incident, `highest_risk_score=61` |
| the stored alert breakdowns each sum to the stored total | yes — severity, status, risk band, confidence |
| the rule ranking accounts for the window's alerts | yes — 2 ranked + 0 keyless = 2 |
| findings, alerts and incidents stay three distinct things | yes — 2 findings, 2 alerts, 1 incident |
| protocol shares are shares of the window | yes — 64.29 % + 35.71 % = 100 % |
| rankings follow `by` and are ordered | yes — `by=packets` → [9, 5]; `by=bytes` → [486, 210] |
| `limit` is capped at 100 | yes — `limit=101` → `422`, `limit=100` → `200` |
| a series never exceeds 240 points | yes — 121, 97 and 181 in the three shapes tested |
| bucket starts are exact multiples of the bucket size | yes |
| buckets lie inside their window | yes |
| inverted, empty, over-long, unknown-bucket and malformed requests are refused | yes — 7/7 `400 INVALID_FILTER` |
| out-of-range parameters are `422` | yes — 4/4 |

### 16.5 End-to-end verification, part 2 — live mode

`backend/scripts/verify_m16.py live` starts the application under uvicorn on a
loopback port and issues **real HTTP requests** over a socket.

```text
base url : http://127.0.0.1:8016
database : the configured one; this mode only reads
/api/v1/analytics/traffic          200 bucket=30s available=True
/api/v1/analytics/protocols        200 bucket=30s available=True
/api/v1/analytics/devices          200 bucket=30s available=True
/api/v1/analytics/connections      200 bucket=30s available=True
/api/v1/analytics/threats          200 bucket=30s available=True
malformed since -> 400 ['INVALID_FILTER']
Live mode complete - all checks passed.
```

This mode asserts *wiring* over real HTTP, not row counts: the configured
database may legitimately be empty, so the claim is that the documented URLs
answer in the documented envelope, with a resolved period and an available stored
block, and that an unhonourable window is still refused. It reads only — it writes
nothing — so it is safe against a working installation.

### 16.6 Frontend verification

The M15 frontend was re-run against the M16 backend:

- `tsc --noEmit -p tsconfig.json` — no type errors.
- Unit suite — **422 tests across 15 files, all passing**.
- Production build (`vite build`) — succeeded: 2545 modules transformed, 893.24 kB
  of JavaScript (237.50 kB gzipped) and 23.17 kB of CSS. The only output note is
  Vite's chunk-size advisory, which is unrelated to M16.
- The M16 additions are typed in `frontend/src/types/analytics.ts`, exported from
  the barrel, and exercised by fixtures and the analytics page tests.
- No `any` appears for any backend-derived value.

### 16.7 Contract verification (M16.15)

The running responses were compared with the schemas the M15 frontend consumes,
field by field, rather than assumed to match. Findings:

| Finding | Resolution |
| --- | --- |
| M13 returned `stored_packet_count` but no windowed traffic | M16 added `stored`, keeping `stored_packet_count` at its M13 meaning |
| the frontend needed a window it could display | `period` added to all five models, with `defaulted` and `max_buckets` |
| `first_seen` / `last_seen` were absent from a ranked device | added to `RankedDevice`, `null` when the registry has not dated the record |
| the backend had no way to say "could not read" | `AnalyticsSection` added; `available` / `error` / `data` on every database-derived block |

No mismatch was found that required *changing* an existing M13 field. The M16
additions are additive, which is why the M15 build continues to work unchanged.
No field is typed `any` on the frontend, and every new backend field is declared
in `frontend/src/types/analytics.ts`.
---

## 17. Known limitations

Each of these is a real limit of the current implementation, stated rather than
worked around. None is a bug; several are deliberate, and the ones inherited from
another milestone are inherited unchanged.

### 17.1 The M8 registry is a snapshot, not a history

The M8 registry holds one *current* record per device: its latest addresses, its
activity state and its `first_seen` / `last_seen` bounds. It keeps no record of
what it observed earlier, and M16 does not add one.

Consequence: the `windowed` block on `analytics/devices` answers **"which devices
were last seen inside this period"**, not "what was observed during this period".
A device that was active in the window but has since gone quiet is not counted in
it. `first_seen` and `last_seen` are the registry's own bounds, so they are
correct; the *set* of devices a window selects is bounded by what the registry
still remembers.

Reconstructing per-window device activity properly would require an observation
log M8 does not keep. M16 does not invent one.

### 17.2 Routed traffic can make a device id a next hop

Inherited unchanged from M8/M15. Where traffic is routed, the next-hop MAC address
can represent several remote IP addresses, so a single device id may carry many
addresses that are not the same host. M16 reports M8's addresses exactly as
recorded and adds no correction — no heuristic, no address-to-device splitting.
A ranking row's addresses are therefore *the addresses seen under that device id*,
not a claim about which remote host sent any particular packet.

### 17.3 An alert's stored risk band can mean "not yet scored"

M11 writes `risk_score = 0` and leaves it until M12 correlates the alert. So in
`stored.by_risk_band`, an alert that no incident has reached is banded `minimal`.
That is the truthful reading of its stored value, but it means *not yet scored*,
not *assessed as minimal*. The live `incidents_by_risk_band` and
`highest_risk_score` are where a scored judgement appears. This is documented on
`StoredAlertsData`, in the TypeScript type, and in §11.6.

### 17.4 Findings are retained in memory, and bounded

The findings blocks on `analytics/threats` read M10's **in-memory** bounded
history, not a table. Two consequences:

- A finding older than M10's retention is not in `retained`, so it is not in
  `in_window` either, even if it falls inside the requested period. `in_window`
  can therefore be smaller than the number of findings the detectors actually
  produced in that window.
- Restarting the process empties that history. An `alerts`-side figure survives a
  restart, because alerts are persisted; a findings-side figure does not.

Alerts and incidents are not affected in the same way: alerts are read from
SQLite, and incidents come from the M12 registry (in memory, but priced by that
milestone's own retention rules).

### 17.5 A stored series describes persistence, not the network

A bucket with zero packets means the store holds no packet in that interval. It
does not mean the network was idle: capture may have been stopped, the interface
may have been down, or persistence may have been unavailable. Every stored block
is named `stored` for exactly this reason, and the live counters are reported
beside it so the two can be compared.

### 17.6 Aggregation is a full scan of the window's rows

SQLite performs `COUNT`, `SUM` and `GROUP BY` over the rows the window selects,
using the timestamp index to find them. Cost is therefore **linear in the rows in
the window** — measured in §15.4 — not sub-linear. Reducing it would require
pre-aggregation (a rollup table written on the capture path), which is a different
milestone's concern and was deliberately not introduced here: it would put
analytics-derived state on the write path, which M16 exists to avoid.

### 17.7 Percentages and rates are floating-point

Shares and rates are computed as doubles and serialised as JSON numbers. A share
is therefore correct to floating-point precision, not exact: an untruncated
protocol breakdown sums to 100 % within a small tolerance, which is what the tests
assert, rather than exactly 100.0 in every case.

### 17.8 Rate labels are the only three M6 offers

The `window` parameter on `analytics/traffic` accepts `1s`, `10s` and `60s`,
because those are the rate windows M6 maintains. M16 adds no fourth window: doing
so would mean a second rate calculation, which is the thing M16 is built not to
do.

### 17.9 The baseline is a local development measurement

§15.4's figures are from one machine, one process, one SQLite file and an
in-process client. They support comparing analytics changes against a recorded
baseline; they do not support any statement about production capacity. See §15.5.

### 17.10 No authentication, no tenancy

M16 adds no access control. The analytics routes are as open as the rest of the
M13 API, and every request reads the same store. Authentication and RBAC are
explicitly later milestones.

---

## 18. Completion checklist

| Criterion | Status | Evidence |
| --- | :-: | --- |
| Analytics architecture is implemented | ✅ | `window.py`, `metrics.py`, `sections.py`, `*_queries.py`, `*_view.py`, `live_view.py`, `service.py` (§6) |
| Traffic analytics work | ✅ | §7; 93 API tests + `verify_m16` checks on real pipeline data |
| Protocol analytics work | ✅ | §8; shares of the window, truncation reported |
| Device analytics work | ✅ | §9; M8 registry + `windowed`, no risk score |
| Connection analytics work | ✅ | §10; M9 counters + stored rows, duration statistics |
| Threat analytics work | ✅ | §11; findings, alerts and incidents kept distinct |
| Time filtering works | ✅ | §12; `[since, until)` verified at the boundary in sample mode |
| Aggregation is bounded | ✅ | §12.3; 240-point ceiling, own `LIMIT` on every series |
| API validation works | ✅ | §14.2; 7 refusals at `400`, 4 at `422`, all exercised |
| Empty/unavailable states are handled correctly | ✅ | §14.4; empty is `available: true` with zeroes, unavailable is `available: false` with `data: null` |
| Existing M13 API conventions are preserved | ✅ | §13; M13 envelope, `INVALID_FILTER`, ISO-8601 UTC, no internals exposed |
| M15 frontend remains compatible | ✅ | §16.6; additive schema, typecheck and 422 unit tests pass |
| Analytics tests pass | ✅ | §16.1; 254 analytics tests |
| Full regression suite passes | ✅ | §16.2; `2083 passed` |
| Pyright/type checking passes | ✅ | §16.3; `0 errors, 0 warnings, 0 informations` |
| Performance baseline is recorded | ✅ | §15.4; `benchmark_m16.py` |
| Manual verification with real data succeeds | ✅ | §16.4 and §16.5; both verifier modes pass |
| `docs/13_M16_Analytics_Design.md` is complete | ✅ | this document |

---

## 19. M16 closure

**Status: implemented and verified.**

M16 added the persisted half of the analytics layer and hardened all five
endpoints, without changing a single M13 field the M15 frontend depends on and
without introducing a second statistics engine, a second device identity, a
second risk score or any detection logic.

What exists now:

- **One time model** (`app/analytics/window.py`) that every route uses, with
  half-open UTC bounds, capped span, epoch-aligned buckets from a fixed table, and
  a hard 240-point ceiling that no request can exceed.
- **A bounded SQL query layer** over `packets`, `connections` and `alerts`, using
  the indexes M7/M9/M11 already defined and adding none.
- **Five hardened endpoints** answering in the M13 envelope, each reporting its
  resolved `period` and its persisted block as an availability section.
- **An honest empty/unavailable/unknown distinction**: a zero means zero, an empty
  window is available and zeroed, an unmeasured value is `null`, and an unreadable
  block says so in one safe sentence.
- **254 analytics tests**, a clean full regression (`2083 passed`), clean type
  checking, and a two-mode verification script that exercised the real pipeline
  end to end and the running application over real HTTP.
- **A recorded local performance baseline**, with its own limits stated.

Work explicitly **not** done, and belonging to later milestones: ML anomaly
detection, behavioural baselines, AI explanations, local LLM/Ollama, automatic
blocking, IPS, SIEM and threat-intelligence integrations, authentication and RBAC,
report generation, notification delivery, and distributed sensors. Nothing in
this document claims any of them.

M16 is ready to close.
