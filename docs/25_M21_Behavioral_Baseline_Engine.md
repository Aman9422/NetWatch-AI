# M21 — Behavioral Baseline Engine

**Project:** NetWatch AI
**Milestone:** M21
**Version:** v0.0.21
**Base version:** v0.0.20
**Status:** Implemented and verified
**Scope:** Behavioural learning only. No anomaly detection, no alerting.

---

## 1. Purpose and scope

M21 teaches NetWatch AI what a device's network behaviour normally looks like, and
keeps that knowledge across restarts. For each device it observes, the engine
accumulates behavioural samples over fixed time windows, calculates a robust
statistical profile from them, and records how mature that profile is.

M22 will compare a fresh window against a profile and decide whether it deviates.
**M21 does not do that.** It builds the knowledge base; it issues no verdict, no
score, no alert, and no anomaly classification. That boundary is enforced in the
code, the API and the UI — every payload carries a `disclaimer` sentence saying
so, `established` is deliberately never rendered as a safety state, and there is
no score field anywhere to display.

### Implemented

| Area | What exists |
|---|---|
| Feature extraction | Nine per-device behavioural metrics from normalized packets |
| Aggregation | Bounded in-memory 60-second windows, flushed in batches |
| Persistence | Two SQLite tables with uniqueness and retention indexes |
| Statistics | count, mean, median, MAD, MAD×1.4826, stdev, p95, min, max |
| Lifecycle | `learning` → `provisional` → `established`, sample-count driven |
| Retention | 7-day default, driven by the existing M19 sweeper |
| REST | list, detail, reset under `/api/v1/baselines` |
| Frontend | Behavioral Baselines page with list, detail and reset |
| Tests | 177 new backend tests, 26 new frontend tests |

### Explicitly not implemented

ML anomaly detection; Isolation Forest / One-Class SVM / autoencoders; anomaly
scoring or classification; baseline-deviation alerts; a local LLM; LLM log
analysis; the AI Security Analyst; Wazuh integration; automatic blocking or IPS;
any cloud learning service. These belong to M22 and later.

---

## 2. Architecture and data flow

The engine is an additional consumer in the pipeline that already exists. It does
not capture, decode or classify anything itself.

```
M5 packet processor (normalized packets)          ← existing
        │
        ├── packets channel (M14)                 ← existing
        ├── M6 statistics                         ← existing
        ├── M8 device registry                    ← existing
        ├── M9 connection tracker                 ← existing
        ├── M10 detection → M11 alerts → M12      ← existing
        │
        └── M21 BaselineEngine.observe(packet)    ← added
                 │
                 ├── features.observe()      → one PacketObservation | None
                 ├── WindowAggregator        → in-memory per-device counters
                 │        (flush every 5 s, window 60 s)
                 ├── store.write_window()    → baseline_windows
                 ├── store.recompute_profile → baseline_profiles
                 └── retention (M19 sweep)   → delete aged windows
```

Module layout, one responsibility per file:

| Module | Responsibility |
|---|---|
| `app/baselines/features.py` | What one normalized packet contributes (M21.4) |
| `app/baselines/aggregation.py` | The bounded in-memory window (M21.5) |
| `app/baselines/statistics.py` | The robust statistical profile (M21.6) |
| `app/baselines/states.py` | Learning lifecycle and maturity (M21.7) |
| `app/baselines/store.py` | Persistence, reads, reset, retention queries (M21.8) |
| `app/baselines/engine.py` | The runtime component the pipeline feeds (M21.9) |
| `app/baselines/retention.py` | Retention policy the M19 sweep drives (M21.8) |

Integration points: `app/services/packet_pipeline.py` (feeds the engine),
`app/services/capture_manager.py` (lifecycle and flush on stop), `app/main.py`
(startup/shutdown flush), `app/services/retention_scheduler.py` (third policy),
`app/api/v1/baselines.py` (routes), `app/schemas/baseline.py` (wire models).

**Failure isolation.** A baseline failure cannot stop capture. `observe()`
returns `None` on any internal error rather than raising, and the pipeline both
guards the call and counts skips, so a broken frame or a full store degrades
baseline coverage and nothing else.

---

## 3. Behavioural features

| Feature | Source | Notes |
|---|---|---|
| `packet_count` | Packet count per window | Always available |
| `byte_count` | `packet.length` summed | Clamped to `>= 0` |
| `tcp_packets` | M5 protocol label `TCP` | |
| `udp_packets` | M5 protocol label `UDP` | |
| `icmp_packets` | Label `ICMP` or `PacketType.ICMP` | |
| `dns_packets` | `PacketType.DNS` | Counts in its transport total too |
| `unique_peers` | Distinct destination IPs | Cardinality only — no address stored |
| `unique_destination_ports` | Distinct destination ports | Cardinality only |
| `new_connections` | Distinct `protocol\|peer_ip\|port` first seen | `null` when unmeasurable |

**A DNS packet counts as both UDP and DNS.** The alternative — forcing the
protocol counts to sum to the packet count — would mean a DNS packet was either
not UDP or not DNS. Both facts are true, so both are recorded.

**Unsupported, and documented rather than guessed:**

- **No inbound/outbound split.** Attribution is by sender, and on a routed path
  this capture cannot determine direction reliably (M21.4's conditional). No
  inbound packet or byte counter is produced.
- **Consequence:** a device that is only ever seen *receiving* is not profiled.
  This is a known limitation, stated in §12, not a bug.
- **No hostname, vendor, OS, port-list or payload feature.** The engine reports
  cardinalities, never the sets.

---

## 4. Device identity

Identity is the M8 string key: `mac:aa:bb:cc:dd:ee:ff` or `ip:10.0.0.7`.

**A packet is attributed to the device that sent it.** The source endpoint is
built from `source_mac` / `source_ip`; the destination is recorded as a *peer*,
never as a device.

That asymmetry is what keeps the router problem out of the baseline. On a routed
path the L2 destination of a frame is the next hop, so keying by destination MAC
would bind every far-end address behind a gateway to the gateway's MAC and
collapse unrelated hosts into one device. A *source* endpoint cannot have that
problem: the frame header names the sender, so its MAC and IP are genuinely its
own.

**IP change.** `source_mac` is preferred precisely because it survives an address
change. A device that moves from `10.0.0.21` to `10.0.0.99` keeps one
`mac:...` key and therefore one continuous baseline; its `last_ip_addresses` is
updated rather than a second profile being created.

**Fallback policy.** When a packet carries no usable MAC, the canonical source IP
is used and the profile is marked `identity_kind="ip"`, which the API and UI both
label as the weaker identity — an IP-keyed profile may not follow the physical
device across an address change.

**Unattributable packets are skipped, not pooled.** Broadcast, multicast,
unspecified, all-zero and link-local-untrackable sources produce `None` from
`features.observe()`. Such a packet is counted as skipped and is **never**
attributed to a placeholder device. The same gate M8 uses
(`is_trackable_endpoint`) decides this, so the two layers cannot disagree.

**The `devices` table is not required.** M20 documents that the live registry is
in memory and the table holds development seed data. `baseline_profiles` keys on
the M8 *string* identity, so baselines work whether or not any row was ever
written to `devices`, and survive a registry eviction.

---

## 5. Time-window aggregation

| Setting | Default | Meaning |
|---|---|---|
| `baseline_window_seconds` | `60.0` | Aggregation interval |
| `baseline_flush_interval_seconds` | `5.0` | How often pending windows are written |
| `baseline_max_tracked_devices` | `4096` | Devices held in memory at once |
| `baseline_max_peers_per_window` | `1024` | Peer-set cap per device per window |
| `baseline_max_ports_per_window` | `1024` | Port-set cap per device per window |
| `baseline_max_connection_keys` | `4096` | Conversation keys remembered per device |
| `baseline_max_windows_per_flush` | `500` | Rows one flush may write |

Rules the implementation enforces:

1. **Counters are aggregated in memory.** A packet updates counters; it never
   triggers a database write.
2. **No per-packet writes.** A flush writes at most `baseline_max_windows_per_flush`
   rows, every `baseline_flush_interval_seconds`.
3. **Capture is never blocked.** The pipeline calls the engine and moves on.
4. **Memory is bounded.** Device count, peer sets, port sets and connection-key
   sets each have a configured cap; the oldest/least-valuable entries are evicted
   when a cap is reached.
5. **Truncation is recorded, not hidden.** When a peer or port set hits its cap
   the window is stored with `peers_truncated` / `ports_truncated = true`, so a
   consumer knows the cardinality is a floor.
6. **Malformed input is skipped, not fatal.** `observe()` cannot raise.
7. **Empty windows are not persisted.** A device that produced no packets in a
   window gets no row — "not observed" and "observed as zero" are different facts.
8. **Graceful shutdown flushes.** `main.py` flushes pending windows and recomputes
   affected profiles on shutdown; `capture_manager` does the same when capture
   stops.

---

## 6. Statistical calculations

Every figure is calculated from **aggregated windows**, never from raw packets.
`baseline_statistics_max_windows` (default `1440`, i.e. 24 h at 60 s) bounds how
many of the most recent samples the profile describes, so the profile stays a
summary of *recent* behaviour rather than an average of all history.

For each feature, over the usable samples:

| Statistic | Definition |
|---|---|
| `count` | Samples that carried a usable value — per feature, not per device |
| `mean` | Arithmetic mean |
| `median` | 50th percentile — the robust centre |
| `mad` | Median of \|x − median\| — the robust spread |
| `mad_scaled` | `mad × 1.4826`, a consistent σ estimate for normal data |
| `stdev` | Population standard deviation (`0.0` for a single sample) |
| `p95` | 95th percentile, linear interpolation (NumPy's default definition) |
| `min` / `max` | Observed range, never widened to a threshold |

**Why MAD beside σ rather than instead of it.** A device with one bulk-transfer
minute has a standard deviation that says "highly variable" and a MAD that says
"mostly steady". Only both together describe it honestly, and M22 will most
likely key on MAD because mean absolute deviation is dragged by the same outlier
that drags the mean.

**Missing observations.** A feature whose every sample was `None` is **absent**
from the profile, never present as zero. `new_connections` is the common case: if
the tracker could not measure it for a window, that window contributes nothing to
the feature's `count`. So `count` can legitimately be lower than the device's
`sample_count`. A feature with no samples at all is omitted rather than reported
as a mean of `0`.

**Small samples.** Median, MAD and p95 are defined for any non-empty sample, so
they are reported even at n=2 — refusing to answer would be worse — with `count`
beside every figure so a consumer can judge. Nothing in M21 claims a p95 from two
windows is stable.

---

## 7. Learning lifecycle

| State | Condition | Statistics published |
|---|---|---|
| `learning` | `sample_count < 5` | **No** — `statistics` is empty |
| `provisional` | `5 ≤ sample_count < 30` | Yes, flagged as still developing |
| `established` | `sample_count ≥ 30` | Yes |

Thresholds are `baseline_provisional_min_samples` (default 5) and
`baseline_established_min_samples` (default 30), counted in observation *windows* —
so 5 and 30 mean five and thirty minutes of observed behaviour at the default
60-second window.

Rules the module enforces:

- **A new device never gets a fabricated baseline.** `learning` publishes no
  statistics at all, rather than a profile of zeroes.
- **Maturity is a sample count, never elapsed time.** A device that appeared once
  an hour ago is still learning; a device that produced thirty windows in thirty
  minutes is established. Time is not evidence of behaviour.
- **The state is a pure function of the count.** There is no transition table, so
  reloading a persisted count also reloads the state, and the two cannot disagree.
  An inconsistent configuration where `established_min < provisional_min` clamps up
  and reports the weaker state rather than skipping a stage; a
  `provisional_min < 1` raises, because a zero threshold would make every device
  established the instant it was created.
- **An unrecognised stored state reads as `learning`.** Claiming more would be
  claiming evidence that is not there.
- **`established` is descriptive, not a verdict.** It means "watched for a while",
  never "safe". The API's `state_description` and `disclaimer` say so in words,
  and the frontend repeats it on the page and in the reset dialog.
- **A restart does not discard a baseline.** The state is recomputed from the
  persisted `sample_count` on the next read.
- **A reset is scoped.** It deletes one device's windows and profile and nothing
  else (see §10).

---

## 8. Database schema

Two tables, extending the existing SQLAlchemy + SQLite architecture. Tables are
created through the repository's existing schema-initialisation path.

### `baseline_profiles`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER | Primary key |
| `device_key` | VARCHAR(80) | **Unique** — one profile per identity |
| `identity_kind` | VARCHAR(8) | `mac` or `ip` |
| `learning_state` | VARCHAR(16) | `learning` / `provisional` / `established` |
| `sample_count` | INTEGER | Windows that shaped the profile; maturity derives from it |
| `statistics_sample_count` | INTEGER | Recent windows the figures describe (bounded) |
| `window_seconds` | FLOAT | Window length the samples were aggregated over |
| `first_observed_at` | DATETIME | UTC |
| `last_observed_at` | DATETIME | UTC |
| `statistics_json` | TEXT | Per-feature figures, serialised |
| `last_mac_address` | VARCHAR(17) | Most recent identity detail |
| `last_ip_addresses` | TEXT | Most recent addresses |
| `created_at` / `updated_at` | DATETIME | UTC, from `TimestampMixin` |

Indexes: `idx_baseline_profiles_state` (filtering by learning state),
`idx_baseline_profiles_last_observed` (recency ordering).

### `baseline_windows`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER | Primary key |
| `device_key` | VARCHAR(80) | |
| `window_start` | DATETIME | UTC start of the window |
| `window_seconds` | FLOAT | Length covered |
| `packet_count`, `byte_count` | INTEGER | Totals |
| `tcp_packets`, `udp_packets`, `icmp_packets`, `dns_packets` | INTEGER | Protocol counts |
| `unique_peers` | INTEGER | Set cardinality |
| `unique_destination_ports` | INTEGER | Set cardinality |
| `new_connections` | INTEGER **NULL** | `NULL` when unmeasurable |
| `peers_truncated`, `ports_truncated` | BOOLEAN | Cardinality is a floor |
| `created_at` | DATETIME | UTC |

Constraints and indexes: `UNIQUE(device_key, window_start)` — which makes a
re-flushed window a no-op rather than a duplicate sample —
`idx_baseline_windows_start` (retention deletes by age),
`idx_baseline_windows_device_start` (the statistics query reads one device's
newest N).

### Design notes

- **`statistics_json` is a document, not 70 columns.** A feature set is a design
  decision (M21.4); one column per statistic per feature would make adding a
  feature a migration.
- **Nothing stores a packet or payload.** A window holds counters and set
  cardinalities — how many peers, never which. That is what makes a multi-day
  retention window tolerable.
- **`baseline_profiles` is not the M2 `behavioral_baselines` table.** That table
  keys on `devices.id` and is M2 seed data; M21 needs an identity that exists
  without that table and survives an IP change. The M2 table is left untouched.
- **Timestamps are UTC throughout**, matching the project convention.

---

## 9. Retention configuration

| Setting | Default | Meaning |
|---|---|---|
| `baseline_retention_days` | `7` | Window rows older than this are deleted |
| `baseline_retention_max_per_run` | `5000` | Most rows one pass deletes |
| `baseline_statistics_max_windows` | `1440` | Recent samples a profile describes |

**The policy is asymmetric on purpose.** A window is *evidence* and evidence ages
out; a profile is the *conclusion* and is kept. When a profile's windows expire,
the profile is **recomputed** rather than removed, so it falls back to `learning`
with its count at zero — the honest statement that its evidence has aged out,
rather than a silent claim that the device was never seen.

The sweep is driven by the existing M19 `RetentionSweeper` as a third policy, so
baseline retention inherits the same interval, the same failure isolation and the
same bounded shutdown as packet and report retention. It issues exactly one write:
a `DELETE` against `baseline_windows`. A failure is reported in the outcome and
logged, never raised into the sweeper.

---

## 10. REST API

All endpoints are versioned under `/api/v1` and use the project's standard
success/error envelopes.

### `GET /api/v1/baselines`

Paginated listing, newest-observed first. Filters: `learning_state`, `limit`
(default `baseline_default_page_size` = 100, max `baseline_max_page_size` = 500),
`offset`.

```json
{
  "success": true,
  "message": "Baselines retrieved",
  "data": {
    "count": 2, "limit": 5, "offset": 0, "total": 2, "has_more": false,
    "baselines": [
      {
        "device_key": "mac:A6:21:AA:90:CB:77",
        "identity_kind": "mac",
        "mac_address": "A6:21:AA:90:CB:77",
        "ip_addresses": ["64:ff9b::ac40:9b77"],
        "learning_state": "provisional",
        "state_description": "The minimum number of observations has been reached, so a profile is available, but it is still developing. Treat its figures as provisional.",
        "sample_count": 8,
        "statistics_sample_count": 8,
        "window_seconds": 60.0,
        "first_observed_at": "2026-11-26T03:58:00+00:00",
        "last_observed_at": "2026-11-26T04:05:59.925641+00:00",
        "statistics": [],
        "recent_windows": [],
        "disclaimer": "A behavioural baseline describes network activity this device has already been observed producing. It is not an anomaly verdict, a risk score or a statement that the device is safe."
      }
    ]
  }
}
```

`statistics` and `recent_windows` are empty in the listing by design; the detail
endpoint supplies them.

### `GET /api/v1/baselines/{device_key}`

One device's profile plus up to `MAX_DETAIL_WINDOWS = 20` of the most recent
observation windows. The key is URL-encoded as a single path segment.

Real response from the live verification (§13):

```
detail mac:A6:21:AA:90:CB:77: windows=8 features=9
  packet_count               n=8   median=3947.50    mean=3732.62    mad=1065.50  p95=5373.65    min=1573.00  max=5430.00
  byte_count                 n=8   median=1741096.50 mean=1992065.75 mad=704666.00 p95=3509946.10 min=985492.00 max=3819561.00
  tcp_packets                n=8   median=3002.00    mean=2955.88    mad=1052.50  p95=4373.70    min=1100.00  max=4464.00
  udp_packets                n=8   median=542.50     mean=761.25     mad=183.00   p95=1572.90    min=343.00   max=1890.00
  icmp_packets               n=8   median=0.00       mean=0.00       mad=0.00     p95=0.00       min=0.00     max=0.00
  dns_packets                n=8   median=21.50      mean=23.38      mad=5.00     p95=57.55      min=0.00     max=74.00
  unique_peers               n=8   median=2.00       mean=2.12       mad=0.00     p95=2.65       min=2.00     max=3.00
  unique_destination_ports   n=8   median=265.00     mean=240.25     mad=48.00    p95=334.60     min=91.00    max=350.00
  new_connections            n=8   median=240.50     mean=205.75     mad=53.00    p95=300.85     min=61.00    max=318.00
```

**Not found.** A device with no completed observation window answers `404` with
`BASELINE_NOT_FOUND`. That is a real answer about a real device, not a fault — the
frontend renders it as "No baseline for this device" and offers no retry, because
only further capture would produce one.

### `POST /api/v1/baselines/{device_key}/reset`

Deletes one device's observation windows and its profile, then allows learning to
restart. No body. Answers `200` even when there was nothing to delete, so the
caller reads what actually happened from the payload rather than from the status.

```json
{
  "success": true,
  "message": "Baseline reset",
  "data": {
    "device_key": "mac:A6:21:AA:90:CB:77",
    "windows_deleted": 8,
    "profile_deleted": true,
    "learning_restarted": true,
    "message": "The behavioural baseline for this device was deleted and learning will restart from the next observed packet. No packet, device, alert, incident, connection or report record was affected."
  }
}
```

Verified: after this call, `GET /api/v1/baselines/{device_key}` returns `404` — the
baseline is genuinely gone, not zeroed.

No endpoint exposes a database path, a stack trace or an internal detail. A reset
touches exactly two tables.

---

## 11. Frontend implementation

A dedicated **Behavioral Baselines** page in the existing React/TypeScript
application, reachable from the **Observe** group of the sidebar.

| File | Role |
|---|---|
| `src/types/baseline.ts` | Wire models, with the deliberate absences documented |
| `src/services/baselines.ts` | `fetchBaselines`, `fetchBaseline`, `resetBaseline` |
| `src/services/endpoints.ts` | `BaselinePaths` incl. the encoded `reset` builder |
| `src/hooks/useBaselines.ts` | Paged listing resource |
| `src/hooks/useBaseline.ts` | Detail resource; separates 404-as-answer from failure |
| `src/hooks/useResetBaseline.ts` | Reset action over `useAction` |
| `src/lib/baseline.ts` | Label/format helpers, testable without rendering |
| `src/components/baselines/LearningStateBadge.tsx` | Maturity badge |
| `src/components/baselines/BaselineStatisticsTable.tsx` | Statistics table |
| `src/components/baselines/BaselineWindowsTable.tsx` | Observation windows |
| `src/components/baselines/BaselineResetDialog.tsx` | Confirmation step |
| `src/components/baselines/BaselineDetailPanel.tsx` | One device's profile |
| `src/pages/Baselines.tsx` | The page |

The page shows: device identity with a MAC/IP kind chip, learning state, sample
count, first and latest observation times, the statistical profile, the
observation windows, and a per-row and per-device reset with a confirmation step.

**States handled:** no baselines learnt, no baselines in the selected learning
state, loading, provisional, established, API unavailable, baseline data
unavailable, and failed retrieval (with the loaded rows kept beside a
staleness banner rather than replaced).

**Truthfulness rules the UI follows:**

- Nothing is re-derived in React. Every figure comes from the backend's
  `statistics`; recomputing a mean from the windows would be a second
  implementation that disagrees the moment the sample set changes.
- A truncated cardinality renders with a `≥` floor marker rather than as an exact
  count.
- `new_connections: null` renders as `—`, never `0`.
- The page states, above the table, that a baseline is not an anomaly verdict, and
  the reset dialog names exactly what is and is not deleted.

---

## 12. Known limitations

1. **A receive-only device is not profiled.** Attribution is by sender, so a
   device only ever seen receiving produces no observation. No inbound/outbound
   metrics exist.
2. **`new_connections` is a conversation-key cardinality**, not an authoritative
   TCP session count. It is bounded by `baseline_max_connection_keys`, and reports
   `null` rather than a guess when it cannot be measured.
3. **Peer and port sets are capped** at 1024 each per window per device. Beyond
   that the figure is a floor, flagged as such.
4. **An IP-keyed profile may not follow the device** across an address change.
   MAC identity is the supported path; the fallback is labelled as weaker.
5. **The statistics describe a bounded recent slice** (`1440` windows by default),
   not all history. `sample_count` and `statistics_sample_count` are reported
   separately so the difference is visible rather than implied.
6. **Small-sample statistics are noisy.** A provisional profile from five windows
   is a real calculation over real data, but it is not a stable estimate, and the
   UI says so.
7. **Local measurements only.** The performance figures in §14 come from one
   development machine and a loopback/local capture; they are not production
   capacity claims.

---

## 13. Testing and verification

### Backend

| Module | Tests |
|---|---|
| `test_baseline_features.py` | 32 |
| `test_baseline_aggregation.py` | 35 |
| `test_baseline_statistics.py` | 29 |
| `test_baseline_states.py` | 30 |
| `test_baseline_store.py` | 29 |
| `test_baseline_engine.py` | 22 |
| `test_baselines_api.py` | (API envelope, pagination, validation, 404, reset) |
| Regression updates | `test_api_contract.py`, `test_api_validation.py`, `test_retention_scheduler.py`, `test_system_api.py` |

Coverage includes feature extraction (valid, missing and malformed fields),
per-device aggregation, separation of two devices, IP change on a stable MAC,
window boundaries, duplicate-window protection, statistical correctness on known
inputs, state transitions, empty and insufficient histories, persistence across a
restart, reset, retention, graceful-shutdown flush, database write failures,
bounded aggregation, response envelopes, pagination, validation and missing
baselines — plus the M0–M20 regression suites.

### Frontend

`src/pages/Baselines.test.tsx` — **26 tests**, all passing:

```
Test Files  18 passed (18)
     Tests  492 passed (492)
```

Covering: list rendering, the paged request window, the learning-state filter
being sent to the backend, detail fetch by encoded key, all three learning
states, tile captions, the anomaly-verdict disclaimer, absence of any risk/score
wording, IP-fallback labelling, detail rendering with statistics and windows,
`new_connections: null` → `—`, `404` → "No baseline for this device" with no
retry, return to listing, loading/empty/error/failure states, reset confirmation
gating the POST, reset success reporting real counts, reset refusal reported as an
error, listing re-read after reset, reset from the detail view, and pagination.

`npm run typecheck` exits 0. `npm run build` succeeds.

### Live end-to-end verification

Performed on this machine with authorized capture on the local Wi-Fi interface and
traffic generated **only** toward the host's own gateway and public DNS resolvers:

```
1. Backend started                      → /api/v1/health 200
2. Capture started on Wi-Fi             → 4,662 packets observed
3. Normalized packets seen              → pipeline running
4. Devices identified                   → 2 MAC identities
5. Features extracted                   → 9 features per device
6. Windows aggregated                   → 8 windows (60 s each)
7. Samples persisted                    → baseline_windows rows
8. Statistical profile calculated       → see §10 figures
9. State advanced                       → learning → provisional
10. Retrieved via REST                  → GET /api/v1/baselines 200
11. Displayed in the frontend           → page verified in a browser
12. Reset one device                    → windows_deleted=8, profile_deleted=true
13. Learning restarts                   → follow-up GET returns 404
```

The frontend was checked visually: the page rendered 2 learnt baselines, the
tiles counted them by state, the disclaimer was present, and the sidebar entry
navigated correctly.

---

## 14. Performance measurements

Measured on one development machine (Windows 11, laptop, AMD64) with a local
capture session. These are local observations, not production capacity claims.

| Measurement | Value |
|---|---|
| Packets observed in the live run | 4,662 |
| Windows persisted, 2 devices | 8 per device |
| Aggregation interval | 60 s |
| Flush interval | 5 s |
| Worst-case rows per flush | 500 (configured cap) |
| Devices held in memory cap | 4,096 |
| Statistics calculation bound | 1,440 windows per device |
| Frontend `Baselines` page chunk | 25.47 kB (6.32 kB gzip) |
| Frontend entry chunk after M21 | 250.86 kB (79.59 kB gzip) |

**Regression check.** Existing capture, statistics, detection, alert, incident,
report and retention behaviour is covered by the unchanged M0–M20 suites, all of
which pass. Baseline collection ran alongside a live capture with no observed
increase in packet-processing errors.

Bounded-state behaviour verified by test: device count, peer sets, port sets and
connection-key sets each evict at their configured cap, and `BoundedCounter`
behaviour under sustained new-key load is covered.

---

## 15. Deferred to M22 and later

- ML anomaly detection: Isolation Forest, One-Class SVM, autoencoders.
- Comparing a live window against a profile and producing a deviation score.
- Classifying an observation as anomalous.
- Baseline-deviation alerts and their integration with the M11/M12 pipeline.
- Any automatic action — blocking, quarantine, IPS.
- A locally hosted LLM, LLM-based log analysis, the AI Security Analyst, Wazuh.

M21's job was to produce the profiles those features will consume, and to describe
them honestly in the meantime.

---

## References

- `docs/24_M20_Base_Application_Release.md` — the v0.0.20 base release
- `docs/12_M8_Device_Discovery_Design.md` — device identity
- `docs/13_M9_Connection_Tracking_Design.md` — conversation tracking
- `docs/17_M13_REST_API_Design.md` — API envelope conventions
- `docs/19_M15_Frontend_Integration.md` — frontend architecture
- `docs/23_M19_Stabilization_Design.md` — the retention sweeper
