# NetWatch AI — Current Task

**Current Phase:** Base Application Implementation  
**Current Milestone:** M6 — Traffic Statistics Engine  
**Status:** ✅ Complete — verified (191 tests pass, pyright clean, baseline recorded)

> Audited after completion; five findings fixed. See `docs/prob.md`.

---

# Current Objective

Build the Traffic Statistics Engine for NetWatch AI.

M5 converts raw Scapy packets into normalized packets.

M6 will consume those normalized packets and continuously calculate useful traffic statistics.

The main flow becomes:

    Network
        ↓
    Scapy Capture
        ↓
    PacketProcessor
        ↓
    NormalizedPacket
        ↓
    Traffic Statistics Engine
        ↓
    Aggregated Statistics

These statistics will later support:

- Dashboard metrics
- Traffic analytics
- Device behavior analysis
- Detection rules
- Behavioral baselines
- ML anomaly detection
- Reports

M6 must remain focused on traffic aggregation.

---

# M6 Development Rule

Do NOT implement:

- Detection rules
- Alerts
- Behavioral baselines
- ML
- AI
- Correlation
- Risk scoring
- Device profiling
- Database persistence
- WebSockets
- Frontend integration

Those belong to later milestones.

---

# M6.1 — Statistics Manager

Create a dedicated service responsible for maintaining traffic statistics.

Suggested responsibility:

    TrafficStatisticsManager

Possible interface:

    record_packet(packet)
    get_statistics()
    reset()
    get_protocol_statistics()

The manager should consume `NormalizedPacket`.

It must not directly depend on Scapy.

---

# M6.2 — Packet Count

Track:

- Total packets
- Packets per protocol
- Packets per time window

Example:

    Total Packets: 125430

Protocol counts:

    TCP: 82100
    UDP: 31000
    ICMP: 1200
    Other: 11130

---

# M6.3 — Byte Count

Track total traffic volume.

Calculate:

- Total bytes
- Bytes per protocol
- Bytes per direction where possible

Example:

    Total Traffic: 842 MB

Do not estimate values.

Use the normalized packet length.

---

# M6.4 — Protocol Statistics

Track basic protocol distribution.

Initial protocols:

- TCP
- UDP
- ICMP
- DNS
- ARP
- IPv4
- IPv6
- Other

Store:

- Packet count
- Byte count
- Percentage of traffic

Percentages should be calculated from actual counters.

---

# M6.5 — Source/Destination Statistics

Track basic traffic distribution by:

- Source IP
- Destination IP
- Source port
- Destination port

The initial implementation should support querying the most active sources and destinations.

Example:

    Top Sources
    192.168.1.10 → 10,532 packets
    192.168.1.15 →  8,231 packets

Do not interpret activity as malicious yet.

---

# M6.6 — Port Statistics

Track commonly observed destination ports.

Examples:

    443
    53
    80
    22
    3389

Track:

- Packet count
- Byte count

Do not classify ports as malicious.

Port-based threat detection belongs to the Detection Engine.

---

# M6.7 — Traffic Direction

Where information allows, classify traffic into:

- Inbound
- Outbound
- Local/unknown

Do not make unreliable assumptions about network direction.

If the local interface/network context is insufficient, use:

    unknown

rather than inventing a direction.

---

# M6.8 — Time Windows

Implement time-based aggregation.

Initial window:

    1 second

Also support:

    10 seconds
    1 minute

The engine should be capable of answering:

    packets/sec
    bytes/sec

without needing to inspect every historical packet again.

---

# M6.9 — Throughput Calculation

Calculate basic traffic throughput.

Examples:

    Packets per second
    Bytes per second
    Bits per second

Use actual observed data.

Avoid claiming network link speed.

---

# M6.10 — Top Talkers

Calculate basic top talkers.

Support:

- Top source IPs
- Top destination IPs
- Top conversations where practical

Ranking should be based on configurable metrics such as:

    packets
    bytes

This is only traffic analytics.

It is not threat detection.

---

# M6.11 — Protocol Distribution

Provide a structured summary.

Example:

    TCP      65%
    UDP      25%
    ICMP      3%
    ARP       2%
    Other     5%

Percentages must be calculated dynamically from counters.

---

# M6.12 — Statistics Snapshot

Create a consistent snapshot representation.

Possible structure:

    {
        timestamp,
        total_packets,
        total_bytes,
        packets_per_second,
        bytes_per_second,
        protocol_statistics,
        top_sources,
        top_destinations,
        top_ports
    }

The exact implementation should use the project's existing schema/model conventions.

---

# M6.13 — Thread Safety

The statistics engine may receive packets from the capture worker while API requests read statistics.

Protect shared state from race conditions.

Potential shared state:

- packet counters
- byte counters
- protocol counters
- source counters
- destination counters
- port counters
- time-window data

Keep reads efficient.

---

# M6.14 — Memory Management

Do not keep every packet indefinitely in memory.

Use bounded/aggregated structures.

The statistics engine should store counters and required aggregation state rather than raw packets.

Avoid unbounded dictionaries for high-cardinality data.

Design a reasonable cleanup/expiration mechanism for time-window statistics.

---

# M6.15 — Integration With Packet Pipeline

Extend the current pipeline:

    Scapy
       ↓
    CaptureManager
       ↓
    PacketProcessor
       ↓
    NormalizedPacket
       ↓
    TrafficStatisticsManager

The processing path should continue even if statistics processing encounters an individual error.

A statistics failure must not terminate packet capture.

---

# M6.16 — Statistics API

Add read-only API endpoints.

Suggested endpoints:

    GET /api/v1/statistics/traffic
    GET /api/v1/statistics/protocols
    GET /api/v1/statistics/top-talkers
    GET /api/v1/statistics/ports

These endpoints should return current aggregated statistics.

Do not add WebSockets yet.

---

# M6.17 — Reset Statistics

Provide a controlled reset mechanism for development/testing.

Suggested endpoint:

    POST /api/v1/statistics/reset

Reset should:

- Clear counters
- Clear time-window data
- Preserve service availability
- Not stop packet capture

---

# M6.18 — Tests

Create unit tests for:

### Packet counts

- Single packet
- Multiple packets
- Protocol-specific counts

### Bytes

- Correct byte aggregation
- Multiple packets

### Protocols

- TCP
- UDP
- ICMP
- DNS
- ARP
- Other

### IP statistics

- Source aggregation
- Destination aggregation

### Ports

- Source port
- Destination port

### Time windows

- Packets/sec
- Bytes/sec
- Window rollover

### Top talkers

- Correct ordering
- Equal values
- Empty state

### Reset

- Statistics reset correctly

### Errors

- Invalid normalized packet
- Individual processing failure does not crash manager

---

# M6.19 — API Tests

Test:

    GET /api/v1/statistics/traffic
    GET /api/v1/statistics/protocols
    GET /api/v1/statistics/top-talkers
    GET /api/v1/statistics/ports
    POST /api/v1/statistics/reset

Verify:

- Correct response structure
- Empty state
- Non-empty state
- Reset behavior
- Invalid HTTP methods
- Unknown routes
- Correct HTTP status codes

---

# M6.20 — Integration Test

Run:

    CaptureManager
        ↓
    PacketProcessor
        ↓
    TrafficStatisticsManager

Generate harmless local traffic.

Verify that:

- Packets are captured.
- Packets are normalized.
- Statistics increase.
- Protocol counters change.
- Byte counters change.
- Top talkers update.

---

# M6.21 — Manual Verification

Perform a controlled local test.

Generate normal traffic such as:

- Web browsing
- DNS lookups
- Ping
- Local application connections

Observe:

    Total packets
    Total bytes
    Packets/sec
    Bytes/sec
    Protocol distribution
    Top sources
    Top destinations
    Top ports

Verify that the values correspond to actual traffic.

---

# M6.22 — Performance Baseline

Measure:

- Packets processed per second
- Statistics update overhead
- CPU usage
- Memory usage
- API response time

Do not optimize prematurely.

Do not claim production-scale performance.

---

# M6 Completion Criteria

M6 is complete when:

- [x] TrafficStatisticsManager exists.
- [x] It consumes NormalizedPacket objects.
- [x] Packet counts work.
- [x] Byte counts work.
- [x] Protocol statistics work.
- [x] Source statistics work.
- [x] Destination statistics work.
- [x] Port statistics work.
- [x] Traffic time windows work.
- [x] Packets/sec and bytes/sec work.
- [x] Top talkers work.
- [x] Statistics are thread-safe.
- [x] Memory growth is controlled.
- [x] Statistics errors do not terminate packet capture.
- [x] Statistics API works.
- [x] Reset functionality works.
- [x] Unit tests pass.
- [x] API tests pass.
- [x] Integration test passes.
- [x] Manual verification succeeds.
- [x] Performance baseline is recorded.

---

# M6 Delivered

**Status: complete and verified.**

## Code

- `backend/app/statistics/manager.py` — `TrafficStatisticsManager`
  (`record_packet`, `get_statistics`, `get_protocol_statistics`, `get_rates`,
  `get_top_talkers`, `get_top_ports`, `reset`, direction classification).
- `backend/app/statistics/bounded_counter.py` — `BoundedCounter`, evicting the
  least-active key so high-cardinality data stays bounded (M6.14).
- `backend/app/statistics/rate_window.py` — `RateWindow`, sliding-window rates
  stored as fixed 100 ms buckets so memory depends on window length, not packet
  rate (M6.8/M6.9/M6.14).
- `backend/app/schemas/statistics.py` — `TrafficSnapshot`, `ProtocolStat`,
  `DirectionStat`, `TopEntry`, `TopTalkers`, `TrafficDirection` (M6.12).
- `backend/app/services/packet_pipeline.py` — ties M5 normalization to M6
  statistics, isolating failures so stats can never stop capture (M6.15).
- `backend/app/api/v1/statistics.py` — read-only endpoints + reset (M6.16/M6.17).
- `backend/app/services/capture_manager.py` — wiring for the shared manager.

## API

    GET  /api/v1/statistics/traffic        (?window=1s|10s|60s)
    GET  /api/v1/statistics/protocols
    GET  /api/v1/statistics/top-talkers    (?limit=&by=)
    GET  /api/v1/statistics/ports          (?limit=&by=&direction=)
    POST /api/v1/statistics/reset

## Tests and tooling

- `backend/tests/test_statistics.py` — engine unit tests (M6.18).
- `backend/tests/test_statistics_windows.py` — windows/rankings/bounded memory.
- `backend/tests/test_statistics_api.py` — API tests (M6.19).
- `backend/tests/test_statistics_pipeline.py` — integration test (M6.20).
- `backend/scripts/verify_m6.py` — manual verification (M6.21).
- `backend/scripts/benchmark_m6.py` — performance baseline (M6.22).

## Verification

- Full suite: **191 passed** (baseline before M6 was 107; +5 audit regression tests).
- `pyright`: **0 errors, 0 warnings**.

## Performance baseline (this machine, `--packets 200000`)

    200,000 packets (direction provider wired; high-cardinality eviction exercised)
    wall 1.43 s  |  cpu 1.44 s  |  ~139,700 packets/sec  |  ~7.16 us/packet
    heap after 1.86 MiB (bounded; independent of packet count)
    API 1.9-3.1 ms avg per endpoint (in-process)

Not a production-capacity claim — see `backend/scripts/benchmark_m6.py`.

> The earlier ~12,000 packets/sec figure was measured on a manager with **no
> direction provider wired** and **low key cardinality**, so it hid the
> per-packet interface-discovery cost. It was replaced after the audit — see
> *Post-Completion Audit* below and `docs/prob.md`.

## Design note (memory, M6.14)

A rate window originally stored one tuple per packet and only pruned when its
own `rates()` was called, so the `10s`/`60s` windows grew without bound. Windows
now prune on every `record()` and aggregate into 100 ms buckets, capping each
window at `window_seconds / 0.1` buckets. Measured heap fell from 27.94 MiB to
0.25 MiB with no measurable throughput cost.

---

# Post-Completion Audit — Problems Found and Fixed

After M6 was marked complete, the engine was audited against its own claims.
Five findings were found — one high-severity throughput bug that both the tests
and the original benchmark had missed — and all five were fixed and verified.
Full detail is in `docs/prob.md`; this section records each problem and its fix.

## BUG-1 (HIGH) — Direction classification re-ran a full interface discovery for every packet

**Problem.** `TrafficStatisticsManager._record()` classifies each packet's
traffic direction by calling `_classify_direction()`, which resolved the local
address set through `_local_addresses()`. That helper invoked the injected
provider unconditionally, and the production provider
(`InterfaceManager.get_local_addresses`) runs `psutil.net_if_addrs()` +
`psutil.net_if_stats()`, rebuilds a Pydantic model per NIC, and emits an INFO
log line every call. Measured cost was ~14.5 ms per call, so the wired capture
path was capped at roughly **69 packets/sec** — about 170x slower than the
~12,000 packets/sec the M6.22 baseline claimed — while flooding the log with one
"Discovered N network interface(s)" line per packet.

It was missed because `benchmark_m6.py` measured a bare manager with no
direction provider wired, so `_local_addresses()` returned an empty set
immediately and the expensive branch never ran.

**Fix.** `_local_addresses()` now caches the resolved set for
`_LOCAL_ADDRESSES_TTL_SECONDS = 5.0`, guarded by its own lock, and
`set_local_addresses_provider()` invalidates that cache. A failed resolution is
cached as an empty set for the same TTL, so a provider outage cannot stall
ingestion. Regression tests: `test_direction_provider_is_not_called_per_packet`
and `test_setting_a_new_provider_invalidates_the_cache`.

## BUG-2 (LOW) — `BoundedCounter` eviction was O(n) per new key

**Problem.** When the counter was at capacity and a new key arrived,
`_evict_smallest()` ran `min()` over every tracked key — O(`max_keys`) per
insertion, ~1024 comparisons per packet under a new-key flood (port scans,
spoofed sources), compounding BUG-1 on the same hot path.

**Fix.** Eviction now uses a lazily-invalidated min-heap of
`(packet_count, key)`. Stale entries are discarded on pop and the heap is
rebuilt when it outgrows `4 * max_keys + 16`, keeping it bounded. Admitting a
new key is O(log n) amortized, and `top()`/`items()`/`reset()` semantics are
unchanged. Regression tests: `test_bounded_counter_keeps_the_most_active_keys`
and `test_bounded_counter_heap_does_not_grow_without_bound`.

## BUG-3 (LOW) — The M6.22 benchmark did not reflect production wiring

**Problem.** The recorded baseline measured a manager with (a) no direction
provider wired, which hid BUG-1, and (b) only 64 distinct source IPs, which
never triggered BUG-2 eviction. It therefore reported a happy-path-only number
that did not represent the running system.

**Fix.** `benchmark_m6.py` now wires a `set_local_addresses_provider(...)` so
direction classification runs through the same TTL cache as production, and
sweeps `_IP_HOSTS = 4096` distinct source hosts (above the default 1024 cap) so
eviction is exercised. Re-measured baseline: **139,671 packets/sec**, 7.16
us/packet (see the performance baseline above).

## NIT-4 (LOW) — Snapshot was not a single atomic read

**Problem.** `get_statistics()` read the aggregate totals under the main lock
but read the ranked counters after releasing it, so `top_*` could be *ahead* of
`total_packets` — a live snapshot could report more per-IP activity than its own
total packet count.

**Fix.** The ranked counters are now snapshotted first, then the totals are read
under the lock. Counters only grow, so the totals are always at least as large
as the ranked lists. Regression test:
`test_snapshot_totals_cover_ranked_entries_under_concurrency`.

## NIT-5 (LOW) — Local addresses were only set once the capture manager was built

**Problem.** `get_statistics_manager()` created the singleton without a
provider; only `get_capture_manager()` set one. Statistics served before any
capture endpoint was touched therefore reported every direction as `unknown`.

**Fix.** The singleton now attaches a default provider on creation (lazily
importing the interface manager to avoid an import cycle), so direction
classification works regardless of capture-manager construction.

## Audit summary

| ID | Severity | Problem | Fix |
|----|----------|---------|-----|
| BUG-1 | High | Interface discovery ran once per packet | 5 s TTL cache for local addresses |
| BUG-2 | Low | O(n) eviction in `BoundedCounter` | Lazy min-heap eviction, O(log n) |
| BUG-3 | Low | Benchmark missed the real path | Wire provider, sweep 4096 hosts |
| NIT-4 | Low | Snapshot `top_*` could exceed totals | Snapshot ranked lists before totals |
| NIT-5 | Low | Direction `unknown` before capture built | Default provider on the singleton |

Result: **191 tests pass** (+5 regression tests), `pyright` clean.

---

# Architecture Boundary

M6 should produce:

    NormalizedPacket
          ↓
    TrafficStatisticsManager
          ↓
    Traffic Statistics Snapshot

Future milestones will consume these statistics for:

    Detection
    Device Discovery
    Behavioral Analysis
    ML
    Dashboard
    Reports

M6 itself must not implement those systems.

---
