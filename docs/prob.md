# M6 Audit — Bugs Found and Fixed

Audit of the M6 Traffic Statistics Engine (`docs/Current_Task.md`).
Baseline reproduced before changes: **186 tests pass**, `pyright` **0 errors, 0 warnings**.
After the fixes below: **191 tests pass**, `pyright` **0 errors, 0 warnings**.

All five findings are **fixed and verified**.

---

## BUG-1 — HIGH — Direction classification re-ran a full interface discovery for every packet *(FIXED)*

**Where**
- `backend/app/statistics/manager.py` — `_record()` calls `_classify_direction()` for each packet;
  `_classify_direction()` calls `_local_addresses()`, which invoked the provider unconditionally.
- `backend/app/services/capture_manager.py` — `get_capture_manager()` wires
  `statistics.set_local_addresses_provider(interface_manager.get_local_addresses)`.
- `backend/app/services/interface_manager.py` — `get_local_addresses()` calls
  `list_interfaces()` -> `discover_interfaces()` -> `psutil.net_if_addrs()` + `psutil.net_if_stats()`,
  rebuilds a Pydantic `NetworkInterface` for every NIC, and emits an INFO log line each call.

**Evidence** (measured before the fix, against the real code path)
```
provider calls for 1000 packets: 1000      # i.e. exactly once per packet
real get_local_addresses():      14527.6 us/call
```

**Impact**
Every captured packet triggered two `psutil` scans plus model construction and an INFO log line.
At ~14.5 ms per packet the *wired* capture path was capped at roughly **69 packets/sec** — about
**170x slower** than the **~12,000 packets/sec** the M6.22 baseline claimed — and it flooded the log
with "Discovered N network interface(s)" once per packet.

**Why it was missed**
`backend/scripts/benchmark_m6.py` measured a *bare* `TrafficStatisticsManager()` with **no
`local_addresses_provider`**, so `_local_addresses()` returned an empty set immediately and the
expensive branch never ran.

**Fix**
Cache the resolved address set for `_LOCAL_ADDRESSES_TTL_SECONDS = 5.0` in `_local_addresses()`
(guarded by its own lock), invalidated by `set_local_addresses_provider()`. A failed resolution is
cached as an empty set for the same TTL, so a provider outage cannot stall ingestion.

**Regression tests** — `backend/tests/test_statistics.py`
- `test_direction_provider_is_not_called_per_packet` — provider runs exactly once for 500 packets.
- `test_setting_a_new_provider_invalidates_the_cache` — a replaced provider takes effect immediately.

---

## BUG-2 — LOW — `BoundedCounter` eviction was O(n) per new key at capacity *(FIXED)*

**Where** `backend/app/statistics/bounded_counter.py` — `_evict_smallest()`.

When full and a **new** key arrived, `add()` ran `min(self._counters, ...)` over every tracked key —
O(`max_keys`) per insertion, ~1024 comparisons per packet under a new-key flood (port scans, spoofed
sources), compounding BUG-1 on the same hot path.

**Fix** — eviction now uses a lazily-invalidated **min-heap** of `(packet_count, key)`. Stale entries
are discarded on pop; the heap is rebuilt when it outgrows `4 * max_keys + 16`, so it stays bounded.
Admitting a new key is now O(log n) amortized. The `top()`/`items()`/`reset()` semantics are unchanged.

**Regression tests** — `backend/tests/test_statistics_windows.py`
- `test_bounded_counter_keeps_the_most_active_keys` — the busiest keys survive eviction.
- `test_bounded_counter_heap_does_not_grow_without_bound` — the heap index stays under its rebuild
  threshold after 20,000 updates (memory bound preserved).

---

## BUG-3 — LOW — The M6.22 benchmark did not reflect production wiring *(FIXED)*

**Where** `backend/scripts/benchmark_m6.py`.

The old baseline measured a manager with (a) no direction provider wired (hid BUG-1) and (b) only
64 distinct source IPs (hid BUG-2 eviction), so it reported a happy-path-only number.

**Fix** — the benchmark now:
- wires a `set_local_addresses_provider(...)` so direction classification runs through the same TTL
  cache as production, and
- sweeps `_IP_HOSTS = 4096` distinct source hosts (above the default 1024 cap) so eviction fires.

**Re-measured baseline** (this machine, `--packets 200000`, default `max-keys 1024`)
```
packets recorded      : 200,000
wall time             : 1.432 s   |  cpu 1.438 s
throughput            : 139,671 packets/sec
per-packet overhead   : 7.160 us
heap after            : 1.86 MiB (bounded; independent of packet count)
API: traffic 3.02 ms · protocols 2.53 ms · top-talkers 3.10 ms · ports 1.93 ms (avg)
```

---

## NIT-4 — LOW — Snapshot was not a single atomic read *(FIXED)*

`get_statistics()` read totals under the main lock but read the ranked counters after releasing it,
so `top_*` could be *ahead* of `total_packets`. It now snapshots the ranked counters **first**, then
reads the totals under the lock. Counters only grow, so the totals are always at least as large as
the ranked lists — a live snapshot can never claim more per-IP activity than its total packet count.

**Regression test** — `backend/tests/test_statistics_windows.py`
- `test_snapshot_totals_cover_ranked_entries_under_concurrency` — under a concurrent writer, for 200
  snapshots, `sum(top_sources.packets) <= total_packets` always holds.

---

## NIT-5 — LOW — Local addresses were only set once the capture manager was built *(FIXED)*

`get_statistics_manager()` created the singleton without a provider; only `get_capture_manager()`
set one, so statistics served before any capture endpoint was touched reported every direction as
`unknown`. The singleton now attaches a default provider on creation (lazily importing the interface
manager to avoid an import cycle), so direction works regardless of capture-manager construction.

---

## Summary

| ID | Severity | Status | Area |
|----|----------|--------|------|
| BUG-1 | High | **Fixed** (+2 tests) | Per-packet interface discovery in direction classification |
| BUG-2 | Low | **Fixed** (+2 tests) | O(n) eviction in `BoundedCounter` -> min-heap |
| BUG-3 | Low | **Fixed** | Benchmark now wires the provider and exercises eviction |
| NIT-4 | Low | **Fixed** (+1 test) | Snapshot now monotonic (ranked lists <= totals) |
| NIT-5 | Low | **Fixed** | Direction provider attached to the singleton |

## Final verification

- Tests: **191 passed** (was 186; +5 regression tests).
- `pyright backend`: **0 errors, 0 warnings**.
- Benchmark (`--packets 200000`, production-like wiring): **139,671 packets/sec**, 7.16 us/packet.
