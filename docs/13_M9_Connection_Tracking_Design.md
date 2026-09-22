# NetWatch AI — M9 Connection Tracking Design

**Milestone:** M9 — Connection Tracking & Network Conversations
**Status:** Implemented
**Depends on:** M5 (NormalizedPacket), M7 (packet persistence), M8 (device discovery), M2 (`connections` table)

---

# 1. Purpose

M9 turns the stream of normalized packets into **network conversations**.

A *connection* is one conversation between two endpoints, identified by the
transport protocol and the pair of endpoints involved:

```text
192.168.1.10:52134
        ↓
     TCP / 443
        ↓
  142.250.1.1:443
```

Both directions of that conversation belong to the **same** `Connection` record,
and each direction keeps its own packet and byte counters.

M9 produces runtime and historical connection data consumed later by detection
(M10), alerts (M11), correlation (M12), analytics (M16) and reports (M17).

## 1.1 Scope boundary

M9 implements connection tracking only. It does **not** implement threat
detection, detection rules, alerts, behavioural baselines, ML/AI, correlation,
risk scoring, automatic blocking, WebSockets, frontend integration or SIEM
integrations. No detection logic exists anywhere in the M9 query layer.

---

# 2. M9.1 — Review of the existing components

## 2.1 `NormalizedPacket` (M5) — `app/schemas/packet.py`

The M9 input. Only these fields are read:

| Field | Use in M9 |
| --- | --- |
| `timestamp` | `first_seen` / `last_seen` |
| `length` | byte counters |
| `ip_version` | recorded on the connection (4 / 6 / unknown) |
| `source_ip`, `destination_ip` | endpoint identity; **both required** |
| `source_port`, `destination_port` | endpoint identity for TCP/UDP |
| `protocol` | transport label (`TCP`, `UDP`, `ICMP`, …) |
| `packet_type` | fallback transport classification (`DNS` → UDP) |
| `tcp_flags` | TCP state evidence (compact Scapy form, e.g. `S`, `SA`, `PA`, `FA`, `R`) |
| `source_mac`, `destination_mac` | **ignored** — M9 identifies endpoints by IP |
| `interface`, `packet_id` | **ignored** — no column and no connection-level meaning |

M9 never imports Scapy. It depends on `NormalizedPacket` exactly as M6/M7/M8 do.

**Missing fields.** `NormalizedPacket` validates that ports are 0–65535, but
`source_ip` / `destination_ip` are unrestricted strings. A packet whose address
is missing or unparseable cannot form an endpoint and is **skipped and counted**
— no value is ever invented.

## 2.2 Device discovery (M8) — `app/devices/`

M9 reuses the M8 registry as the **only** device authority:

* `DeviceRegistry.get_by_ip(ip) -> ObservedDevice | None`
* `ObservedDevice.device_id` (e.g. `mac:AA:BB:...` or `ip:192.168.1.10`)

M9 stores that `device_id` on the connection as
`source_device_id` / `destination_device_id`. If the address is unknown to M8,
the association stays `None` — M9 never creates a device and never keeps a
second device registry.

Note the identity-upgrade behaviour of M8.16: an `ip:` record can be adopted into
a `mac:` record. M9 therefore **refreshes** the association on every
observation, so the connection always names the device identity M8 currently
reports rather than a stale one.

## 2.3 `connections` table (M2) — `app/models/connection.py`

`NetworkConnection` already exists and is the historical store. Its columns:

```text
id, source_device_id, destination_device_id,
source_ip, destination_ip, source_port, destination_port,
protocol, packets_sent, packets_received, bytes_sent, bytes_received,
start_time, end_time, status
```

with `status ∈ {active, completed, failed, timeout}`.

M9 **does not redesign** this table or add columns. It maps the runtime
`Connection` onto the existing columns (§10) through the existing
`ConnectionRepository`. `source_device_id` / `destination_device_id` are
`INTEGER` foreign keys to `devices.id`, while M8 device identities are strings
and M8 devices are **not** persisted (M7 already stores `packets.device_id` as
`NULL` for the same reason). The FK therefore stays `NULL` unless a caller
injects a resolver that maps a runtime device id to a persisted row id.

## 2.4 Packet persistence (M7) — `app/persistence/`

M9 **does not** re-store packets. A connection is an *aggregation* of many
packets, so writing one row per packet would duplicate M7 exactly. M9 reuses the
M7 infrastructure patterns instead:

* `SessionFactory` / `app_session_factory` for a fresh session per write;
* `ConnectionRepository` (M2) for the statements;
* a bounded, low-rate write path (only aggregated connection rows).

## 2.5 What M9 must not duplicate

| Already provided | Provided by | M9 relation |
| --- | --- | --- |
| packet normalization | M5 | consumed, never reimplemented |
| traffic totals, top talkers | M6 | not reused — M6 is flow-agnostic by key only |
| packet rows | M7 | not duplicated; connections are aggregates |
| device registry, MAC/IP mapping, local identity | M8 | reused via `DeviceRegistry.get_by_ip` |
| `connections` table + repository | M2 | reused, not redesigned |

M6's `_conversation_key` (`src:sport->dst:dport`) is intentionally *not* reused:
it is a directional ranking key for statistics, it merges no directions, and M9
needs a canonical, bidirectional, state-carrying identity instead.

---

# 3. Layer map

```text
app/connections/
    identity.py     endpoint/5-tuple/canonical-key/direction rules (no state, no I/O)
    state.py        ConnectionState enum + TCP flag parsing
    tcp.py          TCP state evidence and transitions (not a full state machine)
    connection.py   the runtime Connection record (mutable, lock-free)
    registry.py     the bounded, lock-protected store (active + historical)
    mapping.py      Connection -> ``connections`` column values (no I/O)
    persistence.py  aggregated writes to the ``connections`` table
    manager.py      ConnectionTracker — the M9 entry point
    __init__.py     package exports

app/schemas/connection.py   ConnectionState + ConnectionView + ConnectionListData
app/api/v1/connections.py   internal read-only verification endpoints
```

Dependency direction is strictly downward: `manager → registry → connection →
{tcp, state, identity}`. Nothing in the package imports Scapy, FastAPI or the
detection layer.

---

# 4. Connection identity (M9.3, M9.5, M9.13)

## 4.1 Endpoint

```python
@dataclass(frozen=True)
class Endpoint:
    ip: str                  # canonical IPv4/IPv6 text
    port: int | None = None  # None for ICMP, or when the packet carried no port
```

Addresses are canonicalized with `ipaddress.ip_address` (via the M8 helper
`normalize_ip_address`), so one host never appears under two spellings
(`2001:0db8::1` and `2001:db8::1` are the same endpoint). IPv4 and IPv6 are
handled identically; nothing assumes IPv4.

## 4.2 The 5-tuple (directional flow)

```python
@dataclass(frozen=True)
class Flow:
    protocol: str        # "TCP" | "UDP" | "ICMP"
    source: Endpoint
    destination: Endpoint
```

`flow_of(packet)` builds it, returning `None` when the packet is untrackable.

### Protocol selection

1. `packet.protocol` (upper-cased) is authoritative when recognized:
   `TCP` → **TCP**, `UDP`/`QUIC` → **UDP**, `ICMP`/`ICMPV6` → **ICMP**.
2. Otherwise `packet.packet_type` decides: `TCP` → TCP, `UDP`/`DNS` → UDP,
   `ICMP` → ICMP.
3. Anything else (ARP, IPV4/IPV6 with no transport, OTHER) is **not tracked**
   and is counted as unsupported.

DNS is UDP traffic and is tracked as UDP; DNS-over-TCP is tracked as TCP.

## 4.3 Canonical bidirectional key (M9.4, M9.5)

The two endpoints are ordered deterministically by `(ip, port)`, with a missing
port sorting below port `0` (it is treated as `-1` so a portless endpoint still
orders deterministically):

```python
class ConnectionKey(NamedTuple):
    protocol: str
    first: Endpoint     # min(endpoints)
    second: Endpoint    # max(endpoints)
```

so

```text
A:52134 → B:443        endpoints {(A,52134), (B,443)}  →  key  TCP | (A,52134) | (B,443)
B:443   → A:52134      endpoints {(B,443), (A,52134)}  →  key  TCP | (A,52134) | (B,443)
```

Both directions resolve to **one** connection.

**Why this cannot merge unrelated flows.** Ordering the *endpoint multiset*
only collides when both endpoints are identical, which means the two flows are
the same pair of sockets — by definition the same conversation. Any different
port pair, address pair or protocol yields a different key:

```text
A:1000 → B:2000   →  {A:1000, B:2000}
B:1000 → A:2000   →  {A:2000, B:1000}   ← different key
A:1000 → B:2000 (same key as the first — the same conversation)
B:1000 → B:2000   →  {B:1000, B:2000}   ← different key
```

**Connection id.** `connection_id` is the deterministic text rendering of the
key (`TCP|10.0.0.1:52134|142.250.1.1:443`). It is human readable, stable across
processes, and unique per conversation, so it is usable as an API path parameter
and as a correlation anchor in later milestones. A portless endpoint renders as
its bare address with no `:port` suffix, so an ICMP conversation has an id like
`ICMP|10.0.0.1|10.0.0.2`.

## 4.4 Direction (M9.5)

`Direction ∈ {SOURCE, DESTINATION, UNKNOWN}` describes a packet relative to the
connection's recorded orientation:

* the orientation is fixed by the **first observed packet** (its source becomes
  the connection's `source_ip`/`source_port`) — this is the "original
  source/destination information required for reporting";
* a packet matching the orientation is `SOURCE` direction;
* a packet matching the reversed orientation is `DESTINATION` direction;
* when both endpoints are identical (e.g. loopback to the same port) every
  packet is `SOURCE` direction, because there is no observable difference.

Direction is preserved even though the conversation is grouped: the connection
stores the orientation, and the per-direction counters keep both sides separate.
---

# 5. Runtime Connection model (M9.6)

`app/connections/connection.py` — a plain, mutable dataclass. It carries no lock
of its own: the registry is the single concurrency boundary, exactly as
`ObservedDevice` defers to `DeviceRegistry`.

| Field | Type | Meaning |
| --- | --- | --- |
| `connection_id` | `str` | Deterministic id, the key rendered as text |
| `key` | `ConnectionKey` | Canonical bidirectional identity |
| `protocol` | `str` | `TCP` / `UDP` / `ICMP` |
| `source_ip`, `source_port` | `str`, `int \| None` | Orientation source (first packet) |
| `destination_ip`, `destination_port` | `str`, `int \| None` | Orientation destination |
| `ip_version` | `int \| None` | `4`, `6`, or unknown |
| `first_seen`, `last_seen` | `float` | Epoch seconds |
| `packet_count` | `int` | Total packets (both directions) |
| `byte_count` | `int` | Total bytes (both directions) |
| `source_packet_count`, `source_byte_count` | `int` | Counters for the orientation source direction |
| `destination_packet_count`, `destination_byte_count` | `int` | Counters for the reverse direction |
| `state` | `ConnectionState` | TCP state, or UDP/ICMP activity state |
| `source_device_id`, `destination_device_id` | `str \| None` | M8 device identities |
| `tcp` | `TcpObservation \| None` | TCP flag evidence (TCP only) |
| `expired_at` | `float \| None` | When the connection was retired from active state |
| `persisted_row_id` | `int \| None` | `connections.id` of the persisted aggregate |

`packet_count == source_packet_count + destination_packet_count` and
`byte_count == source_byte_count + destination_byte_count` always hold.

**Only observed values are populated.** A field the traffic did not justify stays
`None` or `0`:

* an ICMP conversation has `source_port = destination_port = None`;
* `source_device_id` stays `None` when M8 does not know the address;
* `ip_version` stays `None` only if a caller constructs a record by hand — the
  normal ingestion path always sets it from the packet;
* `expired_at` and `persisted_row_id` stay `None` until those events happen.

Derived helpers: `total_packets()`, `total_bytes()` (aliases of the totals),
`idle_seconds(now)`, `is_expired(now, timeout)`, `is_terminal()`,
`persisted_status()` and `to_view(now)`.

---

# 6. TCP tracking and state (M9.9, M9.10)

## 6.1 What is tracked

Source/destination IP, source/destination port, the observed TCP flags, packet
count, byte count, `first_seen`, `last_seen` — all of which live on the
`Connection`, plus the flag evidence held in `TcpObservation`.

## 6.2 Flag parsing

`NormalizedPacket.tcp_flags` carries Scapy's compact flag string (`S`, `A`,
`SA`, `PA`, `FA`, `R`, `RA`, …). `TcpFlags.parse` reads the individual bits
(`S`, `A`, `F`, `R`, `P`, `U`) case-insensitively and never raises: an
unparseable or missing string yields "no flags observed", not a guess.

## 6.3 States

```text
observed     a TCP flow was seen; no handshake evidence yet
established  SYN observed in the source direction AND SYN+ACK in the reverse
closing      a FIN was observed, or a RST arrived in one direction
closed       a RST was observed, or FINs were observed in BOTH directions
unknown      reserved for records created without observations
```

## 6.4 Transitions

| Evidence | Resulting state |
| --- | --- |
| first TCP packet | `observed` |
| `SYN` from the source | `observed` (never `established` on its own) |
| `SYN+ACK` from the reverse direction | `established` (no other evidence alone can establish) |
| `ACK` in both directions after a `SYN` | `established` (mid-stream capture that missed the handshake) |
| `SYN` when already `established` | stays `established` |
| `FIN` (either direction) | `closing` |
| `FIN` seen in both directions | `closed` |
| `RST` | `closed` |
| `closed` with more traffic (no `SYN`) | stays `closed` |

`closed` is terminal **for that conversation**. A later pure `SYN` on the same
5-tuple is TCP tuple reuse (a new conversation that happens to share the key), so
the record is restarted: counters and timestamps reset and the state returns to
`observed`. `connection_id` is unchanged, because the identity of the tuple is
unchanged; the aggregate row already written keeps the earlier conversation.

## 6.5 What is deliberately *not* implemented

No receive windows, sequence numbers, retransmission detection, timers, or
half-open tracking. M9 observes what the packets show — it is not a TCP stack.
A single `SYN` never produces `established`, which is exactly the evidence rule
M9.10 requires.

---

# 7. UDP and ICMP tracking (M9.11, M9.12)

## 7.1 UDP

UDP has no handshake, so M9 records activity, not connection setup:

```text
active     traffic observed within the UDP idle timeout
inactive   no traffic for longer than the UDP idle timeout (set on expiration)
unknown    reserved
```

Tracked per UDP conversation: the 5-tuple, packet count, byte count,
`first_seen`/`last_seen`, both directions' counters, and the state. TCP-style
states are never applied to UDP.

## 7.2 ICMP

At minimum M9 tracks source IP, destination IP, protocol, packet count, byte
count, `first_seen` and `last_seen`; it does so through the same `Connection`
model with `source_port = destination_port = None`, so echo traffic between two
hosts appears as one bidirectional conversation.

**Documented limitation.** `NormalizedPacket` (M5) exposes no ICMP type, code,
identifier or sequence number, so M9 can observe a request/reply *exchange* in
both directions but cannot label which packet was the echo request and which the
reply. Adding those fields belongs to a later milestone that changes M5. ICMP
flood detection is explicitly out of scope.

---

# 8. IPv4 / IPv6 (M9.13)

* Both versions go through the same identity code — nothing branches on version.
* Addresses are canonicalized (`normalize_ip_address`), so IPv6 spellings
  collapse to one form and an endpoint can never be duplicated by formatting.
* `ip_version` is recorded from the packet and may be `None` for records built
  without one; it never blocks tracking.
* Mixed-version traffic is naturally separated, because a v4 address and a v6
  address are different endpoints and therefore different keys.

---

# 9. Device association (M9.14)

For every observed packet M9 resolves both endpoints against the M8 registry:

```text
source ip      → DeviceRegistry.get_by_ip  → ObservedDevice.device_id → source_device_id
destination ip → DeviceRegistry.get_by_ip  → ObservedDevice.device_id → destination_device_id
```

* The M8 registry is injected (`DeviceRegistry` or the whole
  `DeviceDiscoveryManager`); M9 never builds its own device store.
* Association is by **address**, which is the only identifier a packet carries.
* An unresolved address leaves the field as `None` — never invented.
* The association is refreshed on every observation so an M8 identity upgrade
  (`ip:… → mac:…`) is reflected.
* If no registry is supplied, both fields stay `None`; connection tracking still
  works, because devices are an enrichment, not a dependency.
* Endpoints that M8 classifies as untrackable (broadcast/multicast MACs) simply
  have no device; M9 still tracks the conversation itself.

Lock ordering note: M9 resolves devices *while holding the connection registry
lock*, so the order is always connections → devices. M8 never touches M9, so
the reverse order cannot occur and the two locks cannot deadlock.

---

# 10. Expiration and memory management (M9.15, M9.16, M9.18)

## 10.1 Timeouts

Idle timeouts are per protocol and come from configuration, never hard-coded in
the tracker:

| Protocol | Setting | Default |
| --- | --- | --- |
| TCP | `CONNECTION_TCP_TIMEOUT_SECONDS` | 300 s |
| UDP | `CONNECTION_UDP_TIMEOUT_SECONDS` | 60 s |
| ICMP | `CONNECTION_ICMP_TIMEOUT_SECONDS` | 30 s |

A connection is expired when `now - last_seen > timeout`.

## 10.2 Active vs historical (M9.16)

The registry keeps **two** collections:

```text
_active      conversations currently being observed      (cap: CONNECTION_MAX_TRACKED, default 8192)
_historical  expired/completed conversations, kept for    (cap: CONNECTION_MAX_HISTORICAL, default 1024)
             reporting and persistence
```

Expiration **moves** a record instead of deleting it, so useful information is
not destroyed just because traffic stopped. Historical records are ordered by
`last_seen` and the oldest are dropped only when the historical cap is exceeded,
which keeps the runtime footprint bounded.

## 10.3 Cleanup behaviour (documented, as M9.18 requires)

```text
1. Idle sweep  expire_connections(now)
               every active connection with idle > its protocol timeout is
               moved to _historical, given an expiration state, and queued for
               persistence.

2. Capacity    when _active exceeds CONNECTION_MAX_TRACKED, the stalest records
               (smallest last_seen) are moved to _historical — never the record
               that was just observed. Eviction is done in amortized batches of
               max(1, cap // 16), so a flood of new flows costs O(n log k)
               instead of a full sort per insertion.

3. Historics   when _historical exceeds CONNECTION_MAX_HISTORICAL, the oldest
               records by last_seen are dropped outright, and their connection
               ids leave the registry completely.
```

Lookup stays O(1): `_active` and `_historical` are dictionaries keyed by the
canonical `ConnectionKey`. Nothing keeps a connection forever in memory.

An optional background cleanup thread (`CLEANUP_INTERVAL_SECONDS`, default 5 s,
started lazily on the first packet) runs the idle sweep so expiration does not
depend on a caller. Tests construct the tracker with the thread disabled and call
`expire_connections()` directly.

## 10.4 State written on expiration

| Protocol | State after expiry | Persisted `status` |
| --- | --- | --- |
| TCP still `observed`/`established`/`closing` | unchanged (its TCP state is real evidence) | `timeout` |
| TCP `closed` | `closed` | `completed` |
| UDP/ICMP `active` | `inactive` | `completed` |
| TCP `closed` that is never persisted | `closed` | `completed` |

`status` uses only values the M2 column already defines
(`active`, `completed`, `timeout`).

---

# 11. Persistence of connections (M9.17)

## 11.1 What is persisted

One row per aggregated conversation in the existing `connections` table, written
through the existing `ConnectionRepository`:

| Runtime field | Column |
| --- | --- |
| `source_ip` / `source_port` | `source_ip` / `source_port` |
| `destination_ip` / `destination_port` | `destination_ip` / `destination_port` |
| `protocol` (truncated to 20) | `protocol` |
| `source_packet_count` | `packets_sent` |
| `destination_packet_count` | `packets_received` |
| `source_byte_count` | `bytes_sent` |
| `destination_byte_count` | `bytes_received` |
| `first_seen` | `start_time` |
| `last_seen` (when terminal) | `end_time` |
| `persisted_status()` | `status` |
| device ids via an optional resolver | `source_device_id` / `destination_device_id` |

**Not persisted:** individual packets (that is M7), per-packet flags, the
canonical key text (it is reconstructible from the columns), and the runtime
state name (folded into `status`). No column is added to the M2 schema.

`packets_sent + packets_received` equals the runtime `packet_count`, so the row
is a faithful aggregate.

## 11.2 When it is written

Persistence never runs on the capture path. It is triggered by events:

1. **Expiration** — each idle sweep persists the connections it just retired,
   with their final counters and `end_time`.
2. **Shutdown** — `flush_persistence()` persists every tracked connection
   (updating rows already written) so an open session is still recorded.

Each connection keeps the `connections.id` it was written to, so the second
write is an `UPDATE`, not a duplicate `INSERT`. A tuple reused after `closed`
gets a fresh row, because the runtime record's counters were restarted.

Writes are chunked and capped per pass (`CONNECTION_PERSISTENCE_MAX_PER_PASS`,
default 500): a connection flood cannot stall the cleanup thread, and anything
above the cap is counted as deferred and picked up by the next sweep. Failures
are counted and logged, never raised — the same containment rule as M7/M8.

---

# 12. Thread safety (M9.19)

* One `threading.RLock` guards `_active`, `_historical`, every counter, every
  timestamp, every state field and both device associations. It is an `RLock`
  so a compound read (`with registry.locked(): …`) can call the registry's own
  methods without self-deadlocking.
* All mutation happens inside `ConnectionRegistry.observe` and
  `ConnectionRegistry.expire`; readers (`get`, `all_active`, `all_historical`)
  take the same lock and return snapshots, so a reader can never observe a
  half-updated record.
* `Connection` objects carry no lock, which keeps the per-packet path free of
  nested locking.
* Persistence runs **outside** the registry lock: the sweep collects the expired
  records under the lock, releases it, and only then writes to the database.

---

# 13. Pipeline integration (M9.20)

```text
Scapy
  ↓
CaptureManager
  ↓
PacketProcessor
  ↓
NormalizedPacket
  ├── TrafficStatisticsManager
  ├── PacketPersistence
  ├── DeviceDiscoveryManager
  └── ConnectionTracker
```

* `ConnectionTracker` is injected into `PacketPipeline` exactly like the other
  consumers, and runs **after** device discovery so the devices it associates are
  already registered.
* Its failure is isolated in its own `try/except`: a connection-tracking error is
  counted (`get_connection_error_count()`) and logged, while capture, processing,
  statistics, persistence and device discovery continue.
* A malformed packet is dropped by the tracker and counted, never propagated.
* `CaptureManager` exposes `get_connection_error_count()` and the pipeline
  exposes `connections`, mirroring `devices`.
* On capture stop the last idle sweep runs, so a session's ended conversations
  are retired and persisted.

---

# 14. Queries and API (M9.21, M9.22)

## 14.1 Query surface

`ConnectionTracker` implements the M9.21 queries over the live registry, with
limits and normalization, and **no detection logic**:

```text
list_connections(protocol=, source_ip=, destination_ip=, source_port=,
                 destination_port=, device_id=, state=, active_only=, limit=)
get_active_connections(limit=)
get_connections_for_device(device_id, limit=)
```

Ordering is by `last_seen` descending with `connection_id` as the tie-break, so
results are deterministic. Address filters are canonicalized before matching
(so `FE80::1` matches `fe80::1`); an unknown state raises `ValueError`; a
non-positive limit raises `ValueError`.

## 14.2 API

M13 owns the complete REST API, so M9 exposes only what verification needs,
following the project's existing conventions (same response envelope, same error
codes, read-only apart from an explicit development helper):

```text
GET  /api/v1/connections                  filtered, bounded list
GET  /api/v1/connections/active           active conversations only
GET  /api/v1/connections/{connection_id}  one conversation, 404 when unknown
POST /api/v1/connections/expire           run the idle sweep (development helper)
```

No frontend-specific endpoint, no mutation of a connection, no alerting.

---

# 15. Error handling

| Condition | Behaviour |
| --- | --- |
| Missing source or destination IP | skipped, `skipped_count` incremented |
| Unparseable IP address | skipped, `skipped_count` incremented |
| Unsupported protocol (ARP, bare IPv4/IPv6, OTHER) | skipped, `skipped_count` incremented |
| Missing ports on TCP/UDP | tracked with `port=None` (never invented) |
| Missing/odd `tcp_flags` | treated as "no flags", state logic skips it |
| Device not in the M8 registry | association stays `None` |
| Unmappable record at persistence time | counted, logged, never raised |
| Any unexpected exception in `process_packet` | counted, logged, never raised |
| Persistence/DB failure | counted, logged, capture unaffected |

`reset()` clears both collections, all diagnostics and pending persistence state.

---

# 16. Configuration

| Setting | Default | Purpose |
| --- | --- | --- |
| `CONNECTION_TRACKING_ENABLED` | `true` | Master switch for the consumer |
| `CONNECTION_TCP_TIMEOUT_SECONDS` | `300` | TCP idle timeout |
| `CONNECTION_UDP_TIMEOUT_SECONDS` | `60` | UDP idle timeout |
| `CONNECTION_ICMP_TIMEOUT_SECONDS` | `30` | ICMP idle timeout |
| `CONNECTION_MAX_TRACKED` | `8192` | Cap on active connections |
| `CONNECTION_MAX_HISTORICAL` | `1024` | Cap on retained expired connections |
| `CONNECTION_CLEANUP_INTERVAL_SECONDS` | `5` | Background sweep period |
| `CONNECTION_PERSISTENCE_ENABLED` | `true` | Write aggregates to `connections` |
| `CONNECTION_PERSISTENCE_MAX_PER_PASS` | `500` | Upper bound on rows per write pass |

---

# 17. Test plan (M9.23, M9.24, M9.25)

| Area | File |
| --- | --- |
| identity, canonical key, IPv4/IPv6, direction | `tests/test_connection_identity.py` |
| TCP flags and state transitions, UDP/ICMP states, counters, timestamps, device association, queries, expiration, capacity, errors, concurrency, registry | `tests/test_connections.py` |
| mapping + `connections` table: create, update, retrieve, query by device/protocol/time, history | `tests/test_connection_persistence.py` |
| pipeline: capture → processor → devices → connections | `tests/test_connections_pipeline.py` |
| API envelope, filters, validation, routing | `tests/test_connections_api.py` |
| manual verification | `scripts/verify_m9.py` |
| performance baseline | `scripts/benchmark_m9.py` |

---

# 18. Deliberate non-goals

* No detection, alerting, scoring, correlation, baselines, ML or AI.
* No full TCP state machine, no retransmission or window tracking.
* No per-packet duplication of M7 storage.
* No new database columns or tables; the existing `connections` model is reused.
* No WebSocket or frontend-facing surface; M13 consolidates the REST API.
* No claim of production-scale capacity — §19 of `docs/Current_Task.md` and the
  benchmark script record a *local* baseline only.
