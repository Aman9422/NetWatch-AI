# M8.1 — Device Discovery Design (model, identity, mapping)

**Status:** Design accepted. Implementation follows this document.
**Scope:** M8 only — discovery and tracking of devices. No detection, scoring,
alerts, baselines, ML, WebSockets, or frontend work.

---

## 1. Purpose

M6 turns captures into `NormalizedPacket` objects and traffic statistics.
M8 consumes those same `NormalizedPacket` objects and answers a different
question:

> *Which hosts are on the network, and how much did each one talk?*

The pipeline becomes:

    Scapy
      ↓
    CaptureManager
      ↓
    PacketProcessor          (M5)  → NormalizedPacket
      ↓
    TrafficStatisticsManager (M6)  → traffic aggregates
      ↓
    DeviceDiscoveryManager   (M8)  → device registry

The two consumers of `NormalizedPacket` are independent: a device-discovery
failure must never stop statistics, and neither may stop capture.

---

## 2. Runtime registry vs. database persistence

There are two different "devices" in the codebase and they must not be
confused.

| | Runtime device (this milestone) | `devices` table (M2) |
|---|---|---|
| Lives in | process memory | SQLite |
| Owner | `DeviceDiscoveryManager` | `DeviceRepository` |
| Keyed by | `device_id` string | integer `id` |
| Lifetime | one capture session (+ retention) | permanent |
| Purpose | observe & attribute live traffic | inventory, history, alerts |

**Decision:** M8 builds the *runtime* registry only. It does **not** write to
the database. The DB `devices` table stays as-is; a later milestone
(persistence) will flush the runtime registry into it.

To keep that future move cheap, the runtime model already carries the same
semantic fields the table has (`mac_address`, `ip_addresses`, `first_seen`,
`last_seen`, `hostname`, `vendor`, `status`, counters), with two deliberate
differences explained in §6:

* the runtime record has **no** `risk_score` / `trust_score` (M8 must not score
  risk), and
* the runtime record stores **a set of IP addresses**, not a single one.

The mapping from runtime record → DB row is therefore a projection, not a
re-think.

---

## 3. Device identity (M8.2)

A device is identified by the strongest identifier the packet actually gives us.

**Identity derivation, in priority order:**

1. **MAC present and valid** → `device_id = "mac:AA:BB:CC:DD:EE:FF"`
2. **MAC absent, IP present and valid** → `device_id = "ip:192.168.1.10"`
3. **Neither** → the endpoint is not attributable and is skipped.

A MAC is the primary identity because it is tied to the hardware and survives
IP changes. An IP is only a *fallback* identity, used when no MAC was observed
(for example, some routed traffic seen above layer 2).

The `device_id` is derived, deterministic, and human-readable, so it is stable
across restarts for the same session inputs and needs no counter.

**An IP never permanently identifies a device.** A device may change IP, have
several IPs, appear over IPv4 and IPv6, or be seen with no IP at all. The model
therefore stores MAC and IP information separately (see §4/§6).

---

## 4. Endpoint extraction and attribution (M8.5)

For each `NormalizedPacket` two *endpoints* are considered:

    source endpoint       = (source_mac, source_ip)
    destination endpoint  = (destination_mac, destination_ip)

Each endpoint that has at least one usable identifier is resolved to a device
and the packet is attributed to it:

* the source device gets `packets_sent += 1`, `bytes_sent += length`
* the destination device gets `packets_received += 1`, `bytes_received += length`
* both get `packet_count += 1`, `byte_count += length` ("observed" totals)
* both get `last_seen = packet.timestamp`; on creation `first_seen` is set too

**Non-device endpoints are filtered out** so the registry does not fill with
junk: broadcast/multicast MAC addresses (e.g. `FF:FF:FF:FF:FF:FF`) and
broadcast/multicast IP addresses are skipped as *destinations*. They are never
created as devices, and they are never counted.

High traffic is never interpreted as malicious — M8 only counts.

---

## 5. MAC and IP normalization (M8.7 / M8.8)

* **MAC** — reuses the existing, tested `normalize_mac` (M3), which folds
  `cc:28:aa:72:aa:99`, `CC-28-AA-72-AA-99`, `cc28.aa72.aa99` and `cc28aa72aa99`
  into one canonical uppercase colon form. Because `NormalizedPacket` already
  normalizes MACs on construction, every representation of one NIC resolves to
  one device, never two.
* **IP** — validated and canonicalized with the standard-library `ipaddress`
  module, which handles IPv4 and IPv6 and compresses IPv6 (`2001:0db8::1` →
  `2001:db8::1`). Invalid text is discarded (treated as "no IP").
* Private/public status is **not** classified here; that belongs to later
  enrichment. Private does not mean safe and public does not mean malicious.

---

## 6. Device record (M8.3)

`ObservedDevice` — a plain, mutable, lock-protected dataclass (runtime state,
not a wire schema):

| field | meaning |
|---|---|
| `device_id` | `mac:…` or `ip:…` — the identity from §3 |
| `mac_address` | canonical MAC, or `None` until one is observed |
| `ip_addresses` | set of canonical IPs currently attributed to the device |
| `first_seen` | epoch seconds of first observation |
| `last_seen` | epoch seconds of most recent observation |
| `packet_count` / `byte_count` | total observed (in + out) |
| `packets_sent` / `bytes_sent` | where the device is the source |
| `packets_received` / `bytes_received` | where the device is the destination |
| `hostname` | `None` unless reliably known (M8.11) |
| `vendor` | `None` unless reliably known (M8.12) |
| `is_local` | True if it matches this machine's own identity (M8.10) |

Only information that is actually available is populated. Hostnames and
vendors are never invented.

`DeviceView` (in `app/schemas/device.py`) is the read-only projection returned
by the API: same fields, `first_seen`/`last_seen` rendered as ISO-8601 UTC, and
a computed `status`.

---

## 7. MAC → device and IP → device mappings (M8.16)

The registry keeps two indexes:

    _devices    : device_id  → ObservedDevice
    _mac_index  : MAC        → device_id        (0 or 1 entry per MAC)
    _ip_index   : IP         → device_id        (0 or 1 entry per IP)

Rules:

* **A device has exactly one MAC** (its identity) but **many IPs** (M8.6).
  `_ip_index` maps each of those IPs back to the same device.
* **New MAC** → new device.
* **Known MAC** → update the existing device; add/refresh its IPs.
* **IP-only endpoint** → the device currently owning that IP, or a new
  `ip:…` device if none is mapped.
* **IP moving to a different MAC** → the IP entry is **repointed** to the new
  device, removed from the old device's set, and a *mapping conflict* is
  recorded (counter + log). The two devices are **never silently merged**.
* **IP-only device later reveals a MAC** → this is an *identity upgrade*, not a
  conflict: the MAC device is created and the MAC-less device's counters,
  timestamps and IPs are **adopted** into it, then the MAC-less record is
  removed. This is the one deliberate merge, and it only ever happens when the
  old record has **no MAC** — i.e. the two records cannot be unrelated hosts.

---

## 8. Status and lifecycle (M8.9 / M8.13)

Three states, derived from timing — never from traffic volume:

    active    last_seen is within  inactivity_threshold
    inactive  last_seen is older than inactivity_threshold
    unknown   the device has no valid timing (last_seen is None)

Status is **computed on read** against the current clock, so it can never go
stale between packet bursts. Both thresholds come from settings:

* `device_inactivity_threshold_seconds` (default **120**) — active → inactive
* `device_retention_seconds` (default **3600**) — when cleanup may remove it

Lifecycle, expressed through the above plus cleanup (M8.13/M8.14):

    New        first packet → record created, first_seen == last_seen
    Observed   subsequent packets → last_seen and counters move
    Active     last_seen within the inactivity threshold
    Inactive   traffic stopped for longer than the inactivity threshold
    Expired    cleanup removes records untouched for the retention window

**A device does not disappear when traffic stops.** Inactivity only changes its
status. Removal is a separate, explicit, *configurable* step
(`remove_expired_devices`) and requires the much longer retention window.
`inactivity < retention` is enforced at construction.

---

## 9. Hostname and vendor (M8.11 / M8.12)

* Hostname resolution is **off by default** and **never blocks packet
  processing**. When it is enabled, resolution runs on a background daemon
  thread — the capture thread only schedules it. The local machine's own
  hostname may be filled in for local devices from local system information.
* Vendor is a **field and an interface only**. No OUI database is shipped in
  M8; vendor stays `None` ("unknown") unless a caller provides a resolver.
  Future versions can back it with an OUI lookup.

---

## 10. Local device (M8.10)

The monitoring machine is identified from the interfaces M3/M4 already
discovered (their MACs and IPs). Nothing is hard-coded. If the interface
information is unavailable, devices are simply not flagged as local.

---

## 11. Thread safety and memory (M8.15 / M8.14)

`DeviceDiscoveryManager` is written to the same contract as
`TrafficStatisticsManager`:

* one `threading.RLock` guards the registry, both indexes and every counter;
  readers and the capture thread cannot race.
* `process_packet` contains its own errors: a malformed packet is counted and
  dropped, never raised, so capture and statistics keep running.
* the registry is bounded by an optional `max_devices` cap; when the cap is hit,
  the oldest-by-`last_seen` record is evicted, so a flood of spoofed addresses
  cannot grow memory without limit.

---

## 12. Interface (M8.1 deliverable)

    process_packet(packet: NormalizedPacket) -> None
    get_device(device_id: str) -> ObservedDevice | None
    list_devices(status=None, ip=None, mac=None, limit=None) -> list[ObservedDevice]
    update_device(...)      # refresh counters/timestamps for a known device
    remove_expired_devices(now=None) -> int
    reset() -> None
    # diagnostics
    get_device_count(), get_error_count(), get_conflict_count()

It depends only on `NormalizedPacket` — never on Scapy.

---

## 13. Out of scope (guard rails)

No threat detection, alerts, baselines, ML/AI, risk or trust scoring,
correlation, blocking, WebSockets, frontend, or SIEM integration. M8 discovers
and tracks devices; everything else is a later milestone's job.
