# NetWatch AI — M13 REST API Design

**Milestone:** M13 — REST API
**Scope:** consolidate and complete the HTTP surface over M3–M12.
**Status:** implemented.

---

# 1. Purpose

M13 exposes what earlier milestones already compute. It adds **no** detection,
alert, correlation or scoring logic, and it does not redesign M3–M12.

    HTTP request
         ↓
    route (thin)
         ↓
    request validation (FastAPI Query/Body + shared helpers)
         ↓
    service / manager / engine  ← the owner of the behaviour
         ↓
    repository / runtime state
         ↓
    response envelope
         ↓
    HTTP response

Route handlers validate, delegate and serialize. Any rule about *what* a
finding, alert or incident is lives where it already lived.

---

# 2. What M13 does not implement

Per the M13 development rule, this milestone contains no new detection, alert,
correlation or risk logic, no ML/AI, no WebSockets, no frontend, no automatic
blocking, no SIEM integration and no authentication/RBAC.

M14 owns WebSockets. M15 owns the frontend. M17 owns report **generation**.

---

# 3. M13.1 audit of the pre-M13 surface

## 3.1 Routes that already existed

| Module | Route | Owner |
| --- | --- | --- |
| health | `GET /api/v1/health` | process |
| capture | `GET /api/v1/capture/interfaces` | `InterfaceManager` (M3) |
| capture | `GET /api/v1/capture/interface` | `InterfaceManager` (M3) |
| capture | `PUT /api/v1/capture/interface` | `InterfaceManager` (M3) |
| capture | `GET /api/v1/capture/status` | `CaptureManager` (M4) |
| capture | `POST /api/v1/capture/start` | `CaptureManager` (M4) |
| capture | `POST /api/v1/capture/stop` | `CaptureManager` (M4) |
| statistics | `GET /api/v1/statistics/traffic` | `TrafficStatisticsManager` (M6) |
| statistics | `GET /api/v1/statistics/protocols` | `TrafficStatisticsManager` (M6) |
| statistics | `GET /api/v1/statistics/top-talkers` | `TrafficStatisticsManager` (M6) |
| statistics | `GET /api/v1/statistics/ports` | `TrafficStatisticsManager` (M6) |
| statistics | `POST /api/v1/statistics/reset` | `TrafficStatisticsManager` (M6, dev helper) |
| packets | `GET /api/v1/packets` | `PacketQueryService` (M7) |
| packets | `GET /api/v1/packets/{id}` | `PacketQueryService` (M7) |
| packets | `POST /api/v1/packets/retention/cleanup` | `PacketRetentionService` (M7, dev helper) |
| devices | `GET /api/v1/devices` | `DeviceDiscoveryManager` (M8) |
| devices | `GET /api/v1/devices/{device_id}` | `DeviceDiscoveryManager` (M8) |
| connections | `GET /api/v1/connections` | `ConnectionTracker` (M9) |
| connections | `GET /api/v1/connections/active` | `ConnectionTracker` (M9) |
| connections | `GET /api/v1/connections/{id}` | `ConnectionTracker` (M9) |
| connections | `POST /api/v1/connections/expire` | `ConnectionTracker` (M9, dev helper) |
| detections | `GET /api/v1/detections` | `DetectionEngine` (M10) |
| detections | `GET /api/v1/detections/rules` | `DetectionEngine` (M10) |
| detections | `POST /api/v1/detections/reset` | `DetectionEngine` (M10, dev helper) |
| alerts | `GET /api/v1/alerts` | `AlertQueries` (M11) |
| alerts | `GET /api/v1/alerts/summary` | `AlertQueries` (M11) |
| alerts | `GET /api/v1/alerts/diagnostics` | `AlertEngine` (M11) |
| alerts | `GET /api/v1/alerts/{id}` | `AlertQueries` (M11) |
| alerts | `GET /api/v1/alerts/{id}/evidence` | `AlertQueries` (M11) |
| alerts | `POST /api/v1/alerts/{id}/status` | `AlertService` (M11) |

Every one of these is under `/api/v1` already. There is no `/api/v2`, no
unversioned production route and no duplicate path.

## 3.2 Findings of the audit

1. **One envelope already existed and was already consistent.** Every router
   returned `{"success", "message", "data"}` or
   `{"success", "message", "errors": [{"field", "code"}]}`. M13.4/M13.5's example
   shape is realized by this envelope, which adds a human `message` and expresses
   errors as a list of `{field, code}` pairs. Per M13.4 ("use the project's
   existing response conventions where they already exist"), M13 keeps it rather
   than introducing a second, incompatible format (see §5).
2. **Error translation was duplicated.** Five modules each defined a private
   `_error_response`, and three defined their own `_parse_timestamp`. M13 moves
   both into `app/api/common/`.
3. **Two modules were doing the same job.** `app.alerts.queries` and
   `app.api.v1.alerts` both validated severities and statuses; M13 keeps the
   service as the sole authority and the route only folds case (§7.13).
4. **Pagination was consistent but implicit.** Packets, devices, connections,
   detections and alerts all used `limit`/`offset` with a default of 100 and a
   maximum of 1000, validated by `Query(ge=1, le=…)`. M13 names that contract in
   `app/api/common/pagination.py` and applies it to every new collection.
5. **Time was already standardized, but only by convention.** Findings and
   alerts filtered in epoch seconds; packets filtered in datetimes; every
   response rendered ISO-8601 UTC. M13 keeps epoch/naive-UTC inside and ISO-8601
   UTC on the wire, and documents the one boundary where each conversion happens
   (§6).
6. **Missing API groups.** There was no incidents, evidence-by-id, baselines,
   analytics, dashboard, reports, settings, system or notifications router, and
   no `GET /detections/{finding_id}`.
7. **Two schema gaps are real and are not papered over.**
   * `packets` has no capture-interface column, so M13.8's `interface` filter
     cannot be honoured. It is **not** accepted rather than silently ignored.
   * `packets.device_id` is always `NULL` (M7 does not set it), so a packet
     `device_id` filter would always match nothing. It is likewise not offered.
8. **Alert lifecycle actions were expressed as a body.** M11 shipped
   `POST /alerts/{id}/status` with `{"status": …}`. M13.13 asks for named action
   routes; both are now served, both delegating to the same validated transition
   table, so there is one rule set and two spellings of the same request
   (§7.13).

## 3.3 Duplicate and overlapping endpoints

None were found. `GET /statistics/*` (live M6 aggregation) and `GET /analytics/*`
(M13 aggregation over the same services plus persisted counts) are deliberately
different: statistics reports the *current runtime snapshot*; analytics reports
*derived views* (ranked summaries, threat counts). Neither recomputes the other's
work, and analytics reads the statistics manager rather than duplicating it.

---

# 4. Route structure

```
app/api/
    common/
        envelope.py       standard success/error payloads and error codes
        errors.py         the controlled API error hierarchy + handlers
        pagination.py     the shared limit/offset contract
        validation.py     shared filter parsing (IP, port, enum, time, range)
    v1/
        __init__.py       registers every router under /api/v1
        capture.py        M13.7
        packets.py        M13.8
        statistics.py     M13.9
        devices.py        M13.10
        connections.py    M13.11
        detections.py     M13.12
        alerts.py         M13.13
        evidence.py       M13.14
        incidents.py      M13.15 + M13.16
        baselines.py      M13.17
        analytics.py      M13.18
        dashboard.py      M13.19
        reports.py        M13.20
        settings.py       M13.21
        system.py         M13.22
        notifications.py  M13.23
        health.py         M1, unchanged
```

Every router is included with `prefix="/api/v1"` and an OpenAPI tag. No
unversioned route is exposed.

---

# 5. Response envelope (M13.4 / M13.5)

Success:

```json
{"success": true, "message": "Devices retrieved", "data": { }}
```

Error:

```json
{
  "success": false,
  "message": "Device not found",
  "errors": [{"field": "device_id", "code": "DEVICE_NOT_FOUND"}]
}
```

Why the list of `{field, code}` rather than a single `error` object: a request can
fail on more than one filter, and the existing contract already carried the field
that failed. The `code` is the machine-readable part a client branches on; the
`message` is for a human and never contains a stack trace, a filesystem path or a
database detail (M13.5/M13.30).

## 5.1 Collection payloads

Collections keep their resource-named key, because they already did and M13 must
not break a working contract:

```json
{"count": 2, "total": 7, "limit": 2, "offset": 0, "devices": [ ]}
```

`count` is the size of this page, `total` the size of the whole match set.
`total` is present wherever it can be computed cheaply (packets, alerts); the
in-memory registries (devices, connections, findings, incidents) report `count`
plus `total` where the store can count without materializing.

## 5.2 Error codes

Every code the API can return, and its HTTP status, is listed in
`app/api/common/envelope.py::ErrorCode` and asserted by the contract tests.
---

# 6. Time handling (M13.26)

One rule, stated once:

| Layer | Representation |
| --- | --- |
| `packets.timestamp`, `traffic_statistics.timestamp`, `connections.start_time` | naive UTC `datetime` in SQLite |
| findings, alerts, incidents, correlation windows, connection clock | epoch seconds (`float`) |
| **every HTTP response** | ISO-8601 UTC string |
| **every HTTP filter** | ISO-8601 UTC string |

The conversion happens at the API boundary and nowhere else:

* `app/api/common/validation.py::parse_epoch_filter` — an ISO-8601 query value
  into epoch seconds, for findings, alerts and incidents. A naive value is read
  as UTC; a trailing `Z` is accepted; a blank or unparseable value is a `400`,
  never a silently widened window.
* `app/api/common/validation.py::parse_datetime_filter` — an ISO-8601 query
  value into the naive UTC `datetime` the packet table stores, so an offset such
  as `+05:30` cannot shift the comparison by hours.
* Responses render with `to_utc_datetime(...).isoformat()` (epoch sources) or the
  stored value's ISO form with a UTC offset attached (datetime sources), so a
  client never has to guess a timezone.

There is no `start_time`/`end_time` spelling anywhere: the project's filters are
`since` (inclusive) and `until` (exclusive), consistently across packets,
findings, alerts and incidents. Introducing the second spelling the older
roadmap text used would have created exactly the competing convention M13.26
forbids, so `since`/`until` is the documented contract.

## 6.1 Why `since` is inclusive and `until` exclusive

Two adjacent windows must not both claim the same instant, or a row would be
counted twice and a page boundary would repeat itself. This matches M10.13 and is
already how M7/M10/M11 filter.

---

# 7. Per-module design

Each subsection names the M13 requirement, the route(s), the owning service and
the decisions that are not obvious from the code.

## 7.1 Capture (M13.7)

```
GET  /api/v1/capture/interfaces
GET  /api/v1/capture/interface
PUT  /api/v1/capture/interface
GET  /api/v1/capture/status
POST /api/v1/capture/start
POST /api/v1/capture/stop
```

Owner: `InterfaceManager` (selection) and `CaptureManager` (session).
`GET /capture/status` is the session view: `status`, `interface`, `packet_count`,
which is the "session information" M13.7 asks for. Raw manager and sniffer
objects are never returned.

Controlled capture errors keep their pre-M13 mapping:

| Error | Status | Code |
| --- | --- | --- |
| capture already running | 409 | `CAPTURE_ALREADY_RUNNING` |
| capture not running | 409 | `CAPTURE_NOT_RUNNING` |
| no / unusable interface | 400 | `CAPTURE_NO_INTERFACE` |
| start failed | 500 | `CAPTURE_START_FAILED` |
| stop failed | 500 | `CAPTURE_STOP_FAILED` |

`GET /capture/interface` with nothing selected is a `400` with
`NO_INTERFACE_SELECTED`, which is the pre-M13 behaviour: "no interface is
selected" is a state the client must act on, not a missing resource.

## 7.2 Packets (M13.8)

```
GET /api/v1/packets
GET /api/v1/packets/{packet_id}
```

Owner: `PacketQueryService` over `PacketRepository`. Filters: `source_ip`,
`destination_ip`, `protocol`, `source_port`, `destination_port`, `since`,
`until`, `limit`, `offset`. Ordered newest first, deterministically
(`timestamp DESC, id DESC`).

**Not offered, and why.** `interface` has no column in `packets` (M7 dropped it
deliberately rather than misuse a column) and `device_id` is always `NULL`
because M7 does not resolve devices. A filter that always matches nothing is
worse than an absent one, so neither is accepted; a client that sends them gets
the normal FastAPI `422` for an unknown query parameter only if it uses
`extra=forbid` — these are simply absent parameters, so they are ignored by
FastAPI's default behaviour. The gap is recorded here rather than hidden.

**Payload policy (M13.8/M7.5).** No payload and no `payload_length` is ever
returned; the M7 mapping never stores one.

## 7.3 Statistics (M13.9)

```
GET  /api/v1/statistics/traffic?window=1s|10s|60s
GET  /api/v1/statistics/protocols
GET  /api/v1/statistics/top-talkers?limit=&by=
GET  /api/v1/statistics/ports?limit=&by=&direction=
POST /api/v1/statistics/reset
```

Owner: `TrafficStatisticsManager`. Nothing is recalculated in the route: every
number comes from a manager query. `reset` is the pre-existing development
helper and clears only in-memory counters.

## 7.4 Devices (M13.10)

```
GET /api/v1/devices?status=&ip=&mac=&limit=
GET /api/v1/devices/{device_id}
```

Owner: `DeviceDiscoveryManager`. Returns identity, addresses, MAC, first/last
seen, packet/byte counts and activity `status`. **No risk score** is returned,
because M8 does not compute one; the M2 `devices.risk_score` column belongs to
the seed data and is not a runtime observation.

An unparseable `ip`/`mac` filter is a `400 INVALID_FILTER`, not an ignored
parameter.

## 7.5 Connections (M13.11)

```
GET  /api/v1/connections?protocol=&source_ip=&destination_ip=&source_port=&destination_port=&device_id=&state=&active_only=&limit=
GET  /api/v1/connections/active?limit=
GET  /api/v1/connections/{connection_id}
POST /api/v1/connections/expire
```

Owner: `ConnectionTracker`. Responses are bounded by `limit`; filters are
validated by the tracker, which raises `ValueError` for an unusable filter and
the route turns that into a `400`. ICMP has no ports, so a port filter combined
with `protocol=ICMP` is a `400` rather than an empty result.

## 7.6 Detection (M13.12)

```
GET  /api/v1/detections?rule_id=&source_ip=&destination_ip=&device_id=&since=&until=&limit=
GET  /api/v1/detections/{finding_id}
GET  /api/v1/detections/rules
POST /api/v1/detections/reset
```

Owner: `DetectionEngine`. The engine *observes*; the API only reports. No route
can trigger a detector: there is no "run rules now" endpoint, because that would
put detection on a request path.

`GET /detections/{finding_id}` is new (M13.12). Findings live in the engine's
bounded runtime history, so introspection is a read method on
`FindingHistory`/`DetectionEngine` — `get_finding(finding_id)` — not a new store.
A finding that has aged out of the bounded history is a `404`, which is the
honest answer: it is no longer retained.

## 7.7 Alerts (M13.13)

```
GET  /api/v1/alerts?severity=&min_severity=&status=&rule_id=&rule_key=&source_ip=&destination_ip=&since=&until=&limit=&offset=
GET  /api/v1/alerts/summary
GET  /api/v1/alerts/diagnostics
GET  /api/v1/alerts/{alert_id}
POST /api/v1/alerts/{alert_id}/acknowledge
POST /api/v1/alerts/{alert_id}/resolve
POST /api/v1/alerts/{alert_id}/dismiss
POST /api/v1/alerts/{alert_id}/false-positive
POST /api/v1/alerts/{alert_id}/status      (body: {"status": …})
```

Owner: `AlertQueries` (reads) and `AlertService` (lifecycle). The named actions
are thin: each calls `AlertService.set_status`, which validates against
`app.alerts.status.VALID_TRANSITIONS`. An illegal move or a move out of a
terminal state is a `409 INVALID_TRANSITION` with the reachable states named in
the message, and the stored alert is left untouched. **No lifecycle rule is
duplicated in the route.**

## 7.8 Evidence (M13.14)

```
GET /api/v1/alerts/{alert_id}/evidence?evidence_type=
GET /api/v1/evidence/{evidence_id}
```

Owner: `AlertQueries` / `AlertEvidenceRepository`. Evidence references the
underlying resource (`packet_id`) rather than duplicating packet data, matching
M11.13. The standalone `GET /evidence/{evidence_id}` returns one record plus the
`alert_id` it belongs to, so a client can navigate from a reference to its alert.

## 7.9 Incidents (M13.15 / M13.16)

```
GET  /api/v1/incidents?status=&source=&device_id=&connection_id=&rule_id=&min_risk_score=&max_risk_score=&since=&until=&limit=&offset=&order=
GET  /api/v1/incidents/open?limit=
GET  /api/v1/incidents/{incident_id}
POST /api/v1/incidents/{incident_id}/investigate
POST /api/v1/incidents/{incident_id}/resolve
POST /api/v1/incidents/{incident_id}/dismiss
```

Owner: `CorrelationEngine` → `IncidentRegistry`. Every filter maps onto an
existing `IncidentQuery` field; the API does not invent a filter the store cannot
apply, and it does not recalculate a risk score.

Exposed per incident: identity, `title`, `status`, `created_at`/`updated_at`,
`start_time`/`last_seen` (both epoch and ISO-8601 UTC), `span_seconds`,
`event_count`, `dropped_events`, member `alert_ids`, `finding_ids`, `device_ids`,
`connection_ids`, `rule_ids`, `correlation_rule_ids`,
`correlation_reasons`, `correlation_confidence`, `alert_confidence`, `severity`,
`risk_score` and `risk_band`.

`correlation_confidence`, `alert_confidence` and `risk_score` stay three
separate fields (M12.16) and the listing uses `CorrelatedIncident.summary()`, the
detail uses `.as_dict()`.

Out-of-range or inverted risk bounds and an inverted time range are rejected by
`IncidentQuery` at construction and surface as `400 INVALID_FILTER`; an unknown
`order` value is a `422`.

`POST /incidents/{id}/investigate|resolve|dismiss` delegate to
`CorrelationEngine.set_status`, so M12.9's transition table is the only
authority. An invalid transition is a `409`.

## 7.10 Baselines (M13.17)

```
GET /api/v1/baselines
GET /api/v1/baselines/{device_id}
```

The behavioural baseline **engine** is not implemented and M13 explicitly does
not implement it. There is therefore no baseline to expose, and this module
returns `501 FEATURE_NOT_IMPLEMENTED` with a message naming the subsystem and the
milestone that owns it.

Why `501` rather than a list of the seeded `behavioral_baselines` rows: those
rows are M2 development seed data (`status='learning'`, `observation_count=0`).
Serving them as baselines would present placeholder data as an analysed
behavioural profile, which is exactly the "fake data" M13.17 forbids.

## 7.11 Analytics (M13.18)

```
GET /api/v1/analytics/traffic
GET /api/v1/analytics/protocols
GET /api/v1/analytics/devices
GET /api/v1/analytics/connections
GET /api/v1/analytics/threats
```

Every number is produced by an already-implemented service, read at request
time. Nothing is simulated and nothing is extrapolated.

| Route | Source |
| --- | --- |
| `traffic` | `TrafficStatisticsManager` live totals + rates; stored packet count from `PacketRepository` |
| `protocols` | `TrafficStatisticsManager.get_protocol_statistics()` |
| `devices` | `DeviceDiscoveryManager` registry: totals and a bounded top-N by packets/bytes |
| `connections` | `ConnectionTracker` counters and a bounded top-N by bytes |
| `threats` | `AlertQueries.summary()` + `DetectionEngine` rule counters + `CorrelationEngine` status/risk-band counts |

`analytics/traffic` deliberately reports the *runtime* view. A historical time
series is not exposed because nothing writes `traffic_statistics`, and inventing
a series from the packet table would be a different (and much more expensive)
query than M13 asks for.

## 7.12 Dashboard (M13.19)

```
GET /api/v1/dashboard/summary
```

Aggregates the existing services into one bounded payload: capture status,
packets observed (session + persisted), traffic rate, device count, active
connections, open alerts, active incidents, recent detections. It duplicates no
business logic — each field is one method call on the object that owns it — and
a failure in any one section is reported as that section being unavailable rather
than failing the whole response (M13.29).

## 7.13 Reports (M13.20)

```
GET /api/v1/reports?report_type=&format=&limit=&offset=
GET /api/v1/reports/{report_id}
POST /api/v1/reports/generate
```

`GET` reads stored report **metadata** from the `reports` table. Report
*generation* is M17 and is not implemented; `POST /reports/generate` therefore
returns `501 FEATURE_NOT_IMPLEMENTED` rather than fabricating a file.

## 7.14 Settings (M13.21)

```
GET /api/v1/settings
GET /api/v1/settings/{setting_key}
PUT /api/v1/settings
```

Owner: the `settings` key/value table, through a repository. Three sets are
defined explicitly (M13.21):

* **readable** — every stored key except the internal-only ones;
* **mutable** — `capture_interface`, `default_theme`, `packet_retention_days`,
  `alert_threshold`, `ai_enabled`;
* **internal-only** — any key whose name matches the secret denylist
  (`secret`, `password`, `token`, `key`, `credential`, `dsn`), plus an explicit
  list. Internal-only keys are neither listed nor readable, so a secret cannot
  leak through this endpoint (M13.30).

`PUT` accepts a mapping of key → value, validates each against its declared
`data_type` and its per-key constraint (a port range, a positive integer, a
member of an enumerated set) and rejects an unknown or immutable key. Every
response states `restart_required`: stored settings are read by the application
at startup from the environment, so changing a stored value does not reconfigure
a running service. That distinction is stated in the payload rather than implied.

## 7.15 System (M13.22)

```
GET /api/v1/system/status
GET /api/v1/system/health
GET /api/v1/system/info
```

* `health` — the liveness probe: process up, database reachable.
* `status` — per-component state: capture, persistence, connections, detection,
  alerting, correlation, database, API; each with its enable flag and counters.
* `info` — version, environment, Python/platform, database dialect, uptime,
  registered route count.

No secret, no absolute filesystem path, no connection string is exposed
(M13.22/M13.30).

## 7.16 Notifications (M13.23)

```
GET /api/v1/notifications?unread_only=&limit=&offset=
GET /api/v1/notifications/{notification_id}
```

Read-only over the `notifications` table. No external delivery integration is
implemented, so nothing here claims one: the endpoints report stored records and
nothing else. Records are ordered newest first with `id` as the tie-break.

---

# 8. Pagination (M13.24)

`app/api/common/pagination.py` defines the one contract:

| Parameter | Default | Minimum | Maximum |
| --- | --- | --- | --- |
| `limit` | `100` | `1` | `1000` (alerts: `settings.alert_max_page_size`) |
| `offset` | `0` | `0` | — |

* The default bounds a response even when the client asks for nothing.
* The maximum is enforced by FastAPI's own validation, so an over-large request
  is a `422` before a handler runs.
* Ordering is deterministic everywhere: each collection orders by its natural
  descending time, then by primary key (or id string) as a tie-break, so the same
  query returns the same page order.
* No endpoint can return an unbounded result set: even `limit` omitted uses the
  default.

Pages report `count` and, where the store can count cheaply, `total`; `limit` and
`offset` are echoed so a client can compute the next request.

---

# 9. Filtering and validation (M13.25)

`app/api/common/validation.py` owns the shared validators, so the same value is
accepted or rejected identically wherever it appears:

| Input | Rule on failure |
| --- | --- |
| IP address | `400 INVALID_FILTER` naming the field |
| port | `422` (`Query(ge=0, le=65535)`) |
| protocol | `422` (closed `Literal`) |
| enumerated state | `422` (closed `Literal`) |
| severity | `400 INVALID_FILTER` naming the field |
| ISO-8601 time | `400 INVALID_FILTER` naming the field |
| risk-score range | `400 INVALID_FILTER` |
| `limit` / `offset` | `422` |

Nothing is silently coerced into an unrelated valid value: an unknown severity is
not treated as `low`, an unparseable address is not treated as "no filter", and a
blank rule key is not treated as "all rules".

Where a closed vocabulary is known at import time it is a `Literal`, so FastAPI
documents it in the OpenAPI schema and rejects a bad value before the handler
runs. Where the vocabulary belongs to a service (`AlertStatus`, `IncidentStatus`)
the service validates and the route maps the failure to `400`/`409`.

---

# 10. Dependency injection (M13.28)

Every route takes its collaborator through `Depends`:

| Dependency | Provides |
| --- | --- |
| `app.database.session.get_db` | a request-scoped SQLAlchemy session |
| `get_interface_manager`, `get_capture_manager` | the process-wide capture singletons |
| `get_statistics_manager`, `get_device_manager`, `get_connection_tracker` | the runtime registries |
| `get_detection_engine`, `get_alert_engine`, `get_correlation_engine` | the processing engines |
| `get_alert_queries` | the alert read service (session factory injected) |
| `get_packet_persistence`, `get_packet_retention_service` | the persistence layer |
| `pagination_params` | the shared page window |

No route constructs a singleton. Where a service holds no per-request state it is
the process-wide instance; where it needs a session it takes a session factory
and opens one per call (`AlertQueries`), because a SQLAlchemy session is not
thread-safe. Tests override these dependencies, which is why the whole API is
testable without a live capture interface.

---

# 11. Error isolation (M13.29)

An API failure cannot crash capture, processing, statistics, device tracking,
connection tracking, detection, alerting or correlation, for three structural
reasons:

1. **The engines already isolate themselves.** Detection, alerting and
   correlation each consume the pipeline on a thread of their own and return
   outcomes instead of raising. No API call is on their path.
2. **Reads are snapshots.** The registries return immutable records or copies, so
   a handler holding one cannot mutate the store the capture thread is writing.
3. **Errors are translated, not propagated.** `ApiError` subclasses are rendered
   by a registered handler; an unexpected exception is rendered as an opaque
   `500 INTERNAL_ERROR` with no traceback, path or query text. `GET` handlers
   additionally catch service-level `ValueError` and translate it to `400`,
   because an unusable filter is a client error, not a server fault.

The dashboard endpoint applies this per section: a section that raises becomes
`{"available": false, "error": …}` while the rest of the summary is still served.

---

# 12. Security boundary (M13.30)

M13 is a **local application API**. There is no authentication and no RBAC, by
design — the local-development assumption is documented here and nowhere else is
it assumed:

* the process binds `127.0.0.1` by default and CORS allows only the local
  frontend dev origins;
* every input is validated and every response bounded;
* no route accepts a filesystem path, a table name or a SQL fragment, so there is
  no arbitrary filesystem access and no arbitrary SQL through a parameter;
* no secret is exposed — settings strips internal-only keys, system reports no
  connection string, errors report no internals;
* `PUT /settings` mutates only a whitelisted set of keys with typed values.

Deploying this API beyond a trusted local network requires M13's successor
work (authentication/RBAC), which is explicitly out of scope here.

---

# 13. OpenAPI (M13.27)

`/docs`, `/redoc` and `/openapi.json` are enabled and every M13 route appears in
them. Tags group the routes by module; each route declares its query parameters
with bounds and descriptions, its request bodies as Pydantic models, and its
responses with their status codes. Response bodies are described by Pydantic
schemas (`app/schemas/*`) wherever a stable shape exists, and the error envelope
is documented once in the description of each router's tag.

---

# 14. Performance baseline (M13.37)

`backend/scripts/benchmark_m13.py` measures the operations the milestone lists:
a simple endpoint, a list endpoint, a filtered query, a paginated query, the
dashboard summary, JSON serialization and the database query behind the packet
list. The numbers are recorded in `docs/TODO.md` and are **not** a
production-capacity claim: they come from one development machine with an
OneDrive-synced SQLite file.

---

# 15. Verification

* Unit/API tests: `tests/test_api_contract.py`, `test_api_validation.py`,
  `test_system_api.py`, `test_settings_api.py`, `test_dashboard_api.py`,
  `test_analytics_api.py`, `test_incidents_api.py`, `test_evidence_api.py`,
  `test_baselines_api.py`, `test_reports_api.py`, `test_notifications_api.py`.
* Integration test: `tests/test_api_integration.py` drives the documented chain
  capture → packet → statistics/devices/connections → detection → alert →
  correlation → HTTP.
* Manual verification: `backend/scripts/verify_m13.py` starts the application
  through the ASGI transport and exercises every group against real services.
