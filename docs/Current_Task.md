# NetWatch AI — Current Task

**Current Phase:** Base Application Implementation
**Current Milestone:** M13 — REST API
**Status:** Ready to start (M12 complete)
**Predecessor:** M12 — Correlation + Risk Scoring ✅ COMPLETE

> M12 is done: 1 271 tests pass, `docs/16_M12_Correlation_Design.md` is the design
> of record, and `scripts/verify_m12.py` / `scripts/benchmark_m12.py` are the
> verification and baseline scripts. M12 deliberately shipped **no** public API —
> M13 is where the incident surface becomes reachable over HTTP.

---

# Current Objective

Turn the backend's existing per-milestone verification endpoints into **one
consistent, validated, paginated REST API** that the frontend can consume, and
expose the surfaces that currently exist only inside the process — above all the
M12 correlated incidents.

The contract already exists: **`docs/04_API_Specification.md`** is the
specification, not a sketch. M13 implements it, and where reality and the spec
disagree the disagreement is reported and the doc corrected rather than the code
silently diverging.

The pipeline M13 exposes:

    Network
       ↓
    Packet Processing
       ↓
    Statistics / Devices / Connections
       ↓
    Detection Engine
       ↓
    Detection Findings
       ↓
    Alert Engine
       ↓
    Alerts
       ↓
    Correlation Engine
       ↓
    Correlated Incidents
       ↓
    Risk Scoring Engine
       ↓
    Risk Score
       ↓
    REST API            ← M13
       ↓
    Frontend (M15)

M13 must keep:

    Read paths
    Write paths

as separate concerns, and must keep:

    Alert confidence
    Correlation confidence
    Risk score

as separate fields on the wire — M12.16 is not relaxed by serialization.

---

# What already exists (review before writing anything)

Eight routers are already registered under `/api/v1`:

| Router | File | Nature |
| --- | --- | --- |
| health | `app/api/v1/health.py` | foundation (M1) |
| capture | `app/api/v1/capture.py` | control plane (M3/M4) |
| packets | `app/api/v1/packets.py` | read, dev/testing (M7) |
| statistics | `app/api/v1/statistics.py` | read (M6) |
| devices | `app/api/v1/devices.py` | read (M8) |
| connections | `app/api/v1/connections.py` | read (M9) |
| detections | `app/api/v1/detections.py` | read (M10) |
| alerts | `app/api/v1/alerts.py` | read + one lifecycle write (M11) |

Their schemas live in `app/schemas/`, they are registered through
`app/api/__init__.py`'s `api_router`, and they already follow the project's
envelope and error conventions. **M13 extends them; it does not rewrite them.**
Every one of those earlier milestones deliberately scoped its endpoints to "what
verification needs" — M13 is the milestone that makes them the real thing.

Not yet exposed anywhere over HTTP: **M12's correlated incidents and risk
scores**, and the dashboard, analytics, detection-rule, settings, system and
report surfaces.

---

# M13 Development Rule

Do NOT implement:

- New packet detectors or detection rules
- New alert types
- New correlation rules or changes to the risk formula
- Behavioural baselines
- ML or AI analysis
- Automatic blocking
- WebSockets (M14)
- Frontend work of any kind (M15)
- New analytics computation beyond what M6/M10/M11/M12 already hold (M16 owns the
  analytics *product*; M13 exposes the data that exists)
- Authentication or RBAC (explicitly out of scope for the base application)
- Report generation (M17) — M13 may expose the *stored* report rows if the table
  is populated, but does not build PDF/CSV generation
- Notifications generation — M13 may expose the `notifications` table; it does not
  create notification events

M13 is a **presentation and validation** milestone. It reads what M5–M12 built,
validates what it is asked for, and refuses clearly when the request is wrong.

---

# M13.1 — Review the existing API surface

Before adding anything, review and write down:

1. The existing envelope and error shape — `docs/04_API_Specification.md` §5, §30.
2. The existing pagination shape — §6 — and whether every current listing honours it.
3. The existing filtering conventions — §7.
4. Every current route, its parameters, its bounds, and where it returns `400`
   versus `404`.
5. `app/schemas/` — which response models exist and which endpoints return ad-hoc
   dictionaries instead of a schema.
6. `app/api/__init__.py` — how routers are registered and in what order.
7. The thread-safety and read-only rules the earlier milestones established
   (M11.23, M12.23) — an endpoint must not mutate what it reads.

Determine what is already consistent before changing anything. **Do not
duplicate a schema that already exists.**

---

# M13.2 — Consistency baseline

Establish, and apply to every endpoint M13 touches:

    One envelope shape for every response
    One error shape for every failure
    One pagination shape for every listing
    One place that knows the valid bounds (limit, offset, time range, score range)

Two rules carried over from earlier milestones and made API-wide:

- **A rejected filter is never ignored.** An unknown severity, an unknown status
  or an empty rule key returns `400`, never an empty result that looks like
  "nothing found".
- **Reads never mutate.** Only explicitly-writable endpoints change state.

The bounds are the ones the owning milestone already documented
(`ALERT_MAX_PAGE_SIZE`, `DEFAULT_MAX_PAGE_SIZE`, `RISK_SCORE_MIN/MAX`, the
correlation window, the alert severity vocabulary, the incident status
vocabulary). The API validates against those tables; it does not invent a second
copy of them.

---

# M13.3 — Dashboard API

    GET /dashboard
    GET /dashboard/traffic
    GET /dashboard/protocols
    GET /dashboard/top-talkers
    GET /dashboard/ai-summary

The dashboard is an **aggregation of what already exists** — the M6 statistics
manager, the M8 device registry, the M9 tracker, the M11 alert store and the M12
incident store. It computes no new metric.

`GET /dashboard/ai-summary` has no implementation to call: M12 shipped no AI or
ML subsystem. It must return the documented "unavailable" shape with a clear
reason, not a fabricated summary. This is the same discipline M12 applied to its
reserved ML contribution.

---

# M13.4 — Capture API

    GET  /capture/interfaces
    GET  /capture/status
    POST /capture/start
    POST /capture/stop

Mostly present from M3/M4. M13 reviews it against §10 and closes the gaps:
validation of the requested interface (an unknown interface is a `400`/`404`
naming the problem, never a silent fallback), `409` on a duplicate start, a
consistent status shape, and an error body that says *why* capture could not
start (no admin rights, no Npcap, interface down).

---

# M13.5 — Packet API

    GET /packets
    GET /packets/{packet_id}

A read-only window onto the M7 `packets` table. Bounds (time range, protocol,
address, limit) are validated; `payload` is never exposed, matching M7's "no
payload storage by default" policy.

---

# M13.6 — Device API

    GET /devices
    GET /devices/{device_id}
    GET /devices/{device_id}/traffic
    GET /devices/{device_id}/connections
    GET /devices/{device_id}/alerts
    GET /devices/{device_id}/baseline

The first two exist from M8; the sub-resources are new and each **composes
existing services** — traffic from M6, connections from M9, alerts from M11.

`/devices/{device_id}/baseline` has no implementation to call: baselines are
deliberately excluded from the base application (M12.19's "do not assign
criticality levels unless the application has an actual configured
asset-classification source" is the same principle). It returns the documented
"unavailable" shape with a reason.

---

# M13.7 — Alert API

    GET  /alerts
    GET  /alerts/{alert_id}
    POST /alerts/{alert_id}/acknowledge
    POST /alerts/{alert_id}/investigate
    POST /alerts/{alert_id}/resolve
    POST /alerts/{alert_id}/false-positive

Reads exist from M11. The four state endpoints are new and map onto the M11
lifecycle through `AlertService.set_status(...)`, which already:

- validates the transition against `VALID_TRANSITIONS` **before** writing,
- raises `InvalidStatusTransition` for a forbidden move,
- returns `None` for an unknown id.

M13 maps those onto HTTP (`409` with the reachable states for an illegal move,
`404` for an unknown id, `200` with the updated alert otherwise) and adds
nothing to the lifecycle itself. A reopen stays rejected (M11).

> The spec (§13) names these four actions; the M11 lifecycle also has an `open`
> state and `AlertStatus` is the authority. Where the spec's action names and the
> M11 state names differ, the M11 states win and the spec is corrected — one
> vocabulary, in one place.

---

# M13.8 — Alert Evidence API

    GET /alerts/{alert_id}/evidence

Exists from M11; M13 reviews it against §14, adds the `evidence_type` filter
validation (the five M11 types plus the documented-but-unused `ml`), and keeps
the "references, never copies" shape — packet evidence returns the packet
reference and digest, never a payload.

---

# M13.9 — Incident API (the M12 surface, made reachable)

This is M13's **principal new content**. M12 built the correlation and risk
machinery and deliberately shipped no API. M13 exposes it:

    GET  /incidents
    GET  /incidents/{incident_id}
    GET  /incidents/{incident_id}/alerts
    GET  /incidents/{incident_id}/findings
    POST /incidents/{incident_id}/status
    GET  /incidents/summary
    GET  /incidents/statistics

Requirements, all of which M12 already supports internally:

- The listing is backed by `CorrelationEngine.get_incidents(IncidentQuery(...))`
  and therefore inherits its **bounded pages and deterministic ordering**
  (`recent`, `oldest`, `risk`, `confidence` — every one total, ties broken on
  `incident_id`).
- The filters are the M12.26 ones: status, active-only, device, connection,
  source, destination, detector rule, correlation rule, risk range, confidence
  floor, and a time range that selects on **overlap** of the incident's extent.
- `POST /status` maps onto `CorrelationEngine.set_status(...)`, which validates
  against the M12.9 transition table and raises `InvalidIncidentTransition` for a
  terminal-state reopen → `409` naming the reachable states, `404` for an
  unknown id.
- **The three quantities appear as three fields.** A serialized incident carries
  `confidence` (correlation), `alert_confidence` (mean of the member alerts) and
  `risk_score` — never a combined number (M12.16). `CorrelatedIncident.as_dict()`
  and `.summary()` already emit exactly this split; the API reuses them rather
  than re-mapping the model by hand.
- **A findings-only incident is legal** (`alert_ids` is empty) and must serialize
  without inventing an alert or a severity.
- **Incidents are runtime state.** M12 stores them in a bounded, expiring
  registry, not in a table. The API must say so plainly — an incident that has
  expired is `404`, and the alerts it referenced are unaffected and still
  reachable through `/alerts`. The docs must not imply incident persistence.

---

# M13.10 — Detection Rules API

    GET  /detection-rules
    GET  /detection-rules/{rule_id}
    PUT  /detection-rules/{rule_id}
    POST /detection-rules/{rule_id}/enable
    POST /detection-rules/{rule_id}/disable

Reads come from the M2 `detection_rules` catalogue seeded in `app/database/seed.py`
(five rules, with the `high_bandwidth` vs `bandwidth_abuse` naming noted in the
M11/M12 verification scripts). Writes change the catalogue row and the enabled
flag only.

**The write endpoints must not silently do nothing.** A rule's thresholds are
read by the M10 detectors from `Settings` and from the detector's own
configuration, so an update that changes a database row the engine never reads
would be a lie. Either wire the update through to the running detector
configuration, or report that the change requires a restart — decided in M13.1
and documented. Do not ship a `PUT` that appears to succeed and has no effect.

---

# M13.11 — Analytics API

    GET /analytics/traffic
    GET /analytics/protocols
    GET /analytics/top-talkers
    GET /analytics/top-ports
    GET /analytics/threats
    GET /analytics/packets
    GET /analytics/connections

These read the same sources as the dashboard but over a requested time range,
with bounded results. `analytics/threats` aggregates the M11 alert and M12
incident stores by severity, risk band and detector — it computes no new
detection.

M16 owns the analytics *product* (the frontend charts and the deeper trends);
M13 owns the endpoints and the range validation.

---

# M13.12 — Settings API

    GET  /settings
    GET  /settings/{setting_key}
    PUT  /settings
    POST /settings/reset

Reads reflect `app/config/settings.py`. Writes are the delicate part and the same
rule as M13.10 applies: **a settings update that the running system does not
observe is not an update.** The M12 engine reads its window, thresholds, caps and
scoring bounds at construction, so a value changed at runtime must either be
picked up deliberately or reported as requiring a restart. Enumerate which
settings are live and which are restart-only, and document it.

Secrets and `.env` internals are never returned.

---

# M13.13 — System API

    GET /system/status
    GET /system/info

Status composes the existing diagnostics: capture state and counters (M4), the
pipeline's per-consumer error counters (M7–M12, including M12's
`get_correlation_error_count()` and `CorrelationEngine.stats()`), database
reachability, and version information. Info reports the application version,
Python version, database path and configured (non-secret) limits.

Neither endpoint mutates anything, and neither fabricates a "health score".

---

# M13.14 — Reports and Notifications APIs

    GET    /reports
    GET    /reports/{report_id}
    GET    /reports/{report_id}/download
    GET    /notifications
    POST   /notifications/{notification_id}/read
    POST   /notifications/read-all

The `reports` and `notifications` tables exist from M2. M13 exposes them
**read-first**: listings and single reads are in scope, and the read/report
mutations are limited to what the tables support.

`POST /reports/generate` and `DELETE /reports/{report_id}` invoke generation that
M17 has not built yet. They are **out of scope for M13** and must not be
registered as endpoints that return success without doing the work. Either they
are absent, or they return the documented "not implemented" shape — decided in
M13.1 and stated in the API docs.

---

# M13.15 — Baselines, ML and AI APIs

The spec (§17, §18, §19) documents baseline, ML and AI endpoints. **The base
application implements none of those subsystems** — baselines, ML anomaly
detection and AI analysis are explicitly excluded (roadmap §30, and M10–M12's own
non-goals).

M13 must therefore decide, once and explicitly: either these routes are not
registered at all, or they are registered and return a documented
"unavailable / not implemented" payload naming the milestone that will implement
them. What they must **not** do is return plausible-looking empty data that a
frontend would render as "no anomalies found" when the truth is "nothing looks
for anomalies yet".

---

# M13.16 — Pagination

One pagination shape for every listing (§6): total count, page, page size, and
the items. Rules:

- `limit` and `offset` are validated against each domain's own ceiling; a value
  above it is a `400`, not a silent clamp.
- Deterministic ordering everywhere, with a tie-break so a page is stable across
  identical requests.
- The count reported to the client is the count that matches the **same filters**
  as the listing — the M12.26 rule that a count must never disagree with its
  listing applies to every endpoint M13 adds.

---

# M13.17 — Validation

Validate, and reject clearly, at minimum:

| Domain | Bound |
| --- | --- |
| `protocol` | the normalized protocol vocabulary (M5) |
| `severity` | the four M11 levels |
| `status` (alert) | the M11 lifecycle vocabulary |
| `status` (incident) | the four M12 states |
| `risk_score` | `0..100` inclusive |
| `confidence` | `0..1` inclusive |
| `limit` | per-domain default and ceiling |
| `offset` | non-negative |
| time range | `since <= until`; an inverted range is a `400`, not an empty page |
| `order` | the documented orderings (`recent`, `oldest`, `risk`, `confidence`) |
| unknown filter value | `400`, never silently ignored |

An empty filter string is a filter error, not "no filter".

---

# M13.18 — Error handling

| Condition | Response |
| --- | --- |
| Unknown id | `404` |
| Malformed / unknown filter value | `400` naming the accepted values |
| Bound out of range (limit, risk, confidence) | `400` |
| Inverted time range | `400` |
| Illegal alert transition | `409` naming the reachable states; the stored alert is untouched |
| Illegal incident transition | `409` naming the reachable states; the stored incident is untouched |
| Duplicate capture start | `409` |
| Capture cannot start (permissions, Npcap, interface) | `503` or `409` with a message that names the cause |
| Unavailable subsystem (AI, ML, baselines, reports generate) | the documented "unavailable" shape with a reason |
| Unexpected internal failure | `500` with the envelope's error shape; the message never leaks a stack trace or a secret |

An error body always carries a machine-readable code and a human-readable
message. A `500` is never used where a `400` or `409` is the truth.

---

# M13.19 — Response schemas

Every endpoint returns a **declared Pydantic response model** — no ad-hoc
dictionaries, so the OpenAPI document is accurate and the frontend has one source
of types. Where a runtime model already has a serialization view
(`Alert`'s schema, `CorrelatedIncident.as_dict()` / `.summary()`), the schema
mirrors it rather than re-deriving it by hand.

Two fields must never be conflated in a schema: alert confidence and risk score.
Where both appear they appear under distinct, documented names.

---

# M13.20 — Router registration and OpenAPI

- Routers registered in a documented order, with static paths before parameterized
  ones (`/alerts/summary` before `/alerts/{alert_id}`, `/incidents/summary` before
  `/incidents/{incident_id}`) so a literal segment can never be parsed as an id.
  This pattern is already used in `app/api/v1/alerts.py`; extend it consistently.
- Tags, summaries and response descriptions set so `/docs` is a usable reference.
- The OpenAPI document is checked to contain no unresolved `$ref` and no route
  registered without a response model.

---

# M13.21 — Thread safety and read-only guarantees

- Every read endpoint is safe to call while capture, detection, alerting and
  correlation are running. Each underlying service already guarantees this
  (M6–M12); the API must not add shared mutable state of its own.
- The API holds no sessions. Repositories are constructed per-request through the
  existing session factory, exactly as M11 does — a SQLAlchemy session is not
  thread-safe and is never shared or cached.
- A read endpoint that returns a stored object copies or serializes it; it does
  not hand out a live mutable reference.
- No endpoint performs work that blocks capture.

---

# M13.22 — Tests — endpoint contracts

For every endpoint, test:

- the success shape (status code, envelope, field names, types),
- every filter, alone and combined,
- pagination bounds — the default, the ceiling, and one past the ceiling,
- ordering determinism — the same request twice returns the same sequence,
- unknown ids → `404`,
- invalid filters and out-of-range bounds → `400`,
- read endpoints do not mutate — assert state before and after.

---

# M13.23 — Tests — lifecycle endpoints

- Every valid alert transition through HTTP, and the invalid ones → `409`.
- Every valid incident transition, and a terminal-state reopen → `409`.
- A transition on an unknown id → `404`.
- The stored object is untouched after a rejected transition — asserted, not
  assumed.

---

# M13.24 — Tests — unavailable subsystems

- The AI, ML, baseline and report-generate surfaces (whichever form M13.1 chose)
  return the documented shape, and the shape distinguishes
  "unavailable / not implemented" from "nothing found".

---

# M13.25 — Tests — concurrency

- Concurrent reads against a live pipeline (capture running, events flowing)
  return consistent pages.
- A read concurrent with a write (a lifecycle transition, a capture start) never
  observes a half-updated object.
- No endpoint raises under concurrent access.

---

# M13.26 — Integration tests

Verify the whole chain over HTTP:

    capture → packets → statistics → devices → connections
                                               ↓
                                    detection → alerts
                                               ↓
                                    correlation → incidents
                                               ↓
                                       risk score

with controlled M10/M11/M12 outputs, confirming that the alert endpoints and the
incident endpoints both reference the same underlying alerts, and that the risk
score visible on `GET /alerts/{id}` is the same value the incident carries.

---

# M13.27 — Manual verification

`scripts/verify_m13.py`, two modes:

- **sample** (default) — build controlled findings through the real M10/M11/M12
  layers against an isolated temporary SQLite database, then exercise every
  endpoint through `TestClient` (or a live ASGI server) and print the request,
  the status code and the response. No admin rights and no Npcap needed.
- **live** — start the real application against real capture for a few seconds
  and exercise the read endpoints against live traffic. Authorized/local traffic
  only.

Must verify, at minimum:

- two related alerts → one incident visible over HTTP, with both alerts still
  listed separately by `/alerts`;
- correlation confidence, alert confidence and risk score appear as **three**
  fields on the incident;
- an unrelated pair stays two incidents;
- every filter on `/incidents` returns what it claims;
- an illegal transition is rejected with `409` and the stored object is unchanged;
- every unavailable subsystem says so;
- every invalid filter yields `400`, not an empty list.

---

# M13.28 — Performance baseline

`scripts/benchmark_m13.py` measures the API layer in isolation, against a
populated database and a populated incident store:

    Request latency per endpoint (median and p95, single client)
    Serialization cost per response (list vs detail)
    Listing latency at the default page size and at the ceiling
    OpenAPI schema generation time
    Throughput under a small number of concurrent readers
    Error-path latency (a 400 and a 404)

Measurements are single-machine and in-process. **Do not claim production
capacity, and do not claim a concurrency level the benchmark did not run.**

---

# M13 Completion Criteria

M13 is complete when:

- The API surface in `docs/04_API_Specification.md` is implemented, or the
  divergence is explicitly documented and the spec corrected.
- Every existing router has been reviewed against the spec and the gaps closed.
- One envelope, one error shape and one pagination shape are used consistently.
- The dashboard, analytics, settings and system surfaces exist and read real data.
- The **incident surface exists** and exposes M12's correlated incidents, their
  reasons and their scores.
- Alert confidence, correlation confidence and risk score remain three separate
  fields on the wire.
- The alert and incident lifecycle endpoints are implemented and validate
  transitions through the existing state tables.
- Unavailable subsystems (AI, ML, baselines, report generation) return a
  documented "unavailable" shape rather than fabricated data.
- Every endpoint declares a response schema, and OpenAPI resolves cleanly.
- Pagination and validation are consistent and reject rather than clamp.
- Reads never mutate, and no endpoint blocks capture.
- Unit/contract tests pass.
- Lifecycle and concurrency tests pass.
- Integration tests pass.
- Manual verification succeeds in sample mode, and in live mode where hardware
  permits.
- Performance baseline is recorded.
- No new detectors, alert types, correlation rules, ML/AI, WebSockets, frontend
  or automatic response functionality is introduced.

---

# Current Immediate Task

**M13.1 — Review the existing API surface and define the consistency baseline.**

Before writing any endpoint:

1. Read `docs/04_API_Specification.md` §5 (response format), §6 (pagination),
   §7 (filtering), §13 (alerts), §29–§31 (status codes, errors, validation).
2. Inventory the eight existing routers: routes, parameters, bounds, and where
   each returns `400` versus `404`.
3. Inventory `app/schemas/` and identify endpoints returning ad-hoc dictionaries.
4. Confirm how routers are registered in `app/api/__init__.py` and the ordering
   rule for static-versus-parameterized paths.
5. Decide, and write down, the treatment of every unavailable subsystem (AI, ML,
   baselines, report generation) — absent route, or documented "unavailable".
6. Decide, and write down, which detection-rule and settings writes are live and
   which require a restart — and make the endpoint say which.
7. Decide the incident API's exact route set and confirm every filter maps onto
   an `IncidentQuery` field that already exists.
8. Define the response schema for a correlated incident, keeping the three
   quantities separate.
9. Only then begin implementing routers, one domain at a time, with its tests.

---

# Architecture Boundary

M10 produces:

    Detection Findings

M11 produces:

    Alerts
       └── Alert Evidence

M12 produces:

    Correlated Incidents
       ├── Related Alerts
       ├── Related Findings
       ├── Correlation Reasons
       ├── Correlation Confidence
       └── Risk Score

M13 exposes all of the above over HTTP, and produces **no new security
conclusions of its own**.

Future milestones will consume this API for:

    WebSockets (M14)
    Frontend (M15)
    Analytics (M16)
    Reports (M17)

M13 itself must not implement those systems.
