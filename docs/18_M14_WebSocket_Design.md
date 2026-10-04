# NetWatch AI — M14 WebSocket Design

**Milestone:** M14 — WebSockets
**Scope:** real-time transport of events the existing services already produce.
**Status:** design (M14.1).

---

# 1. Purpose

M13 exposes what earlier milestones compute, request by request. M14 exposes the
*same* facts as they happen.

    Backend services (M4–M12)
         ↓
    EventPublisher  (transport-agnostic, thread-safe)
         ↓
    WebSocketManager (async, owns connection lifecycle)
         ↓
    /ws/dashboard  /ws/packets  /ws/alerts  /ws/system
         ↓
    M15 React frontend

M14 adds **no** detection, alert, correlation, risk-scoring, ML or AI logic. It
transports what M10–M12 already decided, and it never becomes the source of
truth: every event it carries describes something that is *also* persisted or
held by the service that produced it (M14.1).

---

# 2. What M14 does not implement

Per the M14 development rule: no new detection rules, no new alert logic, no new
correlation logic, no risk scoring, no ML, no AI, no frontend code, no external
SIEM integration, no automatic blocking, no advanced notification integration.
No authentication or RBAC either (M14.22) — the application remains a
local-development application, and that assumption is documented in §14.

M9's connection tracker produces conversations, but the milestone text names four
channels and does not name a connection channel; connection changes are therefore
not streamed. A client reads them from `GET /api/v1/connections` after a
reconnect (M14.19). This is recorded as a deliberate omission rather than an
oversight.

---

# 3. M14.1 review of the existing architecture

## 3.1 Where each event comes from

| Event source | Owner | Available signal |
| --- | --- | --- |
| packets | `app.services.packet_pipeline.PacketPipeline` | one `NormalizedPacket` per processed packet |
| dashboard | M6 statistics, M8 registry, M9 tracker, M11 queries, M12 registry | counts and rates, read at one instant |
| alerts | `app.alerts.engine.AlertEngine` (`process_findings`) and `AlertService.set_status` | created / folded alert, or a lifecycle move |
| incidents | `app.correlation.engine.CorrelationEngine.correlate_alerts` and `.set_status` | created / joined incident, or a lifecycle move |
| system | `CaptureManager.start/stop`, persistence, connection sweeper, database probe | capture state changes and service state |

## 3.2 What already exists to serialize with

M14 does not invent wire models where one is already defined:

| Payload | Existing projection reused |
| --- | --- |
| packet | `NormalizedPacket` (M5), projected by §5.1 — no payload field exists to leak (M7.5) |
| alert | `app.schemas.alert.AlertView.from_alert` (M11.18) |
| incident | `CorrelatedIncident.summary()` (M12.26) |
| dashboard | the same service reads as `app/api/v1/dashboard.py` uses |
| timestamp | ISO-8601 UTC, as every M13 endpoint renders it (M13.26) |

Reusing the M13 projections is what keeps the REST payload and the WebSocket
payload of the same entity from drifting: an `alert.created` event carries the
`schema_version` 1 alert view, not a second opinion about what an alert is.

## 3.3 The one thing that does not exist yet

There is no event bus, no connection registry and no thread→loop handoff. Those
are what this milestone adds; §4 through §13 specify them.

---

# 4. Package layout

    backend/app/websockets/
        __init__.py      singletons: get_event_publisher(), get_websocket_manager(),
                         reset_websockets(), shutdown_websockets()
        channels.py      Channel enum, channel descriptions, path ↔ channel mapping
        event.py         WebSocketEvent envelope + one event type per signal
        connection.py    ClientConnection: one subscriber and its bounded queue
        policy.py        per-channel queue size, rate limit and drop policy
        manager.py       WebSocketManager: lifecycle, registry, broadcast, backpressure
        publisher.py     EventPublisher protocol + WebSocketEventPublisher + NullEventPublisher
        routes.py        /ws/dashboard, /ws/packets, /ws/alerts, /ws/system
        heartbeat.py     the ping/pong keepalive task

Files stay under the project's ~150-line working ceiling by keeping each one
about one idea: the envelope, one subscriber, one policy table, one manager.

---

# 5. The event envelope (M14.7)

Every message on every channel is one JSON object with the same six fields:

```json
{
  "schema_version": 1,
  "event_id": "evt-9f2c1a...",
  "type": "packet.observed",
  "channel": "packets",
  "timestamp": "2026-04-10T11:17:03.412000+00:00",
  "source": "pipeline.packets",
  "sequence": 1481,
  "data": { }
}
```

| Field | Meaning |
| --- | --- |
| `schema_version` | Fixed integer, currently `1`. Bumped only by a breaking change, so a client can refuse a shape it does not know. |
| `event_id` | Opaque, unique per event (`evt-` + uuid4 hex). Lets a client dedupe a retry. |
| `type` | Dotted event name from a closed set (§6). A client branches on this. |
| `channel` | The channel the event belongs to. Redundant with the endpoint by design: a client that multiplexes channels later can still route. |
| `timestamp` | ISO-8601 UTC, always with an offset. Microsecond precision, as the alert and incident views already emit. |
| `source` | Which service produced it (`pipeline.packets`, `alerts.engine`, `correlation.engine`, `capture.manager`, `dashboard`). |
| `sequence` | Process-wide monotonic counter, so a client can see a gap and know events were dropped rather than transmitted. |
| `data` | Channel-specific payload (§6). |

`WebSocketEvent` is a Pydantic model, so a malformed event cannot be constructed
and cannot be sent. Serialization is `model_dump_json()`, which produces the
stable field order above and no raw Python objects (M14.17).

**Size limit (M14.22).** The encoded message is measured before it is queued. An
event longer than `websocket_max_event_bytes` (default 16 KiB) is refused, counted
as `rejected_oversized` and never sent. The cap exists because a socket write of
an unbounded message is a denial-of-service against the client and the server
alike; the payloads §6 defines are all well under it (a packet view is ~300
bytes, an alert view under 1 KiB).

## 5.1 Packet payload (M14.8)

Exactly the fields M14.8 lists, plus the capture interface the packet arrived on,
and nothing else. There is deliberately **no** payload, no raw bytes and no
`metadata` pass-through:

| Field | Source |
| --- | --- |
| `packet_id` | `NormalizedPacket.packet_id` |
| `timestamp` | `NormalizedPacket.timestamp` rendered as ISO-8601 UTC |
| `interface` | `NormalizedPacket.interface` |
| `source_ip`, `destination_ip` | `NormalizedPacket` |
| `protocol` | `NormalizedPacket.protocol` |
| `source_port`, `destination_port` | `NormalizedPacket` |
| `length` | `NormalizedPacket.length` |
| `packet_type` | `NormalizedPacket.packet_type` |

No unbounded packet history is sent: one event describes one packet, as it is
processed (M14.8).

## 5.2 Dashboard payload (M14.9)

`dashboard.updated`, emitted at most once per
`websocket_dashboard_interval_seconds` (default 1.0 s), carrying exactly the six
numbers M14.9 names:

| Field | Owner |
| --- | --- |
| `packet_count` | `CaptureManager` |
| `packets_per_second`, `bytes_per_second` | M6 `TrafficSnapshot` |
| `device_count` | M8 registry |
| `active_connections` | M9 tracker |
| `open_alerts` | M11 query aggregation |
| `active_incidents` | M12 engine |
| `capture_running`, `interface` | `CaptureManager` |

This is a *bounded incremental update*, not the dashboard summary: it carries
counters and rates, never the per-section documents
`GET /api/v1/dashboard/summary` returns, and never the recent-findings list. The
interval is what makes it a rate rather than a flood; the value is recomputed per
tick from the owning services, so the number a client sees is the number the REST
endpoint would report (M14.9).

## 5.3 Alert payload (M14.10)

Events: `alert.created`, `alert.updated`, `alert.acknowledged`, `alert.resolved`,
`alert.dismissed`, `alert.false_positive`. The lifecycle names are M11's own
vocabulary (`AlertStatus`), so a client maps an event type to a state without a
translation table of M14's invention.

`data` is `AlertView.from_alert(alert).model_dump(mode="json")` — the same
projection `GET /api/v1/alerts/{id}` returns.

`alert.updated` is emitted when a repeated observation folds into an existing
alert (M11 deduplication): the alert is not new, but its evidence count moved, and
a dashboard showing it must know.

## 5.4 Incident payload (M14.12)

Events: `incident.created`, `incident.updated`, `incident.status_changed`,
carried on the **alerts** channel with a documented event type. M14.12 allows
"the alert/system channel or another explicitly documented event type"; using the
alerts channel keeps the number of endpoints at the four the milestone requires
while keeping the event type distinct, so a client that only wants alerts can
ignore incident types by name.

`data` is `CorrelatedIncident.summary()` — the compact M12.26 listing view,
including `risk_score` and `risk_band`, which are read from the incident and never
recomputed here (M14.12: "do not create a new incident subsystem").

`incident.created` fires when `CorrelationOutcome.created` is true and
`incident.updated` when `joined` is true; a `set_status` move publishes
`incident.status_changed`.

## 5.5 System payload (M14.11)

Events: `capture.started`, `capture.stopped`, `capture.error`,
`database.status`, `service.status`, and the keepalive pair `ping` / `pong`
(§9). Each carries the state the owning service reported and nothing else:

| Event | `data` |
| --- | --- |
| `capture.started` | `status`, `interface`, `packet_count` from the `CaptureStatusData` the manager returned |
| `capture.stopped` | the same, after the flush |
| `capture.error` | `status` + a fixed reason string, never an exception trace (M14.22) |
| `service.status` | `service`, `state`, `packets_per_second` for a service the pipeline reports on |
| `database.status` | `dialect`, `reachable` — the two facts `GET /api/v1/system/health` already derives |

No system metric is invented: every field is read from the service that owns it
(M14.11).

---

# 6. The event vocabulary

| Type | Channel | Published when |
| --- | --- | --- |
| `packet.observed` | packets | one packet finished the pipeline |
| `dashboard.updated` | dashboard | the dashboard tick fired |
| `alert.created` | alerts | a finding produced a new alert |
| `alert.updated` | alerts | a finding folded into an existing alert |
| `alert.acknowledged` | alerts | an `open → acknowledged` move succeeded |
| `alert.resolved` | alerts | a move into `resolved` succeeded |
| `alert.dismissed` | alerts | a move into `dismissed` succeeded |
| `alert.false_positive` | alerts | a move into `false_positive` succeeded |
| `incident.created` | alerts | correlation opened an incident |
| `incident.updated` | alerts | an event joined an incident |
| `incident.status_changed` | alerts | an incident lifecycle move succeeded |
| `capture.started` | system | capture started |
| `capture.stopped` | system | capture stopped |
| `capture.error` | system | a start or stop failed, or the worker died |
| `database.status` | system | a health probe ran |
| `service.status` | system | a service state changed |
| `ping` | any | the server's keepalive tick, or a client's ping (§9) |
| `pong` | any | the answer to a ping |
| `error` | any | the server refused a client message (§9) |

Types are constants in `channels.py`/`event.py`; nothing is built by string
concatenation at a publish site.

## 6.1 What is broadcast immediately, and what is not

Broadcast immediately (they are already rate-limited by the work that produces
them):

* `alert.*` — an alert is raised at most once per deduplication window per rule
  and source, so its event rate is bounded by the alert rate M11 already bounds.
* `incident.*` — bounded by the alert rate above.
* `capture.*`, `service.status`, `database.status` — state changes, not repeats.

Rate-limited:

* `packet.observed` — the capture path can produce tens of thousands of packets a
  second and a browser cannot consume that. §8 bounds it.

Sampled:

* `dashboard.updated` — a tick, not a change notification, because a dashboard
  wants a steady refresh rather than one event per counter movement.

---
# 7. Channel separation (M14.6)

Four endpoints, four channels, one manager:

| Path | Channel | Purpose |
| --- | --- | --- |
| `/ws/dashboard` | `dashboard` | live dashboard counters and rates |
| `/ws/packets` | `packets` | live normalized packet events |
| `/ws/alerts` | `alerts` | new/updated alerts and incident changes |
| `/ws/system` | `system` | application and capture state changes |

A channel is a property of the **connection**, fixed at connect time by the path
the client dialled. The manager keeps one registry per channel and a broadcast
walks only that channel's registry, so a client subscribed to `/ws/packets`
cannot receive an alert: separation is structural, not a filter applied later
that a bug could forget (M14.6).

`subscribe()` / `unsubscribe()` exist on the manager as the registry operations
`connect()` and `disconnect()` are built from, and as the seam the tests drive.
M14 prefers server-push-only, so there is no client message that changes a
connection's channel: a client that wants two channels opens two connections,
which keeps the policy (queue size, rate limit) unambiguous per socket.

---

# 8. Backpressure, rate control and bounded buffering (M14.15, M14.16)

## 8.1 One bounded queue per connection

Each connection owns an `asyncio.Queue` with a fixed `maxsize`, and a dedicated
sender task drains it with `await websocket.send_text(...)`. The publisher never
awaits a socket write; it only ever offers an item to a queue, so a slow — or
deliberately stalled — client cannot slow the capture path (M14.14/MM14.15). The
queue cannot grow without limit, because `maxsize` is fixed at connect time and
never raised.

## 8.2 The drop policy

| Channel | Queue size | Rate limit | On a full queue |
| --- | --- | --- | --- |
| `packets` | `packet_ws_queue_size` (256) | `packet_ws_max_events_per_second` (200/s, shared per channel) | drop the **oldest** queued event, enqueue the newest, count it |
| `dashboard` | `websocket_dashboard_queue_size` (32) | none (the tick interval is the rate) | drop the oldest |
| `alerts` | `websocket_alert_queue_size` (512) | none | drop the oldest |
| `system` | `websocket_system_queue_size` (128) | none | drop the oldest |

Dropping the *oldest* is the deliberate choice on every channel: the newest
observation is the one a live view needs, and a stale packet from two seconds ago
is worth less than the one that just arrived. A `DROP_OLDEST` policy is also
idempotent under a flood — the queue settles at its cap and the application keeps
running, which is exactly what M14.15 asks for ("bounded memory behaviour").

**Why alerts are not treated exactly like packet telemetry (M14.15).** They are
not: an alert subscriber gets a 512-slot queue while a dashboard subscriber gets
32, a packet event is rate-limited and an alert event is not, and no alert event
is ever discarded for want of a rate budget. What the two *do* share is that
neither may block the producer. The distinction that matters is that a dropped
alert event is not a lost alert: the alert is in SQLite and is served by
`GET /api/v1/alerts`, which is the record of it. The socket is a live view of that
record, and the design says so rather than pretending a socket can be a queue of
record.

Drops are not silent. Every connection counts `dropped_queue_full` and
`dropped_rate_limited`, the manager aggregates them per channel, and the counters
are exposed through `get_stats()`; the number is visible in the verification and
benchmark output.

## 8.3 Rate control (M14.16)

`packet_ws_enabled` is the master switch. When it is false the packet channel
still accepts connections and still answers pings, but no packet event is ever
produced or queued, so the cost of packet streaming is zero rather than merely
small.

`packet_ws_max_events_per_second` is a token bucket on the **channel**, not on the
connection: the packet rate a client sees is bounded independently of how many
clients are connected, so ten subscribers cannot multiply the pipeline's
publishing work by ten. Tokens refill continuously and the bucket is sized to one
second of allowance, so a quiet period lets a short burst through and a sustained
flood settles at the configured rate. The bucket is only ever touched on the event
loop (§10), so it needs no lock.

---

# 9. Connection lifecycle, client input and keepalive

## 9.1 Lifecycle (M14.4)

    CONNECTING ──► CONNECTED ──► CLOSING ──► CLOSED
         │              │            │
         └──────────────┴────────────┴──► CLOSED   (any failure)

| State | Entered when |
| --- | --- |
| `CONNECTING` | the route accepted the socket and before it is registered |
| `CONNECTED` | the client is in the registry and its sender task is running |
| `CLOSING` | a disconnect started, by the server or by the client |
| `CLOSED` | the socket is released; terminal, and reachable from every state |

The `ClientConnection` record holds the state, the channel, `connected_at`, the
queue and the counters. Each exit path is handled explicitly:

| Case | Behaviour |
| --- | --- |
| Normal disconnect (client closes) | `WebSocketDisconnect` ends the route, `disconnect()` runs its cleanup once |
| Client disappears without a close frame | the send failure or the receive failure is caught, and cleanup runs the same way |
| Server shutdown | §12 closes every client with code 1001, then cancels every task |
| Invalid connection | a connection refused by the cap or with an unknown channel is closed with code 1008 before registration |
| Send failure | the client is removed from the registry and its task ends; other clients are untouched (M14.14) |
| Unexpected exception | contained by the route, the client is removed, the API and the pipeline continue (M14.29/M14.30) |

`disconnect()` is idempotent: a repeated call for a client that is already gone is
a no-op that returns `False`, which is what makes cleanup-from-two-paths safe
(M14.18: "repeated disconnect calls should be safe").

## 9.2 Connection registry (M14.5)

The registry holds, per active connection: connection id, channel, state,
connected time and the live counters. It holds nothing else — no client IP, no
headers, no cookies, no message history — because M14.5 asks for a registry of
connections, not of clients, and there is nothing in M14 that would use the
extra. The registry is bounded: `websocket_max_connections` caps the process and
`websocket_max_connections_per_channel` caps each channel, so a connection flood
is refused with a close rather than accepted until memory runs out.

## 9.3 Client input policy (M14.23)

Server-push-only, with exactly two accepted client messages:

| Message | Answer |
| --- | --- |
| `{"type": "ping"}` | `{"type": "pong", ...}` |
| `{"type": "pong"}` | nothing; it clears the keepalive's outstanding-ping mark |

Anything else — malformed JSON, a missing type, an unknown type, an oversized
message (over `websocket_max_client_message_bytes`) — is answered with an `error`
event naming the reason and counted. No client message reaches a backend service,
so there is no path from a socket to a command (M14.22/M14.23). A client that
floods garbage is disconnected after `websocket_max_invalid_messages`
violations, because the alternative is a server spending its budget parsing
them.

## 9.4 Keepalive (M14.24)

The server sends `{"type": "ping"}` on every channel every
`websocket_heartbeat_interval_seconds` (default 20 s) and expects the client's
`pong` — or its own `ping` — before the next tick. One outstanding ping is
tracked per connection; if a second tick arrives with the first still unanswered
the connection is treated as dead and removed. That bounds a half-open socket's
lifetime to roughly two intervals while keeping the heartbeat light: at 20 s, one
message per client per 20 seconds, not per second (M14.24: "avoid unnecessary
high-frequency heartbeats").

---

# 10. The worker-thread → async bridge (M14.21)

The capture pipeline runs on a Scapy worker thread; the alert and correlation
engines are called from that same thread; the API's lifecycle moves run on
FastAPI's thread pool. All three must be able to publish. The manager's socket
objects, queues and tasks, however, belong to one event loop and must only be
touched from it.

    worker thread / thread pool
          │  publisher.publish(event)          ← synchronous, thread-safe
          ▼
    EventPublisher
          │  manager.publish(event)            ← check loop + envelope, then hand over
          ▼
    loop.call_soon_threadsafe(manager._dispatch, event)
          │
          ▼
    event loop thread: _dispatch → rate limit → per-channel fan-out → queue.put_nowait
          │
          ▼
    sender task per connection: await websocket.send_text(...)

Rules that make this safe, and that the tests assert:

* **No socket object leaves the loop.** The only cross-thread call is
  `call_soon_threadsafe`, which is the documented way to schedule work onto a
  loop from another thread. `asyncio.Queue` is documented as *not* thread-safe,
  so every `put_nowait` happens inside `_dispatch`, on the loop.
* **The publishing thread never waits.** `call_soon_threadsafe` does not run the
  callback inline, so a busy loop cannot block capture and a slow client cannot
  block it either.
* **No loop, no crash.** Before startup, or after shutdown, the manager has no
  bound loop. `publish()` then counts the event as `dropped_no_loop` and returns
  `False`. This is what keeps the pipeline publishable in a unit test and what
  stops a shutdown race from raising into the capture thread (M14.14).
* **Counters are the only shared mutable state across threads,** and each is
  updated under a small lock so `get_stats()` from the API thread reads a
  consistent snapshot.

The dashboard tick and the heartbeat are the only timers. Both are
`asyncio` tasks created at startup and cancelled at shutdown, so no non-daemon
thread is added and nothing outlives the application (M14.20).

---

# 11. The publisher (M14.13)

```python
class EventPublisher(Protocol):
    def publish(self, event: WebSocketEvent) -> bool: ...
```

* `WebSocketEventPublisher` — the real one; it holds a reference to the manager
  and forwards. It knows nothing about sockets, queues or loops.
* `NullEventPublisher` — accepts everything and does nothing, returning `False`.
  Used by the tests and by any service constructed without a publisher.

The services take the publisher as an **optional injected collaborator**, exactly
as the persistence layer and the connection tracker are injected today:

* `PacketPipeline(..., events=publisher)` — publishes `packet.observed` after the
  M6/M7/M8/M9 consumers have seen the packet, plus alert and incident events from
  the outcomes the alert and correlation engines already return;
* `AlertService(..., events=publisher)` — publishes the lifecycle event after a
  transition commits, and the create/fold event from the outcome it returns;
* `CaptureManager(..., events=publisher)` — publishes `capture.*`;
* the dashboard tick — publishes `dashboard.updated`.

`None` means "no publisher", the pipeline is unchanged, and every one of the 1639
existing tests keeps passing without a socket in sight. That is the property that
makes this milestone additive: M14 taps a seam, it does not re-route the pipeline.

**Why the pipeline and not the API.** An alert raised by the capture path must be
streamed even if no API request ever asks for it, so publishing happens where the
event happens, not where it can be observed. The API routes change only in the
one place a lifecycle move is made, so a move made through
`POST /api/v1/alerts/{id}/acknowledge` is streamed by the same code path as one
made by any other caller of the service.

---

# 12. Startup and shutdown (M14.20)

Startup, from the application lifespan, before the app accepts traffic:

    bind the running loop to the manager
      ↓
    start the heartbeat task
      ↓
    start the dashboard tick (only if a dashboard subscriber exists — it self-idles)
      ↓
    ready for connections

Shutdown, after capture has been stopped and flushed, so the last events of the
session are still published:

    stop accepting new connections (the manager is marked closed)
      ↓
    broadcast a final `service.status` "shutting_down" on the system channel
      ↓
    close every connection with code 1001
      ↓
    cancel the sender, heartbeat and dashboard tasks and await their completion
      ↓
    clear the registry and unbind the loop

`shutdown()` is `async` and idempotent, and the lifespan `await`s it, so no task
outlives the application. If startup never ran — a test that builds the app
without its lifespan — shutdown is a no-op rather than an error.

---

# 13. Failure isolation (M14.14)

A WebSocket failure must never stop capture, processing, statistics, device
tracking, connection tracking, detection, alerting or correlation. Three
mechanisms enforce it:

1. **The publish call cannot raise.** `publish()` catches everything, counts it
   as `publish_errors` and returns `False`. The pipeline's calls are wrapped in
   its own try/except as well, in keeping with every other consumer, so even a
   bug in the manager's entry point cannot reach the capture thread.
2. **A broken client is removed, not propagated.** A send failure marks that one
   connection closed and cancels its own task. The broadcast loop skips a
   connection whose task is gone, and every other client keeps receiving.
3. **The counters make it visible.** `publish_errors`, `send_errors`,
   `dropped_*` and `closed_unexpectedly` are reported by `get_stats()`, so
   isolation cannot hide a fault that keeps happening.

M14.30 is the test for exactly this: force WebSocket failures and assert that
capture, statistics, detection, alerting and correlation all keep running and keep
their counters.

---

# 14. Security boundary (M14.22)

M14 adds **no** authentication and **no** RBAC. NetWatch AI is a
local-development application: it binds to loopback by default, and the API it
sits beside (`/api/v1`) is unauthenticated by design (M13.30). The WebSocket
surface inherits that assumption, and it is stated here so nobody mistakes the
absence of auth for an oversight.

What M14 does enforce, unauthenticated or not:

| Rule | Why |
| --- | --- |
| Only two client message types are accepted (`ping`, `pong`) | no arbitrary server-side command through a socket (M14.23) |
| Client messages are size-capped | an unbounded frame is a denial of service |
| Repeated invalid messages disconnect the client | a garbage flood must not consume the server |
| Every queue is bounded, at every channel | backpressure, not memory exhaustion |
| Every event is size-capped | an oversized frame is a denial of service |
| No client-supplied topic names or filters | nothing a client sends can widen what it receives |
| No secrets in any payload | events are built from the same views the API serves, which withhold secrets (M13.21/M13.22) |
| Connection caps per process and per channel | a connection flood is refused, not absorbed |
| No stack traces, paths or database internals in `error` events | an error event names a reason, never a trace (M13.5/M13.30) |

---

# 15. Tests

| File | Covers |
| --- | --- |
| `tests/test_ws_event_schema.py` | M14.26 — envelope fields, required fields, ISO-8601 timestamps, unknown type refused, oversized event refused, JSON serialization, no payload in a packet event |
| `tests/test_ws_manager.py` | M14.25 — connect, register, disconnect, duplicate disconnect, connection count, multiple clients, multiple channels, shutdown cleanup |
| `tests/test_ws_broadcast.py` | M14.27 — one subscriber, many subscribers, channel isolation, failed client removal, other clients still served |
| `tests/test_ws_backpressure.py` | M14.28 — queue below/at/over the limit, drop-oldest behaviour, packet rate limiting, alert events not rate-limited, queue never exceeds its cap |
| `tests/test_ws_reconnect.py` | M14.29 — connect → disconnect → reconnect, no history replay, counters reset per connection |
| `tests/test_ws_pipeline_isolation.py` | M14.30 — a failing manager does not stop capture, statistics, detection, alerting or correlation |
| `tests/test_ws_endpoints.py` | M14.31 — real ASGI WebSocket communication on all four channels, ping/pong, client-input refusal, connection cap, channel isolation over the wire |
| `tests/test_ws_publisher.py` | M14.13 — the publisher contract, the null publisher, the no-loop path |

Every test that needs a socket uses Starlette's `TestClient.websocket_connect`,
which speaks ASGI WebSocket to the real application, so these are integration
tests of the real stack rather than of a mock transport.

---

# 16. Manual verification (M14.32)

`backend/scripts/verify_m14.py` has two modes, mirroring `verify_m13.py`:

* **`sample`** — drives controlled packets through the real M4→M12 pipeline over a
  throwaway SQLite file with a WebSocket client attached on every channel, then
  asserts that the packets the pipeline processed arrived as `packet.observed`
  events, that the dashboard tick reported the same counts the REST endpoint
  reports, that a controlled detection produced an alert event, that a controlled
  incident produced an incident event, and that the keepalive answers.
* **`live`** — starts the application under uvicorn on a loopback port and speaks
  real WebSocket over real HTTP to all four channels.

---

# 17. Performance baseline (M14.33)

`backend/scripts/benchmark_m14.py` measures, per channel:

* connection setup time;
* broadcast latency (publish → client received) and messages/second;
* packet event throughput with and without the packet channel connected;
* alert event latency;
* queue depth high-water mark and drop counts under an overrun;
* the pipeline's own packet rate with WebSocket publishing enabled versus the
  same run with it disabled, which is the only honest way to state M14's cost;
* process CPU and RSS across the run;
* simultaneous test clients.

The figures are recorded in `docs/TODO.md`, with the same caveat every previous
baseline carries: one process, one loopback socket, not a production-capacity
claim.

---

# 18. M14 completion checklist → where it is satisfied

| M14 requirement | Where |
| --- | --- |
| WebSocketManager exists (M14.2) | `websockets/manager.py` |
| Four endpoints (M14.3) | `websockets/routes.py`, mounted unversioned at `/ws/...` |
| Connection lifecycle (M14.4) | §9.1, `ClientConnection.state` |
| Connection registry (M14.5) | §9.2, `manager` registry |
| Channel separation (M14.6) | §7 |
| Event envelope (M14.7) | §5, `WebSocketEvent` |
| Packet events (M14.8) | §5.1 |
| Dashboard events (M14.9) | §5.2 |
| Alert events (M14.10) | §5.3 |
| System events (M14.11) | §5.5 |
| Incident events (M14.12) | §5.4 |
| Event publisher (M14.13) | §11 |
| Failure isolation (M14.14) | §13 |
| Backpressure (M14.15) | §8 |
| Packet rate control (M14.16) | §8.3 |
| Serialization (M14.17) | §5 |
| Client disconnect handling (M14.18) | §9.1 |
| Reconnection (M14.19) | §9.1 — a reconnect is a new connection; no replay |
| Startup/shutdown (M14.20) | §12 |
| Thread/async safety (M14.21) | §10 |
| Security boundary (M14.22) | §14 |
| Client input policy (M14.23) | §9.3 |
| Heartbeat (M14.24) | §9.4 |
| Tests (M14.25–M14.31) | §15 |
| Manual verification (M14.32) | §16 |
| Performance baseline (M14.33) | §17 |
