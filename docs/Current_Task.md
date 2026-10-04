# NetWatch AI — Current Task

**Current Phase:** Base Application Implementation
**Current Milestone:** M14 — WebSockets
**Status:** ✅ Complete — implemented, verified, tested and baselined

---

# Current Objective

Carry the state M3–M13 already produce to connected clients in real time.

M13 gave the frontend a REST surface it can *pull* from. M14 adds the push half:
a client subscribes to a channel and receives the events the backend produces as
they happen, without polling.

Four channels:

    /ws/dashboard    a periodic tick of the picture the dashboard shows
    /ws/packets      one event per packet the pipeline processes
    /ws/alerts       alert creation, folding and lifecycle moves
    /ws/system       capture, service and database state changes

M14 produces no new knowledge. It transports what M4–M12 already produce, reading
the same services the M13 routes read.

---

# M14 Architecture

    Producer (capture thread)
         ↓
    Service (M6 statistics / M8 devices / M9 connections /
             M10 detection / M11 alerting / M12 correlation)
         ↓
    publish_* helper          app/websockets/events.py
         ↓
    EventPublisher            app/websockets/publisher.py
         ↓
    call_soon_threadsafe      the worker-thread → loop bridge
         ↓
    WebSocketManager.broadcast
         ↓
    per-channel registry → per-connection bounded queue
         ↓
    sender task → the socket

Two rules hold the design together:

* **The loop owns the queue.** A producer thread never touches a connection's
  buffer. It hands the event to the loop, and everything after that hand-off is
  single-threaded, so no lock protects a queue.
* **M14 is not an API version.** The channels are mounted unversioned at `/ws/...`
  beside `/api/v1/...`. M13.3's versioning rule is about production HTTP routes;
  a WebSocket handshake is not a REST resource.

---

# M14 Development Rule

Do NOT implement:

- Frontend code
- New detection, alert, correlation or risk-scoring logic
- ML / AI
- Automatic blocking
- Authentication / RBAC
- External SIEM or notification integrations
- Message replay, history or backfill
- Client-driven subscriptions beyond holding a channel open

M14 transports existing functionality. It does not redesign earlier milestones.

---

# M14.1 — Review of the Existing Architecture

Review what already exists before adding anything:

- where each event comes from (which M6–M12 service holds the fact);
- what already exists to serialize with (the M13 Pydantic schemas);
- the one thing that does not exist — a serializable envelope and a sink for it.

Outcome: the M13 schemas are reused as payload sources where they fit, and one new
envelope type is introduced for the wire. Recorded in
`docs/18_M14_WebSocket_Design.md` §3.

---

# M14.2 — WebSocket Manager

One manager owns every connection:

- accept, admit, register, broadcast, send, disconnect, shutdown;
- a bounded registry per channel;
- one running loop, bound at startup;
- counters for accepted, closed, refused, dropped and delivered.

Shutdown is idempotent and safe when startup never ran. A publish after shutdown is
dropped and counted rather than raised.

---

# M14.3 — Endpoints

Four routes, mounted unversioned:

    /ws/dashboard
    /ws/packets
    /ws/alerts
    /ws/system

Admission enforces two caps: a process-wide maximum and a per-channel maximum. A
refusal closes with a policy-violation code and never registers the client.

---

# M14.4 — Connection Lifecycle

Every client has an explicit state, and every transition is one call:

    accept → admit → register → sender task starts
                                 ↓
    send / receive → (failure, close, keepalive timeout)
                                 ↓
    unregister → sender task cancelled → socket closed

A disconnect is idempotent: disconnecting an unknown or already-closed connection
returns false and changes nothing.

---

# M14.5 — Connection Registry

- one entry per channel, plus a process-wide view;
- stable connect order for diagnostics;
- bounded by the caps, so a flood cannot grow it without limit;
- snapshot reads, so a broadcast never holds a lock while writing.

---

# M14.6 — Channel Separation

One channel per data type. A packet event reaches the packet channel and no other;
an event type outside the vocabulary is refused at construction. Separation is
enforced by the manager's fan-out, not by the client, so a client cannot widen what
it receives.

---

# M14.7 — Event Envelope

One envelope for every event:

    {
      "type": "packet.observed",
      "channel": "packets",
      "source": "packet_pipeline",
      "timestamp": "2026-01-01T00:00:00.000000Z",
      "sequence": 412,
      "schema_version": 1,
      "data": { ... }
    }

- the type vocabulary is a closed set;
- timestamps are ISO-8601 UTC with an offset;
- the sequence is monotonic across the process;
- the envelope is frozen — a built event cannot be mutated before it is sent.

---

# M14.8 — Packet Events

One `packet.observed` per packet the pipeline processes, projected from the
normalized packet.

- no packet payload, raw bytes or metadata ever appears on the wire (M7.5's policy
  carried to the live stream);
- a missing port stays missing rather than becoming `0`;
- the capture interface is included so a client can attribute the flow.

---

# M14.9 — Dashboard Events

A tick on a configurable interval, carrying the same figures the dashboard route
serves. The tick reads the same services `/api/v1/dashboard/summary` reads; it does
not recompute anything, and the two agree by construction.

---

# M14.10 — Alert Events

`alert.created` for a new alert, `alert.updated` for a finding folded into an
existing one, and the lifecycle types (`alert.acknowledged`, `alert.resolved`,
`alert.dismissed`, `alert.false_positive`) for a controlled status move. The
lifecycle names are M11's status vocabulary, not a second one.

---

# M14.11 — System Events

Capture state changes (`capture.started`, `capture.stopped`, `capture.error`),
service state (`service.status`) and database reachability (`database.status`).

A capture error carries a fixed sentence supplied by the capture layer. The
exception's own text can name a device or a path and never reaches the wire.

---

# M14.12 — Incident Events

`incident.created` when correlation opens an incident, `incident.updated` when an
event joins an existing one, and `incident.status_changed` for a lifecycle move.

A duplicate event — one M12 already deduplicated — publishes nothing, because
nothing changed.

---

# M14.13 — Event Publisher

    publish_*  →  EventPublisher  →  WebSocketManager

Two implementations: the real publisher (which forwards to the manager) and a null
publisher whose calls return false without doing anything. `ensure_publisher` turns
`None` into the null publisher, so no call site tests for `None` and every existing
pipeline remains constructible without a socket.

---

# M14.14 — Failure Isolation

Publishing can never reach the capture thread:

- a projection that raises is logged and refused;
- a publisher that raises is logged and refused;
- a manager that raises does not raise through the publisher;
- an unbound loop, a disabled layer and a shut-down manager are all counted drops,
  not exceptions.

A failing WebSocket layer cannot stop capture, processing, statistics, device
tracking, connection tracking, detection, alerting or correlation.

---

# M14.15 — Backpressure

One bounded queue per connection:

- the depth comes from the channel policy (32 to 512);
- **drop-oldest** when full, so the newest event is the one that survives;
- the drop is counted per connection and visible;
- the queue never grows past its cap — asserted, not assumed.

A client that drains never fills its queue. A client that stalls is retired rather
than allowed to hold up its channel: one bad subscriber does not cost the others
their delivery.

---

# M14.16 — Packet Rate Control

The packet channel carries a token bucket (200 events/s by default) so a busy wire
cannot flood a subscriber. The other channels are unlimited.

- the bucket starts full, so a burst up to its capacity is allowed;
- it refills continuously rather than once a second;
- it never holds more than its capacity and never refills into the past;
- the ceiling is per channel, not per connection;
- a rate-limited event reaches no subscriber and is counted as a drop, not as a
  broadcast.

No other channel is rate-limited: alerts are security events and suppressing one
would be a correctness problem, not a tuning choice.

---

# M14.17 — Serialization

One encoding step per event, once, before it is queued:

- a compact JSON document, UTF-8, no pretty-printing;
- the size is measured and checked against a cap before the frame is queued;
- an event over the cap is refused and never reaches a connection;
- the same encoded frame is handed to every subscriber of the channel, so fan-out
  does not re-encode.

An event whose `data` cannot be expressed as JSON cannot be constructed at all,
which moves that class of mistake to build time rather than to the socket.

---

# M14.18 — Client Disconnect Handling

A dead client is removed, and only that client:

- a failed write retires the failing connection and leaves the others alone;
- the survivors keep receiving on that channel after the failure;
- the failure is counted and visible;
- a client that stalls is retired rather than allowed to hold up its channel.

The manager never blocks on a slow socket, and no broadcast can fail because one
subscriber did.

---

# M14.19 — Reconnection

A reconnect is a **new** connection:

- a new id, fresh counters, the channel's own queue depth;
- nothing that was missed is replayed — there is no history and no backfill;
- the event sequence keeps climbing across the reconnect, because the sequence is a
  property of the process and not of the connection;
- a reconnect after shutdown is refused and counted like any other refusal, and a
  restarted manager admits clients again.

---

# M14.20 — Startup and Shutdown

The background tasks (keepalive, dashboard tick) start and stop with the
application lifespan. The manager binds its loop at startup, which is what makes a
publish from a worker thread a real cross-thread publish instead of a drop to
`dropped_no_loop`.

---

# M14.21 — Thread/Async Safety

Two threads can publish — the capture thread and request handlers — and one loop
owns the sockets.

- a publish from any thread goes through `call_soon_threadsafe` onto the manager's
  loop;
- the queue and the socket are touched only on that loop, so a queue needs no lock;
- the registry is read as a snapshot, so a broadcast holds no lock while writing;
- a publish from a worker thread never blocks.

---

# M14.22 — Security Boundary

M14 is a local, unauthenticated application surface by design.

- no secret, token, internal path or stack trace reaches the wire;
- a capture error's text is a fixed sentence, never the exception's own message;
- every client frame is bounded in size and validated before it is interpreted;
- the payload policy M7 established is carried to the live stream: packet metadata
  only, never payload bytes;
- the local-development assumption is documented.

---

# M14.23 — Client Input Policy

The channels are one-way by design. A client's frames are answered or refused:

- `ping` is answered with a matching `pong`;
- a `pong` is accepted and counted;
- an unknown type, a malformed document, a frame without a type and a binary frame
  are each refused with their own reason;
- an oversized message is refused before it is parsed;
- a flood of invalid messages disconnects the client.

A client can never widen what it receives by asking.

---

# M14.24 — Keepalive

The manager pings on a configurable interval and retires a client that never
answers within the timeout:

- a client that answers is kept;
- one that does not is retired and unregistered;
- a tick with no connections does nothing;
- the keepalive is quiet when its interval is set beyond the run's length, which is
  how the baseline isolates the transport.

---

# M14.25–M14.31 — Tests

Every test that needs a socket speaks ASGI WebSocket to the real application
through Starlette's `TestClient`, so these are integration tests of the real stack
rather than of a mock transport.

| File | Covers | Tests |
| --- | --- | --- |
| `tests/test_ws_manager.py` | M14.25 — connect, register, disconnect, duplicate disconnect, count, admission caps, startup/shutdown, heartbeat | 48 |
| `tests/test_ws_event_schema.py` | M14.26 — envelope fields, the type vocabulary, ISO-8601 timestamps, size cap, JSON serialization, no payload in a packet event | 67 |
| `tests/test_ws_broadcast.py` | M14.27 — one and many subscribers, channel isolation, failed-client removal, survivors still served | 19 |
| `tests/test_ws_backpressure.py` | M14.28 — queue below/at/over the cap, drop-oldest, the packet token bucket, alerts never rate-limited | 33 |
| `tests/test_ws_reconnect.py` | M14.29 — reconnect is a new connection, no replay, counters reset | 16 |
| `tests/test_ws_pipeline_isolation.py` | M14.30 — a failing manager does not stop capture, statistics, detection, alerting or correlation | 8 |
| `tests/test_ws_endpoints.py` | M14.31 — real ASGI WebSocket on all four channels, ping/pong, input refusal, the per-channel cap over the wire | 16 |
| `tests/test_ws_publisher.py` | M14.13 — the publisher contract, the null publisher, the no-loop path | 17 |

---

# M14.32 — Manual Verification

`backend/scripts/verify_m14.py`, two modes mirroring `verify_m13.py`:

- **`sample`** — drives controlled packets through the real M4→M12 pipeline over a
  throwaway SQLite file with a client attached to every channel, then asserts the
  packets the pipeline processed arrived as `packet.observed`, that the dashboard
  tick reports the same counts the REST endpoint reports, that a controlled
  detection produced an alert event, that a controlled incident produced an
  incident event, and that the keepalive answers.
- **`live`** — starts the application under uvicorn on a loopback port and speaks
  real WebSocket over real HTTP to all four channels.

---

# M14.33 — Performance Baseline

`backend/scripts/benchmark_m14.py` with `backend/scripts/m14_bench_harness.py`
measures, per channel:

- connection setup time;
- broadcast latency (publish → the client has it) and messages/second;
- packet event throughput with and without the packet channel connected;
- alert event latency;
- queue depth high-water mark and drop counts under an overrun;
- the pipeline's own packet rate with publishing enabled against the same run with
  it disabled;
- process CPU and RSS across the run;
- simultaneous test clients.

---

# M14 Completion Criteria

M14 is complete when:

- a WebSocket manager exists and owns every connection.
- The four channels are served and separated.
- The event envelope is one type with one vocabulary.
- Packet, dashboard, alert, incident and system events are produced from the real
  services, not from invented data.
- Publishing is failure-isolated from capture.
- Buffering is bounded and the drop policy is enforced and counted.
- The packet channel is rate-controlled and the security channels are not.
- Client input is answered or refused and can never widen what is sent.
- The keepalive retires a dead peer.
- Reconnection works without replay.
- Startup and shutdown are clean.
- Tests pass.
- Manual verification succeeds in both modes.
- The performance baseline is recorded.

---

# M14 Completion Record

M14 is complete: the WebSocket layer is implemented, verified, tested and
baselined.

**What shipped**

* `app/websockets/` — `manager` (accept, admit, register, broadcast, send,
  disconnect, shutdown), `connection` (`ClientConnection`), `channels`, `policy`
  (per-channel queue depth and token bucket), `event` (the envelope), `builders`
  and `payloads` (the five payload kinds), `events` (the `publish_*` helpers),
  `publisher` (the real and null publishers), `dashboard` (the tick),
  `heartbeat`, `messages` (client input) and `routes`.
* Four channels mounted unversioned — `/ws/dashboard`, `/ws/packets`, `/ws/alerts`,
  `/ws/system` — beside the `/api/v1` REST surface.
* The pipeline publishes `packet.observed` last of all, after every M6–M12
  consumer has seen the packet, so an event can never describe a packet whose
  state is still moving.

**Verification**

* Full suite: **1863 passed**; pyright **0 errors, 0 warnings, 0 informations**
  over **268 files**. The M14 suite is **224 tests** (48 manager, 67 event schema,
  33 backpressure, 19 broadcast, 17 publisher, 16 reconnect, 16 endpoints,
  8 pipeline isolation).
* `verify_m14.py` ran green in **both** modes — `sample` (the real M4→M12 pipeline
  with a client on every channel) and `live` (uvicorn on a loopback port answering
  real WebSocket over real HTTP).
* `benchmark_m14.py` produced the M14.33 baseline; the figures are recorded in
  `docs/TODO.md`.

**The measured cost**

The packet ladder is the figure worth quoting, because it is a measured difference
rather than an inference — the same 2,000-packet burst through the same M4–M12
stack at five publishing configurations:

| configuration | packets/s | µs/packet | overhead vs M14 absent |
| --- | --- | --- | --- |
| publish call replaced (M14 absent) | 2,947 | 339.27 | — |
| null publisher — event built, then discarded | 2,418 | 413.59 | +74.32 µs |
| publisher, layer disabled | 2,678 | 373.35 | +34.08 µs |
| publisher, enabled, no subscriber | 2,304 | 434.03 | +94.75 µs |
| publisher, enabled, one subscriber | 2,015 | 496.40 | +157.12 µs |

**Building** a `packet.observed` costs roughly **74 µs/packet**; **delivering** it
to one subscriber costs roughly **158 µs/packet** over having no layer at all. The
M4–M12 pipeline's own ~339 µs/packet dominates both.

Broadcast latency is 0.21–0.40 ms p50 depending on payload size (243–799 B). The
packet channel's 200/s ceiling is plainly visible in the throughput run — 397/s
delivered from 6,748/s offered — which is the throttle working, not a transport
limit. Under an overrun the queue reached its cap on every channel and never went
past it.

**One caveat to carry forward**

The smaller ladder steps are the same order as this disk's run-to-run variance: an
earlier run of the identical ladder measured a 1,564 packets/s baseline where the
recorded run measured 2,947, and one rung measured *cheaper* than the rung below it.
The ladder's trend is quotable; no single step is. If the packet path is
re-measured, run it more than once.

**Boundaries held**

No frontend code; no new detection, alert, correlation or risk-scoring logic; no
ML/AI; no automatic blocking; no authentication/RBAC; no external SIEM or
notification integration; no replay or backfill. M14 transports what M3–M13 already
produce and does not redesign them.

**Next**

M15 — Frontend Integration, consuming this surface from the React frontend:
the `/api/v1` REST routes for reads and the four `/ws/...` channels for live
updates.
