NetWatch AI — M15 Frontend Integration

**Milestone:** M15 — Frontend Integration
**Scope:** make the existing React/TypeScript frontend a real client of the M13 REST
API and the M14 WebSocket channels.
**Status:** implemented and verified (M15.39–M15.42).

---

# 1. Purpose

M13 exposes what M4–M12 compute, request by request. M14 exposes the same facts as
they happen. M15 removes the mock data the Figma Make interface was built on and
connects the interface to both.

    React pages
         ↓
    API service layer   (src/services/*)
         ↓
    FastAPI REST API    (M13, /api/v1)

    React hooks
         ↑
    WebSocket layer     (src/services/websocket.ts, src/hooks/useChannelEvents.ts)
         ↑
    FastAPI channels    (M14, /ws/dashboard /ws/packets /ws/alerts /ws/system)

M15 adds **no** backend intelligence. Every number, verdict, state and confidence
the interface shows is computed by the backend and rendered as given; where the
interface could have formed a second opinion — capture state, risk, rates, health
— it deliberately does not, and the page says so (M15.9/M15.24/M15.12).

---

# 2. What M15 built

    frontend/src/
      services/    23 modules — one per resource, plus the shared client
      types/        7 modules — the wire models, split by subject
      hooks/       28 modules — data access and channel subscriptions
      components/  shell components, async-state primitives, alert/incident parts
      pages/       twelve pages, one per route in App.tsx
    frontend/tests/live/
      live-setup.ts       the harness the live suites share
      inert-socket.ts     a socket that cannot connect, for DOM-environment runs
      rest.test.ts        the live REST suite (50 tests)
      websocket.test.ts   the live channel suite (6 tests, real sockets)
      pages.test.tsx      the live page suite (8 tests, real <App />)

Every page reads through `src/services`; no component calls `fetch` directly
(M15.4). Every page holds its state in a hook; components render (M15.33).

---

# 3. The API service layer and its error model

`src/services/client.ts` is the only module that performs an HTTP request. It owns
the base URL, the timeout, JSON parsing, and the project's response envelope
(`success` / `message` / `data` / `errors`), so no page parses an envelope and no
page repeats status handling (M15.5).

`src/services/errors.ts` turns every failure into one `ApiError` with a `kind` —
`network`, `timeout`, `client`, `server`, `unavailable` — and a `userMessage`
written for an operator. Backend detail is used when the backend supplied it (its
`message` and `errors[].code`) and never invented when it did not, and a stack
trace, a path or a query string never reaches the user (M15.7).

Two shapes the UI depends on are handled explicitly rather than generically:

* **Unavailable sections.** `GET /dashboard/summary` reports a section it could
  not read as `null` *with a reason* (M13.29). The dashboard renders "This section
  could not be read" beside that reason rather than a calm zero, because an
  unread store and an empty store are different facts.
* **`501 FEATURE_NOT_IMPLEMENTED`.** Reports and settings generation are not
  implemented (M17 owns them). The UI renders an unavailable state; it does not
  offer a download that cannot exist (M15.22).

---

# 4. TypeScript models, and a drift that was found and fixed

`src/types/` mirrors the wire field-for-field, split by subject: `traffic.ts`
(capture, packets, statistics), `network.ts` (devices, connections),
`security.ts` (detections, alerts, incidents), `analytics.ts`, `system.ts`,
`websocket.ts` (events), `api.ts` (envelope and errors). `any` is not used for
backend data.

The models were checked against the running API rather than against the schemas'
documentation, and that check found one real drift:

**`NetworkInterface` was wrong.** `src/types/traffic.ts` declared

    { name, is_up, addresses?, description? }

while `app/schemas/interface.py` returns

    { name, description, mac_address, ip_addresses, is_up }

Every entry carries all five keys; `description` and `mac_address` are `null` when
the OS does not report them (loopback has no MAC) and `ip_addresses` is always a
list. The old model named a key the backend has never sent and omitted one it
always sends, so a page reading `addresses` would have rendered an empty address
list forever while the type still checked cleanly. It now mirrors the wire
exactly. This is the failure mode M15.6 exists to prevent, and it was only visible
against real `GET /api/v1/capture/interfaces` output.
---

# 5. The WebSocket layer

`src/services/websocket.ts` is the whole transport: connect, parse the event
envelope, validate the event type, expose the connection phase, reconnect with
backoff, and deduplicate. `src/hooks/useChannelEvents.ts` binds one channel to one
component's handler and unsubscribes on unmount.

Four decisions in that layer are load-bearing:

* **One socket per channel, shared by subscribers.** `channelHub` holds at most one
  connection per channel and fans events out to its subscribers, so ten components
  on `/ws/alerts` are one socket, not ten. A channel's socket is closed when its
  last subscriber leaves — which is why navigating away from the dashboard
  releases `/ws/dashboard` rather than leaving it open behind the new page
  (M15.28/M15.35).
* **Reconnect is REST-then-stream.** After a drop the hook re-reads its REST
  resource and then resumes applying events, because the events that arrived
  during the outage are gone and the REST API is the source of current state
  (M15.27/M15.30). Historical events are never replayed.
* **Deduplication by `event_id`, per channel.** Each channel's socket keeps a
  bounded set of the event ids it has applied, so a redelivered frame is dropped
  instead of applied twice (M15.29). The set is bounded, so dedup cannot grow
  without limit.
* **Event sequences are treated as gappy.** `/ws/packets` is rate-limited on the
  server — 200 events per second for the channel as a whole (M14.16) — so the
  browser receives a *subset* of what was captured. Nothing in the frontend
  assumes consecutive packets, sequential ids, or a complete history, and a gap is
  never treated as a backend failure (M15.11).

The channels are used exactly as M15.28 requires: `/ws/dashboard` for the
dashboard, `/ws/packets` for Live Traffic, `/ws/alerts` for alerts *and* incidents
(the incident events arrive on the alerts channel, M15.18), `/ws/system` for
System. No page multiplexes two of them onto one socket.

---

# 6. Bounded client state

Every list that grows with time is bounded rather than unbounded:

| List | Bound | Where |
| --- | --- | --- |
| Live packets | 500 rows | `useLiveTraffic`, `useBoundedList` |
| Dashboard ticks | 60 points | `Dashboard.tsx` (`LIVE_TICK_CAPACITY`) |
| Live alert rows | 200 per kind (created / updated kept apart) | `useAlerts` (`LIVE_ALERT_CAPACITY`) |
| Dedup ids | per channel, bounded set | `websocket.ts` |

The packet bound was verified under sustained real traffic: with 77,441 packets
captured the page held exactly 500 rows and reported `500 shown · 500 retained ·
bounded at 500`. Memory is therefore a function of the configured capacity, not of
how long the page is open (M15.11/M15.36).

---

# 7. Loading, empty and error states

Every data-driven page renders the same four states through
`components/AsyncState.tsx`: loading, success, empty, error. The empty state names
the milestone that would fill it ("M8 records a device when it appears on a
captured packet"), and the error state offers a retry. No page shows a blank
screen when a request fails (M15.8).

One distinction is applied everywhere and is worth stating once: **unknown is not
zero.** An unread section, an unreported field and an absent value each render as
such — `UNKNOWN_TEXT` for a value the backend did not report, "no interface
selected" for a 400 that means a precondition is unmet, "This section could not be
read" plus the backend's reason for a section that failed. A calm `0` in any of
those places would be a false statement about the network.

---

# 8. Feature matrix (M15.41)

Verified in four places. `unit` = `src/**/*.test.tsx` under `vitest run` (15 files,
422 tests). `live REST` = `tests/live/rest.test.ts` against the running backend
(50 tests). `live WS` = `tests/live/websocket.test.ts` with real sockets (6
tests). `live page` = `tests/live/pages.test.tsx` rendering the real `<App />`
(8 tests). `browser` = the manual run recorded in §9.

| Page | REST | WebSocket | Verified by |
| --- | --- | --- | --- |
| Dashboard | `GET /dashboard/summary` | `/ws/dashboard` | unit, live REST, live page, browser |
| Live Traffic | `GET /statistics/traffic` | `/ws/packets` | unit, live WS, browser |
| Devices | `GET /devices` | — | unit, live REST, live page, browser |
| Connections | `GET /connections`, `/connections/active`, `/connections/{id}` | — | unit, live REST, browser |
| Detections | `GET /detections`, `/detections/{id}`, `/detections/rules` | — | unit, live REST, browser |
| Alerts | `GET /alerts`, `/alerts/{id}`, `/alerts/{id}/evidence` | `/ws/alerts` | unit, live REST, live page, browser |
| Alert lifecycle | `POST /alerts/{id}/{acknowledge,resolve,dismiss,false-positive}` | `/ws/alerts` | unit, live REST, browser |
| Incidents | `GET /incidents`, `/incidents/open`, `/incidents/{id}` | `/ws/alerts` | unit, live REST, browser |
| Incident lifecycle | `POST /incidents/{id}/{investigate,resolve,dismiss}` | `/ws/alerts` | unit, live REST |
| Analytics | `GET /analytics/{traffic,protocols,devices,connections,threats}` | — | unit, live REST, live page |
| Reports | `GET /reports`, `/reports/{id}` | — | unit, live REST, live page, browser (empty) |
| Settings | `GET /settings`, `/settings/{key}`, `PUT /settings` | — | unit, live REST, live page |
| System | `GET /system/status`, `/system/health`, `/system/info` | `/ws/system` | unit, live REST, live page, browser |
| Capture control | `GET /capture/status`, `/capture/interfaces`, `PUT /capture/interface`, `POST /capture/{start,stop}` | `/ws/system` | unit, live REST, browser (API-driven) |
| Notifications | `GET /notifications`, `/notifications/{id}` | — | unit, live REST, browser |

Features that are **not** available, and are rendered as unavailable rather than
faked, because their backend milestone has not been implemented:

| Feature | Backend answer | UI behaviour |
| --- | --- | --- |
| Report generation | `501 FEATURE_NOT_IMPLEMENTED` (M17 owns it) | unavailable state; no download offered |
| Notification delivery (email/push/webhook) | no such endpoint exists | stated on the page: nothing is delivered |
| Mark-as-read on notifications | no write endpoint exists | stated on the page: the counts are stored values and cannot be changed |
| Device risk score | M8 scores nothing | no risk column; the page says "activity state only" |
| Alert `risk_score` | not in the M13 alert payload | not shown on the alert pages; risk is shown on the incident, where M12 computes it |
| Search across devices/alerts | no search endpoint | the filter searches the loaded page and says so |

---
# 9. Manual end-to-end verification (M15.40)

The run, on one machine, on 2026-10-06 (22:22–22:29 local — the window the
capture's own packet timestamps show):

* backend — `uvicorn app.main:app` on `127.0.0.1:8000`, from `backend/.venv`
  (Python 3.13.2), environment `development`;
* frontend — `npm run dev` on `http://localhost:8443` (the port
  `frontend/vite.config.ts` serves on) with the endpoints from the Vite
  configuration;
* traffic — a capture started on the **Wi-Fi** adapter through the documented
  endpoints and stopped at the end of the run. It captured **77,441 packets** in
  roughly six and a half minutes (≈200 packets/s average) and the pipeline turned
  them into **2 devices, 238 connections, 3 alerts and 1 incident with peak risk
  54**. The packets stored for the same window number 78,988 rows, so two
  independent counters of one run agree to within a couple of percent.

Each of the ten M15.40 checks, and what was seen:

1. **Dashboard loads real backend data.** Capture `Running` on interface `Wi-Fi`,
   source `Live tick`, sections unavailable `None`; 4/s and 1.2 KB/s against
   65,761 captured; 2 active devices; 285 connections; **1 open alert of 2 stored**
   — the open count fell from 2 to 1 exactly when the alert was resolved through
   the API, without a page reload; 1 active incident, peak risk 54. The throughput
   chart plotted observed ticks only.
2. **Packet stream displays real normalized packets.** Rows such as
   `35.186.247.105:443 → 192.168.43.174:49262 TCP` and the reverse direction,
   with time, source, destination, protocol and both ports — and no payload
   column, because the backend does not send one (M7.5/M14.8).
3. **Devices display real observed devices.** `Aman` at `192.168.43.174` (+1),
   MAC `E8:BF:B8:DD:68:0A`; and an unnamed device headed by `104.18.2.115`,
   MAC `DA:2A:33:2A:B6:D8`. Both `Active`, and no risk column. (Both address
   counts grew as later capture sessions ran; §12 has the audited figures, and
   what that second record actually is.)
4. **Connections display real conversations.** The page reports its own listing
   mode (`GET /connections`), the tracker's counts, and states that M9 tracks
   without scoring; the API held 238 conversations.
5. **Alerts display real alerts.** Two `High Bandwidth` alerts, at 67% and 65%
   confidence, each with the observed rate in its description
   ("Possible traffic spike detected (1.34 MB/s observed)"), the severity tally,
   and the lifecycle tally — `Open 1 · Resolved 1` after the actions in §10.
6. **Incident data displays real correlation/risk information.** One open
   incident with **Risk**, **Correlation confidence** and **Alert confidence** as
   three separate columns, and the page stating that they are separate readings
   (M15.17).
7. **WebSocket events update the UI.** Counters rose throughout the run without a
   reload; a second alert appeared in the list while the capture ran; the
   system page showed `system channel live`; Live Traffic's footer showed
   `● Streaming` with packets arriving.
8. **Disconnect/reconnect works.** The behaviour is asserted by the unit suite
   (the hub driven with an injectable socket factory and fake timers) and by the
   live socket suite against the real channels. No real drop was staged in the
   browser run, so no wall-clock reconnect figure is claimed (§11).
9. **REST data refresh works.** Every page's Refresh control re-reads its
   resource; the live page suite asserts the REST-then-render path.
10. **No mock data remains active.** The empty states seen before the capture
    were empty because the registry was empty, and they filled the moment real
    traffic arrived — which is the opposite of what a mock would do. No page
    fabricated a value at any point in the run.

Two console messages appeared and neither is a defect. `400` on
`GET /api/v1/capture/interface` is the documented `NO_INTERFACE_SELECTED`
precondition (M13.6), and the page renders "None selected" for it. The
`WebSocket is closed before the connection is established` warnings come from
`React.StrictMode` mounting effects twice in development (§12).

---

# 10. Defects the manual run found — and their fixes

All three were invisible to the test suites, which is the point of running the
application.

**1. The browser could not talk to the backend at all (CORS).** The backend
allowlisted `http://localhost:5173` and `http://127.0.0.1:5173`, while
`frontend/vite.config.ts` serves on `8443`. Every request from the real UI was
refused before the application could read a response — the suites never saw it
because a Node test runner sends no `Origin`. Fixed by making the allowlist
configuration (`settings.cors_allow_origins`) and listing the ports this project
actually serves on, `localhost` and `127.0.0.1` being separate origins. Verified
with an `OPTIONS` preflight and a `GET` carrying `Origin: http://localhost:8443`,
both answered with `access-control-allow-origin: http://localhost:8443`.

**2. Missing favicon, and the template's title.** `.figma/make/site.json` declared
no icon and no title, so every load produced a `404` for `/favicon.ico`, and the
document title fell back to the Vite plugin's default, `Figma Make App`. Fixed by
adding `frontend/public/favicon.svg` — the interface's own brand mark, the
`#38BDF8 → #0EA5E9` tile with the dark shield the rail shows — and a `title` plus
`icons` entry in the site configuration. Verified: `<title>NetWatch AI</title>`,
`<link rel="icon" href="/favicon.svg">`, the icon served as
`200 image/svg+xml`, and no `404` in the console afterwards.

**3. `NetworkInterface` did not mirror the wire** — see §4.

---
# 11. Performance baseline (M15.42)

Measured on this machine, one operator, development configuration. These are the
figures taken during the runs recorded in §9; everything not measured is listed
below the table as not measured, rather than estimated.

| Metric | Measured | How |
| --- | --- | --- |
| Initial document (dev server) | 7.0 ms, 1,116 bytes | HTTP `GET /` from `127.0.0.1:8443` |
| Dashboard summary (REST) | 11.8 ms average (8.6–16.4 ms over 5 calls) | sequential `GET /dashboard/summary` |
| Dashboard live cadence | one tick per second, as designed | the tick the channel delivers |
| Packet events applied | bounded at 200 events/s for the channel (M14.16) | M14 design constant, not a measurement |
| Bounded packet rows | exactly **500** held while packets kept arriving | browser, under the capture in §9 |
| Bounded dashboard ticks | 60 points (`LIVE_TICK_CAPACITY`) | code constant |
| Bounded alert rows | 200 live rows per kind (`LIVE_ALERT_CAPACITY`); the listing itself is one API page, bounded server-side by `alert_max_page_size` | code constant |
| Production build | 988 ms, 2,545 modules | `npm run build` |
| Production bundle | JS 893.24 kB (237.50 kB gzip), CSS 23.17 kB (5.29 kB gzip), HTML 0.95 kB | build output |
| Unit suite | 15 files, 422 tests, all passing | `npm test` |
| Live suite | 3 files, 64 tests (50 REST, 6 sockets, 8 pages), all passing | `npm run test:live` |
| Type check | 0 errors | `npm run typecheck` |

**Not measured, and therefore not claimed:** React memory during sustained packet
streaming; the render latency of an alert event; and the wall-clock time of a
WebSocket reconnect (no drop was staged against a live socket — the reconnect
*behaviour* is covered by the unit suite with an injectable socket and fake
timers, which tests the logic, not the time).

The thing that keeps the frontend's memory flat is the row bound, not the
browser's throughput: with 77,441 packets over the run, the packet list retained
500 rows and said so itself (`500 shown · 500 retained · bounded at 500`). The
memory footprint is therefore a function of the configured capacity, not of how
long the page is open.

This is a local, single-user, development-server baseline. It is not a
production-scale claim.

---

# 12. Known limitations and observations

**1. Device identity collapses the far end onto the next hop when traffic is
routed.** This was found while verifying the Devices page, and it is the one
observation from M15 that belongs to a backend design rather than to the
frontend. The page showed two records:

| Record | Addresses | Local | Counters |
| --- | --- | --- | --- |
| `mac:E8:BF:B8:DD:68:0A` — hostname `Aman` | 3 (`192.168.43.174` + 2 IPv6) | yes | sent 22,790 / received 65,931 |
| `mac:DA:2A:33:2A:B6:D8` — unnamed | **94** | no | sent 65,932 / received 22,760 |

The second record is not a second host: it is **the next hop** — the Wi-Fi AP that
owns `192.168.43.1` — and the evidence is its own:

* its counters are the exact mirror of the monitoring host's (22,790 sent against
  22,760 received, 65,931 received against 65,932 sent), which is only possible if
  essentially every captured frame had exactly two endpoints — this host and the
  gateway;
* `192.168.43.1` is in its address list, and so is every far-end address this host
  talked to (Cloudflare `104.18.x`, Google `2001:4860::…`, Microsoft `20.x`, and
  the NAT64 forms under `64:ff9b::/96` this IPv6-only cellular network synthesizes
  for IPv4 destinations);
* `DA:2A:…` is a locally administered MAC (bit 1 of the first octet is set), which
  is what an AP interface normally presents.

The mechanism is M8's, not the frontend's. M5 takes each endpoint's L2 address
from the captured frame itself (`Ether.src`/`Ether.dst`) and its IP from the same
frame, and M8 keys a device by MAC first and then binds every IP it sees beside
that MAC (`_bind_ip`). On a routed path the frame's L2 peer is the next hop, so
the next hop's record legitimately collects the remote IPs of every frame it
carries. The same thing happens on a wired LAN with a router; it is a property of
MAC-first identity, not of Wi-Fi and not of this project's frontend.

It is **not** a defect introduced by M15, and it is **not** mock data — the
numbers are real observations. `docs/12_M8_Device_Discovery_Design.md` §7 states
"a device has exactly one MAC (its identity) but many IPs" without distinguishing
an L2 neighbour from a network peer, so a follow-up decision is owed: whether an
endpoint whose MAC is the next hop for that IP should instead be keyed by the IP
(`ip:…`), which would list remote peers as devices in their own right. That is a
backend (M8) design change and is therefore outside M15's boundary.

**2. The verification harness could not scroll the application's inner pane**
(900×600 viewport), so Analytics, Reports and Settings were verified by the live
page suite rather than by hand. The same is true of the controls below the fold:
the capture control, the evidence list and the alert/incident action buttons were
driven through the endpoints those buttons call, and confirmed by the resulting
UI state and page reload.

**3. The M13 alert payload carries no `risk_score`**, although M12 persists one on
member alerts. Risk is shown where the backend computes it — on the incident. The
alert pages therefore show confidence but no risk figure, and do not invent one.

**4. The production bundle is 893 kB in one chunk**, over Vite's 500 kB advisory,
because React, recharts and lucide-react land in the same chunk. Not a correctness
problem; code-splitting would be a follow-up.

**5. Two lockfiles exist**: the repository tracks `pnpm-lock.yaml`, and
`frontend/package-lock.json` is also present (untracked). Left as found.

**6. `React.StrictMode` is enabled**, so a development mount subscribes, unsubscribes
and subscribes again, and the console shows the corresponding `WebSocket is closed
before the connection is established` warnings. That is React's development
behaviour, not a duplicate subscription in the application: the hub holds one
socket per channel and the live socket suite asserts it.

**7. The High Bandwidth detector's default threshold is demo-grade, so the
Detections page fills with ordinary traffic.** `high_bandwidth_bytes_per_second_threshold`
defaults to `1_000_000` — 1 MB/s, i.e. **8 Mbit/s** — measured over M6's
one-second rate window, with `high_bandwidth_time_window_seconds = 5.0` as the
*mínimum interval between findings* rather than an averaging window. The live run
produced 16 findings, every one of them this rule, at 1.01–1.35 MB/s (≈1071
packets/s), which on a phone hotspot is ordinary browsing, video and Windows
update traffic. Three properties of the rule explain the volume of rows, and each
is deliberate in the code:

* it is a **whole-capture** observation — `source_ip` and `destination_ip` are
  `None`, because no single endpoint was observed to cause the volume, so the
  page legitimately shows a `—` where a host would be;
* the rate it compares is M6's, not a second aggregation of its own
  (`measurement_window_seconds: 1.0` in the evidence);
* **confidence is a distance from the threshold, not a threat level**:
  `0.5 + 0.5 × (measured − threshold) / threshold`, capped at 1.0. At 1.35 MB/s
  that is exactly `0.6743905` — the 67% the UI shows.

So the wording is honest (*"Possible* traffic spike detected") and the M10
layering is intact — a finding is an observation, and M11 decides which findings
become alerts (three did, its 300 s dedup window folding the rest). What is worth
changing before the defaults are taken as a judgement is the threshold: it should
be set relative to the monitored link's real capacity (e.g.
`HIGH_BANDWIDTH_BYTES_PER_SECOND_THRESHOLD=10000000` for 10 MB/s ≈ 80 Mbit/s, in
`backend/.env`), because 8 Mbit/s is below what an ordinary household link
carries. This is a configuration change, not a code change, and the settings are
cached at import, so the backend must be restarted for it to take effect.

---

# 13. How to run and verify locally

    # 1. backend (from the repository root)
    cd backend
    .venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

    # 2. frontend — serves on 8443, per frontend/vite.config.ts
    cd frontend
    npm run dev

    # 3. unit suite (stubbed transport; needs no backend)
    npm test                  # vitest run, src/**/*.test.{ts,tsx}
    npm run typecheck         # tsc --noEmit

    # 4. live suite (needs the backend running on 127.0.0.1:8000)
    npm run test:live         # vitest run --config vitest.live.config.ts

    # 5. production build
    npm run build

    # 6. drive a capture through the same endpoints the UI uses
    curl -X PUT  http://127.0.0.1:8000/api/v1/capture/interface \
         -H "Content-Type: application/json" -d "{\"interface\":\"Wi-Fi\"}"
    curl -X POST http://127.0.0.1:8000/api/v1/capture/start
    curl -X POST http://127.0.0.1:8000/api/v1/capture/stop

The frontend needs no configuration to reach a local backend: the Vite
configuration supplies `VITE_API_BASE_URL` and `VITE_WS_BASE_URL`
(`http://127.0.0.1:8000/api/v1`, `ws://127.0.0.1:8000`), and both are
browser-visible build-time values. No credential, token or backend secret is read
from them or stored anywhere in the frontend (M15.37).

---

# 14. M15 completion criteria, and where each is proven

| Criterion | Evidence |
| --- | --- |
| Figma Make frontend reviewed | §2 inventory; §10 records what the review surfaced |
| Original visual design preserved | the pages, rail, cards, tables and charts are the template's; §10's fixes are additive (CORS, icon, title, a type) |
| API service layer exists | `src/services/*` (23 modules); §3 |
| TypeScript backend types exist | `src/types/*` (7 modules); §4 |
| API errors handled consistently | one `ApiError` from one client; §3 |
| Dashboard uses real data | §8 row 1; §9 check 1 |
| Live Traffic uses real packets | `/ws/packets`; §8, §9 check 2 |
| Devices use real data | `GET /devices`; §8, §9 check 3 |
| Connections use real data | `GET /connections*`; §8, §9 check 4 |
| Detections use real data | `GET /detections*`; §8 |
| Alerts use real data | `GET /alerts*`; §8, §9 check 5 |
| Alert lifecycle actions work | the four `POST` routes; §8; §10 records the 409 that proves the rule is the backend's |
| Evidence works | `GET /alerts/{id}/evidence`, `GET /evidence/{id}`; §8 |
| Incidents use real data | `GET /incidents*`; §8, §9 check 6 |
| Incident lifecycle actions work | the three `POST` routes; §8 |
| Incident WebSocket events work | `incident.*` on `/ws/alerts`; §8 |
| Analytics use real data | five `GET /analytics/*`; §8 |
| Reports use real metadata only | §8, and the `501` row beneath it |
| Settings use real backend data | `GET/PUT /settings`; §8 |
| System status uses real backend data | `GET /system/*`; §8 |
| Notifications use real data | `GET /notifications*`; §8 |
| WebSocket reconnect works | unit suite (injectable socket, fake timers) + live socket suite; §11 states what was not measured |
| WebSocket event deduplication works | `event_id` per channel; §5 |
| Mock data removed | no `Math.random`, no simulated generator remains; §9 check 10 |
| Loading/empty/error states exist | `AsyncState`; §7 |
| Frontend state is bounded | 500 packet rows / 60 ticks / 200 alert rows per kind / bounded dedup; §6 |
| Frontend tests pass | 422 unit tests; §11 |
| Backend/frontend integration tests pass | 64 live tests; §11 |
| Manual end-to-end verification succeeds | §9 |
| Performance baseline recorded | §11 |

Two criteria are recorded with an explicit qualification rather than a bare tick:
reconnect is proven as *behaviour* but not measured as time (§11), and the manual
walk covered ten pages by hand while Analytics, Reports and Settings were covered
by the live page suite (§12, limitation 2).

---

# 15. The one thing M15 hands back to the backend

Everything else in this milestone is frontend work that is finished. The exception
is §12 limitation 1: on a routed path, a device record can end up keyed to the
next hop and holding every far-end address it carried, because identity is
MAC-first and the MAC is taken from the frame. It is visible on the Devices page,
it is not a frontend bug, and correcting it means deciding what an "endpoint"
means for a packet whose L2 peer is a router. That decision belongs to the M8
design, and it is the recommendation this milestone leaves behind.
