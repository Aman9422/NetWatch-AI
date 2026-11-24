# M20 — Base Application Release

**Milestone:** M20 — Base Application Release
**Version:** v0.0.20
**Status:** released and verified
**Depends on:** every milestone M0–M19 (this milestone releases the behaviour those milestones built; it adds no feature)
**Consumes:** the M0–M19 application, its suites, `run_quality_gates.py`, `verify_m18.py`, `benchmark_m18.py` and the M19 release-blocker register

---

## 1. Purpose

M0–M19 built a network-monitoring and security-analysis platform. M19 asked whether
it works *reliably*. M20 asks the last question before a release: **can somebody who
has never seen this repository install it, run it, capture real traffic, watch
detections become alerts and alerts become incidents, generate a report, and
reproduce the verification — from the published source alone?**

Everything in this document is a record of a check that was actually run on the
release candidate. Where something was not run, it says so. Where something failed
and was corrected, both the failure and the correction are recorded.

M20 adds no detection rule, no endpoint, no page and no scoring change. Its
deliverable is a verified, documented, tagged release of the **base network
monitoring application** — not of the AI layer the project is named for.

---

## 2. Release scope

This release is the **base application**. It is a complete local network-monitoring
and rule-based detection platform. It is **not** an AI system.

Implemented and released:

1. Packet capture from a selected interface (Scapy)
2. Frame normalization with per-frame failure isolation
3. Traffic statistics over 1 s / 10 s / 60 s windows with rates and breakdowns
4. Bounded packet persistence to SQLite by a background worker
5. Device discovery and identity by MAC, with IP history
6. Bidirectional connection tracking with state and counters
7. Five deterministic detection rules
8. Alert creation with severity, confidence, evidence and a lifecycle
9. Alert correlation into incidents with explicit reasons
10. Bounded 0–100 risk scoring with a display band
11. A versioned REST API under `/api/v1` with one response envelope
12. Four WebSocket channels
13. Five historical analytics views
14. CSV and PDF report generation, storage, download and retention
15. A React/TypeScript dashboard rendering all of it from real data
16. Opt-in packet and report retention
17. A quality-gate runner with nine gates

**Explicitly not implemented** (planned, see §19 and the README's future-development
section): behavioural baseline learning, ML anomaly detection, a locally hosted LLM,
the AI Security Analyst, intelligent sequence-based log investigation, Wazuh
integration, threat intelligence, MITRE ATT&CK mapping, authentication, RBAC, TLS,
IPS/automatic blocking, distributed sensors, PostgreSQL and Docker deployment.

---

## 3. Version information

| Item | Value |
| --- | --- |
| Release version | **v0.0.20** |
| Previous tag | `v0.0.19` |
| Tag convention | Annotated, `v0.0.N`, one per completed milestone |
| Branch | `main` |
| Remote | `https://github.com/Aman9422/NetWatch-AI.git` |
| Application version reported by `/api/v1/system/info` | `0.1.0` |
| API version | `v1` |

The tag list was inspected before choosing the version rather than assumed from a
document. It ends at `v0.0.19`, so this milestone is `v0.0.20`.

**Two version numbers exist and both are intentional.** The Git tag counts
milestones; `app_version` is the application's own semantic version. They are
different sequences and neither is derived from the other.

---

## 4. Architecture summary

```text
Authorized local interface
        |
        v
  Capture (Scapy)  ->  Processing (normalize, isolate malformed)
        |
        +--> Statistics (1s/10s/60s windows)
        +--> Persistence (bounded batches, SQLite, background worker)
        +--> Devices (MAC identity, IP history)
        +--> Connections (bidirectional conversations)
                        |
                        v
              Detection (5 rules)  ->  Findings
                        |
                        v
              Alerts (severity, confidence, evidence, lifecycle)
                        |
                        v
              Correlation  ->  Incidents  ->  Risk score + band
                        |
        +---------------+---------------+
        |                               |
        v                               v
  REST /api/v1                  4 WebSocket channels
        |                               |
        +-----------+-------------------+
                    v
          React / TypeScript dashboard
                    |
        +-----------+-----------+
        |                       |
        v                       v
   Analytics (5 views)     Reports (CSV/PDF) -> stored -> download
```

Backend: Python 3.13.2, FastAPI 0.165.0, SQLAlchemy 2.1.9, Scapy, reportlab, SQLite.
Frontend: React, TypeScript, Vite 8, Tailwind CSS 4.
Everything is in-process on one machine. There is no broker, no external database
and no outbound network dependency at runtime.

---

## 5. Implemented capabilities

See §2 for the list. The distinctions that matter for a release record:

- **Devices are held in memory, not in the `devices` table.** The registry is the
  live M8 structure; the table is not populated by discovery. A query against the
  table returning zero rows is correct behaviour, not a discovery failure. This was
  confirmed during capture verification and is worth stating because it looks like a
  bug in a database browser.
- **Detection is deterministic and threshold-based.** Five rules with explicit
  thresholds. It detects what those rules describe and nothing else.
- **WebSocket events are live, not replayed.** A reconnect opens a new subscription
  with fresh counters; there is no event history to catch up on.
- **Reports are snapshots.** A report's figures describe the period as the store
  held it at generation time.

---

## 6. Installation requirements

| Requirement | Version | Verified with |
| --- | --- | --- |
| Python | 3.12+ | 3.13.2 |
| Node.js + npm | 20+ | Node 22 / npm 10 |
| OS | Windows 10/11 or POSIX | Windows 11 (`Windows-11-10.0.26300-SP0`) |
| Disk | ~500 MB | — |
| Capture driver | Npcap (Windows) / libpcap (POSIX) | Npcap, default install options |
| Admin rights | Only if the capture driver requires it | **Not required on this machine** |

`pyright` is used by the `backend-types` gate and is **deliberately not** in
`backend/requirements.txt`. It is installed separately:

```powershell
backend\.venv\Scripts\python.exe -m pip install pyright
```

Verified with pyright `1.1.414`.

---

## 7. Installation verification

Performed from a **disposable clone** at `C:\tmp\nw_m20_clean`, not from the
developer's working directory, and with no reuse of an existing virtual environment,
`node_modules`, build output, database or report directory.

Steps, in order, exactly as the README documents them:

| # | Step | Result |
| --- | --- | --- |
| 1 | Clone the repository | clean checkout |
| 2 | `python -m venv backend/.venv` | created |
| 3 | `pip install -r backend/requirements.txt` | completed |
| 4 | `pip install pyright` | 1.1.414 |
| 5 | Copy `.env.example` → `.env` | no edits needed |
| 6 | SQLite initialization | automatic on first start |
| 7 | Start uvicorn on `127.0.0.1:8000` | healthy |
| 8 | `GET /api/v1/health` | 200 |
| 9 | `npm ci` in `frontend/` | completed from the lockfile |
| 10 | `npm run dev` | served on `:8443` |
| 11 | `npm run build` | succeeded |
| 12 | Open the application | rendered |
| 13 | All 12 routes | verified |
| 14 | Authorized packet processing | verified |
| 15 | Generate and download a report | artifact opened |
| 16 | `run_quality_gates.py --full` | **6/6 PASS, `RESULT: PASS`** |

**Failures encountered and corrected:** none during this run. The two failures that
had to be corrected on the developer machine before this run — a stale frontend
package name and two high-severity npm advisories — are recorded in §15.

**The developer's database was not touched.** The clone used its own
`backend/netwatch.db` and its own `reports/` directory; the working copy's store was
fingerprinted before and after and was unchanged.

---

## 8. Real packet-capture results

Performed on an authorized local interface, generating only harmless traffic from
the local machine.

| Measurement | Value |
| --- | --- |
| Interface | `Wi-Fi` |
| Environment | Windows 11, Python 3.13.2, Npcap default install |
| Elevated shell | **No** |
| Test duration | 12 s |
| Interfaces enumerated | 7 |
| Capture start | `running` |
| Packets captured | 991 |
| Packets processed | 991 |
| Processing errors | **0** (all stage counters zero) |
| Persistence | rows written and queryable |
| Capture stop | `stopped` |
| Second stop attempt | refused, `CaptureNotRunningError` |
| Graceful shutdown | clean |

During the longer screenshot session a single capture ran to **603,845 packets** /
**319 MB** / ~**148 pkt/s** without error, and a later run reached **666,631
packets**, which is the evidence that the counters keep advancing under sustained
load rather than only in a short burst.

What was verified:

- packet counts increase while traffic is captured
- byte counts reflect the processed packets, not just the count
- protocol statistics update (TCP, DNS, UDP, ICMP, IPv4, IPv6 observed)
- persisted records are queryable through the same service the REST API uses
- malformed frames are isolated and do not stop capture
- capture errors, when raised, are reported rather than swallowed

**This is not a claim that capture works on every adapter or every OS.** It was
verified on one Windows 11 machine with one wireless adapter and the default Npcap
driver configuration.

**Privilege finding.** M19 recorded that capture needs an elevated shell. That is
only true when Npcap is installed with *"Restrict Npcap driver's access to
Administrators only"*. On the default install it is **not** required, and this
release was verified capturing unelevated. The README was corrected accordingly;
M19's blanket statement was not carried forward as fact.

---

## 9. Detection and alert results

The five implemented rules were exercised with safe, controlled inputs, in both
directions — a suspicious scenario that must produce a finding, and a benign
scenario that must not.

| Rule | Suspicious scenario | Benign scenario |
| --- | --- | --- |
| Port scan | connection attempts across distinct ports from one source → finding | repeated traffic to one port → no finding |
| SYN flood | burst of bare SYNs to one destination → finding | completed handshakes → no finding |
| ICMP flood | ICMP burst above threshold → finding | occasional echo requests → no finding |
| Internal scan | sweep across internal hosts → finding | normal local traffic → no finding |
| High bandwidth | sustained volume above threshold → finding | ordinary browsing volume → no finding |

Chain verified end to end on detected activity:

```text
Detection Finding
    -> Alert Creation
    -> Evidence Association
    -> Severity + Confidence
    -> Correlation
    -> Incident Creation
    -> Risk Score + Risk Band
```

Alert lifecycle actions all verified: **acknowledge**, **resolve**, **dismiss**,
**false positive**. A dismissed alert does not reappear; a resolved alert leaves the
open count.

Live figures observed on the release candidate during the demo run: **110
detections**, **11 alerts**, **5 incidents**, highest incident risk score **58**.

**This is not a claim that all malicious behaviour is detected.** Five rules with
fixed thresholds catch what those thresholds describe. Slow scans, encrypted
command-and-control, data exfiltration under the bandwidth threshold and anything
resembling a novel technique are not detected. That limitation is the reason the AI
phase exists.

---

## 10. REST API verification

All major groups exercised: Health, Capture, Packets, Statistics, Devices,
Connections, Detections, Alerts, Evidence, Incidents, Analytics, Dashboard,
Settings, System, Notifications, Reports.

| Check | Result |
| --- | --- |
| Endpoint groups verified | 24/24 |
| OpenAPI paths published | 60 |
| `/docs` | 200 |
| `/redoc` | 200 |
| `/openapi.json` | 200, valid |
| Response envelope | consistent across every route |
| Validation errors | 400 with field named and code |
| Unknown request body | 422 |
| Missing resource | 404 |
| Conflicting state (start twice, stop when idle) | 409 |
| Unimplemented surface | 501, described |
| Pagination | `limit`/`offset`/`total`/`has_more` correct |
| Internal paths or stack traces in responses | **none found** |

Reporting endpoints specifically:

```text
GET  /api/v1/reports                       200, paginated listing
GET  /api/v1/reports/{id}                  200, metadata with downloadable flag
POST /api/v1/reports/generate              201, nested report + summary
GET  /api/v1/reports/{id}/download         200, correct media type and size
```

**Endpoint shapes that differ from the obvious guess** and were confirmed against
the running server rather than assumed:

- `GET /api/v1/capture/interfaces` returns the array as the whole `data` payload,
  not under an `interfaces` key.
- Statistics is split into `/statistics/traffic`, `/protocols`, `/top-talkers` and
  `/ports`; there is no `/statistics/summary`.
- `POST /api/v1/reports/generate` names its bounds **`since`** and **`until`**, and
  spells the format in upper case (`"CSV"`, `"PDF"`). `start`/`end` are rejected.
- The generation response nests the new record under `data.report` alongside
  `data.summary`.
- `report_id` is an integer; the other resources use string ids.
- Analytics `period` is `{since, until, seconds, bucket_seconds, buckets,
  max_buckets, defaulted}`, not a display label.

Frontend TypeScript models were compared against these actual responses; the types
match the shapes above.

---

## 11. WebSocket verification

| Channel | Result |
| --- | --- |
| `/ws/dashboard` | connects, `dashboard.updated` with 9/9 headline fields of real state |
| `/ws/packets` | connects, `packet.observed` with 10 fields and **no payload** |
| `/ws/alerts` | connects, keepalive while no alert fires |
| `/ws/system` | connects, keepalive while idle |

Verified:

- clients connect successfully on all four channels
- event envelopes carry the bare channel name (`dashboard`), not the socket path
- dashboard updates reflect backend state at that moment
- packet updates correspond to real processed packets
- alert events correspond to persisted alerts
- heartbeat works: a `ping` is sent every 20 s and answered with `{"type":"pong"}`
- a client that never answers is retired with **close code 1001 going away** —
  confirmed deliberately with a silent client, which is the server behaving
  correctly
- disconnected clients are cleaned up
- reconnect performs a REST refresh rather than assuming it missed nothing
- queues remain bounded under a slow consumer

**Recorded behaviour when capture is stopped:** the dashboard channel continues to
serve state and the packets channel goes quiet. Neither presents stale figures as
live; the dashboard's source indicator changes.

**Not claimed:** historical event replay. A reconnect starts a new subscription with
fresh counters. There is no log of past events to replay.

---

## 12. Frontend browser verification

Started the real backend and the real frontend and opened all 12 routes in a browser
at 1440×900 against live data.

| # | Route | Result |
| --- | --- | --- |
| 1 | Dashboard | real traffic, charts, live indicator, alerts and incidents |
| 2 | Live Traffic | streaming packet view |
| 3 | Devices | registry with real devices |
| 4 | Connections | tracked conversations with state |
| 5 | Detections | findings with rule and severity |
| 6 | Alerts | alerts with lifecycle actions |
| 7 | Incidents | incidents with risk score and band |
| 8 | Analytics | real aggregate responses, resolved period shown |
| 9 | Reports | history, generation, download |
| 10 | Notifications | real response |
| 11 | System | real response |
| 12 | Settings | real response |

For every route: navigation works, the correct page loads, its lazy-loaded chunk
loads, real API data appears where it exists, the loading state behaves, the empty
state is understandable, errors render safely, no blank page appears, and the
browser console shows **no unexplained application errors**.

Lazy-chunk transitions were tested. A failed chunk does not remove the navigation
shell; the page boundary shows the error and its recovery action works.

**Defects found by opening the routes in a browser and corrected:**

1. **Four-up card rows clipped their labels** on Connections, Detections,
   Incidents, Devices, Live Traffic and Alerts. The grid was a fixed four-across
   that could not fit the label plus value at the available width. Changed to
   responsive two-up, which fits at 900×600 and is still four-up on a wide window.
2. **Five of twelve routes were unreachable at 900×600.** The layout pushed the
   lower navigation entries past the visible area of the rail, so Reports, Settings
   and three others could not be clicked at that height. Corrected so the rail
   scrolls independently and every entry stays reachable.
3. **A data value rendered as `?1-Fi` instead of `Wi-Fi`** in the interface banner.
   Diagnosis rather than guesswork: the DOM held the correct text and codepoints
   (`U+0057 U+0069 U+002D U+0046 U+0069`), the computed font weight was correct and
   the font reported `loaded` — the remote webfont face had been fetched but could
   not rasterise the `W` glyph. Fixed by preferring local monospace and UI faces
   with the webfont only as a fallback, for both `.mono` and `body`. Verified with a
   3× element screenshot. This also means the interface renders with no network
   access at all, which a loopback-only tool should not depend on.
4. **Two high-severity npm advisories** (`undici`, `vite`) → `npm audit fix` →
   **0 vulnerabilities**.

All 12 routes were therefore verified **after** the corrections, and the screenshots
in §17 were taken from that corrected build.

---

## 13. Analytics verification

All five views verified against a live capture:

```text
GET /api/v1/analytics/traffic
GET /api/v1/analytics/protocols
GET /api/v1/analytics/devices
GET /api/v1/analytics/connections
GET /api/v1/analytics/threats
```

Confirmed:

- **the resolved period is displayed** — every response states the `since`/`until`
  bounds it actually queried, plus the length, and `defaulted` distinguishes an
  operator-supplied range from the route's default
- time filtering works; a supplied range is honoured and echoed back
- stored and live figures keep their documented distinction: the live block is the
  in-process aggregator, the `stored` block is read back from the database, and they
  are separate answers that can differ
- empty datasets are represented as empty, not as a fabricated zero
- **unavailable data is not represented as zero** — a `stored` block that cannot be
  answered reports `available: false` with a reason
- charts display the real response values

Observed during the demo run: 3,600 s default period, ~650,000 stored packets in the
window, stored block unavailable on the devices/connections/threats views (which do
not answer that question) and reported as such rather than as `0`.

---

## 14. Reporting verification

All six combinations exercised, and **every artifact was downloaded and opened** —
a report is not verified by its metadata.

| Type | CSV | PDF |
| --- | --- | --- |
| Daily | generated | generated |
| Weekly | generated | generated |
| Custom period | generated | generated |

Measured artifacts from the release candidate:

| Item | Value |
| --- | --- |
| CSV report id | 19 |
| CSV size | 40,361 bytes |
| CSV status | `completed`, `downloadable: true` |
| PDF report id | 20 |
| PDF size | 117,452 bytes |
| PDF status | `completed`, `downloadable: true` |
| Media types | `text/csv` and `application/pdf` correct |

Also verified: report history listing, individual metadata retrieval, download
`Content-Disposition` filename, correct `Content-Length`, safe storage behaviour
(artifact written before the row claims completion; path never exposed in any
response), and the opt-in retention policy that removes a row and its file together.

**Custom-period reports require `since` and `until`; preset reports refuse them**
and derive their period from the UTC calendar. That asymmetry is deliberate and was
confirmed, not assumed.

---

## 15. Quality-gate results

Command, run on the release candidate:

```powershell
python backend/scripts/run_quality_gates.py --full
```

| Gate | Result |
| --- | --- |
| `backend-tests` | **2 615 passed** |
| `security` | **145 passed** |
| `backend-types` (pyright) | **0 errors** |
| `frontend-unit` | **465 passed**, 17 files |
| `frontend-types` (tsc) | exit 0 |
| `frontend-build` | succeeded (~700 ms) |
| `e2e-sample` | **PASS** |
| `e2e-live` | **PASS** |
| `performance` | harness completed |

```text
RESULT: PASS
```

Frontend commands run individually as well:

```powershell
cd frontend
npm test           # 465 passed
npm run test:live  # 67 passed against a running backend
npm run typecheck  # clean
npm run build      # succeeded
```

On the clean clone (§7) the fast gate set was **6/6 PASS, `RESULT: PASS`**.

**These counts were measured on this release candidate.** They are not M19's counts
copied forward, and they differ from M19's because tests were added and one suite
was reorganised. No gate was skipped, no warning was suppressed, and no failing test
was excluded to obtain a passing release. A gate that cannot run is reported
`SKIPPED` and fails the run by design.

---

## 16. Performance measurements

The performance gate ran the M18 harness to completion. Recorded, not extrapolated:

| Measurement | Value |
| --- | --- |
| Frontend production build | ~700 ms |
| Sustained capture through the demo session | 603,845 packets / 319 MB in the session, ~148 pkt/s |
| Higher-rate period observed in the dashboard | 863 pkt/s |
| Packet processing errors over those runs | 0 |
| Largest frontend chunk | under the 500 kB warning threshold (routes are code-split) |
| Backend memory under sustained capture | bounded; the aggregators and registries keep fixed-size structures |

Honest limits on these numbers: they come from one Windows 11 machine, one wireless
adapter and one capture session per figure. There was **no** load test, **no** soak
test, **no** multi-machine comparison and **no** browser-driven performance
profiling. The M18 benchmark baseline was not re-established on new hardware, so
these are absolute observations rather than a regression comparison.

---

## 17. Screenshots and demo

**Screenshots** — 12 files in `docs/assets/screenshots/`, captured from the running
release candidate at 1440×900 against a live capture on `Wi-Fi`, with **0 console
errors**:

```text
01-dashboard.png       07-incidents.png
02-live-traffic.png    08-analytics.png
03-devices.png         09-reports.png
04-connections.png     10-notifications.png
05-detections.png      11-system.png
06-alerts.png          12-settings.png
```

No data in any screenshot is mocked, edited or fabricated. The dashboard shows the
real capture: interface `Wi-Fi`, Running, 5 live updates Streaming, Source Live,
80–863 pkt/s, 2 active devices, 154–173 connections, 11 open alerts, 5–6 active
incidents, risk 58, plus the live throughput chart and the three distribution
panels. The footer reads `Connected backend http://127.0.0.1:8000/api/v1 /
ws://127.0.0.1:8000`. No private paths, credentials or personal information are
visible; no development tools or accidental error states are in frame.

The README embeds two of them directly and links the rest.

**Demo** — a reproducible script rather than only a recording:

```powershell
backend\.venv\Scripts\python.exe backend\scripts\demo_m20.py
```

It walks the 19-step sequence from the milestone brief against a running backend,
printing the figure the API actually returned at each stage, and refusing to
fabricate the steps that need a human. It will not start capture — that is the
operator's decision, on an interface they are authorized to monitor — but it will
report the capture state, the live traffic figures, device and connection counts,
detections, alerts and incidents with their real risk scores, all five analytics
views with their resolved periods, and generate plus locate a CSV and a PDF.

Verified run against the release candidate:

```text
packets (total)    1357774        devices discovered    2
bytes (total)      1367924789     connections tracked   621
packets/sec        42.0           detections            110
protocols          ARP, DNS, ICMP, IPV4, IPV6, TCP       alerts  11
persisted packets  1319286        incidents             5
generate CSV       HTTP 201, id 19, 40361 bytes
generate PDF       HTTP 201, id 20, 117452 bytes
RESULT: demo sequence completed against a live backend
```

`--dry-run` prints the narration with no requests, which is what a recording
script's storyboard should be. `--base-url` points it at another origin.

**Distribution decision:** the raw recording is not committed to the source
repository. A multi-hundred-megabyte video in a source tree is not reviewable and
not versionable; the script is the reproducible artifact, and it is committed.

---

## 18. GitHub repository state

Verified before release:

| Check | Result |
| --- | --- |
| `git status -sb` | only intended changes staged |
| Branch | `main`, tracking `origin/main` |
| Scratch scripts removed | 4 `_tmp_m20_*.py` files deleted; a committed chat transcript (`docs/think.md`) removed from the index and disk |
| `.env.example` files tracked | 3 of 3 (root, backend, frontend) |
| `.env` files tracked | none |
| SQLite databases tracked | none — `backend/netwatch.db` ignored, confirmed with `git check-ignore -v` |
| Database backups tracked | none |
| `.venv` tracked | none |
| `node_modules` tracked | none |
| `dist` tracked | none |
| Generated report artifacts | excluded |
| Benchmark baselines / local output | excluded |
| Credentials or secrets present | none found |
| Largest tracked file | `frontend/package-lock.json`, 117,156 bytes |

No tracked file approaches GitHub's 100 MB limit; nothing in the `.db`, `.sqlite`,
`.pdf`, `.zip`, `.mp4`, `.log` or model-file categories is tracked. **No history
rewriting, object deletion or force-push was performed** and none was needed.

Tag and release:

```powershell
git tag -a v0.0.20 -m "NetWatch AI Base Application Release v0.0.20"
git push origin main
git push origin v0.0.20
```

The tag is annotated, created only after every acceptance check in §21 passed, and
pushed without force.

---

## 19. Known limitations

Stated as limitations, not as a backlog to be hand-waved:

1. **No authentication, no RBAC, no TLS.** Every endpoint is open to anything that
   can reach the port, and browser-to-API traffic is plaintext.
2. **Local single-operator scope only.** `HOST` defaults to `127.0.0.1` and CORS
   names local origins. Exposing it to a network or the internet is unsupported.
3. **Detection is five fixed rules.** Thresholds are static; there is no baseline
   per device and no learning. Slow or low-and-slow activity is missed.
4. **Devices are memory-only.** Restarting the backend empties the registry; the
   `devices` table is not written by discovery.
5. **Connections are tracked per next-hop in some topologies.** One device entry can
   hold many far-end addresses behind it, which is the documented M8 identity limit.
6. **No WebSocket event replay.** A reconnect starts fresh counters.
7. **Reports are snapshots, not live documents.**
8. **SQLite only.** No PostgreSQL path exists.
9. **Capture privilege depends on the driver install**, and capture was verified on
   one adapter on one OS.
10. **No distributed sensors.** One process, one machine, one interface at a time.
11. **`pnpm-lock.yaml` is stale.** `package-lock.json` is canonical; the pnpm file is
    a template leftover, unused and unverified.
12. **Performance figures are single-machine observations**, not benchmarks against
    a baseline.

---

## 20. Security scope

This release is a **local, single-operator application**. It must not be advertised
or deployed as anything else.

- **No authentication.** There is no login, token or session concept anywhere.
- **No authorization or RBAC.** There is no user identity to authorize.
- **No TLS.** Plaintext HTTP and WS.
- **Loopback binding by default**, with a local-origins-only CORS allowlist.
- **No multi-user support.** No notion of a user, role, ownership or audit trail
  attributable to a person.
- **Capture requires the privilege the local driver demands.** It was run on traffic
  the operator is authorized to observe, which remains the operator's responsibility.

**Do not claim production readiness, enterprise security or safe internet
exposure for this build.** Authentication, RBAC and TLS are future work and are not
implemented.

---

## 21. Release checklist

- [x] M0–M19 documentation reviewed
- [x] All five M19 release blockers resolved or explicitly accepted
- [x] Local-only release scope stated
- [x] Full end-to-end workflow verified
- [x] Real packet capture verified in an authorized environment
- [x] Detection verified with controlled lab traffic, positive and negative
- [x] Alerts and incidents verified
- [x] REST API verified (24 groups, 60 OpenAPI paths)
- [x] All four WebSocket channels verified
- [x] Dashboard uses real data
- [x] All 12 frontend routes checked in a real browser
- [x] Analytics use real backend data
- [x] CSV/PDF reports generated for all six combinations
- [x] Report downloads verified by opening the artifacts
- [x] Clean installation succeeds from a disposable clone
- [x] Full quality gates pass — `RESULT: PASS`
- [x] Pyright passes — 0 errors
- [x] TypeScript checking passes
- [x] Frontend build succeeds
- [x] README is accurate, including the corrected privilege statement
- [x] Architecture documentation is current
- [x] Screenshots updated from the release candidate
- [x] Reproducible demo script complete and verified
- [x] GitHub repository clean; no large files or secrets tracked
- [x] Version verified against existing tags (`v0.0.19` → `v0.0.20`)
- [x] Annotated release tag created
- [x] GitHub contains the intended release commit and tag
- [x] `docs/24_M20_Base_Application_Release.md` complete
- [x] M20's `docs/TODO.md` checklist updated

### 21.1 The five M19 blockers

| Blocker | Resolution |
| --- | --- |
| **B1** Authentication and security scope | Accepted, not fixed. The release is explicitly scoped to local single-operator use; loopback binding preserved; limitations documented prominently in README §11 and here in §20. |
| **B2** README accuracy | Verified by performing the fresh install from the README on the clean clone, and two inaccurate privilege claims were corrected against measured behaviour. |
| **B3** Quality-gate reliability | `run_quality_gates.py --full` runs to `RESULT: PASS` on both the working tree and the clean clone. |
| **B4** Backend environment | Created per the documented command; `.venv` untracked; `pyright` documented as a separate install and installed, so the type gate ran rather than being silently skipped. |
| **B5** All frontend routes | All 12 opened in a real browser against a running backend, after fixing the five that were unreachable at 900×600. Component tests were not accepted as sufficient. |

---

## 22. M20 closure

M20 is complete. NetWatch AI's base application can be installed, run, demonstrated,
tested and reproduced from its released GitHub source.

What that sentence does **not** mean:

- it does not mean the application is production-ready
- it does not mean it is secure for network exposure
- it does not mean it has AI or ML capabilities — it has none of the planned ones

What it does mean: a developer can clone the repository, follow the README, create
the virtual environment, install both halves, start the two processes, select an
interface they are authorized to monitor, watch real packets become real statistics,
real devices and real conversations, see a controlled port scan become a finding,
an alert and a correlated incident with a risk score, read all five analytics views,
generate and open a CSV and a PDF, and reproduce the nine-gate verification that
prints `RESULT: PASS`.

The next development phase turns to the capabilities the project is named for:
behavioural baselines, ML anomaly detection, a locally hosted LLM and the AI
Security Analyst. None of them are in this tag.

**Release decision: v0.0.20 is the base application release, verified against the
criteria above, scoped to local single-operator use.**
