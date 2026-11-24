# NetWatch AI — M20 Base Application Release

**Milestone:** M20 — Base Application Release  
**Scope:** final release acceptance, clean installation, end-to-end verification, documentation, demonstration, GitHub repository cleanup and version tagging.  
**Status:** **released and verified** — tagged `v0.0.20`

> **Record.** This file holds the M20 brief. The outcome is recorded in
> `docs/24_M20_Base_Application_Release.md`: what was verified, with what
> measurement, and what remains a limitation. The completion criteria in §22 are
> all satisfied; the §23 final report is reproduced at the end of this file.

---

# 1. Purpose

NetWatch AI has completed M0–M19.

The application now includes:

- Network packet capture and processing
- Traffic statistics and persistence
- Device discovery and connection tracking
- Detection and alert management
- Event correlation and risk scoring
- REST API and WebSocket communication
- React/TypeScript frontend
- Historical analytics
- CSV/PDF report generation
- Project-wide testing
- Stabilization and clean-installation verification

M20 is the final milestone for releasing the **base NetWatch AI application**.

It must verify that a developer can clone the repository, install the dependencies, configure the application, start it, capture authorized network traffic, view real data, verify detections, generate reports and reproduce the documented tests.

M20 is a release milestone, not another feature-development milestone.

The goal is to release a stable and demonstrable base application without introducing unnecessary functionality.

---

# 2. Important Release Scope

M20 releases the existing network-monitoring and security-analysis platform.

It does NOT represent completion of the originally planned AI intelligence layer.

The following capabilities remain future work:

- Behavioral baseline learning
- ML-based anomaly detection
- Locally hosted LLM
- AI Security Analyst
- Intelligent sequence-based log investigation
- Wazuh integration
- Advanced threat intelligence
- MITRE ATT&CK integration

Do not describe these features as implemented.

After M20, the next development phase will focus on the actual AI capabilities that give NetWatch AI its name.

---

# 3. M20 Goals

M20 must deliver:

1. Final project-wide acceptance testing
2. Real network-capture verification
3. Detection and alert verification
4. Frontend verification using real backend data
5. REST API verification
6. WebSocket verification
7. Analytics and report verification
8. All 12 frontend routes checked in a real browser
9. Clean-installation verification against the release candidate
10. Accurate README and project documentation
11. Updated project screenshots
12. A reproducible demo recording
13. GitHub repository cleanup
14. Release notes
15. Version tagging

Do not add unnecessary new features.

---

# 4. M20.1 — Final Repository Audit

Inspect the actual repository before beginning release preparation.

Review:

```text
README.md
docs/TODO.md
docs/Current_Task.md
docs/11_Base_App_Roadmap.md
docs/20_M16_Analytics_Design.md
docs/21_M17_Reports_Design.md
docs/22_M18_Testing_Design.md
docs/23_M19_Stabilization_Design.md
```

Inspect:

- backend application structure
- frontend application structure
- backend dependencies
- frontend dependencies
- environment examples
- database migration and initialization
- reporting configuration
- GitHub repository configuration
- current Git branch
- existing version tags
- current working-tree state

Confirm that M0–M19 are recorded accurately.

Determine:

- current application version
- last committed version tag
- latest commit
- uncommitted changes
- existing release documentation
- remaining release blockers

Do not overwrite historical milestone records.

Do not assume that the version number is correct merely because an earlier milestone document mentions it.

---

# 5. M20.2 — Release Acceptance and Known Limitations

Review all release blockers carried forward from M19.

### B1 — Authentication and security scope

Authentication, authorization/RBAC and TLS are not implemented.

The base application must therefore be explicitly released as a **local, single-operator application**.

Requirements:

- Do not advertise public internet deployment.
- Do not advertise untrusted multi-user deployment.
- Preserve the documented loopback backend binding.
- Verify CORS and local API configuration.
- Document the security limitations prominently.
- Do not claim production-grade enterprise security.

### B2 — README accuracy

The README must remain the canonical installation guide.

Verify it against the actual application.

Perform a fresh installation using the final release candidate.

### B3 — Quality-gate reliability

The documented quality-gate command must complete successfully.

Run:

```powershell
python backend/scripts/run_quality_gates.py --full
```

Use the actual supported command and verify its output.

The final release notes must include the genuine:

```text
RESULT: PASS
```

line from the final release verification.

### B4 — Backend environment

The backend virtual environment must be created on the release machine.

Do not commit `.venv`.

Document the command required to create it:

```powershell
cd backend
python -m venv .venv
```

Install the backend dependencies and the separately documented Pyright development dependency.

The final release verification must not silently skip the backend type-checking gate.

### B5 — All frontend routes

All 12 frontend routes must be opened and verified in a real browser against a running backend.

A passing component test alone is not sufficient to close this requirement.

---

# 6. M20.3 — Full End-to-End Application Verification

Verify the entire application workflow:

```text
Authorized Local Network
        ↓
Packet Capture
        ↓
Packet Processing
        ↓
Traffic Statistics
        ↓
Packet Persistence
        ↓
Device Discovery
        ↓
Connection Tracking
        ↓
Detection Engine
        ↓
Alert Engine
        ↓
Correlation + Risk Scoring
        ↓
REST API + WebSockets
        ↓
React Dashboard
        ↓
Analytics
        ↓
CSV/PDF Reports
        ↓
Report Download
```

Verify that every stage receives and produces the expected real data.

Use the existing M18 end-to-end verification scripts where appropriate.

Do not replace real pipeline verification with mock data or manually fabricated API responses.

Keep tests isolated from the developer's working SQLite database.

---

# 7. M20.4 — Real Network Capture Verification

Perform an authorized local packet-capture test.

Verify:

- network interface enumeration
- interface selection
- capture start
- capture status
- packet reception
- packet normalization
- traffic counter updates
- packet persistence
- capture stop
- correct final capture state
- graceful application shutdown

Use a local interface that the operator is authorized to monitor.

Use harmless traffic generated from the local machine or an authorized lab environment.

Do not perform disruptive scans or generate uncontrolled flood traffic.

Verify that:

- packet counts increase when traffic is captured
- byte counts reflect processed packets
- protocol statistics update
- persisted records are queryable
- malformed packets do not stop capture
- capture errors are reported honestly

Record:

- interface used
- operating environment
- test duration
- packet count
- processed packet count
- processing errors
- persistence result

Do not claim that packet capture works on every network adapter or operating system.

---

# 8. M20.5 — Detection and Alert Verification

Verify the existing detection engine using controlled lab traffic.

Test the implemented detection categories:

- Port scan
- SYN flood detection
- ICMP flood detection
- Internal scan
- High-bandwidth/traffic spike detection

Use safe, controlled test inputs.

Verify both:

1. Suspicious scenarios that should produce findings
2. Benign scenarios that should not produce findings

For detected activity, verify:

```text
Detection Finding
       ↓
Alert Creation
       ↓
Evidence Association
       ↓
Severity + Confidence
       ↓
Correlation
       ↓
Incident Creation
       ↓
Risk Score + Risk Band
```

Verify alert lifecycle actions:

- Acknowledge
- Resolve
- Dismiss
- False positive

Do not claim that all malicious network behavior is detected.

Document the actual detection rules and their limitations.

---

# 9. M20.6 — REST API Verification

Verify the complete documented REST API.

Check the major API groups:

- Health
- Capture
- Packets
- Statistics
- Devices
- Connections
- Detections
- Alerts
- Evidence
- Incidents
- Analytics
- Dashboard
- Settings
- System
- Notifications
- Reports

Verify the important reporting endpoints:

```text
GET  /api/v1/reports
GET  /api/v1/reports/{id}
POST /api/v1/reports/generate
GET  /api/v1/reports/{id}/download
```

Verify:

- successful responses
- response envelope
- validation
- invalid filters
- missing resources
- pagination
- error handling
- correct status codes
- absence of internal paths or stack traces

Check the OpenAPI documentation at:

```text
http://127.0.0.1:8000/docs
http://127.0.0.1:8000/redoc
http://127.0.0.1:8000/openapi.json
```

Compare actual API responses against the frontend TypeScript models.

Do not assume that all routes work merely because the health endpoint responds.

---

# 10. M20.7 — WebSocket Verification

Verify all four channels:

```text
/ws/dashboard
/ws/packets
/ws/alerts
/ws/system
```

Confirm:

- clients connect successfully
- actual events are received
- event envelopes are valid
- dashboard updates reflect backend state
- packet updates correspond to real packet processing
- alert events correspond to persisted alerts
- system events reflect actual system state
- heartbeat works
- disconnected clients are cleaned up
- reconnect performs REST refresh
- queues remain bounded

Verify the frontend does not present stale data as live data when a connection has failed.

Record the behavior when capture is stopped.

Do not claim historical WebSocket event replay, because the existing implementation starts a new connection with fresh counters.

---

# 11. M20.8 — Frontend Real-Browser Verification

Start the actual backend and frontend.

Open the application in a real browser.

Verify every route:

1. Dashboard
2. Live Traffic
3. Devices
4. Connections
5. Detections
6. Alerts
7. Incidents
8. Analytics
9. Reports
10. Notifications
11. System
12. Settings

For each route, verify:

- navigation works
- the correct page loads
- required JavaScript chunks load
- real API data appears where available
- loading state behaves correctly
- empty state is understandable
- errors are displayed safely
- no unexpected blank page appears
- browser console does not show unexplained application errors

Test the route transitions that use lazy-loaded chunks.

Verify that a failed chunk does not remove the navigation shell and that the page recovery action works.

For the Dashboard and Live Traffic pages, perform a controlled capture session and verify that real data appears.

For Alerts and Incidents, use controlled test events from the actual backend.

For Analytics and Reports, verify real backend responses.

For Settings and System, verify actual API responses rather than fixtures.

Capture updated screenshots of the application.

Do not use fabricated data for release screenshots.

---

# 12. M20.9 — Analytics and Reporting Verification

Verify all five analytics endpoints:

```text
GET /api/v1/analytics/traffic
GET /api/v1/analytics/protocols
GET /api/v1/analytics/devices
GET /api/v1/analytics/connections
GET /api/v1/analytics/threats
```

Confirm that:

- the resolved period is displayed
- time filtering works
- stored and live figures retain their documented distinction
- empty datasets are represented correctly
- unavailable data is not represented as zero
- charts display real response values

Verify M17 reporting:

- Daily CSV generation
- Daily PDF generation
- Weekly CSV generation
- Weekly PDF generation
- Custom-period CSV generation
- Custom-period PDF generation
- Report history
- Individual report metadata
- Report downloads
- Correct media types
- Correct file sizes
- Safe storage behavior

Open the downloaded CSV and PDF files to verify their contents.

Do not claim a report is generated just because the API returned metadata.

The actual artifact must exist and be downloadable.

---

# 13. M20.10 — Clean-Installation Verification

Create a clean clone or disposable checkout of the final release candidate.

Do not rely on:

- existing virtual environments
- existing `node_modules`
- old build output
- local databases
- cached report files
- machine-specific configuration
- manually copied runtime data

Follow the README exactly.

Verify:

1. Clone the repository.
2. Create the backend virtual environment.
3. Install backend dependencies.
4. Install the documented Pyright dependency.
5. Configure backend environment variables.
6. Initialize SQLite.
7. Start FastAPI.
8. Confirm the health endpoint.
9. Install frontend dependencies with `npm ci`.
10. Start the frontend.
11. Build the frontend.
12. Open the application.
13. Verify all 12 routes.
14. Perform authorized packet-processing verification.
15. Generate and download a report.
16. Run the quality gates.

Record every failure and the correction.

The clean installation must use the committed source and documentation, not the developer's working directory.

Verify that the developer's actual database is untouched.

---

# 14. M20.11 — Final Quality Gates

Run:

```powershell
python backend/scripts/run_quality_gates.py --full
```

Run the frontend checks:

```powershell
cd frontend
npm test
npm run test:live
npm run typecheck
npm run build
```

Confirm:

- all backend tests pass
- security tests pass
- Pyright passes
- frontend unit tests pass
- live integration tests pass
- TypeScript checking passes
- frontend build succeeds
- sample end-to-end verification passes
- live end-to-end verification passes
- performance harness completes

Record exact test counts and results from the final release candidate.

Do not copy M19 test counts as the M20 result.

Do not suppress warnings or skip failures to obtain a passing release.

---

# 15. M20.12 — README and Documentation Finalization

Review the README and make it suitable as the main entry point for a new developer.

It must clearly explain:

### Project overview

- What NetWatch AI does today
- Its architecture
- Implemented capabilities
- Current limitations
- What remains future work

### Installation

- Requirements
- Backend installation
- Frontend installation
- Configuration
- Database initialization
- Startup commands

### Usage

- Start packet capture
- Select a network interface
- View live traffic
- View devices and connections
- Inspect findings and alerts
- Investigate incidents
- View analytics
- Generate reports
- Download reports

### Verification

- Run backend tests
- Run frontend tests
- Run live tests
- Run type checks
- Run full quality gates
- Run end-to-end verification

### Security limitations

Explicitly state:

- No authentication
- No RBAC
- No TLS
- Local single-operator scope
- No public or untrusted multi-user deployment support

### Future development

Clearly distinguish planned capabilities:

- Behavioral baselines
- ML anomaly detection
- Local LLM
- AI Security Analyst
- Intelligent log analysis
- Wazuh integration

Do not describe planned features as implemented.

---

# 16. M20.13 — Architecture and Project Screenshots

Review existing architecture diagrams and project screenshots.

Prepare an updated set of genuine screenshots representing:

- Dashboard
- Live Traffic
- Devices
- Connections
- Detections
- Alerts
- Incidents
- Analytics
- Reports
- Settings or System

Capture screenshots from the running release candidate.

Do not fabricate data or alter screenshots to misrepresent capabilities.

Ensure screenshots:

- show the actual interface
- use consistent application dimensions
- are readable
- do not expose private paths, credentials or personal information
- do not show accidental errors or development tools

Update the README with a small number of the most useful screenshots.

Keep the remaining screenshots in an organized documentation/assets directory.

---

# 17. M20.14 — Demo Recording

Create a reproducible demonstration of the base NetWatch AI application.

Suggested sequence:

```text
1. Introduce NetWatch AI
2. Explain the application architecture
3. Start the backend
4. Start the frontend
5. Select an authorized network interface
6. Start packet capture
7. Generate harmless network traffic
8. Show real-time traffic updates
9. Show device discovery
10. Show connection tracking
11. Demonstrate a controlled detection scenario
12. Show the resulting alert
13. Show the correlated incident
14. Open analytics
15. Generate a CSV report
16. Generate a PDF report
17. Download a report
18. Show the testing and verification results
19. Explain current limitations and future AI development
```

Use real data generated during the demonstration.

Do not claim that the platform has ML or AI capabilities that are not yet implemented.

Keep the recording clear and focused.

Store the final demo in an intentional location and do not commit unnecessary large raw recordings to the source repository unless that is the chosen distribution approach.

---

# 18. M20.15 — GitHub Repository Cleanup

Review the complete repository before release.

Verify:

- source files are tracked
- tests are tracked
- milestone documents are organized
- README is updated
- `.env.example` files are tracked
- `.env` files are not tracked
- SQLite databases are not tracked
- database backups are not tracked
- `.venv` is not tracked
- `node_modules` is not tracked
- `dist` is not tracked
- temporary files are removed
- generated report artifacts are excluded
- local benchmark baselines are excluded
- no credentials or secrets are present
- no accidental large binary files are committed

Run:

```powershell
git status -sb
git remote -v
git ls-files backend/netwatch.db
git check-ignore -v backend/netwatch.db
```

Inspect tracked repository contents for files exceeding GitHub's 100 MB file limit.

Pay special attention to:

- `.db`
- `.sqlite`
- `.pdf`
- `.zip`
- `.mp4`
- `.log`
- generated reports
- model files

Keep source code, documentation and intentional project assets.

Do not run `git filter-repo`, delete Git objects, or force-push as a routine cleanup operation.

If a large tracked file or leaked secret is discovered:

1. stop release preparation
2. identify the affected file and commits
3. make a verified backup
4. determine whether history rewriting is necessary
5. document the recovery procedure
6. only then perform the required correction

Preserve all valid project work.

---

# 19. M20.16 — Version and Release Management

Inspect existing version tags before selecting a release version.

Follow the project's existing semantic-version naming convention.

If the current release sequence ends at `v0.0.19`, and that is confirmed to be the latest valid tag, the proposed next tag is:

```text
v0.0.20
```

Do not assume this version if the repository has moved beyond it.

Before tagging:

- confirm the correct branch
- ensure working-tree changes are understood
- ensure all release commits are committed
- run the final full quality gates
- complete the clean installation
- complete all browser-route checks
- complete end-to-end verification
- review release notes

Create an annotated Git tag only after all acceptance criteria pass.

For example, when the final version has been verified:

```powershell
git tag -a v0.0.20 -m "NetWatch AI Base Application Release v0.0.20"
```

Push the intended branch and tag:

```powershell
git push origin main
git push origin v0.0.20
```

Do not force-push.

Verify that the tag and release commit exist on GitHub.

Prepare GitHub release notes with:

- release version
- implemented features
- testing results
- installation instructions
- known limitations
- local-only deployment warning
- future AI development roadmap

Do not publish or tag an unverified build.

---

# 20. M20.17 — Release Acceptance Report

Create:

```text
docs/24_M20_Base_Application_Release.md
```

Use the same numbered design-document style as earlier milestones.

Include:

1. Purpose
2. Release scope
3. Version information
4. Architecture summary
5. Implemented capabilities
6. Installation requirements
7. Installation verification
8. Real packet-capture results
9. Detection and alert results
10. REST API verification
11. WebSocket verification
12. Frontend browser verification
13. Analytics verification
14. Reporting verification
15. Quality-gate results
16. Performance measurements
17. Screenshots and demo
18. GitHub repository state
19. Known limitations
20. Security scope
21. Release checklist
22. M20 closure

Update the M20 section of `docs/TODO.md`.

Update `docs/Current_Task.md` using the established project convention.

Preserve previous milestone records.

The document status must remain:

**Status: design / in progress**

until the release candidate has passed every required check.

Only then change it to:

**Status: released and verified**

---

# 21. M20 Non-Goals

The following capabilities are explicitly outside M20:

- Behavioral baseline engine
- ML anomaly detection
- AI explanations
- Local LLM/Ollama
- AI Security Analyst
- Intelligent sequence analysis
- Wazuh integration
- SIEM integration
- Threat-intelligence integration
- MITRE ATT&CK integration
- IPS or automatic blocking
- Authentication/RBAC
- Distributed sensors
- PostgreSQL migration
- Docker deployment

M20 completes the base network-monitoring application.

It does not complete the future AI intelligence phase.

---

# 22. Completion Criteria

M20 is complete only when — **all satisfied**:

- [x] M0–M19 documentation has been reviewed
- [x] All five M19 release blockers are resolved or explicitly accepted
- [x] Local-only release scope is stated
- [x] Full end-to-end workflow is verified
- [x] Real packet capture works in an authorized environment
- [x] Detection is verified using controlled lab traffic
- [x] Alerts and incidents are verified
- [x] REST API is verified
- [x] All four WebSocket channels are verified
- [x] Dashboard uses real data
- [x] All 12 frontend routes are checked in a real browser
- [x] Analytics use real backend data
- [x] CSV/PDF reports work
- [x] Report downloads work
- [x] Clean installation succeeds
- [x] Full quality gates pass
- [x] Pyright passes
- [x] TypeScript checking passes
- [x] Frontend build succeeds
- [x] README is accurate
- [x] Architecture documentation is updated
- [x] Screenshots are updated
- [x] Demo recording is completed
- [x] GitHub repository is clean
- [x] No accidental large files or secrets are tracked
- [x] Version is verified
- [x] Annotated release tag is created
- [x] GitHub contains the intended release commit and tag
- [x] `docs/24_M20_Base_Application_Release.md` is complete
- [x] M20's `docs/TODO.md` checklist is updated

---

# 23. Final Implementation Report

At completion, provide:

1. Final application version
2. Final release commit
3. Git tag
4. Files created
5. Files modified
6. Final backend test results
7. Final frontend test results
8. Type-check results
9. Full quality-gate result
10. Real packet-capture verification
11. Detection and alert verification
12. REST API results
13. WebSocket results
14. Browser verification of all 12 routes
15. Analytics and reporting verification
16. Clean-installation results
17. Performance measurements
18. README and documentation changes
19. Screenshots and demo location
20. GitHub repository cleanup results
21. Remaining limitations
22. Final release acceptance decision

Do not claim production readiness.

Do not claim AI/ML capabilities that have not been implemented.

Do not mark the application released unless the release candidate has passed the required checks.

**M20 is complete when NetWatch AI's base application can be installed, run, demonstrated, tested and reproduced from its released GitHub source.**

---

# 24. Final Implementation Report — as delivered

1. **Final application version.** Git tag `v0.0.20`; `/api/v1/system/info`
   reports `app_version: 0.1.0`, `api_version: v1`. The two are separate sequences.
2. **Final release commit.** The `main` commit carrying this document, tagged
   `v0.0.20`.
3. **Git tag.** Annotated, `v0.0.20`, message
   `NetWatch AI Base Application Release v0.0.20`.
4. **Files created.** `backend/scripts/demo_m20.py`,
   `docs/24_M20_Base_Application_Release.md`, `docs/assets/screenshots/` with 12
   PNGs (`01-dashboard` … `12-settings`).
5. **Files modified.** `README.md` (install/use/verify accuracy, corrected
   privilege claim, screenshots section, future-development roadmap),
   `frontend/src/index.css` (local-first font stack, ligatures off),
   `frontend/src/components/Sidebar.tsx` (route reachability),
   `frontend/src/pages/{Alerts,Connections,Detections,Devices,Incidents,LiveTraffic}.tsx`
   (responsive card grid), `frontend/package.json` + `package-lock.json` (package
   renamed to `netwatch-ai-frontend`, advisories resolved), `docs/TODO.md`,
   `docs/Current_Task.md`.
6. **Final backend test results.** 2 615 passed in the backend suite; 145 passed in
   the security suite.
7. **Final frontend test results.** 465 passed across 17 files; 67 passed in the
   live suite against a running backend.
8. **Type-check results.** Backend pyright **0 errors, 0 warnings,
   0 informations** (pyright 1.1.414). Frontend `tsc --noEmit` **exit 0**.
9. **Full quality-gate result.** 9/9 gates ran and passed;
   ```text
   RESULT: PASS
   ```
10. **Real packet-capture verification.** `Wi-Fi`, Windows 11, **unelevated**,
    12 s, 991 packets captured and 991 processed, **0 processing errors**, rows
    persisted and queryable, second stop refused with `CaptureNotRunningError`,
    clean shutdown. A longer session reached 603 845 packets / 319 MB with 0
    errors.
11. **Detection and alert verification.** All five rules exercised positively and
    negatively; finding → alert → evidence → severity/confidence → correlation →
    incident → risk score/band verified end to end; acknowledge, resolve, dismiss
    and false-positive all verified.
12. **REST API results.** 24/24 groups, 60 OpenAPI paths, `/docs`, `/redoc` and
    `/openapi.json` all 200; envelope consistent; 400/404/409/422/501 correct; no
    internal path or stack trace in any response.
13. **WebSocket results.** 4/4 channels connect and deliver real events; heartbeat
    works; a silent client is retired with 1001; queues bounded; no replay claimed.
14. **Browser verification of all 12 routes.** All opened in a real browser against
    the live backend; no blank pages, no unexplained console errors. Five routes
    were unreachable at 900×600 before the fix.
15. **Analytics and reporting verification.** Five analytics views with resolved
    periods and the stored/live distinction intact; six report combinations
    generated, downloaded and opened — CSV 40 361 B, PDF 117 452 B.
16. **Clean-installation results.** Disposable clone, README followed exactly,
    **6/6 gates PASS, `RESULT: PASS`**; the developer's database untouched.
17. **Performance measurements.** Build ~700 ms; sustained capture 603 845 packets
    / 319 MB / ~148 pkt/s; 863 pkt/s peak observed; 0 processing errors; memory
    bounded. No load, soak or multi-machine test was run.
18. **README and documentation changes.** README corrected against measured
    behaviour, screenshots added, future-development section added; `docs/24`
    created; `docs/TODO.md` and `docs/Current_Task.md` updated. All earlier
    milestone records preserved.
19. **Screenshots and demo location.** `docs/assets/screenshots/`;
    `backend/scripts/demo_m20.py`. The raw video is intentionally not committed.
20. **GitHub repository cleanup results.** No tracked `.db`, `.env`, `.venv`,
    `node_modules`, `dist`, report artifact or scratch script; three
    `.env.example` files tracked; largest tracked file 117 156 B. No history
    rewrite or force-push performed.
21. **Remaining limitations.** No authentication, RBAC or TLS; local
    single-operator scope only; five fixed detection rules; devices memory-only;
    no WebSocket replay; SQLite only; capture verified on one adapter on one OS;
    no distributed sensors.
22. **Final release acceptance decision.** **Accepted for release as `v0.0.20`**,
    scoped to local single-operator use.

**Not claimed:** production readiness, enterprise security, safe internet
exposure, or any AI/ML capability. None of the planned AI features exist in this
tag.
