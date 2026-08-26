# NetWatch AI — UI Design

**Project:** NetWatch AI
**UI Design Version:** 1.0
**Status:** In Development
**Primary Design Tool:** Figma / Figma Make
**Frontend:** React + TypeScript + Vite

---

# 1. Overview

The NetWatch AI frontend is designed as a modern Security Operations Center (SOC)-style network monitoring and security analytics interface.

The UI focuses on:

* Real-time network visibility
* Security alert monitoring
* Device investigation
* Network analytics
* Threat analysis
* AI-assisted investigation
* Reporting
* System configuration

The visual design was created in Figma before frontend implementation.

The approved Figma design is the visual reference for the React application.


# 2. Figma Design Source

The NetWatch AI UI was initially designed and refined using Figma and Figma Make.

The exported Figma Make project is included with the frontend source.

Recommended structure:

```text
NetWatch-AI/
│
├── docs/
│   └── 07_UI_Design.md
│
├── frontend/
│   └── figma-design/
│       ├── package.json
│       ├── src/
│       ├── public/
│       ├── index.html
│       └── ...
│
└── backend/
```

The Figma-generated project should remain inside the `frontend/` directory because it represents the starting point for the actual React frontend.

> The exported Figma Make code is a starting implementation of the visual interface. It is not considered the final production architecture until it has been refactored and connected to the NetWatch AI backend.

# 3. Figma Make Export

The exported Figma Make project currently provides the initial React frontend and contains the major application screens.

The exported project uses the following frontend technologies:

* React
* TypeScript
* Vite
* Tailwind CSS
* Recharts
* Lucide React

The generated frontend provides the visual foundation for the application.

The existing UI should be preserved where practical while its simulated data and temporary logic are progressively replaced by real backend functionality.

---

# 4. Design-to-Code Principle

The project follows this workflow:

```text
Figma Design
      ↓
Figma Make Export
      ↓
React Frontend
      ↓
Frontend Refactoring
      ↓
REST API Integration
      ↓
WebSocket Integration
      ↓
Real Network Data
```

The Figma design defines the intended:

* Layout
* Visual hierarchy
* Components
* Colors
* Typography
* Spacing
* Navigation
* Interaction patterns

The implementation may make technical changes where required, but the overall visual language should remain consistent with the approved design.

---

# 5. Design Goals

The interface should be:

* Professional
* Clean
* Information-dense
* Easy to scan
* Suitable for prolonged monitoring
* Security-focused
* Responsive
* Consistent
* Accessible
* Suitable for a portfolio-quality application

The interface should resemble a modern enterprise security platform rather than a generic student dashboard.

---

# 6. Design Inspiration

The visual language takes general inspiration from modern enterprise monitoring and security platforms such as:

* Microsoft Defender
* Microsoft Sentinel
* Grafana
* Elastic Security
* Kibana
* Datadog
* Cisco security products
* Linear-style SaaS interfaces

The project does not attempt to copy the design of any specific product.

---

# 7. Theme

## Primary Theme

Dark mode.

The dark theme provides:

* Strong visual contrast
* Clear alert severity indicators
* Better chart visibility
* Suitable SOC-style appearance

A light theme may be supported later.

---

# 8. Color System

The current design uses a dark blue/slate visual system.

Recommended base palette:

| Purpose        | Color     |
| -------------- | --------- |
| Background     | `#020617` |
| Sidebar        | `#0F172A` |
| Cards          | `#1E293B` |
| Borders        | `#334155` |
| Primary Accent | `#38BDF8` |
| Success        | `#22C55E` |
| Warning        | `#F59E0B` |
| Critical       | `#EF4444` |
| Info           | `#06B6D4` |
| Primary Text   | `#F8FAFC` |
| Secondary Text | `#CBD5E1` |

These values represent the design system and may be centralized into frontend theme variables during implementation.

---

# 9. Typography

Primary font:

**Inter**

Typography hierarchy:

| Element        | Recommended Size |
| -------------- | ---------------: |
| Page Title     |             32px |
| Section Title  |             24px |
| Card Value     |          28–30px |
| Body Text      |          14–16px |
| Table Text     |             14px |
| Secondary Text |          12–14px |

Typography should maintain clear visual hierarchy across all screens.

---

# 10. Spacing System

The UI should follow an approximately 8px spacing system.

Common values:

```text
4px
8px
16px
24px
32px
48px
64px
```

Spacing should remain consistent between:

* Cards
* Sections
* Tables
* Controls
* Navigation elements

---

# 11. Border Radius

Recommended standard:

```text
Cards:       16px
Buttons:     12px
Inputs:      12px
Badges:       8px
Dialogs:     20px
```

The exact values can be adjusted to match reusable components in the frontend.

---

# 12. Navigation Architecture

The main application navigation contains:

```text
Dashboard
Live Traffic
Devices
Alerts
Analytics
Reports
Settings
```

The navigation is represented by a persistent sidebar.

The top navigation contains application-level actions such as:

* Search
* Notifications
* Capture status
* User/profile controls
* Theme controls where applicable

---

# 13. Main Application Layout

```text
+-----------------------------------------------------------+
|                       Top Navigation                      |
+-------------------+---------------------------------------+
|                   |                                       |
|     Sidebar       |             Main Content              |
|                   |                                       |
|                   |                                       |
|                   |                                       |
+-------------------+---------------------------------------+
```

The sidebar remains visually consistent across application pages.

---

# 14. Dashboard

## Purpose

The Dashboard is the primary SOC overview.

It should provide the most important information within a few seconds of opening the application.

---

## Dashboard Components

The dashboard includes:

* Operational status
* Monitoring status
* Capture status
* Threat level
* Packets/sec
* Bandwidth
* Active devices
* Active connections
* Active alerts
* Threat score
* Live traffic chart
* Protocol distribution
* Top talkers
* Recent alerts
* AI insights
* System health
* Quick actions

---

## Dashboard Information Hierarchy

```text
SOC / Operational Status
          ↓
       KPI Cards
          ↓
   Live Network Traffic
          ↓
  Security / Analytics
          ↓
 Alerts + AI Insights
          ↓
 System Health / Actions
```

---

# 15. Dashboard Data Mapping

The UI should eventually consume real backend data.

| UI Element            | Backend Source                     |
| --------------------- | ---------------------------------- |
| Packets/sec           | Traffic Statistics                 |
| Bandwidth             | Traffic Statistics                 |
| Active Devices        | Devices                            |
| Active Connections    | Connections                        |
| Active Alerts         | Alerts                             |
| Threat Score          | Risk Scoring / Alerts              |
| Traffic Chart         | Traffic Statistics                 |
| Protocol Distribution | Protocol Statistics                |
| Top Talkers           | Packets / Connections / Statistics |
| Recent Alerts         | Alerts                             |
| AI Insights           | AI Insights                        |
| System Health         | System Status                      |

---

# 16. Dashboard Real-Time Behavior

Dashboard metrics should eventually be updated through WebSockets.

Target flow:

```text
Network Traffic
      ↓
Packet Capture
      ↓
Statistics Engine
      ↓
WebSocket Service
      ↓
React Dashboard
```

The current Figma Make implementation may contain simulated or generated values. These are temporary and should be replaced by real backend data.

---

# 17. Live Traffic

## Purpose

Provide a real-time packet monitoring interface.

The page should allow analysts to inspect network activity as it occurs.

---

## Main Components

* Packet table
* Search
* Protocol filters
* IP filters
* Port filters
* Time filters
* Severity filters where applicable
* Export
* Pause capture
* Resume capture
* Packet selection

---

# 18. Live Traffic Table

Recommended columns:

```text
Timestamp
Source IP
Destination IP
Protocol
Source Port
Destination Port
Packet Size
TCP Flags
TTL
Status
```

The table should support:

* Sorting
* Filtering
* Search
* Pagination where applicable
* Row selection

---

# 19. Packet Details

Selecting a packet should open a detail view or drawer.

The detail view may contain:

```text
Packet Summary
Ethernet Information
IP Information
TCP/UDP Information
Packet Size
TTL
TCP Flags
Related Device
Related Alerts
Risk Information
```

Future versions may include:

* Hex view
* ASCII view
* Payload details where appropriate
* PCAP reference

Raw payload storage is not part of the default database strategy.

---

# 20. Devices

## Purpose

Provide an inventory of devices observed on the monitored network.

---

## Device Information

Each device may display:

* IP address
* MAC address
* Hostname
* Vendor
* Operating system
* Device type
* Status
* Bandwidth
* Packet count
* Risk score
* Trust score
* Last seen

---

# 21. Device Details

The device investigation interface should contain:

```text
Device Profile
      ↓
Traffic Summary
      ↓
Protocol Usage
      ↓
Connections
      ↓
Historical Activity
      ↓
Alerts
      ↓
Behavioral Information
      ↓
AI Analysis
```

Potential actions:

* View alerts
* View traffic
* View baseline
* Generate report

Blocking devices is not part of the initial implementation.

---

# 22. Alerts

## Purpose

Provide centralized security-event management.

The alert screen should allow an analyst to:

* Search alerts
* Filter by severity
* Filter by status
* Filter by device
* Filter by time
* View confidence
* View risk
* Open investigation details

---

# 23. Alert Severity

The UI should visually distinguish:

```text
Critical
High
Medium
Low
```

Severity should be based on the risk-scoring system.

Risk and confidence should remain separate.

Example:

```text
Risk:       86/100
Confidence: 94%
Severity:   High
```

---

# 24. Alert Investigation

The investigation interface should provide:

```text
Alert Summary
      ↓
Risk Score
      ↓
Detection Rule
      ↓
Affected Device
      ↓
Evidence
      ↓
Related Packets
      ↓
Related Connections
      ↓
Behavioral Evidence
      ↓
ML Analysis
      ↓
AI Explanation
      ↓
Recommendation
```

This should provide a unified analyst workflow.

---

# 25. Analytics

## Purpose

Provide historical network and security analytics.

Expected visualizations include:

* Traffic trends
* Bandwidth
* Protocol distribution
* Top ports
* Top devices
* Threat trends
* Alert trends
* Packet statistics
* Connection statistics

Charts should support appropriate time ranges.

---

# 26. Reports

## Purpose

Provide report generation and report history.

Supported report concepts:

```text
Daily
Weekly
Monthly
Custom
```

Supported output formats:

```text
PDF
CSV
```

Potential report sections:

* Traffic summary
* Security summary
* Top devices
* Protocol usage
* Alerts
* Threat trends
* Recommendations

The current UI is a visual representation; actual report generation will be implemented by the backend.

---

# 27. Settings

The Settings page provides configuration for the platform.

Sections include:

```text
General
Network Interface
Capture Engine
Detection Rules
Alert Thresholds
AI Settings
Database
Backup
Theme
Notifications
System Information
```

---

# 28. Settings-to-Backend Mapping

| UI Section         | Backend Area           |
| ------------------ | ---------------------- |
| Network Interface  | Capture Service        |
| Capture Engine     | Capture Service        |
| Detection Rules    | Detection Rule Service |
| Alert Thresholds   | Detection Engine       |
| AI Settings        | AI Service             |
| Database           | Database Service       |
| Backup             | Backup Service         |
| Notifications      | Notification Service   |
| System Information | System Status          |
| Theme              | Frontend Settings      |

Only configuration options backed by implemented functionality should be exposed as active controls.

---

# 29. System Health

System health is represented in the UI through operational status indicators.

Potential components:

```text
Capture Engine
Database
API
WebSocket
Detection Engine
ML Engine
AI Engine
```

Example:

```text
Capture Engine     Healthy
Database           Healthy
API                Healthy
WebSocket          Connected
Detection Engine   Healthy
ML Engine          Ready
AI Engine          Available
```

If an optional component such as the AI engine fails, core monitoring should continue.

---

# 30. AI Insights UI

The AI Insights component provides analyst-oriented information.

Example:

```text
AI Insight

Elevated DNS Activity Detected

Device:
192.168.1.25

Risk:
72/100

Confidence:
89%

Recommendation:
Investigate recent DNS activity.
```

The information must originate from the AI Analysis Engine rather than from hard-coded frontend text in the final implementation.

---

# 31. Quick Actions

The dashboard may expose common actions such as:

```text
Start Capture
Stop Capture
Generate Report
Export CSV
```

These actions should communicate with backend services through the API.

---

# 32. Notification System

The top navigation contains a notification interface.

Notification types may include:

* New security alert
* Capture started
* Capture stopped
* Report generated
* System warning
* AI availability change

Real-time notification updates should use the WebSocket layer where appropriate.

---

# 33. Loading States

The application should not display blank screens while data is loading.

Recommended states:

* Skeleton loaders
* Loading indicators
* Disabled action buttons during operations

Example:

```text
Loading traffic data...
```

---

# 34. Empty States

Empty states should explain what the user can do next.

Example:

```text
No packets captured yet.

Start network capture to begin monitoring.
```

Other examples:

```text
No alerts found.
No devices discovered.
No reports generated.
```

---

# 35. Error States

Errors should be visible and understandable.

Example:

```text
Unable to access network interface.

Check the selected interface and
capture permissions.
```

The UI should not expose raw backend stack traces to users.

---

# 36. Success States

Successful operations should provide lightweight confirmation.

Examples:

```text
Capture started successfully.
Report generated successfully.
Settings saved.
Alert acknowledged.
```

Toast notifications can be used for short-lived confirmations.

---

# 37. Responsive Design

The application should support:

* Desktop
* Tablet
* Mobile

## Desktop

Full sidebar and multi-column dashboard.

## Tablet

Sidebar may collapse.

Cards should wrap appropriately.

## Mobile

The layout should become single-column where appropriate.

Large tables may use:

* Horizontal scrolling
* Condensed columns
* Detail drawers

---

# 38. Component Architecture

The frontend should be built from reusable components.

Recommended structure:

```text
components/
│
├── common/
│   ├── Button
│   ├── Badge
│   ├── Modal
│   ├── Drawer
│   ├── Toast
│   ├── Loading
│   └── EmptyState
│
├── dashboard/
│   ├── StatCard
│   ├── TrafficChart
│   ├── ThreatGauge
│   ├── AIInsight
│   ├── TopTalkers
│   ├── RecentAlerts
│   └── SystemHealth
│
├── traffic/
│   ├── PacketTable
│   ├── PacketFilters
│   └── PacketDetails
│
├── devices/
│   ├── DeviceTable
│   ├── DeviceCard
│   └── DeviceDetails
│
├── alerts/
│   ├── AlertTable
│   ├── AlertCard
│   ├── AlertFilters
│   └── AlertInvestigation
│
└── charts/
    ├── TrafficChart
    ├── ProtocolChart
    ├── ThreatChart
    └── BandwidthChart
```

The exact final component breakdown may evolve during implementation.

---

# 39. Page Architecture

Recommended pages:

```text
pages/
│
├── Dashboard.tsx
├── LiveTraffic.tsx
├── PacketDetails.tsx
├── Devices.tsx
├── DeviceDetails.tsx
├── Alerts.tsx
├── AlertInvestigation.tsx
├── Analytics.tsx
├── Reports.tsx
└── Settings.tsx
```

The current Figma Make export already provides the primary pages:

```text
Dashboard
Live Traffic
Devices
Alerts
Analytics
Reports
Settings
```

Packet Details, Device Details, and Alert Investigation can initially exist as detail views/drawers and later become dedicated routes if required.

---

# 40. Frontend Service Architecture

Frontend pages should not contain direct backend communication logic.

Recommended:

```text
src/
└── services/
    ├── api.ts
    ├── dashboard.ts
    ├── packets.ts
    ├── devices.ts
    ├── alerts.ts
    ├── analytics.ts
    ├── reports.ts
    ├── settings.ts
    └── ai.ts
```

Example:

```text
Dashboard
   ↓
dashboardService
   ↓
REST API
   ↓
FastAPI
```

This keeps UI components independent from backend implementation details.

---

# 41. WebSocket Integration

The UI should eventually use WebSockets for real-time information.

Planned channels:

```text
/ws/dashboard
/ws/packets
/ws/alerts
/ws/system
```

Example:

```text
Network Traffic
      ↓
Packet Processing
      ↓
WebSocket Service
      ↓
React Hook
      ↓
UI Component
```

The current Figma Make implementation may use simulated timers or generated values for visual demonstration. Those mechanisms are temporary and should be replaced by the real WebSocket implementation.

---

# 42. TypeScript Type Architecture

Shared API and data types should be centralized.

Recommended:

```text
src/
└── types/
    ├── packet.ts
    ├── device.ts
    ├── alert.ts
    ├── dashboard.ts
    ├── analytics.ts
    ├── report.ts
    ├── settings.ts
    └── websocket.ts
```

Example:

```typescript
export interface Packet {
  id: number;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol: string;
  packetLength: number;
}
```

The same data contract should be used consistently throughout the frontend.

---

# 43. Current Figma Make State

The exported Figma Make project should be considered a **frontend prototype / starting implementation**.

The current interface may contain:

* Mock data
* Static data
* Generated values
* Temporary interactions

These are acceptable during UI development.

They must not be treated as evidence that the backend functionality already exists.

The implementation process will progressively replace them with:

```text
Mock Data
   ↓
API Data
   ↓
Real Network Data
```

---

# 44. Frontend Refactoring Plan

The Figma export should be refactored incrementally.

## Step 1

Preserve the visual design.

## Step 2

Clean component structure.

## Step 3

Centralize TypeScript types.

## Step 4

Create API service layer.

## Step 5

Create reusable hooks.

## Step 6

Add WebSocket service.

## Step 7

Replace mock data.

## Step 8

Connect real backend APIs.

## Step 9

Add real-time updates.

## Step 10

Test responsive behavior.

---

# 45. Figma Export Directory

The exported Figma Make project should remain inside the frontend directory.

Recommended:

```text
frontend/
└── figma-design/
```

Example:

```text
NetWatch-AI/
│
├── backend/
│
├── frontend/
│   └── figma-design/
│       ├── src/
│       ├── package.json
│       ├── vite.config.ts
│       └── ...
│
└── docs/
```

If the Figma export is later renamed to become the primary frontend, the final structure can be simplified.

For example:

```text
frontend/
├── src/
├── package.json
├── vite.config.ts
└── ...
```

---

# 46. Figma as Source of Visual Truth

The Figma design should remain the primary reference for:

* Layout
* Visual hierarchy
* Color usage
* Typography
* Component appearance
* Navigation
* Charts
* Alert presentation
* System states

The React implementation should reproduce the approved design while using real application data.

---

# 47. Design-to-Implementation Mapping

```text
Figma Component
      ↓
React Component
      ↓
Data Interface
      ↓
API Service
      ↓
Backend Endpoint
      ↓
Database / Processing Engine
```

Example:

```text
Figma:
Packets/sec Card

        ↓

React:
StatCard

        ↓

Service:
getDashboardMetrics()

        ↓

FastAPI:
GET /api/v1/dashboard

        ↓

Backend:
Statistics Engine

        ↓

Network:
Real packet traffic
```

---

# 48. Security UI Principles

The dashboard should prioritize security information using:

* Clear severity indicators
* Strong visual hierarchy
* Distinct alert states
* Risk and confidence separation
* Source/destination visibility
* Evidence accessibility
* Investigation context

The interface should avoid visual noise that makes important security events difficult to identify.

---

# 49. Accessibility

The frontend should eventually support:

* Sufficient color contrast
* Keyboard navigation
* Descriptive labels
* Accessible buttons
* Tooltips for icon-only controls
* Semantic HTML where appropriate
* Non-color indicators for severity

Severity should not be communicated using color alone.

Example:

```text
🔴 Critical
🟠 High
🟡 Medium
🔵 Low
```

---

# 50. UI Security Considerations

The frontend should:

* Avoid displaying secrets.
* Avoid displaying authentication tokens.
* Sanitize user-generated content where applicable.
* Avoid rendering untrusted HTML.
* Validate user input.
* Handle API errors safely.
* Avoid exposing backend implementation details.

---

# 51. UI Performance Considerations

Live network monitoring can generate large amounts of data.

The frontend should therefore:

* Limit the number of simultaneously rendered packets.
* Use pagination or virtualization for large tables.
* Avoid unnecessary re-renders.
* Throttle non-critical dashboard updates where appropriate.
* Use WebSockets for real-time streams rather than repeated polling.
* Aggregate high-frequency metrics before visualization.

---

# 52. UI Testing

The frontend should eventually include tests for:

* Component rendering
* API states
* Loading states
* Empty states
* Error states
* Filtering
* Search
* Alert interactions
* Capture controls
* WebSocket updates
* Responsive layout

Important user flows:

```text
Start Capture
      ↓
Traffic Appears
      ↓
Device Discovered
      ↓
Detection Triggered
      ↓
Alert Appears
      ↓
Open Alert
      ↓
View Evidence
      ↓
View AI Explanation
```

---

# 53. Final UI Architecture

```text
                         NetWatch AI UI
                              |
              +---------------+---------------+
              |                               |
              v                               v
        Navigation Layer                Main Content
              |                               |
              |                  +------------+------------+
              |                  |            |            |
              v                  v            v            v
          Dashboard          Traffic       Devices      Alerts
                                |            |             |
                                +------------+-------------+
                                             |
                                      Analytics / Reports
                                             |
                                          Settings
```

Data layer:

```text
React Components
      |
      +------ REST Services
      |
      +------ WebSocket Hooks
      |
      v
FastAPI Backend
```

---

# 54. Final Frontend Architecture

```text
frontend/
│
├── figma-design/
│   └── Original Figma Make Export
│
└── src/
    │
    ├── components/
    ├── pages/
    ├── layouts/
    ├── charts/
    ├── services/
    ├── hooks/
    ├── types/
    ├── utils/
    └── assets/
```

The exact final structure may be simplified once the Figma-generated project is refactored.

---

# 55. UI Development Roadmap

## Phase 1 — Preserve Design

* Integrate Figma export.
* Preserve existing visual system.
* Confirm all primary screens.
* Remove unused design code.

## Phase 2 — Frontend Architecture

* Refactor components.
* Create shared types.
* Create service layer.
* Create reusable hooks.
* Introduce proper routing where needed.

## Phase 3 — Backend Integration

Connect:

* Dashboard API
* Devices API
* Alerts API
* Analytics API
* Reports API
* Settings API

## Phase 4 — Real-Time Integration

Connect:

* Dashboard WebSocket
* Packet WebSocket
* Alert WebSocket
* System WebSocket

## Phase 5 — Security Intelligence

Integrate:

* Detection results
* Risk scores
* Behavioral anomalies
* ML results
* AI insights

---

# 56. Current UI Status

```text
Design Concept                  ✅
Wireframes                      ✅
High-Fidelity Figma Design     ✅
Figma Make Export              ✅
React Prototype                ✅
Real Backend Integration       ⬜
Real Packet Data               ⬜
WebSocket Integration          ⬜
Real Detection Data            ⬜
Real ML Data                   ⬜
Real AI Insights               ⬜
```

The Figma frontend is therefore considered **design-complete / prototype-ready**, while the application functionality remains under development.

---

# 57. Conclusion

The NetWatch AI UI is designed as a professional SOC-style interface for network monitoring, security detection, investigation, analytics, and reporting.

The Figma design provides the visual source of truth, while the exported Figma Make project provides the initial React implementation.

The frontend will be progressively transformed from a UI prototype with simulated data into a real security application:

```text
Figma Design
      ↓
React Prototype
      ↓
Frontend Refactoring
      ↓
FastAPI Integration
      ↓
WebSocket Integration
      ↓
Real Network Telemetry
      ↓
Real Detection Results
      ↓
ML Anomaly Detection
      ↓
AI-Assisted Investigation
      ↓
Production-Ready NetWatch AI
```

The Figma export should remain under the `frontend/` directory during development so that the original design implementation is preserved and can be compared against the refactored production frontend.

# 53. Additional Security Analytics Views

The following views are required to expose the behavioral and machine-learning
components of the NetWatch AI detection architecture through the frontend.

---

## 53.1 Device Behavioral Profile

The Device Details interface should expose the behavioral baseline associated
with the selected device.

The view should display:

- Baseline status
- Learning progress
- Normal packets/sec
- Current packets/sec
- Normal bandwidth
- Current bandwidth
- Normal destination count
- Current destination count
- Normal port usage
- Current port usage
- Behavioral deviation score

Example:

```text
Device Behavioral Profile

192.168.1.25

Baseline Status:
Active

Normal Traffic:
40–120 packets/sec

Current:
850 packets/sec

Behavioral Deviation:
91/100

The baseline information is provided by the Behavioral Detection Engine.

53.2 Correlated Incident View

The Alert Investigation interface should provide a correlated view of
multiple related detection signals.

Example:

Incident #1042

Potential Network Reconnaissance

Correlated Events:

✓ Port Scan
✓ High SYN Rate
✓ Failed Connections
✓ Behavioral Anomaly
✓ ML Anomaly

Risk Score:
86/100

Confidence:
94%

The correlated incident should identify:

Related alerts
Source device
Destination
Detection rules
Behavioral findings
ML findings
Timeline
Final risk score
Confidence
Recommended action

The Correlation Engine is responsible for determining which individual
detection events belong to the same security incident.

53.3 ML Anomaly Details

The platform should expose the machine-learning analysis associated with
a security finding.

The view should include:

Model name
Model version
Anomaly score
Behavioral deviation
Feature values
Analysis timestamp

Example:

ML Anomaly Analysis

Model:
Isolation Forest

Anomaly Score:
0.91

Behavioral Deviation:
0.88

Features:

Packets/sec             850
Unique Ports             61
Unique Destinations      27
Failed Connections       48
Average Packet Size     812

The ML result is an input to the risk-scoring and correlation pipeline and
should not independently determine that an attack has occurred.


Then add this section too:

```markdown
# 54. V1 vs Future UI Features

Not every control visible in the Figma prototype represents functionality
that will be implemented in Version 1.

## Version 1

The initial release focuses on:

- SQLite
- NetWatch rule detection
- Behavioral detection
- Isolation Forest anomaly detection
- Local network monitoring
- Local reporting
- Core dashboard functionality

## Future / Planned

The following UI capabilities may be retained as disabled, informational,
or "Coming Soon" features until the corresponding backend functionality
exists:

- PostgreSQL configuration
- Suricata integration
- Zeek integration
- Automatic host blocking
- Slack integration
- Webhooks
- Advanced threat intelligence
- Distributed sensors
- Enterprise authentication/RBAC

UI elements should not imply that a feature is implemented when its backend
functionality does not yet exist.

And finally:

# 55. Final V1 UI Scope

The finalized Version 1 interface consists of:

```text
Dashboard
│
├── SOC Status
├── KPI Cards
├── Live Traffic
├── Threat Score
├── Protocol Distribution
├── Top Talkers
├── Recent Alerts
├── AI Insights
├── System Health
└── Quick Actions

Live Traffic
└── Packet Details

Devices
└── Device Details
    └── Behavioral Profile

Alerts
└── Alert Investigation
    └── Correlated Incident
    └── ML Anomaly Details

Analytics

Reports

Settings

The Figma Make export in the frontend/ directory serves as the starting
frontend implementation of this design.