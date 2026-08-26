# NetWatch AI — System Architecture

**Project:** NetWatch AI  
**Architecture Version:** 1.0  
**Status:** In Development

---

# 1. Overview

NetWatch AI follows a modular, local-first architecture designed to separate network packet collection, data processing, security detection, analytics, backend services, and frontend presentation.

The architecture is designed around the following principles:

- Modularity
- Separation of concerns
- Real-time processing
- Explainability
- Extensibility
- Local-first operation
- Low cost
- Testability

The system should allow individual components to be replaced or upgraded without requiring a complete redesign.

---

# 2. High-Level Architecture


                         +----------------------+
                         |      NETWORK         |
                         | Router / Switch / VM |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | Packet Capture Engine |
                         |       Scapy          |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | Packet Processing    |
                         |      Engine          |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | Feature Extraction   |
                         |       Engine         |
                         +----------+-----------+
                                    |
              +---------------------+----------------------+
              |                     |                      |
              v                     v                      v
      +---------------+     +---------------+      +---------------+
      | Rule Engine   |     | Behavioral    |      | ML Anomaly    |
      |               |     | Detection     |      | Detection     |
      +-------+-------+     +-------+-------+      +-------+-------+
              |                     |                      |
              +---------------------+----------------------+
                                    |
                                    v
                         +----------------------+
                         | Correlation Engine   |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | Risk Scoring Engine  |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | Alert Management     |
                         | Engine                |
                         +----------+-----------+
                                    |
                         +----------+----------+
                         |                     |
                         v                     v
                +----------------+    +----------------+
                | Evidence Store |    | AI Analysis   |
                +-------+--------+    +-------+--------+
                        |                     |
                        +----------+----------+
                                   |
                                   v
                         +----------------------+
                         | Database Layer       |
                         | SQLite               |
                         +----------+-----------+
                                    |
                   +----------------+----------------+
                   |                                 |
                   v                                 v
          +------------------+              +------------------+
          | REST API         |              | WebSocket        |
          | FastAPI          |              | Service          |
          +--------+---------+              +--------+---------+
                   |                                 |
                   +----------------+----------------+
                                    |
                                    v
                         +----------------------+
                         | React Dashboard      |
                         | NetWatch AI UI       |
                         +----------------------+


3. Architecture Layers

The system is divided into the following logical layers:

1. Network Layer
2. Capture Layer
3. Processing Layer
4. Detection Layer
5. Security Intelligence Layer
6. Persistence Layer
7. Application/API Layer
8. Presentation Layer
4. Network Layer

The network layer represents the traffic monitored by NetWatch AI.

Possible sources:

Local Wi-Fi interface
Ethernet interface
Virtual machine network
Host-only network
NAT network
Lab network
Authorized test environment

Example:

Kali Linux VM
      |
      v
Virtual Network
      |
      v
Metasploitable VM
      |
      v
NetWatch AI Sensor

The project should initially focus on monitoring traffic that the local machine is authorized and technically able to capture.

5. Packet Capture Layer
Component

Packet Capture Engine

Technology
Python
Scapy
Responsibilities
Detect available network interfaces
Select capture interface
Start packet capture
Stop packet capture
Apply basic capture filters where appropriate
Forward captured packets to the processing pipeline
Track capture statistics

Input:

Network Interface

Output:

Raw Packet

The capture layer should remain independent from the detection engine.

This allows the capture implementation to be replaced or extended later.

6. Packet Processing Layer
Component

Packet Processing Engine

The processor converts raw packets into a normalized internal representation.

Responsibilities:

Parse Ethernet information
Parse IP information
Parse TCP information
Parse UDP information
Parse ICMP information
Extract timestamps
Extract packet size
Extract TCP flags
Validate available fields
Handle malformed or incomplete packets

Example transformation:

Raw Scapy Packet
       |
       v
Packet Parser
       |
       v
Normalized Packet

Example normalized object:

{
  "timestamp": "2026-08-24T20:15:32Z",
  "source_ip": "192.168.1.20",
  "destination_ip": "8.8.8.8",
  "source_port": 52341,
  "destination_port": 443,
  "protocol": "TCP",
  "packet_size": 1460,
  "ttl": 64,
  "tcp_flags": "ACK"
}
7. Feature Extraction Layer

The Feature Extraction Engine converts packets and connections into features used by:

Statistics Engine
Behavioral Detection
Rule Detection
ML Anomaly Detection
Packet Features
Source IP
Destination IP
Source port
Destination port
Protocol
Packet size
TTL
TCP flags
Timestamp
Aggregated Features
Packets/sec
Bytes/sec
Unique destinations
Unique ports
Connection count
Failed connection ratio
SYN ratio
Protocol distribution
DNS request rate
ICMP request rate
Average packet size

Feature extraction should produce reusable structured data rather than duplicating logic across different detectors.

8. Statistics Layer
Component

Statistics Engine

The Statistics Engine maintains real-time and historical network metrics.

Metrics include:

Packets/sec
Bandwidth
Active connections
Active devices
Protocol distribution
Top talkers
Top ports
Packet size distribution
Traffic trends

The statistics layer feeds the dashboard and analytics APIs.

9. Device Discovery Layer
Component

Device Discovery Engine

The device engine tracks devices observed in the network.

Possible information:

IP address
MAC address
Hostname
Vendor
Device type
Operating system when available
First seen
Last seen
Traffic volume
Risk score
Status

Example:

Observed Traffic
       |
       v
Identify Source / Destination
       |
       v
Match Existing Device
       |
   +---+---+
   |       |
  Yes      No
   |       |
Update    Create
Device    Device
10. Detection Layer

The detection layer contains multiple independent detection mechanisms.

Detection Layer
│
├── Rule Detection
├── Behavioral Detection
└── ML Anomaly Detection

The components should produce standardized detection results.

11. Rule Detection Engine

The Rule Engine detects predefined suspicious behaviors.

Initial capabilities:

Port scan
SYN flood
ICMP flood
Internal scan
DNS anomaly
High bandwidth
Suspicious port activity

Rules should be:

Modular
Configurable
Explainable
Independently testable

The system should avoid hard-coding every possible attack.

12. Behavioral Detection Engine

The Behavioral Detection Engine identifies deviations from the normal behavior of devices.

It maintains device-specific baselines.

Example:

Device A

Normal:
Packets/sec = 50–100

Current:
Packets/sec = 2,500

        ↓

Behavioral Deviation

The engine should consider multiple behavioral dimensions:

Traffic volume
Connection frequency
Destination count
Port usage
Protocol distribution
DNS behavior

New devices should initially enter a learning state.

13. Machine Learning Layer
Component

ML Anomaly Detection Engine

The initial implementation should use an unsupervised anomaly detection model such as Isolation Forest.

The ML system analyzes aggregated feature windows rather than raw packets.

Example:

10-second Window

Packets/sec
Bytes/sec
Unique destinations
Unique ports
TCP ratio
UDP ratio
Failed connections
DNS request rate

Output:

Normal
or
Anomalous

plus an anomaly score.

The ML component provides an additional signal to the detection and correlation pipeline.

14. Correlation Layer
Component

Correlation Engine

The Correlation Engine combines related security findings.

Example:

Port Scan
     +
High SYN Rate
     +
Failed Connections
     +
Behavioral Anomaly
     |
     v
Potential Network Reconnaissance

Without correlation, these may become separate alerts.

With correlation, they can become a single higher-quality security finding.

Responsibilities:

Group related events
Apply time windows
Avoid duplicate findings
Build incident context
Forward correlated events to the risk engine
15. Risk Scoring Layer
Component

Risk Scoring Engine

Risk scoring combines several signals.

Conceptually:

Rule Evidence
      +
Behavioral Deviation
      +
ML Anomaly
      +
Asset Context
      +
Historical Context
      |
      v
Final Risk Score

Initial conceptual weighting:

Rule Evidence          40%
Behavioral Deviation   25%
ML Anomaly             20%
Asset Context          10%
Historical Context      5%

These weights are design starting points and should be validated using testing data.

16. Risk and Confidence

The system should distinguish:

Risk

How potentially harmful the behavior appears.

Confidence

How strong the evidence is that the detection is accurate.

Example:

Risk:       88
Confidence: 74%

This means the potential impact is high but evidence is not conclusive.

17. Alert Management Layer
Component

Alert Management Engine

Responsibilities:

Generate alerts
Assign severity
Store evidence
Deduplicate alerts
Update status
Associate devices
Associate detection rules
Associate related packets
Trigger AI analysis
Publish real-time updates

Alert lifecycle:

New
 |
 v
Acknowledged
 |
 v
Investigating
 |
 +----------------+
 |                |
 v                v
Resolved      False Positive
18. Evidence Layer

Every meaningful alert should retain supporting evidence.

Evidence may include:

Packet references
Connection information
Feature values
Rule results
Baseline comparison
ML anomaly score
Source device
Destination device
Related events

This supports investigation and makes alerts explainable.

19. AI Analysis Layer
Component

AI Analysis Engine

AI operates after the security event has been structured by the detection pipeline.

The AI should not analyze every packet.

Flow:

Detection
    |
    v
Structured Security Event
    |
    v
AI Analysis
    |
    +--> Summary
    +--> Explanation
    +--> Investigation Guidance
    +--> Recommendation

The AI should only use evidence provided by the application.

It should not invent packet details, observations, or threat intelligence.

20. Persistence Layer
Database

Initial:

SQLite

The database stores persistent application and security information.

Primary entities:

Users
Devices
Packets
Connections
Alerts
Alert Evidence
Detection Rules
Traffic Statistics
Protocol Statistics
Reports
Settings
AI Insights
System Status
Notifications

Database design is documented separately in:

03_Database_Design.md
21. Application Layer
Backend

FastAPI

The backend provides:

REST APIs
WebSocket endpoints
Business logic
Database access
Capture management
Detection orchestration
Report generation
Settings management

The backend should act as the central coordination layer between the processing engines and frontend.

22. REST API Layer

The REST API provides historical and configuration-oriented operations.

Examples:

GET  /api/v1/dashboard
GET  /api/v1/packets
GET  /api/v1/devices
GET  /api/v1/alerts
GET  /api/v1/analytics/traffic

POST /api/v1/capture/start
POST /api/v1/capture/stop

PUT  /api/v1/settings

Complete endpoint definitions are maintained in:

04_API_Specification.md
23. WebSocket Layer

WebSockets provide real-time updates to the dashboard.

Proposed channels:

/ws/packets
/ws/dashboard
/ws/alerts
/ws/system

Example:

Packet Capture
      |
      v
Processed Event
      |
      v
WebSocket Service
      |
      v
React Dashboard

The dashboard can therefore update without repeatedly refreshing the page.

24. Presentation Layer
Frontend

The frontend uses:

React
Vite
TypeScript
Tailwind CSS
Charting library

The interface follows the Figma design created for NetWatch AI.

Primary pages:

Dashboard
Live Traffic
Packet Details
Devices
Device Details
Alerts
Alert Investigation
Analytics
Reports
Settings
25. Frontend Data Flow

Historical data:

React
 |
 v
REST API
 |
 v
FastAPI
 |
 v
Database
 |
 v
FastAPI
 |
 v
React

Real-time data:

Packet Capture
 |
 v
Processing
 |
 v
Detection / Statistics
 |
 v
WebSocket
 |
 v
React
26. Real-Time Dashboard Flow

Example:

Network Packet
      |
      v
Scapy Capture
      |
      v
Packet Processing
      |
      +------------------+
      |                  |
      v                  v
Statistics          Detection
      |                  |
      +---------+--------+
                |
                v
           Event Manager
                |
         +------+------+
         |             |
         v             v
      Database      WebSocket
                        |
                        v
                    Dashboard
27. Capture Control Flow

When the user presses Start Capture:

React
 |
 | POST /capture/start
 v
FastAPI
 |
 v
Capture Manager
 |
 v
Scapy
 |
 v
Network Interface

When the user presses Stop Capture:

React
 |
 | POST /capture/stop
 v
FastAPI
 |
 v
Capture Manager
 |
 v
Scapy Capture Stops
28. Alert Flow
Packet
 |
 v
Feature Extraction
 |
 v
Detection
 |
 v
Correlation
 |
 v
Risk Scoring
 |
 v
Alert Created
 |
 +------------+
 |            |
 v            v
Database    AI Analysis
 |            |
 +-----+------+
       |
       v
WebSocket
       |
       v
Dashboard Alert
29. Report Generation Flow
User
 |
 v
React Reports Page
 |
 v
POST /reports/generate
 |
 v
FastAPI
 |
 v
Report Service
 |
 +----------+----------+
 |                     |
 v                     v
Database Data       Analytics
 |                     |
 +----------+----------+
            |
            v
      Report Generator
            |
       +----+----+
       |         |
       v         v
      PDF       CSV
30. Settings Flow

Settings such as:

Network interface
Detection thresholds
Alert configuration
AI settings
Theme
Data retention

should be managed through the backend.

React Settings
      |
      v
FastAPI
      |
      v
Settings Service
      |
      v
SQLite

The detection engine reads validated configuration from the settings service.

31. Error Handling Architecture

Errors should be isolated between modules.

Example:

Packet Capture Error
        |
        v
Capture Manager
        |
        v
Log Error
        |
        v
System Status
        |
        v
Dashboard Notification

A malformed packet should not terminate the entire application.

Similarly, failure of an optional AI component should not stop packet capture or rule-based detection.

32. Failure Isolation

NetWatch AI should continue providing core monitoring even if individual optional components fail.

Example:

AI Engine DOWN
     |
     +--> Packet Capture      ✓
     +--> Statistics         ✓
     +--> Rule Detection     ✓
     +--> Alerts             ✓
     +--> Dashboard          ✓
     +--> AI Explanation     ✗

This is important for overall system reliability.

33. Performance Architecture

High-volume network traffic should not be processed using expensive operations indiscriminately.

The architecture therefore uses:

Short feature windows
In-memory counters
Aggregation
Batched database operations where appropriate
Indexed database queries
ML analysis on aggregated features
AI analysis only for relevant security events
Configurable raw packet retention
34. Data Retention Architecture

Raw packet data can grow quickly.

The recommended strategy is:

Raw Packets
   |
   | Short retention
   v
Rolling Storage
   |
   v
Traffic Summaries
   |
   | Longer retention
   v
Historical Analytics

Initial retention targets should be configurable.

35. Security Architecture

The application should follow basic secure-development practices.

API
Input validation
Parameterized database queries
Error handling
Controlled CORS
Authentication in future versions
Database
Foreign keys
Restricted access
Sensitive data minimization
Configuration

Secrets and environment-specific configuration should be stored outside source code.

Monitoring

Application logs should avoid unnecessarily exposing sensitive network information.

36. Scalability Strategy

The first release is designed for:

Single Machine
        +
Single Network Sensor
        +
SQLite

Future versions can evolve toward:

Multiple Sensors
       |
       v
Message Broker
       |
       v
Central Processing
       |
       v
PostgreSQL / Time-Series DB
       |
       v
Central Dashboard

Potential future technologies:

PostgreSQL
Redis
TimescaleDB
Docker
Message queues
Multiple remote sensors

These are future considerations and are not required for the initial implementation.

37. Extensibility

The architecture should allow components to be replaced or expanded.

Examples:

Capture
Scapy
   |
   +--> Future alternative capture source
Detection
NetWatch Rules
   +
Behavioral Detection
   +
ML
   +
Future Suricata Events
   +
Future Zeek Events
Database
SQLite
   |
   v
PostgreSQL
AI
Local ML/AI
   |
   v
Alternative Local Model
38. Recommended Backend Module Structure
backend/
│
├── app/
│   ├── api/
│   │   ├── routes/
│   │   └── dependencies.py
│   │
│   ├── capture/
│   │   ├── interface_manager.py
│   │   └── capture_engine.py
│   │
│   ├── processing/
│   │   ├── packet_parser.py
│   │   ├── normalizer.py
│   │   └── feature_extractor.py
│   │
│   ├── statistics/
│   │   └── statistics_engine.py
│   │
│   ├── devices/
│   │   └── device_engine.py
│   │
│   ├── detection_engine/
│   │   ├── engine.py
│   │   ├── context.py
│   │   ├── correlation.py
│   │   ├── risk_scorer.py
│   │   ├── deduplicator.py
│   │   ├── state_manager.py
│   │   ├── rules/
│   │   ├── behavioral/
│   │   └── ml/
│   │
│   ├── alerts/
│   │   └── alert_service.py
│   │
│   ├── ai/
│   │   └── ai_service.py
│   │
│   ├── reports/
│   │   └── report_service.py
│   │
│   ├── websocket/
│   │   └── manager.py
│   │
│   ├── database/
│   │   ├── models/
│   │   ├── repositories/
│   │   └── session.py
│   │
│   ├── config/
│   │   └── settings.py
│   │
│   └── main.py
│
└── tests/
39. Recommended Frontend Structure
frontend/
│
├── src/
│   ├── components/
│   │   ├── dashboard/
│   │   ├── traffic/
│   │   ├── devices/
│   │   ├── alerts/
│   │   ├── analytics/
│   │   ├── reports/
│   │   └── common/
│   │
│   ├── pages/
│   ├── layouts/
│   ├── charts/
│   ├── hooks/
│   ├── services/
│   ├── types/
│   ├── utils/
│   └── main.tsx
40. Architectural Principles

NetWatch AI follows these principles:

Separate data collection from detection.
Separate detection from AI explanation.
Prefer structured events over tightly coupled components.
Keep detection modules independently testable.
Use WebSockets for real-time telemetry.
Use REST APIs for historical and configuration data.
Minimize raw packet retention.
Keep high-volume processing efficient.
Make detection thresholds configurable.
Isolate failures between components.
Keep the initial deployment simple and local.
Design future interfaces so the platform can scale.
41. Final End-to-End Architecture
                         ┌───────────────────────┐
                         │       NETWORK         │
                         └───────────┬───────────┘
                                     │
                                     v
                         ┌───────────────────────┐
                         │ Packet Capture Engine │
                         └───────────┬───────────┘
                                     │
                                     v
                         ┌───────────────────────┐
                         │ Packet Processing     │
                         └───────────┬───────────┘
                                     │
                                     v
                         ┌───────────────────────┐
                         │ Feature Extraction    │
                         └───────────┬───────────┘
                                     │
                 +-------------------+-------------------+
                 |                   |                   |
                 v                   v                   v
          Rule Detection      Behavioral Detection   ML Detection
                 |                   |                   |
                 +-------------------+-------------------+
                                     |
                                     v
                         ┌───────────────────────┐
                         │ Correlation Engine    │
                         └───────────┬───────────┘
                                     │
                                     v
                         ┌───────────────────────┐
                         │ Risk Scoring Engine   │
                         └───────────┬───────────┘
                                     │
                                     v
                         ┌───────────────────────┐
                         │ Alert Management      │
                         └───────────┬───────────┘
                                     │
                        +------------+------------+
                        |                         |
                        v                         v
                 Evidence Store             AI Analysis
                        |                         |
                        +------------+------------+
                                     |
                                     v
                              SQLite Database
                                     |
                        +------------+------------+
                        |                         |
                        v                         v
                    REST API                 WebSocket
                        |                         |
                        +------------+------------+
                                     |
                                     v
                         ┌───────────────────────┐
                         │ React Dashboard       │
                         │       NetWatch AI     │
                         └───────────────────────┘
42. Conclusion

The NetWatch AI architecture separates network collection, processing, detection, analytics, persistence, API services, and presentation into modular layers.

The most important architectural characteristic is the hybrid detection pipeline:

Rules
  +
Behavior
  +
ML
  ↓
Correlation
  ↓
Risk
  ↓
Alert
  ↓
AI Analysis

This allows NetWatch AI to detect known suspicious patterns while also identifying unusual behavior that may not match a predefined signature.

The architecture is intentionally simple enough for local development and a student environment while providing a foundation for future expansion into a more distributed security monitoring platform
