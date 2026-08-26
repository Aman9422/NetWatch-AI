# NetWatch AI — Future Roadmap

**Project:** NetWatch AI  
**Roadmap Version:** 1.0  
**Current Status:** In Development

---

# 1. Overview

NetWatch AI is designed as a modular platform that can evolve from a local network monitoring project into a broader network security analytics and detection platform.

The initial implementation focuses on:

- Network monitoring
- Packet analysis
- Device discovery
- Rule-based detection
- Behavioral detection
- ML anomaly detection
- Event correlation
- Risk scoring
- Alert investigation
- AI-assisted analysis
- Reporting

Future development will expand the platform without changing the fundamental architecture.

---

# 2. Development Philosophy

Future features should be added incrementally.

The project should prioritize:

1. Core reliability
2. Detection quality
3. False-positive reduction
4. Performance
5. Security
6. Usability
7. Extensibility
8. Advanced integrations

Advanced features should not be added until the underlying monitoring and detection pipeline is stable.

---

# 3. Current Development Stage

```text
Project Concept                    ✅
Requirements                       ✅
System Architecture                ✅
Database Design                    ✅
API Specification                  ✅
Detection Architecture             ✅
AI Architecture                   ✅
UI / Figma Design                 ✅
Deployment Documentation           ✅
Testing Strategy                  ✅
Implementation                    ⬜
````

The project is currently transitioning from design to implementation.

---

# 4. Phase 1 — Core MVP

## Objective

Create a fully functioning local network monitoring platform.

### Features

* Network interface discovery
* Interface selection
* Packet capture
* Packet parsing
* Packet normalization
* Feature extraction
* Device discovery
* Traffic statistics
* SQLite persistence
* Basic REST API
* WebSocket infrastructure
* Figma frontend integration

### Expected Flow

```text
Network
   ↓
Scapy
   ↓
Packet Processor
   ↓
SQLite
   ↓
FastAPI
   ↓
React Dashboard
```

---

# 5. Phase 2 — Initial Security Detection

## Objective

Introduce reliable, explainable security detections.

Initial detectors:

* Port scan
* SYN flood
* ICMP flood
* Internal network scan
* High bandwidth usage
* DNS anomaly
* Suspicious port activity

### Additional Components

* Alert generation
* Alert severity
* Evidence collection
* Alert lifecycle
* Alert deduplication
* Basic correlation

---

# 6. Phase 3 — Behavioral Detection

## Objective

Move beyond fixed thresholds.

Implement:

* Device-specific baselines
* Baseline learning
* Behavioral deviation detection
* New destination detection
* New port detection
* Protocol behavior analysis
* Historical behavior comparison

Example:

```text
Normal Device Behavior
        ↓
Current Behavior
        ↓
Deviation
        ↓
Behavioral Signal
```

---

# 7. Phase 4 — ML Anomaly Detection

## Objective

Use machine learning to identify unusual combinations of network features.

Initial model:

**Isolation Forest**

### Development Steps

```text
Network Data
    ↓
Feature Windows
    ↓
Feature Dataset
    ↓
Model Training
    ↓
Evaluation
    ↓
Model Storage
    ↓
Live Inference
```

### Future Improvements

* Autoencoders
* One-Class SVM
* Advanced ensemble models
* Sequence-based models
* Device-specific models
* Supervised classifiers where appropriate labeled data is available

Model improvements should be based on measured evaluation results rather than model complexity alone.

---

# 8. Phase 5 — Correlation and Risk Intelligence

## Objective

Improve alert quality by combining multiple detection signals.

Example:

```text
Port Scan
     +
High SYN Rate
     +
Behavioral Anomaly
     +
ML Anomaly
     ↓
Correlated Security Event
     ↓
Risk Score
```

Future improvements:

* Better correlation rules
* Incident grouping
* Asset criticality
* Historical context
* Alert suppression
* Confidence calibration
* False-positive feedback

---

# 9. Phase 6 — AI Analyst

## Objective

Introduce local AI-assisted investigation.

Potential functionality:

* Alert explanation
* Evidence summarization
* Device behavior summaries
* Investigation guidance
* Recommended next steps
* Security report generation

Potential architecture:

```text
Security Event
      ↓
Evidence
      ↓
Prompt Builder
      ↓
Local LLM
      ↓
Response Validation
      ↓
AI Insight
```

The AI should remain an analyst-assistance component rather than an autonomous security decision-maker.

---

# 10. Phase 7 — Advanced Investigation

Future investigation features may include:

* Full event timelines
* Cross-device correlation
* Related alert discovery
* Packet-to-alert relationships
* Connection graphs
* Device communication maps
* Investigation notes
* Analyst comments
* Incident status tracking

Example:

```text
Incident
  |
  +--- Device A
  |
  +--- Device B
  |
  +--- Alert 1
  |
  +--- Alert 2
  |
  +--- Packet Evidence
  |
  +--- AI Summary
```

---

# 11. Phase 8 — Threat Intelligence

Future versions may integrate threat intelligence sources.

Potential functionality:

* Malicious IP lookups
* Domain reputation
* Known indicators
* IOC correlation
* Threat intelligence enrichment

The integration must remain optional.

The core project should continue working without external threat intelligence services.

---

# 12. Phase 9 — MITRE ATT&CK Integration

The platform can map detected behavior to relevant MITRE ATT&CK techniques.

Example:

```text
Port Scanning
     ↓
Reconnaissance
     ↓
MITRE ATT&CK Mapping
```

Potential UI:

```text
Technique:
Network Service Scanning

Tactic:
Reconnaissance
```

The mapping should be evidence-based and should not automatically imply that an attack is confirmed.

---

# 13. Phase 10 — Suricata and Zeek Integration

Rather than attempting to recreate every mature IDS signature, NetWatch AI can integrate with established security tools.

Potential integrations:

```text
NetWatch Behavioral Detection
        +
Suricata Alerts
        +
Zeek Events
        ↓
Correlation Engine
        ↓
Unified Security Findings
```

This would allow NetWatch AI to become an analytics and correlation layer.

---

# 14. Phase 11 — Advanced Network Detection

Potential future detectors:

* ARP spoofing
* DHCP spoofing
* DNS tunneling
* Beaconing
* Command-and-control indicators
* Brute-force patterns
* Lateral movement
* Data exfiltration indicators
* Suspicious encrypted traffic behavior

These features should be implemented incrementally and validated using controlled test data.

---

# 15. Phase 12 — PCAP Analysis

Add the ability to upload and analyze previously captured PCAP files.

Potential workflow:

```text
PCAP Upload
    ↓
Packet Parser
    ↓
Feature Extraction
    ↓
Detection Engine
    ↓
Analytics
    ↓
Alerts
    ↓
Report
```

This would allow offline investigation without requiring a live capture session.

---

# 16. Phase 13 — Advanced Reporting

Future reports may include:

* Executive summary
* Security incidents
* Network activity
* Device risk
* Threat trends
* MITRE ATT&CK mapping
* Detection statistics
* AI-generated summary
* Recommendations

Possible formats:

* PDF
* CSV
* JSON
* HTML

---

# 17. Phase 14 — Notification Integrations

Potential notification channels:

* Email
* Webhooks
* Slack
* Discord

Example:

```text
High Risk Alert
      ↓
Alert Engine
      ↓
Notification Service
      ↓
Configured Channel
```

These should remain optional extensions.

---

# 18. Phase 15 — Authentication and RBAC

The local single-user deployment does not require authentication initially.

A future multi-user deployment can add:

```text
Authentication
      ↓
Authorization
      ↓
Role
```

Potential roles:

```text
Admin
Analyst
Viewer
```

Capabilities could include:

| Role    | View | Investigate | Configure | Admin |
| ------- | ---- | ----------- | --------- | ----- |
| Viewer  | ✓    | Limited     | No        | No    |
| Analyst | ✓    | ✓           | Limited   | No    |
| Admin   | ✓    | ✓           | ✓         | ✓     |

---

# 19. Phase 16 — PostgreSQL Migration

SQLite is suitable for the initial local version.

As data volume and concurrency increase:

```text
SQLite
   ↓
PostgreSQL
```

Potential supporting technologies:

* PostgreSQL
* TimescaleDB
* Redis

The repository/service database abstraction should make the migration easier.

---

# 20. Phase 17 — Distributed Sensors

A future architecture may support multiple network sensors.

Example:

```text
Sensor 1
   |
Sensor 2
   |
Sensor 3
   |
   +---------> Central Backend
                    |
                    v
               Central DB
                    |
                    v
               Dashboard
```

Each sensor could monitor a separate network segment.

---

# 21. Phase 18 — Containerization

Docker can simplify deployment.

Future architecture:

```text
Docker Compose
│
├── Frontend
├── Backend
├── Database
└── Optional AI Service
```

Packet capture containers may require host networking and specific privileges.

Containerization should be introduced after the native deployment is stable.

---

# 22. Phase 19 — Observability

The platform itself can eventually expose operational metrics such as:

* CPU usage
* Memory usage
* Capture rate
* Processing latency
* Detection latency
* WebSocket clients
* Database size
* Alert rate

Potential future integrations:

* Prometheus
* Grafana

These are optional and should not be required for the initial application.

---

# 23. Phase 20 — Performance Improvements

As traffic volume increases, optimize:

* Packet processing
* Feature aggregation
* Memory usage
* Database writes
* API queries
* WebSocket broadcasting
* ML inference
* AI processing

Potential future techniques:

* Batch processing
* Asynchronous pipelines
* Worker processes
* Caching
* Message queues
* Time-series storage
* Distributed processing

---

# 24. Phase 21 — Advanced AI Assistant

A future AI assistant could provide natural-language investigation.

Example questions:

```text
Why was this device flagged?

Show suspicious activity from this host today.

What changed in this device's normal behavior?

Summarize today's security events.

Which devices have the highest risk?
```

Potential architecture:

```text
Analyst Question
       ↓
AI Assistant
       ↓
Retrieval / Query Layer
       ↓
NetWatch Database
       ↓
Structured Evidence
       ↓
Local AI Model
       ↓
Analyst Response
```

---

# 25. Phase 22 — Feedback-Driven Detection

Analyst decisions can eventually become feedback.

Example:

```text
Alert
  ↓
Analyst
  ↓
False Positive
  ↓
Feedback Storage
  ↓
Detection Tuning
```

Possible future uses:

* Threshold tuning
* Allowlist suggestions
* Model retraining
* Detection quality analysis

Any automated model changes should require validation before deployment.

---

# 26. Phase 23 — Security Hardening

Future production-oriented security improvements:

* HTTPS
* JWT authentication
* RBAC
* Secure secrets management
* API rate limiting
* Audit logs
* Database encryption where appropriate
* Secure WebSocket connections
* Security headers
* Dependency scanning
* Container security

---

# 27. Feature Priority

Future features should be prioritized according to:

```text
High Value
+
High Feasibility
+
Security Relevance
```

Recommended priority:

| Feature                      | Priority  |
| ---------------------------- | --------- |
| Core packet capture          | Critical  |
| Detection rules              | Critical  |
| Behavioral detection         | Critical  |
| Dashboard integration        | Critical  |
| Alert correlation            | High      |
| ML anomaly detection         | High      |
| AI analyst                   | High      |
| PCAP analysis                | High      |
| MITRE mapping                | Medium    |
| Suricata integration         | Medium    |
| Zeek integration             | Medium    |
| Threat intelligence          | Medium    |
| Authentication/RBAC          | Medium    |
| Distributed sensors          | Long-term |
| Advanced autonomous response | Long-term |

---

# 28. Version Roadmap

## Version 0.1 — Prototype

```text
Figma UI
+
Mock Data
```

Status:

**Completed**

---

## Version 0.2 — Core Monitoring

```text
Real Packet Capture
+
Packet Processing
+
SQLite
+
Dashboard API
```

---

## Version 0.3 — Security Detection

```text
Rules
+
Alerts
+
Evidence
+
Basic Correlation
```

---

## Version 0.4 — Behavioral Detection

```text
Device Baselines
+
Behavioral Analysis
+
Risk Scoring
```

---

## Version 0.5 — ML

```text
Isolation Forest
+
Anomaly Scores
+
ML Integration
```

---

## Version 0.6 — AI

```text
Local LLM
+
AI Insights
+
Alert Explanation
```

---

## Version 0.7 — Investigation

```text
Incident Views
+
Timelines
+
Advanced Evidence
+
PCAP Analysis
```

---

## Version 0.8 — Integrations

```text
MITRE ATT&CK
+
Suricata
+
Zeek
+
Threat Intelligence
```

---

## Version 0.9 — Platform

```text
Authentication
+
RBAC
+
PostgreSQL
+
Docker
```

---

## Version 1.0 — Portfolio Release

Target capabilities:

```text
Real Monitoring
+
Security Detection
+
Behavioral Detection
+
ML Anomaly Detection
+
Correlation
+
Risk Scoring
+
AI Analysis
+
Reports
+
Professional Dashboard
+
Documentation
+
Testing
```

Version 1.0 should only claim features that have been implemented and validated.

---

# 29. Long-Term Architecture

A possible future architecture:

```text
                         Network Segments
                              |
                +-------------+-------------+
                |             |             |
                v             v             v
             Sensor 1      Sensor 2      Sensor 3
                |             |             |
                +-------------+-------------+
                              |
                              v
                       Message Pipeline
                              |
                              v
                    Central Processing
                              |
          +-------------------+-------------------+
          |                   |                   |
          v                   v                   v
       Detection          Analytics           AI Engine
          |                   |                   |
          +-------------------+-------------------+
                              |
                              v
                       Correlation Engine
                              |
                              v
                         Risk Engine
                              |
                              v
                       Alert Platform
                              |
                              v
                     Security Dashboard
```

This is a future architecture and is not required for the initial student/local release.

---

# 30. What Will Not Be Automatically Implemented

Advanced capabilities should not be added merely to increase the feature count.

Examples:

* Automatic host blocking
* Autonomous response
* Fully automatic model retraining
* Enterprise-scale distributed processing
* Automated firewall modification

These features can introduce significant operational and security risks.

They should only be implemented when there is a clear requirement, safe testing environment, and proper authorization.

---

# 31. Zero-Cost Principle

Future development should continue to prioritize free and open-source technologies.

Core functionality should remain usable without requiring:

* Paid cloud infrastructure
* Paid AI APIs
* Commercial SIEM platforms
* Paid databases
* Paid monitoring platforms

Optional integrations may be supported, but the project should retain a functional local mode.

---

# 32. Resume Evolution

The project description on the resume should evolve as capabilities are actually implemented.

Initial:

> Developing a network monitoring dashboard with packet capture, traffic analytics, and security detection.

After security detection:

> Developing a network monitoring and threat detection platform with rule-based and behavioral security analytics.

After ML:

> Developing an AI-assisted network detection platform using behavioral baselines and ML-based anomaly detection.

After final implementation:

> Developed a modular Network Detection and Response platform integrating real-time packet analysis, behavioral detection, ML anomaly detection, event correlation, risk scoring, and AI-assisted security investigation.

Only the version corresponding to the implemented and tested functionality should be used on the resume.

---

# 33. Roadmap Tracking

The roadmap should be tracked through GitHub Issues or a project board.

Suggested columns:

```text
Backlog
   ↓
Planned
   ↓
In Progress
   ↓
Testing
   ↓
Completed
```

Each feature should ideally have:

* Issue
* Implementation
* Tests
* Documentation
* Pull request or commit
* Completion status

---

# 34. Roadmap Principles

1. Build core functionality before advanced functionality.
2. Validate every security feature with controlled test data.
3. Measure performance before claiming scalability.
4. Do not claim detection accuracy without appropriate evaluation.
5. Keep AI optional.
6. Prefer local and open-source infrastructure.
7. Preserve modular architecture.
8. Avoid unnecessary feature complexity.
9. Document significant architectural changes.
10. Keep the resume synchronized with implemented functionality.

---

# 35. Final Roadmap

```text
                  NETWATCH AI
                       |
               +-------+-------+
               |               |
          CURRENT           FUTURE
               |               |
               v               v
        Core Monitoring     Advanced AI
        Security Detection  Threat Intel
        Behavioral Analysis MITRE
        ML Anomaly          Suricata
        Correlation         Zeek
        Risk Scoring        PCAP Analysis
        Dashboard           RBAC
        Reports             PostgreSQL
                            Docker
                            Multi-Sensor
                            AI Assistant
```

The roadmap is intentionally incremental so that every stage produces a usable improvement rather than requiring the entire future architecture to be completed before the project becomes functional.

---

# 36. Conclusion

NetWatch AI is designed to evolve progressively.

The initial release focuses on building a reliable and explainable local security monitoring platform. Advanced functionality such as sophisticated machine learning, local AI assistance, threat intelligence, external IDS integration, distributed sensors, and enterprise deployment can be introduced after the core system has been validated.

The project should prioritize **depth and correctness over feature count**.

The final objective is not simply to produce a large application, but to build a technically defensible cybersecurity platform that can be demonstrated, tested, explained, and continuously improved.

