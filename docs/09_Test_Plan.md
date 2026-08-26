# NetWatch AI — Test Plan

**Project:** NetWatch AI  
**Test Plan Version:** 1.0  
**Status:** In Development  
**Testing Scope:** Frontend, Backend, Network Processing, Detection, ML, AI, Database, API, WebSocket, and End-to-End Workflows

---

# 1. Overview

This document defines the testing strategy for NetWatch AI.

The purpose of testing is to verify that:

- Network traffic is captured correctly.
- Packets are parsed and normalized correctly.
- Network statistics are accurate.
- Devices are discovered and tracked correctly.
- Detection rules behave as intended.
- Behavioral baselines are generated correctly.
- ML anomaly detection produces useful results.
- Alerts are generated and correlated correctly.
- Risk scores are calculated consistently.
- AI analysis uses the available evidence correctly.
- Database records remain consistent.
- REST APIs behave correctly.
- WebSocket updates reach the frontend.
- The React frontend handles live and historical data correctly.
- Reports are generated correctly.
- System failures do not unnecessarily stop core monitoring.

---

# 2. Testing Objectives

The primary testing objectives are:

1. Validate individual components.
2. Validate communication between components.
3. Validate complete workflows.
4. Identify false positives and false negatives.
5. Verify security-event evidence.
6. Verify real-time functionality.
7. Verify application stability under realistic traffic.
8. Validate the user interface using real backend data.
9. Validate the local deployment process.
10. Ensure that the system fails gracefully when optional components are unavailable.

---

# 3. Testing Levels

NetWatch AI will use multiple testing levels.

```text
Unit Testing
     ↓
Component Testing
     ↓
Integration Testing
     ↓
API Testing
     ↓
System Testing
     ↓
End-to-End Testing
     ↓
Performance Testing
     ↓
Security Testing
     ↓
User Acceptance Testing
````

---

# 4. Unit Testing

Unit tests verify individual functions and classes independently.

Examples:

* Packet parser
* Feature extractor
* Detection rules
* Risk scorer
* Correlation engine
* Deduplication logic
* Baseline calculations
* API validation functions
* Utility functions

---

# 5. Packet Processing Tests

## Test Objective

Verify that raw packets are converted into the correct normalized representation.

### Test Case: TCP Packet

Input:

```text
TCP packet
Source:
192.168.1.10

Destination:
192.168.1.20

Source Port:
50000

Destination Port:
443
```

Expected:

```text
protocol = TCP
source_ip = 192.168.1.10
destination_ip = 192.168.1.20
source_port = 50000
destination_port = 443
```

---

## Test Case: UDP Packet

Expected:

```text
protocol = UDP
```

and correct source/destination ports.

---

## Test Case: ICMP Packet

Expected:

```text
protocol = ICMP
```

No TCP/UDP ports should be assigned.

---

## Test Case: Malformed Packet

Input:

```text
Incomplete or unsupported packet
```

Expected:

* Parser does not crash.
* Error is logged.
* Packet is ignored or marked invalid.
* Remaining packet processing continues.

---

# 6. Feature Extraction Tests

Verify that features are calculated correctly.

Example:

```text
Packets:
100

Time:
10 seconds
```

Expected:

```text
packets_per_second = 10
```

Test:

* Packet rate
* Byte rate
* Unique ports
* Unique destinations
* Protocol ratios
* Failed connection ratio
* SYN ratio
* Average packet size

---

# 7. Device Discovery Tests

## New Device

Expected:

```text
New IP/MAC
      ↓
New Device Record
```

Verify:

* Device created.
* `first_seen` populated.
* `last_seen` populated.
* Initial status assigned.

---

## Existing Device

Expected:

```text
Existing Device
      ↓
Update last_seen
Update traffic
```

No duplicate device should be created.

---

# 8. Database Tests

Verify:

* Tables are created correctly.
* Primary keys work.
* Foreign keys work.
* Constraints work.
* Required fields are enforced.
* Indexes exist.
* Data can be inserted and retrieved.
* Invalid records are rejected.

---

# 9. Detection Rule Tests

Every detection rule requires positive and negative test cases.

---

# 10. Port Scan Detection

## Positive Test

Simulated traffic:

```text
One source
57 unique destination ports
within 30 seconds
high SYN ratio
many failed connections
```

Expected:

```text
Port Scan Detector:
Triggered
```

---

## Negative Test

Normal browsing:

```text
1 source
5 destination ports
normal connection frequency
```

Expected:

```text
No port scan alert
```

---

## Boundary Test

Test exactly at the configured threshold.

Example:

```text
40 unique ports
```

Expected behavior should match the documented rule configuration.

---

# 11. SYN Flood Detection

## Positive Test

Generate controlled traffic that produces:

* High SYN rate
* Large number of incomplete connections
* Significant traffic increase

Expected:

```text
SYN Flood Detector:
Triggered
```

---

## Negative Test

Normal TCP connection establishment.

Expected:

```text
No SYN flood alert
```

---

# 12. ICMP Flood Detection

## Positive Test

Generate a controlled ICMP request rate above the configured threshold.

Expected:

```text
ICMP Flood:
Triggered
```

---

## Negative Test

Normal ping activity.

Expected:

```text
No alert
```

---

# 13. Internal Scan Detection

## Positive Test

One device communicates with a large number of internal destinations within a short period.

Expected:

```text
Internal Scan:
Triggered
```

---

## Negative Test

Normal communication with a small number of known internal devices.

Expected:

```text
No alert
```

---

# 14. High Bandwidth Detection

## Positive Test

Generate traffic significantly above the configured threshold or device baseline.

Expected:

```text
Abnormal Traffic Volume:
Triggered
```

---

## Negative Test

Traffic remains within normal device behavior.

Expected:

```text
No alert
```

---

# 15. DNS Anomaly Tests

Test:

* High DNS request rate
* Long DNS queries
* Unusual DNS destinations
* Large increase from baseline

Expected:

```text
DNS Anomaly:
Potential detection
```

The system should avoid automatically classifying every unusual DNS request as malicious.

---

# 16. Suspicious Port Tests

Test traffic involving configured ports.

Expected:

* Port is recognized.
* Context is recorded.
* Risk contribution is calculated.

Traffic to a sensitive port by itself should not necessarily generate a high-severity alert.

---

# 17. Behavioral Baseline Tests

## Initial Learning

New device:

```text
Status:
Learning
```

Verify that traffic observations are collected.

---

## Baseline Activation

After sufficient data:

```text
Learning
   ↓
Active
```

Verify that baseline statistics are populated.

---

## Deviation Test

Normal:

```text
50–100 packets/sec
```

Current:

```text
2,000 packets/sec
```

Expected:

```text
High behavioral deviation
```

---

# 18. Baseline Stability Tests

A single abnormal event should not immediately redefine the baseline.

Test:

```text
Normal traffic
      ↓
Large temporary spike
      ↓
Return to normal
```

Expected:

* Spike is detected as unusual.
* Baseline does not immediately shift to the abnormal level.

---

# 19. Machine Learning Tests

The ML engine should be tested separately from the rule engine.

Verify:

* Model loads successfully.
* Feature order is correct.
* Missing values are handled.
* Valid feature vectors produce predictions.
* Anomaly score is within the expected application range.
* Model failure does not stop packet capture.

---

# 20. ML Normal-Traffic Test

Provide representative normal traffic.

Expected:

```text
Mostly normal predictions
```

The exact expected anomaly rate should be established through evaluation rather than assumed.

---

# 21. ML Anomalous-Traffic Test

Provide controlled abnormal behavior.

Expected:

```text
Higher anomaly probability / score
```

The result should be recorded for evaluation.

---

# 22. ML False Positive Testing

Test legitimate but unusual behavior such as:

* Large legitimate file transfer
* Software update
* Backup process
* Security testing

Expected:

* ML may identify an anomaly.
* The final risk engine should use context before generating a severe alert.

This test is important because anomaly does not automatically mean attack.

---

# 23. Correlation Testing

## Example

Generate:

```text
Port Scan
+
High SYN Rate
+
Failed Connections
+
Behavioral Anomaly
```

Expected:

```text
Multiple signals
        ↓
Single correlated security finding
```

The system should avoid generating unnecessary duplicate incidents.

---

# 24. Alert Deduplication Testing

Repeated identical events:

```text
Port Scan
Port Scan
Port Scan
Port Scan
```

Expected:

```text
One active correlated alert
+
Updated evidence / event count
```

rather than unlimited duplicate alerts.

---

# 25. Risk Scoring Tests

Test individual contributions:

```text
Rule Evidence
Behavioral Deviation
ML Anomaly
Asset Context
Historical Context
```

Verify that the final score is calculated consistently.

Boundary cases:

```text
0
39
40
69
70
89
90
100
```

Verify severity mapping:

```text
Critical
High
Medium
Low
```

---

# 26. Risk and Confidence Tests

Verify that risk and confidence remain separate.

Example:

```text
Risk:
90

Confidence:
60
```

Expected:

```text
High potential impact
with uncertain evidence
```

The UI should display the two values separately.

---

# 27. Alert Lifecycle Tests

Test:

```text
New
 ↓
Acknowledged
 ↓
Investigating
 ↓
Resolved
```

Also test:

```text
New
 ↓
False Positive
```

Expected:

* Database status updated.
* Dashboard status updated.
* Audit information preserved.

---

# 28. Evidence Tests

When an alert is generated, verify that the relevant evidence can be retrieved.

Evidence may include:

* Packets
* Connections
* Feature values
* Rule result
* Baseline comparison
* ML result
* Device context

Expected:

```text
Alert
  ↓
Evidence
  ↓
Investigation UI
```

---

# 29. AI Tests

AI should be tested separately from deterministic detection.

Verify:

* Structured event is constructed correctly.
* Prompt contains relevant evidence.
* Sensitive unnecessary information is excluded.
* AI response is parsed correctly.
* Invalid AI output is handled.
* AI timeout is handled.
* AI service failure does not stop core detection.

---

# 30. AI Evidence Integrity Test

Provide:

```text
Source IP
Unique Ports
SYN Ratio
Failed Connections
Risk
```

Expected AI response:

* Uses those observations.
* Does not invent additional packet information.
* Clearly distinguishes observation from inference.

---

# 31. AI Failure Test

Simulate:

```text
AI Engine unavailable
```

Expected:

```text
Packet Capture       ✓
Statistics           ✓
Rule Detection       ✓
Behavioral Detection ✓
ML                   ✓
Alert Generation     ✓
AI Explanation       unavailable
```

The application should remain usable.

---

# 32. API Testing

Every API endpoint should be tested for:

* Valid request
* Invalid request
* Missing parameters
* Not found resources
* Correct response structure
* Correct HTTP status
* Error handling

---

# 33. Dashboard API Tests

Test:

```text
GET /api/v1/dashboard
GET /api/v1/dashboard/traffic
GET /api/v1/dashboard/protocols
GET /api/v1/dashboard/top-talkers
GET /api/v1/dashboard/ai-summary
```

Verify that the returned data matches the underlying database/statistics.

---

# 34. Capture API Tests

Test:

```text
GET /api/v1/capture/interfaces
GET /api/v1/capture/status
POST /api/v1/capture/start
POST /api/v1/capture/stop
```

Test:

* Valid interface
* Invalid interface
* Starting an already-running capture
* Stopping an already-stopped capture

---

# 35. Packet API Tests

Test:

```text
GET /api/v1/packets
GET /api/v1/packets/{id}
```

Verify:

* Pagination
* Filtering
* Sorting where supported
* Valid packet IDs
* Invalid packet IDs
* Large datasets

---

# 36. Device API Tests

Test:

```text
GET /api/v1/devices
GET /api/v1/devices/{id}
GET /api/v1/devices/{id}/traffic
GET /api/v1/devices/{id}/connections
GET /api/v1/devices/{id}/alerts
GET /api/v1/devices/{id}/baseline
```

---

# 37. Alert API Tests

Test:

```text
GET /api/v1/alerts
GET /api/v1/alerts/{id}
POST /api/v1/alerts/{id}/acknowledge
POST /api/v1/alerts/{id}/investigate
POST /api/v1/alerts/{id}/resolve
POST /api/v1/alerts/{id}/false-positive
```

Verify valid and invalid status transitions.

---

# 38. Detection Rule API Tests

Test:

```text
GET /api/v1/detection-rules
GET /api/v1/detection-rules/{id}
PUT /api/v1/detection-rules/{id}
POST /api/v1/detection-rules/{id}/enable
POST /api/v1/detection-rules/{id}/disable
```

Changing a rule configuration should affect future detection behavior.

---

# 39. Behavioral Baseline API Tests

Test:

```text
GET /api/v1/baselines/{device_id}
POST /api/v1/baselines/{device_id}/reset
POST /api/v1/baselines/{device_id}/pause
POST /api/v1/baselines/{device_id}/resume
```

Verify that baseline state changes correctly.

---

# 40. AI API Tests

Test:

```text
GET /api/v1/ai/insights
GET /api/v1/ai/alerts/{alert_id}
GET /api/v1/ai/devices/{device_id}
POST /api/v1/ai/analyze
```

Verify:

* Correct input validation
* Response structure
* Error handling
* AI-unavailable behavior

---

# 41. WebSocket Testing

WebSockets should be tested independently.

Endpoints:

```text
/ws/dashboard
/ws/packets
/ws/alerts
/ws/system
```

Verify:

* Connection establishment
* Event delivery
* Multiple messages
* Disconnect handling
* Reconnection
* Invalid data handling

---

# 42. Dashboard WebSocket Test

Generate network traffic.

Expected:

```text
Traffic changes
      ↓
WebSocket event
      ↓
Dashboard metric updates
```

The user should not need to refresh the browser.

---

# 43. Live Packet WebSocket Test

Capture packets.

Expected:

```text
Packet captured
      ↓
WebSocket event
      ↓
Live Traffic table updates
```

---

# 44. Alert WebSocket Test

Trigger a detection.

Expected:

```text
Detection
   ↓
Alert created
   ↓
WebSocket event
   ↓
Dashboard notification
   ↓
Alert appears
```

---

# 45. Frontend Component Testing

React components should be tested independently.

Examples:

* StatCard
* TrafficChart
* ThreatGauge
* AlertTable
* PacketTable
* DeviceTable
* AIInsight
* SystemHealth
* Settings components

---

# 46. Frontend State Testing

Test:

```text
Loading
Empty
Success
Error
```

Example:

```text
API unavailable
     ↓
Error state displayed
```

The UI should not crash because an API request fails.

---

# 47. Frontend Integration Testing

Test complete UI workflows.

Example:

```text
Dashboard
   ↓
Select Alert
   ↓
Alert Investigation
   ↓
View Evidence
   ↓
View AI Insight
   ↓
Resolve Alert
```

---

# 48. Figma-to-Backend Integration Tests

The exported Figma Make interface should be tested against actual backend data.

The final application should no longer rely on:

```text
Math.random()
Static mock alerts
Static device data
Simulated packet streams
```

for production functionality.

Expected flow:

```text
FastAPI
   ↓
Real Data
   ↓
React
   ↓
Figma-designed Components
```

---

# 49. Report Testing

Test:

```text
Daily Report
Weekly Report
Monthly Report
Custom Report
```

Formats:

```text
PDF
CSV
```

Verify:

* File generated
* Correct date range
* Correct data
* Charts included where expected
* Download works
* Invalid parameters handled

---

# 50. Performance Testing

Performance testing should focus on:

* Packet processing rate
* API response time
* WebSocket latency
* Database write performance
* Dashboard rendering
* Detection throughput
* ML inference time
* AI inference time

---

# 51. Packet Processing Benchmark

Measure:

```text
Packets/sec processed
```

Test increasing traffic levels:

```text
100 packets/sec
500 packets/sec
1,000 packets/sec
5,000 packets/sec
```

The actual supported throughput should be determined experimentally rather than assumed.

---

# 52. API Performance

Measure response times for:

```text
GET /dashboard
GET /devices
GET /alerts
GET /analytics/*
```

High-volume packet queries should use pagination.

---

# 53. WebSocket Performance

Measure:

```text
Packet event rate
Message latency
Client update rate
```

The system should avoid overwhelming the browser with an unbounded number of UI updates.

---

# 54. Database Performance

Test:

* Bulk packet insertion
* Alert queries
* Historical analytics
* Device searches
* Time-range queries

Indexes should be verified using realistic datasets.

---

# 55. Load Testing

Potential scenarios:

```text
Low Traffic
Normal Traffic
High Traffic
Burst Traffic
```

Observe:

* CPU usage
* RAM
* Database growth
* Processing latency
* Alert latency
* UI responsiveness

---

# 56. Stability Testing

Run NetWatch AI continuously for an extended period.

Monitor:

* Memory usage
* CPU usage
* Database growth
* WebSocket stability
* Packet-processing errors
* Detection errors

Expected:

* No progressive memory leak.
* No uncontrolled database growth.
* No repeated crash/restart cycle.

---

# 57. Security Testing

Security testing should include:

* API input validation
* SQL injection testing
* Authentication testing when authentication is implemented
* Authorization testing
* CORS configuration
* Secret exposure checks
* Error-message inspection
* Dependency vulnerability scanning
* Access-control checks

---

# 58. SQL Injection Testing

Test API parameters with malicious input.

Expected:

* Query is safely parameterized.
* No raw SQL injection occurs.
* Application returns controlled error responses.

---

# 59. API Input Validation Testing

Test invalid:

* IP addresses
* Ports
* IDs
* Risk scores
* Confidence values
* Dates
* Pagination values

Expected:

```text
400 / 422
```

with a clear validation response.

---

# 60. Secret Management Testing

Verify that:

```text
.env
credentials
tokens
API keys
```

are not committed to Git.

Check:

```text
.gitignore
repository history
logs
frontend bundles
```

---

# 61. Permission Testing

Where authentication/RBAC is implemented, verify:

```text
Viewer
Analyst
Admin
```

have appropriate access.

For the initial unauthenticated local version, this test remains a future requirement.

---

# 62. Dependency Security Testing

The project should periodically scan dependencies.

Potential tools:

* pip-audit
* npm audit

Results should be reviewed and important vulnerabilities addressed.

---

# 63. Privacy Testing

Verify that the system does not unnecessarily store sensitive payload data.

Check:

* Database
* Logs
* Reports
* AI prompts
* AI responses
* Debug output

---

# 64. Deployment Testing

Test the complete installation process on a clean environment.

Verify:

```text
Clone Repository
      ↓
Install Dependencies
      ↓
Configure Environment
      ↓
Initialize Database
      ↓
Run Backend
      ↓
Run Frontend
      ↓
Start Capture
      ↓
Monitor Traffic
```

A new developer should be able to reproduce the environment using the Deployment Guide.

---

# 65. Cross-Platform Testing

Where practical, test:

```text
Windows
Linux
macOS
```

Packet capture behavior may vary between operating systems.

The UI and API should be tested independently of OS-specific packet-capture differences.

---

# 66. Controlled Security Testing

All attack simulations must occur in authorized environments.

Recommended laboratory:

```text
Host
 |
 +---- NetWatch AI
 |
 +---- Kali Linux
 |
 +---- Metasploitable
```

Controlled tests can include:

* Port scanning
* Excessive ICMP traffic
* Controlled SYN traffic
* Internal scanning
* High-bandwidth test traffic

The purpose is to validate the detection engine, not to test unauthorized external systems.

---

# 67. End-to-End Test 1 — Normal Monitoring

```text
Start Application
      ↓
Select Interface
      ↓
Start Capture
      ↓
Network Traffic Observed
      ↓
Packets Processed
      ↓
Statistics Updated
      ↓
Dashboard Updated
```

Expected:

* No application errors.
* Packets visible.
* Metrics update.
* Devices appear.
* WebSocket works.

---

# 68. End-to-End Test 2 — Port Scan

```text
Authorized Test Scanner
        ↓
Controlled Scan
        ↓
Packet Capture
        ↓
Feature Extraction
        ↓
Port Scan Detector
        ↓
Behavioral Signal
        ↓
Correlation
        ↓
Risk Score
        ↓
Alert
        ↓
Dashboard
        ↓
AI Explanation
```

Expected:

* Detection occurs.
* Evidence is stored.
* Alert appears.
* AI can summarize the event when enabled.

---

# 69. End-to-End Test 3 — False Positive

Use legitimate traffic that appears unusual.

Example:

```text
Large file transfer
```

Expected:

* Traffic anomaly may be identified.
* System should consider baseline and context.
* It should not automatically classify the activity as malicious.

---

# 70. End-to-End Test 4 — Unknown Anomaly

Generate unusual traffic that does not match an explicit rule.

Expected:

```text
No rule match
       ↓
Behavioral deviation
       +
ML anomaly
       ↓
Suspicious behavior
       ↓
Risk assessment
```

This validates the reason for having behavioral and ML detection.

---

# 71. End-to-End Test 5 — AI Failure

Disable the local AI service.

Expected:

```text
Packet Capture       ✓
Statistics           ✓
Detection            ✓
Alerts               ✓
Dashboard            ✓
AI Explanation      Unavailable
```

The application remains operational.

---

# 72. Acceptance Criteria

Version 1 should satisfy:

```text
[ ] Live traffic can be captured.
[ ] Packets are normalized correctly.
[ ] Devices are discovered.
[ ] Traffic statistics are accurate enough for the intended use.
[ ] Detection rules work against controlled test traffic.
[ ] Behavioral baselines can be established.
[ ] ML anomaly detection can run.
[ ] Related events can be correlated.
[ ] Risk scores are generated.
[ ] Alerts contain supporting evidence.
[ ] Alerts can be investigated.
[ ] REST APIs work.
[ ] WebSockets provide real-time updates.
[ ] Figma frontend consumes real backend data.
[ ] Reports can be generated.
[ ] AI analysis works when enabled.
[ ] Core monitoring continues when AI is unavailable.
[ ] No paid services are required for core operation.
```

---

# 73. Test Data

The project should maintain test data separately from production data.

Recommended:

```text
tests/
├── fixtures/
├── sample_packets/
├── sample_pcap/
├── sample_alerts/
└── sample_features/
```

Where legally and technically appropriate, public datasets may also be used for ML experimentation.

---

# 74. Sample PCAP Testing

Saved PCAP files can be used for repeatable testing.

Example:

```text
sample_data/
├── normal_traffic.pcap
├── port_scan.pcap
└── icmp_test.pcap
```

This allows the detection pipeline to be tested repeatedly without needing to recreate the network activity every time.

---

# 75. Regression Testing

Every major change should verify that previously working functionality still works.

Examples:

```text
Change:
Detection Rule

Regression Tests:
Dashboard
Alerts
WebSocket
Database
Reports
```

---

# 76. CI Testing

Future GitHub Actions workflow:

```text
Push
 ↓
Install Dependencies
 ↓
Lint
 ↓
Unit Tests
 ↓
Integration Tests
 ↓
Build Frontend
 ↓
Build Backend
```

CI should initially focus on code tests that do not require live packet capture hardware.

---

# 77. Test Result Tracking

Test results should eventually be tracked.

Possible format:

| Test ID | Description        | Expected       | Actual  | Status |
| ------- | ------------------ | -------------- | ------- | ------ |
| NET-001 | TCP packet parsing | Correct fields | Pending | ⬜      |
| DET-001 | Port scan          | Alert          | Pending | ⬜      |
| DET-002 | Normal browsing    | No alert       | Pending | ⬜      |
| ML-001  | Normal traffic     | Mostly normal  | Pending | ⬜      |
| API-001 | Dashboard API      | 200            | Pending | ⬜      |
| WS-001  | Alert stream       | Event received | Pending | ⬜      |

---

# 78. Defect Classification

Issues should be categorized as:

```text
Critical
High
Medium
Low
```

## Critical

Core application cannot start or major security function fails.

## High

Major feature is unusable.

## Medium

Feature works incorrectly under some conditions.

## Low

Minor UI or usability issue.

---

# 79. Test Environment Documentation

Each significant detection experiment should record:

```text
Operating System
Network Interface
IP Configuration
Traffic Source
Test Tool
Test Time
Detection Configuration
Expected Result
Actual Result
```

This makes results reproducible.

---

# 80. Detection Accuracy Evaluation

Detection quality should be evaluated using controlled and reproducible datasets.

For labeled scenarios, record:

```text
True Positive
False Positive
True Negative
False Negative
```

Potential metrics:

```text
Precision
Recall
F1 Score
False Positive Rate
False Negative Rate
```

These metrics should only be reported when supported by appropriate test data.

---

# 81. Important Testing Principle

A detection system should not be judged only by:

```text
"Did it detect the attack?"
```

It should also be evaluated on:

```text
Did it provide useful evidence?

Did it avoid unnecessary duplicate alerts?

Did it distinguish confidence from risk?

Did it identify anomalous but legitimate behavior?

Did it continue operating when optional components failed?

Could an analyst understand why the alert was generated?
```

---

# 82. Final End-to-End Validation

The complete system is validated through:

```text
Network
   ↓
Packet Capture
   ↓
Packet Processing
   ↓
Feature Extraction
   ↓
Statistics
   ↓
Rule Detection
   ↓
Behavioral Detection
   ↓
ML Detection
   ↓
Correlation
   ↓
Risk Score
   ↓
Alert
   ↓
Evidence
   ↓
AI Analysis
   ↓
Database
   ↓
WebSocket / REST
   ↓
React Dashboard
   ↓
Analyst Investigation
```

Every major transition should have automated or repeatable tests where practical.

---

# 83. Conclusion

Testing for NetWatch AI covers the complete platform rather than focusing only on the user interface.

The test strategy combines:

* Unit testing
* Integration testing
* API testing
* WebSocket testing
* Detection testing
* Behavioral testing
* ML testing
* AI testing
* Performance testing
* Security testing
* Deployment testing
* End-to-end testing

The most important goal is to demonstrate that the platform can transform real network traffic into reliable, explainable security information while remaining stable when individual optional components fail.

Testing results should be used to improve thresholds, behavioral baselines, ML models, correlation logic, and UI workflows before reporting performance or detection metrics in the project documentation or resume.
