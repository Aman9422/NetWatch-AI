# NetWatch AI — Current Task

**Current Phase:** Base Application Implementation
**Current Milestone:** M10 — Base Detection
**Status:** In Progress

---

# Current Objective

Build the first rule-based detection layer for NetWatch AI.

M5 provides normalized packets.
M6 provides traffic statistics.
M7 provides packet persistence.
M8 provides device discovery and tracking.
M9 provides network conversations.

M10 will use these existing components to identify a small set of high-confidence suspicious network behaviors.

The main flow becomes:

    Network
        ↓
    Packet Capture
        ↓
    Packet Processing
        ↓
    NormalizedPacket
        ├── Statistics
        ├── Packet Persistence
        ├── Device Discovery
        └── Connection Tracking
                    ↓
              Detection Engine
                    ↓
              Detection Findings

M10 produces detection findings.

The Alert Engine in M11 will later convert appropriate findings into alerts.

---

# Important Detection Architecture

M10 must NOT depend on hundreds of static rules.

The initial detection layer should use a small number of clear, configurable, testable detectors.

Initial detectors:

1. Port Scan
2. SYN Flood
3. ICMP Flood
4. Internal Network Scan
5. High Bandwidth / Traffic Spike

Future detectors may include:

- DNS anomaly
- Suspicious port activity
- Brute-force patterns
- Beaconing
- Unusual connection behavior

These are future additions unless explicitly added to the M10 implementation.

---

# M10 Development Rule

Do NOT implement:

- Alert lifecycle
- Alert deduplication
- Correlation engine
- Risk scoring
- Behavioral baselines
- ML anomaly detection
- AI analysis
- Automatic blocking
- WebSockets
- Frontend integration
- External SIEM integrations
- Full incident response

M10 is responsible only for detection.

Detection findings must remain separate from alerts.

---

# M10.1 — Review Existing Components

Review:

- `NormalizedPacket`
- TrafficStatisticsManager
- PacketPersistence
- DeviceDiscoveryManager
- ConnectionTracker
- Existing database models
- Existing configuration system

Identify which existing data each detector will consume.

Do not duplicate functionality from previous milestones.

---

# M10.2 — Detection Package

Create a dedicated detection package.

Suggested structure:

    app/detection/
        __init__.py
        base.py
        context.py
        finding.py
        engine.py
        rules/
            __init__.py
            port_scan.py
            syn_flood.py
            icmp_flood.py
            internal_scan.py
            high_bandwidth.py

The exact structure may follow existing project conventions.

Keep detectors modular.

---

# M10.3 — Detection Rule Interface

Define a common detector interface.

Conceptually:

    DetectionRule
        ↓
    evaluate(context)
        ↓
    DetectionFinding | None

Each detector should:

- Have a stable rule identifier
- Have a human-readable name
- Accept a defined detection context
- Return a structured finding
- Avoid direct database/API/frontend logic

---

# M10.4 — Detection Context

Create a controlled detection context containing only the information required by the detectors.

Possible inputs:

    NormalizedPacket
    Traffic statistics
    Connections
    Devices
    Current timestamp

The context should avoid exposing unrelated application internals.

Do not make detectors directly access global application state.

---

# M10.5 — Detection Finding

Create a normalized detection finding model.

Suggested fields:

    finding_id
    rule_id
    rule_name
    timestamp
    source_ip
    destination_ip
    source_device_id
    destination_device_id
    protocol
    description
    evidence
    confidence
    metadata

Do not add final alert severity/risk scoring here.

A detection finding is an observation from a detector, not an alert.

---

# M10.6 — Detection Engine

Create:

    DetectionEngine

Responsibilities:

- Register enabled detection rules
- Evaluate rules
- Process detection context
- Collect findings
- Isolate individual rule failures
- Track detector execution diagnostics

Conceptually:

    Detection Context
          ↓
    Detection Engine
          ↓
    ┌──────────┬──────────┬──────────┬──────────┬──────────┐
    ↓          ↓          ↓          ↓          ↓
   Port      SYN        ICMP       Internal   Bandwidth
   Scan      Flood      Flood       Scan       Spike
    ↓          ↓          ↓          ↓          ↓
    └──────────┴──────────┴──────────┴──────────┴──────────┘
                         ↓
                  Detection Findings

---

# M10.7 — Rule Configuration

Detection thresholds must be configurable.

Do not hard-code important thresholds directly inside detector logic.

Configuration should support values such as:

    PORT_SCAN_TIME_WINDOW_SECONDS
    PORT_SCAN_UNIQUE_PORT_THRESHOLD
    PORT_SCAN_SYN_RATIO_THRESHOLD

    SYN_FLOOD_TIME_WINDOW_SECONDS
    SYN_FLOOD_RATE_THRESHOLD

    ICMP_FLOOD_TIME_WINDOW_SECONDS
    ICMP_FLOOD_RATE_THRESHOLD

    INTERNAL_SCAN_TIME_WINDOW_SECONDS
    INTERNAL_SCAN_UNIQUE_DESTINATION_THRESHOLD

    HIGH_BANDWIDTH_TIME_WINDOW_SECONDS
    HIGH_BANDWIDTH_BYTES_PER_SECOND_THRESHOLD

Use sensible development defaults.

The exact defaults should be documented.

---

# M10.8 — Port Scan Detector

Detect a host attempting connections to an unusually large number of destination ports within a configured time window.

Possible evidence:

- Unique destination ports
- Number of connection attempts
- SYN count where available
- Failed/incomplete connection observations

Initial design:

    Source Device/IP
          ↓
    Time Window
          ↓
    Unique Destination Ports
          ↓
    Configurable Threshold
          ↓
    Finding

Do not label every multi-port connection as malicious.

The detector should produce a finding only when its configured conditions are met.

---

# M10.9 — SYN Flood Detector

Detect an unusually high rate of TCP SYN traffic.

Possible evidence:

- SYN packet rate
- Incomplete connection observations
- Time window
- Destination concentration

Initial detector should focus on observable network behavior.

Do not implement traffic blocking.

Do not treat a single SYN packet as a flood.

---

# M10.10 — ICMP Flood Detector

Detect unusually high ICMP packet rates.

Possible evidence:

- ICMP packets per second
- Time window
- Destination concentration

Use configurable thresholds.

Do not assume that normal ping activity is malicious.

---

# M10.11 — Internal Network Scan Detector

Detect a source communicating with an unusually large number of internal destinations within a configured window.

Possible evidence:

- Unique destination IPs
- Connection attempts
- Time window

The detector should define what counts as an internal destination using available network context.

Do not assume every private IP is malicious.

---

# M10.12 — High Bandwidth / Traffic Spike Detector

Detect unusually high observed traffic volume using the statistics already produced by M6.

Possible evidence:

- Bytes per second
- Packet rate
- Time window
- Source/destination concentration where available

Use a configurable threshold.

This is a traffic-volume finding, not automatically a security incident.

---

# M10.13 — Detection Windows

Detectors that use time-based thresholds must use explicit windows.

The system should support:

    Start time
    End time
    Window duration

Avoid repeatedly scanning unlimited historical data.

Reuse existing M6/M9 aggregation capabilities where appropriate.

---

# M10.14 — Evidence

Every finding must contain enough evidence to explain why it was produced.

Examples:

    Unique destination ports: 37
    Threshold: 20
    Observation window: 10 seconds

or:

    SYN packets: 2400
    SYN threshold: 1000
    Window: 5 seconds

Evidence must come from actual observed data.

Do not fabricate packet counts, IPs, devices, or timestamps.

---

# M10.15 — Confidence

Detection findings may contain a confidence value describing how strongly the detector's evidence supports its own rule condition.

Keep:

    confidence

separate from future:

    risk score

Do not implement the M12 risk-scoring engine here.

---

# M10.16 — False Positive Awareness

Detectors must not assume:

    threshold exceeded = confirmed attack

Use wording such as:

    Possible port scan detected

or another clearly descriptive finding description.

The finding should describe observed behavior.

The Alert Engine and later correlation/risk layers will add additional context.

---

# M10.17 — Rule Failure Isolation

A failure in one detector must not stop the other detectors.

Example:

    Port Scan      → finding
    SYN Flood      → error
    ICMP Flood     → finding
    Internal Scan  → finding
    Bandwidth      → finding

The engine must continue evaluating remaining rules.

Track detector failures for diagnostics.

---

# M10.18 — Deduplication Boundary

Do not implement full alert deduplication.

However, a single detector should avoid generating an excessive number of identical findings from the same observation window.

Implement only minimal rule-level suppression if required.

Full finding/alert deduplication belongs to later architecture.

---

# M10.19 — Detection State

Rules that require a time window may maintain bounded runtime state.

Examples:

    Port observations
    SYN counters
    ICMP counters
    Destination sets

State must be bounded and periodically cleaned.

Do not keep unlimited packet history in detector memory.

---

# M10.20 — Thread Safety

Detection may run while packet capture and other pipeline components operate.

Protect mutable detector state.

Do not introduce unnecessary global locks.

A detector must not corrupt shared state used by other services.

---

# M10.21 — Pipeline Integration

Extend the architecture:

    Scapy
       ↓
    CaptureManager
       ↓
    PacketProcessor
       ↓
    NormalizedPacket
       ├── TrafficStatisticsManager
       ├── PacketPersistence
       ├── DeviceDiscoveryManager
       ├── ConnectionTracker
       └── DetectionEngine

Detection must run after the required normalized data is available.

A detection failure must not stop:

- Capture
- Processing
- Statistics
- Persistence
- Device discovery
- Connection tracking

---

# M10.22 — Detection Queries

Provide an internal mechanism to retrieve findings for testing and later milestones.

Support:

    Recent findings
    Findings by rule
    Findings by source IP
    Findings by destination IP
    Findings by device
    Findings by time window

Do not implement the complete alert API.

---

# M10.23 — Tests — Detection Framework

Test:

- Rule registration
- Rule enable/disable
- Context creation
- Finding validation
- Engine execution
- Multiple rules
- Rule failure isolation
- Empty context
- Invalid context
- Diagnostics

---

# M10.24 — Port Scan Tests

Test at minimum:

- Below threshold
- Exactly at threshold
- Above threshold
- Multiple ports
- Repeated same port
- Multiple sources
- Multiple time windows
- SYN evidence
- Cleanup
- No false finding for normal low-volume traffic

---

# M10.25 — SYN Flood Tests

Test:

- Below threshold
- At threshold
- Above threshold
- Different destinations
- Different time windows
- Normal SYN traffic
- Cleanup

---

# M10.26 — ICMP Flood Tests

Test:

- Below threshold
- At threshold
- Above threshold
- Normal ping traffic
- Time window behavior
- Cleanup

---

# M10.27 — Internal Scan Tests

Test:

- Few destinations
- Threshold boundary
- Large number of destinations
- Internal destination filtering
- External destination traffic
- Multiple sources
- Cleanup

---

# M10.28 — High Bandwidth Tests

Test:

- Below threshold
- At threshold
- Above threshold
- Different windows
- Normal traffic
- Statistics input failure

---

# M10.29 — Integration Tests

Verify:

    CaptureManager
        ↓
    PacketProcessor
        ↓
    Statistics
        +
    Devices
        +
    Connections
        ↓
    DetectionEngine

Use controlled local/lab traffic.

Verify that findings are generated only when configured detection conditions are actually satisfied.

---

# M10.30 — Manual Verification

Use only authorized/local traffic.

Perform controlled tests for:

- Port scan-like traffic in a lab
- High-rate SYN traffic in a controlled environment
- High-rate ICMP traffic in a controlled environment
- Multiple internal destinations
- Controlled traffic-volume increase

Verify:

    Observed behavior
         ↓
    Detection condition
         ↓
    Detection finding
         ↓
    Evidence

Do not perform attacks against unauthorized systems.

---

# M10.31 — Performance Baseline

Measure:

- Packets processed per second with detection disabled
- Packets processed per second with detection enabled
- Detection overhead per packet/window
- Rule execution time
- Memory usage
- Active detector state size

Measure each detector individually where practical.

Do not claim production-scale detection throughput.

---

# M10 Completion Criteria

M10 is complete when:

- Detection framework exists.
- Common detection rule interface exists.
- Detection context exists.
- Detection finding model exists.
- Detection Engine exists.
- Rule configuration exists.
- Port Scan detector works.
- SYN Flood detector works.
- ICMP Flood detector works.
- Internal Scan detector works.
- High Bandwidth detector works.
- Evidence is attached to findings.
- Confidence is separated from future risk scoring.
- Detector state is bounded.
- Rule failures are isolated.
- Detection integrates with the packet pipeline.
- Unit tests pass.
- Integration tests pass.
- Manual authorized verification succeeds.
- Performance baseline is recorded.
- No alerts, correlation, risk scoring, ML/AI, WebSockets, or frontend code are introduced.

---

# Current Immediate Task

**M10.1 — Design the detection framework before implementing individual detectors.**

First:

1. Review `NormalizedPacket`.
2. Review M6 traffic statistics.
3. Review M8 device information.
4. Review M9 connection information.
5. Define the DetectionContext.
6. Define the DetectionRule interface.
7. Define the DetectionFinding schema.
8. Define rule registration and configuration.
9. Define detector state ownership.
10. Define error isolation behavior.
11. Add framework tests.
12. Only after the framework is stable, implement the Port Scan detector.

---

# Architecture Boundary

M10 produces:

    Network Data
         ↓
    Detection Engine
         ↓
    Detection Findings

M11 will consume findings to create:

    Alerts
    Alert Evidence
    Alert Severity
    Alert Lifecycle
    Alert Deduplication

M12 will later add:

    Correlation
    Risk Scoring
    Historical Context
    Behavioral Contribution
    ML Contribution

M10 itself must not implement those systems.