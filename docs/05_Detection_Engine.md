# NetWatch AI — Detection Engine

**Project:** NetWatch AI  
**Detection Architecture:** Hybrid Detection  
**Version:** 1.0  
**Status:** In Development

---

# 1. Overview

The Detection Engine is responsible for identifying suspicious, anomalous, and potentially malicious network behavior from network telemetry collected by NetWatch AI.

NetWatch AI does not attempt to maintain a static rule for every possible cyberattack.

Instead, it uses a hybrid detection architecture consisting of:

1. Rule-Based Detection
2. Behavioral Detection
3. Machine-Learning Anomaly Detection
4. Event Correlation
5. Risk Scoring
6. AI-Assisted Investigation

This approach is designed to provide broader detection coverage while reducing the number of unnecessary or duplicate alerts.

---

# 2. Detection Objectives

The Detection Engine should:

- Detect known suspicious network patterns.
- Identify unusual behavior without requiring a predefined attack signature.
- Establish behavioral baselines for monitored devices.
- Combine multiple detection signals.
- Reduce duplicate and low-value alerts.
- Preserve evidence for every important security finding.
- Produce explainable risk scores.
- Support configurable detection thresholds.
- Allow new detectors to be added without redesigning the entire system.

---

# 3. Detection Architecture

```text
                         Network Traffic
                                |
                                v
                       +-------------------+
                       | Packet Capture     |
                       +---------+---------+
                                 |
                                 v
                       +-------------------+
                       | Packet Processing |
                       +---------+---------+
                                 |
                                 v
                       +-------------------+
                       | Feature Extraction|
                       +---------+---------+
                                 |
          +----------------------+----------------------+
          |                      |                      |
          v                      v                      v
   +--------------+       +--------------+       +--------------+
   | Rule Engine  |       | Behavioral   |       | ML Anomaly   |
   |              |       | Detection    |       | Detection    |
   +------+-------+       +------+-------+       +------+-------+
          |                      |                      |
          +----------------------+----------------------+
                                 |
                                 v
                       +-------------------+
                       | Correlation       |
                       | Engine            |
                       +---------+---------+
                                 |
                                 v
                       +-------------------+
                       | Risk Scoring      |
                       | Engine            |
                       +---------+---------+
                                 |
                                 v
                       +-------------------+
                       | Alert Management  |
                       +---------+---------+
                                 |
                       +---------+---------+
                       |                   |
                       v                   v
                +-------------+    +-------------+
                | Evidence    |    | AI Analysis |
                +------+------+    +------+------+
                       |                  |
                       +---------+--------+
                                 |
                                 v
                     Dashboard / API / Reports
````

---

# 4. Detection Layers

## 4.1 Rule-Based Detection

Rule-based detection identifies network behavior with clearly defined characteristics.

Initial examples:

* Port scanning
* SYN flood
* ICMP flood
* Internal network scanning
* High bandwidth usage
* DNS anomalies
* Suspicious port activity

Rules should be:

* Deterministic
* Explainable
* Configurable
* Independently testable
* Versioned

The initial system should contain a small number of strong rules instead of attempting to implement hundreds of static signatures.

---

# 5. Behavioral Detection

Behavioral detection identifies deviations from a device's normal activity.

Instead of asking:

> Does this traffic match a known attack?

the behavioral engine asks:

> Is this behavior significantly different from the device's established behavior?

Example:

```text
Normal Device Behavior

Packets/sec:
50–100

Current:

2,500 packets/sec

        ↓

Behavioral Anomaly
```

Other behavioral indicators include:

* Sudden traffic spikes
* New destinations
* New destination ports
* Unusual protocol usage
* Increased connection frequency
* Increased failed connections
* Unusual outbound traffic
* Unusual DNS activity

---

# 6. Device-Specific Baselines

A single network-wide threshold is not suitable for every device.

For example:

```text
Router

Normal:
10,000 packets/sec


Laptop

Normal:
150 packets/sec
```

A threshold appropriate for the router may be meaningless for the laptop.

NetWatch AI therefore maintains behavioral information at the device level where sufficient historical data is available.

---

# 7. Baseline Learning

A newly discovered device enters a learning state.

```text
New Device
     |
     v
Learning
     |
     v
Sufficient Observations
     |
     v
Baseline Established
     |
     v
Continuous Monitoring
```

Baseline information may include:

* Average packets/sec
* Average bytes/sec
* Average unique destinations
* Average unique ports
* Average packet size
* Typical protocol distribution
* Typical connection frequency

The baseline should evolve gradually rather than immediately changing because of a single unusual event.

---

# 8. Feature Extraction

The detection engine operates on structured features rather than raw packet objects.

## Packet Features

* Timestamp
* Source IP
* Destination IP
* Source port
* Destination port
* Protocol
* Packet size
* TTL
* TCP flags

## Connection Features

* Connection duration
* Packets sent
* Packets received
* Bytes sent
* Bytes received
* Connection state
* Connection frequency

## Behavioral Features

* Packets/sec
* Bytes/sec
* Unique destinations
* Unique ports
* Failed connection ratio
* SYN ratio
* ACK ratio
* ICMP rate
* DNS request rate
* Protocol ratios
* Average packet size

---

# 9. Feature Windows

High-frequency network traffic should be aggregated into short time windows.

Example:

```text
10-Second Window

Source:
192.168.1.25

Packets/sec:          850
Bytes/sec:            1.8 MB
Unique destinations:  27
Unique ports:         61
TCP ratio:            0.92
UDP ratio:            0.06
ICMP ratio:           0.02
Failed connections:   48
DNS requests:         14
```

This feature window can be evaluated by:

* Rule detectors
* Behavioral detection
* ML anomaly detection

---

# 10. Rule Detection Strategy

Rules should use multiple signals whenever practical.

Avoid detection logic such as:

```text
40 ports = attack
```

Instead use combinations such as:

```text
Unique ports
+
Connection rate
+
SYN ratio
+
Failed connection ratio
+
Time window
```

This provides stronger evidence and can reduce false positives.

---

# 11. Port Scan Detection

## Objective

Detect behavior consistent with network reconnaissance.

Potential indicators:

* Many unique destination ports
* High connection attempt rate
* High SYN ratio
* High failed connection ratio
* Short time window

Example:

```text
Source:
192.168.1.25

Unique Ports:
57

Duration:
30 seconds

SYN Ratio:
93%

Failed Connections:
48
```

Potential result:

```text
Potential Port Scan

Severity:
High
```

Initial configuration:

```text
Unique ports >= 40
Time window = 30 seconds
```

These values are configurable defaults.

---

# 12. SYN Flood Detection

## Objective

Detect unusually high volumes of TCP SYN traffic associated with incomplete connection establishment.

Potential signals:

* SYN packets/sec
* SYN-to-SYN/ACK ratio
* Number of incomplete connections
* Traffic increase compared with baseline
* Concentration toward a target

The system should combine multiple indicators where possible.

Severity:

**High**

---

# 13. ICMP Flood Detection

## Objective

Identify abnormal ICMP traffic.

Potential indicators:

* ICMP packets/sec
* Increase relative to baseline
* Large concentration toward one destination

Initial default threshold:

```text
> 100 ICMP packets/sec
```

This should remain configurable.

Severity:

**Medium / High**

---

# 14. Internal Network Scan Detection

## Objective

Detect a host communicating with an unusually large number of internal destinations.

Example:

```text
192.168.1.25
      |
      +----> 192.168.1.1
      +----> 192.168.1.2
      +----> 192.168.1.3
      +----> 192.168.1.4
      +----> ...
```

Potential indicators:

* Large number of unique internal destinations
* High connection attempt rate
* Short-lived connections
* Many previously unseen hosts

Severity:

**High**

---

# 15. High Bandwidth Detection

## Objective

Identify abnormal bandwidth consumption.

The detector should consider:

1. Absolute bandwidth
2. Device baseline
3. Duration
4. Traffic direction

Example:

```text
Normal:
2 Mbps

Current:
150 Mbps

Duration:
45 seconds
```

This should initially produce:

```text
Abnormal Traffic Volume
```

rather than automatically declaring an attack.

Severity:

**Medium**

---

# 16. DNS Anomaly Detection

The initial DNS detector focuses on measurable traffic characteristics.

Possible indicators:

* Excessive DNS request rate
* Sudden DNS traffic increase
* Unusually long DNS queries
* Large number of unique domains
* Repeated unusual DNS destinations

Advanced DNS tunneling detection may be added later.

Severity:

**Medium**

---

# 17. Suspicious Port Detection

Traffic to a particular port should not automatically be classified as malicious.

Potentially sensitive services include:

```text
22
23
445
3389
1433
3306
```

Instead, suspicious port activity should become stronger evidence when combined with other signals.

Example:

```text
Suspicious Port
      +
Unknown Source
      +
Behavioral Anomaly
      +
Unusual Connection Rate
      ↓
Elevated Risk
```

---

# 18. Machine Learning Anomaly Detection

The ML engine provides an additional signal for identifying unusual traffic behavior.

Initial candidate:

**Isolation Forest**

Reasons for initial selection:

* Supports unsupervised anomaly detection.
* Does not require a fully labeled attack dataset.
* Works with numerical traffic features.
* Lightweight enough for a local development environment.

The model should operate on aggregated feature windows.

Example input:

```text
packets_per_second
bytes_per_second
unique_destinations
unique_ports
average_packet_size
failed_connection_ratio
tcp_ratio
udp_ratio
icmp_ratio
dns_request_rate
```

Example output:

```json
{
  "anomalous": true,
  "anomaly_score": 0.91
}
```

The ML result should be treated as a signal, not a final security verdict.

---

# 19. Why ML Does Not Analyze Every Packet

Sending every raw packet to a machine-learning model would create unnecessary computational overhead and may not provide useful context.

Instead:

```text
Raw Packets
     |
     v
Feature Aggregation
     |
     v
10-second Feature Window
     |
     v
ML Model
```

This reduces the amount of data processed by the model while providing behavioral context.

---

# 20. Correlation Engine

The Correlation Engine combines findings from multiple detectors.

Example:

```text
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
```

Without correlation, these could become multiple independent alerts.

With correlation, they can become one higher-quality security finding.

---

# 21. Correlation Window

Events occurring within a configurable time period can be grouped.

Example:

```text
30-second window

Event 1:
Port Scan

Event 2:
High SYN Rate

Event 3:
Failed Connections

        ↓

Correlated Security Event
```

The initial implementation can use short time windows such as 30–60 seconds.

---

# 22. Alert Deduplication

Repeated detection of the same behavior should not generate unlimited duplicate alerts.

Example:

```text
Detection
    |
    v
Existing Related Alert?
    |
  +---+---+
  |       |
 Yes      No
  |       |
Update   Create
Alert    Alert
```

A deduplication key may include:

```text
rule_id
source_ip
destination_ip
correlation_window
```

---

# 23. Risk Scoring

The final risk score combines multiple signals.

Conceptual model:

```text
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
```

Initial conceptual weighting:

```text
Rule Evidence          40%
Behavioral Deviation   25%
ML Anomaly             20%
Asset Context          10%
Historical Context      5%
```

These are starting design values and must be validated during testing.

---

# 24. Asset Context

The risk engine can consider contextual information about a device.

Example:

```text
Device:
Kali VM

Role:
Security Testing

Activity:
Port Scanning
```

The same activity generated by an unknown workstation may deserve greater investigation priority.

Context should influence risk rather than automatically declaring the activity safe.

---

# 25. Trust Score

Devices may have a contextual trust score:

```text
0–100
```

Example:

```text
Authorized Security Testing VM
Trust = 90

Normal Workstation
Trust = 70

Unknown IoT Device
Trust = 30
```

The trust score is one input to risk calculation.

It does not represent proof that a device is safe.

---

# 26. Risk vs Confidence

Risk and confidence are separate concepts.

## Risk

How potentially harmful the behavior appears.

## Confidence

How strong the evidence is that the detection is correct.

Example:

```text
Risk:
90

Confidence:
72%
```

This represents potentially serious behavior with incomplete evidence.

---

# 27. Severity Classification

Initial severity mapping:

```text
Critical: 90–100
High:     70–89
Medium:   40–69
Low:       1–39
```

Severity may be adjusted using contextual information.

---

# 28. Alert Generation

An alert should contain enough information for an analyst to understand why it was generated.

Example:

```json
{
  "title": "Potential Port Scan Detected",
  "severity": "high",
  "risk_score": 86,
  "confidence": 94,
  "source_ip": "192.168.1.25",
  "destination_ip": "192.168.1.10",
  "rule_id": "PORT_SCAN_001",
  "status": "new"
}
```

---

# 29. Evidence Collection

Every important alert should preserve supporting evidence.

Possible evidence:

* Related packet IDs
* Source IP
* Destination IP
* Ports
* Protocol
* Timestamp
* Connection statistics
* Behavioral baseline values
* Feature values
* Rule result
* ML anomaly score
* Related events
* Device context

Example:

```text
Alert
 |
 +-- Detection Rule
 |
 +-- Source Device
 |
 +-- Related Packets
 |
 +-- Related Connections
 |
 +-- Behavioral Evidence
 |
 +-- ML Evidence
 |
 +-- Correlated Events
```

---

# 30. Alert Lifecycle

```text
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
```

False-positive decisions should be retained for future detection tuning.

---

# 31. False Positive Reduction

The system should use multiple mechanisms rather than relying on one technique.

Methods include:

* Device-specific baselines
* Multiple behavioral signals
* Configurable thresholds
* Confidence scoring
* ML anomaly scores
* Asset context
* Historical context
* Alert correlation
* Alert deduplication
* Allowlisting
* Analyst feedback

The goal is not zero false positives.

The goal is to produce useful and explainable alerts with manageable noise.

---

# 32. Allowlisting

Authorized devices or activities can be explicitly configured.

Example:

```text
Device:
192.168.1.50

Role:
Authorized Security Scanner
```

Allowlisting should adjust or suppress selected alerts according to configuration while maintaining appropriate audit visibility.

---

# 33. False-Positive Feedback

When an analyst marks an event as:

```text
False Positive
```

the system should retain relevant information such as:

* Detector
* Source device
* Features
* Time
* Detection result
* Analyst decision

Future versions can use this information to tune thresholds and ML models.

---

# 34. AI Analysis Boundary

AI should not be responsible for analyzing every packet or directly declaring every event malicious.

Instead:

```text
Detection Engine
      |
      v
Structured Security Event
      |
      v
AI Analysis
```

The AI receives structured evidence generated by the detection system.

Example input:

```json
{
  "event_type": "port_scan",
  "source_ip": "192.168.1.25",
  "unique_ports": 57,
  "duration_seconds": 30,
  "syn_ratio": 0.93,
  "failed_connections": 48,
  "ml_anomaly_score": 0.91
}
```

The AI can then:

* Explain the finding
* Summarize evidence
* Suggest investigation steps
* Recommend actions
* Generate analyst-readable summaries

The AI must not invent evidence that does not exist in the event data.

---

# 35. Unknown Attack Handling

NetWatch AI does not need to identify the exact name of every previously unseen attack.

For unknown behavior, the system may detect:

* Large traffic deviation
* New communication patterns
* Unusual ports
* Unusual destinations
* Protocol changes
* Connection anomalies
* Large outbound transfers
* Abnormal packet rates

Example:

```text
No matching rule
        +
Behavioral Deviation = 97
        +
ML Anomaly = 94
        |
        v
Suspicious Network Behavior
        |
        v
Risk Score = 91
```

This allows the system to surface suspicious activity even when the exact attack type is unknown.

---

# 36. Detection Context

Detection components should operate using a shared context object.

Conceptual structure:

```text
DetectionContext

recent_packets
recent_connections
device_profile
behavioral_baseline
feature_window
active_alerts
configuration
```

This allows individual detectors to use information beyond a single packet.

---

# 37. Detection Result Interface

Every detector should return a standardized result.

Example:

```json
{
  "rule_id": "PORT_SCAN_001",
  "triggered": true,
  "confidence": 94,
  "risk_contribution": 80,
  "source_ip": "192.168.1.25",
  "destination_ip": "192.168.1.10",
  "evidence": {
    "unique_ports": 57,
    "syn_ratio": 0.93,
    "failed_connections": 48
  }
}
```

This makes the detection architecture modular.

---

# 38. Detection Engine Interface

Conceptually:

```python
class DetectionRule:

    rule_id: str

    def evaluate(self, context):
        pass
```

Example:

```python
class PortScanRule(DetectionRule):

    rule_id = "PORT_SCAN_001"

    def evaluate(self, context):
        # Analyze the current feature window
        # Return a standardized detection result
        pass
```

New detectors can therefore be added without modifying the entire detection engine.

---

# 39. Detection State Management

Some detectors require temporary state.

Examples:

* Recent connections
* Recent destination ports
* Recent destinations
* Packet counters
* SYN counters
* DNS counters
* Recent anomaly scores

Conceptual flow:

```text
Packet 1
   |
Packet 2
   |
Packet 3
   |
Packet N
   |
   v
Feature Window
   |
   v
Detection
```

Temporary state should generally remain in memory.

Persistent security findings should be written to the database.

---

# 40. Time Windows

Initial default detection windows:

| Detection         | Initial Window |
| ----------------- | -------------: |
| Port Scan         |         30 sec |
| SYN Flood         |         10 sec |
| ICMP Flood        |         10 sec |
| Internal Scan     |         60 sec |
| DNS Anomaly       |         60 sec |
| Bandwidth Abuse   |         30 sec |
| Event Correlation |      30–60 sec |

All values should remain configurable.

---

# 41. Detection Rules Configuration

Rules should be stored in the database rather than having every threshold permanently hard-coded.

Example:

```text
Port Scan Detection

Enabled:
ON

Unique Ports:
40

Time Window:
30 seconds

Minimum SYN Ratio:
0.60

Severity:
High
```

The UI can modify configuration through the Detection Rules API.

---

# 42. Detection Engine Modules

Recommended backend structure:

```text
detection_engine/
│
├── __init__.py
├── engine.py
├── context.py
├── correlation.py
├── risk_scorer.py
├── deduplicator.py
├── state_manager.py
│
├── rules/
│   ├── __init__.py
│   ├── base.py
│   ├── port_scan.py
│   ├── syn_flood.py
│   ├── icmp_flood.py
│   ├── dns_anomaly.py
│   ├── bandwidth_abuse.py
│   ├── internal_scan.py
│   └── suspicious_port.py
│
├── behavioral/
│   ├── __init__.py
│   ├── baseline.py
│   ├── deviation.py
│   └── profile.py
│
└── ml/
    ├── __init__.py
    ├── anomaly_detector.py
    ├── feature_builder.py
    └── model_manager.py
```

---

# 43. Detection Pipeline

Conceptual pseudocode:

```python
def process_feature_window(context):

    detection_results = []

    for detector in rule_detectors:
        result = detector.evaluate(context)

        if result.triggered:
            detection_results.append(result)

    behavioral_result = behavioral_engine.evaluate(context)

    if behavioral_result:
        detection_results.append(behavioral_result)

    ml_result = ml_engine.evaluate(context)

    if ml_result:
        detection_results.append(ml_result)

    correlated_events = correlation_engine.correlate(
        detection_results
    )

    risk = risk_scorer.calculate(
        correlated_events,
        context
    )

    if risk.should_alert:

        alert = alert_engine.create(
            events=correlated_events,
            risk=risk,
            evidence=context
        )

        return alert

    return None
```

---

# 44. Performance Considerations

Network traffic can be high volume.

The detection engine should therefore:

* Aggregate traffic into short windows.
* Maintain counters in memory.
* Avoid expensive operations for every packet.
* Run ML on aggregated features rather than raw packets.
* Run AI analysis only for significant security events.
* Batch database writes where practical.
* Avoid unnecessary payload storage.
* Use indexed queries during investigation.

---

# 45. Detection Logging

The system should log:

* Detection errors
* Triggered detectors
* Correlation events
* Risk calculations
* Alert creation
* Alert deduplication
* Configuration changes
* ML model errors

Logs should support troubleshooting without unnecessarily exposing sensitive packet contents.

---

# 46. Testing Strategy

Every detector should have unit tests.

Example:

```text
Test:
50 unique destination ports
within 20 seconds

Expected:
Port scan detection triggered
```

Normal traffic:

```text
Test:
5 unique destination ports
during normal browsing

Expected:
No port scan alert
```

Additional tests:

* Threshold boundaries
* Multiple source IPs
* Multiple destination IPs
* Repeated scans
* Baseline deviation
* ML anomaly detection
* Alert correlation
* Alert deduplication
* False-positive handling
* Invalid packet data
* High traffic volume

---

# 47. Initial Detection Components

| Component         | Detection Method  | Initial Version |
| ----------------- | ----------------- | --------------- |
| Port Scan         | Rule + Behavioral | V1              |
| SYN Flood         | Rule + Behavioral | V1              |
| ICMP Flood        | Rule + Behavioral | V1              |
| Internal Scan     | Rule + Behavioral | V1              |
| Bandwidth Abuse   | Rule + Baseline   | V1              |
| DNS Anomaly       | Rule + ML         | V1/V2           |
| Suspicious Port   | Rule + Context    | V1              |
| Device Baseline   | Behavioral        | V1              |
| Isolation Forest  | ML                | V1/V2           |
| Event Correlation | Correlation       | V1              |
| Risk Scoring      | Risk Engine       | V1              |
| AI Analysis       | AI                | V2              |

---

# 48. Future Detection Integrations

NetWatch AI should not attempt to recreate every mature IDS signature.

Future versions may integrate with established open-source security tools such as:

* Suricata
* Zeek

Future architecture:

```text
                         Network Traffic
                                |
             +------------------+------------------+
             |                  |                  |
             v                  v                  v
        NetWatch           Suricata             Zeek
       Detection            Alerts              Events
             |                  |                  |
             +------------------+------------------+
                                |
                                v
                       Correlation Engine
                                |
                                v
                           Risk Scoring
                                |
                                v
                              Alert
```

This allows NetWatch AI to act as a monitoring, analytics, and correlation platform instead of attempting to recreate every specialized detection signature.

---

# 49. Future Detection Capabilities

Potential future detectors include:

* ARP spoofing
* DHCP spoofing
* DNS tunneling
* Beaconing
* Brute-force activity
* Data exfiltration indicators
* Lateral movement
* Command-and-control patterns
* Threat intelligence correlation
* MITRE ATT&CK technique mapping

These should be added incrementally and validated using test traffic.

---

# 50. Detection Design Principles

NetWatch AI follows these principles:

1. Do not attempt to encode every attack as a static rule.
2. Prefer behavioral signals for broader coverage.
3. Use device-specific baselines where sufficient history exists.
4. Treat ML as an additional signal rather than absolute truth.
5. Correlate multiple weak indicators into stronger findings.
6. Separate risk from confidence.
7. Preserve evidence for every meaningful alert.
8. Keep detection thresholds configurable.
9. Deduplicate repeated events.
10. Support allowlisting and analyst feedback.
11. Keep detection separate from AI explanation.
12. Keep detectors modular and independently testable.
13. Use established IDS integrations for mature signature coverage where appropriate.
14. Optimize for useful and explainable alerts rather than maximum alert volume.

---

# 51. Final Detection Architecture

```text
                         Network Traffic
                                |
                                v
                        Packet Capture
                                |
                                v
                       Packet Processing
                                |
                                v
                       Feature Extraction
                                |
             +------------------+------------------+
             |                  |                  |
             v                  v                  v
        Rule Engine       Behavioral Engine    ML Engine
             |                  |                  |
             +------------------+------------------+
                                |
                                v
                       Correlation Engine
                                |
                                v
                         Risk Scoring
                                |
                                v
                        Alert Generator
                                |
                    +-----------+-----------+
                    |                       |
                    v                       v
                 Evidence              AI Analysis
                    |                       |
                    +-----------+-----------+
                                |
                                v
                         Database / API
                                |
                                v
                       WebSocket Service
                                |
                                v
                       NetWatch AI UI
```

---

# 52. Conclusion

The NetWatch AI Detection Engine uses a hybrid architecture rather than depending on a large static rule base.

Known suspicious patterns are identified through configurable rules. Device behavior is evaluated through behavioral baselines. Machine learning provides an additional anomaly signal. Multiple findings are correlated before risk is calculated, and the resulting security events are presented through the alert system.

AI operates as an analyst-assistance layer that explains evidence and provides recommendations rather than acting as the sole source of truth.

This architecture allows NetWatch AI to detect known suspicious activity while still providing visibility into unusual behavior that may not match a predefined attack signature.

The system is intentionally modular so that additional detectors, ML models, threat intelligence sources, Suricata/Zeek integrations, and advanced security analytics can be added without redesigning the core detection pipeline.

