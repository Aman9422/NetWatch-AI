# NetWatch AI — AI Module

**Project:** NetWatch AI  
**Module:** AI and Machine Learning  
**Version:** 1.0  
**Status:** In Development  
**Primary Approach:** Hybrid ML + Local AI

---

# 1. Overview

The AI Module provides machine-learning-based anomaly detection and AI-assisted security analysis for NetWatch AI.

The module is divided into two separate capabilities:

```text
AI Module
│
├── Machine Learning Layer
│   └── Network Anomaly Detection
│
└── AI Analyst Layer
    └── Security Event Explanation
````

These components have different responsibilities.

## Machine Learning

The ML component analyzes structured network behavior and identifies anomalous activity.

## AI Analyst

The AI component analyzes structured security events and provides:

* Explanations
* Summaries
* Investigation guidance
* Recommendations

The AI Analyst should not independently decide whether every packet is malicious.

---

# 2. AI Architecture

```text
                       Network Traffic
                              |
                              v
                     Packet Processing
                              |
                              v
                      Feature Extraction
                              |
                              v
                    Feature Aggregation
                              |
                              v
                    +-------------------+
                    | ML Anomaly Engine |
                    +---------+---------+
                              |
                              v
                       Anomaly Score
                              |
                              v
                    Detection / Correlation
                              |
                              v
                         Security Event
                              |
                              v
                    +-------------------+
                    |   AI Analyst      |
                    |   Engine          |
                    +---------+---------+
                              |
                 +------------+------------+
                 |            |            |
                 v            v            v
             Summary      Explanation   Recommendation
                 |
                 v
             Dashboard
```

---

# 3. AI Design Principles

The AI architecture follows these principles:

1. ML and LLM-based analysis have separate responsibilities.
2. AI should operate on structured evidence whenever possible.
3. Raw packets should not be sent to an LLM unnecessarily.
4. AI should not invent evidence.
5. Security-critical decisions should remain explainable.
6. ML results should be treated as signals rather than absolute truth.
7. AI analysis should be optional.
8. Core packet monitoring and rule-based detection should continue if the AI module fails.
9. Local models should be preferred to avoid recurring API costs.
10. AI functionality should remain modular so the model can be replaced later.

---

# 4. Machine Learning Layer

## Objective

The ML layer identifies network behavior that deviates from learned or expected patterns.

The initial implementation should focus on **unsupervised anomaly detection**.

This reduces dependence on a large labeled attack dataset.

---

# 5. Initial ML Algorithm

The first candidate model is:

**Isolation Forest**

Reasons for the initial choice:

* Suitable for unsupervised anomaly detection.
* Does not require every training example to be labeled.
* Works with numerical feature vectors.
* Relatively lightweight.
* Suitable for local experimentation.
* Can be used with behavioral network features.

The model will not be treated as a complete intrusion-detection solution.

---

# 6. ML Input Data

The ML model should receive aggregated network features rather than raw packet objects.

Example 10-second feature window:

```text
packets_per_second
bytes_per_second
unique_destinations
unique_ports
connection_count
failed_connection_ratio
syn_ratio
tcp_ratio
udp_ratio
icmp_ratio
dns_request_rate
average_packet_size
```

Example feature vector:

```text
[
  850,
  1800000,
  27,
  61,
  94,
  0.51,
  0.93,
  0.92,
  0.06,
  0.02,
  14,
  812
]
```

---

# 7. Feature Preparation

Before features are passed to the model, the application should:

1. Validate the values.
2. Handle missing values.
3. Normalize or scale features where appropriate.
4. Ensure a consistent feature order.
5. Remove features that are not useful for the selected model.
6. Store the feature definition with the model version.

Conceptual pipeline:

```text
Raw Packets
     |
     v
Feature Extraction
     |
     v
Feature Window
     |
     v
Validation
     |
     v
Transformation
     |
     v
ML Model
```

---

# 8. Feature Windows

The model should operate on time-based windows instead of individual packets.

Initial window:

```text
10 seconds
```

The implementation should allow this value to be changed later.

Example:

```text
08:00:00 – 08:00:10
       |
       v
Feature Vector
       |
       v
ML Analysis
```

---

# 9. Training Strategy

The first model can be trained using traffic considered representative of normal behavior.

Potential sources:

* Controlled local network traffic
* Normal browsing
* DNS activity
* File transfers
* Authorized lab traffic
* Public datasets where licensing permits their use

The project should avoid assuming that a single training dataset represents every network environment.

---

# 10. Baseline Learning

The behavioral baseline and ML model serve complementary purposes.

## Behavioral Baseline

Tracks expected behavior for a particular device.

Example:

```text
Laptop
Normal packets/sec:
40–120
```

## ML Model

Looks at combinations of features and identifies unusual patterns.

Example:

```text
Packets/sec:
500

Unique ports:
80

Failed connections:
60

ML:
Anomalous
```

The two signals can therefore reinforce one another.

---

# 11. Device-Specific ML Consideration

Network devices can behave very differently.

A router, server, laptop, and IoT device may have completely different traffic patterns.

Therefore, future versions may support:

```text
Global Model
+
Device-Specific Baselines
```

Initially, the project can use a common model while maintaining device-specific behavioral statistics.

---

# 12. ML Output

The ML component should produce a structured result.

Example:

```json
{
  "model": "IsolationForest",
  "model_version": "1.0",
  "anomalous": true,
  "anomaly_score": 0.91,
  "timestamp": "2026-08-25T10:30:00Z"
}
```

The anomaly score should be normalized into an application-defined range if it is displayed directly in the dashboard.

---

# 13. ML Result Interpretation

The system should not automatically interpret:

```text
anomaly = true
```

as:

```text
attack = true
```

Instead:

```text
ML Anomaly
     +
Behavioral Deviation
     +
Rule Evidence
     +
Context
     |
     v
Correlation
     |
     v
Risk Assessment
```

This is an important architectural distinction.

---

# 14. ML Model Lifecycle

```text
Dataset
   |
   v
Feature Engineering
   |
   v
Training
   |
   v
Validation
   |
   v
Model Evaluation
   |
   v
Model Storage
   |
   v
Model Loading
   |
   v
Inference
```

---

# 15. Model Storage

Models should be stored separately from application source code.

Example:

```text
backend/
└── models/
    ├── anomaly_detector/
    │   ├── model.pkl
    │   ├── metadata.json
    │   └── feature_schema.json
```

Sensitive or environment-specific model files should not be committed unnecessarily to the repository.

---

# 16. Model Metadata

Each model should record information such as:

```text
Model Name
Model Type
Version
Training Date
Feature List
Training Data Description
Parameters
Evaluation Results
```

Example:

```json
{
  "model_name": "network_anomaly_detector",
  "algorithm": "IsolationForest",
  "version": "1.0",
  "features": [
    "packets_per_second",
    "bytes_per_second",
    "unique_destinations",
    "unique_ports"
  ]
}
```

---

# 17. Model Evaluation

Because unsupervised anomaly detection does not provide traditional classification metrics automatically, evaluation should use controlled test scenarios and available labeled data where possible.

Possible evaluation methods:

* Known normal traffic tests
* Controlled attack simulations
* Public datasets
* False-positive measurement
* Detection consistency
* Threshold sensitivity analysis

If labeled test data becomes available, metrics such as precision, recall, F1 score, and false-positive rate may be used.

---

# 18. ML False Positive Management

ML anomalies should not immediately become high-severity alerts.

For example:

```text
ML anomaly = 0.91
```

may only contribute to risk:

```text
ML contribution = high
```

The final alert should depend on the combined detection context.

---

# 19. AI Analyst Layer

The second part of the AI Module is the AI Analyst.

Its purpose is to help an analyst understand already-detected security events.

The AI Analyst may provide:

* Security summary
* Event explanation
* Evidence interpretation
* Investigation guidance
* Recommended next steps
* Device behavior summary

---

# 20. AI Analyst Input

The AI Analyst should receive structured information.

Example:

```json
{
  "event_type": "port_scan",
  "source_ip": "192.168.1.25",
  "destination_ip": "192.168.1.10",
  "unique_ports": 57,
  "duration_seconds": 30,
  "syn_ratio": 0.93,
  "failed_connections": 48,
  "behavioral_deviation": 0.88,
  "ml_anomaly_score": 0.91,
  "risk_score": 86,
  "confidence": 94
}
```

The AI should not be required to inspect every raw packet.

---

# 21. Local AI Strategy

To maintain the zero-cost requirement, the AI Analyst should preferably use a local model.

Possible local inference framework:

**Ollama**

Potential model families can be selected based on available hardware.

Examples may include:

* Llama
* Gemma
* Mistral

The exact model should be chosen after evaluating the development machine's hardware capacity.

---

# 22. Why Local AI

Local AI provides:

* No per-request API cost
* No mandatory external service
* Better privacy for network telemetry
* Offline operation
* Easier reproducibility

The project should not require a commercial AI API for core functionality.

---

# 23. AI Analyst Workflow

```text
Security Event
      |
      v
Evidence Collection
      |
      v
Structured Event
      |
      v
AI Prompt Builder
      |
      v
Local AI Model
      |
      v
Response Validation
      |
      v
AI Insight
      |
      v
Database
      |
      v
Dashboard
```

---

# 24. Prompt Construction

The backend should construct a controlled prompt from trusted structured data.

Example:

```text
Security Event:
Potential Port Scan

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

ML Anomaly:
0.91

Risk:
86/100

Explain the observed behavior.
Summarize the evidence.
Provide investigation recommendations.
Do not introduce evidence that is not provided.
```

The application should avoid sending unnecessary sensitive packet data.

---

# 25. AI Response Structure

The AI response should be converted into structured fields.

Example:

```json
{
  "summary": "Potential network reconnaissance was detected.",
  "explanation": "The source host contacted 57 unique ports within 30 seconds and generated a high proportion of failed TCP connections.",
  "recommendation": "Determine whether the source host is authorized to perform network discovery.",
  "confidence": 94
}
```

The backend should validate the response before displaying it.

---

# 26. AI Hallucination Prevention

The AI should be explicitly constrained.

Principles:

* Use only supplied evidence.
* Do not invent packet contents.
* Do not invent users or devices.
* Do not claim an attack is confirmed unless the detection system supports that conclusion.
* Clearly distinguish observed evidence from inference.
* Mark uncertain recommendations appropriately.

---

# 27. AI Confidence

The AI's confidence should not replace the detection engine's confidence.

There may be:

```text
Detection Confidence = 94%
AI Confidence = separate / optional
```

The system should clearly distinguish these values.

---

# 28. AI Insight Types

The system may support multiple insight types.

## Alert Summary

Short explanation of an alert.

## Alert Explanation

Detailed interpretation of evidence.

## Device Analysis

Summary of device behavior.

## Traffic Summary

Overview of recent traffic.

## Investigation Guidance

Possible analyst next steps.

---

# 29. AI Dashboard Integration

The Figma dashboard contains an AI insights section.

Example:

```text
+------------------------------------------+
|              AI Insight                  |
|                                          |
| Elevated DNS Activity Detected           |
|                                          |
| Device 192.168.1.25 generated unusually |
| high DNS request activity.               |
|                                          |
| Risk: 72/100                             |
| Confidence: 89%                          |
|                                          |
| Recommendation: Investigate the source   |
| device and review recent DNS activity.   |
+------------------------------------------+
```

The dashboard should obtain this data from the AI API.

---

# 30. AI Alert Investigation

When an analyst opens an alert:

```text
Alert
 |
 +---- Evidence
 |
 +---- Detection Results
 |
 +---- Behavioral Data
 |
 +---- ML Result
 |
 +---- AI Explanation
 |
 +---- Recommendation
```

This creates a single investigation workflow.

---

# 31. AI Failure Handling

AI is an optional component.

If the AI service fails:

```text
AI Engine DOWN
      |
      +---- Packet Capture continues
      +---- Statistics continue
      +---- Rule Detection continues
      +---- Behavioral Detection continues
      +---- Alerts continue
      +---- Dashboard continues
      |
      +---- AI Explanation unavailable
```

The system should display:

```text
AI Analysis Unavailable
```

rather than causing the application to fail.

---

# 32. AI Performance Considerations

LLM analysis may be significantly more expensive than normal rule evaluation.

Therefore:

* Do not send every packet to the AI.
* Analyze only significant events.
* Reuse previously generated insights where appropriate.
* Limit prompt size.
* Use structured evidence.
* Run AI analysis asynchronously where appropriate.

---

# 33. AI Caching

Repeated requests for the same alert should not always regenerate the same analysis.

Example:

```text
Alert #105
    |
    v
AI Insight already exists?
    |
  +---+---+
  |       |
 Yes      No
  |       |
Return   Generate
existing  new insight
```

This reduces unnecessary computation.

---

# 34. AI and Privacy

Network monitoring data can contain sensitive information.

The local AI architecture helps reduce the need to send telemetry to external services.

The application should still minimize the information provided to the model.

Avoid sending:

* Unnecessary packet payloads
* Passwords
* Authentication tokens
* Sensitive application data
* Unrelated user information

---

# 35. AI Module Backend Structure

Recommended structure:

```text
backend/
└── app/
    └── ai/
        ├── __init__.py
        ├── ai_service.py
        ├── prompt_builder.py
        ├── response_parser.py
        ├── model_manager.py
        ├── insight_service.py
        └── providers/
            ├── __init__.py
            └── ollama_provider.py
```

ML components remain separate:

```text
detection_engine/
└── ml/
    ├── anomaly_detector.py
    ├── feature_builder.py
    └── model_manager.py
```

---

# 36. ML vs AI Responsibilities

| Function                      | ML              | AI Analyst        |
| ----------------------------- | --------------- | ----------------- |
| Detect traffic anomaly        | Yes             | No                |
| Calculate anomaly score       | Yes             | No                |
| Learn traffic patterns        | Yes             | No                |
| Explain alert                 | No              | Yes               |
| Summarize evidence            | No              | Yes               |
| Recommend investigation steps | No              | Yes               |
| Identify exact attack         | Not necessarily | Not authoritative |
| Process every packet          | No              | No                |
| Operate on structured events  | Yes             | Yes               |

---

# 37. Complete AI Pipeline

```text
                       Network Traffic
                              |
                              v
                      Feature Extraction
                              |
                              v
                     Behavioral Window
                              |
                              v
                        ML Detector
                              |
                              v
                      Anomaly Score
                              |
                              v
                  Detection / Correlation
                              |
                              v
                       Security Event
                              |
                              v
                     Evidence Collection
                              |
                              v
                       AI Prompt Builder
                              |
                              v
                      Local AI Model
                              |
                              v
                    Response Validation
                              |
                              v
                        AI Insight
                              |
                              v
                       Database
                              |
                              v
                         Dashboard
```

---

# 38. AI API Integration

The AI Module is accessed through API endpoints such as:

```text
GET /api/v1/ai/insights
GET /api/v1/ai/alerts/{alert_id}
GET /api/v1/ai/devices/{device_id}
POST /api/v1/ai/analyze
```

API details are maintained in:

```text
docs/04_API_Specification.md
```

---

# 39. Database Integration

AI-related information is stored in:

```text
ai_insights
```

Important relationships:

```text
Alert
  |
  +---- AI Insight

Device
  |
  +---- AI Insight
```

The AI insight should contain:

* Summary
* Explanation
* Recommendation
* Model name
* Confidence where applicable
* Creation time

---

# 40. Initial ML Implementation Plan

## Step 1

Collect network telemetry.

## Step 2

Create feature windows.

## Step 3

Build the feature dataset.

## Step 4

Establish normal traffic data.

## Step 5

Train Isolation Forest.

## Step 6

Evaluate with controlled test traffic.

## Step 7

Integrate inference into the Detection Engine.

## Step 8

Combine ML results with rule and behavioral signals.

---

# 41. Initial AI Analyst Implementation Plan

## Step 1

Create structured security-event format.

## Step 2

Build prompt templates.

## Step 3

Install and configure a local model provider.

## Step 4

Implement AI service.

## Step 5

Validate model responses.

## Step 6

Store AI insights.

## Step 7

Display AI insights in the dashboard.

---

# 42. Evaluation Strategy

The AI module should be evaluated separately from the detection engine.

## ML Evaluation

Measure:

* False positives
* Anomaly detection consistency
* Detection sensitivity
* Behavior separation

Where labeled data is available:

* Precision
* Recall
* F1 score
* False-positive rate

## AI Evaluation

Evaluate:

* Accuracy of evidence summarization
* Hallucination rate
* Recommendation usefulness
* Response consistency
* Response latency

AI evaluation should be based on predefined test events rather than subjective impressions alone.

---

# 43. Limitations

The AI Module will have limitations.

## ML Limitations

* Quality depends on feature engineering.
* Network baselines vary between environments.
* Unsupervised models may identify legitimate unusual behavior as anomalous.
* Model performance may change as traffic patterns change.

## Local AI Limitations

* Model quality depends on available hardware.
* Response time depends on model size and hardware.
* Local models may provide imperfect recommendations.
* Larger models may require significant memory.

These limitations should be documented rather than hidden.

---

# 44. Future AI Improvements

Potential future capabilities:

* Better anomaly models
* Supervised attack classification
* Autoencoder-based anomaly detection
* Sequence-based traffic modeling
* Device-specific ML models
* Feedback-driven model tuning
* Natural-language security queries
* AI investigation assistant
* PCAP explanation
* Threat report generation
* MITRE ATT&CK mapping
* Local Retrieval-Augmented Generation (RAG)
* Historical incident comparison

---

# 45. Future AI Assistant

A future version may allow analysts to ask questions such as:

```text
Why was this host flagged?
```

or:

```text
Show me all suspicious activity from this device
today.
```

The assistant would retrieve structured information from NetWatch AI and generate an explanation.

Architecture:

```text
Analyst Question
      |
      v
AI Assistant
      |
      v
Query / Retrieval Layer
      |
      v
NetWatch Database
      |
      v
Structured Evidence
      |
      v
Local AI Model
      |
      v
Answer
```

This should be implemented only after the core monitoring and detection workflows are stable.

---

# 46. Design Principles

The AI Module follows these principles:

1. Separate ML anomaly detection from LLM-based analysis.
2. Use structured network features for ML.
3. Use structured security events for AI analysis.
4. Do not send every packet to an LLM.
5. Do not allow AI to become the sole security decision-maker.
6. Preserve evidence for AI explanations.
7. Prevent unsupported claims from being presented as observations.
8. Prefer local AI to maintain the project's zero-cost requirement.
9. Make AI optional.
10. Isolate AI failures from core monitoring.
11. Version ML models and record feature definitions.
12. Evaluate ML and AI independently.
13. Keep model providers replaceable.
14. Store generated insights for investigation and auditing.

---

# 47. Final Architecture

```text
                        NetWatch AI
                            |
              +-------------+-------------+
              |                           |
              v                           v
       Detection Engine                AI Module
              |                           |
       +------+-------+            +------+-------+
       |              |            |              |
       v              v            v              v
    Rules       Behavioral       ML Layer    AI Analyst
                     |              |              |
                     +------+-------+--------------+
                            |
                            v
                       Risk Score
                            |
                            v
                          Alert
                            |
                     +------+------+
                     |             |
                     v             v
                 Evidence      AI Insight
                     |             |
                     +------+------+
                            |
                            v
                       Dashboard
```

---

# 48. Conclusion

The NetWatch AI Module combines machine-learning-based anomaly detection with a local AI analyst layer.

The ML component focuses on identifying unusual network behavior from structured traffic features. The AI Analyst operates on structured security events and evidence to explain findings, summarize incidents, and provide investigation guidance.

This separation prevents the system from relying entirely on an AI model for security decisions and provides a more explainable architecture.

The initial implementation should remain lightweight:

```text
Feature Windows
      ↓
Isolation Forest
      ↓
Anomaly Signal
      ↓
Rule + Behavioral + ML
      ↓
Correlation
      ↓
Risk
      ↓
Alert
      ↓
Local AI Explanation
```

As the project matures, more advanced ML models, local language models, analyst assistance, and security integrations can be introduced without changing the fundamental architecture.
