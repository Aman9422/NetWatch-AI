# M22 — ML-Based Anomaly Detection

**Project:** NetWatch AI  
**Milestone:** M22  
**Suggested version:** v0.0.22  
**Base version:** v0.0.21  
**Status:** Planned  
**Primary objective:** Implement local machine-learning-based network anomaly detection using the behavioural profiles and observation windows produced by M21.

---

## 1. Context and instructions

M0–M20 established and released the base network-monitoring application.

M21 implemented the Behavioral Baseline Engine and is marked implemented and verified.

M21 provides:
- Per-device behavioural observation windows.
- Nine behavioural features.
- Persistent SQLite storage.
- Statistical profiles.
- Learning states.
- A REST API.
- A frontend page for inspecting learned behaviour.

M22 must consume this existing functionality rather than create another baseline system.

Before changing anything:

1. Inspect the current repository and Git state.
2. Read the M20 release and M21 milestone documentation.
3. Inspect the actual M21 source code, database models, configuration, services, tests and API response models.
4. Understand how completed 60-second windows are produced and persisted.
5. Inspect the existing detection, finding, alert and incident pipelines.
6. Inspect the current frontend navigation and page architecture.
7. Confirm the installed Python and frontend versions.

Do not assume that proposed architecture matches the implementation. Base every integration decision on the actual code.

**Preserve every working M0–M21 feature.** Avoid unnecessary rewrites and do not modify M21's historical records to make M22 work.

## 2. Objective

Implement an ML-based engine that identifies network activity that differs significantly from a device's previously observed behaviour.

For example:

A device normally:
- Transmits a relatively stable number of packets per minute.
- Communicates with a small number of peers.
- Uses a familiar set of protocols.
- Contacts a predictable number of destination ports.

A later observation window might show:
- A sudden increase in packet volume.
- An unusually large number of peers.
- A substantial increase in destination ports.
- Unusual protocol distribution.
- A significantly different connection rate.

M22 should use a machine-learning model trained on historical observations to identify such unusual windows.

The engine should be capable of answering:

- Which device exhibited unusual behaviour?
- Which observation window was unusual?
- Which model evaluated the window?
- What decision score did the model produce?
- How many historical observations were used?
- Which features were available for the evaluation?
- Was an anomaly finding created?

The system must preserve the evidence used to produce each result.

**Important:** An anomaly is not automatically proof of malicious activity. It means the observed behaviour differs from the learned pattern and requires investigation.

## 3. Scope boundaries

### Implement in M22

1. Local ML dependency and model integration.
2. Per-device model training.
3. Isolation Forest anomaly detection.
4. Historical training-data selection.
5. Inference on completed behavioural windows.
6. Model lifecycle and training status.
7. Anomaly result persistence.
8. Duplicate-evaluation protection.
9. Anomaly REST APIs.
10. Integration with existing findings and alerts where supported.
11. Anomalies frontend page.
12. Model status and investigation information.
13. Backend, frontend and integration tests.
14. Performance verification and documentation.

### Explicitly exclude

- Local LLM integration.
- AI-generated explanations.
- AI Security Analyst.
- LLM-based log or event sequence investigation.
- Wazuh integration.
- Automatic blocking, quarantine or IPS.
- Cloud-hosted inference or training.
- Mandatory GPU requirements.
- Deep-learning models and autoencoders.
- Multiple competing ML algorithms in this milestone.

These belong to later milestones.

## 4. ML algorithm selection

Implement **Isolation Forest** as the primary anomaly-detection algorithm.

Use the locally installed and maintained `scikit-learn` package, selecting a version compatible with the project's Python environment.

Requirements:

- Local CPU inference.
- No external API.
- No cloud dependency.
- Reproducible model training.
- Configurable model parameters.
- Explicit model version and configuration.
- Consistent feature ordering between training and inference.

Start with a configurable implementation using parameters such as:

| Parameter | Suggested default |
|---|---:|
| Algorithm | Isolation Forest |
| Number of estimators | 100 |
| Contamination | 0.02 |
| Random state | 42 |
| Maximum training windows | 1,440 |
| Minimum training windows | 100 |
| Model refresh interval | 30 new usable windows |

These are starting defaults, not claims of optimal accuracy. Validate them with controlled data and document their limitations.

Keep model construction behind a dedicated service or interface so the implementation can support additional algorithms in future milestones without rewriting the packet pipeline.

Do not implement Isolation Forest, One-Class SVM and Autoencoders simultaneously. One correctly integrated and tested algorithm is preferable to several incomplete implementations.

## 5. Training-data requirements

Use the historical observations stored by M21 in `baseline_windows`.

Do not train directly on raw packet payloads.

Training must be device-specific wherever sufficient historical observations exist.

### Eligibility

A model must not become ready merely because a device has an `established` M21 profile.

M21's established state begins at 30 windows. M22 should impose its own configurable minimum training-data requirement.

Use a default minimum of 100 usable historical observation windows.

Suggested model states:

- `collecting_data`: insufficient historical observations.
- `training`: model training is in progress.
- `ready`: trained and available for inference.
- `stale`: a refresh is due or the training dataset has changed materially.
- `failed`: training or model initialization failed.
- `disabled`: the model has been explicitly disabled.

The API and frontend must distinguish these states.

### Training-data selection

1. Fetch a bounded number of recent historical observation windows for the selected device.
2. Exclude the window currently being evaluated.
3. Exclude previously identified anomalous windows from subsequent training where sufficient history is available.
4. Never use future observations to score an earlier observation.
5. Respect the M21 retention policy and available training history.
6. Do not query an unlimited historical dataset into memory.
7. Report the actual number of usable training windows.
8. Handle insufficient data without fabricating a model.

### Cold-start limitation

During initial training, there is no trusted anomaly history.

The initial dataset may therefore contain unusual activity that was not recognized earlier. Isolation Forest cannot guarantee that the initial training set is entirely benign.

Document this cold-start limitation prominently.

Do not claim that unsupervised learning can determine malicious intent or eliminate training-data poisoning.

## 6. Feature engineering

Use the nine M21 features as the starting point:

| Feature | M21 source |
|---|---|
| `packet_count` | Packets per observation window |
| `byte_count` | Total bytes |
| `tcp_packets` | TCP count |
| `udp_packets` | UDP count |
| `icmp_packets` | ICMP count |
| `dns_packets` | DNS count |
| `unique_peers` | Distinct observed peers |
| `unique_destination_ports` | Distinct destination ports |
| `new_connections` | Conversation-key cardinality |

Use actual stored observations and preserve the existing meanings of the metrics.

### Missing-value handling

M21 explicitly represents unmeasurable `new_connections` as `NULL`.

Never replace missing data with zero without a documented reason.

Implement a consistent per-device feature-selection and preprocessing strategy.

For example:

- Determine which features have sufficient usable historical observations.
- Exclude features that are unavailable too frequently.
- Use a documented imputation strategy for occasional missing values when a feature remains eligible.
- Preserve the feature list and preprocessing configuration used by each model.
- Use precisely the same preprocessing during inference.

Do not change the order or meaning of features between training and inference.

### Truncated cardinalities

M21 may report `peers_truncated` or `ports_truncated`.

These values represent lower bounds, not exact cardinalities.

Do not silently treat them as exact measurements.

Choose and document a consistent strategy for training and inference, such as excluding unreliable measurements or explicitly representing truncation.

The model must receive equivalent feature semantics during both phases.

## 7. Model training and lifecycle

Implement a dedicated anomaly-detection module.

Suggested organization:

```text
app/
  anomaly_detection/
    features.py
    preprocessing.py
    model.py
    training.py
    inference.py
    lifecycle.py
    store.py
    engine.py
```

Adapt this layout to the existing repository conventions.

Responsibilities:

- `features.py`: creates model-ready inputs from M21 windows.
- `preprocessing.py`: handles feature eligibility, missing values and input consistency.
- `model.py`: constructs and configures Isolation Forest.
- `training.py`: loads historical observations and trains models.
- `inference.py`: evaluates new completed windows.
- `lifecycle.py`: manages model states, freshness and refresh.
- `store.py`: persists model metadata and anomaly outcomes.
- `engine.py`: connects the components to the existing runtime pipeline.

### Model caching

Do not train an Isolation Forest for every packet or every API request.

Use a bounded model cache.

Requirements:

- One logical model per device identity.
- Configurable cache size.
- Deterministic cache eviction.
- Model reuse between inference requests.
- Controlled retraining.
- No model-cache growth without limits.

### Retraining

Use a configurable refresh interval, initially 30 new usable windows.

Retraining must:

- Use fresh eligible historical data.
- Exclude the window being evaluated.
- Exclude previously flagged anomalous windows where practical.
- Preserve the previous working model if a refresh fails.
- Report training failures.
- Avoid blocking packet capture.

Do not retrain the complete model after every packet.

### Restart behaviour

Do not require unsafe Python pickle files to be committed to the repository or loaded from untrusted paths.

A practical initial design is:

- Persist model metadata and configuration.
- Reconstruct the model from retained observation windows when required after restart.
- Retrain lazily or through a controlled startup/background mechanism.
- Expose the model as unavailable until training successfully completes.

If model persistence is introduced, document the security and compatibility implications and validate model artifacts before loading them.

## 8. Completed-window inference

The M21 engine aggregates observations over 60-second windows and flushes them in batches.

M22 must evaluate **completed windows**, not individual packets.

Inspect the actual M21 flush lifecycle and identify a reliable integration point.

Requirements:

1. Receive a completed observation window.
2. Identify the device and window using the stable M21 identity.
3. Check whether the window has already been evaluated.
4. Obtain a suitable historical training dataset.
5. Load or train the device's model when eligible.
6. Generate the feature vector.
7. Apply the model's inference operation.
8. Store the evaluation result.
9. Create an anomaly finding only when the model classifies the window as anomalous.
10. Continue monitoring without interrupting capture.

### Important: no self-training leakage

A window must never be part of the training dataset used to score itself.

This must remain true even if M21 has already persisted the window before M22 performs inference.

Use a strict historical cutoff based on device identity and window timestamp.

### Idempotency

A completed window must not generate multiple anomaly records or multiple alerts because of:

- A repeated flush.
- A service retry.
- Backend restart.
- API pagination.
- A WebSocket reconnect.

Use a stable uniqueness key such as device identity plus window start, with an appropriate model-version strategy.

Repeated evaluation attempts must not create duplicate findings.

### Failure isolation

M22 must be an additional pipeline consumer.

An ML failure must not stop:

- Packet capture.
- Packet processing.
- Statistics collection.
- M21 baseline learning.
- Existing deterministic detection.
- Alert processing.

Handle model errors explicitly and report them using existing logging and monitoring conventions.

## 9. Anomaly scoring and interpretation

Use Isolation Forest's actual output.

The implementation should retain the raw model decision score and classification.

Remember:

- `predict()` classifies samples as inliers or outliers.
- `decision_function()` produces a decision score.
- A lower decision score represents more unusual behaviour.
- The decision score is not a probability.
- The model's output is not proof of a cyberattack.

Expose fields such as:

```text
device_key
window_start
window_seconds
algorithm
model_version
model_trained_at
training_sample_count
feature_names
decision_score
is_anomaly
contamination
created_at
```

Do not call the raw Isolation Forest score a probability or calibrated confidence.

Do not invent a probability such as 95% malicious.

If a display score is derived or normalized, document the exact transformation and distinguish it from the raw model output.

### Feature context

Provide useful evidence for investigation.

The system may compare an evaluated window against the corresponding M21 statistical profile.

For each available feature, provide useful context such as:

- Observed value.
- Baseline median.
- MAD or scaled MAD.
- Difference from the baseline median.
- Whether the feature is missing or truncated.

Clearly distinguish these statistical comparisons from actual Isolation Forest feature attribution.

Do not claim that Isolation Forest identifies a particular feature as the cause of a prediction unless a validated explanation method is implemented.

## 10. Anomaly persistence

Add suitable SQLAlchemy models and SQLite tables for M22.

At minimum, persist:

1. Model metadata and lifecycle information.
2. Anomaly evaluation outcomes.

An evaluation record should contain enough information to reproduce or inspect the decision:

- Stable device identity.
- Observation-window timestamp.
- Algorithm and model version.
- Raw decision score.
- Classification.
- Model training sample count.
- Model configuration.
- Feature-schema version.
- Evaluation timestamp.
- Evaluation status or skip reason when applicable.

Store feature context only when it is useful and bounded.

Avoid storing packet payloads, credentials, or unnecessary network-identifying details.

Use suitable uniqueness constraints and indexes.

Preserve M21's two baseline tables and their data model. Do not modify M21 observations simply to mark something as an anomaly.

### Retention

Introduce a configurable anomaly-record retention policy.

Use an appropriate default, for example 30 days, subject to the existing retention architecture.

Use the established M19 retention-sweeper pattern, with:

- Bounded deletion per run.
- Failure isolation.
- A clear outcome.
- No blocking of packet capture.
- Correct shutdown behaviour.

Document whether model metadata is retained after anomaly history expires.

## 11. Findings and alert integration

M22 should integrate genuine ML anomaly findings into the existing detection and alert architecture where the existing contracts support it.

Inspect the real M10, M11 and M12 implementations first.

Requirements:

- Preserve all existing deterministic detection rules.
- Do not alter their thresholds or behaviour.
- Identify ML-generated findings using a distinct detector source, such as `ml_anomaly`.
- Keep the underlying model evidence linked to the finding.
- Use existing alert lifecycle operations.
- Avoid generating repeated alerts for the same device and observation window.
- Apply a transparent severity policy if the current alert contract requires severity.
- Do not describe anomaly scores as alert confidence or probability.
- Make model-unavailable and insufficient-data states distinguishable from normal behaviour.

Do not silently rewrite M12's deterministic risk-scoring methodology.

If an ML finding enters incident correlation and changes an incident risk score through existing rules, document exactly how that occurs.

An anomaly record should remain available even when alert creation is deduplicated or unavailable.

**No automatic blocking, quarantine, or traffic modification.** The operator retains control.

## 12. REST API

Add API endpoints under `/api/v1`, following the project's existing response envelopes, validation and pagination conventions.

Suggested endpoints:

```http
GET  /api/v1/anomalies
GET  /api/v1/anomalies/{id}
GET  /api/v1/anomalies/models
GET  /api/v1/anomalies/models/{device_key}
POST /api/v1/anomalies/models/{device_key}/retrain
```

Adapt endpoint naming to existing conventions where necessary.

### Anomaly listing

Support:

- Pagination.
- Device filtering.
- Anomaly classification filtering.
- Time-range filtering.
- Model and algorithm information.
- Newest-first ordering.

### Individual anomaly detail

Return:

- Device identity.
- Evaluated window.
- Anomaly classification.
- Raw model score.
- Model metadata.
- Training sample count.
- Available feature context.
- Linked finding or alert, when one exists.

### Model listing and details

Expose:

- Device identity.
- Model lifecycle state.
- Algorithm.
- Model version.
- Training sample count.
- Last trained timestamp.
- Last evaluated timestamp.
- Available feature list.
- Next refresh status, if applicable.
- Failure or unavailable reason where safe.

### Manual retraining

Provide a controlled device-level retraining operation.

Requirements:

- Validate device identity.
- Require sufficient historical samples.
- Avoid concurrent duplicate training requests.
- Preserve the previous working model if training fails.
- Return a clear operation result.
- Never reset M21 behavioural history.

Use the established HTTP status codes and error envelopes.

Do not expose private file paths, stack traces, database paths or secrets.

Verify all new response shapes against the running backend before implementing frontend assumptions.

## 13. Frontend — Anomalies

Add a dedicated **Anomalies** page to the existing React/TypeScript application.

Use the existing component design, API service layer, typed models, hooks, page boundaries, navigation and error-handling patterns.

The page should display:

- Anomaly count.
- Affected devices.
- Recent anomalous observation windows.
- Device identity.
- Detection time.
- Isolation Forest classification.
- Raw decision score.
- Model readiness.
- Training sample count.
- Linked alerts or incidents where available.

Add filters for device, time range and classification.

Provide a device-level model detail view showing training and lifecycle information.

### Investigation context

For an individual anomaly, display available feature context alongside M21's historical statistical values.

Keep raw model decisions and baseline comparisons visually distinct.

The UI must not claim that an anomaly is necessarily malicious.

Display an explicit explanation such as:

"An anomaly indicates a deviation from previously observed network behaviour. It is not confirmation of malicious activity."

### Model status

Clearly represent:

- Collecting data.
- Insufficient training samples.
- Training.
- Ready.
- Stale.
- Failed.
- Disabled.

An insufficient-data model must never be displayed as healthy or normal.

### Frontend states

Handle:

- No anomalies.
- No models ready.
- Devices still collecting baseline samples.
- Model training.
- Model unavailable.
- Model failure.
- API unavailable.
- Empty historical results.
- Loading and pagination.
- Stale model information.
- Retraining in progress.
- Retraining success and failure.

Use real backend data only.

Do not create fabricated demo anomalies in the production interface.

## 14. Performance and reliability

The new ML functionality must not make the existing packet pipeline unreliable.

Verify:

- Capture is not blocked by model training.
- Model inference occurs on completed windows only.
- Training does not run for every packet.
- The model cache is bounded.
- Training datasets are bounded.
- Inference input sizes are bounded.
- Model refresh is controlled.
- Database writes are batched or appropriately managed.
- Duplicate evaluation is prevented.
- Database failures are isolated.
- Model failures do not stop M21.
- Restart recovery works.
- Anomaly retention works.
- Existing capture, statistics, detections, alerts, incidents and reporting remain functional.

Measure actual CPU and memory impact during controlled local capture.

Do not claim high throughput, enterprise-scale capacity or production accuracy based solely on development-machine tests.

## 15. Testing

### Backend tests

Add tests for at least:

1. Isolation Forest initialization.
2. Deterministic model configuration.
3. Feature-vector construction.
4. Consistent feature ordering.
5. Missing-value handling.
6. Truncated cardinality handling.
7. Minimum training sample requirements.
8. Training-data selection by device.
9. Historical time cutoff.
10. Exclusion of the evaluated window from training.
11. Exclusion of previously flagged anomalies where supported.
12. Inference on known normal synthetic data.
13. Inference on deliberately unusual synthetic data.
14. Raw decision-score handling.
15. Correct anomaly classification.
16. No probability claims in output fields.
17. Model lifecycle transitions.
18. Retraining interval.
19. Failed retraining preserves the previous model.
20. Bounded model caching.
21. Model recreation after backend restart.
22. Duplicate evaluation prevention.
23. Repeated flush idempotency.
24. Anomaly persistence.
25. API pagination and filters.
26. API validation and error envelopes.
27. Manual retraining.
28. Anomaly retention.
29. Database failure isolation.
30. Model failure isolation.
31. Existing M0–M21 regression behaviour.

Use deterministic synthetic test datasets. Do not depend on internet access or external datasets.

### Frontend tests

Test:

- Anomaly listing.
- Empty results.
- Filters and pagination.
- Device detail.
- Model lifecycle statuses.
- Insufficient training data.
- Raw decision-score display.
- Feature-context presentation.
- Linked alerts and incidents.
- Retraining confirmation.
- Retraining success and failure.
- API-unavailable state.
- Anomaly disclaimer.
- Correct navigation.

### Integration tests

Demonstrate:

```text
Start backend
    ↓
Start authorized packet capture
    ↓
M21 receives normalized packets
    ↓
M21 aggregates behavioural windows
    ↓
M21 persists historical samples
    ↓
M22 verifies training eligibility
    ↓
M22 trains the device-specific Isolation Forest
    ↓
A new completed window arrives
    ↓
M22 excludes the current window from training
    ↓
M22 evaluates the window
    ↓
Anomaly outcome is persisted
    ↓
Anomalous result creates a finding when appropriate
    ↓
Existing alert and incident pipeline processes it
    ↓
Frontend displays the actual result
```

Also verify:

- A device with insufficient training history does not receive a fabricated prediction.
- A normal window is not automatically labelled anomalous.
- An unusual controlled test window can be detected when the trained model supports that distinction.
- Reprocessing the same window does not duplicate outcomes.
- A model failure does not interrupt capture or M21 learning.

Use authorized local traffic and controlled synthetic data.

## 16. Model evaluation and honest reporting

There is no established labelled production dataset in the current project.

Therefore:

- Do not claim a real-world accuracy percentage.
- Do not claim a false-positive rate without labelled evaluation data.
- Do not claim precision or recall based on synthetic tests alone.
- Do not describe Isolation Forest decision scores as probabilities.
- Do not claim that every anomaly represents an attack.

Record:

- Number of training samples.
- Number of test samples.
- Synthetic scenarios evaluated.
- Detected injected anomalies.
- Normal scenarios tested.
- Cases the model missed.
- Cases where model output was unstable.
- CPU and memory measurements.

Include the model configuration and random seed so tests can be reproduced.

## 17. Quality gates

Preserve all M0–M21 quality gates.

Run the full backend quality gate:

```powershell
python backend/scripts/run_quality_gates.py --full
```

Run the frontend verification:

```powershell
cd frontend
npm test
npm run test:live
npm run typecheck
npm run build
```

Verify that the Python dependencies work in the project's supported Python environment.

Add required security