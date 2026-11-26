# M22 — ML-Based Anomaly Detection

**Milestone:** M22 · **Version:** `v0.0.22` · **Status:** implemented and verified
**Depends on:** M21 (`v0.0.21`) for the observation windows every model is trained on

---

## 1. What M22 is

M21 learns. M22 judges — narrowly, and in one specific sense: it asks whether a
device's *last completed minute of traffic* looks like that device's *previous
minutes*. It does not ask whether the traffic is malicious, and it takes no action
against anything.

```text
M21 aggregation (60 s windows)
        |
        |  flush of completed windows
        v
  +-----------------+   bounded queue    +----------------------+
  | BaselineEngine  | -----------------> |  AnomalyEngine       |
  +-----------------+  (never blocks)    |  own thread          |
                                         +----------+-----------+
                                                    |
                     +------------------------------+-----------------------+
                     v                              v                       v
            ModelLifecycle                  inference.py             EvaluationStore
            (cache, train, refresh)          (score + context)       anomaly_evaluations
                     |                              |                       |
                     v                              |                       v
              anomaly_models                        |              scored  -> finding
              (metadata, state)                     |              skipped -> no verdict
                                                    |                       |
                                                    v                       v
                                            feature context        M11 alert (ml_anomaly)
```

One algorithm: **Isolation Forest** (`scikit-learn`), local CPU, no cloud, no GPU,
no second algorithm. Everything scikit-learn touches lives inside
`app/anomaly_detection/model.py`; the rest of the system talks to `FittedModel`.

---

## 2. Module layout

| File | Responsibility |
| --- | --- |
| `features.py` | Builds a `FeatureVector` from one M21 window. Owns missing-value semantics. |
| `preprocessing.py` | Chooses which features a model may use; stores the imputation plan. |
| `model.py` | The only scikit-learn import. Constructs, fits and scores the forest. |
| `training.py` | Loads history, builds the plan, fits, reports a `TrainingResult`. |
| `inference.py` | Scores one window; builds the statistical feature context. |
| `lifecycle.py` | Cache lookup, training orchestration, refresh, failure retention. |
| `dataset.py` | Bounded, strictly-historical window selection. |
| `cache.py` | Bounded LRU model cache. |
| `model_store.py` | `anomaly_models` reads and writes. |
| `evaluation_store.py` | `anomaly_evaluations` reads and writes. |
| `retention.py` | The 30-day evaluation-retention policy. |
| `states.py` | The lifecycle vocabulary and its operator-facing sentences. |
| `engine.py` | The runtime consumer: queue, worker thread, evaluation, findings. |

---

## 3. Features

The nine M21 features are reused unchanged; names and order come from
`app.baselines.statistics.FEATURE_COLUMNS`, so M21's profile and M22's matrix
cannot disagree about what a feature is called or where it sits.

| Feature | Meaning |
| --- | --- |
| `packet_count` | Packets in the window |
| `byte_count` | Total bytes |
| `tcp_packets` / `udp_packets` / `icmp_packets` / `dns_packets` | Per-protocol counts |
| `unique_peers` | Distinct observed peers |
| `unique_destination_ports` | Distinct destination ports |
| `new_connections` | Conversation-key cardinality |

### Missing values — never zero

M21 stores `new_connections = NULL` when the connection tracker could not measure
it. M22 carries that through as **absent**, never as `0`. A zero is the most
normal-looking value a feature can take, which is exactly the wrong direction for
an anomaly detector.

### Truncated cardinalities — treated as missing

When M21 reports `peers_truncated` or `ports_truncated`, the count is a **floor**,
not a measurement. Feeding a floor in as an exact number would systematically
understate a device's reach during exactly the burst an anomaly detector should
notice. The chosen and documented policy, applied identically at training and
inference:

> **A truncated cardinality is treated as missing for that window**, with the
> reason recorded as `truncated`.

### Eligibility and imputation

* A feature is retained only when at least `anomaly_feature_min_availability`
  (default **0.8**) of the training windows carry it.
* At least **2** features must survive — one column is a threshold detector
  wearing a model's name.
* A retained feature's occasional gaps are filled with the **median of the
  training values**, computed once and stored *with the model*, so inference uses
  the identical number.
* Excluded features and their reasons are persisted, because *"this device's
  connection counts were too often unmeasurable to model"* is a real statement
  about the data.

`FEATURE_SCHEMA_VERSION = 1` and `PREPROCESSING_VERSION = 1` are stored beside the
model, so a future change to these rules cannot silently reinterpret an existing
model's columns.

---

## 4. Model

```text
algorithm       isolation_forest
n_estimators    100
contamination   0.02
random_state    42
n_jobs          1        (one thread: this runs beside packet capture)
```

These are **starting defaults, not tuned values**. They are configurable
(`anomaly_model_*` settings) precisely because they were never fitted against
labelled production traffic, which this project does not have.

`n_jobs=1` is deliberate: a thread pool competing with the capture thread for cores
is a real cost for 100 trees over ~1,400 rows.

### What the model says

* `predict()` gives `-1` for an outlier, `1` for an inlier.
* `decision_function()` gives a score where **lower is more unusual**.
* The score is **not a probability**, not a calibrated confidence, and not
  comparable between two devices' models.

Both values are stored unmodified. No display transformation is applied anywhere,
so no reader can mistake a presentation for the model's own answer.

---

## 5. Training data

| Rule | Implementation |
| --- | --- |
| Device-specific | Every query filters on `device_key`. |
| Bounded | `LIMIT anomaly_model_max_training_windows` (default 1,440), applied to the newest rows before the cutoff. |
| Never self-training | Every query carries `window_start < before`, where `before` is the start of the window being evaluated. |
| Exclude known anomalies | Windows M22 already flagged are withheld — **only while at least `min_training_windows` survive** it, so a mostly-flagged device is still trained on what it has. |
| Never fabricate | Below the minimum, no model is fitted and the state is `collecting_data`. |
| Report what was used | `training_sample_count` (used) and `training_window_count` (offered) are both stored. |

M21's own `established` threshold is 30 windows. M22's minimum is **100** — a
device whose baseline is established has enough history for a statistical profile,
not necessarily enough for a model. That difference is visible in the API rather
than implied by it.

### Cold-start limitation — read this before trusting a first model

During a device's first training there is **no trusted anomaly history**. The
initial training set may therefore contain unusual activity that was never
recognised, and Isolation Forest cannot guarantee that a cold-start training set is
entirely benign. Unsupervised learning also cannot eliminate training-data
poisoning.

This is a real limitation of the approach, not a footnote.

---

## 6. Lifecycle

| State | Meaning |
| --- | --- |
| `collecting_data` | Fewer usable windows than training requires. **No model, no verdict.** |
| `training` | A pass is in progress. |
| `ready` | A fitted model is available. |
| `stale` | A model exists but `anomaly_model_refresh_interval` (default **30**) new usable windows have accumulated. Evaluations continue. |
| `failed` | The last attempt raised. **The previous working model is kept** and keeps scoring. |
| `disabled` | Switched off by configuration. |

Two invariants the code enforces:

* **`collecting_data` never reads as healthy.** "No anomalies detected" and "no
  model exists" are different statements, and only one of them is evidence about
  traffic.
* **An unrecognised stored state reads as `failed`**, never `ready`.

### Cache

One model per device, in a bounded LRU (`anomaly_model_cache_size`, default 64),
with deterministic eviction and the lock held for the dictionary operation only —
never across a fit.

### Refresh

Measured in **new usable windows**, not seconds: a device silent for a day has not
fallen behind; one that produced thirty new minutes has. A failed refresh records
the failure, keeps the cached forest, and does not advance `model_version`.

### No pickle

No model artifact is written to disk, read from disk or loaded from a path. A model
is reconstructed by retraining from the retained M21 windows plus the stored
preprocessing plan and configuration; until that succeeds, the device is reported
as unavailable rather than as having a model. This is how M22.7's "do not require
unsafe pickle files" is met without giving up restart recovery.

---

## 7. Evaluation

A completed window goes into a **bounded queue** (`anomaly_evaluation_queue_size`,
default 1,024) and is evaluated on the engine's own thread, at most
`anomaly_max_windows_per_pass` (default 25) per pass. When the queue is full the
oldest pending evaluation is dropped and counted — a stale evaluation is worth less
than the newest one, and unbounded growth is forbidden.

Per window:

1. Look up the persisted M21 row. Gone (retention) means `skipped`, and nothing is
   claimed about it.
2. `(device_key, window_start)` already has a verdict: return it, write nothing.
3. Ask the lifecycle for a model, with `before = window_start`.
4. No model: `skipped` with a stable reason (`insufficient_training_data`,
   `insufficient_features`, `disabled`, `training_already_in_progress`, ...).
5. Score: store `status=scored`, the raw score, the classification and the model
   metadata.
6. Anomalous and newly created: raise one `ml_anomaly` finding.

### Idempotency

The uniqueness key is `(device_key, window_start)`. A repeated flush, a service
retry, a backend restart, a WebSocket reconnect and an API page all reduce to "does
a row already exist for this key". Retraining does **not** re-score historical
windows: a second verdict reached by a model trained on data that now includes the
window is neither more truthful nor comparable with the first.

### Failure isolation

Every failure in this package is caught and counted. An ML failure cannot stop
packet capture, packet processing, statistics, M21 baseline learning, deterministic
detection, alerting or correlation. The symptom of a failure is a `failed` or
missing evaluation row — which is the honest report.

---

## 8. Storage

Two tables, mirroring M21's split.

`anomaly_models` — one row per device identity: state, algorithm, `model_version`,
`feature_names_json`, `feature_schema_version`, `preprocessing_json`,
`config_json`, `training_sample_count`, `training_window_count`,
`min_training_windows`, `contamination`, `trained_at`, `last_evaluated_at`,
`windows_since_training`, `last_error`.

`anomaly_evaluations` — one row per `(device_key, window_start)`: raw
`decision_score`, `is_anomaly`, `model_version`, `model_trained_at`,
`training_sample_count`, `contamination`, `feature_schema_version`, `status`,
`skip_reason`, bounded `feature_context_json`, `alert_id`, `created_at`.

Indexes: `created_at` (retention), `(device_key, window_start)` (a device's newest
verdicts), `(is_anomaly, window_start)` (classification filter and ordering), plus
`state` and `last_evaluated_at` on the model table.

**Not stored:** packets, payloads, peer addresses, port numbers, credentials. A row
holds counters, a score and statistics.

**M21 is untouched.** No baseline table, column or row is modified by M22.

### Retention

`anomaly_retention_days` (default **30**) is the third of four policies on the
existing M19 sweeper, in 5,000-row bounded passes, failure-isolated.

**Evaluation history expires; model metadata does not.** An evaluation is evidence
about one minute; a model is the conclusion about a device's learned behaviour, and
deleting it because its verdicts aged out would force a pointless retrain.

---

## 9. Findings and alerts

* Detector source: **`ml_anomaly`**, distinct from all five deterministic rules,
  which are untouched.
* The alert mapping lives in `app/alerts/mapping.py`, the single place a rule
  becomes an alert: title *Behaviour Anomaly*, severity **medium**, and a **fixed**
  confidence. The decision score is never used as alert confidence, because that
  would present a model output as a probability.
* The finding carries the evaluation's evidence (score, `training_sample_count`,
  `model_version`, `contamination`, the algorithm and the deviation disclaimer), so
  the alert trail reaches the model output.
* Alert creation is deduplicated by M11 as usual; the `anomaly_evaluations` row
  survives either way and records `alert_id` when one was created.
* If an ML finding joins an existing M12 incident, M12's own rules decide the
  incident's risk score. M22 does not alter M12's methodology, and
  `risk_ml_contribution_enabled` remains `False`.

**No automatic blocking, quarantine or traffic modification.** The operator
retains control.

---

## 10. REST API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/anomalies` | Page of evaluated windows, newest first |
| `GET` | `/api/v1/anomalies/{evaluation_id}` | One verdict with feature context |
| `GET` | `/api/v1/anomalies/models` | Every device's model lifecycle |
| `GET` | `/api/v1/anomalies/models/{device_key}` | One device's model, or an honest "collecting data" record |
| `POST` | `/api/v1/anomalies/models/{device_key}/retrain` | Controlled retraining |

Listing filters: `device_key`, `is_anomaly`, `status`, `since`, `until`, `limit`,
`offset`. Ordering is `window_start DESC, id DESC` — a total order, so a page never
repeats or skips a row. The listing also returns counted totals and a summary so
the frontend needs no second round trip.

Every payload carries `ANOMALY_DISCLAIMER`. Error envelopes are the M13 ones: a
timestamp that cannot be parsed is a `400` naming the field, an unknown enum a
`422`, an unknown id a `404`. No stack trace, file path, database path or secret
appears in any response.

**Retraining** answers `200` in every non-exceptional case and reports the outcome
in the payload (`trained`, `state`, `state_description`, `previous_model_retained`,
`reason`, `message`), so a caller reads a field rather than inferring from a status
code. It refuses below the minimum, refuses concurrent runs for the same device,
and never resets M21 history.

---

## 11. Frontend

A dedicated **Anomalies** page (`frontend/src/pages/Anomalies.tsx`), built from the
existing component, service, hook, type and navigation patterns.

* Four stat tiles, a prominent disclaimer, and a results table showing device,
  window, classification, **raw** decision score, model state and training sample
  count.
* Filters for classification, evaluation status, device and time range, with
  pagination.
* A models table covering every lifecycle state, with a per-device detail panel:
  algorithm, version, samples, trained and evaluated timestamps, the feature list
  and the state sentence.
* A per-verdict feature-context panel showing the observed value, the training
  median, scaled MAD and the difference — visually separated from the model's own
  verdict, because it is a comparison, not attribution.
* Retraining from either the models table or the device panel, behind a
  confirmation dialog, with success and failure reporting.

Explicit states for: no anomalies, no models yet, still collecting data, training,
model unavailable, model failed, API unavailable, empty history, loading, stale
models, and retraining in progress. **No fabricated demo anomalies.**

---

## 12. Performance — measured, not claimed

`backend/scripts/benchmark_m22.py`, deterministic (`DATA_SEED = 20260101`,
`random_state = 42`), measured on the development machine (Windows 11, Python
3.13.2 in the project virtualenv):

| Measurement | Result |
| --- | --- |
| Fit, 100 trees, 1,440 rows, 8 features | **1,633 ms** |
| Score one window (`decision_function` + `predict`) | **7,103 µs** |
| Features used | 8 of 9 (`new_connections` excluded — the synthetic data carried none) |

Windows arrive **once per device per minute**, so ~7 ms of scoring and a ~1.6 s
periodic fit are immaterial. The pipeline's real constraint is that neither ever
runs on the capture thread, which is why evaluation has its own queue and worker.

The benchmark also reports how far the decision scores of a synthetic normal set
and a deliberately unusual set fall apart. In the recorded run the normal set's
median was `+0.0897` with **5 of 200** flagged, and the unusual set's median was
`-0.1520` with **200 of 200** flagged.

**Read that as a wiring check only.** The two synthetic populations are trivially
separable — they differ by a factor of eight in volume and by an order of magnitude
in peers and ports. It demonstrates that the feature pipeline, the plan, the forest
and the classification all work end to end. It says **nothing** about how this
detector performs on real traffic.

---

## 13. Honest reporting

This project has **no labelled production dataset**. Therefore:

* No accuracy percentage is claimed.
* No false-positive rate is claimed.
* No precision or recall is claimed, from synthetic tests or otherwise.
* Decision scores are never described as probabilities or confidence.
* An anomaly is never described as an attack.

What is recorded and reproducible: the number of training samples, the number of
test samples, the synthetic scenarios evaluated, the injected anomalies detected,
the normal scenarios tested, the CPU cost of a fit and a score, and the exact
configuration and seeds — all above.

**A flagged window means "this differs from what was learned".** A window not
flagged means "this did not stand out against the learned pattern", never "this was
benign". A device with no model has **no verdict at all**, which is not the same as
being judged normal.

---

## 14. Testing

**Backend — 133 M22 tests** across seven files:

| File | Covers |
| --- | --- |
| `test_anomaly_features.py` | Vector construction, feature order, missing-is-missing, truncated cardinalities |
| `test_anomaly_preprocessing.py` | Eligibility, median imputation, plan round-trip, column order |
| `test_anomaly_model.py` | Deterministic construction, fit and score, raw-score handling, no probability claims |
| `test_anomaly_lifecycle.py` | States, minimum samples, refresh interval, failed refresh preserves the model, bounded cache |
| `test_anomaly_engine.py` | Inference on normal and unusual synthetic data, duplicate prevention, re-flush idempotency, failure isolation |
| `test_anomalies_api.py` | Pagination, filters, validation, error envelopes, manual retraining |
| `test_anomaly_retention.py` | Bounded deletion, model metadata survival |

**Frontend — 39 tests** (`frontend/src/pages/Anomalies.test.tsx` and the shared
component suites): listing, empty results, filters, pagination, device detail,
every lifecycle status, insufficient training data, raw score display, feature
context, linked alerts, retraining confirmation/success/failure, the
API-unavailable state, the disclaimer and navigation.

**Regression:** the four tests that assert the exact M19 retention-policy list and
the exact M11 detector set were updated for the two legitimate additions (the
`anomalies` policy and the `ml_anomaly` rule) — and the M11 test now additionally
asserts that the ML rule's confidence is *not* the decision score.

---

## 15. Verification

```text
backend suite      2 940 passed
security suite       145 passed
frontend unit        537 passed (19 files)
frontend live         59 REST + 9 page tests passed (against a running backend)
pyright              0 errors, 0 warnings, 0 informations
tsc --noEmit         0 errors
npm run build        clean
quality gates        9/9 PASS  (RESULT: PASS)
```

The live suites gained M22 coverage in this milestone: `tests/live/rest.test.ts`
asserts the anomaly listing's counted totals, that no payload carries a
`confidence`/`probability`/`risk_score` field, that a skipped row has no decision
score and no feature context, that `ready` agrees with the model state, and the
`404`/`400` refusals; `tests/live/pages.test.tsx` navigates to the page against
the real endpoints, checks the disclaimer, the evaluations tile, the empty state
and the models tab.

One note on how the gate suite was run: `e2e-live` asserts that the developer's
own `netwatch.db` is untouched across its run, so a backend left running from a
browser check makes it fail — correctly, since that is exactly the isolation it
exists to prove. With the stray server stopped it passes. The gate did its job;
the failure was an artefact of the verification session, not of M22.

End-to-end, against a running backend: M21 aggregated windows, M22 evaluated two
completed windows for one device, classified one as anomalous, persisted both with
their raw scores, and served them back through `/api/v1/anomalies` (2 results, 1
with `is_anomaly=true`), its detail, and `/api/v1/anomalies/models` (1 model), each
response carrying the disclaimer.

---

## 16. Known limitations

1. **No labelled evaluation.** Accuracy, precision, recall and false-positive rate
   are unknown, and none is claimed.
2. **Cold start.** The first training set may contain unrecognised unusual
   activity, and unsupervised learning cannot rule out poisoning.
3. **`contamination = 0.02` is a starting default**, not a measured optimum. It
   defines where `predict` places its boundary.
4. **Scores are per-model.** A decision score is meaningful only against the model
   that produced it — not across devices, and not after a retrain.
5. **The nine features are coarse.** A 60-second aggregate cannot see a
   low-and-slow exfiltration spread over an hour, nor payload content.
6. **Bursty devices train wide bands.** A genuinely variable device produces a
   broad learned pattern, and deviations inside it are missed.
7. **`new_connections` is often excluded.** Where the tracker could not measure it
   in 80% of windows, the feature is dropped rather than imputed into fiction.
8. **Feature context is not attribution.** It compares a window with the training
   median. Isolation Forest does not report which feature caused a prediction, and
   no validated explanation method is implemented.
9. **Single-node, single-process.** One SQLite file, one worker thread, a 64-model
   cache and a 1,024-window queue. Not a capacity claim.

---

## 17. Explicitly out of scope

Local LLM integration · AI-generated explanations · AI Security Analyst ·
LLM-based log and event-sequence investigation · Wazuh · automatic
blocking/quarantine/IPS · cloud inference or training · GPU requirements · deep
learning and autoencoders · a second or third ML algorithm.

M22 identifies deviation and hands it to a human. Nothing is blocked.
