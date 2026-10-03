# NetWatch AI — M12 Correlation & Risk Scoring Design

**Milestone:** M12 — Correlation + Risk Scoring
**Status:** Implemented
**Depends on:** M11 (`Alert`, `AlertEvidence`, `alerts`/`alert_evidence` tables), M10 (`DetectionFinding`), M9 (connections), M8 (devices), M7 (persisted packets), M2 (`alerts.risk_score` column)

---

# 1. Purpose

M12 turns **individual alerts** into **correlated incidents with a risk score**.

An alert says one thing happened and it matters. An incident says several things
happened *together*, which rule justified grouping them, and how much attention
the group deserves.

```text
Detection Finding (M10)
        ↓
    Alert Engine (M11)
        ↓
      Alert + Alert Evidence
        ↓
  Correlation Engine (M12)          ← this milestone
        ↓
   Correlated Incident
        ↓
  Risk Scoring Engine (M12)
        ↓
      Risk Score (0..100)
```

## 1.1 The architecture principle

An individual alert does not necessarily represent a complete incident. A port
scan alert, a suspicious connection alert and a high-traffic alert may be three
views of one piece of activity, or three unrelated events. Correlation decides,
using **evidence and context** rather than by adding severities together.

Correlation is therefore about **identity**, not about severity and not about
proximity:

```text
Port Scan Alert
      +          same source, close in time
Internal Scan Alert
      ↓
 Correlation Engine
      ↓
 One Correlated Incident
      ↓
 Risk Score
```

## 1.2 Scope boundary

M12 implements **correlation and risk scoring only**. It does **not** implement
new packet detectors, new alert types, a behavioural baseline engine, ML anomaly
detection, AI analysis, automatic blocking, WebSockets, frontend integration,
external SIEM integrations or incident-response automation.

M10 **detects**; M11 **alerts**; M12 **correlates and prioritises**. M12 never
acts on what it finds and never rewrites what M11 recorded.

## 1.3 The three quantities that must stay apart

Three numbers exist in the system, and none is derived from another (M12.16):

| Quantity | Question it answers | Owner |
| --- | --- | --- |
| **Alert confidence** | how strong is the *evidence*? | M11.5 |
| **Correlation confidence** | are these the *same incident*? | M12.7 |
| **Risk score** | how much does this deserve *attention*? | M12.14 |

A pair of events can be correlated at confidence `0.98` and still score `12`. A
single high-confidence alert can score `70` with no correlation at all. The one
permitted connection between them is that correlation confidence is **one
bounded term out of seven** in the risk formula — a documented, bounded
contribution, never an identity.

The separation is enforced structurally rather than by convention:

* `CorrelatedIncident.confidence` is the *correlation* confidence;
  `alert_confidences` holds the alerts' own values, and `mean_alert_confidence()`
  deliberately excludes the correlation confidence from its average (averaging
  two different questions would produce a third meaningless number).
* `RiskInputs` carries both as **separate fields**, and the formula consumes them
  in **separate terms**.
* `RiskResult` echoes all three back side by side, so a caller must read a field
  named `score` to get the score — it cannot mistake `0.9` for it.

---

# 2. M12.1 — Review of the existing components

M12 consumes the outputs of earlier milestones. Nothing was duplicated, and no
existing structure was redesigned.

## 2.1 `DetectionFinding` (M10) — `app/detection/finding.py`

| Field | Use in M12 |
| --- | --- |
| `finding_id` | the event identity (`fnd:<finding_id>`) and the incident's `finding_ids` |
| `rule_id` | relationship dimension (`same_rule`), rule attribution, dedup identity, title fallback |
| `rule_name` | the incident's title |
| `timestamp` | the event's timeline position — findings are timed in **epoch seconds** |
| `confidence` | the event's confidence (M12.7 consumes it only as a *separate* quantity) |
| `source_ip` / `destination_ip` | `same_source` / `same_destination` dimensions |
| `source_device_id` / `destination_device_id` | `same_device` and device resolution (M8) |
| `protocol` | carried for reasons and traceability |
| `description` | carried for traceability |
| `evidence` | **not copied** into correlation — see 2.6 |

A finding carries **no severity**. M12 therefore stores `severity=None` for a
finding event and never invents a level for it (M12.15).

## 2.2 `Alert` (M11) — `app/alerts/alert.py`

| Field | Use in M12 |
| --- | --- |
| `alert_id` | the event identity (`alert:<id>`), the incident's `alert_ids`, the risk-write target (M12.24) |
| `severity` | one input to the severity term (via the incident's worst member severity) |
| `confidence` | the alert confidence, kept separate from risk (M12.16) |
| `created_at` | the event's timeline position — alerts are timed in **naive UTC datetime** |
| `source_ip` / `destination_ip` / `source_device_id` / `destination_device_id` | the identity dimensions |
| `connection_id` | `same_connection`, the strongest relationship |
| `correlation_key` | M11's dedup key, carried so a reason can name the incident the alert belonged to |
| `status`, `evidence_count` | **not read** — M12 does not reinterpret M11's lifecycle or evidence |

## 2.3 `AlertEvidence` (M11) — `app/alerts/evidence.py`

Not consumed. Evidence is M11's justification for an alert and it stays with the
alert. M12 references the alert by id and never restates what supported it — the
same "references, never copies" rule M11.13 applies to packets.

## 2.4 Device information (M8) and connections (M9)

Neither is re-implemented. A finding or alert that already resolved an M8 device
identity contributes that identity to the incident's index; a `connection_id` is
used when one was resolved. `app/devices/registry.py` and
`app/connections/manager.py` remain the only authorities, and correlation never
looks an address up on its own: **an unresolved address stays an address**
(M12.19).

## 2.5 Persisted packets (M7)

Not read at all. A packet is referenced by the finding that saw it, and the
finding is referenced by id. This is M12.3's "do not copy complete packet data
into the correlation layer" honoured by never touching it.

## 2.6 Database schema (M12.24) — no new tables, no new columns

The M2 schema is sufficient, and this is a deliberate finding rather than a
convenience:

| Needed by M12 | Where it already lives |
| --- | --- |
| alert grouping | `alerts.correlation_key` — the column M2 documents as "optional key used to deduplicate related alerts" — plus the incident's `alert_ids` in runtime state |
| a risk score per alert | `alerts.risk_score` (M2 `INT`, CHECK `0..100`) — written `0` by M11 precisely so M12 could fill it in |
| relationship metadata | runtime only. Correlation context is bounded and expires (M12.22); the *alerts* are the durable record |

**Documented gap, and why no schema change was made.** The correlated incident
itself — its id, title, lifecycle, reasons and score — lives in **bounded runtime
state**, not in a table. Persisting incidents would add a table (and a lifecycle
column, and a reasons blob) that no reader in M12 needs: M12 explicitly does not
build the REST API (M12.26), so incidents are read from the process that built
them. What *must* survive a restart is already durable — the alerts — and their
risk score is stamped onto them (M12.24). Adding an `incidents` table now would
be designing the API's storage before the API exists. The one schema-level change
M12 needed was none: `alerts.risk_score` already existed with the right bound and
CHECK constraint, and `AlertRepository.update_risk_scores` writes only that
column.

---

# 3. Layer map (M12.2)

```text
app/correlation/
    window.py          the bounded time window + the incident-acceptance rule (M12.5)
    relationship.py    the six relationships, their weights, which may anchor (M12.6/M12.7)
    identity.py        IdentityIndex + the comparison that produces relationships (M12.4)
    confidence.py      relationships → one bounded correlation confidence (M12.7)
    rules.py           the five explicit correlation rules, as data (M12.12)
    event.py           the normalized input, from a finding or an alert (M12.3)
    incident.py        the immutable CorrelatedIncident model (M12.8/M12.10)
    status.py          the four-state lifecycle + transition table (M12.9)
    registry.py        the bounded, lock-protected store, queries, lifecycle (M12.22/M12.23/M12.26)
    persistence.py     writing an incident's score onto its alerts (M12.24)
    engine.py          the pipeline consumer that ties them together (M12.2/M12.25)
    __init__.py        package exports + get_correlation_engine() singleton

app/risk/
    bands.py           the 0..100 bound and the four display bands (M12.14/M12.27)
    inputs.py          RiskInputs — the complete, closed set of scoring facts (M12.15)
    contributions.py   the formula: seven independently bounded terms (M12.17)
    engine.py          RiskScoringEngine, isolation, RiskResult (M12.13/M12.25)

app/repositories/alert.py       update_risk_scores(...) — the M12.24 write (M11.16)
app/config/settings.py          the M12 configuration block
app/services/packet_pipeline.py correlation runs last, after alerting (M12.25)
app/services/capture_manager.py wires the shared engine into the pipeline (M12.25)
scripts/verify_m12.py           the M12.33 lab scenario
scripts/benchmark_m12.py        the M12.34 performance baseline
```

Dependency direction is strictly downward and one-way:

```text
app.risk   ← knows nothing about correlation, incidents or the database
app.correlation ← imports app.risk; app.risk never imports app.correlation
```

Nothing in `app/correlation/` or `app/risk/` imports Scapy, FastAPI or a
repository at module level. The pure modules (`window`, `relationship`,
`identity`, `confidence`, `rules`, `status`, `bands`, `inputs`, `contributions`)
are importable in isolation with no database, environment or clock side effect,
which is what lets the formula and the rule set be tested from literals.

---

# 4. M12.3 — Correlation event

```python
@dataclass(frozen=True)
class CorrelationEvent:
    event_id: str                     # "fnd:<finding_id>" or "alert:<alert_id>"
    kind: EventKind                   # FINDING | ALERT
    timestamp: float                  # epoch seconds — one timeline for both sources
    rule_id: str                      # detector rule id, e.g. "port_scan"
    title: str = ""
    description: str = ""
    severity: AlertSeverity | None = None   # None for a finding
    confidence: float = 0.0
    source_ip / destination_ip: str | None
    source_device_id / destination_device_id: str | None
    protocol: str | None
    connection_id: str | None
    alert_id: int | None
    finding_id: str | None
    correlation_key: str | None
    metadata: dict[str, str]
```

Three deliberate properties:

* **One normalized input.** The engine never learns that findings and alerts are
  different shapes. `from_finding(...)` and `from_alert(...)` are the only
  conversion points.
* **References, never packet data.** There is no payload, no byte count and no
  packet row here — M12.3 forbids it explicitly. A packet is reachable by walking
  event → finding → packet, without correlation holding a copy.
* **One timeline.** A finding is timed in **epoch seconds**, an alert in a
  **naive UTC datetime** (M11.3). Both are normalized to epoch seconds through
  M11's own converters (`app.alerts.timestamps`), not by a second, private
  implementation of the same arithmetic.

`EventKind` distinguishes the two sources, which matters for one thing only: a
finding carries no severity and no alert id, so an incident built from findings
alone has no alerts to stamp and no severity to consume (M12.15). `is_alert` /
`is_finding` are exposed so that is never guessed from a `None` check.

An untimed event is **rejected, not guessed**: `from_alert` raises when an alert
has neither `created_at` nor a supplied timestamp, because correlation is
fundamentally about time. The engine contains that per event, so one unusable
alert cannot stop alert processing (M12.25).

---

# 5. M12.4 / M12.6 — Correlation identity

M12.4 requires that "correlation rules must be explicit" and that events are not
merged "simply because they occurred close together". Identity is where that
becomes concrete.

Each event reduces to a small set of **identity dimensions**, and the comparison
answers one narrow question: *which dimensions do these two things share?*

```python
@dataclass(frozen=True)
class IdentityIndex:
    source_devices: frozenset[str]
    source_addresses: frozenset[str]
    destination_devices: frozenset[str]
    destination_addresses: frozenset[str]
    devices: frozenset[str]            # union of the two device sets
    connections: frozenset[str]
    rules: frozenset[str]
```

**Identity is a set, not a single value, and that matters.** An event may know
both a device identity (M8) *and* the address it resolved to. If one event knows
the device and another only knows the address, they are still the same actor — so
the comparison is between *sets* of known identities, not between two chosen
representatives. A comparison that picked one value per side would miss exactly
the case where enrichment succeeded on one observation and not the other, which
is the common case, not the edge case.

Devices and addresses are therefore kept **apart** in the index, and the
comparison prefers a device when both overlap:

```python
source = _first_shared(left.source_devices, right.source_devices) \
      or _first_shared(left.source_addresses, right.source_addresses)
```

A device identity is the stronger statement, and reporting `same_source:dev-7`
is more useful to an operator than `same_source:10.0.0.5` for the same
relationship.

**Determinism.** Every overlap is reported as the *lowest element of a sorted
set*, not "any member". An unordered membership test would let the reported
detail vary between runs, and an incident's reasons are stored and read back.

The dimensions map one-to-one onto the relationship kinds below. `IdentityIndex`
for an incident is built with `from_sets(...)`, which **derives** the `devices`
union rather than accepting it — so a caller cannot construct an index whose
device set contradicts its source and destination device sets, a state that would
make `same_device` and `same_source` disagree about the same fact. Growing an
incident unions two indexes (`merged_with`).

---

# 6. M12.5 — Correlation time window

Two events are only *candidates* for correlation while they are close in time.
One module owns that "close", because a time window is the easiest thing in a
correlation engine to get subtly wrong.

M12.5 states the requirement in two halves and both are implemented:

* **Bounded.** An unbounded window would let a port scan this morning correlate
  with unrelated traffic tonight, which is not correlation at all. A deployment
  cannot configure a window longer than `MAX_CORRELATION_WINDOW_SECONDS`
  (86 400 s — one day, matching M11's dedup ceiling so the two are bounded on the
  same scale). A longer one raises at construction.
* **Configurable.** What counts as "close" depends on the network, so the length
  is a setting (`correlation_window_seconds`), not a constant.

**Two different comparisons are needed, and conflating them is the usual bug.**

| Method | Compares | Question |
| --- | --- | --- |
| `pairwise(a, b)` | two events | may these two be related *at all*? |
| `incident_accepts(start_time, last_seen, timestamp)` | an event vs an incident | may this event join that incident? |

An incident is not one timestamp, it is a growing span, so the second question is
different and needs two conditions, both required:

1. **Temporal proximity to the incident** — the event must be within `seconds` of
   the incident's *most recent* activity. An event far before the incident's last
   event is a different episode; an event far after it is a new one.
2. **A bounded total span** — the span from the incident's first event to the
   later of its last event and the candidate must not exceed `max_span_seconds`
   (defaults to one window).

**Condition 2 is the anti-chaining bound, and it is the important one.** If
membership only required proximity to the *previous* member, a busy network would
grow one incident that never ends — each new event one window further from the
first. The total span is therefore capped separately, so chaining is bounded even
when every consecutive pair is inside the window.

**Every boundary is inclusive.** An event exactly `seconds` away is inside the
window, an event exactly `proximity_seconds` away is proximal, and an incident
span exactly at `max_span_seconds` is accepted. Inclusive edges are used
consistently across M12 (window, anchor check, confidence floor) so a test can
pin each edge exactly rather than approximately.

Two smaller documented decisions:

* An event **before** the incident's start is allowed while condition 1 holds:
  findings can be generated out of order, and refusing an earlier observation
  would split a genuine incident in two. It is the span rule, not arrival order,
  that keeps the incident bounded.
* A timestamp *after* the reference time — which can only mean a clock moved
  backwards — is treated as **inside** the window. Correlating is the safe
  direction: the alternative is losing the relationship between two events that
  plainly belong to the same activity.

The **proximity** window (`correlation_proximity_seconds`, default 300 s) is
separate from and narrower than the correlation window. It expresses
`time_proximity`, which strengthens a relationship but never creates one
(M12.6). Many events may belong to one incident; only tightly clustered ones are
evidence of a single burst.

---

# 7. M12.6 / M12.7 — Relationship strength and anchoring

Two separate ideas, and keeping them apart is the whole point:

* **Relationship strength** — how much a *relationship* says that two events
  belong to the same activity. A property of the shared dimension, not of how
  serious anything is.
* **Anchor vs. strengthening** — whether a relationship is strong enough, *on its
  own*, to justify correlating two events at all.

The table is normative and lives as data in `app/correlation/relationship.py`:

| relationship | weight | anchors? | why |
| --- | --- | --- | --- |
| `same_connection` | 0.90 | **yes** | the same M9 conversation id is the strongest evidence of one activity |
| `same_device` | 0.75 | **yes** | one affected asset is a real pivot |
| `same_source` | 0.70 | **yes** | one origin emitting related events |
| `same_destination` | 0.55 | **yes** | one target being contacted |
| `same_rule` | 0.35 | no | the same detector firing twice is expected and says little alone |
| `time_proximity` | 0.25 | no | merely happening at the same time |

The default anchor threshold is **0.55** — exactly `same_destination`'s weight.
That is deliberate: it makes the boundary of "anchor" legible (the four identity
relationships anchor; rule identity and time proximity do not) instead of resting
on a number someone has to look up. An operator may raise or lower it via
`correlation_min_anchor_strength`, and the classification follows the configured
value rather than being hard-coded — which is what makes M12.4's rule structural:
**no rule can be satisfied by time alone, because the only non-identity
relationship is below the anchor threshold.**

`Relationship` carries a `detail` (the shared value — the connection id, the
device id, the rule id) so a correlation reason can name *why*, not merely *that*.
`Relationship.reason()` renders a stable, machine-readable `kind:detail` string;
reasons are stored on the incident and read by tests and the API, so they must not
depend on punctuation or a locale.

> **These weights are not a risk score and are never reported as one.** A pair of
> perfectly correlated trivial events is strongly correlated and barely risky, and
> the model must be able to say both at once (M12.16).

## 7.1 M12.7 — Correlation confidence

`combine_relationships(...)` folds a set of relationships into **one** bounded
confidence. The combination rule is a **noisy-OR**, not a sum and not an average:

```text
confidence = 1 - Π (1 - wᵢ)
```

Three properties, each the reason the other obvious choices were rejected:

* **Bounded.** Every `wᵢ` is in `[0, 1]`, so the result is in `[0, 1]` by
  construction and never needs clamping to be valid.
* **Monotonic.** Adding another relationship can only *raise* the confidence. An
  average would *lower* it when a weak relationship was added, which is wrong:
  finding one more thing in common never makes two events less related.
* **Saturating, never certain.** The reported value is capped at
  `MAX_CORRELATION_CONFIDENCE = 0.999`. No finite set of relationships reaches
  exactly `1.0`, which is honest — correlation is inference from partial
  identities, never proof — and it lets a caller relying on "strictly below 1"
  stay safe.

Worked example, the M12.7 case:

```text
same_connection (0.90) + same_source (0.70) + time_proximity (0.25)
1 − (0.10 × 0.30 × 0.75) = 1 − 0.0225 = 0.9775   → "high"
```

An empty relationship set returns `0.0`: having established no relationship is
not weak evidence of a relationship, it is no relationship.

`meets_threshold(confidence, minimum)` applies the configured floor
(`correlation_min_confidence`, default `0.5`) with an **inclusive** boundary. It
is a *second, independent gate* after the anchor check: the anchor decides whether
a relationship of the right *kind* exists, the floor decides whether the overall
judgement is strong enough to act on. Either can reject. The two are separate
because they answer different questions, and an engine with only one of them
would merge on a single weak overlap or refuse an obviously strong multi-dimension
match.

---

# 8. M12.12 — The explicit correlation rules

M12.12 asks for "a small initial set of explicit correlation rules" and warns
against creating "dozens". M12 defines **five**, expressed as data rather than as
control flow, in the order they are evaluated — most specific first, so a pair
satisfying two rules is attributed to the more informative one.

| order | rule id | anchors | extra requirement | milestone |
| --- | --- | --- | --- | --- |
| 1 | `scan_sequence` | `same_source` | the detectors `internal_scan` **and** `port_scan` must both be present | M12.12 Rule 2 |
| 2 | `same_connection` | `same_connection` | — | M12.12 Rule 3 |
| 3 | `same_source_activity` | `same_source` | at least one prior event | M12.12 Rule 1 |
| 4 | `device_centric_activity` | `same_device` | at least one prior event | M12.12 Rule 4 |
| 5 | `same_destination_activity` | `same_destination` | at least one prior event | M12.6 "Same Destination" |

**Rule 5 exists for a specific reason, and it is worth stating.** M12.6 defines
`same_destination` as an *anchoring* relationship — its weight is exactly the
default anchor threshold and it is a member of `ANCHOR_RELATIONSHIPS` — while the
milestone's four *example* rules happen to reference only source, connection and
device. M12's completion criteria require same-destination correlation to work,
so without a rule consuming it an anchor-capable relationship would exist that
nothing could ever match on. That is the case that matters in practice: when an
address does **not** resolve to an M8 device, a shared destination can only be
expressed as `same_destination`, and two events sharing only it would otherwise be
uncorrelatable. It is evaluated last because its weight is the lowest of the four
anchors, so any stronger shared dimension wins the attribution.

Every rule requires an **anchoring** relationship, and the anchor threshold is
configuration rather than a literal. That is the structural guarantee behind
M12.4's "do not merge events simply because they occurred close together": the
rules can only be satisfied by identity overlap, because the only non-identity
relationship — time proximity — is below the anchor threshold and no rule lists it
as an anchor. Time proximity appears in reasons and raises the correlation
confidence; it can never, by itself, cause a correlation.

`min_incident_events = 1` on the three volume rules means they describe the
joining of **two or more** events rather than a lone event with itself: a seed
incident always holds one event by the time it can be a candidate.

A matched rule produces a `CorrelationMatch` carrying the rule id, its title, and
the **full reason trail**, deterministically ordered: the matched rule first
(`matched:<rule_id>`), then every established relationship as `kind:detail`,
sorted by `(kind, detail)`. An incident therefore says not only "these alerts were
grouped" but *which rule grouped them* and *which shared values justified it*.

```text
correlation_reasons = (
    "matched:scan_sequence",
    "same_rule:internal_scan",
    "same_source:192.168.11.10",
    "time_proximity",
)
```

---

# 9. M12.8 — The correlated incident model

```python
@dataclass(frozen=True)
class CorrelatedIncident:
    incident_id: str                  # "inc:<seeding event id>" — derived, not random
    title: str
    created_at: float                 # epoch seconds
    updated_at: float
    start_time: float                 # earliest member event
    last_seen: float                  # latest member event
    status: IncidentStatus            # open | investigating | resolved | dismissed
    identity: IdentityIndex           # the union of every member's dimensions
    event_ids: tuple[str, ...]        # capped
    alert_ids: tuple[int, ...]        # capped — the database ids
    finding_ids: tuple[str, ...]      # capped
    rule_ids: tuple[str, ...]         # detector rules involved
    correlation_rule_ids: tuple[str, ...]   # which M12.12 rules have matched
    correlation_reasons: tuple[str, ...]    # the reason trail, capped
    correlation_confidence: float     # M12.7 — separate from everything else
    alert_confidences: tuple[float, ...]    # the alerts' own confidences (M11.5)
    severities: tuple[str, ...]       # the member alerts' severities
    event_count: int                  # every event folded in, cap or no cap
    dropped_events: int               # counted but not retained (M12.22)
    risk_score: int                   # 0..100 (M12.14)
    risk_band: RiskBand               # documented display band (M12.27)
```

Everything is **derived from the events that actually arrived**, and M12.8's
closing line — "use only information supported by the correlated events" — is
enforced structurally rather than trusted:

* Identity is one `IdentityIndex`, unioned as events join. There is no field a
  caller can set to an identity no event mentioned.
* `severities` and `alert_confidences` **accumulate as events arrive**, so the
  worst severity and the mean confidence are facts about the membership rather
  than estimates. `worst_severity()` returns `None` when no member carried one —
  the normal state of a findings-only incident — which keeps "unmeasured"
  distinguishable from "low".
* `risk_score` starts at the model minimum and is only ever written by
  `RiskScoringEngine` via `with_risk(...)`, which also recomputes the band unless
  one is supplied, so a stored band can never disagree with the score it labels.

**Risk and confidence are two fields, not one.** `correlation_confidence` is how
strongly the events were judged *related*; `alert_confidences` holds the alerts'
own numbers; `mean_alert_confidence()` averages the latter and **deliberately
excludes** the former. A caller cannot read one and mistake it for the other
because they do not share a name or a derivation.

**Instances are immutable.** Growing an incident returns a *new* one
(`merged_with_event`), which is what lets a reader hold a consistent snapshot
while the correlation engine keeps folding events in (M12.23). `replace(...)` is
used for every derived transition, so no field can be silently mutated in place.

**`incident_id` is derived, not generated.** It is `inc:<seeding event id>`, for
three reasons: the id is traceable back to the observation that opened the
incident, it is reproducible across runs (which the tests and the verification
script rely on), and re-seeing the same seeding event cannot invent a second
incident under a new name (M12.11).

Derived views keep the query layer honest: `device_ids` and `connection_ids` are
sorted tuples over the identity sets, `alert_count()` is `len(alert_ids)`,
`span_seconds()` orders its two ends on read so an out-of-order arrival still
reports a sensible extent, and `has_event(event_id)` is the membership test
behind deduplication.

Two serialization views are provided for the eventual API (M12.26 owns the
*internal* queries; M13 owns the REST surface): `as_dict()` is the full record
(member lists, reasons, both confidences, both timestamps forms — epoch seconds
to reason with and ISO-8601 UTC to display), and `summary()` is the compact
listing view. Both are deterministic: every list is already ordered on arrival or
sorted on read.

---

# 10. M12.9 — Incident lifecycle

Four states, one transition table, and no automation:

```text
open ──► investigating ──► resolved
 │             │
 │             └────────► dismissed
 ├────────────► resolved
 └────────────► dismissed
```

| from | to |
| --- | --- |
| `open` | `investigating`, `resolved`, `dismissed` |
| `investigating` | `resolved`, `dismissed` |
| `resolved` | **nothing** (terminal) |
| `dismissed` | **nothing** (terminal) |

Three deliberate properties:

* **`resolved` and `dismissed` are terminal, and there is no reopen.** Reopening
  is either editing a conclusion already recorded or introducing a state the
  milestone did not ask for. The absence is explicit and tested.
* **Validation happens before any write.** `set_status` consults
  `validate_transition(...)` first, so an illegal move leaves the store untouched
  rather than half-updated. `InvalidIncidentTransition` names the states that
  *are* reachable.
* **A move to the current state is an explicit no-op**, mirroring M11:
  re-marking an incident as investigating changes nothing and is not an error.

`ACTIVE_STATUSES = {open, investigating}` drives two things: an active incident
accepts newly correlated events, and `open_incidents()` counts it. An event can
therefore **never reopen a relationship someone has already resolved** — the
candidate scan filters to active incidents only.

This mirrors `app/alerts/status.py` closely, and that is intentional: an operator
who has learned the alert lifecycle already knows this one. It is a separate
module rather than a reuse because the two lifecycles are free to diverge — an
incident is a grouping and may later grow states (a "merged" incident, for
example) that make no sense on a single alert.

---

# 11. M12.10 / M12.11 — Grouping and deduplication

## 11.1 Grouping preserves the alerts

Multiple alerts may belong to one incident:

```text
Alert 1: Port Scan
Alert 2: Internal Scan
Alert 3: High Traffic
        ↓
   One Incident
   alert_ids = (1, 2, 3)
```

`merged_with_event(...)` **records references and changes nothing else**. The
alerts are not consumed, not deleted and not rewritten: they stay in the `alerts`
table exactly as M11 wrote them, and the incident holds their ids. Correlation
creates a higher-level relationship; it does not replace what it grouped. This is
verified directly — `scripts/verify_m12.py` asserts after correlating that each
member alert row still has its original `severity` and `status` (M12.10).

Only `risk_score` is ever written onto an alert, and only by the M12.24 writer.

## 11.2 Deduplication has a different purpose from M11's

M12.11 warns explicitly against reusing M11's deduplication logic, and the
distinction is the point:

| | M11 | M12 |
| --- | --- | --- |
| question | *is this the same alert?* | *has this event already been folded into an incident?* |
| key | `rule_id \| source \| destination \| protocol \| device \| connection` | the normalized `event_id` (`fnd:<id>` / `alert:<id>`) |
| window | a bounded time window | a bounded FIFO of recent identities |
| effect of a repeat | no second alert row | no change to membership or to the score |

Both the effect **and the mechanism** differ. M11's key is a *description of an
incident* and expires by time; M12's is an *event identity* and expires by
capacity. The registry holds `_seen_events: dict[event_id → incident_id]` with a
FIFO of insertion order, bounded by `DEFAULT_SEEN_EVENT_CAPACITY` (4096). A
repeat therefore does not inflate an incident's membership, its reason trail or
its risk score.

The mapping is deliberately a **dict, not a set**: a bare set could only answer
"seen", while the mapping lets a repeated event report *which incident already
holds it* — which is what makes the duplicate outcome useful rather than merely
negative.

The bound is a real, documented trade-off: the guarantee is **exact for the most
recent N events** and best-effort beyond it. Without a bound, the cost of
deduplication would grow with uptime, which M12.22 forbids.

---

# 12. M12.13 / M12.14 — Risk scoring engine and the bounded score

`RiskScoringEngine` is a thin, stateless wrapper around the documented formula.
It exists for three reasons:

* **Assembly.** It reads the bounded configuration once (bundled as
  `ScoringBounds`) instead of making every caller know which settings feed the
  formula.
* **Result shape.** It returns a `RiskResult` that keeps the three quantities
  visibly side by side — `score`, `alert_confidence`, `correlation_confidence` —
  so a caller has to read a field *named* `score` to get the score.
* **Isolation.** It never raises out of `score(...)`. A scoring error is counted
  and reported as a zero-result carrying the `error` message, because a
  risk-scoring failure must not destroy the underlying alert or finding
  (M12.25).

The engine holds **no per-incident state** and takes **no lock** for scoring. Two
threads may score simultaneously; the only shared state is integer counters
updated under a lock, which exist for diagnostics and cannot affect a score. Same
inputs, same score, always (M12.17).

```python
@dataclass(frozen=True)
class RiskResult:
    score: int                        # 0..100, the prioritisation metric
    band: RiskBand                    # documented display band (M12.27)
    band_label: str
    alert_confidence: float           # M11.5 — echoed, NOT derived from the score
    correlation_confidence: float     # M12.7 — echoed, likewise separate
    contributions: RiskContributions  # the full term-by-term breakdown
    ml_available: bool                # False throughout M12 (M12.18)
    error: str | None                 # set on failure; score is then 0
```

## 12.1 M12.14 — The range, and what the number means

```text
0   = minimal observed risk
100 = maximum score within the model
```

The score is an **application-derived prioritisation metric**. It is not a
probability, not proof that an attack occurred, and not a claim about severity in
any absolute sense. That statement is repeated wherever a number is produced,
because a score that gets treated as a verdict is a score that misleads.

The bound is enforced in **one** place, `clamp_score(...)`, through which every
path that produces a score passes (M12.21). It handles the inputs a caller should
never send, deliberately without raising:

| input | result |
| --- | --- |
| `nan` | `0` (an explicit check — `nan` compares false against every bound, so naive clamping would let it through) |
| `inf` | `100` |
| `-inf` | `0` |
| non-numeric (`None`, a string, an object) | `0` |
| a float in range | rounded to the nearest `int`, matching the `alerts.risk_score` integer column |

Because the contribution maxima sum to exactly 100, a **fully-satisfied input
reaches the top of the range without being clamped to get there** — clamping is a
guard against invalid input, not the mechanism that makes the formula bounded.

---

# 13. M12.15 — Risk inputs

Everything the formula is allowed to look at lives in one immutable value object,
`RiskInputs`. The scorer has **no database handle, no registry, no clock and no
settings object**, so a score cannot depend on anything a test cannot control.

| input | where it comes from |
| --- | --- |
| `severity` | worst severity among the incident's alerts (M11.4) |
| `confidences` | the alerts' own confidences (M11.5) |
| `alert_count` | how many alerts the incident groups (M12.10) |
| `rule_ids` | the detection rules that fired (M10) |
| `device_ids` | resolved M8 device identities |
| `connection_ids` | resolved M9 conversations |
| `last_seen` / `now` | event recency |
| `historical_occurrences` | repeated related occurrence, when history exists (M12.20) |
| `correlation_confidence` | how strongly the events were judged related (M12.7) |
| `ml_contribution` | reserved; pinned to **0** in M12 (M12.18) |

**This model does not invent anything.** There is no asset-criticality field,
because the application has no configured asset-classification source (M12.19).
There is no history field that fills itself in, because a caller with no
historical data must be able to say so by passing nothing (M12.20).

Every accessor is **defensive**, because untrusted input is normal here — the
values are assembled from alert rows and detector output:

* `nan`, `inf` and negatives are absorbed and bounded rather than propagated.
* Non-numeric confidences are **dropped, not coerced to zero** — a dropped value
  is honest ("we could not read this confidence") while a zero would claim the
  evidence was absent.
* `alert_count` defaults to `len(confidences)` rather than to zero when unset, so
  the two views of the same fact cannot disagree.
* `mean_confidence()` takes the **mean**, not the maximum: a single confident
  alert among several weak ones is weaker evidence than a group that agrees.
* `age_seconds()` returns `None` when either timestamp is unknown (so "we have no
  timestamps" stays distinguishable from "it happened just now") and reports a
  negative age as `0`, so a backwards clock cannot inflate or deflate recency.

The **only** strictly validated input is `severity`: an unknown value raises
`ValueError`, because a misspelled severity is a bug in the caller's mapping, not
a value worth silently degrading to "low" (M11.4).

`last_seen` and `now` default to the incident scoring "as of itself", which
yields a full recency contribution rather than a decay that depends on when
someone happened to ask.

---

# 14. M12.17 — The risk contribution model

A risk score is **not** a sum of arbitrary numbers. It is the sum of seven
*independently bounded* terms, each a maximum multiplied by a fraction in `[0,
1]`. That shape gives the three properties the milestone demands: deterministic,
bounded for **every** input, and explainable point by point.

| # | term | max | what earns it |
| --- | --- | --- | --- |
| 1 | `base` | 20 | a detection exists at all (any alert count, confidence or rule id) |
| 2 | `severity` | 25 | the most serious severity among the related alerts |
| 3 | `confidence` | 15 | the mean **alert** evidence strength |
| 4 | `correlation` | 15 | how strongly the events were judged related **and** how many related alerts there are |
| 5 | `context` | 15 | device context, connection context and event recency, in three equal thirds |
| 6 | `historical` | 10 | repeated related occurrences, when history exists |
| 7 | `ml` | **0** | reserved; no ML subsystem exists in M12 (M12.18) |
| | **total** | **100** | |

The exact fractions:

```text
base         = 20  if (alert_count > 0 or confidences non-empty or rule_ids non-empty) else 0
severity     = 25 × rank(severity) / 4          # low .25, medium .50, high .75, critical 1.00
confidence   = 15 × mean(alert confidences)
correlation  = 15 × (0.6 × correlation_confidence + 0.4 × min(max(alert_count − 1, 0) / volume_alerts, 1))
context      = 5 × min(len(device_ids)/2, 1) + 5 × min(len(connection_ids)/2, 1)
             + 5 × recency_fraction
historical   = 10 × min(historical_occurrences / historical_occurrences_bound, 1)
ml           = 0
─────────────────────────────────────────────────────────────────────────────
raw_total    = sum of the seven terms
score        = clamp_score(raw_total)           # 0..100, rounded
```

Five decisions inside that formula are worth stating explicitly:

* **Severity uses the existing ordering table.** The fraction is the severity's
  `rank / 4` from `app.alerts.severity`, not a second hand-written mapping that
  could drift out of step with M11's.
* **Correlation is two halves, deliberately unequal (0.6 / 0.4).** One half is
  *confidence* (does this look like one piece of activity?), the other is
  *volume* (how much of it is there?). **Volume counts only alerts beyond the
  first**, so a lone alert contributes no correlation points at all: one alert is
  not a correlation, and scoring it as one would make every alert look related.
* **Context is three equal thirds — device, connection and recency.**
  `CONTEXT_ENTITY_CAP = 2` is the natural ceiling: a finding names a source and a
  destination, so asking for more than two resolved identities would reward
  correlations simply for being large. Recency decays **linearly** to zero over
  `risk_recency_seconds` (default 3600) — linear rather than exponential so a
  reviewer can check the arithmetic by hand, and because the term is only one
  third of a fifteen-point contribution.
* **Historical is bounded** so repeated occurrence can never dominate: the
  occurrence count saturates at `risk_max_historical_occurrences` (default 5),
  giving at most 10 points out of 100 (M12.20).
* **Unknown timestamps earn nothing** rather than defaulting to "fresh", which
  would reward missing data.

`RiskContributions` returns every term *and* the `raw_total` *and* the clamped
`score`, with a `clamped` flag. Keeping the raw total visible is what lets a test
prove **where** clamping happened rather than only that the result was in range.

Determinism is structural: no randomness, no clock read inside the formula, and
no iteration over an unordered set — `RiskInputs.from_parts(...)` deduplicates and
sorts the identity lists, because the same device named by three findings is one
device and an unordered set would make the score depend on insertion order.

## 14.1 M12.16 — The separation, restated as terms

Two separations are **structural, not stylistic**:

* **Risk and confidence are different terms.** `confidence` (max 15) consumes the
  *alert* confidences. A confidence of `1.0` on a low-severity alert therefore
  cannot by itself produce a high score: at most it earns 15 of 100.
* **Risk and correlation confidence are different terms.** `correlation` (max 15)
  consumes the *correlation* confidence. A perfectly correlated pair of trivial
  events scores low.

M12.31 tests exactly this: changing an alert's confidence does not move the score
to the same value, changing the risk *context* moves the score appropriately, the
correlation confidence remains its own quantity, and the ML contribution stays
unavailable at zero.

## 14.2 M12.18 — The ML contribution

The master architecture reserves a future ML contribution. For M12:

```text
ML contribution = 0 / unavailable
```

The field exists so the shape is future-proof, and it is **validated to 0**: any
non-zero contribution while `risk_ml_contribution_enabled` is `False` raises
`ValueError`, which the engine reports in `RiskResult.error` rather than
propagating. Accepting one would mean scoring against a model that does not
exist — the exact thing M12.18 forbids.

The future path is a configuration change, not a redesign: a later milestone
implements the signal, flips `ml_enabled` and raises `ML_MAX`, and **the rest of
the formula is untouched** — the term is already wired, already bounded, and
already part of the 100-point budget.

## 14.3 M12.19 / M12.20 — Asset and historical context

**Asset context** uses only what M8 actually knows: device *identity*, whether the
device was at the source or destination end, and the count of resolved devices
and conversations. **No criticality level is assigned**, because the application
has no configured asset-classification source (M12.19). Device identity is used,
never an invented importance rating.

**Historical context** is used only when reliable data exists. The
`historical_occurrences` count is a parameter with a default of `0`, and the
absence of history is expressible by passing nothing. There is no implicit lookup
and no self-filling field. Repetition is **not** treated as automatically
malicious: it contributes a bounded fraction (at most 10 points) and nothing more
(M12.20).

---

# 15. M12.21 — Risk boundaries

The invariant, stated once and tested everywhere:

```text
0 <= risk_score <= 100
```

It holds for **every** input, because the maxima sum to 100 and `clamp_score` is
the single enforcement point. The behaviour is pinned by tests rather than
asserted:

| case | expected |
| --- | --- |
| empty inputs | `0`, no error — "nothing observed" is a legal score, not a failure |
| a single low-severity alert | low, dominated by the base term |
| many related alerts | higher, through volume, context and severity |
| minimum possible | exactly `0` |
| maximum possible | exactly `100`, reached without clamping |
| negative / oversized contributions | clamped into the term's own bound, never out of the model's range |
| `nan` / `inf` / non-numeric | `0` / `100` / `0` respectively |
| floating-point values | rounded to an `int` *after* clamping, matching the integer column |
| score clamping | `raw_total != score` is visible via the `clamped` flag |

---

# 16. M12.22 — Correlation state management

Correlation runs indefinitely on a live capture, so "what is held" must be
bounded independently of how long the process has been up and how much traffic
has passed.

| bounded thing | bound | on overflow |
| --- | --- | --- |
| held incidents | `correlation_max_incidents` (default 1024) | the **least recently active** incident is evicted |
| incident age | `correlation_retention_seconds` (default 3600 s) | dropped, `last_seen` older than the cutoff |
| recent event identities | `DEFAULT_SEEN_EVENT_CAPACITY` (4096) | FIFO — the oldest identity is forgotten |
| identity sets per incident | `MAX_IDENTITY_ENTITIES` (256) per dimension | the dimension stops growing |
| reference lists per incident | `correlation_max_related_alerts` (default 64) | growth stops, the count keeps rising |
| reason trail per incident | `correlation_max_correlation_reasons` (default 16) | growth stops |

Four properties of that table are deliberate:

* **Eviction is by least-recent activity, not least-recent insertion.** The
  incident given up is the one an operator is least likely to still be looking
  at, which is the useful choice when a spoofed flood forces a bound to bite.
* **Expiration is swept at most ten times per retention period**, not on every
  event. Expiration is O(n) and correlation is on the capture path, so its cost
  must be bounded independently of the event rate. `expire_old_context()` is
  exposed so an operator or a background task can force a sweep instead of
  waiting for the next event.
* **Truncation is visible, never silent.** When a reference list hits its cap, the
  event count keeps rising and `dropped_events` records how many references were
  held back — so a truncated incident reads as truncated in the data.
* **Expiring correlation context loses a relationship, never a record.** The
  alerts an incident referred to stay in the `alerts` table. `verify_m12.py`
  asserts exactly this: the stored alert count is identical before and after a
  retention sweep.

Bounding the reason trail and the reference lists separately is not redundant: a
single incident under a flood of matching events would otherwise accumulate a
reasons entry per event forever.

---

# 17. M12.23 — Thread safety

Correlation runs on the capture thread while the read paths answer from a thread
pool, so both the mutation and the read must be safe.

**One lock, around the whole read-decide-write step.** A correlation step is
*find the incident this event belongs to*, then *fold the event in*. If the lock
covered only the write, two threads could both decide to fold an event into the
same incident and the second write would silently discard the first. The whole
step therefore runs under one `RLock`, which is what `IncidentRegistry.ingest(...)`
exists to provide. An `RLock` rather than a `Lock` because the public methods
compose (a lifecycle change reads, validates and writes) and re-entrancy keeps
that composition readable instead of forcing private unlocked variants.

**The lock does not cover the database — deliberately.** Scoring is pure
arithmetic and is allowed inside. Persistence is *not*: the risk write (M12.24)
runs **outside** the critical section, on the immutable incident `ingest` returned.
That keeps a slow disk from stalling correlation for every other thread, and it
keeps the failure-isolation boundary (M12.25) outside the lock.

**Incidents are immutable, so a reader never sees a half-updated object.** A read
under the lock collects the current values into a list; sorting happens *after* the
lock is released, on that snapshot. A later join produces a new instance rather
than mutating the one a reader holds.

**Per-event closures, not shared state.** The rule evaluator is built per incoming
event (`_evaluator_for(event)`), so two threads correlating different events cannot
observe each other's event.

**The risk engine takes no lock at all for scoring.** Only its integer counters are
guarded, and those exist for diagnostics and cannot affect a score.

No global lock is held across database work, and detection, alerting, statistics,
persistence, device discovery and connection tracking keep running on their own
state throughout.

---

# 18. M12.24 — Persistence

M11 leaves `alerts.risk_score` at `0` **on purpose**: a risk score needs the
incident context and the historical context M12 owns, so M11 writing a number
there would be M11 inventing one. M12 is the other half of that decision — the
writer that fills the column in once correlation actually has something to say.

```text
CorrelatedIncident  ──►  IncidentRiskWriter  ──►  AlertRepository.update_risk_scores  ──►  alerts.risk_score
```

Three boundaries are respected, and they are why this is its own module rather
than a method on the engine:

* **The engine holds no session.** `CorrelationEngine` takes a *callable*
  (`RiskPersistence`) and never imports SQLAlchemy or a repository. That keeps the
  engine importable and testable without a database, and keeps the choice of
  storage in the layer that owns storage.
* **One session per write, always closed.** The writer is called from the capture
  path and possibly a background sweep, so it opens its own short-lived session
  through the *injected* factory rather than holding one. The factory is injected,
  not imported, so a test can point it at an isolated database — exactly as the M7
  persistence worker does.
* **A write failure changes nothing about the correlation.** The failure is counted
  and then deliberately allowed to propagate, because the **engine** owns
  containment on the capture path: it contains the call, counts it in
  `stats()["persist_errors"]` and logs it with the incident's own context. Swallowing
  it in the writer as well would leave that counter structurally unable to fire, and
  a run whose every write failed would still report no persistence errors at all.

**What is written, and what is not.** Only `risk_score`. The alert's own severity,
confidence, status and evidence are M11's record of what was observed and are not
correlation's to revise — correlation records a *relationship* between
observations, it does not rewrite them (M12.10). `updated_at` is likewise left
alone: that column dates a **human's** lifecycle actions, and a machine's grouping
is not one of them. `UPDATE ... SET risk_score = :score, updated_at = updated_at`
is the deliberate self-assignment that keeps the column's existing value while
satisfying SQLAlchemy's requirement that an `UPDATE` name something.

The write is chunked (`RISK_UPDATE_CHUNK_SIZE`) so one statement bound is bounded
too, and `__call__` returns the number of rows stamped — which is what lets the
engine report how many alert rows were actually touched, rather than how many it
hoped to touch.

The column already carries a `CHECK (risk_score BETWEEN 0 AND 100)`, so the
database enforces the same bound the model does. A score is still clamped in
`clamp_score` before it is written, so the constraint is a backstop rather than
the mechanism.

---

# 19. M12.25 — Pipeline integration

```text
Scapy → CaptureManager → PacketProcessor → NormalizedPacket
    ├── TrafficStatisticsManager (M6)
    ├── PacketPersistence        (M7)
    ├── DeviceDiscoveryManager   (M8)
    ├── ConnectionTracker        (M9)
    ├── DetectionEngine          (M10) ──► DetectionFinding(s)
    ├── AlertEngine              (M11) ◄── consumes those findings
    └── CorrelationEngine        (M12) ◄── consumes those alerts
```

Correlation runs **last of all**, and only when alerting produced something:

* it consumes the alerts the alert layer just produced, normalized into
  correlation events, so it never re-inspects raw packets;
* a repeated alert identity deduplicates (M12.11), so re-correlating an alert
  already folded into an incident cannot inflate it;
* the read-only incident surface is unaffected, because the engine's public read
  methods are the only thing M13 will touch.

**Failure isolation, both directions (M12.25).** Two statements, two mechanisms:

| failure | mechanism | consequence |
| --- | --- | --- |
| a correlation failure must not stop alert processing | the pipeline wraps the correlation call in its own `try/except`; the engine additionally contains its own failures and returns a `CorrelationOutcome` with `error` set | alerting, detection, capture and persistence continue; the failure is counted (`get_correlation_error_count()`) and logged |
| a risk-scoring failure must not destroy the alert or finding | `RiskScoringEngine.score(...)` never raises — it returns a zero-result with `error` set; the registry's `_score(...)` contains anything that escapes it and stores the incident **unmodified** | the incident keeps its membership; the alert keeps everything M11 wrote; the score simply is not updated |

Both counters exist so a problem can never be silent: `packet_pipeline` and
`capture_manager` expose `get_correlation_error_count()`, and
`CorrelationEngine.stats()` reports `errors`, `persist_errors`,
`score_errors` and the store's own counters. There is nothing to flush on capture
stop — each incident is scored inline and its alerts stamped as it is built.

The engine is built once per process by `get_correlation_engine()`, on first use,
so importing the package never reads the environment, opens a database or wires a
session factory as a side effect. The risk writer is skipped entirely when
`correlation_risk_persistence_enabled` is off, in which case correlation still
runs and incidents still carry their scores in memory — only the column is left
alone.

---

# 20. M12.26 — Query support

M12.26 asks for internal query functionality with **bounded results and
deterministic ordering**, and explicitly not for the REST API. The registry
therefore exposes:

| question | method |
| --- | --- |
| recent incidents | `recent_incidents(limit=...)` |
| open incidents | `open_incidents(limit=...)` — active **and** riskiest first |
| incidents by device | `incidents_for_device(device_id, ...)` |
| incidents by source | `incidents_for_source(source_ip, ...)` |
| incidents by connection | `incidents_for_connection(connection_id, ...)` |
| incidents by rule | `incidents_for_rule(rule_id, correlation=False, ...)` |
| incidents by risk score | `incidents_by_risk(min_risk_score=..., max_risk_score=..., ...)` |
| incidents by time range | `incidents_in_range(since, until=..., ...)` |
| a general filtered page | `list_incidents(IncidentQuery(...))` / `count_incidents(...)` |
| one incident | `get(incident_id)` |

Three rules make the read surface trustworthy:

* **One value object, one filter implementation.** `IncidentQuery` is a single
  frozen dataclass and both `list_incidents` and `count_incidents` go through
  `IncidentQuery.matches(...)`, so a count can never disagree with the listing it
  accompanies — a disagreement would make paging a lie.
* **Every ordering is total.** `IncidentOrder` has four options (`RECENT`,
  `OLDEST`, `RISK`, `CONFIDENCE`) and *every* sort key ends in `incident_id`, so
  two incidents with the same timestamp still have a defined relative order and a
  page of results is stable across identical queries.
* **Every bound is validated at construction.** `limit` is `1..500`, `offset` is
  non-negative, risk bounds must be inside `0..100` and must not be inverted, and
  `since` must not be after `until`. An inverted range **raises** rather than
  returning an empty page, deliberately: an empty result would look like "no
  incidents" when the query was simply wrong. The same applies to an unknown
  status or a string order — it is normalised at construction so an `is`
  comparison downstream cannot silently fall through to the wrong ordering.

Filters combine **conjunctively**, and `active_only` composes with an explicit
status filter **by intersection** — so asking for an active `resolved` incident
correctly returns nothing rather than quietly ignoring one of the two filters.

A time-range query is a query about a **span**: an incident is selected when its
`[start_time, last_seen]` **overlaps** `[since, until)`, so an incident that began
before `since` but was still active inside the window is included.

`CorrelationEngine` re-exposes the common ones with `limit=100` defaults and adds
`highest_risk_incidents(...)`, and `engine.registry` is exposed so a caller can
reach the full query surface without the engine mirroring every method. The
engine also exposes `rescore(incident_id)` for the case where a score should
reflect *now* rather than the incident's own last activity.

---

# 21. M12.27 — Risk bands

The score is reported through four bands, defined as data in
`app/risk/bands.py` so the documentation, the tests and the API read the same
table:

| band | range | meaning for prioritisation |
| --- | --- | --- |
| `minimal` | 0 – 24 | nothing much observed; routine |
| `low` | 25 – 49 | worth a look when convenient |
| `moderate` | 50 – 74 | worth looking at soon |
| `high` | 75 – 100 | look at this first |

The bands are **inclusive on both edges and tile `0..100` with no gap and no
overlap** — a property the tests assert directly rather than assume. A band is
recomputed from the score whenever the score changes, so a stored band can never
disagree with the score beside it.

> **These bands are application-defined prioritisation ranges. They are not proof
> of attack severity, and they are not a probability.** `high` means "look at this
> first", not "an attack occurred".

---

# 22. Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `CORRELATION_ENABLED` | `true` | master switch for the pipeline consumer |
| `CORRELATION_WINDOW_SECONDS` | `900.0` | the correlation window (ceiling 86 400) |
| `CORRELATION_PROXIMITY_SECONDS` | `300.0` | the time-proximity band, within the window |
| `CORRELATION_MIN_CONFIDENCE` | `0.5` | the correlation confidence floor (M12.7) |
| `CORRELATION_MIN_ANCHOR_STRENGTH` | `0.55` | the strength a relationship needs to anchor alone (M12.4) |
| `CORRELATION_MAX_INCIDENTS` | `1024` | hard cap on held incidents (M12.22) |
| `CORRELATION_RETENTION_SECONDS` | `3600.0` | age after which inactive context expires |
| `CORRELATION_MAX_RELATED_ALERTS` | `64` | cap on each per-incident reference list |
| `CORRELATION_MAX_CORRELATION_REASONS` | `16` | cap on the reason trail |
| `CORRELATION_RISK_PERSISTENCE_ENABLED` | `true` | whether a score is written to `alerts.risk_score` (M12.24) |
| `CORRELATION_DEFAULT_PAGE_SIZE` | `100` | default incident listing page size |
| `CORRELATION_MAX_PAGE_SIZE` | `500` | maximum incident listing page size |
| `RISK_ML_CONTRIBUTION_ENABLED` | `false` | whether a non-zero ML contribution is accepted (M12.18) |
| `RISK_MAX_VOLUME_ALERTS` | `5` | additional related alerts that saturate the volume half of the correlation term |
| `RISK_MAX_HISTORICAL_OCCURRENCES` | `5` | previous occurrences that saturate the historical term |
| `RISK_RECENCY_SECONDS` | `3600.0` | age at which the recency third falls to zero |

Every bound is configuration, never hard-coded, and each has a documented
default. The settings object meets the model in exactly two places —
`CorrelationEngine.from_settings(...)` and `RiskScoringEngine.from_settings(...)` —
so the rule set, the relationship table and the formula each stay free of
configuration coupling, and neither can be reconfigured into an unbounded state:
the window, the retention age and the page size all reject an unusable value at
construction rather than at the first event.

---

# 23. Error handling

| Condition | Behaviour |
| --- | --- |
| A finding/alert that cannot be normalized | the engine returns an error `CorrelationOutcome`; the alert is untouched, capture continues (M12.25) |
| An alert with no observation time | `ValueError` from `from_alert`, contained per event — correlation is about time, so an untimed event is not correlated rather than guessed at |
| Unexpected failure correlating | counted in `stats()["errors"]`, logged with the event id, returns an error outcome; alert processing continues (M12.25) |
| A risk-scoring failure | `RiskResult.error` set, score `0`; the incident is stored **unmodified** and the alert keeps everything M11 wrote (M12.25) |
| A persistence failure | counted in `stats()["persist_errors"]`, logged with the incident id; the correlation stands and the score stays in memory (M12.24) |
| A non-zero ML contribution while ML is off | `ValueError` surfaced in `RiskResult.error`; never scored (M12.18) |
| An unknown severity | `ValueError` — a typo in the caller's mapping, surfaced rather than degraded to "low" |
| A severity/status typo written to an incident | `ValueError` at construction, so it can never be stored as state |
| An illegal lifecycle move | `InvalidIncidentTransition` naming the reachable states; the stored incident is untouched (M12.9) |
| A lifecycle move on a missing incident | `None` → the eventual API's `404` |
| An unusable window / retention / page size | `ValueError` at construction (startup, not first event) |
| An inverted query range or an out-of-range risk bound | `ValueError` at construction, so a wrong query never looks like "no incidents" (M12.26) |

---

# 24. Manual verification (M12.33)

`scripts/verify_m12.py` has two modes:

* **sample** (default) — builds controlled M10 findings, turns them into real M11
  alerts through the real `AlertService` (backed by an isolated temporary SQLite
  database), feeds those alerts to the real `CorrelationEngine`, and prints every
  incident with the rule that grouped it, its reason trail, its score, and the
  three separate confidences. No admin rights and no Npcap needed. The database is
  created and removed by the script, so it never touches the developer's
  `netwatch.db`.
* **live** — captures real traffic through `CaptureManager` and the whole pipeline
  with correlation enabled, for a few seconds. Authorized/local traffic only.

Six scenarios, each asserting one completion criterion, plus a pipeline scenario
driven through real packets:

| scenario | what it proves |
| --- | --- |
| 1 — port scan then internal scan, one source | **the M12.33 headline**: two related alerts → one incident, `matched:scan_sequence` attributed, the shared source in the reason trail, both alerts preserved with their M11 severity and status, the score written onto both alert rows, and re-correlating a member reported as a duplicate without growing the incident |
| 2 — two unrelated sources | unrelated activity is **not** merged (M12.4); each still opens its own incident |
| 3 — the same source, far outside the window | proximity does not override the window (M12.5); both open separate incidents with correlation confidence `0.0` |
| 4 — two sources, one destination | `same_destination` correlation works and is attributed to `same_destination_activity` (M12.6) |
| 5 — two findings on one M9 conversation | `same_connection` works, a findings-only incident has no alert ids, and its risk write is a no-op rather than an error (M12.3/M12.24) |
| 6 — two alerts on one M8 device | `same_device` works, with the shared identity deliberately on the *destination* device so it is not also a `same_source` match |
| identity demo | two events sharing only a timestamp produce `time_proximity` with **no anchor**; adding a shared source produces an anchoring relationship and raises the confidence — M12.4's rule, checked against the real table |
| bounded state | the store holds no more than its cap, a retention sweep clears the incidents, and **the stored alert count is identical before and after** (M12.22) |
| lifecycle | `open → investigating → resolved` applies, and `resolved → open` is rejected (M12.9) |
| ML | `ml_available` is `False` and a non-zero ML signal is refused (M12.18) |
| score bounds | every incident the run produced scores inside `0..100` and carries a documented band (M12.14/M12.21) |

The scenario set asserts a fixed expected incident count
(`EXPECTED_SCENARIO_INCIDENTS = 9`), so an accidental cross-scenario merge cannot
pass unnoticed. Each scenario uses its own address space for the same reason: a
shared destination between two scenarios would anchor them together and quietly
test the opposite of what the scenario claims.

The verified chain:

```text
Detection Finding → Alert → Correlation Engine → Correlated Incident
                                                → Correlation Reasons
                                                → Risk Score  → alerts.risk_score
                                (alert confidence ≠ correlation confidence ≠ risk score)
```

---

# 25. Performance baseline (M12.34)

`scripts/benchmark_m12.py` measures the M12 code in isolation, in seven phases:
distinct-incident correlation, grouped-alert correlation, deduplication, the
scoring formula, incident query response, `tracemalloc` heap, and the bounded
store under a cap smaller than the workload.

**Local baseline (this machine, OneDrive-synced disk, single process, defaults):**

| phase | result |
| --- | --- |
| findings correlated, one distinct incident each (2 000) | 85 / sec, **11 726 µs per finding** |
| alerts correlated, folding into groups (2 000 → 400 incidents) | 595 / sec, 1 680 µs per alert |
| deduplication, one repeated identity (20 000 repeats) | 249 893 / sec, **4.0 µs per lookup** |
| risk calculation (20 000 scores) | 33 776 / sec, 29.6 µs per score |
| incident → risk inputs | 328 794 / sec, 3.0 µs |
| incident queries (store of 200 incidents, ~12 paths) | 0.03 – 0.27 ms per read; `get_incident(id)` ≈ 0 |
| heap per held incident (`tracemalloc`) | 2 264 bytes |
| bounded store, cap 256, 2 048 distinct incidents | cap held at 256, 1 792 evicted, retention sweep of 256 in 0.18 ms |

**The baseline's main finding is the first row, and it is worth stating plainly.**
With no match, every held incident is *evaluated* against the incoming event
before the engine can conclude there is none. That is **O(held incidents) per
event**, so N distinct incidents cost O(N²) relationship evaluations in total. At
2 000 held incidents that is ~12 ms per finding, and it is this term — not
normalization, not deduplication and not scoring — that dominates correlation
cost. The grouped-alert row shows the other side of the same coin: when a match
exists and the matching incident is recently active, it is found early in the
candidate scan, so the same machinery runs at ~1.7 ms per alert.

This is a real scalability characteristic, recorded rather than smoothed over. The
bound in M12.22 caps how far the quadratic term can grow; a future milestone that
needs higher throughput would index the incident store by identity dimension
rather than scanning it.

Every figure is a **single-machine, in-process measurement of the M12 code
alone**. It excludes real capture, the M5–M11 consumers, JSON serialisation and
the network stack, and the defaults are sized so a full run takes well under a
minute. **This is a local baseline, not a production-capacity claim.**

---

# 26. Deliberate non-goals

* No new packet detectors, new alert types, behavioural baselines, ML anomaly
  detection or AI analysis. M12 consumes M10/M11 output; it does not extend it.
* No automatic blocking and no incident-response automation. M12 groups and
  prioritises; it never acts.
* No WebSockets and no frontend integration.
* No REST API. M12.26 asks for *internal* queries only; M13 owns the API surface.
* No new database tables or columns. `alerts.risk_score` —
  which M11 deliberately left at `0` for exactly this milestone — is the one
  column M12 writes, and the correlated incident lives in bounded runtime state.
* No asset criticality. The application has no configured asset-classification
  source, so none is invented (M12.19).
* No ML contribution. The term exists, is bounded, and is pinned to zero; a
  non-zero signal is refused (M12.18).
* No claim of production-scale throughput — the benchmark records a local
  baseline and names the quadratic term that dominates it.

---

# 27. Test plan (M12.28 – M12.32)

| Area | File | Tests |
| --- | --- | --- |
| correlation identity: same source, destination, device and connection; time-window correlation; the exact window boundary (inside and outside); different unrelated events; multiple alerts and multiple findings; deduplication; incident creation and update | `tests/test_correlation_identity.py` | 29 |
| correlation rules: each rule's conditions, evaluation order, attribution of the most specific rule, the anchor requirement, the reason trail | `tests/test_correlation_rules.py` | 22 |
| correlation engine: event in → incident out, both gates (anchor and confidence floor), deduplication, incident growth, bounded membership, thread safety, failure isolation, lifecycle transitions, the full query surface with deterministic ordering and bounded pages | `tests/test_correlation_engine.py` | 40 |
| risk scoring: empty context, single low-severity alert, multiple related alerts, high/low confidence, high severity, repeated historical activity, maximum input, clamping, invalid input, determinism, and the explicit risk/confidence/ML separation | `tests/test_risk_scoring.py` | 40 |
| persistence: the risk write reaching `alerts.risk_score`, only that column changing, chunking, no-op on a findings-only incident, a write failure contained by the engine | `tests/test_correlation_persistence.py` | 11 |
| integration: Detection Engine → Finding → Alert Engine → Correlation Engine → Risk Scoring Engine → Incident, with the underlying alerts still accessible | `tests/test_correlation_integration.py` | 10 |
| shared test doubles | `tests/correlation_fakes.py` | — |
| manual verification | `scripts/verify_m12.py` | — |
| performance baseline | `scripts/benchmark_m12.py` | — |

The M12 suite is **194 tests** (collected; several are parametrized, which is why
the count exceeds the number of test functions). The project-wide suite is
**1 271 tests**, all passing.

Boundary coverage is explicit rather than incidental: the correlation window is
pinned at *exactly* the boundary, just inside it and just outside it; missing
source, destination, device and connection references are each exercised; and
multiple simultaneously plausible incidents are checked to confirm the engine
picks deterministically and does not merge unrelated activity.
