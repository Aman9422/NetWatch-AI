# M17 — Reports

**Milestone:** M17 — Report Generation
**Status:** implemented and verified
**Depends on:** M6 (traffic statistics), M7 (packet persistence), M8 (device discovery), M9 (connection tracking), M10 (detection), M11 (alert engine), M12 (correlation and risk), M13 (REST API), M15 (frontend integration), M16 (analytics)
**Consumes:** `requests` from the M15 frontend, over the M13 endpoints

---

## 1. Purpose

M13 exposed `GET /api/v1/reports` and `GET /api/v1/reports/{id}`, and M15 put a
Reports page in front of them. Those routes could only ever *list*: the `reports`
table is written by hand, nothing in the application produced a row, and no route
produced a document. A user could see that a report had once been recorded and
could not ask for one.

M17 makes the reporting layer real. It resolves a reporting period, reads the M16
analytics views over it, assembles one renderer-agnostic content model, renders it
to CSV or PDF, writes the artifact to disk, records the outcome, and serves the
file back. Four routes over one subsystem:

```text
GET  /api/v1/reports              stored metadata, newest first
GET  /api/v1/reports/{id}         one report's metadata
POST /api/v1/reports/generate     produce a report and record it
GET  /api/v1/reports/{id}/download  serve the artifact itself
```

The governing constraint is that M17 is a **consumer and a formatter**. It reads
what M6–M12 already produced, through the M16 analytics service, and writes it
down. It introduces no second statistics engine, no second device identity, no
second risk score, no new detection logic and no new metric of any kind.

---

## 2. Scope

M17 delivers:

1. **A period model** — one module that decides what a reporting period is, so a
   report and a dashboard query for the same instants select the same rows.
2. **A request layer** — one module that decides which combinations of type,
   format, title and bounds are answerable, and refuses the rest with a sentence.
3. **A content model** — one renderer-agnostic description of what a report says,
   consumed by both renderers.
4. **A CSV renderer and a PDF renderer** — two independent producers of the same
   content, behind one lookup table.
5. **An artifact store** — one directory, one collision-safe naming rule, atomic
   writes and confined reads.
6. **A generation lifecycle** — a metadata row that moves through `generating`,
   `completed` and `failed`, and never claims a file that is not there.
7. **A generation API** — validation, explicit refusals, safe failures and a
   download route that serves bytes rather than JSON.
8. **A frontend** — a generation form, an outcome panel, a report row and a detail
   panel, over the same typed client M15 already used.
9. **Tests** — 257 reporting tests across eight files plus a shared fake set, the
   full M0–M16 regression suite, a local performance baseline and a two-mode
   verification script run against the real stack.

---

## 3. Non-goals

Explicitly outside M17, and not implemented by it:

- ML anomaly detection, behavioural baselines, AI explanations
- local LLM / Ollama integration
- automatic blocking, IPS functionality
- SIEM or threat-intelligence integrations
- authentication, RBAC
- notification delivery
- distributed sensors, scheduled or recurring reports
- new analytics figures, new risk scores, new severity vocabularies
- any change to M6, M8, M9, M10, M11, M12 or M16 behaviour

Where an M17 document mentions future ML/AI work, it is named as out of scope
rather than described as present.

---

## 4. Architecture position

```text
M6  Traffic Statistics ─┐
M7  Packet Persistence → packets
M8  Devices            ─┤
M9  Connections        → connections
M10 Detection          ─┤
M11 Alerts             → alerts
M12 Correlation + Risk ─┘
                        │
                        ▼
                  Analytics (M16)
                        │
────────────────────────┴──────────────────────
                  Reports (M17)
───────────────────────────────────────────────
                        │
                        ▼
                  M13 REST API
                        │
                        ▼
                  M15 Frontend
```

M17 reads **the analytics layer and nothing else**. A report does not query the
packet table, does not touch the M8 registry directly, does not read an incident
from the M12 registry itself. Every figure in a report came from a call the
analytics service already answers, which is what makes the report and the
dashboard agree by construction rather than by discipline (§6).

M17 *does* hold state, unlike M16, and it is the first milestone in the project to
do so. Two kinds:

| State | Where | Lifetime |
| --- | --- | --- |
| report metadata | the `reports` table | permanent |
| report artifacts | the configured storage directory | until deleted |

The third kind it deliberately does **not** hold: no cached analytics, no cached
content model, no in-memory report registry. A report is generated once and read
from disk after that.

---

## 5. Data sources

### 5.1 Persisted (SQLite)

| Table | Owner | M17 reads / writes | Filter column | Index used |
| --- | --- | --- | --- | --- |
| `reports` | M2, extended by M17.9 | reads and writes one row per generation | `generated_at` for the listing | `ix_reports_generated_at` |
| `packets` | M7 | **indirectly**, through M16's traffic, protocol and device sections | `timestamp` | `idx_packets_timestamp` |
| `connections` | M9 | **indirectly**, through M16's connection section | `start_time` | `idx_connections_start_time` |
| `alerts` | M11 | **indirectly**, through M16's threat section | `created_at` | `idx_alerts_created_at` |

No new table is introduced. The `reports` table gains five columns and no more
(§12). No new index is added: the listing orders by `generated_at` on a column
M2 already indexed, and every other read is an M16 read on a column M7, M9 or
M11 already indexed.

### 5.2 Live (in-process)

M17 reads no live service directly. The five in-memory blocks a report carries —
the M6 statistics snapshot, the M8 device registry, the M9 tracker counters, the
M10 detection counters and the M12 incident registry — are read by the M16
analytics service, and the report receives them as an already-assembled view.
That indirection is deliberate: it is why a report cannot disagree with the
analytics endpoints about what the registry holds.

### 5.3 The filesystem

| Location | Owner | M17 does |
| --- | --- | --- |
| `settings.report_storage_dir` (default `reports`) | M17.9 | creates it on first write, writes artifacts into it, resolves downloads inside it |

This is the only filesystem location M17 touches. A report's bytes never enter the
database and a report's metadata never enters a filename beyond its id.

### 5.4 What M17 does *not* read

- No second copy of a packet, device, connection, alert or incident is created.
- The M5 packet processor, M6 rate windows, M7 persistence internals, M8–M12
  runtime internals are not queried; the M16 views over them are.
- No table is written other than the one `reports` row a generation owns.

---
## 6. Reporting architecture

```text
app/api/v1/reports.py      route: validate the body, call the service, wrap in the
                           M13 envelope (or serve bytes, for a download)
        ↓
app/reports/service.py     ReportService: the generation state machine — row,
                           content, bytes, artifact, outcome
        ↓
    ┌──────────────────────┬─────────────────────────┬──────────────────────┐
    │ period.py            │ assembler.py            │ storage.py           │
    │ resolve a period     │ M16 analytics → content │ atomic writes,       │
    │                      │ (the only reader of     │ confined reads,      │
    │ requests.py          │  AnalyticsService)      │ naming rule          │
    │ validate a request   │                         │                      │
    │                      │ content.py              │ renderers.py         │
    │                      │ the renderer-agnostic   │ format → renderer    │
    │                      │ model                   │                      │
    │                      │                         │ csv_renderer.py      │
    │                      │                         │ pdf_renderer.py      │
    └──────────────────────┴─────────────────────────┴──────────────────────┘
```

### 6.1 Modules

| Module | Responsibility |
| --- | --- |
| `app/reports/period.py` | the only definition of a reporting period: presets, bounds, validation, the ceiling |
| `app/reports/requests.py` | the only place a loose request becomes a canonical one: type, format, title, bounds |
| `app/reports/content.py` | `Metric`, `ReportTable`, `ReportSection`, `ReportContent` — what a report says, with no renderer knowledge |
| `app/reports/assembler.py` | `build_report_content`: reads the M16 views and writes them into the content model |
| `app/reports/csv_renderer.py` | `render_csv`: the content model as a block-structured UTF-8 document |
| `app/reports/pdf_renderer.py` | `render_pdf`: the same model as a paginated PDF, via reportlab |
| `app/reports/renderers.py` | the one table mapping a format to its renderer, and `render_report` |
| `app/reports/storage.py` | `ReportStorage`: the directory, the naming rule, atomic writes, confined reads |
| `app/reports/errors.py` | three failure kinds, each mapping to one HTTP status |
| `app/reports/status.py` | the generation-state vocabulary, shared by the service and the schema |
| `app/reports/service.py` | `ReportService`: the generation lifecycle over one request's session |
| `app/repositories/report.py` | the `reports` table's queries, extended by M17 for period, status and size |
| `app/schemas/report.py` | the wire contract: `ReportView`, `ReportGenerationRequest`, `GeneratedReportData` |
| `app/api/v1/reports.py` | the four routes |

### 6.2 Design decisions

1. **Reuse the analytics layer rather than re-query.** Every figure in a report has
   to agree with the figure the dashboard shows for the same instants. Two
   implementations of the same aggregation drift apart; one cannot. `assembler.py`
   is therefore not a query layer at all — it calls `AnalyticsService` and writes
   the answers down.

2. **One content model, two renderers.** `content.py` knows nothing about CSV,
   PDF, reportlab or the `csv` module. Both renderers walk the same structure, so
   the two formats cannot disagree about what a report says. This is the whole
   reason the content model exists as a separate module.

3. **The period is bounded by M16's own ceiling.** `MAX_REPORT_PERIOD_SECONDS` is
   `app.analytics.window.MAX_WINDOW_SECONDS` (30 days), reused rather than
   re-declared. A reports-specific ceiling would eventually let a caller ask a
   question the analytics layer would refuse, and the report would fail deep
   inside a query instead of at the door.

4. **Refusal, never adjustment.** A request that cannot be honoured is refused with
   a sentence naming the field. A daily report is *the previous completed UTC day*,
   so a caller who also sends `since` and `until` has asked two contradictory
   things and is told so, rather than having one silently dropped.

5. **The row is written before the file, and says so.** A generation is a small
   state machine over one row. Writing the row first is what makes the middle
   state observable: a request interrupted mid-render leaves a row that truthfully
   says the file does not exist yet, rather than leaving no trace of the attempt.

6. **The file name comes from the row's id.** The name carries the id, so it can
   only be built after the insert has assigned one. The row is created with an
   empty location and the name filled in immediately after; an empty value is not
   a location, and the storage layer refuses to resolve it.

7. **Where files live is decided in one place.** The service takes a
   `ReportStorage` rather than reaching for one, so a test generates a real report
   into a temporary directory without touching the configured one.

---

## 7. Reporting periods

**Module:** `app/reports/period.py`
**Model:** `ReportPeriod`

### 7.1 The four rules

| Rule | Value |
| --- | --- |
| Convention | `[since, until)` — `since` **inclusive**, `until` **exclusive** (M13.26) |
| Encoding | ISO-8601 UTC, explicit `+00:00` offset |
| Maximum span | 30 days (`MAX_REPORT_PERIOD_SECONDS = 2 592 000 s`) |
| Empty range | refused (`since == until`) |
| Inverted range | refused (`since > until`) |

Bounds follow M13.26 because M10's finding query, M11's alert query, M16's
analytics window and M13's HTTP filters already do. A report and an analytics view
for the same instants therefore select the same records.

### 7.2 Why half-open, and not merely "consistent"

Consecutive daily reports share a boundary instant — one ends at `T` and the next
begins at `T`. A half-open interval is what stops the record observed exactly at
`T` from being counted in **both**. A closed interval would double-count it in two
adjacent reports, and the sum of a month of daily reports would exceed the monthly
one. This is a correctness property, not a convention, and M17.5 asks for it to be
verified as absent.

### 7.3 Daily and weekly mean *the previous completed* UTC day and week

A daily report generated on Tuesday covers **Monday**. A weekly report generated
on a Wednesday covers the Monday-to-Sunday week that **ended most recently**. This
is stated in the report itself, so a reader never has to infer which day a "daily"
report describes.

| Preset | Resolves to |
| --- | --- |
| `daily` | `[previous day 00:00 UTC, today 00:00 UTC)` |
| `weekly` | `[previous Monday 00:00 UTC, this Monday 00:00 UTC)` |
| `custom` | the caller's bounds, validated |

`utc_day_start` floors to a whole day **through `datetime`** rather than by integer
division, so a DST rule or a change of UTC offset in some future tz database cannot
make the arithmetic disagree with the calendar. `utc_week_start` uses
`datetime.weekday()`, which makes Monday day 0 — the ISO-8601 week.

### 7.4 Presets take no bounds, and a half-supplied custom period is refused

A preset derives its period from the calendar, so a preset that also carries
`since` or `until` is refused. Defaulting the missing half of a custom period would
answer a question nobody asked, and the period a report covers is the one fact a
reader must be able to trust.

### 7.5 A period always has a name

| Type | Label |
| --- | --- |
| `daily` | the calendar day, e.g. `2026-10-10` |
| `weekly` | `2026-09-28 to 2026-10-04` |
| `custom` | both instants, e.g. `2026-10-04T07:05:09+00:00 to 2026-10-11T07:05:11+00:00` |

The weekly label ends on the last day the report **covers**, not on the exclusive
bound: a week ending Monday 00:00 is named `...-10-04` rather than `...-10-05`,
because nobody considers the following Monday part of the week.

The label is what the default title is built from, so two daily reports generated
in the same hour cannot share a name.

### 7.6 There is no path that reports over all of history

A period is always bounded: the presets derive bounds from the calendar and a
custom period is refused when it is empty, inverted or longer than the ceiling.
A report over "everything" would scan the packet table without limit.

---

## 8. Report content model

**Module:** `app/reports/content.py`

A report is *data* before it is a file. Four shapes, each with one job:

| Shape | Job |
| --- | --- |
| `Metric` | a labelled scalar: `{label, value}`. The value is already rendered text, so a number's format is decided once, at the point where its unit is known. |
| `ReportTable` | a titled table with **declared** column names and string rows, plus an optional `notice` shown instead of rows. |
| `ReportSection` | one subject — traffic, protocols, devices, connections, threats — with its own metrics, tables and an explicit `available` flag. |
| `ReportContent` | everything one report says: identity, period, summary metrics and body sections. |

### 8.1 The five body sections, and the summary

| Section key | Title | Built from |
| --- | --- | --- |
| `traffic` | Traffic | `analytics.traffic(window, limit, by="bytes")` |
| `protocols` | Protocols | `analytics.protocols(window, by="bytes")` |
| `devices` | Devices | `analytics.devices(window, limit, by="bytes")` |
| `connections` | Connections | `analytics.connections(window, limit, by="bytes")` |
| `threats` | Threats | `analytics.threats(window)` |

The summary is not a sixth section: it is a tuple of `Metric` values built from the
report's identity plus **named headline figures lifted out of the five sections**.
`HEADLINE_METRICS` names each `(section key, metric label)` pair explicitly, so
renaming a section's metric without updating the summary fails the test suite
rather than silently dropping a headline figure from every future report. A
summary can therefore never disagree with the body it summarises.

### 8.2 The ranking metric is documented, not implicit

Every ranking in a report is ordered by **bytes** (`REPORT_RANK_METRIC`), not by
packets, because a report is read after the fact and a reader comparing two days
cares more about how much moved than about how many frames carried it. The choice
is stated in each table's column header (`Busiest sources (by bytes)`), so it is
visible in the document rather than only in the code.

### 8.3 Availability is inherited, not re-invented

The analytics service already reports a database-derived block that could not be
read as an unavailable section (M16.8). The assembler carries that through
unchanged:

| Block state | Becomes |
| --- | --- |
| unreadable | a `ReportSection` with `available=False` and a fixed sentence; **no** metrics and **no** tables |
| readable but empty | an available section holding an empty table with an explicit "no rows" notice |
| readable with rows | an available section holding the rows |

The two sentences are constants — `NO_ROWS_NOTICE` and `UNAVAILABLE_NOTICE` — so
the two renderers cannot word the same situation differently.

### 8.4 Live and stored are reported separately, where M16 reports both

For traffic, protocols, connections and threats, the M16 view carries a *live* half
and a *stored* half, and a report prints both:

| Half | Means |
| --- | --- |
| live | the in-process counters: they reset with the process and describe "since capture started" |
| stored | the persisted rows read over the period: the historical record |

A report is a historical document, so the stored half is the one that matters — but
the live half is printed beside it rather than dropped, because a reader comparing
a report against a running dashboard needs to see why the two numbers differ.

### 8.5 Nothing in this package scores anything

Risk bands, severities and confidence ranges are read from M11 and M12 **as M16
reports them**. No figure in a report is judged, weighted or scored by M17.

---

## 9. CSV rendering

**Module:** `app/reports/csv_renderer.py`
**Function:** `render_csv(content: ReportContent) -> bytes`

### 9.1 Shape

A block-structured document, written with the standard `csv` module so quoting,
delimiting and line endings are the library's problem rather than M17's:

```text
report                                    <- the identity block
metric,value
Report title,Weekly network report 2026-09-28 to 2026-10-04 (CSV)

section:traffic                           <- one block per body section
metric,value
Packets stored in period,"1,005"
table:traffic_series
Bucket start (UTC),Packets,Bytes
2026-09-28T00:00:00+00:00,12,20480

table:top_sources
Source,Packets,Bytes
10.0.0.7,"120","24000"
```

Every block is introduced by a marker line (`report`, `section:<key>`,
`table:<key>`), so a reader — a person or a script — can find a named part of the
document without parsing the whole thing. Table keys and column names come from
the content model, so the CSV header and the PDF table header cannot disagree.

### 9.2 Rules

| Rule | Why |
| --- | --- |
| UTF-8, written with `csv.writer` | quoting and escaping stay the library's job |
| One marker line per block | named parts are findable without a full parse |
| Column names from the content | the CSV and the PDF headers share one source |
| Cell text already rendered | a number's unit and precision are decided once, in the assembler |
| An empty table writes its notice instead of rows | an empty report says why rather than presenting an unlabelled blank |

---
## 10. PDF rendering

**Module:** `app/reports/pdf_renderer.py`
**Function:** `render_pdf(content: ReportContent) -> bytes`
**Library:** `reportlab` (declared in `backend/requirements.txt` by M17)

### 10.1 What it produces

A paginated document in the same reading order as the CSV: the title, the period,
the summary metrics, then one block per body section, each with its metrics
followed by its tables.

| Element | Rendered as |
| --- | --- |
| title | document heading |
| period | the half-open bounds, printed under the heading |
| summary metrics | a two-column label/value table |
| section | a section heading, then its metrics, then its tables |
| table | a reportlab table with the declared column names as its header row |
| empty table | the content's notice sentence in place of rows |
| unavailable section | the section's notice sentence in place of metrics and tables |

### 10.2 Rules

| Rule | Why |
| --- | --- |
| Column names come from the content | the PDF header and the CSV header share one source |
| Cell text comes from the content | the PDF cannot round or unit-shift a figure the CSV left alone |
| An empty report says so once | the document states "the period holds no stored data" rather than presenting unlabelled empty tables |
| No figure is computed here | the renderer formats; the assembler decides what a number means |
| Text is wrapped to the page width | a long label or address cannot overflow the page |
| The renderer is pure | it takes content and returns bytes; it touches no session, no filesystem, no clock |

### 10.3 The cost is real and it is the dominant cost

The PDF renderer is by far the most expensive step in a generation — roughly
**600 ms** against roughly **1 ms** for the CSV encoder on the same content (see
§15.4). This is reportlab's layout work, not M17's. It is the honest explanation
for why the two formats have very different generation latencies, and it is why the
generation endpoint's cost is described per format rather than as one number.

---

## 11. Storage and artifacts

**Module:** `app/reports/storage.py`
**Class:** `ReportStorage`

Everything that touches the filesystem is in this one file, so "which paths can the
reporting layer touch?" has a single answer a reviewer can read in one place.

### 11.1 One directory, configurable

Artifacts go in `settings.report_storage_dir` (default `reports`). A relative value
is resolved against the process working directory — the same directory the default
`sqlite:///./netwatch.db` already assumes — so the default configuration needs no
absolute path and a deployment can point the directory at a mounted volume by
setting one variable.

The directory is created **on first use**, not at construction and not at import:
importing a module must never write to disk, and a service may be built to answer a
listing request that never writes anything.

### 11.2 One naming rule, and it is collision-safe

```text
netwatch-report-000123-2026-10-09-daily.csv
      │            │     │          │      └─ format extension
      │            │     │          └─ period label, reduced to [A-Za-z0-9-]
      │            │     └─ zero-padded six-digit report id
      │            └─ constant prefix
      └─ constant prefix
```

| Element | Why |
| --- | --- |
| the id | what makes the name unique. Two daily reports for the same day — generated twice, or generated in two formats — get different ids and therefore different names, so a second generation can never overwrite the first one's file. |
| the period label | for a human browsing the directory |
| the format extension | derived from the stored format, so a request cannot choose one |
| six-digit padding | directory listings sort lexicographically: without padding, report 10 would sort before report 9 |

A label's characters are collapsed to `[A-Za-z0-9-]`, which is defence in depth
rather than a routine substitution: it guarantees a label can never contribute a
path separator, a drive letter or a wildcard to a name.

### 11.3 Writes are atomic

Bytes go to a temporary file **in the same directory** and are then moved onto the
final name with `os.replace`, which is atomic on both POSIX and Windows. A reader
therefore never sees a half-written artifact: it is either the previous file or the
complete new one.

The write also `fsync`s before the replace, so the bytes are durable before the
name points at them. A failure removes the temporary file, so a failed generation
leaves no debris and no directory slowly accumulates `.tmp` files.

### 11.4 Downloads are confined

`ReportStorage.artifact_path` returns a path only when it resolves **inside** the
storage directory. A stored `file_path` is data read from a database row, and a
database value must never be able to make the process open an arbitrary file: the
containment check is what stops it, and it is applied **on every read** rather than
trusted once at write time.

| Input | Result |
| --- | --- |
| a bare file name | resolved against the storage directory |
| a path inside the directory | resolved and served |
| a path outside the directory | refused as `ReportArtifactMissing` |
| a path that does not exist | refused as `ReportArtifactMissing` |
| a directory | refused as `ReportArtifactMissing` |

All four refusals produce the *same* answer to a client — the artifact is not
available — and none of them names a path (M13.30).

### 11.5 Failures are sentences

A directory that cannot be created, a file that cannot be written, an artifact that
is not there: each raises a reporting error whose message names the *situation* and
not the path. The real exception is logged beside the report's id and never
returned.

---

## 12. Generation lifecycle

**Module:** `app/reports/service.py`
**Class:** `ReportService`

### 12.1 The three states

**Module:** `app/reports/status.py`

| State | Means | Downloadable |
| --- | --- | --- |
| `generating` | the metadata row exists and the artifact is being produced | no |
| `completed` | the artifact was written and its size recorded | yes |
| `failed` | generation was attempted and did not finish; `error` carries a safe sentence and any partial file was removed | no |

The vocabulary lives in its own module because both the storage layer and the API
schema compare against it, and a shared module is what stops three modules from
spelling "completed" three ways. The three values are compared as plain strings, so
the class is a namespace rather than an `Enum`: a value read out of SQLite is a
string, and wrapping it in an enum would mean every read site constructs one before
comparing.

### 12.2 The steps of one generation

```text
1. resolve the period          resolve_period(request)     -- refuses an unanswerable
                                                             request before any write
2. write the row               status = generating, file_path = ""
3. fill in the file name       the name needs the id step 2 assigned
4. assemble the content        build_report_content(analytics, period, ...)
5. render the bytes            render_report(content)
6. write the artifact          storage.write(filename, payload)
7. record the outcome          status = completed, file_size, error = None
```

Steps 4–6 are wrapped: a failure in any of them marks the row `failed`, removes any
partial artifact, and re-raises a reporting error carrying a sentence an operator
can act on. The real exception is logged in step 7's failure path, beside the
report's id, and never returned.

**Why the row is written before the file.** A generation is a small state machine
over one row, and writing the row first is what makes the middle state
*observable* rather than theoretical: a request interrupted mid-render leaves a row
that truthfully says the file does not exist yet, instead of leaving no trace of the
work that was attempted.

**Why the file name follows the insert.** The name carries the row's own id, so it
can only be built once the insert has assigned one. The row is created with an
empty location and the name filled in immediately afterwards; the empty value is
not a location, and the storage layer refuses to resolve it, so a row interrupted
between the two steps can never be served as though it had a file.

### 12.3 A failure leaves nothing behind that claims otherwise

On failure the row is marked `failed` with a safe sentence, the file size is set to
`None`, and any partial artifact is deleted. `_mark_failed` runs on the way out of
a failure, so it must not raise: a second exception raised while cleaning up would
replace the one worth reporting. Both steps are attempted and any trouble is logged
rather than propagated.

### 12.4 "Downloadable" is asked of the store, not inferred from the status

`artifact_is_available` returns `False` unless the row's status is `completed`
**and** the file is actually present. The two can genuinely disagree: a file removed
by hand leaves a `completed` row with nothing to serve, and reporting it as
downloadable would be a promise the next request breaks. The listing therefore
states, per row, whether a download would succeed — without a download being
attempted.

### 12.5 The row's schema

**Module:** `app/models/report.py`
**Migration:** `app/database/upgrade.py` (additive)

M2's `reports` table recorded *when* a report was generated. M17 adds five columns
to describe a *generated* report:

| Column | Type | Nullable | Why |
| --- | --- | --- | --- |
| `period_start` | DateTime | yes | the inclusive bound of the covered period |
| `period_end` | DateTime | yes | the exclusive bound of the covered period |
| `status` | String(20) | no, default `completed` | the generation state |
| `file_size` | Integer | yes | the artifact's size, once written |
| `error` | Text | yes | a safe sentence explaining a failure |

Both period columns are nullable because a row written before M17 genuinely has no
recorded period, and a fabricated one would be a lie. `status` is `NOT NULL` with a
*server* default because SQLite requires a default to add a `NOT NULL` column to an
existing table at all — and with the default in place every pre-M17 row is
correctly described as `completed`, which is what it was: those rows were written
by hand and always described a file that existed. `file_size` is nullable because
it is unknown for a pre-M17 row, and unknown is not zero.

The migration is additive: no column is dropped, renamed or retyped, and no row is
rewritten.

### 12.6 The row limit

`_row_limit()` returns the configured ceiling, but never above the analytics layer's
own group cap:

```text
row_limit = max(1, min(settings.report_max_table_rows, REPORT_ROW_LIMIT))
```

`REPORT_ROW_LIMIT` is `app.analytics.metrics.MAX_GROUPS` (100), reused rather than
re-declared, so a report cannot show more groups than the service it reads is
willing to produce. Lowering the setting lowers the report; raising it past the
analytics ceiling changes nothing, which is the honest behaviour.

---

## 13. API contracts

All three JSON routes follow the M13 envelope:

```json
{
  "success": true,
  "message": "Report generated",
  "data": { "...": "..." }
}
```

The download route is the one exception: a file is not a JSON payload, so it is
served as an attachment with its own media type (§13.4).

### 13.1 `GET /api/v1/reports`

| Parameter | Type | Default | Notes |
| --- | --- | --- | --- |
| `report_type` | string | none | keep only this stored type |
| `format` | string | none | keep only this stored format, case-folded |
| `limit` | int | 100 | M13 pagination |
| `offset` | int | 0 | M13 pagination |

Ordering is `generated_at DESC, id DESC` — the natural order with the primary key as
a tie-break, so the order is total and two identical requests return the same page.
`total` comes from a count over the same filters, so a page and its total cannot
disagree.

`data` is `ReportListData`: `count`, `total`, `limit`, `offset`, `has_more`, and
`reports` — a list of `ReportView` (§13.5).

### 13.2 `GET /api/v1/reports/{id}`

Returns one `ReportView`, or `404` with `REPORT_NOT_FOUND`.

### 13.3 `POST /api/v1/reports/generate`

**Body:** `ReportGenerationRequest`. Every field is optional, and the defaults are
the layer's own: an empty body produces the **previous completed UTC day as a PDF**.

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `report_type` | string | `daily` | `daily`, `weekly` or `custom` |
| `format` | string | `PDF` | `CSV` or `PDF`, case-folded |
| `title` | string | derived from the period | blank is treated as absent |
| `generated_by` | int | `null` | an optional user id |
| `since` | string | `null` | ISO-8601 UTC, inclusive; required by `custom`, refused for a preset |
| `until` | string | `null` | ISO-8601 UTC, exclusive; required by `custom`, refused for a preset |

The fields are declared as plain strings rather than as an enum so the *service* owns
the vocabulary and answers with the documented `400` naming the offending field,
exactly as it does for a bad timestamp. An enum here would answer `422` for a bad
format and `400` for a bad date — two shapes for one kind of mistake.

**Response:** `201 Created`, `data` is `GeneratedReportData`:

```json
{
  "report": { "...": "a ReportView, downloadable: true" },
  "summary": [
    { "label": "Report title", "value": "Daily network report 2026-10-10 (CSV)" },
    { "label": "Packets stored in period", "value": "1,429" },
    { "label": "Alerts recorded in period", "value": "3" }
  ]
}
```

The summary is the same block the artifact opens with, from the same assembly, so
the summary a client shows here and the summary printed inside the PDF cannot
disagree.

### 13.4 `GET /api/v1/reports/{id}/download`

Serves the artifact as a `FileResponse`:

| Aspect | Value |
| --- | --- |
| `Content-Type` | `text/csv; charset=utf-8` for CSV, `application/pdf` for PDF, `application/octet-stream` for an unrecognised stored format |
| `Content-Disposition` | the artifact's own name — already reduced to `[A-Za-z0-9-]` by the storage layer, so it cannot inject a header |
| success | `200` with the bytes |
| unknown id | `404 REPORT_NOT_FOUND` |
| artifact not available | `404 REPORT_NOT_FOUND` with one fixed sentence |

The status codes still follow the API's conventions, and the message on failure is
the same regardless of *why* the file is unavailable. The client never learns the
directory the artifact lives in, which M13.30 forbids exposing.

### 13.5 `ReportView`

| Field | Type | Notes |
| --- | --- | --- |
| `report_id` | int | |
| `name` | string | |
| `report_type` | string | `daily`, `weekly` or `custom` |
| `format` | string | `CSV` or `PDF` |
| `generated_by` | int \| null | |
| `generated_at` | string \| null | ISO-8601 UTC |
| `generated_at_epoch` | float \| null | the same instant in epoch seconds (M13.26) |
| `period_start` | string \| null | inclusive bound, ISO-8601 UTC |
| `period_end` | string \| null | exclusive bound, ISO-8601 UTC |
| `period_start_epoch` | float \| null | |
| `period_end_epoch` | float \| null | |
| `status` | string | `generating`, `completed` or `failed` |
| `file_size` | int \| null | artifact size in bytes, once written |
| `error` | string \| null | a safe sentence explaining a failure |
| `downloadable` | bool | whether a download would actually succeed |

**`file_path` is absent from every model.** It is an internal filesystem location,
and M13.30 forbids exposing one. The choice is structural rather than a filter
applied at the last moment, so no code path can forget it.

Fields a pre-M17 row genuinely cannot answer are `null` rather than a plausible
default: an unknown period is not the epoch, and an unknown size is not zero.

### 13.6 Why the M15 TypeScript models still work

- Every M13 field keeps its name, its type and its source.
- The M17 additions (`status`, `file_size`, `period_*`, `downloadable`, `error`) are
  new keys on the existing view, typed in `frontend/src/types/system.ts`.
- The generation request and response types are new exports
  (`frontend/src/services/reports.ts`), so an M15 build that predates them continues
  to type-check and render.
- No `any` is used for any backend-derived value.

---
## 14. Validation and error handling

**Modules:** `app/reports/errors.py`, `app/reports/requests.py`,
`app/api/v1/reports.py`

### 14.1 Three failure kinds, three HTTP answers

| Failure | Raised by | HTTP | Error code |
| --- | --- | --- | --- |
| `ReportRequestError` | request validation, period resolution | `400` | `INVALID_REQUEST`, with the offending `field` |
| `ReportGenerationError` | assembly, rendering, the artifact write | `500` | `INTERNAL_ERROR` |
| `ReportArtifactMissing` | a download whose file is absent or outside the directory | `404` | `REPORT_NOT_FOUND` |

`_as_api_error` maps a reporting failure onto the API's controlled error, taking the
failure's **own sentence** — which the reporting layer already guarantees is free of
internals — and deciding only the status and the machine-readable code, because
those are the HTTP layer's vocabulary.

### 14.2 The refusal cases, each covered by a test

| Request | Result |
| --- | --- |
| `report_type` not `daily` / `weekly` / `custom` | `400` naming `report_type` |
| blank `report_type` | `400` naming `report_type` |
| `format` not `CSV` / `PDF` | `400` naming `format` |
| blank `format` | `400` naming `format` |
| `custom` without `since` or without `until` | `400` naming the period |
| `custom` with `since` **after** `until` | `400` naming the period |
| `custom` with `since` **equal to** `until` | `400` naming the period |
| `custom` longer than 30 days | `400` naming the period |
| a preset (`daily` / `weekly`) carrying `since` or `until` | `400` naming the period |
| malformed `since` / `until` | `400` naming that field |
| `generated_by` that is not an integer | `422` (FastAPI validation) |

The `400`-versus-`422` split is deliberate and matches M16's: a value that is
*well-formed but unanswerable* comes back in the project's own envelope with a
queryable code, while a value that never reaches a handler at all is FastAPI's own
`422`. `"format": "DOCX"` is a `400` — the request is comprehensible and the answer
is no — while `"generated_by": "abc"` is a `422`, because the body does not match
its declared shape.

### 14.3 Error bodies expose nothing internal

An error body names the field and the rule, and nothing else: no table name, no
column, no SQL, no stack trace, no filesystem path, no exception text. This is
M13.30's rule and M17's routes honour it in every path, including:

- a storage directory that cannot be written — `"The report storage directory could
  not be created"`, with the path logged and never returned;
- an artifact outside the storage directory — the same `"The report file is not
  available for download"` a missing file produces, so the two are indistinguishable
  to a client;
- a renderer that raised — the fixed sentence `"The report could not be generated"`,
  with the real exception logged beside the report's id.

### 14.4 Empty versus unavailable versus unknown

The distinction M16.8 established is inherited unchanged, because a report's
sections are M16's blocks:

| Answer | Meaning | In a report |
| --- | --- | --- |
| `0` | the value is known and is zero | the rendered number |
| empty | a valid query, and the store holds no matching record | an available section with an empty table and the `NO_ROWS_NOTICE` sentence |
| unknown | the value was never reported | the `NOT_REPORTED` text — never `0` |
| unavailable | the block could not be read at all | `available=False` with the `UNAVAILABLE_NOTICE` sentence, and **no** metrics or tables |

Nothing converts unavailable or unknown into `0`:

- An unreadable block becomes an unavailable section. It never becomes a table of
  zeroes, which a reader would take for a measurement.
- A statistic with no observation — a mean duration over conversations that have not
  ended, a mean confidence over no findings, an average packet size over no packets
  — is `not reported`, because `0` would be a claim rather than an absence.
- A timestamp that was never observed is `not reported`, not epoch 1970.
- A percentage of a zero total is `n/a`, not `0.00%`: a share of nothing is
  undefined, and printing zero would claim the value was measured and found to be
  nothing.

A report whose period holds nothing at all is a *valid* report: every section is
available with zeroes and empty tables, each table carries its notice, and the
document states once that the period holds no stored data. That is a different
answer from a report whose database could not be read, and the two are never
conflated.

### 14.5 A generation that fails leaves a truthful row

A generation that cannot finish is a `500`, and before the error is raised the row
is marked `failed` with a safe sentence and any partial artifact is deleted. The
store therefore never claims a file that is not there, and the listing shows the
failure rather than hiding it.

---

## 15. Performance considerations

### 15.1 Where the work happens

A generation does no aggregation of its own. Every figure comes from the M16
analytics service, which aggregates in SQLite (§15 of the M16 document). M17's own
work is:

| Step | What it costs |
| --- | --- |
| period resolution | arithmetic on the bounds — no query |
| assembly | the five M16 analytics calls plus building the content model |
| CSV rendering | encoding the model — linear in the rows it carries |
| PDF rendering | reportlab's layout work — the dominant cost |
| the artifact write | one file write with an `fsync` and an atomic replace |
| the metadata row | one insert, one update, plus two more updates for the outcome |

### 15.2 What the design avoids

| Anti-pattern | How M17 avoids it |
| --- | --- |
| a second aggregation engine | every figure comes from `AnalyticsService`; the assembler queries nothing |
| unbounded tables | a report's rankings are capped at `min(settings.report_max_table_rows, MAX_GROUPS)`, and its time series are capped by M16's own bucket rules |
| unbounded periods | a period is always bounded and never longer than 30 days |
| loading the packet table | nothing is loaded: the M16 blocks are already aggregated |
| N+1 queries | one analytics call per section, and the sections are independent |
| re-rendering to measure | the artifact is rendered once per generation |
| rewriting a whole report on a listing | the listing reads metadata only |

### 15.3 Indexes

**No index was added by M17.** The one question M17 asks of a table of its own —
"list stored reports, newest first" — orders by `generated_at`, which M2 already
indexed. Every other read is an M16 read on a column M7, M9 or M11 already indexed.

### 15.4 Measured baseline

Produced by `backend/scripts/benchmark_m17.py`. The store is seeded with 10 000
packets, 100 conversations and 20 alerts spanning 168 hours; the configured row
limit is the shipped default of 100; each measurement is 10 timed calls after 2
discarded warm-ups. Times are milliseconds.

Environment, as the script reports it:

```text
machine   : Windows-11-10.0.26300-SP0
python    : 3.13.2
sqlite    : 3.45.3
store     : throwaway SQLite file in a temporary directory
artifacts : throwaway directory in the same temporary directory
client    : in-process (TestClient), so no loopback network stack
seeded    : 10 000 packets, 100 conversations, 20 alerts, spanning 168.00 h
```

**1. Generation, end to end, over the whole seeded store:**

| Measurement | p50 | mean | p95 | max | what it produced |
| --- | ---: | ---: | ---: | ---: | --- |
| `POST /reports/generate` (CSV) | 104.43 | 104.72 | 117.54 | 117.54 | `custom` CSV, 28.72 KiB, 10 000 packets, 20 alerts |
| `POST /reports/generate` (PDF) | 657.25 | 643.11 | 732.19 | 732.19 | `custom` PDF, 112.06 KiB, 10 000 packets, 20 alerts |

Both routes answered `201`. The CSV figure is the one a user waits for when they
want data; the PDF figure is the one they wait for when they want a document.

**2. Where one generation's time goes (same content, no HTTP):**

| Step | p50 | mean | p95 | max | what it covered |
| --- | ---: | ---: | ---: | ---: | --- |
| assemble (analytics queries → content model) | 74.58 | 73.05 | 87.04 | 87.04 | 5/5 sections, 17 summary metrics, 30 tables, 874 rows |
| render (content model → bytes), CSV | 0.69 | 0.73 | 1.11 | 1.11 | 28.71 KiB out |
| write artifact (temp file + `fsync` + replace) | 2.98 | 2.97 | 3.39 | 3.39 | 28.71 KiB written |

The three sum to **78.25 ms** against the 104.43 ms end-to-end CSV figure; the
difference is the HTTP layer, the metadata row (4.86 ms, below) and response
serialization. Assembly is the whole cost of a CSV generation, and the CSV encoder
itself is free by comparison.

**3. Configured row limit (same store, same period, same format):**

| Row limit | p50 | mean | p95 | artifact |
| ---: | ---: | ---: | ---: | ---: |
| 5 | 95.48 | 94.78 | 102.57 | 23.02 KiB |
| 100 (default) | 109.47 | 108.85 | 114.97 | 28.71 KiB |
| 100 000 | 113.12 | 114.12 | 130.04 | 28.72 KiB |

The column is flat, and the last row is the point: a ceiling far above the analytics
layer's own group cap produces the *same* report as the cap, because
`_row_limit()` clamps it. A report's cost is bounded by the configured cap and by
M16's group cap, **not** by how much the store holds.

**4. Period length (same store, different windows):**

| Window | p50 | mean | packets selected | artifact |
| --- | ---: | ---: | ---: | ---: |
| `daily` preset, 2026-10-10 | 58.52 | 57.97 | 1 429 | 19.56 KiB |
| `weekly` preset, 2026-09-28 → 2026-10-04 | 53.23 | 54.77 | 1 005 | 25.10 KiB |
| `custom`, the 30-day ceiling | 112.44 | 109.39 | 10 000 | 23.52 KiB |

The window is what decides how many rows SQLite scans, so the cost moves with it —
but only weakly, because the seed's whole 168 hours fits inside 30 days and a report
is assembled from aggregates rather than from rows. The `packets selected` column is
the check that each window really selected what it says: the daily and weekly
presets cover a *calendar* day and week, which is why their counts are smaller than
the whole-store figure.

**5. Storage and metadata writes:**

| Measurement | p50 | mean | p95 | max | what it covered |
| --- | ---: | ---: | ---: | ---: | --- |
| write one 64.00 KiB artifact | 3.25 | 3.25 | 3.57 | 3.57 | temp file + `fsync` + atomic replace |
| insert one report metadata row | 4.86 | 4.98 | 6.16 | 6.16 | one row, one commit |

A 64 KiB artifact costs about the same as the ~29 KiB one a real report produces,
because the write is dominated by the `fsync`, not by the bytes. The metadata row
costs more than the file for the same reason a report is cheap: it is one commit
against a file that already exists.

### 15.5 What these numbers are and are not

They are **local development measurements**: one machine, one process, one SQLite
file, an in-process client, an otherwise idle machine. They exist so that a change to
the reporting layer can be compared against a recorded baseline, and so the two
formats, the three row limits and the three period lengths can be compared against
each other.

They are **not** a capacity claim. No load generator, no concurrency, no production
hardware and no production data size is involved. Nothing here supports a statement
about how many reports a second a deployment would sustain.

Two specific caveats:

- **The in-memory blocks are empty in the benchmark.** The device, incident and
  detection-counter blocks read the M8, M10 and M12 services, which hold nothing in
  a freshly started process — the honest state of a backend that has captured
  nothing. The figures therefore describe the route's fixed cost plus its database
  work, and the stored blocks (which are the bulk of a report) are measured over the
  seeded store.
- **The benchmark excludes capture entirely.** M5 normalization, M6 statistics, M7
  persistence, M8 discovery, M9 tracking, M10 detection, M11 alerting and M12
  correlation each have their own milestone baseline. M17.13 is about what the
  *reporting* layer adds on top of data that already exists, which is what this
  script measures.

---
## 16. Testing and verification

### 16.1 Reporting tests

**257 tests** across eight files plus one shared fake module:

| File | Tests | Covers |
| --- | ---: | --- |
| `tests/test_reports_period.py` | 27 | presets, the UTC calendar, half-open bounds, the ceiling, labels, refusals |
| `tests/test_reports_request.py` | 36 | format and type canonicalisation, timestamp parsing, the custom-versus-preset rule |
| `tests/test_reports_content.py` | 21 | the content model: metrics, tables, sections, availability, emptiness |
| `tests/test_reports_csv_renderer.py` | 29 | block markers, headers, quoting, notices, an empty report |
| `tests/test_reports_pdf_renderer.py` | 24 | a valid PDF, page structure, notices, an empty report, long values |
| `tests/test_reports_assembler.py` | 41 | the five sections, headline metrics, availability inheritance, the window conversion |
| `tests/test_reports_storage.py` | 27 | the naming rule, atomic writes, containment, deletion, failure sentences |
| `tests/test_reports_service.py` | 20 | the generation lifecycle, the row states, failure cleanup, downloadability |
| `tests/test_reports_api.py` | 32 | the four routes: defaults, validation, limits, schemas, errors, downloads |
| `tests/reports_fakes.py` | — | the shared fakes the reporting tests build on |

69 further tests in `tests/test_api_contract.py` cover the report routes' place in
the project-wide contract (envelope shape, error codes, versioned base).

Each area named in the milestone's test plan is present:

| Area | Tests |
| --- | --- |
| Periods — daily, weekly, custom, half-open bounds, the ceiling, labels, presets given bounds | yes |
| Requests — type, format, title, bounds, refusal, defaults | yes |
| Content — sections, metrics, tables, availability, empty versus unavailable | yes |
| CSV — blocks, headers, quoting, empty report, notice text | yes |
| PDF — valid bytes, pages, tables, empty report, wrapping | yes |
| Assembly — the five sections, headline metrics, analytics agreement, window conversion | yes |
| Storage — naming, atomicity, containment, deletion, failures | yes |
| Service — the lifecycle, the three states, failure cleanup, downloadability | yes |
| API — defaults, validation, maximum limits, schemas, empty results, error handling | yes |
| Contract — envelope, error codes, no internals leaked | yes |

### 16.2 Full regression

```text
2322 passed, 1 warning in 34.14s
```

The single warning is `StarletteDeprecationWarning: Using httpx with
starlette.testclient is deprecated`, raised from the installed FastAPI package —
not from project code.

All existing M0–M16 tests pass. M17 changed no M0–M16 behaviour; it added alongside
it, and the only edits to pre-existing modules were additive (the five `reports`
columns, the two settings, the migration, and the `ReportView` additions).

### 16.3 Type checking

```text
0 errors, 0 warnings, 0 informations
```

Pyright over the whole backend, including the `app/reports` package and both M17
scripts.

### 16.4 End-to-end verification, part 1 — sample mode

`backend/scripts/verify_m17.py sample` builds the **real** stack — M6 statistics,
M7 persistence, M8 discovery, M9 tracking, M10 detection, M11 alerting, M12
correlation, M16 analytics — over an isolated throwaway SQLite database, drives
controlled packets through it, then serves the real FastAPI application with its
dependencies overridden onto that same stack and a throwaway artifact directory.

The one substitution is the sniffer, which is dispensed with entirely: packets are
handed to the pipeline at the same seam the capture callback uses. Everything
downstream runs for real. **No mock data, no fixtures, no hand-built payloads.**

Result:

```text
Sample mode complete - all checks passed.
```

What it established, with the figures the run printed:

**The read surface, unchanged by M17:**

| Check | Result |
| --- | --- |
| `GET /api/v1/reports` | `200`, `count=0 total=0 limit=100` |
| `GET /api/v1/reports/424242` | `404` |
| `GET /api/v1/reports/not-a-number` | `422` |
| `GET /api/v1/reports/424242/download` | `404` |
| `POST` / `PUT` / `DELETE` on the collection | `405` |

**Generation, over the driven packets:**

| Check | Result |
| --- | --- |
| `POST /reports/generate` with no body | `201`, `daily`/`PDF`, `status=completed`, `size=88875` |
| its period | `2026-10-10T00:00:00+00:00 .. 2026-10-11T00:00:00+00:00` |
| its title | `Daily network report 2026-10-10 (PDF)` |

**The half-open boundary, checked directly:**

| Check | Bound |
| --- | --- |
| the `daily` preset | `2026-10-09T00:00:00+00:00 .. 2026-10-10T00:00:00+00:00` |
| the next day | `2026-10-10T00:00:00+00:00 .. 2026-10-11T00:00:00+00:00` |
| the `weekly` preset | `2026-09-28T00:00:00+00:00 .. 2026-10-05T00:00:00+00:00` |

The two daily periods meet at `2026-10-10T00:00:00` and do **not** overlap it: the
instant belongs to exactly one of them. A `weekly` preset carrying bounds is
refused with `400 ['period']`.

**The artifact on disk:**

| Check | Result |
| --- | --- |
| files in the directory | `1` |
| expected name | `netwatch-report-000001-2026-10-10.pdf` |
| found | the same name, exactly |
| size | `row=88875 file=88875` — the row and the file agree |

**The download:**

| Check | Result |
| --- | --- |
| status | `200` |
| content-type | `application/pdf` |
| filename | `netwatch-report-000001-2026-10-10.pdf` |
| bytes | `88875` |

**The report agrees with the analytics layer — the check the whole design exists
for.** A report and the analytics endpoints were asked about the same instants, and
every figure matched:

| Figure | Report | Analytics |
| --- | ---: | ---: |
| Packets stored in period | 14 | 14 |
| Bytes stored in period | 696 | 696 |
| Distinct protocols in period | 2 | 2 |
| Alerts recorded in period | 2 | 2 |

with `analytics traffic` reporting `packets=14 bytes=696 protocols=2` and
`analytics threats` reporting `stored alerts=2`. The protocol table inside the
report carried `2 group(s), 14 packet(s)` — the stored half, not the live one.
There is no path by which a report can disagree with the dashboard about the same
window, because there is one aggregation.

**The listing:**

| Check | Result |
| --- | --- |
| `listing` | `count=2 total=2 has_more=False` |
| `filter format=pdf` | `count=1` |
| `filter report_type` | `count=1` |
| `filter format=xlsx` | `count=0` |
| `paging limit=1` | `page1=2 page2=1` |
| `single read` | `id=1 name='Daily network report 2026-10-10 (PDF)'` |

**Every documented refusal, each with the field it names:**

| Request | Result |
| --- | --- |
| unsupported format | `400 ['format']` |
| blank format | `400 ['format']` |
| unsupported type | `400 ['report_type']` |
| blank type | `400 ['report_type']` |
| preset given bounds | `400 ['period']` |
| custom without bounds | `400 ['period']` |
| custom missing `until` | `400 ['period']` |
| custom inverted | `400 ['period']` |
| custom empty | `400 ['period']` |
| custom longer than the ceiling | `400 ['period']` |
| malformed `since` | `400 ['since']` |
| malformed `until` | `400 ['until']` |

and, crucially, `rows after refusals 2 -> 2`: **a refused request writes nothing.**
The parameter-level refusals come back as FastAPI's own `422` (`limit=0`,
`limit=1001`, `offset=-1`).

**Nothing internal leaks:** `surfaces checked 3, leaks=0`.

**The row limit is really applied:** with `limit=1`, `top_sources` carried
`1 row(s)`; restoring the setting restored the row count.

**A failure is recorded truthfully.** A generation whose storage directory could
not be created produced:

| Check | Result |
| --- | --- |
| status | `500` |
| message | `'The report storage directory could not be created'` |
| rows | `4 -> 5, failed=1` |
| the failed row | `size=None error='The report storage directory could not be created'` |
| a download of it | `404` |

The message names the situation, not the path — the path and the real `OSError`
went to the log. And the store gained a row that truthfully says the report failed.

**A file that vanishes is reported as unavailable, not as present.** After removing
the artifacts, a row whose status is still `completed` reports
`downloadable=False` and its download is `404 ['REPORT_NOT_FOUND']` — the status and
the filesystem are allowed to disagree, and the API reports the error the download
would actually hit.

### 16.5 End-to-end verification, part 2 — live mode

`backend/scripts/verify_m17.py live --port 8017` starts the **real application under
uvicorn** on a loopback port, over a throwaway database and artifact directory, and
drives it over real HTTP — a genuine socket, a genuine server process.

Result:

```text
Live mode complete - all checks passed.
```

| Check | Result |
| --- | --- |
| `GET /api/v1/reports` | `200`, `count=0 total=0` |
| `GET /api/v1/reports/424242` | `404` |
| `POST /api/v1/reports/generate` | `201` |
| `GET /api/v1/reports/1/download` | `200`, `content-type=text/csv; charset=utf-8`, `bytes=15221` |
| `POST generate (DOCX)` | `400` |

The generated artifact was `netwatch-report-000001-2026-10-10.csv` (15 221 bytes),
its name and size agreeing with the stored row, and the download served it as
`text/csv` with the artifact's own name.

Sample mode and live mode together cover both ends: sample mode over the real
in-process stack (which is how the pipeline is actually driven), live mode over the
real HTTP transport (which is how a browser actually reaches it).

### 16.6 Frontend verification

| Check | Result |
| --- | --- |
| typecheck | clean (`tsc --noEmit`) |
| unit tests | **448 passed**, 15 files |
| Reports page tests | 36 of the 448; the page, the generation form, the outcome panel, the row and the detail panel each have their own |
| live integration tests | **67 passed**, 3 files, against the real FastAPI app on `127.0.0.1:8000` — 53 REST, 6 WebSocket, 8 page tests. `tests/live/rest.test.ts` gained 6 report tests, including one that generates a report for real and checks the figures it opens with |
| production build | clean — `vite build`, 2 554 modules, `907.84 kB` JS (`241.03 kB` gzip) and `24.71 kB` CSS (`5.52 kB` gzip), built in 3.62 s |

The frontend types every report field from `frontend/src/types/system.ts`; no `any`
is used for a backend-derived value.

### 16.7 Contract verification

The M13-era fields were read back from the running API and compared with what M15
had typed, rather than assumed identical. Three additions were required, each
additive and each recorded in the TypeScript types:

| Addition | Why it was needed |
| --- | --- |
| `status` on `ReportView` | a client cannot otherwise tell a completed report from a failed one |
| `file_size` and the `period_*` pair | a client cannot otherwise show what a report covers or how big it is |
| `downloadable` | a client must not infer downloadability from a status it may not understand |

No existing field changed name or type, so the M15 build continued to compile
unchanged.

---
## 17. Known limitations

Each of these is a real limit of the current implementation, stated rather than
worked around. None is a bug; several are deliberate, and the ones inherited from
another milestone are inherited unchanged.

### 17.1 A report is a snapshot, and the data underneath it keeps moving

An artifact is rendered once, at generation time, from whatever the stores held
at that instant. Nothing re-renders it and nothing marks it stale.

Consequence: a report downloaded an hour after it was generated describes the
period, not the store as it is now. Some of its figures will have moved since —
a device's `last_seen` can advance, an alert's lifecycle status can change, and a
packet that arrived later inside the same period cannot appear at all. The
`generated_at` field on the row is the only statement of *when* the report was
true, which is why it is rendered onto every artifact and is not optional.

This is the intended design: a report is a document, and a document that silently
changes after it was produced would be worse than one that is visibly dated.

### 17.2 Every figure is M16's, so every M16 limitation is inherited

M17 does no aggregation of its own (§6.2). It calls the M16 analytics service and
renders what comes back, which means the limitations recorded in §17 of
`docs/20_M16_Analytics_Design.md` apply to report content unchanged, and a report
does not remove any of them:

| Inherited limit | What it means inside a report |
| --- | --- |
| the M8 registry is a snapshot, not a history (M16 §17.1) | a device table is *the devices the registry currently remembers*, and its `first_seen` / `last_seen` are the registry's own bounds |
| routed traffic can make a device id a next hop (M16 §17.2) | a device row's addresses are *the addresses seen under that id*, not a claim about one host |
| findings live in a bounded in-memory history (M16 §17.4) | a finding older than M10's retention is absent from the report, even when it falls inside the period |
| a stored bucket with zero packets means the *store* held none (M16 §17.5) | a zero in a traffic table is not evidence that the network was idle |
| percentages are floating-point (M16 §17.7) | a protocol share is correct to double precision, not exact |
| the baseline is a local measurement (M16 §17.9) | §15.4 here is the same kind of measurement |

None of these is *worked around* in the renderer. A renderer that quietly corrected
its inputs would be a second analytics implementation wearing a document's
clothes, which is precisely what §6.2 forbids.

### 17.3 Generation is synchronous: the request waits for the file

`POST /reports/generate` assembles, renders and writes before it answers. There is
no job queue, no worker and no `202 Accepted` path — the response that creates a
row already says `completed` or `failed`.

Consequence: a PDF generation holds the request for as long as reportlab takes —
`657 ms` for the benchmark's content (§15.4) — and the caller's connection stays
open for that time. On the local architecture this is acceptable; it would not be
for a report spanning an unbounded amount of data, which is one reason a period
has a ceiling at all (§17.7).

A background generation is not a hard change — the row's `status` column already
models `pending`, `completed` and `failed`, so a future milestone could accept a
request, answer `201` with a `pending` row, and let a worker finish it. Nothing in
the store would have to change. That milestone is not this one.

### 17.4 No artifact retention policy

Nothing prunes the storage directory. `ReportStorage.delete()` exists and is used
in exactly one place — to remove a partial artifact when a generation fails
(§12.3) — and no scheduler calls into the reports layer at all.

Consequence: `settings.report_storage_dir` grows without bound as reports are
generated, and the listing endpoint is the only view of what is there. Packet rows
have a retention setting (`packet_retention_days`, M7.13); report artifacts do
not, because "how long a produced document should be kept" is a policy question
this milestone was not asked, and deleting a file a user still has a database row
for would be worse than keeping it.

An operator can delete files; the store copes honestly when they do (§17.6).

### 17.5 A report is a bounded summary, not an export

Every table a report carries is capped at
`min(settings.report_max_table_rows, REPORT_ROW_LIMIT)`, clamped to at least one
(§12.6), and every time series is capped by M16's own bucket ceiling. There is no
request that produces a report with one row per packet, and no offset or paging
parameter on the generate route.

That is deliberate: M17 renders *summaries* (§3), and the pipeline's own data
export is M13's `GET /api/v1/packets` with its own filters and paging. A report is
what you send to someone who was not watching; the packets API is what you query
when you need the rows.

The row limit is also a **ceiling on cost**: §15.4's third table shows a configured
limit of `100 000` producing the same artifact as a limit of `100`, because
`_row_limit()` clamps to `REPORT_ROW_LIMIT`. Raising the configuration cannot make
a report unbounded.

### 17.6 The metadata row and the artifact can diverge

The row and the file are two stores, and they are written in that order: the row
is inserted, the artifact is written, then the row is updated with the size and
the outcome (§12.2). If a file is removed afterwards — by hand, by a backup
restore, by a container being rebuilt with a fresh volume — the row still claims
`completed`.

The read path does not paper over this: `downloadable` is asked of the storage
directory per row (§12.4), so such a report lists with `downloadable: false`, and
its download answers `404` in the same way a missing file does. The store tells
the truth about what it can serve; it does not, however, repair itself, and it
does not retry or regenerate.

### 17.7 A period has a ceiling, so no report covers all of history

`MAX_REPORT_PERIOD_SECONDS` is M16's own `MAX_WINDOW_SECONDS`, imported rather
than chosen (§7.6). A custom period longer than it is refused with `400`, and the
presets are shorter than it by construction. There is no `all` preset and no
unbounded option.

Consequence: a question like "how has this network changed since installation"
cannot be asked of this endpoint in one request. It would have to be asked as a
sequence of windows, each its own report. The ceiling exists because a bounded
window is what keeps a synchronous generation answerable at all (§17.3) and
because both layers then share one definition of the longest span either will
aggregate.

### 17.8 Everything is UTC

Periods are UTC calendar days and weeks (§7.3), bounds are parsed as UTC (§10 of
M16), and every timestamp rendered into a report is UTC. There is no timezone
parameter, no local-time rendering, and no per-report display timezone.

Consequence: a `daily` report is *the previous completed UTC day*, which for a
reader east or west of UTC is not their local day — at UTC+5:30 the "daily" report
covers 05:30 to 05:30 local. The document says so on its own first page (§10.1),
and the period's bounds are printed as explicit instants so a reader is never left
to infer which day was meant. Local-time presentation is a frontend or later
milestone concern; the backend's answers are unambiguous as they stand.

### 17.9 PDF rendering is the dominant cost, and it is reportlab's

§15.4's second table is unambiguous: assembly (74.58 ms) plus the write (2.98 ms)
against a PDF end-to-end figure of 657.25 ms. Almost all of a PDF generation is
`reportlab` laying the document out, and M17 does not attempt to make it faster —
no caching of laid-out fragments, no incremental rendering, no streaming response.

The CSV figure (104.43 ms end to end, 0.69 ms of which is the encoder) is what
makes the two formats worth offering at all: a caller who wants data quickly asks
for CSV, and a caller who wants a document accepts the cost. This is why the
default format is decided by "who reads it" (§6.2) rather than by what is fastest.

### 17.10 A failed report is recorded, not retried

A generation that raises marks its row `failed`, stores one safe sentence, deletes
any partial artifact and answers `500` (§12.3, §14.5). It does not retry, and it
does not leave the row `pending`.

Consequence: a failure is permanent until a caller asks again — the store contains
the evidence that it happened and nothing acts on it. There is no automatic
re-generation and no queue to re-drive, consistently with §17.3.

### 17.11 No authentication, no tenancy

M17 adds no access control. The four report routes are as open as the rest of the
M13 API, every request reads the same store, and an artifact's **URL is its only
credential**: anyone who can reach the download route with an id can retrieve the
file, whatever it contains.

Downloads are confined to the storage directory (§11.4) so that an id cannot be
turned into a path traversal, but confinement is not authorization. `generated_by`
records who *asked* for a report where the caller supplied it; it grants nothing
and is not checked by anything. Authentication and RBAC are explicitly later
milestones (§3).

### 17.12 The baseline is a local development measurement

§15.4's figures are from one machine, one process, one SQLite file and an
in-process client. They support comparing reporting changes against a recorded
baseline; they do not support any statement about production capacity, and the
benchmark's in-memory analytics blocks are empty by design (§15.5). See §15.5 and
M16 §15.5.

---
## 18. Completion checklist

| Criterion | Status | Evidence |
| --- | :-: | --- |
| Reporting architecture is implemented | ✅ | §6; `period.py`, `requests.py`, `content.py`, `assembler.py`, `renderers.py`, the two renderers, `storage.py`, `service.py` |
| CSV generation works | ✅ | §9; 29 renderer tests, and sample mode read the artifact back |
| PDF generation works | ✅ | §10; 24 renderer tests, and sample mode checked an 88 875-byte PDF |
| Daily reports work | ✅ | §7.3; the previous completed UTC day, verified at the day boundary |
| Weekly reports work | ✅ | §7.3; the ISO-8601 week, labelled on its last covered day |
| Custom reports work | ✅ | §7.4; both bounds required, inverted and empty refused, ceiling inherited from M16 |
| Report history works | ✅ | §13.1; `generated_at DESC, id DESC`, filtered and paged, with a matching `total` |
| Report download works | ✅ | §13.4; bytes served with the right media type, `404` for an unknown id or an absent file, confined to the storage directory |
| Report metadata is truthful | ✅ | §12; row before file, `failed` rows carry a sentence and no file, `downloadable` asked of the store |
| Period filtering is correct and half-open | ✅ | §7.2; the boundary instant belongs to exactly one of two adjacent reports |
| Aggregation is bounded | ✅ | §12.6; `max(1, min(settings.report_max_table_rows, REPORT_ROW_LIMIT))`, and M16's bucket ceiling behind it |
| API validation works | ✅ | §14.2; 10 refusals at `400` naming the field, plus FastAPI's `422` for a malformed body |
| Empty/unavailable states are handled correctly | ✅ | §14.4; empty is an available section with a notice, unavailable carries no tables, unknown is never `0` |
| Existing M13 API conventions are preserved | ✅ | §13; the M13 envelope, ISO-8601 UTC, additive pagination, no internals exposed |
| M15 frontend remains compatible | ✅ | §16.7; additive fields, `tsc --noEmit` clean, 448 unit tests, production build |
| Errors expose nothing internal | ✅ | §14.3; three fixed sentences, no path, no SQL, no traceback |
| Reporting tests pass | ✅ | §16.1; 257 reporting tests |
| Full regression suite passes | ✅ | §16.2; `2322 passed` |
| Pyright/type checking passes | ✅ | §16.3; `0 errors, 0 warnings, 0 informations` |
| Performance baseline is recorded | ✅ | §15.4; `benchmark_m17.py` |
| Verification with real data succeeds | ✅ | §16.4 and §16.5; both verifier modes pass, live mode over real HTTP |
| `docs/21_M17_Reports_Design.md` is complete | ✅ | this document |

---

## 19. M17 closure

**Status: implemented and verified.**

M17 turned the `reports` table from a hand-written list into a subsystem that
produces documents — without changing a single M13 field the M15 frontend depends
on, and without introducing a second statistics engine, a second device identity,
a second risk score, a new metric or any detection logic.

What exists now:

- **One period model** (`app/reports/period.py`) that every generation uses, with
  half-open UTC bounds, the previous-completed-day and previous-completed-week
  presets, and a ceiling imported from M16 rather than re-declared.
- **One request layer** (`app/reports/requests.py`) that canonicalises type,
  format, title and bounds, and refuses — in a sentence naming the field — every
  combination it cannot honour.
- **One renderer-agnostic content model** (`app/reports/content.py`) that both
  renderers walk, so the CSV and the PDF cannot disagree about what a report says.
- **Two renderers** behind one lookup table: a block-structured CSV encoder and a
  paginated PDF built with `reportlab`, which M17 declared in
  `backend/requirements.txt`.
- **One storage layer** (`app/reports/storage.py`) with a single configurable
  directory, a collision-safe naming rule keyed on the report id, atomic writes
  with `fsync` and `os.replace`, and reads confined to that directory on every
  request.
- **A truthful generation lifecycle** (`app/reports/service.py`): the row is
  written before the file, a failure marks the row `failed` and removes the partial
  artifact, and `downloadable` is asked of the store rather than inferred from a
  status.
- **Four routes** in the M13 envelope — list, get, generate and download — with
  validation, explicit maximum limits, correct empty responses and controlled
  errors that expose no internals.
- **One additive migration**: five nullable-or-defaulted columns on `reports`, no
  row rewritten and no column dropped, renamed or retyped.
- **257 reporting tests**, a clean full regression (`2322 passed`), clean type
  checking, a green frontend typecheck and 448 passing unit tests, a two-mode
  verification script that exercised the real stack end to end and over real HTTP,
  and a recorded local performance baseline with its own limits stated.

Work explicitly **not** done, and belonging to later milestones: ML anomaly
detection, behavioural baselines, AI explanations, local LLM/Ollama, automatic
blocking, IPS, SIEM and threat-intelligence integrations, authentication and RBAC,
notification delivery, scheduled or recurring reports, and distributed sensors.
Nothing in this document claims any of them: §17 states what the reporting layer
*is* limited by, and §3 states what it deliberately does not do.

M17 is ready to close.
