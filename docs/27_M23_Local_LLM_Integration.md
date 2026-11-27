# M23 — Local LLM Integration

**Project:** NetWatch AI
**Milestone:** M23
**Version:** v0.0.23
**Base version:** v0.0.22
**Status:** Implemented and verified

---

## 1. What this milestone is

M23 adds a **local language model runtime** to NetWatch AI and the plumbing an
analyst layer will use later. It does not analyse anything.

Concretely, after M23 the application can:

* report whether a local model runtime is switched on, running and holding the
  configured model — as one of four states, not as an error;
* list the models that runtime actually has installed;
* send a bounded prompt to the configured model and show the reply.

And it cannot, by construction:

* reach any cloud service, or fall back to one;
* download a model;
* execute model output, or let it touch a detection, alert, incident or score;
* read packets, database rows, credentials or file paths into a prompt.

The last group is the point of the milestone. A model is an untrusted external
process even when it lives on the same machine, and M23 is where that is made
structural rather than promised.

---

## 2. Why this shape, and not "just call the API"

Three decisions are load-bearing and were made against measurements on the
reference machine (Windows 11, Python 3.13.2, 4 GB VRAM), not against intuition.

### 2.1 A state, never an error, for the ordinary conditions

A disabled feature and a stopped service are both normal. Reporting either as a
failure makes the page shout at an operator for something that needs a sentence and
a switch — and, worse, makes *switched off* indistinguishable from *broken*, which
is the single distinction an operator most needs.

So `GET /api/v1/ai/status` always answers `200` and carries one word:

| State | Meaning | What an operator does |
| --- | --- | --- |
| `disabled` | `llm_enabled` is false | Set `LLM_ENABLED=true` if wanted |
| `unreachable` | Enabled, runtime not answering | Start Ollama |
| `model_missing` | Runtime answers, configured model absent | Install the model |
| `ready` | Enabled, reachable, installed | Send a test prompt |

Each is fixed differently, which is why they are not flattened into one error.

### 2.2 Two timeouts, because a probe is not a generation

An unreachable host on this machine does not refuse the connection — it **hangs**
until the timeout expires. A status check sharing the generation budget would
therefore block for a minute to answer a question worth three seconds.

* `LLM_HEALTH_TIMEOUT_SECONDS` (default **3**) — the probe.
* `LLM_TIMEOUT_SECONDS` (default **60**) — a generation.

Startup validation refuses a configuration where the probe may outlast a
generation, because a probe that can outlast the thing it precedes is not a probe.

A true cold load of `llama3.2:3b` measured **9,074 ms**, and 512 output tokens
measured ~9 s at ~56 tokens/second. The 60-second budget is those two figures with
headroom, not a round number.

### 2.3 `num_ctx` is pinned, because inheriting it does not fit

The reference model advertises a **131,072-token** context. Left to its default the
runtime sizes the KV cache from that number, and a 2 GB model then exceeds 4 GB of
VRAM — it fails to load.

Pinning `num_ctx=4096` brought the resident footprint to a measured **~2.35 GB**.
`num_predict` (the output cap) and `keep_alive` are pinned for the same reason: they
are decisions this application makes, not runtime defaults that change between
versions.

---

## 3. Architecture

```text
app/ai/
  __init__.py        the process-wide singleton and its reset
  exceptions.py      the controlled failure vocabulary
  health.py          the four-state model, and one sentence per state
  schemas.py         the API payloads
  service.py         limits, concurrency, state — the one place they live
  providers/
    base.py          the provider interface (no HTTP, no provider name)
    ollama.py        the Ollama HTTP adapter
api/v1/ai.py         the three routes
```

### 3.1 The provider boundary

`providers/base.py` defines what an inference runtime must do:

| Member | Purpose |
| --- | --- |
| `check_health(timeout_seconds)` | Is it answering, what version, how many models |
| `list_models(timeout_seconds)` | Its own inventory, projected |
| `model_available(model, timeout_seconds)` | Is this specific model installed |
| `generate(options, timeout_seconds)` | Produce a reply |
| `close()` | Release its HTTP client |

Nothing above this line knows the word "Ollama". `app/ai/service.py`,
`app/api/v1/ai.py` and the whole frontend speak only in `LlmProvider`. A second
local runtime is a new file in `providers/` plus one entry in
`SUPPORTED_LLM_PROVIDERS`; no route, schema, service or page changes.

That is a claim the code has to keep, so the only place `OllamaProvider` is named
outside its own module is the factory in `app/ai/__init__.py`.

### 3.2 Where each rule is enforced

| Rule | Enforced in |
| --- | --- |
| Disabled means nothing is called | `AiService.status` / `generate` — before any network access |
| Prompt length | `AiService.generate`, against `llm_max_prompt_chars` |
| Output length | `GenerationOptions.max_output_tokens` → `num_predict` |
| One generation at a time | `threading.BoundedSemaphore`, refused not queued (`409`) |
| Generation budget | `LLM_TIMEOUT_SECONDS`, per call |
| Probe budget | `LLM_HEALTH_TIMEOUT_SECONDS`, per call |
| No model or host from a client | `AiTestRequest`, which has one field |
| No provider text to a client | `_to_api_error`; the detail goes to the log only |

A `BoundedSemaphore` rather than a `Lock` is deliberate: releasing one time too many
raises instead of quietly widening the concurrency budget, which is the failure that
would surface as two models on a card that fits one.

### 3.3 Why there is no background thread

M23 is entirely request-driven. Nothing in `app/ai/` runs on a timer, so no code in
this package can execute on the packet-capture thread — the requirement is met by
the absence of the mechanism rather than by a guard around it.

---

## 4. Configuration

Every value is read at startup and validated then. Nine are in the milestone brief;
two more were added because the measurements in §2 made them necessary.

| Setting | Default | Notes |
| --- | --- | --- |
| `LLM_ENABLED` | `false` | The authoritative switch. Off by default. |
| `LLM_PROVIDER` | `ollama` | Closed vocabulary; anything else is refused at startup |
| `LLM_BASE_URL` | `http://127.0.0.1:11434` | Must be an absolute http(s) URL with a host |
| `LLM_MODEL` | *(blank)* | Required once `LLM_ENABLED=true` |
| `LLM_TIMEOUT_SECONDS` | `60` | A generation |
| `LLM_HEALTH_TIMEOUT_SECONDS` | `3` | A probe; must be shorter than the above |
| `LLM_MAX_CONCURRENT_REQUESTS` | `1` | Correct for one consumer GPU |
| `LLM_MAX_PROMPT_CHARS` | `4000` | Ceiling 8000, refused above it |
| `LLM_MAX_OUTPUT_TOKENS` | `512` | Ceiling 2048, and must be below `LLM_NUM_CTX` |
| `LLM_NUM_CTX` | `4096` | Pinned for the VRAM reason in §2.3 |
| `LLM_KEEP_ALIVE` | `5m` | How long the model stays resident |

**What startup validation does and does not do.** It checks *shape* only: the
provider is known, the URL parses, the timeouts are positive and ordered, the limits
are positive and under their ceilings, and a model is named if the feature is on.

It never checks reachability. An unreachable Ollama must not stop NetWatch AI from
starting, because capture, detection, alerting, correlation and every existing route
work without it. Whether the runtime is actually listening is asked lazily and
answered as a state.

**Two switches named alike, on purpose.** `LLM_ENABLED` (this environment variable)
is the switch for this runtime. The database row called `ai_enabled`, visible on the
Settings page, is a different and older switch that M23 does not read. Neither
silently controls the other, and the AI Configuration page says so, because two
similarly-named switches that quietly interact would be worse than either alone.

---

## 5. REST API

| Method | Endpoint | Answers |
| --- | --- | --- |
| `GET` | `/api/v1/ai/status` | One of four states, always `200` |
| `GET` | `/api/v1/ai/models` | The runtime's inventory; `503` when it cannot be read |
| `POST` | `/api/v1/ai/test` | A bounded prompt and the reply |

### 5.1 `GET /ai/status`

Answers `200` in every non-transport case:

```json
{
  "success": true,
  "message": "Local AI status retrieved",
  "data": {
    "enabled": true,
    "provider": "ollama",
    "model": "llama3.2:3b",
    "state": "ready",
    "state_label": "Ready",
    "state_description": "The model runtime is reachable and the configured model is installed. A test generation will be attempted on request.",
    "runtime_reachable": true,
    "model_available": true,
    "runtime_version": "0.40.18",
    "installed_model_count": 1,
    "message": "Ready to generate.",
    "disclaimer": "..."
  }
}
```

### 5.2 `GET /ai/models`

A passthrough of what the runtime reports: nothing cached, nothing curated, nothing
invented. Each entry carries `name`, `parameter_size`, `quantization`, `size_bytes`
and `family`; the payload marks whether the configured model is among them, so a
page need not compare strings.

Answers `503` when the feature is disabled or the runtime is unreachable, which a
caller must read as *cannot list* rather than *no models installed*.

### 5.3 `POST /ai/test`

Request body:

```json
{ "prompt": "In one sentence, what does a port scan typically indicate?" }
```

One field. There is no `model`, `base_url`, `timeout`, `temperature` or `num_ctx`,
so "a client cannot choose what runs or where" is a property of the schema rather
than a rule someone must remember to enforce.

Refusals:

| Cause | Status | `field` |
| --- | --- | --- |
| Feature disabled | `503` | `llm_enabled` |
| Runtime unreachable | `503` | `llm` |
| Configured model absent | `503` | `llm_model` |
| Generation timed out | `503` | `llm` |
| Another generation running | `409` | `llm` |
| Blank or oversized prompt | `400` | `prompt` |

The status code is chosen from the *reason*, not the exception class, because a
missing model is a misconfiguration and an unreachable runtime is a stopped
service — both `503`, but different sentences and different fields.

**Every error is sanitised.** The provider's own text is logged in `detail` and
never placed in `message` or any response field. Ollama's 404 body names the model,
its connection errors name the host, and M13.30 says neither reaches a client.

---

## 6. Frontend

A new **AI Configuration** page, in the sidebar's *Operate* group beside System.

| Panel | Shows |
| --- | --- |
| State | The badge, its sentence, and the runtime version when it reported one |
| Configuration | Enabled, provider, model, reachability, model availability, model count, version |
| Installed models | The real inventory: name, size, quantization, family, and which is in use |
| Test generation | A prompt box, a gated send button, and the reply |

Three choices worth stating:

* **The test form is gated, not hidden.** It stays visible in every state, with the
  button disabled and the reason named. A hidden control teaches nothing.
* **The wait is labelled with a measurement.** M23 does not stream, so the browser
  learns nothing until the reply is complete and cannot distinguish a cold model
  load from a slow generation. The page says which is *likely*, using the measured
  9,074 ms cold load as its threshold, and shows elapsed time beside it.
* **The disclaimer is not dismissible.** The reply is rendered in a `<pre>` as text
  — never as markup — and the sentence saying what it is travels with it.

The inventory is only requested when `/ai/status` says the runtime is reachable.
Asking a stopped runtime for its models produces a second failure for the same
cause, which the page would then have to explain twice.

A failed *status* request is the one case that is not a state: it means the backend
itself did not answer, and the page says exactly that rather than claiming the
runtime is down.

---

## 7. Installing Ollama and a model

Explicit operator actions. **M23 never installs a model and never downloads one.**

1. Install Ollama from <https://ollama.com/download> and start it. By default it
   listens on `http://127.0.0.1:11434`.
2. Pull a model **in your own shell**:

   ```powershell
   ollama pull llama3.2:3b
   ```

   `llama3.2:3b` is ~2 GB and was the reference model. On a machine with less VRAM
   try `llama3.2:1b` (~1.3 GB) or `qwen2.5:1.5b`.
3. Confirm it is there:

   ```powershell
   ollama list
   ```

4. Point NetWatch AI at it, in `backend/.env`:

   ```dotenv
   LLM_ENABLED=true
   LLM_PROVIDER=ollama
   LLM_BASE_URL=http://127.0.0.1:11434
   LLM_MODEL=llama3.2:3b
   ```

5. Restart the backend, then open **AI Configuration**.

### 7.1 Resource requirements

| | |
| --- | --- |
| Disk | ~2 GB for `llama3.2:3b`, ~1.3 GB for `llama3.2:1b` |
| VRAM / RAM | Measured **~2.35 GB resident** at `num_ctx=4096` on `llama3.2:3b` |
| Cold load | Measured **9,074 ms** for the first request after a start |
| Generation | Measured ~56 tokens/second, so 512 tokens ~9 s |

### 7.2 Where the model is stored

Ollama keeps pulled models on disk outside this repository. On Windows the default
is `%USERPROFILE%\.ollama\models`; on Linux and macOS it is `~/.ollama/models`.

To move them — the usual reason is a full system drive — set **Ollama's own**
`OLLAMA_MODELS` environment variable before starting the service:

```powershell
setx OLLAMA_MODELS "D:\ollama-models"
# restart the Ollama service for it to take effect
ollama list   # confirm the models are still visible
```

`OLLAMA_MODELS` belongs to Ollama, not to NetWatch AI. **M23 has no setting that
controls it and does not read it.** If you move the directory, the only thing this
application notices is whatever `/api/tags` reports afterwards — which is exactly
the intended behaviour, because the runtime owns its inventory and this layer only
reports what it has. An empty or missing directory therefore appears as
`model_missing`, not as an error in NetWatch AI.

**For limited hardware**, in order of effect:

1. Choose a smaller model and set `LLM_MODEL` to it — the largest single change.
2. Lower `LLM_NUM_CTX` (minimum 512). The KV cache scales with it.
3. Lower `LLM_MAX_OUTPUT_TOKENS`, which caps how long one reply may run.
4. Set `LLM_KEEP_ALIVE` to a shorter window if the card is shared with other work.

---

## 8. Verifying it

### 8.1 The six runtime conditions

Run and recorded on this machine; the application was checked in each.

| # | Condition | Observed state | Monitoring |
| --- | --- | --- | --- |
| 1 | Enabled off, no runtime | `disabled` | unaffected |
| 2 | Enabled, runtime not running | `unreachable` | unaffected |
| 3 | Enabled, runtime up, model absent | `model_missing` | unaffected |
| 4 | Enabled, runtime up, model present | `ready` (`0.40.18`) | unaffected |
| 5 | Disabled, live runtime present | `disabled` | unaffected |
| 6 | Disabled, no runtime at all | `disabled` | unaffected |

In every case `/api/v1/system/status` and `/api/v1/dashboard/summary` answered
`200`. With the default (disabled) configuration `/api/v1/ai/status` answered
`200 state=disabled` — the feature does not have to be on to be reachable.

Measured during the check: the model answered a real prompt in **9,565 ms** for 128
output tokens, and case 2 reported `unreachable` within **one health budget** rather
than hanging for the generation budget.

### 8.2 Automated tests

| Suite | Result |
| --- | --- |
| `test_ai_provider`, `test_ai_service`, `test_ai_generation`, `test_ai_api` | **24 passed** (mocked provider — deterministic) |
| `test_ai_live` | **8 passed** against the real runtime; skips with a stated reason when absent |
| Full backend suite | **3,020 passed** |
| Full frontend suite | **557 passed** (20 files) |
| Pyright (M23 files) | **0 errors, 0 warnings** |
| `tsc --noEmit` | **0 errors** |
| Production build | clean; `AIConfiguration` in its own **13.33 kB** chunk |

`test_ai_live.py` is opt-in precisely so the ordinary suite never depends on a
running service.

### 8.3 Manual

```powershell
# Is the feature usable?
Invoke-RestMethod http://127.0.0.1:8000/api/v1/ai/status

# What is installed?
Invoke-RestMethod http://127.0.0.1:8000/api/v1/ai/models

# Say something
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/ai/test `
  -ContentType 'application/json' `
  -Body '{"prompt":"In one sentence, what is a SYN flood?"}'
```

---

## 9. Privacy and the trust boundary

**What leaves the machine: nothing.** There is no cloud provider in the provider
vocabulary, no fallback path, and no URL a client can supply. The one address the
application talks to is `LLM_BASE_URL`, loopback by default, read only from
configuration.

**What a prompt may contain:** what an operator typed into the AI Configuration
page. In M23 that is the only source. The page and the service have no access to
packets, payloads, device rows, alerts, incidents, credentials or file paths — not
by policy but by not being connected to any of them.

**What the model may do:** produce text. Its output is returned as a string,
rendered as text, and never evaluated, executed, or written into a detection,
alert, incident or risk record. The model has no database handle, no shell, and no
filesystem access through this application.

**Why this is not paranoia about a local process.** A model's output is
attacker-influenceable if its input ever is, and a local service is still a separate
process with its own bugs. The boundary costs almost nothing to draw and is
impossible to retrofit after an output has been trusted.

**What is logged:** the state, the token count, the duration. **Not** the prompt and
not the reply. A prompt is operator text and may contain anything; the log is not
the place to keep it.

---

## 10. Known limitations

* **No streaming.** A reply arrives whole. The page's "likely loading / generating"
  label is an inference from elapsed time against a measured cold load, not a
  server-reported phase, and it says "likely" for that reason.
* **One generation at a time.** A second concurrent request is refused with `409`
  rather than queued. On a 4 GB card that is correct; on a larger one it is a
  conservative default, configurable through `LLM_MAX_CONCURRENT_REQUESTS`.
* **Context is capped at 4,096 tokens** by configuration. A prompt near the 4,000
  character limit plus a long reply can approach it.
* **No conversation memory.** Each request is independent; there is no session, and
  the page holds no history.
* **The model's quality is the model's.** Nothing here validates an answer, scores
  its confidence, or checks it against captured traffic. Deliberate: M23 is
  infrastructure, M24 is the analyst.
* **No automatic model selection.** If `LLM_MODEL` names a model the runtime does
  not have, the state is `model_missing` and nothing is substituted.
* **`ai_enabled` on the Settings page is unrelated** — an older database row.
* **Ollama is the only implemented runtime.** The interface admits another, but only
  one adapter exists.
* **Not measured, and not claimed:** throughput under concurrent operators, quality
  of any answer, or memory behaviour across a long session. One operator, one
  request at a time is the verified case.

---

## 11. What M24 and later will use this for

The layer exists so these can be built without renegotiating the boundary:

* Explaining a security event, given evidence an operator selected.
* Summarising an alert or an incident.
* Reasoning over an ordered sequence of events rather than isolated rules.
* Suggesting an investigation step, with the evidence it was based on.

**None of that is implemented.** M23 answers "is local AI working, and what does it
say to this sentence?". It does not read an alert, form an opinion about traffic, or
change a single stored value.

| Capability | Milestone |
| --- | --- |
| Local LLM infrastructure | **M23 — this milestone** |
| AI Security Analyst | M24+ |
| Automated investigation | Later |
| MITRE ATT&CK mapping | Later |
| Wazuh integration | Later |
| Autonomous remediation | Not planned |

---

## 12. Files

**Created — backend**

`app/ai/{__init__,exceptions,health,schemas,service}.py`,
`app/ai/providers/{__init__,base,ollama}.py`, `app/api/v1/ai.py`,
`tests/{ai_fakes,test_ai_provider,test_ai_service,test_ai_generation,test_ai_api,test_ai_live}.py`

**Created — frontend**

`types/ai.ts`, `services/ai.ts`, `hooks/useAiStatus.ts`, `hooks/useAiTest.ts`,
`pages/AIConfiguration.tsx`, `pages/AIConfiguration.test.tsx`

**Modified**

`app/config/settings.py` (eleven settings and one validator),
`app/api/v1/__init__.py` (router mount), `app/main.py` (service lifecycle),
`backend/requirements.txt` (`httpx`),
`frontend/src/{App.tsx,components/Navbar.tsx,components/Sidebar.tsx}` (route, title,
nav), `frontend/src/{types,services,hooks}/index.ts` (barrels),
`frontend/src/services/endpoints.ts` (`AiPaths`),
`README.md`, `docs/TODO.md`, `backend/.env.example`

**Not modified:** anything under `app/services/`, `app/detection/`, `app/alerts/`,
`app/correlation/`, `app/risk/`, `app/baselines/`, `app/anomaly_detection/`,
`app/persistence/` or `app/processing/`. M23 adds a leaf; it does not touch the
pipeline.

---

## 13. Completion criteria, as met

| Criterion | Evidence |
| --- | --- |
| Local Ollama integration works | §8.1 case 4 — a real 9,565 ms generation |
| Provider interface isolated | §3.1 — `OllamaProvider` named in one factory only |
| Runtime and model availability reported accurately | §8.1 — six conditions, four states |
| Operator-triggered test generation works | §5.3, §8.3 |
| No cloud inference or fallback | §9 — no provider in the vocabulary, no URL from a client |
| No automatic model download | §7 — install is an operator action; no pull call exists |
| Input, output, timeout and concurrency limits enforced | §3.2 — each with a named location |
| AI Configuration page integrated | §6 — route, navbar title, sidebar entry |
| Failure isolation verified | §8.1 — monitoring answered `200` in every case |
| Backend and frontend tests pass | §8.2 — 3,020 / 557 |
| Existing M0–M22 functionality intact | 3,020 backend tests, no pipeline module modified |
| Documentation updated | this document, README, `docs/TODO.md` |
| Quality gates pass | §8.2 |
| Version tagged | annotated `v0.0.23` |
