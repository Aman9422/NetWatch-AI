# M23 — Local LLM Integration (Revised)

**Version:** v0.0.23\
**Base Version:** v0.0.22\
**Status:** Planned\
**Milestone Type:** Local AI Infrastructure\
**Runtime:** Ollama\
**Deployment:** Local-only, CPU/GPU inference\
**Database Changes:** None

## 1. Objective

Implement the local LLM infrastructure required for future AI-powered security analysis in NetWatch AI.

This milestone establishes a reliable connection between the backend and a locally hosted language model. It provides model availability checks, model listing, bounded test generation, configuration management, and frontend visibility.

M23 is strictly an infrastructure milestone.

Do not implement the AI Security Analyst, alert explanations, incident investigation, or sequence-based analysis yet. Those belong to later milestones.

## 2. Mandatory Pre-Implementation Checks

Before modifying code:

1. Inspect the existing repository structure and M20–M22 implementation.
2. Read:
   - `docs/06_AI_Module.md`
   - `docs/TODO.md`
   - `docs/22_*`
   - `docs/23_*`
   - `docs/26_M22_ML_Anomaly_Detection.md`
   - Existing Settings, API, frontend service, test, and quality-gate implementations.
3. Confirm the actual Python environment and dependency versions.
4. Confirm the current Git tag is `v0.0.22`.
5. Confirm the existing frontend request timeout and API client behavior.
6. Check the existing `ai_enabled` database setting and document how it differs from the new LLM configuration.
7. Verify Ollama is installed and accessible before beginning implementation.

### Required local runtime

Use Ollama as the initial provider.

Recommended starting model for the available hardware:

- Model: `llama3.2:3b` or `qwen2.5:3b-instruct`
- Quantization: Q4 where supported by the selected model
- Context window: 4096 tokens
- Local inference only

The machine has approximately 4 GB of dedicated GPU VRAM and 16 GB system RAM. Do not assume that 7B–8B models will run efficiently alongside NetWatch AI.

Configure Ollama's model directory using `OLLAMA_MODELS` to a local storage path outside the OneDrive-synchronised project directory.

Before coding, verify:

- Ollama is available on PATH.
- Ollama service is running.
- `GET http://127.0.0.1:11434/api/tags` returns successfully.
- At least one compatible model is downloaded and listed.
- A small test generation completes successfully.

If these prerequisites cannot be met, stop and report the blocker. Do not silently replace live-runtime verification with mocked tests while claiming full integration.

## 3. Architecture

Implement a provider-independent AI infrastructure layer.

```
React Frontend
      |
      v
FastAPI AI API
      |
      v
AI Service
      |
      v
Provider Adapter Interface
      |
      v
Ollama Provider
      |
      v
Local Ollama Runtime
      |
      v
Local Language Model
```

The provider interface must allow another local inference runtime to be introduced later without rewriting the AI service or API.

Ollama is the only provider implemented in M23.

No external cloud LLM provider.

## 4. Configuration

Add the following configuration to the existing Pydantic Settings implementation.

Suggested settings:

- `llm_enabled`: false by default
- `llm_provider`: `ollama`
- `llm_base_url`: `http://127.0.0.1:11434`
- `llm_model`: operator-configured model name
- `llm_timeout_seconds`: 60
- `llm_health_timeout_seconds`: 3
- `llm_max_concurrent_requests`: 1
- `llm_max_prompt_chars`: bounded prompt size
- `llm_max_output_tokens`: bounded output size

Requirements:

1. Validate configuration shape at application startup.
2. Validate that the provider is supported.
3. Validate that URL configuration is syntactically valid.
4. Validate positive timeout and resource-limit values.
5. Validate that the configured model name is non-blank when LLM functionality is enabled.
6. Do not check Ollama reachability during application startup.
7. Runtime availability must be checked lazily through the AI status or generation endpoints.

**Critical:** An unavailable Ollama service must never prevent NetWatch AI from starting or monitoring network traffic.

### Existing `ai_enabled` setting

The existing API already exposes a mutable database-stored setting named `ai_enabled`.

Do not create two ambiguous switches.

Document the distinction clearly:

- `llm_enabled` is the authoritative configuration switch for M23 local LLM infrastructure.
- The existing database-stored `ai_enabled` must not silently control the new LLM runtime.
- Do not remove or change existing settings behavior without an explicit compatibility requirement.

Explain this distinction in the documentation and frontend.

## 5. Backend Module Structure

Follow the existing single-responsibility module conventions.

Suggested structure:

```
backend/app/ai/
    __init__.py
    exceptions.py
    schemas.py
    client.py
    service.py
    health.py

    providers/
        __init__.py
        base.py
        ollama.py
```

Implement:

- Provider interface and common response schemas.
- Ollama HTTP adapter.
- AI service abstraction.
- Runtime health checking.
- Model listing.
- Test generation.
- Error handling and sanitisation.
- Service factory and reset function.

Follow the M22 factory convention where appropriate:

- `get_ai_service()`
- `reset_ai_service()`

Reuse existing project conventions for errors, response envelopes, logging, and dependency injection.

### Dependency management

`httpx` version 0.28.1 is already installed but currently declared under the testing dependency group.

Promote it to the appropriate production dependency section because the Ollama adapter requires it at runtime.

Do not introduce unnecessary dependencies.

## 6. Runtime and Threading Requirements

M23 must be request-driven.

Do not create:

- A background LLM worker.
- A polling thread.
- A model-refresh scheduler.
- A packet-capture integration.
- An application lifespan startup task for LLM inference.

Inference must happen only when an authorised API request explicitly invokes it.

This means no LLM operation can run on the packet-capture or packet-processing thread.

An Ollama failure, timeout, or model-loading delay must not affect packet capture, rule detection, anomaly detection, alert generation, or existing APIs.

## 7. Resource and Concurrency Controls

Implement bounded resource usage.

Requirements:

1. Maximum concurrent LLM requests defaults to one.
2. Use a `threading.BoundedSemaphore` or an equivalent safe mechanism.
3. Do not queue unlimited generation requests.
4. If the service is busy, reject the request with HTTP `409 CONFLICT`.
5. Use a short semaphore-acquisition timeout.
6. Enforce backend generation timeout.
7. Enforce prompt length and output token limits.
8. Ensure HTTP connections close correctly.
9. Avoid unbounded response buffering.
10. Do not allow model configuration to be overridden by individual API requests.

Health checks and generation requests must have separate timeouts:

- Health check: approximately 2–3 seconds.
- Generation: approximately 60 seconds.

## 8. Ollama Provider

Implement the Ollama adapter using its local HTTP API.

Required operations:

- Check runtime availability.
- Retrieve installed models through `GET /api/tags`.
- Generate text through the Ollama generation endpoint.
- Handle connection failures.
- Handle timeout errors.
- Handle missing models.
- Handle malformed responses.
- Sanitize provider errors before returning them to the frontend.

`/api/models` must return actual installed models from Ollama. Do not fabricate model entries or return a hardcoded model list.

Do not automatically download or pull models.

The operator must explicitly install and select a model.

Do not expose internal filesystem paths, sensitive URLs, stack traces, or raw provider errors to the frontend.

## 9. REST API

Create:

`backend/app/api/v1/ai.py`

Implement the following endpoints.

### GET `/api/v1/ai/status`

Return:

- Whether LLM functionality is enabled.
- Configured provider.
- Configured model.
- Runtime availability.
- Model availability.
- Current state.
- A safe diagnostic message.

Use a consistent state vocabulary:

- `disabled`
- `unreachable`
- `model_missing`
- `ready`

Return HTTP `200` when the feature is disabled, with `enabled: false` and state `disabled`.

Do not return `503` merely because the feature is disabled.

Health checks must use the short health timeout, not the generation timeout.

### GET `/api/v1/ai/models`

Return the actual installed Ollama models.

Include relevant model metadata when available.

Handle unavailable runtime responses safely.

### POST `/api/v1/ai/test`

Provide a bounded test-generation endpoint.

Requirements:

- Accept a JSON request body validated through Pydantic.
- Enforce prompt `max_length`.
- Use the configured model, not a client-supplied model.
- Enforce output limits.
- Enforce generation timeout.
- Return generated text and safe metadata.
- Return `503` if the LLM feature is disabled or runtime/model is unavailable.
- Return `409` when concurrency capacity is exhausted.
- Return safe error responses for timeouts and provider failures.

Include a clear disclaimer that this is a local model test, not a security verdict.

## 10. Security Requirements

The local LLM integration must follow strict boundaries.

- No cloud fallback.
- No automatic model downloads.
- No arbitrary provider URL supplied by the user.
- No model override through API requests.
- No shell command execution.
- No filesystem access through generated prompts.
- No direct database access.
- No automatic remediation.
- No automatic network blocking.
- No raw packet payloads.
- No unnecessary sensitive network information.
- No unrestricted prompt or output size.

Treat all model output as untrusted text.

Add security regression tests for:

1. `llm_base_url` cannot be overridden per request.
2. `llm_model` cannot be attacker-selected through the test endpoint.
3. Provider errors do not leak internal URLs or filesystem paths.
4. Oversized prompts are rejected.
5. Disabled LLM functionality cannot invoke generation.
6. No cloud provider or fallback path is used.

Extend the dedicated `test_security_regression.py` suite, not only the general backend tests.

## 11. Frontend Integration

Create an AI Configuration page.

Follow the existing frontend architecture and conventions.

Expected files or equivalents:

```
frontend/src/
    types/ai.ts
    services/ai.ts
    hooks/useAiStatus.ts
    hooks/useAiTest.ts
    pages/AIConfiguration.tsx
```

Also update:

- API path definitions.
- Service exports.
- `App.tsx` page union and route/switch.
- Sidebar navigation.
- Relevant frontend tests.

The page must display:

- LLM enabled/disabled state.
- Provider.
- Configured model.
- Ollama availability.
- Model availability.
- Installed models.
- Safe diagnostic messages.
- Test prompt input.
- Generated test output.
- Loading and error states.

### Frontend timeout correction

The existing frontend API client has a default timeout of 15 seconds.

A 60-second backend generation timeout conflicts with that default.

The test-generation service must explicitly pass a request timeout greater than the backend timeout, with a reasonable margin.

Use the existing `WriteRequestOptions.timeoutMs` mechanism rather than changing every API request globally.

The UI must distinguish:

- Checking runtime.
- Loading model.
- Generating response.
- Request timeout.
- Runtime unavailable.
- Model missing.

Do not let the frontend abort a legitimate cold model load at 15 seconds.

A runtime-unreachable page must not be considered complete merely because it renders. Test its actual status and failure behavior.

## 12. Contract and Regression Tests

Extend the existing API contract tests.

In `test_api_contract.py`:

- Add `/api/v1/ai` to `EXPECTED_PREFIXES`.
- Add `/api/v1/ai/status` to `COLLECTION_URLS`.
- Ensure new endpoints are included in the response-envelope checks.
- Ensure documented operations include summaries.
- Ensure every operation declares a response.

Add backend tests for:

- Disabled configuration.
- Runtime unavailable.
- Model missing.
- Runtime ready.
- Health timeout.
- Generation timeout.
- Successful generation.
- Provider failure.
- Prompt-size enforcement.
- Output limits.
- Concurrency rejection.
- Error sanitisation.
- No model override.
- No URL override.
- Service factory behavior.

Use mocks for deterministic unit tests.

However, mocks must not be presented as proof of live Ollama integration.

## 13. Live Runtime Verification

Live integration verification is mandatory for a complete M23 release.

After implementation, verify the following six states and record the actual result of each:

1. LLM disabled.
2. LLM enabled, but Ollama unreachable.
3. Ollama reachable, but configured model missing.
4. Ollama reachable with the configured model installed.
5. Successful real generation through the backend API.
6. Successful generation through the frontend UI.

Also verify that:

- The application starts when Ollama is unavailable.
- Existing packet capture still operates.
- Existing rule and ML detection still operate.
- A generation timeout does not affect monitoring.
- A second concurrent generation request is rejected safely.

Do not mark a live test as passed if it was only mocked.

Do not silently skip required runtime tests.

If any state cannot be verified, report it as incomplete and do not claim full M23 acceptance.

## 14. Documentation

Create:

`docs/27_M23_Local_LLM_Integration.md`

Do not use `docs/26` because it is already occupied by M22.

Update:

- README.
- `docs/06_AI_Module.md`, especially the existing §35 implementation structure.
- Relevant architecture documentation.
- `docs/TODO.md` milestone status.

Documentation must explain:

- Ollama installation.
- Local model installation.
- `OLLAMA_MODELS` configuration.
- Recommended 3B model configuration.
- Hardware limitations.
- Configuration variables.
- API endpoints.
- Runtime states.
- Security boundaries.
- Resource controls.
- Troubleshooting.
- Verified and unverified tests.

Explain that 7B–8B models may exceed the available VRAM and can cause substantial CPU offloading and poor generation performance.

Update documentation in the same commit as the implementation so it never describes a structure that does not exist.

## 15. Quality Gates

Run the repository's established quality gates.

Required:

- Full backend test suite.
- Security regression suite.
- Pyright.
- Frontend unit tests.
- Frontend type checking.
- Frontend production build.
- API contract tests.
- Live Ollama integration tests.
- Manual end-to-end frontend verification.

Record actual test counts and results.

Do not copy historical M22 results and present them as fresh M23 results.

Do not weaken existing quality gates, delete tests, or silently skip failures.

## 16. Explicitly Out of Scope

Do not implement:

- AI Security Analyst.
- AI-generated alert explanations.
- Incident investigation.
- Sequence-by-sequence event analysis.
- Intelligent log analysis.
- MITRE ATT&CK mapping.
- Wazuh integration.
- Automatic network blocking.
- Automatic remediation.
- Cloud LLM APIs.
- Model fine-tuning.
- Deep learning anomaly detection.
- Additional ML algorithms.

These belong to later milestones.

## 17. Completion Criteria

M23 is complete only when:

1. Ollama is installed and verified locally.
2. At least one compatible model is installed.
3. Provider adapter architecture is implemented.
4. Local runtime health checking works.
5. Installed model listing works.
6. Real test generation works.
7. Backend resource and concurrency limits work.
8. Frontend AI Configuration page works.
9. Frontend timeout is compatible with backend generation.
10. Application startup is independent of Ollama availability.
11. Security regression tests pass.
12. API contract tests cover the new endpoints.
13. Existing functionality remains unaffected.
14. Documentation is updated.
15. All quality gates pass.
16. Live runtime verification is honestly recorded.

Create the Git tag:

`v0.0.23`

Do not tag the milestone as complete while mandatory live-runtime acceptance criteria remain unverified.

## 18. Final Implementation Report

After implementation, provide:

1. Summary of completed work.
2. Final backend file structure.
3. Frontend files created or modified.
4. Configuration variables.
5. Ollama model and runtime details.
6. API endpoint results.
7. Six live-runtime verification results.
8. Security regression results.
9. Backend and frontend test counts.
10. Pyright, typecheck, and build results.
11. Confirmation that existing network monitoring remains functional.
12. Documentation changes.
13. Git commit and tag details.
14. Known limitations and remaining issues.

Clearly distinguish mocked tests from real Ollama integration tests.

Do not claim successful live inference unless an actual generation was performed.

---

**Final instruction:** Implement M23 only. Preserve all existing M20–M22 behavior. Do not begin M24 until M23 has been implemented, tested, documented, and honestly verified.

**Key changes from the original prompt:**

- Ollama installation and a real model are now prerequisites.
- The 15-second frontend timeout is addressed.
- The documentation filename is corrected to `docs/27`.
- The existing `ai_enabled` setting conflict is explicitly handled.
- Startup validates configuration but does not require Ollama to be reachable.
- Health and generation timeouts are separated.
- Concurrent requests are rejected rather than queued.
- API contract and security regression suites are explicitly extended.
- Live Ollama tests cannot be replaced by mocked tests.
