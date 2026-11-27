"""The Ollama HTTP adapter (M23.8).

Ollama's local HTTP API through ``httpx``, which M23's plan names as the client
this layer uses. One client is held for the adapter's lifetime so a connection is
reused between the status probe and the generation that follows it, and each call
passes its **own** timeout — that per-call budget is what makes the health and
generation split real rather than nominal (M23.7).

========================  ==========================================
Method                    Ollama path
========================  ==========================================
``check_health``          ``GET /api/version`` + ``GET /api/tags``
``list_models``           ``GET /api/tags``
``generate``              ``POST /api/generate``
``model_available``       ``GET /api/tags``
========================  ==========================================

**Three things are pinned on every generation**, and each is pinned because the
alternative was measured and was wrong:

* ``num_ctx`` — the reference model advertises a 131,072-token context. Left to its
  default the runtime sizes the KV cache from that, and a 2 GB model exceeds 4 GB
  of VRAM. Pinned to 4096, the resident footprint measured ~2.35 GB.
* ``num_predict`` — the output budget. Without it a reply runs to the context limit.
* ``stream: false`` — one JSON object back, so there is no framing to parse and no
  partial-response handling to get wrong. Streaming is a deliberate non-feature.

**Every failure becomes an** :class:`app.ai.exceptions.LlmError`. The runtime's own
error text is captured in ``detail`` for the log and never placed in ``message``:
Ollama's 404 body names the model and its connection errors name the host, both of
which M23.10 says must not reach a client.
"""

from __future__ import annotations

import logging

import httpx

from app.ai.exceptions import (
    REASON_INVALID_RESPONSE,
    REASON_MODEL_MISSING,
    REASON_NOT_RUNNING,
    REASON_PROVIDER_ERROR,
    REASON_TIMEOUT,
    LlmGenerationError,
    LlmUnavailableError,
)
from app.ai.providers.base import (
    GenerationOptions,
    LlmProvider,
    ProviderGeneration,
    ProviderHealth,
    ProviderModel,
)

logger = logging.getLogger(__name__)

#: Ollama's own provider name, matching the ``llm_provider`` setting.
PROVIDER_NAME = "ollama"

#: The message used when a host does not answer. Deliberately generic: the address
#: is configuration and must not be echoed back (M23.10).
UNREACHABLE_MESSAGE = (
    "The local model runtime is not answering. Start Ollama and check that it "
    "listens on the configured address, then try again."
)

#: The message used when the runtime is up but the configured model is absent.
MODEL_MISSING_MESSAGE = (
    "The configured model is not installed in the local runtime. Install it, then "
    "reload this page. M23 never downloads a model on its own."
)


class OllamaProvider(LlmProvider):
    """Talk to a local Ollama service over its HTTP API (M23.8).

    Args:
        base_url: The runtime's address, from configuration.
        model: The configured model. Required — this adapter cannot choose one, and
            choosing would be the automatic selection M23 forbids.
        num_ctx: The context window to request, pinned for the VRAM reason above.
        keep_alive: How long the runtime should keep the model resident.

    Holds configuration and one HTTP client; keeps no per-request state, so it is
    safe to share across the thread pool FastAPI serves requests from.
    """

    name = PROVIDER_NAME

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        num_ctx: int = 4096,
        keep_alive: str = "5m",
    ) -> None:
        self._base_url = base_url.strip().rstrip("/")
        self._model = model.strip()
        self._num_ctx = int(num_ctx)
        self._keep_alive = str(keep_alive)
        # No timeout is configured on the client: each call supplies its own, which
        # is the health/generation split this milestone requires (M23.7).
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={"Accept": "application/json"},
            follow_redirects=False,
        )

    @property
    def model(self) -> str:
        """Return the configured model name."""
        return self._model

    @property
    def num_ctx(self) -> int:
        """Return the pinned context window."""
        return self._num_ctx

    def close(self) -> None:
        """Close the HTTP client. Called by :meth:`reset_ai_service`."""
        self._client.close()

    # -- transport ---------------------------------------------------------

    def _request_json(
        self,
        path: str,
        *,
        timeout_seconds: float,
        payload: dict[str, object] | None = None,
    ) -> object:
        """Perform one HTTP call and return its decoded JSON body.

        Centralised so all four calls share one timeout mechanism, one error
        translation and one place where a transport fault becomes a controlled
        exception.

        Raises:
            LlmUnavailableError: On a connection failure or a timeout reaching the
                host — an unreachable runtime, which is what an operator needs to
                know.
            LlmGenerationError: On a non-2xx answer or a body that is not JSON.
        """
        try:
            response = self._client.request(
                "POST" if payload is not None else "GET",
                f"{self._base_url}{path}",
                json=payload,
                timeout=timeout_seconds,
            )
        except httpx.TimeoutException as exc:
            # A stopped service usually times out rather than refusing, so this is
            # the ordinary "nothing answered" case.
            raise LlmUnavailableError(
                UNREACHABLE_MESSAGE,
                reason=REASON_NOT_RUNNING,
                detail=f"timed out after {timeout_seconds:.1f}s",
            ) from exc
        except httpx.HTTPError as exc:
            # ConnectError, ReadError, a resET mid-request: all mean the host did
            # not serve this call.
            raise LlmUnavailableError(
                UNREACHABLE_MESSAGE,
                reason=REASON_NOT_RUNNING,
                detail=type(exc).__name__,
            ) from exc

        if response.status_code == 404:
            # The runtime answered, so it is not unreachable — it refused the
            # request, and for /api/generate that means the model is not installed.
            raise LlmUnavailableError(
                MODEL_MISSING_MESSAGE,
                reason=REASON_MODEL_MISSING,
                detail=_safe_text(response),
            )
        if response.status_code >= 400:
            raise LlmGenerationError(
                "The local model runtime refused the request. Check its log for "
                "the reason, then try again.",
                reason=REASON_PROVIDER_ERROR,
                detail=f"HTTP {response.status_code}: {_safe_text(response)}",
            )

        try:
            return response.json()
        except ValueError as exc:
            raise LlmGenerationError(
                "The local model runtime returned a response that could not be "
                "read. This usually means the configured address is not an Ollama "
                "service.",
                reason=REASON_INVALID_RESPONSE,
                detail=f"{len(response.content)} bytes",
            ) from exc

    # -- interface ---------------------------------------------------------

    def check_health(self, *, timeout_seconds: float) -> ProviderHealth:
        """Return whether the runtime is answering, and what it reports (M23.9).

        Never raises: a runtime that is down is a state this method represents
        rather than a failure it propagates, because its caller asks precisely to
        find that out.

        Version and inventory are read separately and each is allowed to fail
        alone — a service that answers ``/api/version`` but refuses ``/api/tags``
        is still reachable, and reporting it as dead would send an operator looking
        for the wrong fault.
        """
        version = ""
        model_count = 0
        try:
            body = self._request_json("/api/version", timeout_seconds=timeout_seconds)
            if isinstance(body, dict):
                version = str(body.get("version", "") or "")
        except Exception as exc:  # noqa: BLE001 - health never raises by contract
            logger.info("Ollama health probe could not read the version: %r", exc)
            return ProviderHealth(reachable=False)

        try:
            body = self._request_json("/api/tags", timeout_seconds=timeout_seconds)
            model_count = len(_models_from_tags(body))
        except Exception as exc:  # noqa: BLE001 - reachable but partly unreadable
            logger.info("Ollama health probe could not read the inventory: %r", exc)

        return ProviderHealth(reachable=True, version=version, model_count=model_count)

    def list_models(self, *, timeout_seconds: float) -> list[ProviderModel]:
        """Return the models the runtime actually has installed (M23.8).

        Raises:
            LlmUnavailableError: If the runtime cannot be reached.
            LlmGenerationError: If it answers with something unusable.
        """
        body = self._request_json("/api/tags", timeout_seconds=timeout_seconds)
        return _models_from_tags(body)

    def generate(
        self, options: GenerationOptions, *, timeout_seconds: float
    ) -> ProviderGeneration:
        """Complete ``options.prompt`` with the configured model (M23.9).

        The request carries no model and no context size from the caller: both come
        from configuration, which is what stops a client selecting either (M23.10).

        Raises:
            LlmUnavailableError: If the runtime is unreachable or lacks the model.
            LlmGenerationError: On a timeout, a refusal or an unusable body.
        """
        if not self._model:
            # Defensive: startup validation refuses this, so reaching it means the
            # service was constructed outside the normal factory.
            raise LlmUnavailableError(
                MODEL_MISSING_MESSAGE, reason=REASON_MODEL_MISSING
            )

        generation_options: dict[str, object] = {
            "num_ctx": self._num_ctx,
            "num_predict": max(1, int(options.max_output_tokens)),
            "temperature": float(options.temperature),
        }
        if options.stop:
            generation_options["stop"] = list(options.stop)

        payload: dict[str, object] = {
            "model": self._model,
            "prompt": options.prompt,
            "stream": False,
            "keep_alive": self._keep_alive,
            "options": generation_options,
        }

        body = self._request_json(
            "/api/generate", timeout_seconds=timeout_seconds, payload=payload
        )

        if not isinstance(body, dict):
            raise LlmGenerationError(
                "The local model runtime returned an unexpected response shape.",
                reason=REASON_INVALID_RESPONSE,
            )
        if body.get("error"):
            # Ollama reports some failures as a 200 carrying an ``error`` field
            # rather than a non-2xx status.
            raise LlmGenerationError(
                "The local model could not produce a reply. Check the runtime log.",
                reason=REASON_PROVIDER_ERROR,
                detail=str(body.get("error")),
            )
        text = body.get("response")
        if not isinstance(text, str):
            raise LlmGenerationError(
                "The local model returned no text.",
                reason=REASON_INVALID_RESPONSE,
            )
        return ProviderGeneration(
            text=text,
            model=str(body.get("model", self._model) or self._model),
            prompt_tokens=_as_int(body.get("prompt_eval_count")),
            output_tokens=_as_int(body.get("eval_count")),
            total_ms=_as_nanos_to_ms(body.get("total_duration")),
            done_reason=str(body.get("done_reason", "") or ""),
        )

    def model_available(self, model: str, *, timeout_seconds: float) -> bool:
        """Return whether ``model`` is installed (M23.4).

        Matching is exact on the name, and a bare name also matches a tagged
        installation — asking for ``llama3.2`` finds ``llama3.2:3b``, which is how an
        operator reads the two.

        Raises:
            LlmUnavailableError: If the runtime cannot be reached.
        """
        wanted = model.strip()
        if not wanted:
            return False
        installed = self.list_models(timeout_seconds=timeout_seconds)
        for entry in installed:
            if entry.name == wanted:
                return True
            if ":" not in wanted and entry.name.split(":", 1)[0] == wanted:
                return True
        return False


def _models_from_tags(body: object) -> list[ProviderModel]:
    """Project an ``/api/tags`` body onto :class:`ProviderModel` entries.

    Tolerant by design: a runtime that renames or drops a detail field must not make
    the whole inventory unreadable, so an unknown entry is skipped and a missing
    field becomes blank rather than raising.
    """
    if not isinstance(body, dict):
        return []
    raw_models = body.get("models")
    if not isinstance(raw_models, list):
        return []
    models: list[ProviderModel] = []
    for entry in raw_models:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("model")
        if not isinstance(name, str) or not name.strip():
            continue
        details = entry.get("details")
        details = details if isinstance(details, dict) else {}
        models.append(
            ProviderModel(
                name=name.strip(),
                parameter_size=str(details.get("parameter_size", "") or ""),
                quantization=str(details.get("quantization_level", "") or ""),
                size_bytes=_as_int(entry.get("size")),
                family=str(details.get("family", "") or ""),
            )
        )
    return models


def _as_int(value: object) -> int:
    """Return ``value`` as an int when it is an integer, else 0."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return 0


def _as_nanos_to_ms(value: object) -> float:
    """Convert Ollama's nanosecond duration to milliseconds."""
    nanos = value if isinstance(value, (int, float)) and not isinstance(value, bool) else 0
    return round(float(nanos) / 1_000_000.0, 2)


def _safe_text(response: httpx.Response) -> str:
    """Return a bounded slice of a response body, for the log only.

    Never returned to a client. The cap exists so a runtime answering with a
    megabyte of HTML cannot turn one failed request into a large allocation.
    """
    try:
        return response.text[:2048]
    except Exception:  # noqa: BLE001 - reading an error body must not raise
        return ""


__all__ = [
    "MODEL_MISSING_MESSAGE",
    "PROVIDER_NAME",
    "UNREACHABLE_MESSAGE",
    "OllamaProvider",
]
