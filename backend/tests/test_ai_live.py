"""Live Ollama integration (M23.13).

**This is the suite M23.13 requires, and the only one that proves the integration
works.** ``test_ai_service``, ``test_ai_provider``, ``test_ai_generation`` and
``test_ai_api`` all drive fakes; none of them says anything about a real Ollama.
This file does, and it is written so it cannot silently pass when the runtime is
absent.

**Skipping is honest here, and only here.** The project's honesty rules say a
skipped test is not a pass. Two things satisfy that: a skip carries an explicit
reason naming the missing prerequisite, and the release record states which of the
six runtime states were actually observed on this machine. There is no path by
which "the runtime is not installed" becomes "the integration works".

Verified against the real service:

* The runtime is reachable and reports a version.
* At least one model is installed, and the configured one is found by name.
* A real generation returns text, and the pinned options are accepted (an unpinned
  ``num_ctx`` of 131,072 would be rejected or would exhaust VRAM).
* A model that does not exist produces ``model_missing`` rather than a hang.
* An address with nothing listening produces ``unreachable`` within the health
  budget — the behaviour that makes the short probe timeout worth having.

Configuration comes from the environment, defaulting to the reference machine's
setup, so a developer with ``llama3.2:3b`` pulled gets real coverage for free.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from app.ai.exceptions import (
    REASON_MODEL_MISSING,
    REASON_NOT_RUNNING,
    LlmUnavailableError,
)
from app.ai.providers.base import GenerationOptions
from app.ai.providers.ollama import OllamaProvider

#: The address the tests talk to. Overridable so a non-default port still works.
BASE_URL = os.environ.get("LLM_BASE_URL", "http://127.0.0.1:11434")

#: The model expected to be installed. Overridable for a different machine.
MODEL = os.environ.get("LLM_MODEL", "llama3.2:3b")

#: The short health budget, matching the application default.
HEALTH_TIMEOUT = 3.0

#: The generation budget. Generous because a cold load was measured at ~9 s.
GENERATION_TIMEOUT = 60.0


def live_status() -> str:
    """Return why the live suite cannot run, or an empty string when it can.

    A probe rather than an assumption: the skip reason states what is missing, so a
    reader of the report knows whether Ollama was absent or a model was.
    """
    provider = OllamaProvider(base_url=BASE_URL, model=MODEL)
    try:
        health = provider.check_health(timeout_seconds=HEALTH_TIMEOUT)
    except Exception as exc:  # noqa: BLE001 - the probe must never raise
        return f"the local model runtime could not be probed ({type(exc).__name__})"
    finally:
        provider.close()

    if not health.reachable:
        return (
            "no model runtime is answering at the configured address "
            f"(health probe timed out after {HEALTH_TIMEOUT:.0f}s)"
        )
    if health.model_count == 0:
        return "the model runtime is running but has no models installed"
    return ""


#: Evaluated once at import, so every test shares one probe.
UNAVAILABLE_REASON = live_status()

#: Every test here needs a real runtime and a real model.
pytestmark = pytest.mark.skipif(
    bool(UNAVAILABLE_REASON), reason=UNAVAILABLE_REASON or "runtime available"
)


@pytest.fixture
def provider() -> Iterator[OllamaProvider]:
    """Yield a real adapter, closing its client afterwards.

    A generator fixture, so the annotation is ``Iterator`` rather than the provider
    type: pytest reads the ``yield`` and hands the yielded value to each test.
    """
    instance = OllamaProvider(
        base_url=BASE_URL, model=MODEL, num_ctx=4096, keep_alive="5m"
    )
    try:
        yield instance
    finally:
        instance.close()


# -- state 4: reachable with the configured model ---------------------------


def test_the_runtime_reports_a_version(provider: OllamaProvider) -> None:
    """A real runtime answers with a version, which is what an operator needs first."""
    health = provider.check_health(timeout_seconds=HEALTH_TIMEOUT)

    assert health.reachable is True
    assert health.version, "a real runtime must report a version"


def test_at_least_one_model_is_installed(provider: OllamaProvider) -> None:
    """The inventory is non-empty, so a generation could actually run."""
    models = provider.list_models(timeout_seconds=HEALTH_TIMEOUT)

    assert models, "the runtime reported no models"
    assert all(entry.name for entry in models)


def test_the_configured_model_is_installed(provider: OllamaProvider) -> None:
    """State 4: the runtime is reachable *and* has the configured model."""
    assert provider.model_available(MODEL, timeout_seconds=HEALTH_TIMEOUT)


# -- state 5: a real generation ---------------------------------------------


def test_a_real_generation_returns_text(provider: OllamaProvider) -> None:
    """A real completion produces text, token counts and a stop reason.

    The assertion a mock cannot make: the request shape, the pinned ``num_ctx``, the
    keep-alive and the response parsing all have to be right for this to pass against
    the real service.
    """
    generation = provider.generate(
        GenerationOptions(
            prompt="Reply with exactly: NETWATCH_LIVE_OK", max_output_tokens=24
        ),
        timeout_seconds=GENERATION_TIMEOUT,
    )

    assert generation.text.strip(), "a real generation must return text"
    assert generation.output_tokens > 0
    assert generation.done_reason in {"stop", "length"}


def test_a_real_generation_accepts_the_pinned_context(provider: OllamaProvider) -> None:
    """The pinned 4096-token context is accepted by the real runtime.

    Relevant because the model advertises 131,072: an unpinned request would size the
    KV cache from that, and on a 4 GB card the load fails rather than runs.
    """
    generation = provider.generate(
        GenerationOptions(prompt="Say OK", max_output_tokens=8),
        timeout_seconds=GENERATION_TIMEOUT,
    )

    assert generation.model


# -- state 3: reachable, model missing --------------------------------------


def test_an_absent_model_is_reported_as_model_missing() -> None:
    """A real 404 for an uninstalled model maps to ``model_missing``, not a hang.

    The name is deliberately one nobody would have pulled.
    """
    absent = OllamaProvider(base_url=BASE_URL, model="netwatch-definitely-absent:0b")
    try:
        with pytest.raises(LlmUnavailableError) as caught:
            absent.generate(
                GenerationOptions(prompt="hi", max_output_tokens=4),
                timeout_seconds=GENERATION_TIMEOUT,
            )
        assert caught.value.reason == REASON_MODEL_MISSING
    finally:
        absent.close()


# -- state 2: nothing listening --------------------------------------------


def test_an_address_with_nothing_listening_is_unreachable() -> None:
    """A closed port produces ``unreachable`` within the health budget.

    This is what justifies the short probe timeout: measured earlier, a closed port
    *hangs* rather than refusing, so a probe using the generation budget would block
    for a minute to learn that nothing is there.
    """
    import time

    absent = OllamaProvider(base_url="http://127.0.0.1:11999", model="llama3.2:3b")
    try:
        started = time.perf_counter()
        health = absent.check_health(timeout_seconds=HEALTH_TIMEOUT)
        elapsed = time.perf_counter() - started
    finally:
        absent.close()

    assert health.reachable is False
    # Generous bound: the point is that it is bounded by the health budget rather
    # than the generation budget.
    assert elapsed < HEALTH_TIMEOUT * 3, (
        f"a health probe took {elapsed:.1f}s, which is not a short probe"
    )


def test_a_generation_against_a_closed_port_is_unreachable() -> None:
    """A generation against nothing listening reports ``unreachable``, not a hang."""
    absent = OllamaProvider(base_url="http://127.0.0.1:11999", model="llama3.2:3b")
    try:
        with pytest.raises(LlmUnavailableError) as caught:
            absent.generate(
                GenerationOptions(prompt="hi", max_output_tokens=4),
                timeout_seconds=HEALTH_TIMEOUT,
            )
        assert caught.value.reason == REASON_NOT_RUNNING
    finally:
        absent.close()
