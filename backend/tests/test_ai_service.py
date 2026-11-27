"""The AI service contract (M23.12).

What the service guarantees, stated as behaviour:

* Disabled is a state, not an error, and it probes nothing.
* Unreachable is distinguished from model-missing, because the remedy differs.
* Limits are enforced before the network: a blank or oversized prompt never
  reaches the provider.
* One generation at a time, refused rather than queued.
* The generation budget is the long one; the probe budget is the short one.

Every test here drives ``tests.ai_fakes.FakeProvider``. None proves Ollama behaves
this way - ``test_ai_live.py`` does that, and M23.13 forbids presenting the two as
the same evidence.
"""

from __future__ import annotations

import threading

import pytest

from app.ai.exceptions import (
    REASON_BUSY,
    REASON_DISABLED,
    REASON_INVALID_PROMPT,
    LlmBusyError,
    LlmDisabledError,
    LlmGenerationError,
)
from app.ai.health import (
    STATE_DISABLED,
    STATE_MODEL_MISSING,
    STATE_READY,
    STATE_UNREACHABLE,
    is_usable,
    resolve_state,
)
from tests.ai_fakes import (
    GENERATION_ERRORS,
    FakeProvider,
    empty_provider,
    make_service,
    unreachable_provider,
)

# -- state ------------------------------------------------------------------


def test_disabled_reports_disabled_and_probes_nothing() -> None:
    """A disabled feature answers without touching the runtime."""
    provider = FakeProvider()
    service = make_service(provider, enabled=False)

    status = service.status()

    assert status.state == STATE_DISABLED
    assert status.enabled is False
    assert provider.health_calls == 0


def test_unreachable_runtime_reports_unreachable() -> None:
    """A runtime that does not answer is its own state, not a model problem."""
    status = make_service(unreachable_provider()).status()

    assert status.state == STATE_UNREACHABLE
    assert status.runtime_reachable is False
    assert status.enabled is True


def test_runtime_without_the_model_reports_model_missing() -> None:
    """A reachable runtime lacking the configured model is ``model_missing``."""
    status = make_service(FakeProvider(installed=["other:7b"])).status()

    assert status.state == STATE_MODEL_MISSING
    assert status.runtime_reachable is True
    assert status.model_available is False


def test_runtime_with_the_model_reports_ready() -> None:
    """A reachable runtime with the configured model is ``ready``."""
    status = make_service(FakeProvider(installed=["llama3.2:3b"])).status()

    assert status.state == STATE_READY
    assert status.model_available is True
    assert status.runtime_version == "0.40.18"


def test_status_echoes_the_configured_provider_and_model() -> None:
    """The payload reports what was configured, not what was guessed."""
    status = make_service(FakeProvider(), model="llama3.2:3b").status()

    assert status.provider == "fake"
    assert status.model == "llama3.2:3b"


def test_a_tagless_name_matches_a_tagged_installation() -> None:
    """Asking for ``llama3.2`` finds ``llama3.2:3b``."""
    service = make_service(FakeProvider(installed=["llama3.2:3b"]), model="llama3.2")

    assert service.status().state == STATE_READY


def test_an_empty_inventory_is_model_missing_not_unreachable() -> None:
    """A runtime with no models is up, and that is worth distinguishing."""
    status = make_service(empty_provider()).status()

    assert status.state == STATE_MODEL_MISSING
    assert status.runtime_reachable is True


@pytest.mark.parametrize(
    ("enabled", "reachable", "present", "expected"),
    [
        (False, True, True, STATE_DISABLED),
        (False, False, False, STATE_DISABLED),
        (True, False, True, STATE_UNREACHABLE),
        (True, True, False, STATE_MODEL_MISSING),
        (True, True, True, STATE_READY),
    ],
)
def test_resolve_state_is_ordered_disabled_first(
    enabled: bool, reachable: bool, present: bool, expected: str
) -> None:
    """Disabled wins over every other fact, so nothing probes a disabled feature."""
    resolved = resolve_state(
        enabled=enabled, reachable=reachable, model_present=present
    )
    assert resolved.value == expected


def test_only_ready_is_usable() -> None:
    """A generation is attempted only in ``ready``; every other state fails fast."""
    assert is_usable(STATE_READY) is True
    assert is_usable(STATE_DISABLED) is False
    assert is_usable(STATE_UNREACHABLE) is False
    assert is_usable(STATE_MODEL_MISSING) is False


# -- limits -----------------------------------------------------------------


def test_generation_is_refused_when_disabled() -> None:
    """A disabled feature cannot generate, and says so with its own reason."""
    provider = FakeProvider()
    service = make_service(provider, enabled=False)

    with pytest.raises(LlmDisabledError) as caught:
        service.generate("hello")

    assert caught.value.reason == REASON_DISABLED
    assert provider.generate_calls == 0


def test_a_blank_prompt_is_refused_before_the_provider() -> None:
    """An empty prompt is a client mistake, caught without a network call."""
    provider = FakeProvider()
    service = make_service(provider)

    with pytest.raises(LlmGenerationError) as caught:
        service.generate("   ")

    assert caught.value.reason == REASON_INVALID_PROMPT
    assert provider.generate_calls == 0


def test_an_oversized_prompt_is_refused_before_the_provider() -> None:
    """The configured character limit is enforced in the service, once."""
    provider = FakeProvider()
    service = make_service(provider, max_prompt_chars=16)

    with pytest.raises(LlmGenerationError) as caught:
        service.generate("x" * 17)

    assert caught.value.reason == REASON_INVALID_PROMPT
    assert "16" in caught.value.message
    assert provider.generate_calls == 0


def test_a_prompt_at_exactly_the_limit_is_accepted() -> None:
    """The limit is inclusive, so an operator's own ceiling is reachable."""
    provider = FakeProvider()
    service = make_service(provider, max_prompt_chars=16)

    generation = service.generate("x" * 16)

    assert generation.text == "NETWATCH_TEST_OK"
    assert provider.generate_calls == 1


def test_the_configured_output_cap_reaches_the_provider() -> None:
    """The reply cap is handed down rather than left to a provider default."""
    provider = FakeProvider()
    service = make_service(provider, max_output_tokens=128)

    service.generate("hello")

    assert provider.last_options is not None
    assert provider.last_options.max_output_tokens == 128


def test_a_generation_uses_the_long_budget() -> None:
    """A generation is given ``timeout_seconds``, not the short health budget."""
    provider = FakeProvider()
    service = make_service(provider)

    service.generate("hello")

    assert provider.last_timeout == pytest.approx(60.0)


def test_listing_models_is_refused_when_disabled() -> None:
    """A disabled feature will not reach a service the operator switched off."""
    with pytest.raises(LlmDisabledError):
        make_service(FakeProvider(), enabled=False).list_models()


# -- concurrency ------------------------------------------------------------


def test_a_second_concurrent_generation_is_refused() -> None:
    """Only one generation runs at a time, and the second is refused not queued.

    The fake holds the first call open on an event, so the second really does
    arrive while the slot is taken.
    """
    started = threading.Event()
    release = threading.Event()

    class SlowProvider(FakeProvider):
        """A provider whose generation blocks until the test releases it."""

        def generate(self, options, *, timeout_seconds):  # type: ignore[override]
            started.set()
            release.wait(timeout=5.0)
            return super().generate(options, timeout_seconds=timeout_seconds)

    provider = SlowProvider()
    service = make_service(provider, max_concurrent_requests=1)
    outcome: list[object] = []

    def run_first() -> None:
        try:
            outcome.append(service.generate("first"))
        except Exception as exc:  # noqa: BLE001 - recorded for the assertion
            outcome.append(exc)

    worker = threading.Thread(target=run_first)
    worker.start()
    assert started.wait(timeout=5.0), "the first generation never started"

    try:
        with pytest.raises(LlmBusyError) as caught:
            service.generate("second")
        assert caught.value.reason == REASON_BUSY
    finally:
        release.set()
        worker.join(timeout=5.0)

    assert len(outcome) == 1
    assert not isinstance(outcome[0], Exception)


def test_the_slot_is_released_after_a_failed_generation() -> None:
    """A provider failure must not leak the slot, or the feature would wedge."""
    provider = FakeProvider()
    provider.generate_error = GENERATION_ERRORS[0]
    service = make_service(provider)

    with pytest.raises(LlmGenerationError):
        service.generate("hello")

    provider.generate_error = None
    assert service.generate("hello").text == "NETWATCH_TEST_OK"


# -- failure propagation ----------------------------------------------------


@pytest.mark.parametrize("error", GENERATION_ERRORS)
def test_provider_failures_reach_the_caller_unchanged(error: Exception) -> None:
    """The service adds no wrapping, so a caller still sees the real reason."""
    provider = FakeProvider()
    provider.generate_error = error
    service = make_service(provider)

    with pytest.raises(type(error)) as caught:
        service.generate("hello")

    expected = getattr(error, "reason", None)
    assert caught.value.reason == expected  # type: ignore[attr-defined]


def test_listing_propagates_a_provider_failure() -> None:
    """An unreachable runtime during a listing is reported, not swallowed."""
    provider = FakeProvider()
    provider.list_error = GENERATION_ERRORS[2]
    service = make_service(provider)

    with pytest.raises(type(GENERATION_ERRORS[2])):
        service.list_models()


# -- lifecycle --------------------------------------------------------------


def test_close_releases_the_provider_transport() -> None:
    """``close`` is the one resource the service holds, so it must reach it."""
    closed: list[bool] = []

    class CloseableProvider(FakeProvider):
        """A provider that records being closed."""

        def close(self) -> None:
            closed.append(True)

    make_service(CloseableProvider()).close()

    assert closed == [True]


def test_close_is_safe_for_a_provider_without_a_transport() -> None:
    """A provider holding nothing is skipped, so ``close`` is universal."""
    make_service(FakeProvider()).close()
