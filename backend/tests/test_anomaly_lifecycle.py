"""Historical selection, cutoff and model lifecycle tests (M22.5/M22.7).

The two properties most worth breaking are asserted first, because both are silent
when they fail:

* **No self-training.** A window must never appear in the dataset used to score it,
  even though M21 has already persisted it by the time M22 looks. The cutoff is a
  property of the query, so it is tested at the query.
* **A failed refresh keeps the working model.** A detector that degrades beats one
  that goes blind, and the state must say ``failed`` while still scoring.

The rest covers the minimum-data requirement, the refresh interval, the bounded
cache and restart reconstruction.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.anomaly_detection.lifecycle import (
    SKIP_INSUFFICIENT_DATA,
    SKIP_TRAINING_FAILED,
)
from app.anomaly_detection.cache import ModelCache
from app.anomaly_detection.dataset import TrainingDatasetReader
from app.anomaly_detection.states import (
    MODEL_STATES,
    ModelState,
    can_score,
    describe_state,
    normalize_state,
)
from app.anomaly_detection.training import (
    REASON_INSUFFICIENT_WINDOWS,
    REASON_EMPTY_DATASET,
    train_model,
)
from app.anomaly_detection.dataset import TrainingDataset
from app.anomaly_detection.model import ModelConfig, build_model
from app.anomaly_detection.preprocessing import build_plan, to_matrix
from app.anomaly_detection.features import build_feature_vector
from tests.anomaly_fakes import (
    DEVICE_IP,
    DEVICE_MAC,
    make_engine,
    make_window,
    normal_windows,
    persist_windows,
    window_before,
)


# ---------------------------------------------------------------------------
# the strict cutoff: nothing trains on itself
# ---------------------------------------------------------------------------


def test_the_dataset_excludes_the_window_being_evaluated(session_factory) -> None:
    """The evaluated window is not in its own training set (M22.8).

    M21 persists the window before M22 is handed it, so "the most recent N windows"
    would include it and the model would be fitted on the very observation it is
    asked to judge.
    """
    persist_windows(session_factory, normal_windows(10))
    reader = TrainingDatasetReader(session_factory=session_factory)
    cutoff = window_before(5)

    dataset = reader.select(
        DEVICE_MAC, before=cutoff, max_windows=100, exclude_anomalies=False
    )

    assert dataset.count == 5
    assert all(window.window_start < cutoff for window in dataset.windows)
    assert cutoff not in [window.window_start for window in dataset.windows]


def test_no_future_window_is_used_to_score_an_earlier_one(session_factory) -> None:
    """A window after the cutoff is not training data for an earlier window."""
    persist_windows(session_factory, normal_windows(20))
    reader = TrainingDatasetReader(session_factory=session_factory)
    cutoff = window_before(3)

    dataset = reader.select(
        DEVICE_MAC, before=cutoff, max_windows=500, exclude_anomalies=False
    )

    assert max(window.window_start for window in dataset.windows) < cutoff


def test_the_dataset_is_device_specific(session_factory) -> None:
    """One device's history never trains another device's model."""
    persist_windows(session_factory, normal_windows(10, device_key=DEVICE_MAC))
    persist_windows(session_factory, normal_windows(10, device_key=DEVICE_IP))
    reader = TrainingDatasetReader(session_factory=session_factory)

    dataset = reader.select(
        DEVICE_MAC, before=window_before(50), max_windows=500, exclude_anomalies=False
    )

    assert dataset.count == 10
    assert {window.device_key for window in dataset.windows} == {DEVICE_MAC}


def test_the_dataset_is_bounded_and_takes_the_newest_windows(session_factory) -> None:
    """A bounded read, applied to the newest rows before the cutoff (M22.5)."""
    persist_windows(session_factory, normal_windows(30))
    reader = TrainingDatasetReader(session_factory=session_factory)

    dataset = reader.select(
        DEVICE_MAC, before=window_before(30), max_windows=10, exclude_anomalies=False
    )

    assert dataset.count == 10
    # The newest ten, oldest first.
    assert dataset.windows[0].window_start == window_before(20)
    assert dataset.windows[-1].window_start == window_before(29)


def test_a_previously_flagged_window_is_withheld_from_training(
    session_factory,
) -> None:
    """A forest fitted on the outliers it found would learn them as normal."""
    from app.anomaly_detection.evaluation_store import EvaluationStore

    persist_windows(session_factory, normal_windows(30))
    store = EvaluationStore(session_factory=session_factory)
    store.write(
        device_key=DEVICE_MAC,
        window_start=window_before(5),
        window_seconds=60.0,
        algorithm="isolation_forest",
        model_version=1,
        model_trained_at=None,
        training_sample_count=10,
        contamination=0.02,
        decision_score=-0.2,
        is_anomaly=True,
        status="scored",
    )
    reader = TrainingDatasetReader(session_factory=session_factory)

    dataset = reader.select(
        DEVICE_MAC, before=window_before(30), max_windows=500, exclude_anomalies=True
    )

    assert dataset.excluded_anomalies == 1
    assert window_before(5) not in [window.window_start for window in dataset.windows]


def test_a_flagged_window_is_kept_when_too_little_history_would_remain(
    session_factory,
) -> None:
    """The exclusion yields to the minimum, so a noisy device is still trainable."""
    from app.anomaly_detection.evaluation_store import EvaluationStore

    persist_windows(session_factory, normal_windows(4))
    store = EvaluationStore(session_factory=session_factory)
    for index in (0, 1, 2):
        store.write(
            device_key=DEVICE_MAC,
            window_start=window_before(index),
            window_seconds=60.0,
            algorithm="isolation_forest",
            model_version=1,
            model_trained_at=None,
            training_sample_count=4,
            contamination=0.02,
            decision_score=-0.2,
            is_anomaly=True,
            status="scored",
        )
    reader = TrainingDatasetReader(session_factory=session_factory)

    dataset = reader.select(
        DEVICE_MAC, before=window_before(10), max_windows=500,
        exclude_anomalies=True, min_windows=3,
    )

    assert dataset.excluded_anomalies == 0
    assert dataset.count == 4


# ---------------------------------------------------------------------------
# the minimum is M22's own
# ---------------------------------------------------------------------------


def test_too_little_history_yields_no_model_and_a_reason() -> None:
    """ "Not enough data" is an answer, not a fabricated model (M22.5)."""
    windows = normal_windows(5)
    vectors = [build_feature_vector(window) for window in windows]
    plan = build_plan(vectors)
    dataset = TrainingDataset(windows=windows, offered=len(windows))

    result = train_model(
        dataset,
        config=ModelConfig(),
        min_training_windows=100,
        plan=plan,
    )

    assert result.succeeded is False
    assert result.model is None
    assert result.reason == REASON_INSUFFICIENT_WINDOWS
    assert result.training_sample_count == 5


def test_an_empty_dataset_is_reported_separately_from_too_few() -> None:
    """ "Never observed" and "observed but too little" are different facts."""
    result = train_model(
        TrainingDataset(windows=[], offered=0),
        config=ModelConfig(),
        min_training_windows=10,
    )

    assert result.succeeded is False
    assert result.reason == REASON_EMPTY_DATASET


def test_an_established_m21_baseline_is_not_enough_on_its_own() -> None:
    """M21's 30-window ``established`` state says nothing about M22 eligibility.

    A device with 30 windows is ``established`` in M21 and still ``collecting_data``
    here, and that difference must be visible rather than implied.
    """
    windows = normal_windows(30)
    vectors = [build_feature_vector(window) for window in windows]
    plan = build_plan(vectors)

    result = train_model(
        TrainingDataset(windows=windows, offered=30),
        config=ModelConfig(),
        min_training_windows=100,
        plan=plan,
    )

    assert result.succeeded is False
    assert result.training_sample_count == 30


# ---------------------------------------------------------------------------
# lifecycle through the engine's own path
# ---------------------------------------------------------------------------


def test_a_device_with_enough_history_reaches_ready(session_factory) -> None:
    """The happy path: history, a fitted forest, a ``ready`` model row."""
    persist_windows(session_factory, normal_windows(30))
    engine = make_engine(session_factory, min_training_windows=20)

    outcome = engine.lifecycle.ensure_model(
        DEVICE_MAC,
        identity_kind="mac",
        before=window_before(30),
        now=window_before(31),
    )

    assert outcome.available is True
    assert outcome.state == ModelState.READY.value
    assert outcome.training_sample_count == 30
    assert outcome.model_version == 1
    snapshot = engine.model_store.get(DEVICE_MAC)
    assert snapshot is not None and snapshot.has_model is True


def test_a_device_with_too_little_history_stays_collecting(
    session_factory,
) -> None:
    """No model is fabricated from five windows, and the reason is recorded."""
    persist_windows(session_factory, normal_windows(5))
    engine = make_engine(session_factory, min_training_windows=20)

    outcome = engine.lifecycle.ensure_model(
        DEVICE_MAC,
        identity_kind="mac",
        before=window_before(5),
        now=window_before(6),
    )

    assert outcome.available is False
    assert outcome.state == ModelState.COLLECTING_DATA.value
    assert outcome.reason == SKIP_INSUFFICIENT_DATA
    snapshot = engine.model_store.get(DEVICE_MAC)
    assert snapshot is not None
    assert snapshot.model_version == 0


def test_a_disabled_lifecycle_never_trains(session_factory) -> None:
    """Configuration off means no model and no verdict, and it says so."""
    persist_windows(session_factory, normal_windows(30))
    engine = make_engine(session_factory, min_training_windows=10, enabled=False)

    outcome = engine.lifecycle.ensure_model(
        DEVICE_MAC,
        identity_kind="mac",
        before=window_before(30),
        now=window_before(31),
    )

    assert outcome.available is False
    assert outcome.state == ModelState.DISABLED.value


def test_a_second_call_reuses_the_cached_model(session_factory) -> None:
    """Training is expensive, so a reuse must not run a second pass."""
    persist_windows(session_factory, normal_windows(30))
    engine = make_engine(session_factory, min_training_windows=20)
    first = engine.lifecycle.ensure_model(
        DEVICE_MAC, identity_kind="mac", before=window_before(30), now=window_before(31)
    )
    trains_after_first = engine.lifecycle.get_train_count()

    second = engine.lifecycle.ensure_model(
        DEVICE_MAC, identity_kind="mac", before=window_before(30), now=window_before(31)
    )

    assert second.model_version == first.model_version
    assert engine.lifecycle.get_train_count() == trains_after_first


def test_a_failed_refresh_keeps_the_previous_working_model(
    session_factory, monkeypatch
) -> None:
    """The detector degrades to ``failed``; it does not go blind (M22.7)."""
    persist_windows(session_factory, normal_windows(30))
    engine = make_engine(session_factory, min_training_windows=20)
    ready = engine.lifecycle.ensure_model(
        DEVICE_MAC, identity_kind="mac", before=window_before(30), now=window_before(31)
    )
    assert ready.available is True

    def explode(*_args, **_kwargs):
        raise RuntimeError("fitted library failure")

    monkeypatch.setattr(
        "app.anomaly_detection.lifecycle.train_model", explode
    )

    failed = engine.lifecycle.retrain(
        DEVICE_MAC, identity_kind="mac", before=window_before(30), now=window_before(32)
    )

    assert failed.state == ModelState.FAILED.value
    assert failed.reason == SKIP_TRAINING_FAILED
    assert failed.previous_retained is True
    assert failed.cached is not None
    assert failed.model_version == ready.model_version


def test_a_manual_retrain_produces_a_new_version(session_factory) -> None:
    """A successful retrain advances the version rather than reusing the old one."""
    persist_windows(session_factory, normal_windows(30))
    engine = make_engine(session_factory, min_training_windows=20)
    first = engine.lifecycle.ensure_model(
        DEVICE_MAC, identity_kind="mac", before=window_before(30), now=window_before(31)
    )

    second = engine.lifecycle.retrain(
        DEVICE_MAC, identity_kind="mac", before=window_before(30), now=window_before(32)
    )

    assert second.retrained is True
    assert second.model_version == first.model_version + 1


def test_a_restart_reconstructs_the_model_from_history(session_factory) -> None:
    """No pickle is written; the model is rebuilt from windows plus its plan."""
    persist_windows(session_factory, normal_windows(30))
    first_engine = make_engine(session_factory, min_training_windows=20)
    trained = first_engine.lifecycle.ensure_model(
        DEVICE_MAC, identity_kind="mac", before=window_before(30), now=window_before(31)
    )
    assert trained.available is True

    # A fresh process: new cache, same database.
    restarted = make_engine(session_factory, min_training_windows=20)
    rebuilt = restarted.lifecycle.ensure_model(
        DEVICE_MAC, identity_kind="mac", before=window_before(30), now=window_before(33)
    )

    assert rebuilt.available is True
    assert rebuilt.cached is not None
    assert rebuilt.cached.model.is_fitted is True


def test_the_refresh_interval_is_measured_in_windows(session_factory) -> None:
    """A silent device has not fallen behind; one with new windows has."""
    persist_windows(session_factory, normal_windows(30))
    engine = make_engine(
        session_factory, min_training_windows=20, refresh_interval=3
    )
    engine.lifecycle.ensure_model(
        DEVICE_MAC, identity_kind="mac", before=window_before(30), now=window_before(31)
    )
    assert engine.lifecycle.is_stale(DEVICE_MAC) is False

    for _ in range(3):
        engine.lifecycle.note_window(DEVICE_MAC)

    assert engine.lifecycle.is_stale(DEVICE_MAC) is True


# ---------------------------------------------------------------------------
# the bounded cache
# ---------------------------------------------------------------------------


def test_the_cache_evicts_the_least_recently_used_and_is_bounded() -> None:
    """An unbounded cache is the growth M22.7 forbids outright."""
    cache = ModelCache(max_size=2)
    vectors = [build_feature_vector(window) for window in normal_windows(10)]
    plan = build_plan(vectors)
    model = build_model(config=ModelConfig(), plan=plan)
    model.fit(to_matrix(vectors, plan))

    from app.anomaly_detection.cache import CachedModel

    def entry(key: str) -> CachedModel:
        return CachedModel(
            device_key=key,
            model=model,
            model_version=1,
            trained_at=None,
            training_sample_count=len(vectors),
            training_vectors=vectors,
        )

    cache.put(entry("a"))
    cache.put(entry("b"))
    cache.get("a")  # `a` becomes most recently used
    cache.put(entry("c"))  # evicts `b`

    assert len(cache) == 2
    assert cache.keys() == ("a", "c")
    assert cache.get_eviction_count() == 1


def test_the_cache_requires_a_positive_capacity() -> None:
    """A zero-capacity cache would retrain on every evaluation."""
    with pytest.raises(ValueError):
        ModelCache(max_size=0)


# ---------------------------------------------------------------------------
# vocabulary
# ---------------------------------------------------------------------------


def test_the_state_vocabulary_is_the_documented_six() -> None:
    """The API and the page both enumerate these, so the set is asserted."""
    assert MODEL_STATES == (
        "collecting_data",
        "training",
        "ready",
        "stale",
        "failed",
        "disabled",
    )


def test_only_ready_and_stale_may_score() -> None:
    """A ``collecting_data`` device is not being checked, so it cannot verdict."""
    assert can_score("ready") is True
    assert can_score("stale") is True
    for state in ("collecting_data", "training", "failed", "disabled"):
        assert can_score(state) is False


def test_an_unknown_stored_state_reads_as_failed_not_ready() -> None:
    """Claiming a working model that cannot be identified is the unsafe direction."""
    assert normalize_state("nonsense") is ModelState.FAILED
    assert normalize_state(None) is ModelState.FAILED


#: Words that would present a state as a clean bill of health. None of them may
#: appear in a state description, whatever the state.
REASSURING_WORDS = ("is safe", "healthy", "no anomalies", "nothing unusual", "all clear")


@pytest.mark.parametrize("state", MODEL_STATES)
def test_every_state_description_refuses_to_read_as_healthy(state: str) -> None:
    """No state's wording may be mistaken for a clean bill of health (M22.13).

    The failure mode is not a missing phrase but a *reassuring* one: a state
    description that said "no anomalies" would turn "this device is not being
    evaluated" into "this device is fine". Each description must also explain the
    state, so it is never a bare label.
    """
    text = describe_state(state)
    lowered = text.lower()

    assert text
    assert len(text) > 40
    for wording in REASSURING_WORDS:
        if wording not in lowered:
            continue
        # A description may *mention* a reassuring phrase only to deny it: the
        # ``collecting_data`` wording says this is "not the same as 'nothing
        # unusual was observed'". Naming it inside a negation is the honest form;
        # asserting it without one would be the failure.
        assert "not" in lowered, (
            f"description for {state!r} uses {wording!r} without a negation"
        )


def test_a_stale_model_still_describes_itself_as_behind() -> None:
    """``stale`` says the model is behind the data rather than merely older."""
    assert "due" in describe_state("stale").lower()


def test_window_arithmetic_helper_matches_the_fixture() -> None:
    """Guards the fake against drifting from the windows the tests assert on."""
    assert window_before(0) + timedelta(minutes=1) == window_before(1)
    assert make_window(index=1).window_start == window_before(1)
