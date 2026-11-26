"""Isolation Forest construction, scoring and reproducibility (M22.4/M22.9).

Four requirements are asserted here, each of which has a specific failure mode the
milestone forbids:

* the configuration is deterministic and validated (a model whose parameters are
  guessed cannot be reproduced);
* two forest fits over the same matrix agree (the seed is stored *and used*);
* the output is the model's own score and classification, with no probability
  anywhere (M22.9);
* a clearly unusual row scores lower than a clearly ordinary one (the model does
  the one thing the milestone needs of it).
"""

from __future__ import annotations

import pytest

from app.anomaly_detection.model import (
    ALGORITHM_ISOLATION_FOREST,
    DEFAULT_CONTAMINATION,
    DEFAULT_N_ESTIMATORS,
    DEFAULT_RANDOM_STATE,
    FittedModel,
    ModelConfig,
    build_model,
)
from app.anomaly_detection.preprocessing import build_plan, to_matrix
from tests.anomaly_fakes import make_window, normal_windows
from app.anomaly_detection.features import build_feature_vector


def fitted_model(windows: list) -> FittedModel:
    """Fit a forest over the given windows through the ordinary plan path."""
    vectors = [build_feature_vector(window) for window in windows]
    plan = build_plan(vectors)
    model = build_model(config=ModelConfig(), plan=plan)
    model.fit(to_matrix(vectors, plan))
    return model


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------


def test_the_default_configuration_matches_the_documented_starting_point() -> None:
    """The defaults are M22.4's suggested values, not tuned ones (M22.16)."""
    config = ModelConfig()

    assert config.n_estimators == DEFAULT_N_ESTIMATORS == 100
    assert config.contamination == DEFAULT_CONTAMINATION == 0.02
    assert config.random_state == DEFAULT_RANDOM_STATE == 42
    assert config.algorithm == ALGORITHM_ISOLATION_FOREST


def test_the_configuration_round_trips_through_its_stored_document() -> None:
    """The stored parameters are what reproduce the model after a restart."""
    config = ModelConfig(n_estimators=64, contamination=0.05, random_state=7)

    restored = ModelConfig.from_dict(config.to_dict())

    assert restored == config


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("n_estimators", 0),
        ("contamination", 0.0),
        ("contamination", 0.51),
        ("contamination", -0.1),
    ],
)
def test_an_invalid_configuration_is_rejected(field: str, value: float) -> None:
    """A contamination of zero would be a detector that can never fire."""
    kwargs = {field: value}
    with pytest.raises(ValueError):
        ModelConfig(**kwargs)  # type: ignore[arg-type]


def test_an_unreadable_stored_configuration_is_reported_as_absent() -> None:
    """A config this build would not accept cannot describe a reproducible model."""
    assert ModelConfig.from_dict(None) is None
    assert ModelConfig.from_dict({"n_estimators": 0}) is None


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------


def test_two_fits_over_the_same_matrix_agree() -> None:
    """The stored seed is used, so two runs produce the same scores."""
    windows = normal_windows(40)
    first = fitted_model(windows)
    second = fitted_model(windows)

    row = build_feature_vector(make_window()).ordered_values(first.feature_names)
    from app.anomaly_detection.preprocessing import to_row

    vector = build_feature_vector(make_window())
    assert first.score(to_row(vector, first.plan)).decision_score == pytest.approx(
        second.score(to_row(vector, second.plan)).decision_score
    )
    assert row is not None


def test_a_different_seed_produces_a_different_forest() -> None:
    """The seed is genuinely live, not merely recorded."""
    windows = normal_windows(40)
    vectors = [build_feature_vector(window) for window in windows]
    plan = build_plan(vectors)
    matrix = to_matrix(vectors, plan)
    from app.anomaly_detection.preprocessing import to_row

    first = build_model(config=ModelConfig(random_state=1), plan=plan)
    second = build_model(config=ModelConfig(random_state=999), plan=plan)
    first.fit(matrix)
    second.fit(matrix)
    vector = build_feature_vector(make_window())
    assert first.score(to_row(vector, plan)).decision_score != pytest.approx(
        second.score(to_row(vector, plan)).decision_score
    )


# ---------------------------------------------------------------------------
# what the model says
# ---------------------------------------------------------------------------


def test_the_model_returns_a_raw_score_and_a_classification() -> None:
    """Both values come straight from scikit-learn, unmodified (M22.9)."""
    model = fitted_model(normal_windows(40))
    vector = build_feature_vector(make_window())
    from app.anomaly_detection.preprocessing import to_row

    result = model.score(to_row(vector, model.plan))

    assert isinstance(result.decision_score, float)
    assert isinstance(result.is_anomaly, bool)


def test_the_score_is_not_a_probability() -> None:
    """A decision score is unbounded around zero, so it cannot be a 0..1 ratio.

    Asserting the absence of a probability is not possible directly; asserting the
    value is outside ``[0, 1]`` for at least one ordinary row is what distinguishes
    this output from one. Isolation Forest's ``decision_function`` is negative for
    most inliers, which is exactly the value a probability could never take.
    """
    model = fitted_model(normal_windows(40))
    vectors = [build_feature_vector(window) for window in normal_windows(40, seed=7)]
    from app.anomaly_detection.preprocessing import to_matrix as matrix_for

    scores = model.decision_scores(matrix_for(vectors, model.plan))

    assert any(score < 0 for score in scores)


def test_an_unusual_window_scores_lower_than_an_ordinary_one() -> None:
    """The one property the milestone needs: a flood is more unusual than normal.

    Asserted as an ordering rather than a threshold, because the absolute value
    depends on the fitted forest and is not comparable across models.
    """
    from app.anomaly_detection.preprocessing import to_row
    from tests.anomaly_fakes import unusual_window

    model = fitted_model(normal_windows(60))
    ordinary = build_feature_vector(make_window(packet_count=200))
    flood = build_feature_vector(unusual_window())

    ordinary_score = model.score(to_row(ordinary, model.plan)).decision_score
    flood_score = model.score(to_row(flood, model.plan)).decision_score

    assert flood_score < ordinary_score


def test_the_anomaly_flag_follows_the_model_not_the_caller() -> None:
    """The classification is ``predict``'s answer, never inferred from the score."""
    model = fitted_model(normal_windows(60))
    from app.anomaly_detection.preprocessing import to_row
    from tests.anomaly_fakes import unusual_window

    flood = build_feature_vector(unusual_window())
    result = model.score(to_row(flood, model.plan))

    assert result.is_anomaly is True


# ---------------------------------------------------------------------------
# guards
# ---------------------------------------------------------------------------


def test_a_plan_with_too_few_features_cannot_build_a_model() -> None:
    """One column would be a threshold detector wearing a model's name."""
    from app.anomaly_detection.preprocessing import PreprocessingPlan

    with pytest.raises(ValueError):
        build_model(
            config=ModelConfig(),
            plan=PreprocessingPlan(feature_names=("packet_count",), fill_values={}),
        )


def test_fitting_needs_at_least_two_rows() -> None:
    """scikit-learn's floor, checked here so the failure message is ours."""
    vectors = [build_feature_vector(window) for window in normal_windows(2)]
    plan = build_plan(vectors)
    model = build_model(config=ModelConfig(), plan=plan)

    with pytest.raises(ValueError):
        model.fit([to_matrix(vectors, plan)[0]])


def test_a_row_of_the_wrong_width_is_rejected_rather_than_misread() -> None:
    """A width mismatch means the row was not built by this plan."""
    model = fitted_model(normal_windows(10))

    with pytest.raises(ValueError):
        model.score([1.0, 2.0])


def test_scoring_before_fitting_is_a_clear_failure() -> None:
    """The error names the condition instead of surfacing a library traceback."""
    vectors = [build_feature_vector(window) for window in normal_windows(5)]
    model = build_model(config=ModelConfig(), plan=build_plan(vectors))

    with pytest.raises(RuntimeError):
        model.score([1.0, 2.0, 3.0])
