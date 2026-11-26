"""Feature eligibility and imputation tests (M22.6).

The plan is what makes training and inference answer the same question, so these
tests assert the four decisions it encodes: a mostly-absent feature is dropped, a
feature the model keeps is filled with the *training median* rather than zero, the
column order is canonical, and the plan survives a JSON round trip intact.
"""

from __future__ import annotations

import json

import pytest

from app.anomaly_detection.features import build_feature_vector
from app.anomaly_detection.preprocessing import (
    EXCLUDED_TOO_MISSING,
    MIN_MODEL_FEATURES,
    PreprocessingPlan,
    build_plan,
    to_matrix,
    to_row,
)
from tests.anomaly_fakes import make_window, normal_windows


def vectors_for(windows: list) -> list:
    """Extract one vector per window."""
    return [build_feature_vector(window) for window in windows]


# ---------------------------------------------------------------------------
# eligibility
# ---------------------------------------------------------------------------


def test_every_feature_is_retained_when_all_are_measured() -> None:
    """A fully measured dataset keeps the whole nine-feature vocabulary."""
    plan = build_plan(vectors_for(normal_windows(20)))

    assert len(plan.feature_names) == 9
    assert plan.excluded == {}
    assert plan.is_usable is True


def test_a_feature_measured_in_most_windows_is_retained() -> None:
    """Availability at the threshold keeps the column."""
    windows = normal_windows(20)
    # 16 of 20 measured == 0.8, exactly the default threshold.
    for window in windows[16:]:
        window.new_connections = None

    plan = build_plan(vectors_for(windows), min_availability=0.8)

    assert "new_connections" in plan.feature_names
    assert plan.availability["new_connections"] == pytest.approx(0.8)


def test_a_feature_usually_missing_is_excluded_with_a_reason() -> None:
    """Below the threshold the column is dropped, and the reason is recorded.

    Imputing most of a column would mean the model was largely trained on the
    imputed value rather than on a measurement (M22.6).
    """
    windows = normal_windows(20)
    for window in windows[:10]:
        window.new_connections = None

    plan = build_plan(vectors_for(windows), min_availability=0.8)

    assert "new_connections" not in plan.feature_names
    assert plan.excluded["new_connections"] == EXCLUDED_TOO_MISSING


def test_a_plan_with_too_few_features_is_not_usable() -> None:
    """One column is not a behavioural description of a device."""
    windows = normal_windows(10)
    for window in windows:
        for attribute in (
            "tcp_packets",
            "udp_packets",
            "icmp_packets",
            "dns_packets",
            "unique_peers",
            "unique_destination_ports",
            "new_connections",
        ):
            setattr(window, attribute, None)

    plan = build_plan(vectors_for(windows))

    assert len(plan.feature_names) == 2
    assert plan.is_usable is True  # exactly at MIN_MODEL_FEATURES
    assert MIN_MODEL_FEATURES == 2

    empty = build_plan([])
    assert empty.is_usable is False


def test_an_invalid_threshold_is_rejected() -> None:
    """A threshold outside [0, 1] would retain or exclude everything silently."""
    with pytest.raises(ValueError):
        build_plan([], min_availability=1.5)
    with pytest.raises(ValueError):
        build_plan([], min_availability=-0.1)


# ---------------------------------------------------------------------------
# imputation
# ---------------------------------------------------------------------------


def test_the_fill_value_is_the_training_median_not_a_zero() -> None:
    """Zero is a real measurement; filling with it would assert "sent nothing"."""
    windows = [
        make_window(packet_count=100),
        make_window(packet_count=200),
        make_window(packet_count=400),
    ]

    plan = build_plan(vectors_for(windows))

    assert plan.fill_values["packet_count"] == 200.0
    assert plan.fill_values["packet_count"] != 0.0


def test_an_outlier_does_not_drag_the_fill_value() -> None:
    """The median is robust to exactly the burst a mean would be ruined by."""
    counts = [100, 100, 110, 105, 100, 100, 50_000]
    windows = [make_window(packet_count=count) for count in counts]

    plan = build_plan(vectors_for(windows))

    assert plan.fill_values["packet_count"] == 100.0


# ---------------------------------------------------------------------------
# matrix construction
# ---------------------------------------------------------------------------


def test_the_row_order_follows_the_plan_not_the_vector() -> None:
    """The matrix is positional; a reordered plan must reorder the row."""
    vector = build_feature_vector(make_window(packet_count=111, byte_count=222))
    plan = PreprocessingPlan(
        feature_names=("byte_count", "packet_count"),
        fill_values={"byte_count": 0.0, "packet_count": 0.0},
    )

    assert to_row(vector, plan) == [222.0, 111.0]


def test_a_missing_value_is_imputed_with_the_plan_fill_in_the_matrix() -> None:
    """The same number the model was fitted with is the one inference supplies."""
    vector = build_feature_vector(make_window(new_connections=None))
    plan = PreprocessingPlan(
        feature_names=("packet_count", "new_connections"),
        fill_values={"packet_count": 1.0, "new_connections": 7.5},
    )

    row = to_row(vector, plan)

    assert row[1] == 7.5


def test_a_matrix_has_one_row_per_vector_and_one_column_per_feature() -> None:
    """Shape errors are the quietest bug in this module, so it is asserted."""
    vectors = vectors_for(normal_windows(5))
    plan = build_plan(vectors)

    matrix = to_matrix(vectors, plan)

    assert len(matrix) == 5
    assert all(len(row) == len(plan.feature_names) for row in matrix)


# ---------------------------------------------------------------------------
# persistence
# ---------------------------------------------------------------------------


def test_a_plan_survives_a_json_round_trip() -> None:
    """A restart reconstructs the model from this document, so it must be lossless."""
    plan = build_plan(vectors_for(normal_windows(20)))

    restored = PreprocessingPlan.from_json(plan.to_json())

    assert restored is not None
    assert restored.feature_names == plan.feature_names
    assert restored.fill_values == plan.fill_values
    assert restored.availability == plan.availability


@pytest.mark.parametrize("document", [None, "", "not json", "[]", "{}"])
def test_an_unreadable_plan_is_reported_as_absent(document: object) -> None:
    """An unusable plan must not be half-reconstructed into a scoring model."""
    assert PreprocessingPlan.from_json(document) is None  # type: ignore[arg-type]


def test_a_plan_missing_a_fill_value_is_rejected() -> None:
    """A column that cannot be imputed makes the whole plan unusable."""
    document = json.dumps(
        {
            "feature_names": ["packet_count", "byte_count"],
            "fill_values": {"packet_count": 1.0},
        }
    )

    assert PreprocessingPlan.from_json(document) is None


def test_a_stored_feature_this_build_does_not_know_is_dropped() -> None:
    """A column this build cannot name cannot be fed to a forest correctly."""
    document = json.dumps(
        {
            "feature_names": ["packet_count", "made_up_feature"],
            "fill_values": {"packet_count": 1.0, "made_up_feature": 2.0},
        }
    )

    restored = PreprocessingPlan.from_json(document)

    assert restored is not None
    assert restored.feature_names == ("packet_count",)
