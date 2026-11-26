"""Feature-vector construction tests (M22.6).

The feature vector is the only thing a model ever sees of a device, so a mistake
here is not a slightly wrong score — it is a forest fitted to a description of the
device that the packets never wrote. These tests assert the four properties M22.6
requires: the nine M21 features, a stable order, ``NULL`` carried through as absent,
and a truncated cardinality not presented as an exact count.
"""

from __future__ import annotations

import pytest

from app.anomaly_detection.features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    MISSING_NOT_MEASURED,
    MISSING_TRUNCATED,
    build_feature_vector,
    feature_names_for_model,
    missing_reason_for,
)
from app.baselines.statistics import FEATURE_NAMES as M21_FEATURE_NAMES
from tests.anomaly_fakes import make_window

#: The nine features M22.6 lists, written out so a change to either milestone's
#: definition fails here rather than silently reinterpreting a stored model.
EXPECTED_FEATURES = (
    "packet_count",
    "byte_count",
    "tcp_packets",
    "udp_packets",
    "icmp_packets",
    "dns_packets",
    "unique_peers",
    "unique_destination_ports",
    "new_connections",
)


# ---------------------------------------------------------------------------
# the feature set is M21's, in M21's order
# ---------------------------------------------------------------------------


def test_the_feature_names_are_exactly_the_nine_m21_features() -> None:
    """M22 adds no feature of its own; it models the nine M21 already defines."""
    assert EXPECTED_FEATURES == FEATURE_NAMES
    assert FEATURE_NAMES == M21_FEATURE_NAMES


def test_the_order_is_stable_across_calls() -> None:
    """A positional matrix depends on this order, so it must not vary.

    Two calls constructing the same tuple is a weak theorem, but the assertion
    documents *why* the order matters: `to_matrix` is positional, so a reordered
    feature list would feed the wrong column to the wrong tree (M22.6).
    """
    first = build_feature_vector(make_window())
    second = build_feature_vector(make_window())
    assert (
        first.ordered_values(FEATURE_NAMES)
        == second.ordered_values(FEATURE_NAMES)
    )


# ---------------------------------------------------------------------------
# a normal window
# ---------------------------------------------------------------------------


def test_a_fully_measured_window_yields_every_feature() -> None:
    """Nothing is dropped when every field carries a number."""
    vector = build_feature_vector(
        make_window(packet_count=200, unique_peers=6, new_connections=4)
    )

    assert vector.values_observed == len(EXPECTED_FEATURES)
    assert vector.values["packet_count"] == 200.0
    assert vector.values["unique_peers"] == 6.0
    assert vector.values["new_connections"] == 4.0
    assert vector.missing_reasons == {}


def test_values_are_floats_even_when_the_column_is_an_integer() -> None:
    """The matrix is a float array; an int column must not smuggle a type through."""
    vector = build_feature_vector(make_window(packet_count=7))

    assert isinstance(vector.values["packet_count"], float)


def test_the_vector_carries_the_window_identity_and_length() -> None:
    """The identity is what makes the vector attributable to one device."""
    window = make_window(index=42, window_seconds=60.0)
    vector = build_feature_vector(window)

    assert vector.device_key == window.device_key
    assert vector.window_start == window.window_start
    assert vector.window_seconds == 60.0


def test_the_schema_version_is_recorded() -> None:
    """A model stores the version it was trained under, so it must exist."""
    assert FEATURE_SCHEMA_VERSION >= 1


# ---------------------------------------------------------------------------
# NULL is absent, never zero
# ---------------------------------------------------------------------------


def test_an_unmeasurable_connection_count_is_absent_rather_than_zero() -> None:
    """M21 stores ``NULL`` for an unmeasurable ``new_connections``; it stays absent.

    This is the single most important property in the module: zero is the most
    normal-looking value a feature can take, which is exactly the wrong direction
    for an anomaly detector (M22.6).
    """
    vector = build_feature_vector(make_window(new_connections=None))

    assert "new_connections" not in vector.values
    assert vector.missing_reasons["new_connections"] == MISSING_NOT_MEASURED
    assert vector.ordered_values(FEATURE_NAMES)[-1] is None


def test_a_boolean_column_is_not_read_as_the_number_one() -> None:
    """``True`` is an ``int`` in Python and would otherwise arrive as ``1``."""
    window = make_window()
    window.packet_count = True  # type: ignore[assignment]

    vector = build_feature_vector(window)

    assert "packet_count" not in vector.values


# ---------------------------------------------------------------------------
# a truncated cardinality is a floor, not a measurement
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("truncated_field", "feature"),
    [
        ("peers_truncated", "unique_peers"),
        ("ports_truncated", "unique_destination_ports"),
    ],
)
def test_a_truncated_cardinality_is_treated_as_missing(
    truncated_field: str, feature: str
) -> None:
    """A capped set count is a lower bound, so the model must not receive it.

    Feeding a floor in as though it were exact would systematically understate a
    device's reach during precisely the bursts an anomaly detector should notice
    (M22.6).
    """
    window = make_window()
    setattr(window, truncated_field, True)

    vector = build_feature_vector(window)

    assert feature not in vector.values
    assert vector.missing_reasons[feature] == MISSING_TRUNCATED
    assert missing_reason_for(window, feature) == MISSING_TRUNCATED


def test_truncation_affects_only_the_capped_feature() -> None:
    """Capping the peer set says nothing about the port count."""
    vector = build_feature_vector(
        make_window(peers_truncated=True, ports_truncated=False)
    )

    assert "unique_peers" not in vector.values
    assert "unique_destination_ports" in vector.values


# ---------------------------------------------------------------------------
# tolerance
# ---------------------------------------------------------------------------


def test_a_window_with_no_usable_field_yields_an_empty_vector() -> None:
    """The caller is not made to guard the call; preprocessing excludes it."""

    class Nothing:
        device_key = "mac:00:00:00:00:00:01"
        window_start = None
        window_seconds = 60.0

    vector = build_feature_vector(Nothing())

    assert vector.values == {}
    assert vector.values_observed == 0


def test_feature_names_for_a_vector_are_in_canonical_order() -> None:
    """A caller inspecting one window gets M21's order, not dict insertion order."""
    vector = build_feature_vector(make_window(new_connections=None))

    names = feature_names_for_model(vector)

    assert names == tuple(name for name in EXPECTED_FEATURES if name != "new_connections")
