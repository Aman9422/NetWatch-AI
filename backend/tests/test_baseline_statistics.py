"""Statistical-baseline tests (M21.6).

Every figure M21.6 names is checked against a hand-computable sample here, because
a profile that is quietly wrong is worse than one that is absent: M22 will compare
live behaviour against these numbers, and a bad median would make a normal minute
look anomalous.

The two properties that get their own tests:

* **Robustness.** One bulk transfer must not move the median or the MAD. If it
  did, the "normal" a device is measured against would be its worst minute.
* **Honesty about missing data.** A feature with no usable samples is *absent*,
  never present as a mean of zero — "never measured" and "measured as zero" are
  different facts (M21.5/M21.7).
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.baselines.aggregation import WindowCounters
from app.baselines.statistics import (
    FEATURE_COLUMNS,
    FEATURE_NAMES,
    MAD_TO_STDEV,
    FeatureStatistics,
    median_absolute_deviation,
    percentile,
    summarise_feature,
    summarise_samples,
    summaries_from_json,
    summaries_to_json,
)

#: A small sample with a known centre and known spread.
SAMPLE = [10.0, 12.0, 13.0, 14.0, 30.0]

#: The keys a stored feature document carries, which is the contract M22 reads.
STORED_KEYS = {
    "feature",
    "count",
    "mean",
    "median",
    "mad",
    "mad_scaled",
    "stdev",
    "p95",
    "min",
    "max",
    "truncated",
}


@dataclass
class Sample:
    """One aggregated window, shaped like a stored ``BaselineWindow`` row.

    ``summarise_samples`` is duck-typed on the attributes in ``FEATURE_COLUMNS``,
    and there are two producers of those attributes: the live
    :class:`~app.baselines.aggregation.WindowCounters` (where
    ``new_connections`` is always an ``int``) and the reloaded
    :class:`~app.models.baseline_observation.BaselineWindow` (where the column is
    ``NULL``-able). This stand-in is the second shape, so a test can express the
    case the live aggregator never produces: a window whose connection count could
    not be measured.
    """

    packet_count: int = 10
    byte_count: int = 1000
    tcp_packets: int = 10
    udp_packets: int = 0
    icmp_packets: int = 0
    dns_packets: int = 0
    unique_peers: int = 2
    unique_destination_ports: int = 2
    new_connections: int | None = 1
    peers_truncated: bool = False
    ports_truncated: bool = False


# ---------------------------------------------------------------------------
# percentile
# ---------------------------------------------------------------------------


def test_the_median_is_the_fiftieth_percentile() -> None:
    """``percentile`` and ``median`` must agree, or every figure drifts."""
    assert percentile(SAMPLE, 0.5) == 13.0


def test_the_percentile_interpolates_between_orders() -> None:
    """The same definition ``numpy.percentile`` uses, so it can be checked."""
    # Position 1.8 between 12 and 13: 12 + 0.8.
    assert percentile([10.0, 12.0, 13.0], 0.9) == pytest.approx(12.8)


def test_the_extreme_percentiles_are_the_minimum_and_maximum() -> None:
    """A p0 and p100 that disagreed with min/max would be a contradiction."""
    assert percentile(SAMPLE, 0.0) == 10.0
    assert percentile(SAMPLE, 1.0) == 30.0


def test_a_single_value_is_its_own_percentile() -> None:
    """One sample has one answer, and it is not an error."""
    assert percentile([7.0], 0.95) == 7.0


def test_the_percentile_ignores_the_caller_order() -> None:
    """Sorting internally is what makes the result order-independent."""
    assert percentile([30.0, 10.0, 14.0, 12.0, 13.0], 0.5) == 13.0


@pytest.mark.parametrize("fraction", [-0.1, 1.1])
def test_an_impossible_fraction_is_rejected(fraction: float) -> None:
    """A percentile outside [0, 1] is a caller bug, not a value to guess."""
    with pytest.raises(ValueError):
        percentile(SAMPLE, fraction)


def test_a_percentile_of_nothing_is_rejected() -> None:
    """There is no such figure, and returning 0 would be inventing one."""
    with pytest.raises(ValueError):
        percentile([], 0.5)


# ---------------------------------------------------------------------------
# median absolute deviation
# ---------------------------------------------------------------------------


def test_the_mad_is_the_median_distance_from_the_centre() -> None:
    """Distances from 13 are 3, 1, 0, 1, 17; the median of those is 1."""
    assert median_absolute_deviation(SAMPLE, 13.0) == 1.0


def test_the_mad_of_identical_samples_is_zero() -> None:
    """A perfectly regular device has zero spread, which is a real answer."""
    assert median_absolute_deviation([5.0, 5.0, 5.0], 5.0) == 0.0


def test_the_mad_of_nothing_is_rejected() -> None:
    """Again: no sample, no figure."""
    with pytest.raises(ValueError):
        median_absolute_deviation([], 0.0)


# ---------------------------------------------------------------------------
# one feature
# ---------------------------------------------------------------------------


def test_every_reported_figure_is_the_expected_one() -> None:
    """The whole summary of a hand-checkable sample, value by value."""
    summary = summarise_feature("packet_count", SAMPLE)

    assert summary.feature == "packet_count"
    assert summary.count == 5
    assert summary.mean == pytest.approx(15.8)
    assert summary.median == 13.0
    assert summary.mad == 1.0
    assert summary.mad_scaled == pytest.approx(MAD_TO_STDEV)
    # Population stdev (``statistics.pstdev``), not the sample stdev: the values
    # here are every window the profile was built from, not a sample of them.
    assert summary.stdev == pytest.approx(7.2222, rel=1e-4)
    assert summary.minimum == 10.0
    assert summary.maximum == 30.0


def test_one_outlier_barely_moves_the_median() -> None:
    """The property the robust figures exist for.

    The mean is dragged enormously by the outlier; the median moves by one. A
    baseline whose centre was the mean would call a normal minute anomalous the
    day after one bulk transfer.
    """
    without = summarise_feature("packet_count", [10.0, 11.0, 12.0, 13.0])
    with_outlier = summarise_feature(
        "packet_count", [10.0, 11.0, 12.0, 13.0, 5000.0]
    )

    assert with_outlier.mean > without.mean * 50
    assert with_outlier.median == 12.0
    assert with_outlier.mad <= 2.0


def test_a_single_sample_reports_zero_spread_rather_than_an_error() -> None:
    """Population stdev of one value is undefined; zero is the honest substitute.

    Reporting it as zero keeps the ``count`` beside it as the signal that there is
    nothing to spread yet.
    """
    summary = summarise_feature("packet_count", [42.0])

    assert summary.count == 1
    assert summary.mean == 42.0
    assert summary.median == 42.0
    assert summary.mad == 0.0
    assert summary.stdev == 0.0
    assert summary.p95 == 42.0


def test_a_feature_with_no_samples_is_rejected_rather_than_zero_filled() -> None:
    """The caller omits the feature; it does not get a mean of 0 (M21.5)."""
    with pytest.raises(ValueError):
        summarise_feature("packet_count", [])


def test_a_truncated_cardinality_is_carried_onto_the_summary() -> None:
    """A floor must stay flagged as a floor all the way to the API."""
    summary = summarise_feature("unique_peers", [2.0, 2.0], truncated=True)

    assert summary.truncated is True


# ---------------------------------------------------------------------------
# a set of windows
# ---------------------------------------------------------------------------


def test_every_supported_feature_is_summarised() -> None:
    """The profile carries M21.4's features, not a subset of them."""
    summaries = summarise_samples([Sample(), Sample()])

    assert set(summaries) == set(FEATURE_NAMES)


def test_a_live_window_aggregator_object_is_accepted_too() -> None:
    """The summariser serves a live flush and a reloaded profile alike.

    ``WindowCounters`` is the live shape; ``Sample`` above is the stored shape. If
    the calculation only accepted one of them, a flush would have to convert one
    into the other first — which is the copy this duck-typing exists to avoid.
    """
    live = WindowCounters(
        device_key="mac:aa:bb:cc:dd:ee:01",
        identity_kind="mac",
        window_start=1_700_000_040.0,
        window_seconds=60.0,
        packet_count=7,
        byte_count=700,
        tcp_packets=7,
        peers={"10.0.0.5"},
        ports={443},
        new_connections=1,
    )

    summary = summarise_samples([live])["packet_count"]

    assert summary.count == 1
    assert summary.mean == 7.0


def test_the_feature_order_is_the_declared_order() -> None:
    """The API and the frontend present volume, then protocol, then variety."""
    assert FEATURE_COLUMNS[0][0] == "packet_count"
    assert FEATURE_NAMES[-1] == "new_connections"


def test_an_unmeasurable_feature_is_absent_rather_than_zero() -> None:
    """``new_connections`` is NULL for a window where it could not be measured.

    Reporting a mean of zero would claim the device opened no connections, which
    is a statement it never made.
    """
    summaries = summarise_samples([Sample(new_connections=None)])

    assert "new_connections" not in summaries
    assert "packet_count" in summaries


def test_a_partly_measurable_feature_uses_only_the_measured_samples() -> None:
    """``count`` is per feature, so it says how many windows it read."""
    summaries = summarise_samples(
        [Sample(new_connections=2), Sample(new_connections=None)]
    )

    assert summaries["new_connections"].count == 1
    assert summaries["new_connections"].mean == 2.0


def test_no_samples_produce_no_statistics_at_all() -> None:
    """An empty history is an empty result, not a profile of zeroes."""
    assert summarise_samples([]) == {}


def test_a_capped_sample_flags_the_cardinality_feature_only() -> None:
    """Truncation is a property of the peer count, not of the packet count."""
    summaries = summarise_samples([Sample(peers_truncated=True)])

    assert summaries["unique_peers"].truncated is True
    assert summaries["packet_count"].truncated is False


def test_a_non_numeric_sample_value_is_skipped() -> None:
    """A corrupt row must not be averaged in, and must not raise."""
    broken = Sample()
    broken.packet_count = "not a number"  # type: ignore[assignment]

    summaries = summarise_samples([broken, Sample(packet_count=20)])

    assert summaries["packet_count"].count == 1
    assert summaries["packet_count"].mean == 20.0


# ---------------------------------------------------------------------------
# storage round-trip
# ---------------------------------------------------------------------------


def test_a_summary_survives_being_stored_and_reloaded() -> None:
    """What the profile row holds must rebuild exactly what was calculated."""
    original = summarise_samples(
        [Sample(packet_count=5), Sample(packet_count=7)]
    )

    rebuilt = summaries_from_json(summaries_to_json(original))

    assert set(rebuilt) == set(original)
    for name, summary in original.items():
        assert rebuilt[name] == summary


def test_a_stored_document_with_a_broken_entry_is_partly_recovered() -> None:
    """A profile written by an earlier run must still be readable."""
    document = summaries_to_json(summarise_samples([Sample()]))
    document["packet_count"] = {"feature": "packet_count"}

    rebuilt = summaries_from_json(document)

    assert "packet_count" not in rebuilt
    assert "byte_count" in rebuilt


def test_a_profile_with_no_statistics_rebuilds_as_empty() -> None:
    """A device still learning has no stored document, which is not an error."""
    assert summaries_from_json(None) == {}
    assert summaries_from_json({}) == {}


def test_the_stored_figures_are_the_documented_names() -> None:
    """The JSON keys are the contract M22 will read, so they are pinned."""
    # Asserted from ``to_dict`` rather than read back out of the mapping that
    # ``summaries_to_json`` returns: indexing a ``dict[str, object]`` yields
    # ``object``, and the keys being pinned are exactly what ``to_dict`` emits.
    assert set(summarise_feature("packet_count", SAMPLE).to_dict()) == STORED_KEYS


def test_a_feature_statistics_renders_minimum_and_maximum_as_min_and_max() -> None:
    """The dataclass fields are ``minimum``/``maximum``; the document uses ``min``/``max``."""
    summary = FeatureStatistics(
        feature="packet_count",
        count=2,
        mean=5.0,
        median=5.0,
        mad=0.0,
        mad_scaled=0.0,
        stdev=0.0,
        p95=5.0,
        minimum=4.0,
        maximum=6.0,
    )

    rendered = summary.to_dict()

    assert rendered["min"] == 4.0
    assert rendered["max"] == 6.0
