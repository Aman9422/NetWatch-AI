"""Behavioural statistics (M21.6).

Every figure here is calculated from *aggregated windows*, never from raw packets.
That is the requirement M21.6 makes explicit — "the baseline should not be
influenced by an unbounded accumulation of raw packet data" — and it is why this
module's input is a list of windows rather than a packet stream.

## The statistics, and why each one

For every supported numeric feature this module reports:

``count``
    How many samples carried the feature. This is the sample count the figure is
    trustworthy at, and it is *per feature*: ``new_connections`` is ``None`` for a
    window where it could not be measured, so its count can be lower than the
    window count. A feature with zero samples reports no statistics at all rather
    than a mean of 0.
``mean``
    Arithmetic mean. Reported because it is the figure an operator expects, but
    never the only one.
``median``
    The 50th percentile: the robust centre. A single minute of bulk transfer moves
    the mean a long way and the median barely at all.
``mad``
    Median absolute deviation — the median of ``|x - median|``. The robust
    *spread*, and the number M22 will most likely use, because a mean absolute
    deviation is itself dragged by the same outlier that drags the mean.
``mad_scaled``
    ``mad * 1.4826``, which for normally distributed data estimates the standard
    deviation. Reported *beside* the raw MAD rather than instead of it, so a
    stored figure is never ambiguous about which one it is.
``stdev``
    Population standard deviation. Less robust, reported because it is what a
    reader compares against.
``p95``
    The 95th percentile with linear interpolation — the "how bad does it normally
    get" figure.
``min`` / ``max``
    The observed range. Never inferred, never widened to a configured threshold.

## Small-sample honesty

Median, MAD and p95 are defined for any non-empty sample, but for one or two
samples they carry little information. They are still reported — refusing to
answer would be worse — and ``count`` is reported beside every feature so a
consumer decides for itself. Nothing here claims a p95 from five samples is as
stable as one from thirty thousand; M21 defers the anomaly detection that would
depend on that.
"""

from __future__ import annotations

import statistics
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

#: For normally distributed data, ``1.4826 * MAD`` estimates the standard
#: deviation. Reported separately so a stored ``mad`` is never ambiguous.
MAD_TO_STDEV = 1.4826

#: Which window attribute feeds which feature name, in the order the API and the
#: frontend present them: volume, then protocol mix, then variety, then rate of
#: change.
FEATURE_COLUMNS: tuple[tuple[str, str], ...] = (
    ("packet_count", "packet_count"),
    ("byte_count", "byte_count"),
    ("tcp_packets", "tcp_packets"),
    ("udp_packets", "udp_packets"),
    ("icmp_packets", "icmp_packets"),
    ("dns_packets", "dns_packets"),
    ("unique_peers", "unique_peers"),
    ("unique_destination_ports", "unique_destination_ports"),
    ("new_connections", "new_connections"),
)

#: The feature names, derived from ``FEATURE_COLUMNS`` so the two cannot drift.
FEATURE_NAMES: tuple[str, ...] = tuple(name for name, _ in FEATURE_COLUMNS)

#: Features whose value is a set cardinality that may have been capped.
CARDINALITY_FEATURES = frozenset({"unique_peers", "unique_destination_ports"})


@dataclass(frozen=True)
class FeatureStatistics:
    """The statistical summary of one behavioural feature (M21.6).

    Attributes:
        feature: The feature's stable name, e.g. ``packet_count``.
        count: How many samples carried a usable value for this feature.
        mean: Arithmetic mean over those samples.
        median: 50th percentile.
        mad: Median absolute deviation (raw, unscaled).
        mad_scaled: ``mad * 1.4826``, a consistent standard-deviation estimate for
            normal data.
        stdev: Population standard deviation.
        p95: 95th percentile with linear interpolation.
        minimum: Smallest observed value.
        maximum: Largest observed value.
        truncated: True when a contributing sample hit a peer/port cap, so the
            central figures are floors rather than exact numbers.
    """

    feature: str
    count: int
    mean: float
    median: float
    mad: float
    mad_scaled: float
    stdev: float
    p95: float
    minimum: float
    maximum: float
    truncated: bool = False

    def to_dict(self) -> dict[str, object]:
        """Render as the JSON document stored on the profile (M21.8)."""
        return {
            "feature": self.feature,
            "count": self.count,
            "mean": self.mean,
            "median": self.median,
            "mad": self.mad,
            "mad_scaled": self.mad_scaled,
            "stdev": self.stdev,
            "p95": self.p95,
            "min": self.minimum,
            "max": self.maximum,
            "truncated": self.truncated,
        }


def percentile(values: Sequence[float], fraction: float) -> float:
    """Return the ``fraction`` percentile of ``values`` with interpolation.

    Uses the definition ``numpy.percentile`` uses by default (linear interpolation
    between the two nearest order statistics), so a figure here can be checked
    against the tool a reader is most likely to reach for.

    Args:
        values: A non-empty sequence. It is copied and sorted, so the result never
            depends on the caller's order.
        fraction: A fraction in ``[0, 1]``.

    Returns:
        The interpolated percentile.

    Raises:
        ValueError: If ``values`` is empty or ``fraction`` is outside ``[0, 1]``.
    """
    if not values:
        raise ValueError("percentile of an empty sample")
    if not 0.0 <= fraction <= 1.0:
        raise ValueError("fraction must be between 0 and 1")
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = fraction * (len(ordered) - 1)
    lower_index = int(position)
    upper_index = min(lower_index + 1, len(ordered) - 1)
    weight = position - lower_index
    lower = ordered[lower_index]
    upper = ordered[upper_index]
    return lower + (upper - lower) * weight


def median_absolute_deviation(values: Sequence[float], centre: float) -> float:
    """Return the median of ``|x - centre|`` over ``values``.

    Args:
        values: A non-empty sequence.
        centre: The centre to measure from — the sample's median, in practice.

    Returns:
        The median absolute deviation.

    Raises:
        ValueError: If ``values`` is empty.
    """
    if not values:
        raise ValueError("MAD of an empty sample")
    return float(statistics.median([abs(float(value) - centre) for value in values]))


def summarise_feature(
    feature: str, values: Sequence[float], *, truncated: bool = False
) -> FeatureStatistics:
    """Calculate the statistical summary of one feature (M21.6).

    Args:
        feature: The feature's name, used to label the result.
        values: The observed values. Only samples that carried a usable value for
            this feature should be included, so ``count`` is honest.
        truncated: True when any contributing sample hit a cap.

    Returns:
        The summary.

    Raises:
        ValueError: If ``values`` is empty. A feature with no observations has no
            statistics; the caller omits it rather than reporting zeroes, because
            "never measured" and "measured as zero" are different facts (M21.5).
    """
    if not values:
        raise ValueError(f"no samples for feature {feature!r}")
    floats = [float(value) for value in values]
    centre = float(statistics.median(floats))
    mad = median_absolute_deviation(floats, centre)
    return FeatureStatistics(
        feature=feature,
        count=len(floats),
        mean=float(statistics.fmean(floats)),
        median=centre,
        mad=mad,
        mad_scaled=mad * MAD_TO_STDEV,
        stdev=float(statistics.pstdev(floats)) if len(floats) > 1 else 0.0,
        p95=percentile(floats, 0.95),
        minimum=min(floats),
        maximum=max(floats),
        truncated=truncated,
    )


def _truncation_flag(sample: Any, feature: str) -> bool:
    """Return True when ``sample`` hit the cap for ``feature``'s cardinality."""
    if feature == "unique_peers":
        return bool(getattr(sample, "peers_truncated", False))
    if feature == "unique_destination_ports":
        return bool(getattr(sample, "ports_truncated", False))
    return False


def summarise_samples(samples: Sequence[Any]) -> dict[str, FeatureStatistics]:
    """Summarise every supported feature over a list of window samples (M21.6).

    A sample is any object exposing the attributes in ``FEATURE_COLUMNS`` — in
    practice a :class:`~app.models.baseline_observation.BaselineWindow` or a
    :class:`~app.baselines.aggregation.WindowCounters`. Duck-typed on purpose so
    the same calculation serves a live flush and a reloaded profile without the
    engine converting one into the other first.

    Args:
        samples: The windows to summarise. May be empty, in which case the result
            is empty — there is nothing to report.

    Returns:
        One entry per feature that had at least one usable value. A feature whose
        every sample was ``None`` (``new_connections`` on a window where it could
        not be measured) is absent, never present as zero.
    """
    summaries: dict[str, FeatureStatistics] = {}
    for feature, attribute in FEATURE_COLUMNS:
        values: list[float] = []
        truncated = False
        for sample in samples:
            raw = getattr(sample, attribute, None)
            if raw is None or isinstance(raw, bool):
                continue
            if not isinstance(raw, (int, float)):
                continue
            values.append(float(raw))
            if _truncation_flag(sample, feature):
                truncated = True
        if not values:
            continue
        summaries[feature] = summarise_feature(feature, values, truncated=truncated)
    return summaries


def summaries_to_json(summaries: dict[str, FeatureStatistics]) -> dict[str, object]:
    """Render a summary set as a JSON-serialisable document (M21.8).

    The stored shape is ``{"feature": {...}, ...}`` rather than a list, so a
    reader can look a feature up by name without scanning. Feature order within a
    JSON object is not significant, so nothing downstream may depend on it.
    """
    return {name: summary.to_dict() for name, summary in summaries.items()}


def summaries_from_json(
    document: dict[str, object] | None,
) -> dict[str, FeatureStatistics]:
    """Rebuild a summary set from its stored document (M21.8).

    Tolerant by design: a stored figure that is missing or of the wrong type is
    skipped rather than raising, because a profile written by an earlier run must
    still be readable. A feature that cannot be rebuilt is simply absent, which
    the API reports as "not measured" rather than as zero.

    Args:
        document: The stored mapping, or ``None`` for a profile with no
            statistics yet (a device still in ``learning``).

    Returns:
        The summaries that could be rebuilt, keyed by feature name.
    """
    if not document:
        return {}
    rebuilt: dict[str, FeatureStatistics] = {}
    for name, raw in document.items():
        if not isinstance(raw, dict):
            continue
        try:
            rebuilt[str(name)] = FeatureStatistics(
                feature=str(raw.get("feature", name)),
                count=int(raw["count"]),
                mean=float(raw["mean"]),
                median=float(raw["median"]),
                mad=float(raw["mad"]),
                mad_scaled=float(raw["mad_scaled"]),
                stdev=float(raw["stdev"]),
                p95=float(raw["p95"]),
                minimum=float(raw["min"]),
                maximum=float(raw["max"]),
                truncated=bool(raw.get("truncated", False)),
            )
        except (KeyError, TypeError, ValueError):
            continue
    return rebuilt


__all__ = [
    "CARDINALITY_FEATURES",
    "FEATURE_COLUMNS",
    "FEATURE_NAMES",
    "FeatureStatistics",
    "MAD_TO_STDEV",
    "median_absolute_deviation",
    "percentile",
    "summaries_from_json",
    "summaries_to_json",
    "summarise_feature",
    "summarise_samples",
]
