"""Model-ready feature vectors from M21 observation windows (M22.6).

This module is the *only* place a feature vector is defined, and it is a set of
pure functions over the M21 window model. Three properties follow, and each is a
requirement rather than a convenience:

* **The feature set is M21's, not a new one.** The names and their order come
  from :data:`app.baselines.statistics.FEATURE_COLUMNS`, so M21's statistical
  profile and M22's model matrix can never disagree about what a feature is
  called or where it sits. Re-listing the nine names here would be a second
  definition that drifts the moment M21 gains a tenth.
* **Missing is missing.** M21 stores ``new_connections = NULL`` for a window
  where the tracker could not measure it, and this module carries that through
  as absent. It is never coerced to zero: a fabricated zero is the most
  normal-looking value a feature can take, which is precisely the wrong
  direction for an anomaly detector (M22.6).
* **A truncated cardinality is not a measurement.** M21 sets
  ``peers_truncated`` / ``ports_truncated`` when a set hit its cap, so the count
  is a *floor*. Feeding a floor into an Isolation Forest as though it were an
  exact number would systematically understate a device's reach during exactly
  the bursts an anomaly detector should notice. The chosen and documented policy
  is therefore: **a truncated cardinality is treated as missing for that
  window**, applied identically at training and inference time.

``FEATURE_SCHEMA_VERSION`` records which rules produced a vector. A model stores
the version it was trained under and refuses vectors built under another, so a
future change to this module cannot silently reinterpret an existing model's
columns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from app.baselines.statistics import FEATURE_COLUMNS, FEATURE_NAMES

#: Version of the feature-extraction rules in this module. Bumped whenever a
#: value's *meaning* changes — not when a feature is merely added, which each
#: model's own feature list already records.
FEATURE_SCHEMA_VERSION = 1

#: Features whose value is a set cardinality M21 may have capped. A capped value
#: is a lower bound, so it is treated as missing rather than as a number.
CARDINALITY_FEATURES: frozenset[str] = frozenset(
    {"unique_peers", "unique_destination_ports"}
)

#: The attribute on a window row that says a cardinality hit its cap.
_TRUNCATION_ATTRIBUTE: dict[str, str] = {
    "unique_peers": "peers_truncated",
    "unique_destination_ports": "ports_truncated",
}

#: Stable codes explaining why a feature's value is absent for one window, used
#: in the persisted feature context so an operator can tell "not measured" from
#: "measured as zero".
MISSING_NOT_MEASURED = "not_measured"
MISSING_TRUNCATED = "truncated"
MISSING_NOT_APPLICABLE = "not_applicable"


class WindowLike(Protocol):
    """What this module needs from an observation window.

    Structural rather than a concrete import, so the same extraction serves a
    persisted :class:`~app.models.baseline_observation.BaselineWindow`, an
    in-memory :class:`~app.baselines.aggregation.WindowCounters` and a synthetic
    object a test builds without touching a database.
    """

    device_key: str
    window_start: Any
    window_seconds: float


@dataclass(frozen=True)
class FeatureVector:
    """The measured features of one observation window (M22.6).

    Attributes:
        device_key: The stable M8 identity the window belongs to.
        window_start: UTC start of the window, as a naive datetime — the same
            representation M21 stores, so the value can key a uniqueness
            constraint directly.
        window_seconds: Length of the window the counters cover.
        values: Feature name → measured value. A feature that was not measurable
            is **absent** from this mapping rather than present as ``None`` or
            ``0``, so a caller cannot accidentally treat it as a number.
        missing_reasons: Feature name → why it is absent, for the persisted
            context. Only features that were considered appear here.
    """

    device_key: str
    window_start: datetime
    window_seconds: float
    values: dict[str, float] = field(default_factory=dict)
    missing_reasons: dict[str, str] = field(default_factory=dict)

    @property
    def values_observed(self) -> int:
        """Return how many features carried a usable value."""
        return len(self.values)

    def ordered_values(self, feature_names: tuple[str, ...]) -> list[float | None]:
        """Return this vector's values in a model's own feature order.

        A caller must pass the order the *model* was trained with, never a
        freshly computed one: the model matrix is positional, so a reordered list
        would silently feed the wrong column to the wrong tree (M22.6).

        Args:
            feature_names: The model's stored feature order.

        Returns:
            One entry per name, ``None`` where the feature was not measured.
        """
        return [self.values.get(name) for name in feature_names]


def missing_reason_for(window: WindowLike, feature: str) -> str | None:
    """Return why ``feature`` is unusable for ``window``, or ``None`` when it is.

    Args:
        window: The observation window.
        feature: A feature name from :data:`FEATURE_NAMES`.

    Returns:
        A stable reason code when the feature cannot be used, otherwise ``None``.
    """
    attribute = _TRUNCATION_ATTRIBUTE.get(feature)
    if attribute is not None and bool(getattr(window, attribute, False)):
        # A capped set cardinality is a floor. Recorded as unusable rather than
        # passed to the model as an exact count (M22.6).
        return MISSING_TRUNCATED
    return None


def _raw_value(window: WindowLike, attribute: str) -> float | None:
    """Return one stored attribute as a float, or ``None`` when unusable.

    ``bool`` is rejected explicitly: ``True`` is an ``int`` in Python and would
    otherwise arrive as the value ``1``, which a model would treat as meaningful.
    """
    raw = getattr(window, attribute, None)
    if raw is None or isinstance(raw, bool):
        return None
    if not isinstance(raw, (int, float)):
        return None
    return float(raw)


def build_feature_vector(window: WindowLike) -> FeatureVector:
    """Build the feature vector for one M21 observation window (M22.6).

    Never raises for ordinary input: a window missing every field yields a vector
    with no values, which preprocessing then excludes rather than the caller
    having to guard the call.

    Args:
        window: The observation window to read.

    Returns:
        The measured features, with an explicit reason for every dropped value.
    """
    values: dict[str, float] = {}
    missing: dict[str, str] = {}
    for feature, attribute in FEATURE_COLUMNS:
        reason = missing_reason_for(window, feature)
        if reason is not None:
            missing[feature] = reason
            continue
        value = _raw_value(window, attribute)
        if value is None:
            # `new_connections` is genuinely NULL for a window the tracker could
            # not measure. Recorded, never replaced with zero (M22.6).
            missing[feature] = MISSING_NOT_MEASURED
            continue
        values[feature] = value
    return FeatureVector(
        device_key=str(getattr(window, "device_key", "")),
        window_start=window.window_start,
        window_seconds=float(getattr(window, "window_seconds", 0.0) or 0.0),
        values=values,
        missing_reasons=missing,
    )


def feature_names_for_model(vector: FeatureVector) -> tuple[str, ...]:
    """Return the feature names present in a vector, in canonical order.

    Convenience for a caller inspecting one window. A *model's* feature list is
    always the list stored with that model, never this one.
    """
    return tuple(name for name in FEATURE_NAMES if name in vector.values)


__all__ = [
    "CARDINALITY_FEATURES",
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "MISSING_NOT_APPLICABLE",
    "MISSING_NOT_MEASURED",
    "MISSING_TRUNCATED",
    "FeatureVector",
    "WindowLike",
    "build_feature_vector",
    "feature_names_for_model",
    "missing_reason_for",
]
