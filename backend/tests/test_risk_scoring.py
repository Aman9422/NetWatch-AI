"""The risk scoring model (M12.30/M12.31).

The score is the one number in M12 that a person acts on, so the tests here are
written to prove the properties the milestone states rather than to sample the
formula's output:

* **Bounded.** ``0 <= score <= 100`` for every input, including the ones a caller
  should never send — empty, oversized, negative, fractional, ``nan``, ``inf``
  and non-numeric (M12.14/M12.21).
* **Deterministic.** The same inputs produce the same score, twice (M12.17).
* **Separated.** Risk is not alert confidence and is not correlation confidence,
  and the three are asserted to move independently (M12.16/M12.31).
* **Placeholder-aware.** ML contributes nothing, and a non-zero ML signal is
  refused while no ML subsystem exists (M12.18).
"""

from __future__ import annotations

import pytest

from app.alerts.severity import AlertSeverity, rank
from app.risk.bands import (
    BAND_RANGES,
    MAX_RISK_SCORE,
    MIN_RISK_SCORE,
    RiskBand,
    band_for,
    band_label,
    band_range,
    clamp_score,
)
from app.risk.contributions import (
    BASE_MAX,
    CONFIDENCE_MAX,
    CONTEXT_MAX,
    CORRELATION_MAX,
    HISTORICAL_MAX,
    MAX_TOTAL,
    ML_MAX,
    SEVERITY_MAX,
    ScoringBounds,
    compute_contributions,
)
from app.risk.engine import RiskScoringEngine
from app.risk.inputs import RiskInputs, bounded_confidence

#: Every input a caller could plausibly (or implausibly) supply, used to assert
#: the bound over a wide sample rather than over chosen examples.
BOUNDARY_INPUTS: tuple[RiskInputs, ...] = (
    RiskInputs(),
    RiskInputs(severity=None),
    RiskInputs(confidences=(), alert_count=0),
    RiskInputs(severity="low", confidences=(0.0,), alert_count=1),
    RiskInputs(severity="critical", confidences=(1.0,) * 32, alert_count=10**9),
    RiskInputs(severity="high", confidences=(-5.0, 42.0, float("nan"))),
    RiskInputs(alert_count=-3),
    RiskInputs(historical_occurrences=-7),
    RiskInputs(correlation_confidence=float("inf")),
    RiskInputs(last_seen=1_000.0, now=-1_000.0),
    RiskInputs(alert_count=10**12, historical_occurrences=10**12),
    RiskInputs(
        severity="critical",
        confidences=(1.0,),
        alert_count=6,
        rule_ids=("port_scan",),
        device_ids=("a", "b", "c"),
        connection_ids=("x", "y"),
        last_seen=1_000.0,
        now=1_000.0,
        historical_occurrences=5,
        correlation_confidence=1.0,
    ),
)


def _score(inputs: RiskInputs, bounds: ScoringBounds | None = None) -> int:
    """Return the score for ``inputs`` under the documented bounds."""
    return compute_contributions(inputs, bounds).score


def _severity_points(severity: AlertSeverity) -> float:
    """Return the severity term's documented value for one level.

    Derived from the shared ordering table rather than hard-coded, so a change to
    the severity set is reflected here instead of silently disagreeing.
    """
    return SEVERITY_MAX * rank(severity) / float(len(AlertSeverity))


# --------------------------------------------------------------------------
# The bound and the band table (M12.14/M12.21/M12.27)
# --------------------------------------------------------------------------


def test_the_contribution_maxima_sum_to_the_top_of_the_range() -> None:
    """A fully-satisfied input reaches 100 without being clamped (M12.17)."""
    assert ML_MAX == 0.0
    assert MAX_TOTAL == MAX_RISK_SCORE == 100
    assert MAX_TOTAL == (
        BASE_MAX
        + SEVERITY_MAX
        + CONFIDENCE_MAX
        + CORRELATION_MAX
        + CONTEXT_MAX
        + HISTORICAL_MAX
        + ML_MAX
    )


@pytest.mark.parametrize("inputs", BOUNDARY_INPUTS, ids=range(len(BOUNDARY_INPUTS)))
def test_the_score_is_always_inside_its_bound(inputs: RiskInputs) -> None:
    """``0 <= score <= 100`` holds for every input, however malformed."""
    assert MIN_RISK_SCORE <= _score(inputs) <= MAX_RISK_SCORE


def test_clamping_is_total_over_every_kind_of_bad_value() -> None:
    """Out-of-range and non-numeric values are bounded, never propagated."""
    assert clamp_score(-1) == MIN_RISK_SCORE
    assert clamp_score(-10**9) == MIN_RISK_SCORE
    assert clamp_score(MAX_RISK_SCORE + 1) == MAX_RISK_SCORE
    assert clamp_score(10**9) == MAX_RISK_SCORE
    # ``nan`` compares false against every bound, so it needs its own check.
    assert clamp_score(float("nan")) == MIN_RISK_SCORE
    assert clamp_score(float("inf")) == MAX_RISK_SCORE
    assert clamp_score(float("-inf")) == MIN_RISK_SCORE
    assert clamp_score(None) == MIN_RISK_SCORE  # type: ignore[arg-type]
    assert clamp_score("high") == MIN_RISK_SCORE  # type: ignore[arg-type]
    # Floats round to the integer the column stores (M12.24).
    assert clamp_score(49.4) == 49
    assert clamp_score(49.6) == 50


def test_the_documented_bands_tile_the_range_without_gap_or_overlap() -> None:
    """The bands are display ranges, and they must cover 0..100 exactly once."""
    assert BAND_RANGES[0][1] == MIN_RISK_SCORE
    assert BAND_RANGES[-1][2] == MAX_RISK_SCORE
    for (_, _, high), (_, next_low, _) in zip(BAND_RANGES, BAND_RANGES[1:]):
        assert next_low == high + 1
    for score in range(MIN_RISK_SCORE, MAX_RISK_SCORE + 1):
        matching = [band for band, low, high in BAND_RANGES if low <= score <= high]
        assert len(matching) == 1


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0, RiskBand.MINIMAL), (24, RiskBand.MINIMAL), (25, RiskBand.LOW),
     (49, RiskBand.LOW), (50, RiskBand.MODERATE), (74, RiskBand.MODERATE),
     (75, RiskBand.HIGH), (100, RiskBand.HIGH)],
)
def test_band_boundaries_are_inclusive_on_both_edges(score: int, expected: RiskBand) -> None:
    """Each documented boundary belongs to the band it opens (M12.27)."""
    assert band_for(score) is expected
    assert band_range(expected) == next(
        (low, high) for band, low, high in BAND_RANGES if band is expected
    )


def test_a_band_is_reported_by_its_clamped_score() -> None:
    """An out-of-range score is banded rather than raising (M12.21)."""
    assert band_for(-50) is RiskBand.MINIMAL
    assert band_for(10_000) is RiskBand.HIGH
    assert band_for(float("nan")) is RiskBand.MINIMAL


def test_every_band_has_a_documented_label() -> None:
    """The label describes prioritisation, never a claim that an attack occurred."""
    for band, _, _ in BAND_RANGES:
        label = band_label(band)
        assert label
        assert "risk" in label.lower()
    # An unknown band degrades to the lowest rather than raising in a report path.
    assert band_label("not-a-band") == band_label(RiskBand.MINIMAL)


# --------------------------------------------------------------------------
# The contribution model (M12.15/M12.17)
# --------------------------------------------------------------------------


def test_an_empty_input_scores_the_minimum() -> None:
    """Nothing observed is a legal input that scores ``0`` (M12.30)."""
    contributions = compute_contributions(RiskInputs())

    assert contributions.score == MIN_RISK_SCORE
    assert contributions.raw_total == 0.0
    assert contributions.base == 0.0
    assert contributions.severity == 0.0
    assert contributions.confidence == 0.0
    assert contributions.correlation == 0.0
    assert contributions.context == 0.0
    assert contributions.historical == 0.0
    assert contributions.ml == 0.0
    assert contributions.clamped is False


def test_the_base_term_recognises_that_a_detection_exists() -> None:
    """The base is earned by evidence existing, in any of its forms."""
    assert compute_contributions(RiskInputs(alert_count=1)).base == BASE_MAX
    assert compute_contributions(RiskInputs(confidences=(0.1,))).base == BASE_MAX
    assert compute_contributions(RiskInputs(rule_ids=("port_scan",))).base == BASE_MAX
    assert compute_contributions(RiskInputs()).base == 0.0


def test_the_severity_term_follows_the_shared_ordering_table() -> None:
    """Severity contributes through one explicit model, not a second table."""
    for severity in AlertSeverity:
        contributions = compute_contributions(RiskInputs(severity=severity))
        assert contributions.severity == pytest.approx(_severity_points(severity))
    # And it is ordered: a more serious level can never contribute less.
    points = [_severity_points(severity) for severity in AlertSeverity]
    assert points == sorted(points)


def test_the_confidence_term_uses_the_mean_of_the_alerts() -> None:
    """A group that agrees outweighs one confident alert among weak ones."""
    strong = compute_contributions(RiskInputs(confidences=(1.0,), alert_count=1))
    weak_many = compute_contributions(
        RiskInputs(confidences=(1.0, 0.0), alert_count=2)
    )

    assert strong.confidence == pytest.approx(CONFIDENCE_MAX)
    assert weak_many.confidence == pytest.approx(CONFIDENCE_MAX / 2.0)


def test_the_correlation_term_weights_relationship_and_volume() -> None:
    """A lone alert contributes no correlation, however confident (M12.16).

    One alert is not a correlation, so counting volume from the first alert would
    make every alert look like one.
    """
    lone = compute_contributions(
        RiskInputs(alert_count=1, correlation_confidence=1.0)
    )
    assert lone.correlation == pytest.approx(CORRELATION_MAX * 0.6)

    grouped = compute_contributions(
        RiskInputs(alert_count=6, correlation_confidence=1.0),
        ScoringBounds(volume_alerts=5),
    )
    assert grouped.correlation == pytest.approx(CORRELATION_MAX)


def test_the_context_term_scores_identity_and_recency_in_equal_thirds() -> None:
    """Device, connection and recency are bounded thirds of one term (M12.19).

    No asset importance is invented: only *identity* is counted, because the
    application has no configured asset-classification source.
    """
    rich = compute_contributions(
        RiskInputs(
            alert_count=1,
            device_ids=("dev-a", "dev-b"),
            connection_ids=("conn-1", "conn-2"),
            last_seen=1_000.0,
            now=1_000.0,
        )
    )
    assert rich.context == pytest.approx(CONTEXT_MAX)
    assert rich.detail["context_device"] == pytest.approx(CONTEXT_MAX / 3.0)
    assert rich.detail["context_connection"] == pytest.approx(CONTEXT_MAX / 3.0)
    assert rich.detail["context_recency"] == pytest.approx(CONTEXT_MAX / 3.0)

    # Extra identities beyond the cap cannot earn more than the third is worth.
    excessive = compute_contributions(
        RiskInputs(alert_count=1, device_ids=("a", "b", "c", "d", "e"))
    )
    assert excessive.detail["context_device"] == pytest.approx(CONTEXT_MAX / 3.0)


def test_recency_decays_to_zero_at_the_configured_window() -> None:
    """An old incident earns less recency, and none past the window (M12.15)."""
    bounds = ScoringBounds(recency_seconds=3_600.0)
    fresh = compute_contributions(
        RiskInputs(alert_count=1, last_seen=1_000.0, now=1_000.0), bounds
    )
    half = compute_contributions(
        RiskInputs(alert_count=1, last_seen=1_000.0, now=2_800.0), bounds
    )
    stale = compute_contributions(
        RiskInputs(alert_count=1, last_seen=1_000.0, now=10_000.0), bounds
    )

    assert fresh.detail["recency_fraction"] == pytest.approx(1.0)
    assert half.detail["recency_fraction"] == pytest.approx(0.5)
    assert stale.detail["recency_fraction"] == 0.0
    # An unmeasured time earns nothing rather than defaulting to "fresh".
    unknown = compute_contributions(RiskInputs(alert_count=1), bounds)
    assert unknown.detail["recency_fraction"] == 0.0


def test_a_clock_that_moved_backwards_cannot_inflate_recency() -> None:
    """A negative age is reported as ``0``, not as a bonus (M12.21)."""
    inputs = RiskInputs(alert_count=1, last_seen=2_000.0, now=1_000.0)
    assert inputs.age_seconds() == 0.0
    assert inputs.recency_fraction(window_seconds=3_600.0) == 1.0


def test_the_historical_term_is_bounded_so_history_cannot_dominate() -> None:
    """Repeated occurrence contributes, but at most its own tenth (M12.20)."""
    none = compute_contributions(RiskInputs(alert_count=1, historical_occurrences=0))
    some = compute_contributions(RiskInputs(alert_count=1, historical_occurrences=5))
    lots = compute_contributions(RiskInputs(alert_count=1, historical_occurrences=10**9))

    assert none.historical == 0.0
    assert some.historical == pytest.approx(HISTORICAL_MAX)
    assert lots.historical == pytest.approx(HISTORICAL_MAX)
    assert HISTORICAL_MAX < SEVERITY_MAX


def test_a_fully_satisfied_input_reaches_the_top_without_clamping() -> None:
    """Every term at its maximum sums to exactly 100 (M12.17)."""
    contributions = compute_contributions(
        RiskInputs(
            severity="critical",
            confidences=(1.0,) * 6,
            alert_count=6,
            rule_ids=("port_scan",),
            device_ids=("dev-a", "dev-b"),
            connection_ids=("conn-1", "conn-2"),
            last_seen=1_000.0,
            now=1_000.0,
            historical_occurrences=5,
            correlation_confidence=1.0,
        ),
        ScoringBounds(volume_alerts=5, historical_occurrences=5),
    )

    assert contributions.base == BASE_MAX
    assert contributions.severity == SEVERITY_MAX
    assert contributions.confidence == CONFIDENCE_MAX
    assert contributions.correlation == CORRELATION_MAX
    assert contributions.context == CONTEXT_MAX
    assert contributions.historical == HISTORICAL_MAX
    assert contributions.raw_total == pytest.approx(float(MAX_RISK_SCORE))
    assert contributions.score == MAX_RISK_SCORE
    assert contributions.clamped is False


# --------------------------------------------------------------------------
# What different inputs do to the score (M12.30)
# --------------------------------------------------------------------------


def test_a_single_low_severity_alert_scores_low() -> None:
    """One weak observation is routine, and the score says so."""
    single = compute_contributions(
        RiskInputs(severity="low", confidences=(0.5,), alert_count=1)
    )

    assert single.score < 50
    assert band_for(single.score) in (RiskBand.MINIMAL, RiskBand.LOW)


def test_a_high_severity_alert_scores_above_a_low_one() -> None:
    """Severity is ordered through the term, not asserted anywhere else."""
    low = compute_contributions(RiskInputs(severity="low", confidences=(0.5,), alert_count=1))
    critical = compute_contributions(
        RiskInputs(severity="critical", confidences=(0.5,), alert_count=1)
    )

    assert critical.score > low.score


def test_more_related_alerts_score_above_a_lone_one() -> None:
    """Several related alerts are more activity than one, and rank higher."""
    one = compute_contributions(
        RiskInputs(
            severity="high",
            confidences=(0.8,),
            alert_count=1,
            correlation_confidence=0.8,
        )
    )
    many = compute_contributions(
        RiskInputs(
            severity="high",
            confidences=(0.8,) * 6,
            alert_count=6,
            correlation_confidence=0.8,
        ),
        ScoringBounds(volume_alerts=5),
    )

    # Identical mean confidence, so the only difference is the related volume.
    assert many.confidence == pytest.approx(one.confidence)
    assert many.correlation > one.correlation
    assert many.score > one.score


def test_a_high_confidence_finding_scores_above_a_low_confidence_one() -> None:
    """Evidence strength contributes, within the confidence term's own cap."""
    weak = compute_contributions(
        RiskInputs(severity="medium", confidences=(0.1,), alert_count=1)
    )
    strong = compute_contributions(
        RiskInputs(severity="medium", confidences=(0.9,), alert_count=1)
    )

    assert strong.confidence > weak.confidence
    assert strong.score > weak.score


def test_repeated_historical_activity_raises_the_score_but_stays_bounded() -> None:
    """History contributes context and can never dominate (M12.20)."""
    none = compute_contributions(RiskInputs(severity="high", historical_occurrences=0))
    repeated = compute_contributions(
        RiskInputs(severity="high", historical_occurrences=5)
    )
    excessive = compute_contributions(
        RiskInputs(severity="high", historical_occurrences=10**9)
    )

    assert repeated.score > none.score
    assert excessive.historical == repeated.historical
    assert excessive.score == repeated.score


# --------------------------------------------------------------------------
# Invalid input and defensive reading (M12.21)
# --------------------------------------------------------------------------


def test_an_unknown_severity_surfaces_as_a_caller_bug() -> None:
    """A misspelled severity must not be scored as "no severity" (M11.4).

    Silently degrading it would understate risk without leaving a trace, so the
    one strictly validated input is validated loudly.
    """
    with pytest.raises(ValueError):
        RiskInputs(severity="catastrophic")
    with pytest.raises(ValueError):
        RiskInputs(severity="")


def test_an_unreadable_confidence_is_dropped_rather_than_counted_as_zero() -> None:
    """A dropped value is honest; a zero would claim the evidence was absent."""
    inputs = RiskInputs(confidences=(0.8, float("nan"), "unreadable"))  # type: ignore[list-item]

    assert inputs.bounded_confidences() == (0.8,)
    assert inputs.mean_confidence() == pytest.approx(0.8)


def test_confidences_are_bounded_by_one_shared_implementation() -> None:
    """``[0, 1]`` is a fact about the application, not a per-module convention."""
    assert bounded_confidence(2.0) == 1.0
    assert bounded_confidence(-1.0) == 0.0
    assert bounded_confidence(float("nan")) == 0.0
    assert bounded_confidence(float("inf")) == 1.0
    assert bounded_confidence("unreadable") == 0.0
    assert bounded_confidence(0.5) == pytest.approx(0.5)


def test_the_alert_count_defaults_to_the_confidences_it_can_see() -> None:
    """Two views of one fact cannot disagree (M12.15)."""
    inputs = RiskInputs(confidences=(0.5, 0.5, 0.5))

    assert inputs.alert_count is None
    assert inputs.bounded_alert_count() == 3


@pytest.mark.parametrize(
    "kwargs",
    [
        {"volume_alerts": 0},
        {"volume_alerts": -1},
        {"historical_occurrences": 0},
        {"recency_seconds": 0},
        {"recency_seconds": -1},
    ],
)
def test_unusable_scoring_bounds_are_rejected_at_construction(
    kwargs: dict[str, float],
) -> None:
    """A zero or negative bound would divide by zero or make a term meaningless."""
    with pytest.raises(ValueError):
        ScoringBounds(**kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# The engine and its result shape (M12.13)
# --------------------------------------------------------------------------


def test_the_engine_returns_the_score_beside_the_quantities_it_is_not() -> None:
    """A caller must have to name ``score`` to get the score (M12.16)."""
    engine = RiskScoringEngine(ScoringBounds(volume_alerts=5))
    inputs = RiskInputs.from_parts(
        severity="high",
        confidences=(0.9, 0.8),
        alert_count=2,
        device_ids=("dev-a",),
        last_seen=1_000.0,
        now=1_000.0,
        correlation_confidence=0.7,
    )

    result = engine.score(inputs)

    assert result.ok is True
    assert MIN_RISK_SCORE <= result.score <= MAX_RISK_SCORE
    assert result.band is band_for(result.score)
    assert result.band_label == band_label(result.band)
    # Three quantities side by side, none derived from another.
    assert result.alert_confidence == pytest.approx(0.85)
    assert result.correlation_confidence == pytest.approx(0.7)
    assert result.score != result.alert_confidence
    assert result.score != result.correlation_confidence
    assert result.contributions.score == result.score
    assert result.ml_available is False


def test_the_engine_is_deterministic_over_the_same_inputs() -> None:
    """Same inputs, same score, every time (M12.17/M12.30)."""
    engine = RiskScoringEngine()
    inputs = RiskInputs.from_parts(
        severity="medium",
        confidences=(0.6, 0.7),
        alert_count=3,
        device_ids=("dev-a", "dev-b"),
        connection_ids=("conn-1",),
        last_seen=500.0,
        now=600.0,
        historical_occurrences=2,
        correlation_confidence=0.65,
    )

    first = engine.score(inputs)
    second = engine.score(inputs)

    assert first.score == second.score
    assert first.as_dict() == second.as_dict()


def test_scoring_many_preserves_order_and_isolates_each_item() -> None:
    """One bad input cannot affect the next (M12.25)."""
    engine = RiskScoringEngine()
    ascending = list(AlertSeverity)
    inputs = [RiskInputs(severity=severity) for severity in ascending]

    results = engine.score_many(inputs)

    assert len(results) == len(inputs)
    # Severity is in ascending order, so the scores must be non-decreasing: one
    # item's outcome cannot depend on the item scored before it.
    scores = [item.score for item in results]
    assert scores == sorted(scores)


def test_a_non_input_is_reported_rather_than_raising() -> None:
    """A scoring failure must not lose the incident it was scoring (M12.25)."""
    engine = RiskScoringEngine()

    result = engine.score("not inputs")  # type: ignore[arg-type]

    assert result.ok is False
    assert result.error is not None
    assert result.score == MIN_RISK_SCORE


def test_the_engine_reports_its_counters_and_resets_them() -> None:
    """Counters are diagnostics, and a reset leaves no mixture behind (M12.34)."""
    engine = RiskScoringEngine()
    engine.score(RiskInputs(severity="high"))
    engine.score(RiskInputs(ml_contribution=0.5))

    stats = engine.stats()
    assert stats["scored"] >= 1
    assert stats["errored"] >= 1

    engine.reset()
    assert engine.stats() == {"scored": 0, "errored": 0, "clamped": 0}


# --------------------------------------------------------------------------
# Risk and confidence stay separate (M12.16/M12.31)
# --------------------------------------------------------------------------


def test_perfect_alert_confidence_on_a_low_severity_alert_is_not_high_risk() -> None:
    """The strongest evidence signal cannot lift the weakest detection to high.

    This is the whole point of a bounded, separate confidence term: if risk were
    derived from confidence, a ``1.0`` could not coexist with a low score.
    """
    confident_and_low = compute_contributions(
        RiskInputs(severity="low", confidences=(1.0,), alert_count=1)
    )

    assert confident_and_low.confidence == pytest.approx(CONFIDENCE_MAX)
    assert confident_and_low.score < 50


def test_raising_alert_confidence_moves_risk_by_a_bounded_amount() -> None:
    """Confidence contributes — through one explicit term with its own maximum."""
    weak = compute_contributions(RiskInputs(severity="high", confidences=(0.0,)))
    strong = compute_contributions(RiskInputs(severity="high", confidences=(1.0,)))

    assert strong.confidence > weak.confidence
    assert strong.confidence - weak.confidence == pytest.approx(CONFIDENCE_MAX)
    assert 0 <= strong.score - weak.score <= round(CONFIDENCE_MAX)


def test_correlation_confidence_moves_its_own_term_and_nothing_else() -> None:
    """The third quantity is independent of the other two (M12.7/M12.16)."""
    weakly_related = compute_contributions(
        RiskInputs(alert_count=6, correlation_confidence=0.0),
        ScoringBounds(volume_alerts=5),
    )
    strongly_related = compute_contributions(
        RiskInputs(alert_count=6, correlation_confidence=1.0),
        ScoringBounds(volume_alerts=5),
    )

    assert weakly_related.correlation == pytest.approx(CORRELATION_MAX * 0.4)
    assert strongly_related.correlation == pytest.approx(CORRELATION_MAX)
    # The same alert confidences, so that term is unmoved by the correlation.
    assert weakly_related.confidence == strongly_related.confidence


def test_the_same_confidence_on_different_context_is_different_risk() -> None:
    """Context is its own term, so equal confidence is not equal risk (M12.31)."""
    bare = compute_contributions(
        RiskInputs(severity="high", confidences=(0.9,), alert_count=1)
    )
    contextualised = compute_contributions(
        RiskInputs(
            severity="high",
            confidences=(0.9,),
            alert_count=1,
            device_ids=("dev-a", "dev-b"),
            connection_ids=("conn-1", "conn-2"),
            last_seen=1_000.0,
            now=1_000.0,
        )
    )

    assert bare.confidence == contextualised.confidence
    assert contextualised.context > bare.context
    assert contextualised.score > bare.score


def test_the_result_reports_all_three_quantities_under_distinct_names() -> None:
    """The M12.16 example, made explicit in one result."""
    engine = RiskScoringEngine()

    result = engine.score(
        RiskInputs(
            severity="critical",
            confidences=(0.95,),
            alert_count=4,
            correlation_confidence=0.88,
            last_seen=1_000.0,
            now=1_000.0,
        )
    )

    assert result.alert_confidence == pytest.approx(0.95)
    assert result.correlation_confidence == pytest.approx(0.88)
    assert isinstance(result.score, int)
    payload = result.as_dict()
    assert payload["alert_confidence"] == pytest.approx(0.95, abs=1e-4)
    assert payload["correlation_confidence"] == pytest.approx(0.88, abs=1e-4)
    assert payload["score"] == result.score


# --------------------------------------------------------------------------
# The reserved ML contribution (M12.18)
# --------------------------------------------------------------------------


def test_ml_contributes_nothing_and_is_reported_unavailable() -> None:
    """M12 ships no ML subsystem, so the reserved term is pinned to zero."""
    assert ML_MAX == 0.0
    assert compute_contributions(RiskInputs(alert_count=1)).ml == 0.0

    engine = RiskScoringEngine()
    assert engine.ml_available is False
    assert engine.score(RiskInputs(alert_count=1)).ml_available is False


def test_a_non_zero_ml_signal_is_refused_while_ml_is_unavailable() -> None:
    """Accepting one would mean scoring against a model that does not exist.

    The refusal is explicit rather than a silent clamp, because a caller sending
    an ML signal believes a model exists — and that belief should surface.
    """
    inputs = RiskInputs(alert_count=1, ml_contribution=0.5)

    with pytest.raises(ValueError):
        compute_contributions(inputs)

    result = RiskScoringEngine().score(inputs)
    assert result.ok is False
    assert result.error is not None
    assert result.score == MIN_RISK_SCORE


def test_the_ml_term_exists_and_is_carried_through_the_breakdown() -> None:
    """The shape is future-proof: enabling ML needs no redesign of the formula.

    The term is present in every breakdown and the guard is configuration-driven
    (``ScoringBounds.ml_enabled``), so a later milestone flips that flag and
    raises ``ML_MAX`` without touching the call sites above it.
    """
    contributions = compute_contributions(RiskInputs(alert_count=1))
    assert "ml" in contributions.as_dict()
    assert contributions.ml == ML_MAX

    # And the guard is what a future signal meets, not a hard-coded constant.
    assert ScoringBounds().ml_enabled is False
