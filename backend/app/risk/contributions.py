"""The risk contribution model: the formula, written down in one place (M12.17).

A risk score is **not** a sum of arbitrary numbers. It is the sum of seven
*independently bounded* terms, each of which is a maximum multiplied by a
fraction in ``[0, 1]``. That shape gives three properties the milestone demands:

* **Deterministic.** The same inputs always produce the same score (M12.17/M12.30).
  There is no randomness, no clock read and no iteration over an unordered set.
* **Bounded.** The maxima sum to exactly 100, and the score is clamped afterwards,
  so ``0 <= score <= 100`` holds for *every* input, including empty, oversized and
  invalid ones (M12.14/M12.21).
* **Explainable.** Every point has a named owner, so a score can be shown as its
  parts rather than as a single opaque number.

The table (M12.17)::

    term          maximum   what earns it
    ------------  -------   --------------------------------------------------
    base          20        a detection exists at all
    severity      25        the most serious severity among the related alerts
    confidence    15        the mean evidence strength of those alerts
    correlation   15        how strongly the events were judged related, and how
                            many related alerts the incident carries
    context       15        device context, connection context and event recency
    historical    10        repeated related occurrences, when history exists
    ml             0        reserved; no ML subsystem exists in M12 (M12.18)
    ------------  -------
    total        100

Two separations are structural, not stylistic (M12.16):

* **Risk and confidence are different terms.** ``confidence`` above consumes the
  *alert* confidences and is capped at 15 points; a confidence of ``1.0`` on a low
  severity alert therefore cannot by itself produce a high score.
* **Risk and correlation confidence are different terms.** ``correlation`` above
  consumes the *correlation* confidence, which says how strongly two events were
  judged related. A perfectly correlated pair of trivial events scores low.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.alerts.severity import AlertSeverity, rank
from app.risk.bands import MAX_RISK_SCORE, clamp_score
from app.risk.inputs import RiskInputs

# ---------------------------------------------------------------------------
# The documented maxima. They sum to exactly MAX_RISK_SCORE (M12.14/M12.17).
# ---------------------------------------------------------------------------

#: A detection exists at all. Without it nothing else has anything to score.
BASE_MAX = 20.0

#: Severity of the most serious related alert.
SEVERITY_MAX = 25.0

#: Mean confidence of the related alerts — the evidence, never the risk.
CONFIDENCE_MAX = 15.0

#: How strongly the events correlate, plus how many related alerts there are.
CORRELATION_MAX = 15.0

#: Device, connection and recency context, in three equal thirds (M12.19).
CONTEXT_MAX = 15.0

#: Repeated related occurrence, bounded so history can never dominate (M12.20).
HISTORICAL_MAX = 10.0

#: Reserved for a future ML signal. Zero in M12 (M12.18).
ML_MAX = 0.0

#: The total a fully-satisfied input can reach. Asserted against the parts below.
MAX_TOTAL = (
    BASE_MAX
    + SEVERITY_MAX
    + CONFIDENCE_MAX
    + CORRELATION_MAX
    + CONTEXT_MAX
    + HISTORICAL_MAX
    + ML_MAX
)

#: The three equal thirds of the context term.
_CONTEXT_DEVICE_MAX = CONTEXT_MAX / 3.0
_CONTEXT_CONNECTION_MAX = CONTEXT_MAX / 3.0
_CONTEXT_RECENCY_MAX = CONTEXT_MAX / 3.0

#: Weight of correlation confidence inside the correlation term. The remainder
#: belongs to related-alert volume, so an incident formed of several alerts is
#: scored above a lone one even when the relationship is judged equally strong.
_CORRELATION_CONFIDENCE_WEIGHT = 0.6
_CORRELATION_VOLUME_WEIGHT = 0.4

#: How many resolved devices / connections earn the full context third. Two is
#: the natural ceiling: a finding names a source and a destination, so an
#: incident can involve at most two devices per event, and asking for more would
#: reward correlations simply for being large.
CONTEXT_ENTITY_CAP = 2

#: The four alert severities in ascending order of seriousness, so the severity
#: fraction is ``rank / len`` rather than a hand-written table that could drift.
_SEVERITY_LEVELS = len(AlertSeverity)


@dataclass(frozen=True)
class RiskContributions:
    """One score, broken into the terms that produced it (M12.17).

    Each ``*_contribution`` is the bounded number of points that term
    contributed; ``raw_total`` is their sum before clamping and ``score`` is the
    value actually used, clamped to ``[0, 100]`` (M12.21). Keeping the raw total
    visible is what lets a test prove *where* clamping happened rather than only
    that the result was in range.
    """

    base: float = 0.0
    severity: float = 0.0
    confidence: float = 0.0
    correlation: float = 0.0
    context: float = 0.0
    historical: float = 0.0
    ml: float = 0.0
    raw_total: float = 0.0
    score: int = 0
    detail: dict[str, float] = field(default_factory=dict)

    @property
    def clamped(self) -> bool:
        """Return True when clamping changed the score (M12.21)."""
        return bool(round(self.raw_total) != self.score)

    def as_dict(self) -> dict[str, float]:
        """Return every term as a JSON-friendly mapping, for diagnostics."""
        return {
            "base": round(self.base, 4),
            "severity": round(self.severity, 4),
            "confidence": round(self.confidence, 4),
            "correlation": round(self.correlation, 4),
            "context": round(self.context, 4),
            "historical": round(self.historical, 4),
            "ml": round(self.ml, 4),
            "raw_total": round(self.raw_total, 4),
            "score": float(self.score),
        }


@dataclass(frozen=True)
class ScoringBounds:
    """The bounded context the terms are measured against (M12.15/M12.17).

    These are configuration, never magic numbers: a deployment can tune what
    "enough related alerts" or "recent enough" means without touching the
    formula's shape.

    Attributes:
        volume_alerts: How many *additional* related alerts earn the full volume
            share of the correlation term. Must be positive.
        historical_occurrences: How many previous occurrences earn the full
            historical term. Must be positive, so history is always bounded
            (M12.20).
        recency_seconds: The age at which the recency third falls to zero. Must
            be positive.
        ml_enabled: Whether a non-zero ML contribution is accepted (M12.18).
            ``False`` in M12, so the ML term is pinned to zero.

    Raises:
        ValueError: If any bound is not positive. A zero or negative bound would
            divide by zero or make the term meaningless.
    """

    volume_alerts: int = 5
    historical_occurrences: int = 5
    recency_seconds: float = 3600.0
    ml_enabled: bool = False

    def __post_init__(self) -> None:
        """Reject unusable bounds at construction, not on the first score."""
        if self.volume_alerts < 1:
            raise ValueError("volume_alerts must be at least 1")
        if self.historical_occurrences < 1:
            raise ValueError("historical_occurrences must be at least 1")
        if self.recency_seconds <= 0:
            raise ValueError("recency_seconds must be positive")


def _fraction(count: int, cap: int) -> float:
    """Return ``count / cap`` bounded to ``[0, 1]`` for a non-negative count."""
    if cap <= 0:
        return 0.0
    return min(max(float(count), 0.0) / float(cap), 1.0)


def _severity_fraction(inputs: RiskInputs) -> float:
    """Return the severity term's fraction, in ``[0, 1]``.

    ``low`` is a quarter, ``critical`` a whole: the fraction is the severity's
    rank over the number of levels, so the mapping follows the one ordering table
    ``app.alerts.severity`` already owns rather than a second copy of it.
    """
    severity = inputs.normalized_severity()
    if severity is None:
        return 0.0
    return rank(severity) / float(_SEVERITY_LEVELS)


def _has_any_evidence(inputs: RiskInputs) -> bool:
    """Return True when there is anything at all to score (the base term)."""
    return bool(
        inputs.bounded_alert_count() > 0
        or inputs.bounded_confidences()
        or inputs.rule_ids
    )


def _correlation_contribution(inputs: RiskInputs, bounds: ScoringBounds) -> float:
    """Return the correlation term, in ``[0, CORRELATION_MAX]`` (M12.16).

    Two halves, deliberately unequal: the *correlation confidence* (does this
    look like one piece of activity?) and the *related-alert volume* (how much of
    the activity is there?). Volume counts only alerts **beyond the first**, so a
    lone alert contributes no correlation points at all: one alert is not a
    correlation, and scoring it as one would make every alert look related.
    """
    confidence = inputs.bounded_correlation_confidence()
    extra_alerts = max(inputs.bounded_alert_count() - 1, 0)
    volume = _fraction(extra_alerts, bounds.volume_alerts)
    mixed = (
        _CORRELATION_CONFIDENCE_WEIGHT * confidence
        + _CORRELATION_VOLUME_WEIGHT * volume
    )
    return CORRELATION_MAX * min(max(mixed, 0.0), 1.0)


def _context_contribution(
    inputs: RiskInputs, bounds: ScoringBounds
) -> tuple[float, dict[str, float]]:
    """Return the context term and its three parts (M12.19).

    Three equal thirds: how identity-rich the incident is (devices and
    conversations resolved), and how recent it is. Nothing here assigns an asset
    criticality the application has no source for — device *identity* is used,
    never an invented importance rating.
    """
    device = _CONTEXT_DEVICE_MAX * _fraction(len(inputs.device_ids), CONTEXT_ENTITY_CAP)
    connection = _CONTEXT_CONNECTION_MAX * _fraction(
        len(inputs.connection_ids), CONTEXT_ENTITY_CAP
    )
    recency = _CONTEXT_RECENCY_MAX * inputs.recency_fraction(
        window_seconds=bounds.recency_seconds
    )
    detail = {
        "context_device": round(device, 4),
        "context_connection": round(connection, 4),
        "context_recency": round(recency, 4),
    }
    return device + connection + recency, detail


def _ml_contribution(inputs: RiskInputs, bounds: ScoringBounds) -> float:
    """Return the reserved ML term, in ``[0, ML_MAX]`` (M12.18).

    Raises:
        ValueError: If a non-zero contribution is supplied while ML scoring is
            disabled. M12 ships no ML subsystem, so accepting one would mean
            scoring against a model that does not exist — the exact thing M12.18
            forbids. When a future milestone *does* implement ML it flips
            ``ml_enabled`` and raises ``ML_MAX``, and the formula is otherwise
            untouched.
    """
    try:
        supplied = float(inputs.ml_contribution)
    except (TypeError, ValueError):
        supplied = 0.0
    if supplied != supplied:  # nan
        supplied = 0.0
    if supplied < 0:
        supplied = 0.0
    if supplied > 0 and not bounds.ml_enabled:
        raise ValueError(
            "An ML risk contribution was supplied while ML scoring is disabled; "
            "M12 has no ML subsystem, so the contribution must be 0"
        )
    if not bounds.ml_enabled:
        return 0.0
    return min(supplied, ML_MAX)


def compute_contributions(
    inputs: RiskInputs, bounds: ScoringBounds | None = None
) -> RiskContributions:
    """Score ``inputs`` and return the score with every term that produced it.

    This is the whole formula (M12.17). It never raises for a *value* it dislikes:
    out-of-range numbers are clamped into their term's own bound, so a caller
    cannot turn a bad input into a lost incident. It does raise for a
    structurally impossible input — a severity that is not a severity
    (``ValueError`` from :mod:`app.alerts.severity`) — because silently scoring a
    typo as "no severity" would understate risk without a trace.

    The result is deterministic: the same inputs always produce the same score
    (M12.17/M12.30).

    Raises:
        ValueError: If the supplied severity is not one of the four levels, or if
            a non-zero ML contribution is supplied while ML scoring is disabled
            (M12.18).
    """
    config = bounds or ScoringBounds()

    base = BASE_MAX if _has_any_evidence(inputs) else 0.0
    severity = SEVERITY_MAX * _severity_fraction(inputs)
    confidence = CONFIDENCE_MAX * inputs.mean_confidence()
    correlation = _correlation_contribution(inputs, config)
    context, context_detail = _context_contribution(inputs, config)
    historical = HISTORICAL_MAX * _fraction(
        inputs.bounded_historical_occurrences(), config.historical_occurrences
    )
    ml = _ml_contribution(inputs, config)

    detail: dict[str, float] = dict(context_detail)
    detail["correlation_confidence"] = round(
        inputs.bounded_correlation_confidence(), 4
    )
    detail["mean_confidence"] = round(inputs.mean_confidence(), 4)
    detail["historical_occurrences"] = float(inputs.bounded_historical_occurrences())
    detail["recency_fraction"] = round(
        inputs.recency_fraction(window_seconds=config.recency_seconds), 4
    )

    terms = (base, severity, confidence, correlation, context, historical, ml)
    raw_total = float(sum(terms))
    return RiskContributions(
        base=base,
        severity=severity,
        confidence=confidence,
        correlation=correlation,
        context=context,
        historical=historical,
        ml=ml,
        raw_total=raw_total,
        score=clamp_score(raw_total),
        detail=detail,
    )


__all__ = [
    "BASE_MAX",
    "CONFIDENCE_MAX",
    "CONTEXT_ENTITY_CAP",
    "CONTEXT_MAX",
    "CORRELATION_MAX",
    "HISTORICAL_MAX",
    "MAX_TOTAL",
    "ML_MAX",
    "RiskContributions",
    "SEVERITY_MAX",
    "ScoringBounds",
    "compute_contributions",
]
