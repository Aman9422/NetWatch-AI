"""The risk scoring engine (M12.13).

``RiskScoringEngine`` is a thin, stateless wrapper around the documented formula
in :mod:`app.risk.contributions`. It exists for three reasons:

* **Assembly.** It reads the bounded configuration once (bundled as
  :class:`~app.risk.contributions.ScoringBounds`) instead of making every caller
  know which settings feed the formula.
* **Result shape.** It returns a :class:`RiskResult` that keeps the three
  quantities M12.16 forbids conflating visibly side by side: the alert
  confidence, the correlation confidence, and the risk score. A caller has to
  read a field named ``score`` to get the score — it cannot accidentally use a
  confidence value as one.
* **Isolation.** It never raises out of :meth:`score`. The M12.25 rule is that a
  risk-scoring failure must not destroy the underlying alert or finding, so a
  scoring error is counted and reported as a zero-result rather than propagated
  into the pipeline. The one exception is deliberate and local: a structurally
  impossible input (an unknown severity, or a non-zero ML contribution while ML
  scoring is off) is reported in ``error``, still without raising.

The engine holds no per-incident state and takes no lock. Two threads may score
simultaneously; the only shared state is a set of integer counters updated under
a lock, which exist for diagnostics and cannot affect a score.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from app.alerts.severity import AlertSeverity
from app.config.settings import Settings
from app.risk.bands import (
    MAX_RISK_SCORE,
    MIN_RISK_SCORE,
    RiskBand,
    band_for,
    band_label,
)
from app.risk.contributions import (
    RiskContributions,
    ScoringBounds,
    compute_contributions,
)
from app.risk.inputs import RiskInputs


@dataclass(frozen=True)
class RiskResult:
    """One score and the separate quantities it must never be confused with.

    Attributes:
        score: The bounded risk score, an ``int`` in ``[0, 100]``. This is the
            prioritisation metric, nothing more (M12.14).
        band: The documented display band for the score (M12.27).
        band_label: Human-readable label for the band.
        alert_confidence: The mean confidence of the incident's alerts, echoed
            back as its own field. **Not** derived from the score and **not**
            interchangeable with it — a ``0.9`` here and a ``42`` above are two
            different statements about the same incident (M12.16).
        correlation_confidence: How strongly the events were judged related,
            echoed back as its own field. Also separate from both of the above
            (M12.7/M12.16).
        contributions: The full term-by-term breakdown, so a score can be
            explained rather than asserted (M12.17).
        ml_available: Whether a future ML signal was permitted to contribute.
            ``False`` throughout M12 (M12.18).
        error: ``None`` on success, or a message describing why scoring failed.
            When set, ``score`` is ``0`` and the caller can still use everything
            else it already had (M12.25).
    """

    score: int = MIN_RISK_SCORE
    band: RiskBand = RiskBand.MINIMAL
    band_label: str = ""
    alert_confidence: float = 0.0
    correlation_confidence: float = 0.0
    contributions: RiskContributions = field(default_factory=RiskContributions)
    ml_available: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        """Return True when scoring completed without error."""
        return self.error is None

    @property
    def clamped(self) -> bool:
        """Return True when the raw total had to be clamped into range."""
        return self.contributions.clamped

    def as_dict(self) -> dict[str, object]:
        """Return the result as a JSON-friendly mapping for diagnostics/API."""
        return {
            "score": self.score,
            "band": self.band.value,
            "band_label": self.band_label,
            "alert_confidence": round(self.alert_confidence, 4),
            "correlation_confidence": round(self.correlation_confidence, 4),
            "ml_available": self.ml_available,
            "clamped": self.clamped,
            "error": self.error,
            "contributions": self.contributions.as_dict(),
        }


class RiskScoringEngine:
    """Scores a bounded set of facts into a bounded risk score (M12.13).

    The engine is stateless with respect to the data it scores: it holds
    configuration and counters, never incidents. Scoring the same inputs twice
    always returns the same score (M12.17/M12.30).

    Args:
        bounds: The bounded context the terms are measured against. Defaults to
            :meth:`ScoringBounds` defaults, which mirror the M12 settings.
        severity: Unused by the current formula; accepted so a deployment can
            pass a severity source later without changing call sites.
    """

    def __init__(self, bounds: ScoringBounds | None = None) -> None:
        self._bounds = bounds or ScoringBounds()
        self._lock = threading.Lock()
        self._scored = 0
        self._errored = 0
        self._clamped = 0

    # -- construction -------------------------------------------------------

    @classmethod
    def from_settings(cls, settings: Settings) -> RiskScoringEngine:
        """Build an engine from application settings (M12 configuration).

        This is the only place the formula's bounds meet the settings object, so
        the scoring model itself stays free of configuration coupling.
        """
        return cls(
            ScoringBounds(
                volume_alerts=settings.risk_max_volume_alerts,
                historical_occurrences=settings.risk_max_historical_occurrences,
                recency_seconds=settings.risk_recency_seconds,
                ml_enabled=settings.risk_ml_contribution_enabled,
            )
        )

    # -- properties ---------------------------------------------------------

    @property
    def bounds(self) -> ScoringBounds:
        """Return the bounded scoring context in use."""
        return self._bounds

    @property
    def ml_available(self) -> bool:
        """Return whether a future ML contribution would be accepted (M12.18)."""
        return self._bounds.ml_enabled

    # -- scoring ------------------------------------------------------------

    def score(self, inputs: RiskInputs) -> RiskResult:
        """Score ``inputs`` and return the score plus its separated parts.

        Never raises (M12.25). A failure inside the formula is reported in
        ``RiskResult.error`` with a zero score, because a scoring problem must
        not lose the incident it was scoring. The literal input is still echoed
        back in the result's confidence fields, so a caller can retry or display
        the incident without it.
        """
        if not isinstance(inputs, RiskInputs):
            return self._error("RiskInputs required, got %r" % type(inputs).__name__)

        try:
            contributions = compute_contributions(inputs, self._bounds)
        except ValueError as exc:
            # A structurally impossible input: a bad severity, or an ML
            # contribution while ML scoring is disabled. Reported, not raised.
            return self._error(str(exc), inputs=inputs)

        result = RiskResult(
            score=contributions.score,
            band=band_for(contributions.score),
            band_label=band_label(band_for(contributions.score)),
            alert_confidence=inputs.mean_confidence(),
            correlation_confidence=inputs.bounded_correlation_confidence(),
            contributions=contributions,
            ml_available=self.ml_available,
            error=None,
        )
        with self._lock:
            self._scored += 1
            if result.clamped:
                self._clamped += 1
        return result

    def score_many(self, inputs: list[RiskInputs]) -> list[RiskResult]:
        """Score a sequence of inputs, preserving order.

        Convenience for tests and benchmarks. Each item is scored independently,
        so one bad input cannot affect the next.
        """
        return [self.score(item) for item in inputs]

    # -- diagnostics --------------------------------------------------------

    def stats(self) -> dict[str, int]:
        """Return counters describing the work the engine has done."""
        with self._lock:
            return {
                "scored": self._scored,
                "errored": self._errored,
                "clamped": self._clamped,
            }

    def reset(self) -> None:
        """Clear counters. Does not change the configuration."""
        with self._lock:
            self._scored = 0
            self._errored = 0
            self._clamped = 0

    # -- internals ----------------------------------------------------------

    def _error(self, message: str, *, inputs: RiskInputs | None = None) -> RiskResult:
        """Count and return a zero-scored result carrying ``message``."""
        with self._lock:
            self._errored += 1
        return RiskResult(
            score=MIN_RISK_SCORE,
            band=band_for(MIN_RISK_SCORE),
            band_label=band_label(band_for(MIN_RISK_SCORE)),
            alert_confidence=inputs.mean_confidence() if inputs else 0.0,
            correlation_confidence=(
                inputs.bounded_correlation_confidence() if inputs else 0.0
            ),
            contributions=RiskContributions(score=MIN_RISK_SCORE),
            ml_available=self.ml_available,
            error=message,
        )


#: The number of severity levels the formula scales by, re-exported so a caller
#: reporting on the model does not need to import from another package.
SEVERITY_LEVEL_COUNT = len(AlertSeverity)

#: Highest score the model can produce, re-exported for convenience.
TOP_OF_RANGE = MAX_RISK_SCORE


__all__ = [
    "RiskResult",
    "RiskScoringEngine",
    "SEVERITY_LEVEL_COUNT",
    "TOP_OF_RANGE",
]
