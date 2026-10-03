"""Risk scoring (M12.13–M12.21).

This package turns a bounded set of observed facts into a bounded,
deterministic, explainable **risk score**, while keeping that score separate
from the confidences it is made partly from (M12.16).

The layers, bottom up:

* :mod:`app.risk.bands` — the ``0..100`` bound and the four documented display
  bands (M12.14/M12.27).
* :mod:`app.risk.inputs` — :class:`RiskInputs`, the complete and *closed* set of
  facts a score may be computed from (M12.15).
* :mod:`app.risk.contributions` — the formula itself, written down as seven
  independently bounded terms that sum to 100 (M12.17).
* :mod:`app.risk.engine` — :class:`RiskScoringEngine`, which assembles
  configuration, enforces isolation, and returns the three separated quantities
  in one :class:`RiskResult` (M12.13/M12.25).

What this package deliberately does **not** contain: any ML or AI signal
(M12.18), any asset criticality rating the application has no source for
(M12.19), any database access, and any notion of an "attack" — a score is an
application-derived prioritisation metric and the docstrings say so wherever a
number is produced (M12.14).

Nothing here imports :mod:`app.correlation`. The dependency runs one way:
correlation builds :class:`RiskInputs` from an incident and calls the engine.
Risk scoring knows nothing about incidents, which is what keeps the formula
testable in isolation.
"""

from app.risk.bands import (
    BAND_LABELS,
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
    RiskContributions,
    ScoringBounds,
    compute_contributions,
)
from app.risk.engine import RiskResult, RiskScoringEngine
from app.risk.inputs import (
    MAX_CONFIDENCE,
    MAX_CORRELATION_CONFIDENCE,
    MAX_COUNT,
    MIN_CONFIDENCE,
    RiskInputs,
    bounded_confidence,
)

__all__ = [
    "BASE_MAX",
    "BAND_LABELS",
    "BAND_RANGES",
    "CONFIDENCE_MAX",
    "CONTEXT_MAX",
    "CORRELATION_MAX",
    "HISTORICAL_MAX",
    "MAX_CONFIDENCE",
    "MAX_CORRELATION_CONFIDENCE",
    "MAX_COUNT",
    "MAX_RISK_SCORE",
    "MAX_TOTAL",
    "MIN_CONFIDENCE",
    "MIN_RISK_SCORE",
    "ML_MAX",
    "RiskBand",
    "RiskContributions",
    "RiskInputs",
    "RiskResult",
    "RiskScoringEngine",
    "SEVERITY_MAX",
    "ScoringBounds",
    "band_for",
    "band_label",
    "band_range",
    "bounded_confidence",
    "clamp_score",
    "compute_contributions",
]
