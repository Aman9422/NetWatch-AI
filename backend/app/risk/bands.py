"""The bounded risk score and its documented display bands (M12.14/M12.27).

A risk score is an **application-derived prioritisation metric**. It is not a
probability, not a proof that an attack occurred, and not a claim about severity
in any absolute sense. Two things follow from taking that seriously:

* The score is *always* in ``[0, 100]``. :func:`clamp_score` is the single place
  that guarantees it, so every path that produces a score goes through it
  (M12.21).
* The bands are *display ranges*, named here and documented here, so the UI and
  the API cannot each invent their own thresholds (M12.27).

The four bands are inclusive on both edges and tile ``0..100`` with no gap and
no overlap::

    band        range      meaning for prioritisation
    ----------  ---------  ------------------------------------------------
    minimal      0 - 24    nothing much observed; routine
    low         25 - 49    worth a look when convenient
    moderate    50 - 74    worth looking at soon
    high        75 - 100   look at this first

Nothing in this module reads configuration: the bands are part of the model's
vocabulary, and a deployment tunes what *feeds* the score rather than the ranges
the score is reported in.
"""

from __future__ import annotations

import math
from enum import Enum

#: The lowest score the model can produce.
MIN_RISK_SCORE = 0

#: The highest score the model can produce. The contribution maxima in
#: :mod:`app.risk.contributions` sum to exactly this value, so a fully-satisfied
#: input reaches the top of the range without being clamped to get there.
MAX_RISK_SCORE = 100


class RiskBand(str, Enum):
    """The four documented display bands for a risk score (M12.27)."""

    MINIMAL = "minimal"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


#: Inclusive lower and upper bound of each band. Defined as data so
#: :func:`band_for` and the tests read the same table the docs describe.
BAND_RANGES: tuple[tuple[RiskBand, int, int], ...] = (
    (RiskBand.MINIMAL, 0, 24),
    (RiskBand.LOW, 25, 49),
    (RiskBand.MODERATE, 50, 74),
    (RiskBand.HIGH, 75, 100),
)

#: Human-readable meaning per band. These are prioritisation hints for an
#: operator, explicitly not statements about whether an attack happened.
BAND_LABELS: dict[RiskBand, str] = {
    RiskBand.MINIMAL: "Minimal observed risk",
    RiskBand.LOW: "Low observed risk",
    RiskBand.MODERATE: "Moderate observed risk",
    RiskBand.HIGH: "High observed risk",
}


def clamp_score(value: float | int) -> int:
    """Return ``value`` as an integer score inside ``[0, 100]`` (M12.21).

    This is the only place the bound is enforced, and it is enforced for every
    input, including the ones a caller should never send:

    * ``nan`` (a divide-by-zero somewhere upstream) becomes ``0``. ``nan``
      compares false against every bound, so naive clamping would let it through;
      an explicit check stops it at the door.
    * ``inf`` becomes ``100``, ``-inf`` becomes ``0``.
    * Non-numeric input (``None``, a string, an object) becomes ``0`` rather than
      raising, because a scoring failure must never destroy the underlying alert
      or finding (M12.25).
    * Floats are rounded to the nearest integer *after* clamping, so the result
      type matches the ``alerts.risk_score`` integer column (M12.24).

    Returns:
        An ``int`` in ``[0, 100]``.
    """
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return MIN_RISK_SCORE
    if math.isnan(number):
        return MIN_RISK_SCORE
    if number <= MIN_RISK_SCORE:
        return MIN_RISK_SCORE
    if number >= MAX_RISK_SCORE:
        return MAX_RISK_SCORE
    return int(round(number))


def band_for(score: float | int) -> RiskBand:
    """Return the display band a score falls in (M12.27).

    The score is clamped first, so an out-of-range value is banded by its clamped
    value rather than raising or falling into an undefined gap.
    """
    bounded = clamp_score(score)
    for band, low, high in BAND_RANGES:
        if low <= bounded <= high:
            return band
    # Unreachable while BAND_RANGES tiles 0..100, but returning the lowest band
    # keeps the function total rather than raising inside a reporting path.
    return RiskBand.MINIMAL


def band_label(band: RiskBand | str) -> str:
    """Return the human-readable label for ``band``, defaulting to minimal."""
    try:
        resolved = band if isinstance(band, RiskBand) else RiskBand(str(band))
    except ValueError:
        return BAND_LABELS[RiskBand.MINIMAL]
    return BAND_LABELS[resolved]


def band_range(band: RiskBand | str) -> tuple[int, int]:
    """Return the inclusive ``(low, high)`` bounds of ``band``."""
    try:
        resolved = band if isinstance(band, RiskBand) else RiskBand(str(band))
    except ValueError:
        resolved = RiskBand.MINIMAL
    for candidate, low, high in BAND_RANGES:
        if candidate is resolved:
            return low, high
    return BAND_RANGES[0][1], BAND_RANGES[0][2]


__all__ = [
    "BAND_LABELS",
    "BAND_RANGES",
    "MAX_RISK_SCORE",
    "MIN_RISK_SCORE",
    "RiskBand",
    "band_for",
    "band_label",
    "band_range",
    "clamp_score",
]
