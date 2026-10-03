"""Correlation confidence: how strongly two events were judged related (M12.7).

This is the number M12.7 is most emphatic about keeping separate. There are now
three different quantities in the system, and they answer three different
questions:

========================  =========================================
quantity                  question it answers
========================  =========================================
alert confidence          how strong is the *evidence*? (M11.5)
correlation confidence    are these the *same incident*? (M12.7)
risk score                how much does this deserve *attention*? (M12.14)
========================  =========================================

None is derived from another. A pair of events can be correlated with confidence
``1.0`` and still be low risk, and a single high-confidence alert can be high
risk with no correlation at all. The risk formula consumes this number as *one*
bounded term out of seven (M12.17) — which is the only connection permitted
between them, and it is a documented one.

**The combination rule is a noisy-OR**, not a sum and not an average::

    confidence = 1 - Π (1 - wᵢ)

Three properties, and each is the reason the other obvious choices were rejected:

* **Bounded.** Every ``wᵢ`` is in ``[0, 1]``, so the product is in ``[0, 1]`` and
  the result is in ``[0, 1]`` by construction. No clamping is needed for the
  result to be valid, so a confidence can never be reported outside its range.
* **Monotonic.** Adding another relationship can only raise the confidence. An
  average would *lower* it when a weak relationship was added, which is wrong:
  finding one more thing in common never makes two events less related.
* **Saturating, never certain.** No finite set of relationships reaches exactly
  ``1.0`` on its own, which is honest — correlation is inference from partial
  identities, never proof. With every relationship present the value lands just
  below 1, and the reported value is capped there.

A worked example, using the M12.7 case::

    same_connection (0.90) + same_source (0.70) + time_proximity (0.25)
    1 - (0.10 × 0.30 × 0.75) = 1 - 0.0225 = 0.9775   → "high"

The recorded confidence is capped at :data:`MAX_CORRELATION_CONFIDENCE`, so a
caller relying on "strictly below 1" is safe even if a future relationship
weight were ``1.0``.
"""

from __future__ import annotations

from app.correlation.relationship import Relationship

#: Highest correlation confidence reported. Just below 1 on purpose: correlation
#: is inference, and a value of exactly ``1`` would claim certainty the identity
#: dimensions cannot support (M12.7).
MAX_CORRELATION_CONFIDENCE = 0.999

#: Lowest correlation confidence reported.
MIN_CORRELATION_CONFIDENCE = 0.0


def _bounded_weight(value: float) -> float:
    """Return a relationship weight clamped to ``[0, 1]``.

    Defensive rather than paranoid: the weights are module constants, but a
    caller may construct a :class:`Relationship` subclass or patch a weight, and
    a weight outside the unit interval would break the boundedness the noisy-OR
    is chosen for.
    """
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number != number:  # nan
        return 0.0
    return min(max(number, 0.0), 1.0)


def combine_relationships(relationships: list[Relationship]) -> float:
    """Return the correlation confidence for a set of relationships (M12.7).

    The noisy-OR described in the module docstring. Deterministic and
    order-independent: the product of the complements does not care what order
    the relationships are in, so the same set always yields the same confidence.

    Returns:
        A value in ``[0, MAX_CORRELATION_CONFIDENCE]``. An empty list returns
        ``0.0`` — having established no relationship is not weak evidence of a
        relationship, it is no relationship.
    """
    if not relationships:
        return MIN_CORRELATION_CONFIDENCE
    remaining = 1.0
    for relationship in relationships:
        remaining *= 1.0 - _bounded_weight(relationship.strength)
    return min(max(1.0 - remaining, MIN_CORRELATION_CONFIDENCE), MAX_CORRELATION_CONFIDENCE)


def meets_threshold(
    confidence: float, minimum: float
) -> bool:
    """Return True when ``confidence`` reaches ``minimum`` (M12.7).

    The boundary is inclusive: a confidence exactly at the configured minimum
    joins the incident. Inclusive edges are used consistently across M12 (the
    window, the anchor check and this threshold), so a test can pin each of them
    exactly rather than approximately.
    """
    try:
        value = float(confidence)
        floor = float(minimum)
    except (TypeError, ValueError):
        return False
    if value != value or floor != floor:  # nan
        return False
    return value >= floor


def describe_confidence(relationships: list[Relationship]) -> dict[str, object]:
    """Return a correlation confidence and its workings, for reports (M12.7).

    Used by the design documentation, by ``scripts/verify_m12.py`` and by the
    incident's own reason trail, so the number and the explanation of the number
    always come from the same computation.
    """
    confidence = combine_relationships(relationships)
    return {
        "confidence": round(confidence, 6),
        "relationship_count": len(relationships),
        "relationships": [
            {
                "kind": relationship.kind.value,
                "detail": relationship.detail,
                "weight": round(_bounded_weight(relationship.strength), 4),
            }
            for relationship in relationships
        ],
    }


__all__ = [
    "MAX_CORRELATION_CONFIDENCE",
    "MIN_CORRELATION_CONFIDENCE",
    "combine_relationships",
    "describe_confidence",
    "meets_threshold",
]
