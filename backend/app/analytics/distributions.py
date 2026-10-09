"""Bounded distribution vocabularies for analytics blocks (M16.3/M16.6).

M16.6 asks for "findings by confidence range", and the stores hold two different
confidence scales: an M11 *alert* carries ``confidence`` as an integer ``0..100``,
and an M10 *finding* carries ``confidence`` as a float ``0.0..1.0``
(:class:`~app.detection.finding.DetectionFinding`). Reporting a distribution needs
range boundaries, and inventing a second set of thresholds for each scale is
exactly the kind of drift this project avoids — M12.27 already establishes that a
0-100 value in this system is described by *one* documented tiling, and
:data:`~app.risk.bands.BAND_RANGES` is it.

So :data:`CONFIDENCE_RANGES` is derived from that tiling rather than re-spelled,
and its labels are the literal bounds (``"0-24"``, ``"25-49"``, ...) rather than
band *names*. That matters: the band names (``minimal``, ``moderate``) are the
vocabulary of a *risk* band, and calling a confidence ``moderate`` would read as a
risk verdict. The numeric label makes the same numbers unambiguous without lending
them risk's meaning. A finding's ``0.0..1.0`` confidence is scaled to ``0..100``
purely to place it in these ranges, which is stated wherever it is done.

Nothing here produces a score. These are display ranges for counting values that
already exist, and :func:`confidence_range_label` never invents a value: a
confidence outside the range is reported in the nearest range rather than dropped,
because a histogram that silently omits observations is worse than one whose edges
are stated.
"""

from __future__ import annotations

from app.risk.bands import BAND_RANGES

#: The confidence ranges, as ``(label, low, high)`` inclusive triples covering
#: ``0..100``. Derived from the one tiling the project documents (M12.27), so the
#: boundaries cannot differ from the risk bands' boundaries by accident.
CONFIDENCE_RANGES: tuple[tuple[str, int, int], ...] = tuple(
    (f"{low}-{high}", low, high) for _band, low, high in BAND_RANGES
)

#: Every confidence-range label, in order.
CONFIDENCE_RANGE_LABELS: tuple[str, ...] = tuple(
    label for label, _low, _high in CONFIDENCE_RANGES
)


def confidence_range_label(value: float) -> str:
    """Return the range label a ``0..100`` confidence falls in (M16.6).

    A value below the first range or above the last is clamped into the nearest
    one rather than raising or vanishing: the caller is counting observations it
    already has, and an out-of-range value (a future column that widened, a
    hand-edited row) is still an observation. The clamp is one-sided at each end
    and can only fire outside ``0..100``.
    """
    for label, low, high in CONFIDENCE_RANGES:
        if low <= value <= high:
            return label
    if value < CONFIDENCE_RANGES[0][1]:
        return CONFIDENCE_RANGES[0][0]
    return CONFIDENCE_RANGES[-1][0]


__all__ = [
    "CONFIDENCE_RANGES",
    "CONFIDENCE_RANGE_LABELS",
    "confidence_range_label",
]
