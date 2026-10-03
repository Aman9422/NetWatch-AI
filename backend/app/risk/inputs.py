"""The risk scoring input model (M12.15).

Everything the risk formula is allowed to look at lives in one immutable value
object. That is deliberate: the scorer has no database handle, no registry, no
clock and no settings object, so a score cannot depend on anything a test cannot
control. Same inputs, same score, always (M12.17).

The inputs are the ones M12.15 lists, and nothing more:

========================  ====================================================
input                     where it comes from
========================  ====================================================
``severity``              worst severity among the incident's alerts (M11.4)
``confidences``           the alerts' own confidences (M11.5)
``alert_count``           how many alerts the incident groups (M12.10)
``rule_ids``              the detection rules that fired (M10)
``device_ids``            resolved device identities (M8)
``connection_ids``        resolved conversations (M9)
``last_seen`` / ``now``   event recency (M12.15)
``historical_occurrences`` repeated related occurrence, when history exists
                          (M12.20)
``correlation_confidence`` how strongly the events were judged related (M12.7)
``ml_contribution``       reserved; pinned to 0 in M12 (M12.18)
========================  ====================================================

**This module does not invent anything.** There is no asset criticality field,
because the application has no configured asset-classification source (M12.19).
There is no history field that fills itself in, because a caller with no
historical data must be able to say so by passing nothing (M12.20).

Every accessor is *defensive*. Untrusted input is normal here — the values are
assembled from alert rows and detector output — so ``nan``, ``inf``, negative
counts and out-of-range confidences are all absorbed and bounded rather than
propagated into the score. The only input validated strictly is ``severity``,
because a misspelled severity is a bug in the caller's mapping, not a value
worth silently degrading (M11.4).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from app.alerts.severity import AlertSeverity, from_value

#: The highest confidence accepted. A confidence above 1.0 is meaningless, and
#: clamping keeps a bad producer from inflating the confidence term.
MAX_CONFIDENCE = 1.0

#: The lowest confidence accepted.
MIN_CONFIDENCE = 0.0

#: Highest count any count-like input is trusted up to. One hundred million is
#: far above any real incident and well inside float precision, so a garbage
#: count cannot overflow the arithmetic or distort a fraction.
MAX_COUNT = 100_000_000

#: Highest correlation confidence accepted (M12.7). Same reasoning as above.
MAX_CORRELATION_CONFIDENCE = 1.0

#: Highest ML contribution any caller may express (M12.18). Zero in M12: the
#: field exists so the shape is future-proof, and it is validated to 0 until a
#: real ML subsystem is configured.
MAX_ML_CONTRIBUTION = 1.0


def _bounded_float(
    value: object, *, low: float, high: float, default: float = 0.0
) -> float:
    """Return ``value`` as a float inside ``[low, high]`` (M12.21).

    ``nan`` and non-numeric values become ``default``; infinities fall to the
    matching bound. Never raises: a scoring input is not a place to fail.
    """
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    if math.isnan(number):
        return default
    if number <= low:
        return low
    if number >= high:
        return high
    return number


def _bounded_count(value: object) -> int:
    """Return ``value`` as a non-negative, bounded integer count (M12.21)."""
    number = _bounded_float(value, low=0.0, high=float(MAX_COUNT))
    return int(number)


def bounded_confidence(value: object, *, default: float = 0.0) -> float:
    """Return ``value`` as a confidence clamped to ``[0, 1]`` (M12.16).

    Public because the correlation layer normalises alert and finding
    confidences as well, and a confidence has to be bounded identically wherever
    it is read. One implementation is what makes "confidence is in 0..1" a fact
    about the application rather than a convention each module re-implements.
    """
    return _bounded_float(
        value, low=MIN_CONFIDENCE, high=MAX_CONFIDENCE, default=default
    )


@dataclass(frozen=True)
class RiskInputs:
    """The complete, bounded set of facts a risk score may be computed from.

    Instances are immutable and self-contained: build one, hand it to the
    scoring engine, get a deterministic score back. No field is required, so the
    empty input is a legal value that scores ``0`` and means "nothing observed"
    rather than an error (M12.21/M12.30).

    Attributes:
        severity: The most serious alert severity in the incident, or ``None``
            when the incident carries no severity. Validated against the four
            levels; an unknown value raises :class:`ValueError` (M11.4).
        confidences: The alerts' confidence values, each in ``[0, 1]``. These are
            *evidence strength* and are kept strictly separate from the risk
            score they help produce (M12.16).
        alert_count: How many alerts the incident groups. A caller that passes
            ``confidences`` may leave this unset; it then defaults to the number
            of confidences rather than to zero, so the two views of the same fact
            cannot disagree.
        rule_ids: Ids of the detection rules involved. Used only as "a detection
            exists" evidence — no per-rule weight is invented here (M12.15).
        device_ids: Resolved device identities (M8), used for the device third of
            the context term.
        connection_ids: Resolved conversation ids (M9), used for the connection
            third of the context term.
        last_seen: Epoch seconds of the most recent correlated event, or ``None``
            when unknown. Combined with ``now`` for the recency third.
        now: Epoch seconds of scoring time. Defaults to ``last_seen`` when both
            are set — scoring an incident "as of itself" — which yields a full
            recency contribution rather than a spurious decay.
        historical_occurrences: How many *previous* related occurrences are known
            to exist. Left at ``0`` when no reliable history exists, which is the
            honest answer and also the safe one (M12.20).
        correlation_confidence: The correlation engine's judged relationship
            strength in ``[0, 1]``, separate from alert confidence and from risk
            (M12.7/M12.16).
        ml_contribution: Reserved for a future ML signal. Must stay ``0`` while
            ML scoring is disabled (M12.18).
    """

    severity: AlertSeverity | str | None = None
    confidences: tuple[float, ...] = field(default_factory=tuple)
    alert_count: int | None = None
    rule_ids: tuple[str, ...] = field(default_factory=tuple)
    device_ids: tuple[str, ...] = field(default_factory=tuple)
    connection_ids: tuple[str, ...] = field(default_factory=tuple)
    last_seen: float | None = None
    now: float | None = None
    historical_occurrences: int = 0
    correlation_confidence: float = 0.0
    ml_contribution: float = 0.0

    # -- validation ---------------------------------------------------------

    def __post_init__(self) -> None:
        """Validate the one strict field: severity.

        Raises:
            ValueError: If ``severity`` is set but is not one of the four alert
                levels. A typo must surface as a caller bug, not as a silently
                less risky incident (M11.4).
        """
        if self.severity is not None:
            from_value(self.severity)

    # -- severity -----------------------------------------------------------

    def normalized_severity(self) -> AlertSeverity | None:
        """Return the severity as an enum, or ``None`` when unset."""
        if self.severity is None:
            return None
        return from_value(self.severity)

    # -- counts -------------------------------------------------------------

    def bounded_alert_count(self) -> int:
        """Return the alert count, non-negative and bounded (M12.10).

        When ``alert_count`` was not supplied, the number of confidences stands
        in for it: both describe the same alerts, and using the confidences keeps
        a caller from having to pass the same fact twice.
        """
        if self.alert_count is None:
            return len(self.bounded_confidences())
        return _bounded_count(self.alert_count)

    def bounded_historical_occurrences(self) -> int:
        """Return the historical occurrence count, non-negative and bounded."""
        return _bounded_count(self.historical_occurrences)

    # -- confidences --------------------------------------------------------

    def bounded_confidences(self) -> tuple[float, ...]:
        """Return the alert confidences, each clamped to ``[0, 1]``.

        Non-numeric entries are dropped rather than coerced to zero, because a
        dropped value is honest ("we could not read this confidence") while a
        zero would claim the evidence was absent.
        """
        cleaned: list[float] = []
        for raw in self.confidences:
            try:
                number = float(raw)
            except (TypeError, ValueError):
                continue
            if math.isnan(number):
                continue
            cleaned.append(
                _bounded_float(number, low=MIN_CONFIDENCE, high=MAX_CONFIDENCE)
            )
        return tuple(cleaned)

    def mean_confidence(self) -> float:
        """Return the mean alert confidence in ``[0, 1]``, or ``0.0`` if none.

        The mean rather than the maximum: a single confident alert among several
        weak ones is weaker evidence than a group that agrees, and risk should
        reflect the group.
        """
        confidences = self.bounded_confidences()
        if not confidences:
            return 0.0
        return sum(confidences) / float(len(confidences))

    # -- correlation --------------------------------------------------------

    def bounded_correlation_confidence(self) -> float:
        """Return the correlation confidence, clamped to ``[0, 1]`` (M12.7)."""
        return _bounded_float(
            self.correlation_confidence,
            low=0.0,
            high=MAX_CORRELATION_CONFIDENCE,
        )

    # -- recency ------------------------------------------------------------

    def age_seconds(self) -> float | None:
        """Return how many seconds ago the incident was last seen, if known.

        Returns ``None`` when either end of the subtraction is unknown, so
        "we have no timestamps" stays distinguishable from "it happened just
        now". A negative age (a clock that moved backwards between capture and
        scoring) is reported as ``0``: the event is not in the future, and a
        negative age must not be able to reduce or inflate the recency term.
        """
        if self.last_seen is None or self.now is None:
            return None
        age = _bounded_float(
            float(self.now) - float(self.last_seen),
            low=0.0,
            high=float(MAX_COUNT),
        )
        return max(age, 0.0)

    def recency_fraction(self, *, window_seconds: float) -> float:
        """Return how recent the incident is, as a fraction in ``[0, 1]``.

        ``1.0`` when the incident was seen at or after scoring time, decaying
        linearly to ``0.0`` at ``window_seconds`` of age. Linear rather than
        exponential on purpose: a reviewer can check the arithmetic by hand, and
        the term is only one third of a fifteen-point contribution (M12.17).

        Unknown timestamps contribute ``0.0`` — an unmeasured fact earns nothing
        rather than defaulting to "fresh", which would reward missing data
        (M12.20).

        Args:
            window_seconds: Age at which the contribution reaches zero. Must be
                positive.

        Raises:
            ValueError: If ``window_seconds`` is not positive.
        """
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        age = self.age_seconds()
        if age is None:
            return 0.0
        return max(1.0 - (age / float(window_seconds)), 0.0)

    # -- ml -----------------------------------------------------------------

    def bounded_ml_contribution(self) -> float:
        """Return the reserved ML contribution, clamped to its own bound.

        The contribution model — not this accessor — decides whether a non-zero
        value is acceptable, so the "must be zero in M12" rule lives with the
        formula it constrains (M12.18).
        """
        return _bounded_float(
            self.ml_contribution, low=0.0, high=MAX_ML_CONTRIBUTION
        )

    # -- construction helpers ----------------------------------------------

    @classmethod
    def from_parts(
        cls,
        *,
        severity: AlertSeverity | str | None = None,
        confidences: tuple[float, ...] = (),
        alert_count: int | None = None,
        rule_ids: tuple[str, ...] = (),
        device_ids: tuple[str, ...] = (),
        connection_ids: tuple[str, ...] = (),
        last_seen: float | None = None,
        now: float | None = None,
        historical_occurrences: int = 0,
        correlation_confidence: float = 0.0,
        ml_contribution: float = 0.0,
    ) -> RiskInputs:
        """Build inputs from explicit parts, deduplicating identity lists.

        Devices and connections are deduplicated and sorted because the context
        term counts *distinct* identities: the same device named by three
        findings is one device, and an unordered set would make the score depend
        on insertion order (M12.17 determinism).
        """
        return cls(
            severity=severity,
            confidences=tuple(confidences),
            alert_count=alert_count,
            rule_ids=tuple(sorted({str(rule) for rule in rule_ids})),
            device_ids=tuple(sorted({str(device) for device in device_ids})),
            connection_ids=tuple(
                sorted({str(connection) for connection in connection_ids})
            ),
            last_seen=last_seen,
            now=now,
            historical_occurrences=historical_occurrences,
            correlation_confidence=correlation_confidence,
            ml_contribution=ml_contribution,
        )


__all__ = [
    "MAX_CONFIDENCE",
    "MAX_CORRELATION_CONFIDENCE",
    "MAX_COUNT",
    "MAX_ML_CONTRIBUTION",
    "MIN_CONFIDENCE",
    "RiskInputs",
]
