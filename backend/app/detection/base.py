"""The common detector interface (M10.3).

Every M10 detector is one subclass of :class:`DetectionRule`. A rule:

* carries a **stable** :attr:`DetectionRule.rule_id`, so configuration,
  diagnostics and the API can name it without depending on its class;
* carries a human-readable :attr:`DetectionRule.rule_name` and a short
  :attr:`DetectionRule.description`;
* receives exactly one :class:`~app.detection.context.DetectionContext` and
  returns either one :class:`~app.detection.finding.DetectionFinding` or
  ``None``;
* owns its own bounded, lock-protected state (M10.19/M10.20);
* does no database, socket or API work, and takes its thresholds as constructor
  arguments rather than reading them from the environment itself (M10.7).

A rule never raises for ordinary input: a packet it cannot reason about simply
yields ``None``. It *may* raise for a genuinely unexpected failure, and the
engine isolates that failure so the remaining rules still run (M10.17).

Rules are not thread-safe as objects — the engine may enable or disable them —
but the state they accumulate is, because it lives in the bounded structures in
:mod:`app.detection.state`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from app.detection.context import DetectionContext
from app.detection.finding import DetectionFinding


class DetectionRule(ABC):
    """Base class for every detection rule (M10.3)."""

    #: Stable identifier, used by configuration, diagnostics and the API.
    rule_id: ClassVar[str] = ""
    #: Human-readable name, for reports and API output.
    rule_name: ClassVar[str] = ""
    #: One-line description of the behaviour the rule observes.
    description: ClassVar[str] = ""

    def __init__(
        self, *, enabled: bool = True, window_seconds: float | None = None
    ) -> None:
        self._enabled = bool(enabled)
        self._window_seconds = window_seconds

    @property
    def enabled(self) -> bool:
        """Return True when the engine should evaluate this rule."""
        return self._enabled

    def enable(self) -> None:
        """Include this rule in evaluation."""
        self._enabled = True

    def disable(self) -> None:
        """Exclude this rule from evaluation without discarding it."""
        self._enabled = False

    @property
    def window_seconds(self) -> float | None:
        """Return the detection window this rule reasons over, if any (M10.13)."""
        return self._window_seconds

    @abstractmethod
    def evaluate(self, context: DetectionContext) -> DetectionFinding | None:
        """Evaluate this rule against one context (M10.3).

        Returns:
            A finding when the rule's configured condition is met, otherwise
            ``None``. ``None`` is also the correct answer for a context the rule
            cannot reason about — it must never invent an observation.
        """

    def state_size(self) -> int:
        """Return how many subjects the rule currently holds (M10.19/M10.31)."""
        return 0

    def reset(self) -> None:
        """Discard every observation the rule has accumulated."""
        return None

    def __repr__(self) -> str:
        """Return a diagnostic representation naming the rule and its state."""
        return (
            f"<{type(self).__name__} id={self.rule_id!r} "
            f"enabled={self._enabled} subjects={self.state_size()}>"
        )
