"""The bounded correlation time window (M12.5).

Two events are only *candidates* for correlation while they are close in time.
This module owns that "close", and it owns it in one place, because a time window
is the easiest thing in a correlation engine to get subtly wrong.

M12.5 states the requirement in two halves, and both are implemented here:

* **Bounded.** An unbounded window would let a port scan this morning be
  correlated with unrelated traffic tonight, which is not correlation at all.
  :data:`MAX_CORRELATION_WINDOW_SECONDS` is a hard ceiling on what a deployment
  may configure.
* **Configurable.** What counts as "close" depends on the network, so the length
  is a setting, not a constant.

Two different comparisons are needed, and conflating them is the usual bug:

* :meth:`CorrelationWindow.pairwise` compares **two events**. It answers "may
  these two findings be related at all?", and is the basis of the M12.4 identity
  check.
* :meth:`CorrelationWindow.incident_accepts` compares **an event to an existing
  incident**. An incident is not one timestamp, it is a growing span, so the
  question is different: the event has to be near the incident's recent activity
  *and* the incident may not keep growing forever.

The second rule is what stops the classic failure mode of correlation engines:
incident chaining. If incident membership only required proximity to the
*previous* member, a busy network would grow one incident that never ends, each
new event one window further from the first. The total span is therefore capped
separately by :attr:`CorrelationWindow.max_span_seconds`.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Hard ceiling on a configured window. M12.5 forbids correlating events across
#: unlimited historical time; a day is the ceiling, chosen to match the M11
#: deduplication ceiling so the two windows are bounded on the same scale.
MAX_CORRELATION_WINDOW_SECONDS = 86_400.0

#: Default window, in step with ``settings.correlation_window_seconds``.
DEFAULT_CORRELATION_WINDOW_SECONDS = 900.0

#: Default *proximity* window — how close two related events must be to count as
#: time-proximal, which strengthens a relationship but never creates one
#: (M12.6). Shorter than the correlation window on purpose: many events may
#: belong to one incident, but only tightly clustered ones are evidence of a
#: single burst of activity.
DEFAULT_PROXIMITY_SECONDS = 300.0

#: Hard ceiling on how long a single incident's span may grow. Chaining is
#: bounded by this even when every consecutive pair is inside the window.
MAX_INCIDENT_SPAN_SECONDS = 86_400.0


@dataclass(frozen=True)
class CorrelationWindow:
    """The bounded interval inside which two events may be correlated (M12.5).

    Attributes:
        seconds: How far apart two events may be and still be candidate
            relatives. Must be positive and at most
            :data:`MAX_CORRELATION_WINDOW_SECONDS`.
        proximity_seconds: How close two events must be to count as
            *time-proximal* (M12.6). Must be positive and at most ``seconds``:
            proximity is a strengthening signal inside the correlation window, so
            a proximity window wider than the correlation window would be
            meaningless.
        max_span_seconds: The longest wall-clock span one incident may cover.
            Must be positive and at most :data:`MAX_INCIDENT_SPAN_SECONDS`.
            Defaults to ``seconds``, so by default an incident may span at most
            one window from its first event to its last.

    Raises:
        ValueError: If any bound is not positive, or exceeds its ceiling. M12.5
            requires a bounded window, so an unusable one is rejected at
            construction rather than silently clamped.
    """

    seconds: float = DEFAULT_CORRELATION_WINDOW_SECONDS
    proximity_seconds: float = DEFAULT_PROXIMITY_SECONDS
    max_span_seconds: float | None = None

    def __post_init__(self) -> None:
        """Validate the configured bounds (M12.5).

        Raises:
            ValueError: If a bound is not positive, exceeds its ceiling, or the
                proximity window is wider than the correlation window.
        """
        window = float(self.seconds)
        if window <= 0:
            raise ValueError("The correlation window must be positive")
        if window > MAX_CORRELATION_WINDOW_SECONDS:
            raise ValueError(
                "The correlation window must not exceed "
                f"{MAX_CORRELATION_WINDOW_SECONDS:.0f} seconds"
            )

        proximity = float(self.proximity_seconds)
        if proximity <= 0:
            raise ValueError("The correlation proximity window must be positive")
        if proximity > window:
            raise ValueError(
                "The correlation proximity window must not exceed the "
                "correlation window"
            )

        span = window if self.max_span_seconds is None else float(self.max_span_seconds)
        if span <= 0:
            raise ValueError("The maximum incident span must be positive")
        if span > MAX_INCIDENT_SPAN_SECONDS:
            raise ValueError(
                "The maximum incident span must not exceed "
                f"{MAX_INCIDENT_SPAN_SECONDS:.0f} seconds"
            )
        # Frozen dataclass: normalise the defaulted span so later reads see the
        # resolved value instead of ``None``. object.__setattr__ is the supported
        # way to do this in __post_init__ without giving up immutability.
        object.__setattr__(self, "max_span_seconds", span)

    # -- event to event -----------------------------------------------------

    def cutoff(self, at: float) -> float:
        """Return the earliest event time still inside the window at ``at``.

        The boundary is **inclusive**: an event exactly ``seconds`` before ``at``
        is inside the window, so a test can pin the edge exactly rather than
        approximately (M12.29).
        """
        return float(at) - float(self.seconds)

    def contains(self, timestamp: float, at: float) -> bool:
        """Return True when an event at ``timestamp`` is inside the window at ``at``.

        A timestamp *after* ``at`` — which can only mean a clock moved backwards
        between observations — is treated as inside the window. Correlating is
        the safe direction here: the alternative would be losing the relationship
        between two events that plainly belong to the same activity.
        """
        return (float(at) - float(timestamp)) <= float(self.seconds)

    def pairwise(self, first: float, second: float) -> bool:
        """Return True when two events may be correlated by time (M12.5).

        Symmetric, and inclusive at the boundary: two events exactly ``seconds``
        apart are still candidates.
        """
        return abs(float(first) - float(second)) <= float(self.seconds)

    def are_proximal(self, first: float, second: float) -> bool:
        """Return True when two events are *time-proximal* (M12.6).

        Proximity is a strengthening signal, never an anchoring one: on its own
        it is deliberately too weak to correlate anything (M12.4), which
        :mod:`app.correlation.relationship` enforces by weight.
        """
        return abs(float(first) - float(second)) <= float(self.proximity_seconds)

    def distance(self, first: float, second: float) -> float:
        """Return the absolute number of seconds between two events."""
        return abs(float(first) - float(second))

    # -- event to incident --------------------------------------------------

    def incident_accepts(
        self, *, start_time: float, last_seen: float, timestamp: float
    ) -> bool:
        """Return True when an event may join the incident it is compared with.

        Two conditions, both required, and both bounded:

        1. **Temporal proximity to the incident.** The event must be within
           ``seconds`` of the incident's most recent activity. An event far
           before the incident's last event is a different episode, and an event
           far after it is a new one.
        2. **A bounded total span.** The incident's span, measured from its first
           event to the later of its last event and the candidate, must not
           exceed ``max_span_seconds``. This is the anti-chaining bound: without
           it, a long-lived flow of related-looking events could merge into one
           incident indefinitely, each step individually inside the window.

        An event *before* the incident's start is allowed while condition 1
        holds: findings can be generated out of order, and refusing an earlier
        observation would split a genuine incident in two. It is the span rule,
        not arrival order, that keeps the incident bounded.
        """
        span_start = min(float(start_time), float(timestamp))
        span_end = max(float(last_seen), float(timestamp))
        if (span_end - span_start) > float(self.max_span_seconds or self.seconds):
            return False
        return abs(float(timestamp) - float(last_seen)) <= float(self.seconds)


__all__ = [
    "CorrelationWindow",
    "DEFAULT_CORRELATION_WINDOW_SECONDS",
    "DEFAULT_PROXIMITY_SECONDS",
    "MAX_CORRELATION_WINDOW_SECONDS",
    "MAX_INCIDENT_SPAN_SECONDS",
]
