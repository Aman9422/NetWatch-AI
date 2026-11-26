"""Learning lifecycle and maturity states (M21.7).

A baseline is not a device record with a boolean on it. It is a claim about
behaviour, and the claim is only as strong as the number of observations behind
it. This module is that rule, written once, so the engine, the API and the
frontend cannot disagree about what "established" means.

## The three states

``learning``
    Fewer than ``provisional_min_samples`` observation windows have been
    collected. No statistical profile is published, because a median of two
    windows is not a description of normal behaviour.
``provisional``
    The minimum sample requirement has been reached, but the profile is still
    developing. A statistical profile **is** published, because it is genuinely
    calculated from real observations — it is simply flagged as not yet mature.
``established``
    ``established_min_samples`` windows have been collected: a mature profile.

## The rules this module enforces

* **A new device never gets a fabricated baseline.** ``learning`` publishes no
  statistics at all, rather than a profile of zeroes.
* **Maturity is a sample count, never elapsed time.** A device that appeared once
  an hour ago is still learning; a device that has produced thirty windows in
  thirty minutes is established. Time is not evidence of behaviour.
* **Missing data is not zero traffic.** A window that could not measure
  ``new_connections`` contributes nothing to that feature's sample count, so the
  count is lower — never the mean.
* **The state is a pure function of the count.** There is no transition table, so
  reloading a persisted sample count also reloads the state, and the two cannot
  disagree.
* **Established is descriptive, not a verdict.** It means "this device has been
  watched for a while", not "this device is safe". Both the API and the frontend
  have to say so (M21.7/M21.11).
"""

from __future__ import annotations

from enum import Enum

#: Default thresholds, mirroring ``app.config.settings``. Counted in observation
#: windows, so 5 and 30 mean five and thirty minutes of observed behaviour at the
#: default 60-second window.
DEFAULT_PROVISIONAL_MIN_SAMPLES = 5
DEFAULT_ESTABLISHED_MIN_SAMPLES = 30


class LearningState(str, Enum):
    """How mature a device's behavioural profile is (M21.7).

    A ``str`` enum so it serialises to exactly the value stored in the database
    and sent over the wire, with no mapping table in between.
    """

    LEARNING = "learning"
    PROVISIONAL = "provisional"
    ESTABLISHED = "established"


#: Every stored state, for validation and for the API's closed vocabulary.
LEARNING_STATES: tuple[str, ...] = tuple(state.value for state in LearningState)

#: Display order, least to most mature.
STATE_ORDER: dict[str, int] = {
    LearningState.LEARNING.value: 0,
    LearningState.PROVISIONAL.value: 1,
    LearningState.ESTABLISHED.value: 2,
}


def _as_state(state: LearningState | str | None) -> LearningState:
    """Coerce a state value or enum into a :class:`LearningState`."""
    if isinstance(state, LearningState):
        return state
    return normalize_state(state)


def state_for_samples(
    sample_count: int,
    *,
    provisional_min: int = DEFAULT_PROVISIONAL_MIN_SAMPLES,
    established_min: int = DEFAULT_ESTABLISHED_MIN_SAMPLES,
) -> LearningState:
    """Return the learning state a sample count earns (M21.7).

    Args:
        sample_count: How many observation windows the profile was built from. A
            negative value is treated as zero, because a corrupt count must not
            be able to claim maturity.
        provisional_min: Samples needed to leave ``learning``.
        established_min: Samples needed to reach ``established``.

    Returns:
        The state. ``established_min`` is clamped up to ``provisional_min``, so an
        inconsistent configuration reports the weaker state rather than skipping
        a stage.

    Raises:
        ValueError: If ``provisional_min`` is less than 1. A zero threshold would
            make every device established the moment it was created, which is
            exactly the fabricated baseline M21.7 forbids.
    """
    if provisional_min < 1:
        raise ValueError("provisional_min must be at least 1")
    established = max(established_min, provisional_min)
    count = max(int(sample_count), 0)
    if count >= established:
        return LearningState.ESTABLISHED
    if count >= provisional_min:
        return LearningState.PROVISIONAL
    return LearningState.LEARNING


def normalize_state(state: str | None) -> LearningState:
    """Return a stored state as a :class:`LearningState`.

    An unrecognised or absent value is reported as ``learning``, which is the
    honest answer for a profile whose maturity cannot be established — claiming
    more would be claiming evidence that is not there.
    """
    if state is None:
        return LearningState.LEARNING
    try:
        return LearningState(str(state).strip().lower())
    except ValueError:
        return LearningState.LEARNING


def is_mature(state: LearningState | str | None) -> bool:
    """Return True when the state is ``established``."""
    return _as_state(state) is LearningState.ESTABLISHED


def publishes_statistics(state: LearningState | str | None) -> bool:
    """Return True when a state may publish a statistical profile (M21.7).

    ``learning`` publishes none: there is not yet enough observation to describe
    anything, and a profile of two samples presented as "normal behaviour" would
    be a fabrication.
    """
    return _as_state(state) is not LearningState.LEARNING


def describe_state(state: LearningState | str | None) -> str:
    """Return one sentence an operator can read (M21.7/M21.11).

    Deliberately explicit that an established baseline is a *description* of
    previous behaviour rather than a security verdict, because that is the one
    sentence a reader is most likely to misread.
    """
    normalized = _as_state(state)
    if normalized is LearningState.ESTABLISHED:
        return (
            "Enough observations have been collected for a mature statistical "
            "profile. It describes what this device normally does; it is not a "
            "statement that the device is safe."
        )
    if normalized is LearningState.PROVISIONAL:
        return (
            "The minimum number of observations has been reached, so a profile "
            "is available, but it is still developing. Treat its figures as "
            "provisional."
        )
    return (
        "Not enough observations have been collected yet to describe this "
        "device's normal behaviour."
    )


__all__ = [
    "DEFAULT_ESTABLISHED_MIN_SAMPLES",
    "DEFAULT_PROVISIONAL_MIN_SAMPLES",
    "LEARNING_STATES",
    "STATE_ORDER",
    "LearningState",
    "describe_state",
    "is_mature",
    "normalize_state",
    "publishes_statistics",
    "state_for_samples",
]
