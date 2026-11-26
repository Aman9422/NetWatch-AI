"""Model lifecycle vocabulary (M22.5).

A model's state answers one question: *can this device's behaviour be evaluated
right now, and if not, why not?* It is deliberately separate from M21's learning
state. M21's ``established`` means "enough windows for a statistical profile";
M22's ``ready`` means "a fitted model exists". A device can be established at 30
windows and still be ``collecting_data`` here, because M22 requires its own,
higher minimum — and that difference must be visible rather than implied.

The states
----------

``collecting_data``
    Fewer usable historical windows than training requires. **No model exists
    and no verdict is issued.** This is the state a device is in for its first
    hundred windows, and it is not a failure.
``training``
    A training pass is in progress. Transient: the pass either reaches ``ready``
    or falls back to ``failed`` (or to the previous state, when one is being
    refreshed).
``ready``
    A fitted model is available and the refresh interval has not been reached.
``stale``
    A model exists but enough new usable windows have accumulated that a retrain
    is due. Evaluations still run against the current model; the state simply
    says the model is behind the data.
``failed``
    The last training or inference attempt raised. The failure is recorded with
    a safe sentence, and — critically — the *previous* working model is kept, so
    a failed refresh does not blind the detector (M22.7).
``disabled``
    The engine is switched off for this device by configuration. Not reachable
    from the API; it exists so an operator-disabled device is distinguishable
    from one that merely has no data.

Two invariants this module enforces:

* **``collecting_data`` never reads as healthy.** The frontend and the API both
  say so in words, because "no anomalies detected" and "no model exists" are
  very different statements and only one of them is evidence about traffic.
* **An unrecognised stored state reads as ``failed``**, not as ``ready``.
  Claiming a working model that cannot be identified would be the one direction
  a model-status reader must never be wrong in.
"""

from __future__ import annotations

from enum import Enum

#: Default lifecycle state for a device that has never been trained.
DEFAULT_STATE = "collecting_data"


class ModelState(str, Enum):
    """How far a device's anomaly model has progressed (M22.5).

    A ``str`` enum so it serialises to exactly the value stored in the database
    and sent over the wire, with no mapping table in between.
    """

    COLLECTING_DATA = "collecting_data"
    TRAINING = "training"
    READY = "ready"
    STALE = "stale"
    FAILED = "failed"
    DISABLED = "disabled"


#: Every stored state, for validation and for the API's closed vocabulary.
MODEL_STATES: tuple[str, ...] = tuple(state.value for state in ModelState)

#: States in which a fitted model exists and can score a window.
SCORING_STATES: frozenset[str] = frozenset(
    {ModelState.READY.value, ModelState.STALE.value}
)

#: States that represent a problem rather than a stage of learning.
PROBLEM_STATES: frozenset[str] = frozenset(
    {ModelState.FAILED.value, ModelState.DISABLED.value}
)


def normalize_state(state: str | None) -> ModelState:
    """Return a stored state as a :class:`ModelState`.

    An unrecognised or absent value is reported as ``failed``: a state this build
    cannot name is a model whose availability cannot be established, and the one
    answer that must never be given is "ready". ``disabled`` is *not* the
    fallback, because that would claim an operator had chosen it.
    """
    if state is None:
        return ModelState.FAILED
    try:
        return ModelState(str(state).strip().lower())
    except ValueError:
        return ModelState.FAILED


def can_score(state: str | None) -> bool:
    """Return True when a fitted model exists that may evaluate a window."""
    return str(state).strip().lower() in SCORING_STATES


def is_problem(state: str | None) -> bool:
    """Return True when the state represents a failure or a disablement.

    Distinct from :func:`can_score`: ``collecting_data`` cannot score either, but
    it is a normal stage of learning rather than a problem, and a page that
    showed both as warnings would cry wolf for the first hundred windows of
    every device (M22.13).
    """
    return str(state).strip().lower() in PROBLEM_STATES


def describe_state(state: str | None) -> str:
    """Return one sentence an operator can read (M22.13).

    Written so no state can be mistaken for a clean bill of health. The
    ``ready`` wording in particular says what the model is *not*: it is a
    description of what differs from learned behaviour, never proof of malice.
    """
    normalized = normalize_state(state)
    if normalized is ModelState.READY:
        return (
            "A model has been trained from this device's historical observation "
            "windows and is available for evaluation. It identifies behaviour "
            "that differs from what was learned; it does not prove malicious "
            "activity."
        )
    if normalized is ModelState.STALE:
        return (
            "A model is available, but enough new observation windows have "
            "accumulated that a retraining is due. Evaluations continue against "
            "the current model, which is behind the latest data."
        )
    if normalized is ModelState.TRAINING:
        return "A training pass is running. No evaluation is possible until it finishes."
    if normalized is ModelState.COLLECTING_DATA:
        return (
            "Not enough historical observation windows have accumulated to train "
            "a model. No evaluation is possible yet, and no verdict is being "
            "issued — this is not the same as 'nothing unusual was observed'."
        )
    if normalized is ModelState.DISABLED:
        return (
            "Anomaly detection is switched off for this device. Nothing is being "
            "evaluated, and the absence of anomalies is not evidence of normal "
            "behaviour."
        )
    return (
        "The last training or evaluation attempt failed. No current model is "
        "available, and the absence of anomalies is not evidence of normal "
        "behaviour."
    )


def next_state_after_training(*, succeeded: bool, windows_since: int) -> ModelState:
    """Return the state a training pass should leave behind (M22.7).

    Args:
        succeeded: Whether the pass produced a usable model.
        windows_since: Usable windows observed since that model was fitted.

    Returns:
        ``ready`` or ``stale`` on success — a fresh model that is already behind
        its data is honestly stale rather than pretending to be current — and
        ``failed`` otherwise.
    """
    if not succeeded:
        return ModelState.FAILED
    return ModelState.READY if windows_since <= 0 else ModelState.STALE


__all__ = [
    "DEFAULT_STATE",
    "MODEL_STATES",
    "PROBLEM_STATES",
    "SCORING_STATES",
    "ModelState",
    "can_score",
    "describe_state",
    "is_problem",
    "next_state_after_training",
    "normalize_state",
]
