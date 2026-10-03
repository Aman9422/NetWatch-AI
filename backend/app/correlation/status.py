"""Correlated incident lifecycle: the states and the moves between them (M12.9).

M12.9 asks for a *basic* lifecycle and explicitly warns against implementing "full
incident response workflow". Four states, one transition table, and no
automation:

    open ──► investigating ──► resolved
     │             │
     │             └────────► dismissed
     ├────────────► resolved
     └────────────► dismissed

``resolved`` and ``dismissed`` are terminal. There is no reopen, for the same
reason M11 has none: reopening is either editing a conclusion already recorded or
introducing a state the milestone did not ask for. The absence is deliberate and
tested rather than accidental.

This mirrors :mod:`app.alerts.status` closely, and that is intentional — an
operator who has learned the alert lifecycle already knows this one. It is a
separate module rather than a reuse because the two lifecycles are free to
diverge: an incident is a grouping of alerts and may later grow states (a
"merged" incident, for example) that make no sense on a single alert.
"""

from __future__ import annotations

from enum import Enum


class IncidentStatus(str, Enum):
    """The four correlated incident states (M12.9)."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class InvalidIncidentTransition(ValueError):
    """Raised when a lifecycle move is not one of the allowed transitions."""

    def __init__(self, current: str, target: str) -> None:
        self.current = current
        self.target = target
        allowed = ", ".join(allowed_targets(current)) or "nothing"
        super().__init__(
            f"Cannot move an incident from {current!r} to {target!r} "
            f"(allowed from {current!r}: {allowed})"
        )


#: Every state an incident may be written with, in lifecycle order (M12.9).
STATUS_VALUES: tuple[str, ...] = tuple(status.value for status in IncidentStatus)

#: The allowed transitions, keyed by current state (M12.9). A terminal state
#: maps to an empty set: nothing may follow it.
VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    IncidentStatus.OPEN.value: frozenset(
        {
            IncidentStatus.INVESTIGATING.value,
            IncidentStatus.RESOLVED.value,
            IncidentStatus.DISMISSED.value,
        }
    ),
    IncidentStatus.INVESTIGATING.value: frozenset(
        {
            IncidentStatus.RESOLVED.value,
            IncidentStatus.DISMISSED.value,
        }
    ),
    IncidentStatus.RESOLVED.value: frozenset(),
    IncidentStatus.DISMISSED.value: frozenset(),
}

#: States that still need attention: an incident in one of these accepts newly
#: correlated events and counts towards "open incidents" queries (M12.26).
ACTIVE_STATUSES: frozenset[str] = frozenset(
    {IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value}
)

#: States that end an incident's life. Nothing may follow them (M12.9).
TERMINAL_STATUSES: frozenset[str] = frozenset(
    {IncidentStatus.RESOLVED.value, IncidentStatus.DISMISSED.value}
)


def from_value(value: IncidentStatus | str) -> IncidentStatus:
    """Return the incident status named by ``value``.

    Raises:
        ValueError: If ``value`` is not one of the four states. Failing loudly is
            the point: a typo must never be stored as a status.
    """
    if isinstance(value, IncidentStatus):
        return value
    text = str(value).strip().lower()
    if text not in STATUS_VALUES:
        allowed = ", ".join(STATUS_VALUES)
        raise ValueError(
            f"Unknown incident status: {value!r} (expected one of: {allowed})"
        )
    return IncidentStatus(text)


def allowed_targets(current: IncidentStatus | str) -> tuple[str, ...]:
    """Return the states reachable from ``current``, in lifecycle order.

    Raises:
        ValueError: If ``current`` is not a known state.
    """
    value = from_value(current).value
    reachable = VALID_TRANSITIONS[value]
    return tuple(status for status in STATUS_VALUES if status in reachable)


def is_valid_transition(
    current: IncidentStatus | str, target: IncidentStatus | str
) -> bool:
    """Return True when ``current`` may move to ``target``.

    A move to the *same* state is accepted as an explicit no-op, mirroring M11:
    re-marking an incident as investigating changes nothing and is not an error.

    Raises:
        ValueError: If either argument is not a known state.
    """
    current_value = from_value(current).value
    target_value = from_value(target).value
    if current_value == target_value:
        return True
    return target_value in VALID_TRANSITIONS[current_value]


def validate_transition(
    current: IncidentStatus | str, target: IncidentStatus | str
) -> bool:
    """Validate a lifecycle move and report whether it changes anything.

    Returns:
        ``True`` when the move changes the incident's state, ``False`` when it is
        a no-op on an already-matching state.

    Raises:
        ValueError: If either argument is not a known state.
        InvalidIncidentTransition: If the move is not allowed (M12.9).
    """
    current_value = from_value(current).value
    target_value = from_value(target).value
    if current_value == target_value:
        return False
    if target_value not in VALID_TRANSITIONS[current_value]:
        raise InvalidIncidentTransition(current_value, target_value)
    return True


def is_terminal(status: IncidentStatus | str) -> bool:
    """Return True when no further lifecycle move is possible.

    Raises:
        ValueError: If ``status`` is not a known state.
    """
    return from_value(status).value in TERMINAL_STATUSES


def is_active(status: IncidentStatus | str) -> bool:
    """Return True when an incident in this state still needs attention.

    Raises:
        ValueError: If ``status`` is not a known state.
    """
    return from_value(status).value in ACTIVE_STATUSES


__all__ = [
    "ACTIVE_STATUSES",
    "IncidentStatus",
    "InvalidIncidentTransition",
    "STATUS_VALUES",
    "TERMINAL_STATUSES",
    "VALID_TRANSITIONS",
    "allowed_targets",
    "from_value",
    "is_active",
    "is_terminal",
    "is_valid_transition",
    "validate_transition",
]
