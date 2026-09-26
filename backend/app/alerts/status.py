"""Alert lifecycle: statuses and the transitions allowed between them (M11.6/M11.19).

An alert moves through a small, explicit set of states, and only along the edges
defined here. The lifecycle is **validated**: an invalid move is rejected rather
than silently applied, because an alert that can be talked back out of
``resolved`` without a deliberate reopen operation has no real lifecycle at all
(M11.19).

    open ──► acknowledged ──► resolved
     │            │
     │            ├──────────► dismissed
     │            └──────────► false_positive
     ├────────────► resolved / dismissed / false_positive

``resolved``, ``dismissed`` and ``false_positive`` are terminal. Reopening a
closed alert is deliberately *not* supported: it would mean either editing a
conclusion that was already recorded or introducing a further state, and neither
is in M11's scope. The absence is explicit and tested, not accidental.

Two legacy M2 names are read as their M11 equivalent
(:func:`from_stored_value`). Nothing writes the legacy names any more; they are
tolerated so a pre-M11 row stays readable rather than becoming an error.
"""

from __future__ import annotations

from enum import Enum


class AlertStatus(str, Enum):
    """The five alert lifecycle states (M11.6)."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    FALSE_POSITIVE = "false_positive"


class InvalidStatusTransition(ValueError):
    """Raised when a lifecycle move is not one of the allowed transitions."""

    def __init__(self, current: str, target: str) -> None:
        self.current = current
        self.target = target
        allowed = ", ".join(allowed_targets(current)) or "nothing"
        super().__init__(
            f"Cannot move an alert from {current!r} to {target!r} "
            f"(allowed from {current!r}: {allowed})"
        )


#: Every state an alert may be written with, in lifecycle order (M11.6). This is
#: the set ``alerts.status`` accepts after the M11 constraint upgrade.
STATUS_VALUES: tuple[str, ...] = tuple(status.value for status in AlertStatus)

#: The allowed transitions, keyed by current state (M11.19). A terminal state
#: maps to an empty set: nothing may follow it.
VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    AlertStatus.OPEN.value: frozenset(
        {
            AlertStatus.ACKNOWLEDGED.value,
            AlertStatus.RESOLVED.value,
            AlertStatus.DISMISSED.value,
            AlertStatus.FALSE_POSITIVE.value,
        }
    ),
    AlertStatus.ACKNOWLEDGED.value: frozenset(
        {
            AlertStatus.RESOLVED.value,
            AlertStatus.DISMISSED.value,
            AlertStatus.FALSE_POSITIVE.value,
        }
    ),
    AlertStatus.RESOLVED.value: frozenset(),
    AlertStatus.DISMISSED.value: frozenset(),
    AlertStatus.FALSE_POSITIVE.value: frozenset(),
}

#: States that still need attention: a new observation may still be attached to
#: them and they count towards "unresolved" queries (M11.18).
ACTIVE_STATUSES: frozenset[str] = frozenset(
    {AlertStatus.OPEN.value, AlertStatus.ACKNOWLEDGED.value}
)

#: States that end an alert's life. Nothing may follow them (M11.19).
TERMINAL_STATUSES: frozenset[str] = frozenset(
    {
        AlertStatus.RESOLVED.value,
        AlertStatus.DISMISSED.value,
        AlertStatus.FALSE_POSITIVE.value,
    }
)

#: Legacy M2 status names mapped onto their M11 equivalent. ``new`` was the M2
#: name for the state a freshly created alert starts in, and ``investigating``
#: the one a human had picked up — which M11 calls ``acknowledged``.
LEGACY_STATUS_ALIASES: dict[str, str] = {
    "new": AlertStatus.OPEN.value,
    "investigating": AlertStatus.ACKNOWLEDGED.value,
}

#: Everything the database column may hold: the M11 states plus the legacy M2
#: names, so pre-existing rows stay valid (see the M11 schema upgrade).
STORED_STATUS_VALUES: tuple[str, ...] = STATUS_VALUES + tuple(
    name for name in LEGACY_STATUS_ALIASES if name not in STATUS_VALUES
)


def from_value(value: AlertStatus | str) -> AlertStatus:
    """Return the M11 status named by ``value``.

    Raises:
        ValueError: If ``value`` is not one of the five states. Failing loudly is
            the point: a typo must never be stored as a status.
    """
    if isinstance(value, AlertStatus):
        return value
    text = str(value).strip().lower()
    if text not in STATUS_VALUES:
        allowed = ", ".join(STATUS_VALUES)
        raise ValueError(
            f"Unknown alert status: {value!r} (expected one of: {allowed})"
        )
    return AlertStatus(text)


def from_stored_value(value: AlertStatus | str) -> AlertStatus:
    """Return the M11 status for a value read out of the database.

    The only difference from :func:`from_value` is that the two legacy M2 names
    are translated first, so an alert written before M11 is still readable.
    Every other value must be one of the M11 states.

    An :class:`AlertStatus` is returned unchanged. That case matters: this
    function is called with the status of a *runtime* alert as well as with a
    stored string, and ``str()`` on a ``str``-mixin enum renders the enum's
    *name* (``"AlertStatus.OPEN"``) rather than its value on Python before 3.11's
    ``StrEnum``. Delegating the enum case to :func:`from_value` keeps a lifecycle
    transition working whichever form it is handed.

    Raises:
        ValueError: If ``value`` is neither an M11 state nor a legacy alias.
    """
    if isinstance(value, AlertStatus):
        return value
    text = str(value).strip().lower()
    mapped = LEGACY_STATUS_ALIASES.get(text, text)
    return from_value(mapped)


def allowed_targets(current: AlertStatus | str) -> tuple[str, ...]:
    """Return the states reachable from ``current``, in lifecycle order.

    Raises:
        ValueError: If ``current`` is not a known state.
    """
    value = from_stored_value(current).value
    reachable = VALID_TRANSITIONS[value]
    return tuple(status for status in STATUS_VALUES if status in reachable)


def is_valid_transition(current: AlertStatus | str, target: AlertStatus | str) -> bool:
    """Return True when ``current`` may move to ``target``.

    A move to the *same* state is accepted as an explicit no-op: re-acknowledging
    an acknowledged alert changes nothing and is not an error. A move out of a
    terminal state is not accepted.

    Raises:
        ValueError: If either argument is not a known state.
    """
    current_value = from_stored_value(current).value
    target_value = from_value(target).value
    if current_value == target_value:
        return True
    return target_value in VALID_TRANSITIONS[current_value]


def validate_transition(current: AlertStatus | str, target: AlertStatus | str) -> bool:
    """Validate a lifecycle move and report whether it changes anything.

    Returns:
        ``True`` when the move changes the alert's state, ``False`` when it is a
        no-op on an already-matching state.

    Raises:
        ValueError: If ``current`` is not a known state (including a legacy
            alias), or ``target`` is not one of the five M11 states.
        InvalidStatusTransition: If the move is not allowed (M11.19).
    """
    current_value = from_stored_value(current).value
    target_value = from_value(target).value
    if current_value == target_value:
        return False
    if target_value not in VALID_TRANSITIONS[current_value]:
        raise InvalidStatusTransition(current_value, target_value)
    return True


def is_terminal(status: AlertStatus | str) -> bool:
    """Return True when no further lifecycle move is possible.

    Raises:
        ValueError: If ``status`` is not a known state.
    """
    return from_stored_value(status).value in TERMINAL_STATUSES
