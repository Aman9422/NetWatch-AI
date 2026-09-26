"""Alert severity vocabulary and ordering (M11.4).

Severity answers *how serious the reported behaviour is*. It is deliberately
independent of confidence (M11.5): ``severity=high`` with ``confidence=0.92``
means "this class of behaviour matters, and the evidence for it is strong". It
is **not** a risk score of 92 — risk scoring is M12's job and no risk field
exists anywhere in this package.

A severity is never invented by a detector. The mapping from a detection rule to
a severity is explicit, documented and lives in :mod:`app.alerts.mapping`. This
module owns only the vocabulary and the ordering the rest of M11 needs:
comparison, "at least this severe" filtering, and validation of a value read
back from the database.
"""

from __future__ import annotations

from enum import Enum


class AlertSeverity(str, Enum):
    """The four alert severity levels, ordered ``low`` → ``critical`` (M11.4)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Numeric rank per severity. Rank 1 is the least serious, 4 the most.
SEVERITY_RANK: dict[str, int] = {
    AlertSeverity.LOW.value: 1,
    AlertSeverity.MEDIUM.value: 2,
    AlertSeverity.HIGH.value: 3,
    AlertSeverity.CRITICAL.value: 4,
}

#: Every accepted severity value, in ascending order of seriousness. This is the
#: set the ``alerts.severity`` CHECK constraint allows (M2), and it is asserted
#: against the database by the M11 model tests.
SEVERITY_VALUES: tuple[str, ...] = tuple(
    severity.value for severity in AlertSeverity
)


def from_value(value: AlertSeverity | str) -> AlertSeverity:
    """Return the severity named by ``value``.

    Raises:
        ValueError: If ``value`` is not one of the four levels. Failing loudly is
            the point: a typo must never silently degrade to ``low``.
    """
    if isinstance(value, AlertSeverity):
        return value
    text = str(value).strip().lower()
    if text not in SEVERITY_RANK:
        allowed = ", ".join(SEVERITY_VALUES)
        raise ValueError(
            f"Unknown alert severity: {value!r} (expected one of: {allowed})"
        )
    return AlertSeverity(text)


def rank(severity: AlertSeverity | str) -> int:
    """Return the numeric rank of ``severity`` (``low`` is 1).

    Raises:
        ValueError: If ``severity`` is not a known level.
    """
    return SEVERITY_RANK[from_value(severity).value]


def at_least(severity: AlertSeverity | str, minimum: AlertSeverity | str) -> bool:
    """Return True when ``severity`` is at or above ``minimum``.

    Raises:
        ValueError: If either argument is not a known level.
    """
    return rank(severity) >= rank(minimum)


def values_at_or_above(minimum: AlertSeverity | str) -> tuple[str, ...]:
    """Return every severity value at or above ``minimum``, least serious first.

    This is what the repository uses to turn a "high and above" filter into an
    ``IN`` clause, so the ordering rule is expressed in exactly one place.

    Raises:
        ValueError: If ``minimum`` is not a known level.
    """
    threshold = rank(minimum)
    return tuple(
        value for value in SEVERITY_VALUES if SEVERITY_RANK[value] >= threshold
    )
