"""Shared filter parsing and validation for every router (M13.25/M13.26).

Every router needs the same handful of checks, and before M13 each one wrote its
own copy: three modules carried a private ``_parse_timestamp``, two validated
severities against a private tuple, and the address filters were validated inline
in a single router. The copies agreed by luck. This module is the agreement.

Two rules govern everything here, both from M13.25:

* **A rejected value is never silently converted.** An unknown severity is not
  treated as ``low``; an unparseable address is not treated as "no filter"; a
  blank rule key is not treated as "all rules". Each returns a value the caller
  must turn into a controlled error, or raises :class:`ValueError` for the caller
  to translate.
* **A failure names the field that failed.** The message says which query
  parameter was wrong, because "invalid filter" with no field is not actionable.

The functions come in two families:

* ``raise``-style (``parse_epoch_filter``, ``validate_choice``, ...) — return the
  parsed value on success and raise :class:`ValueError` with a caller-ready
  message on failure. A route catches it and maps it to ``400`` with the field it
  passed in.
* ``predicate``-style (``normalize_filter_ip``, ``normalize_filter_mac``) — return
  the canonical form or ``None``, because the device layer's own normalizers
  already answer that way and the caller wants to name a different field for each.

Nothing here imports FastAPI or a service: it is pure parsing, importable from a
route, a test or a script.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TypeVar

from app.devices.identity import normalize_ip_address, normalize_mac_address

#: The two representations a filter pair may arrive in: epoch seconds (findings,
#: alerts, incidents) or the naive UTC datetime the packet table stores. Both
#: order the same way, so one comparison covers them — but they are *not*
#: mutually comparable, and the bound makes a mixed pair a type error rather
#: than a runtime ``TypeError``.
_Sortable = TypeVar("_Sortable", datetime, float)

#: The lowest and highest risk score an incident may carry (M12 risk bands).
MIN_RISK_SCORE = 0
MAX_RISK_SCORE = 100

#: Inclusive lower bound for a port number.
MIN_PORT = 0
#: Inclusive upper bound for a port number.
MAX_PORT = 65535


def _as_utc(value: datetime) -> datetime:
    """Return ``value`` as an aware UTC datetime.

    A naive datetime is read as UTC rather than as local time. That is the only
    safe reading: the API documents UTC everywhere, and interpreting a naive
    value in the server's local zone would make the same request mean different
    things on two machines.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_epoch_filter(value: str | None, field: str) -> float | None:
    """Parse an ISO-8601 query timestamp into epoch seconds.

    Used by the filters whose store reasons in epoch seconds: detection findings,
    alerts and correlated incidents. The conversion belongs at the API boundary
    and nowhere else (M13.26).

    Args:
        value: The raw query value, or ``None`` when the filter was not sent.
        field: The query parameter name, echoed in the error message.

    Returns:
        Epoch seconds, or ``None`` when ``value`` is ``None``.

    Raises:
        ValueError: If ``value`` is present but empty or not ISO-8601. A typo
            must fail loudly rather than silently widen or shift the window.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        raise ValueError(f"{field} must not be empty")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"'{value}' is not a valid ISO-8601 timestamp for {field}"
        ) from exc
    return _as_utc(parsed).timestamp()


def parse_datetime_filter(value: str | datetime | None, field: str) -> datetime | None:
    """Parse an ISO-8601 query timestamp into the naive UTC datetime a table stores.

    Used by the packet filter, whose column holds a timezone-aware UTC value that
    SQLite reads back as *naive* UTC. Returning the equivalent naive UTC means an
    offset such as ``+05:30`` cannot shift the comparison by hours.

    Args:
        value: The raw query value (a string, or a datetime FastAPI already
            coerced), or ``None`` when the filter was not sent.
        field: The query parameter name, echoed in the error message.

    Returns:
        A naive UTC datetime, or ``None`` when ``value`` is ``None``.

    Raises:
        ValueError: If ``value`` is present but empty or not ISO-8601.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = _as_utc(value)
    else:
        text = str(value).strip()
        if not text:
            raise ValueError(f"{field} must not be empty")
        try:
            parsed = _as_utc(datetime.fromisoformat(text.replace("Z", "+00:00")))
        except ValueError as exc:
            raise ValueError(
                f"'{value}' is not a valid ISO-8601 timestamp for {field}"
            ) from exc
    return parsed.replace(tzinfo=None)


def normalize_filter_ip(value: str | None) -> str | None:
    """Return the canonical form of an IP filter, or ``None`` when unusable.

    ``None`` in, ``None`` out: an absent filter is not a failure. A present but
    unparseable value also returns ``None``, which the caller distinguishes from
    the absent case by checking what it was given — the device router wants to
    name ``ip`` in the error, and the connection router lets the tracker decide,
    so neither can take the naming decision from here.
    """
    if value is None:
        return None
    return normalize_ip_address(str(value).strip())


def normalize_filter_mac(value: str | None) -> str | None:
    """Return the canonical form of a MAC filter, or ``None`` when unusable."""
    if value is None:
        return None
    return normalize_mac_address(str(value).strip())


def validate_choice(
    value: str | None, allowed: tuple[str, ...], field: str, *, case_insensitive: bool = True
) -> str | None:
    """Fold and validate a value against a closed vocabulary.

    Args:
        value: The raw query value, or ``None`` when the filter was not sent.
        allowed: The permitted values, already canonical.
        field: The query parameter name, echoed in the error message.
        case_insensitive: When ``True`` (the default) the value is lower-cased
            before comparison, so ``HIGH`` and ``high`` are the same filter. The
            returned value is always the canonical one from ``allowed``.

    Returns:
        The canonical member of ``allowed``, or ``None`` when ``value`` is
        ``None``. An empty string is a failure, not "no filter": a blank query
        value is exactly the typo this function exists to catch.

    Raises:
        ValueError: If ``value`` is present and not a member of ``allowed``.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        raise ValueError(f"{field} must not be empty")
    candidate = text.lower() if case_insensitive else text
    for option in allowed:
        if candidate == (option.lower() if case_insensitive else option):
            return option
    raise ValueError(
        f"'{value}' is not a valid {field} (expected one of: {', '.join(allowed)})"
    )


def validate_port(value: int | None, field: str) -> int | None:
    """Validate a port filter.

    Raises:
        ValueError: If ``value`` is present and outside ``0..65535``.
    """
    if value is None:
        return None
    port = int(value)
    if port < MIN_PORT or port > MAX_PORT:
        raise ValueError(
            f"'{value}' is not a valid {field} (expected {MIN_PORT}-{MAX_PORT})"
        )
    return port


def validate_risk_range(
    min_score: float | None,
    max_score: float | None,
    *,
    floor: int = MIN_RISK_SCORE,
    ceiling: int = MAX_RISK_SCORE,
) -> tuple[float | None, float | None]:
    """Validate a risk-score filter pair (M13.25).

    Args:
        min_score: Lower bound, or ``None``.
        max_score: Upper bound, or ``None``.
        floor: Lowest accepted score.
        ceiling: Highest accepted score.

    Returns:
        The pair unchanged when both bounds are usable.

    Raises:
        ValueError: If a bound is outside ``floor..ceiling`` or the lower bound
            exceeds the upper one. An inverted range is a ``400`` rather than an
            empty result, because an empty result would hide the mistake.
    """
    if min_score is not None and (min_score < floor or min_score > ceiling):
        raise ValueError(
            f"min_risk_score must be between {floor} and {ceiling}"
        )
    if max_score is not None and (max_score < floor or max_score > ceiling):
        raise ValueError(
            f"max_risk_score must be between {floor} and {ceiling}"
        )
    if min_score is not None and max_score is not None and min_score > max_score:
        raise ValueError("min_risk_score must not exceed max_risk_score")
    return min_score, max_score


def validate_time_range(
    since: _Sortable | None, until: _Sortable | None
) -> tuple[_Sortable | None, _Sortable | None]:
    """Validate that a time window is not inverted.

    ``since`` is inclusive and ``until`` is exclusive (M13.26/M10.13). A window
    whose start is after its end can never match, and returning an empty list
    would hide the caller's mistake, so it is a ``400``.

    The bounds come in whichever form the endpoint's store reasons in — epoch
    seconds for findings, alerts and incidents; a naive UTC datetime for stored
    packets — so this is generic over the two rather than duplicated per form.
    The point is only that the ordering is checked in exactly one place.

    Args:
        since: Inclusive lower bound, or ``None``.
        until: Exclusive upper bound, or ``None``. Both must be the same form:
            the bound rejects a mixed pair at check time, because comparing a
            datetime with a float raises at runtime.

    Returns:
        The pair unchanged when the window is usable.

    Raises:
        ValueError: If both bounds are given and ``since`` is later than ``until``.
    """
    if since is not None and until is not None and since > until:
        raise ValueError("since must not be later than until")
    return since, until


__all__ = [
    "MAX_PORT",
    "MAX_RISK_SCORE",
    "MIN_PORT",
    "MIN_RISK_SCORE",
    "normalize_filter_ip",
    "normalize_filter_mac",
    "parse_datetime_filter",
    "parse_epoch_filter",
    "validate_choice",
    "validate_port",
    "validate_risk_range",
    "validate_time_range",
]
