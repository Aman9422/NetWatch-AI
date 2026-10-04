"""The one response envelope and the machine-readable error codes (M13.4/M13.5).

Every endpoint in M13 answers with one of exactly two shapes:

    {"success": true,  "message": "...", "data": {...}}
    {"success": false, "message": "...", "errors": [{"field": ..., "code": ...}]}

Why this shape and not the single ``error`` object the milestone text sketches:
the pre-M13 API already answered this way everywhere, and M13.4 says to use the
project's existing conventions where they exist rather than "create multiple
incompatible response formats". The additions the project's envelope carries are
worth keeping:

* ``message`` — a human sentence, so a log line or a developer console reads
  without decoding a code;
* ``errors`` as a *list* — a request can fail on more than one filter at once,
  and ``field`` names which one, which a single opaque ``error`` could not.

The ``code`` is the part a client branches on, and it is stable. The ``message``
is the part a human reads, and it never contains a stack trace, a filesystem
path or a database detail (M13.5/M13.30).

This module is deliberately free of FastAPI and of any domain import: it is pure
data shaping, importable from anywhere.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Final

#: JSON value a payload field may hold.
JsonValue = (
    str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)


class ErrorCode:
    """Every machine-readable error code the API can return.

    Grouped by intent rather than by module, because a client branches on the
    kind of failure (not found, invalid input, conflict, unavailable) rather than
    on which router produced it. Resource-specific ``*_NOT_FOUND`` codes exist
    because the pre-M13 API already returned them and a client may already
    depend on the distinction between "no such device" and "no such alert".

    The contract tests assert that every code here is reachable and that no
    handler invents one outside this class.
    """

    # -- generic ---------------------------------------------------------
    INVALID_REQUEST: Final = "INVALID_REQUEST"
    INVALID_FILTER: Final = "INVALID_FILTER"
    NOT_FOUND: Final = "NOT_FOUND"
    CONFLICT: Final = "CONFLICT"
    INTERNAL_ERROR: Final = "INTERNAL_ERROR"
    FEATURE_NOT_IMPLEMENTED: Final = "FEATURE_NOT_IMPLEMENTED"
    SERVICE_UNAVAILABLE: Final = "SERVICE_UNAVAILABLE"
    METHOD_NOT_ALLOWED: Final = "METHOD_NOT_ALLOWED"

    # -- resource-specific not-found -------------------------------------
    PACKET_NOT_FOUND: Final = "PACKET_NOT_FOUND"
    DEVICE_NOT_FOUND: Final = "DEVICE_NOT_FOUND"
    CONNECTION_NOT_FOUND: Final = "CONNECTION_NOT_FOUND"
    FINDING_NOT_FOUND: Final = "FINDING_NOT_FOUND"
    ALERT_NOT_FOUND: Final = "ALERT_NOT_FOUND"
    EVIDENCE_NOT_FOUND: Final = "EVIDENCE_NOT_FOUND"
    INCIDENT_NOT_FOUND: Final = "INCIDENT_NOT_FOUND"
    REPORT_NOT_FOUND: Final = "REPORT_NOT_FOUND"
    NOTIFICATION_NOT_FOUND: Final = "NOTIFICATION_NOT_FOUND"
    SETTING_NOT_FOUND: Final = "SETTING_NOT_FOUND"

    # -- resource-specific conflict / validation -------------------------
    INVALID_TRANSITION: Final = "INVALID_TRANSITION"
    INVALID_LIFECYCLE: Final = "INVALID_LIFECYCLE"
    INVALID_SETTING: Final = "INVALID_SETTING"
    IMMUTABLE_SETTING: Final = "IMMUTABLE_SETTING"

    # -- capture (M4's own vocabulary, preserved) ------------------------
    CAPTURE_ALREADY_RUNNING: Final = "CAPTURE_ALREADY_RUNNING"
    CAPTURE_NOT_RUNNING: Final = "CAPTURE_NOT_RUNNING"
    CAPTURE_NO_INTERFACE: Final = "CAPTURE_NO_INTERFACE"
    CAPTURE_START_FAILED: Final = "CAPTURE_START_FAILED"
    CAPTURE_STOP_FAILED: Final = "CAPTURE_STOP_FAILED"
    NO_INTERFACE_SELECTED: Final = "NO_INTERFACE_SELECTED"
    INTERFACE_NOT_FOUND: Final = "INTERFACE_NOT_FOUND"
    INTERFACE_UNAVAILABLE: Final = "INTERFACE_UNAVAILABLE"
    EMPTY_INTERFACE_NAME: Final = "EMPTY_INTERFACE_NAME"


#: The HTTP status each generic code is rendered with. Resource-specific codes
#: inherit their status from the exception that carries them, so this table is
#: a reference for the contract test rather than a lookup used at runtime.
GENERIC_CODE_STATUS: Mapping[str, int] = {
    ErrorCode.INVALID_REQUEST: 400,
    ErrorCode.INVALID_FILTER: 400,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.CONFLICT: 409,
    ErrorCode.INTERNAL_ERROR: 500,
    ErrorCode.FEATURE_NOT_IMPLEMENTED: 501,
    ErrorCode.SERVICE_UNAVAILABLE: 503,
    ErrorCode.METHOD_NOT_ALLOWED: 405,
}


def success_payload(message: str, data: object) -> dict[str, object]:
    """Return the standard successful envelope.

    Args:
        message: A short human sentence describing what was returned.
        data: The payload. Any JSON-serializable object is accepted; callers
            normally pass a ``model_dump()`` result or a plain mapping.

    Returns:
        ``{"success": True, "message": message, "data": data}``.
    """
    return {"success": True, "message": str(message), "data": data}


def error_payload(
    message: str,
    code: str,
    field: str = "request",
    *,
    errors: Iterable[tuple[str, str]] | None = None,
) -> dict[str, object]:
    """Return the standard error envelope.

    Args:
        message: A short human sentence. Must not contain internals.
        code: The machine-readable code. Defaults to
            :attr:`ErrorCode.INTERNAL_ERROR` when blank, because an empty code
            would give a client nothing to branch on.
        field: Which request field failed. Only used when ``errors`` is omitted.
        errors: Explicit ``(field, code)`` pairs, for the rare case where more
            than one field failed at once. When supplied it replaces ``field``.

    Returns:
        ``{"success": False, "message": message, "errors": [...]}``.
    """
    if errors is not None:
        pairs = [(str(name), str(value)) for name, value in errors]
    else:
        pairs = [(str(field or "request"), str(code or ErrorCode.INTERNAL_ERROR))]
    return {
        "success": False,
        "message": str(message),
        "errors": [{"field": name, "code": value} for name, value in pairs],
    }


__all__ = [
    "ErrorCode",
    "GENERIC_CODE_STATUS",
    "JsonValue",
    "error_payload",
    "success_payload",
]
