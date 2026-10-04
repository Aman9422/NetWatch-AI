"""Settings API endpoints for NetWatch AI (M13.21).

M13.21 asks for three sets to be separated explicitly, and this module is where
that separation is enforced:

**readable** — every stored key except the internal-only ones. A listing returns
them; ``GET /settings/{key}`` returns one.

**mutable** — the keys ``PUT /settings`` will accept. They are named in
:data:`MUTABLE_KEYS` with the type and the constraint each one carries, so a value
is validated against its own declaration rather than against a generic rule.

**internal-only** — never listed and never readable. A key whose name matches the
secret denylist (:data:`SECRET_NAME_MARKERS`) is withheld, so a credential cannot
leak through this endpoint even if someone stores one in this table. The check is
applied on read rather than on write, which means a secret written by any other
path is still withheld.

Two decisions are worth stating because the code alone would not show them:

* **``restart_required`` is reported, not implied.** Stored settings are read by
  the application at startup from the environment, so writing a row does not
  reconfigure a running service. Saying so in the payload is the difference
  between a client knowing a restart is needed and believing the change took
  effect (M13.21).
* **An immutable key is a ``409``, not a silent skip.** A key that exists and is
  readable but not writable is a conflict with the server's policy; a key the
  application never heard of is a ``400``. Collapsing the two would hide a typo
  behind a policy refusal (M13.25).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Callable

from fastapi import APIRouter, Depends

from app.api.common import (
    BadRequestError,
    ConflictError,
    ErrorCode,
    NotFoundError,
    success_payload,
)
from app.api.v1.deps import get_setting_repository
from app.models.setting import Setting
from app.repositories.setting import SettingRepository
from app.schemas.alert import to_iso_timestamp
from app.schemas.setting import (
    SettingListData,
    SettingUpdateRequest,
    SettingUpdateResult,
    SettingValue,
    SettingView,
)

logger = logging.getLogger(__name__)

router = APIRouter()

#: Substrings that mark a key as internal-only. A key containing any of these is
#: never listed and never read, so a credential stored in this table cannot leak
#: through the settings API (M13.30). Matching on the *name* means the rule holds
#: for keys this module has never seen.
SECRET_NAME_MARKERS: tuple[str, ...] = (
    "secret",
    "password",
    "token",
    "key",
    "credential",
    "dsn",
)

#: Explicit internal-only keys. Empty today: the marker rule above already covers
#: the names this application would use, and an entry here is how a future
#: non-secret-but-internal key would be added.
INTERNAL_ONLY_KEYS: frozenset[str] = frozenset()


def _is_internal_only(key: str) -> bool:
    """Return True when ``key`` must never be listed or read (M13.21)."""
    lowered = str(key).strip().lower()
    return lowered in INTERNAL_ONLY_KEYS or any(
        marker in lowered for marker in SECRET_NAME_MARKERS
    )


def _positive_int(value: object) -> bool:
    """Return True when ``value`` is an integer of at least 1."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _bounded_int(low: int, high: int) -> Callable[[object], bool]:
    """Return a predicate accepting an integer inside ``low..high``."""

    def predicate(value: object) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and low <= value <= high
        )

    return predicate


def _one_of(allowed: tuple[str, ...]) -> Callable[[object], bool]:
    """Return a predicate accepting a member of ``allowed``."""

    def predicate(value: object) -> bool:
        return isinstance(value, str) and value.strip().lower() in allowed

    return predicate


def _is_string(value: object) -> bool:
    """Return True when ``value`` is a non-blank string."""
    return isinstance(value, str) and bool(value.strip())


def _is_bool(value: object) -> bool:
    """Return True when ``value`` is a boolean and not an integer ``0``/``1``."""
    return isinstance(value, bool)


#: Keys a client may change, each with its stored type, a predicate its value must
#: satisfy, and the wording used when it does not. Declaring all three together is
#: what keeps the four rules (type, constraint, message, default) from drifting
#: apart as keys are added.
MUTABLE_SETTINGS: dict[str, tuple[str, Callable[[object], bool], str]] = {
    "capture_interface": (
        "string",
        _is_string,
        "must be a non-empty interface name",
    ),
    "default_theme": (
        "string",
        _one_of(("light", "dark", "system")),
        "must be one of: light, dark, system",
    ),
    "packet_retention_days": (
        "int",
        _positive_int,
        "must be a whole number of days, at least 1",
    ),
    "alert_threshold": (
        "int",
        _bounded_int(0, 100),
        "must be a whole number between 0 and 100",
    ),
    "ai_enabled": (
        "bool",
        _is_bool,
        "must be true or false",
    ),
}

#: The mutable keys in a stable, documented order.
MUTABLE_KEYS: tuple[str, ...] = tuple(sorted(MUTABLE_SETTINGS))


def _decode_value(raw: str, data_type: str) -> SettingValue:
    """Decode a stored text value according to its declared type (M13.21).

    A value that will not decode is returned as the raw text rather than raising:
    one malformed row must not make the whole settings listing fail, and the raw
    text is the truthful representation of what the store holds.
    """
    text = "" if raw is None else str(raw)
    kind = (data_type or "string").strip().lower()
    try:
        if kind == "int":
            return int(text)
        if kind == "float":
            return float(text)
        if kind == "bool":
            return text.strip().lower() in {"1", "true", "yes", "on"}
        if kind == "json":
            return json.loads(text)
    except (TypeError, ValueError):
        return text
    return text


def _encode_value(value: str | int | float | bool, data_type: str) -> str:
    """Serialize a client value for storage, matching its declared type.

    The value has already been checked against its declaration in
    :data:`MUTABLE_SETTINGS`, so this only has to render it the way the declared
    type is stored. Booleans are written as ``"true"``/``"false"`` rather than
    ``repr``, because that is what :func:`_decode_value` reads back.
    """
    if data_type == "json":
        return json.dumps(value)
    if data_type == "bool":
        return "true" if bool(value) else "false"
    return str(value)


def _view(row: Setting) -> SettingView:
    """Project a stored row onto the readable model (M13.21)."""
    key = str(row.setting_key)
    return SettingView(
        key=key,
        value=_decode_value(row.setting_value, row.data_type),
        data_type=str(row.data_type),
        mutable=key in MUTABLE_SETTINGS,
        updated_at=to_iso_timestamp(_as_utc(row.updated_at)),
    )


def _as_utc(value: datetime | None) -> datetime | None:
    """Return a stored naive-UTC datetime as an aware UTC datetime (M13.26)."""
    if value is None:
        return None
    if value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


@router.get("", response_model=None)
def list_settings(
    repository: SettingRepository = Depends(get_setting_repository),
) -> dict:
    """Return every readable setting, ordered by key (M13.21).

    Internal-only keys are filtered out before the payload is built, so they
    cannot appear even as an unexplained gap: the response reports how many were
    withheld, which is information about the *policy* rather than about any
    secret's contents or name.
    """
    rows = repository.list_all()
    readable = [row for row in rows if not _is_internal_only(row.setting_key)]
    payload = SettingListData(
        count=len(readable),
        settings=[_view(row) for row in readable],
        mutable_keys=list(MUTABLE_KEYS),
        internal_key_count=len(rows) - len(readable),
    )
    logger.info("Returning %d readable setting(s) via API", payload.count)
    return success_payload("Settings retrieved", payload.model_dump(mode="json"))


@router.get("/{setting_key}", response_model=None)
def get_setting(
    setting_key: str,
    repository: SettingRepository = Depends(get_setting_repository),
) -> dict:
    """Return one readable setting, or ``404`` (M13.21).

    An internal-only key answers exactly as an unknown one does. Distinguishing
    them would confirm that a credential is stored under that name, which is the
    leak this endpoint exists to prevent (M13.30).
    """
    if _is_internal_only(setting_key):
        logger.info("Refused to read an internal-only setting by name")
        raise NotFoundError(
            "Setting not found",
            code=ErrorCode.SETTING_NOT_FOUND,
            field="setting_key",
        )
    row = repository.get_by_key(setting_key)
    if row is None:
        logger.info("Setting lookup failed for key %r", setting_key)
        raise NotFoundError(
            "Setting not found",
            code=ErrorCode.SETTING_NOT_FOUND,
            field="setting_key",
        )
    return success_payload("Setting retrieved", _view(row).model_dump(mode="json"))


def _validated_update(
    repository: SettingRepository, values: dict[str, str | int | float | bool]
) -> dict[str, tuple[str, str]]:
    """Validate a settings change and return what to store (M13.21/M13.25).

    Every key is checked before anything is written, so a request that names one
    good key and one bad key changes nothing. A partially applied change would
    leave the client unable to tell which half took effect.

    Args:
        repository: Used to tell "a real but immutable setting" apart from "a key
            this application has never heard of".
        values: The requested key/value pairs.

    Returns:
        ``key -> (serialized_value, data_type)``, ready for the repository.

    Raises:
        BadRequestError: If the mapping is empty, or a key is unknown or
            internal-only, or a value does not satisfy its declared constraint.
        ConflictError: If the key exists and is readable but is not mutable.
    """
    if not values:
        raise BadRequestError(
            "No settings were supplied", code=ErrorCode.INVALID_SETTING, field="values"
        )

    prepared: dict[str, tuple[str, str]] = {}
    for key, value in values.items():
        name = str(key).strip()
        if _is_internal_only(name):
            # Deliberately the same answer as an unknown key: confirming that a
            # credential is stored would be the leak (M13.30).
            raise BadRequestError(
                f"{name!r} is not a known mutable setting",
                code=ErrorCode.INVALID_SETTING,
                field=name,
            )
        declaration = MUTABLE_SETTINGS.get(name)
        if declaration is None:
            if repository.get_by_key(name) is not None:
                raise ConflictError(
                    f"{name!r} is read-only and cannot be changed through this API",
                    code=ErrorCode.IMMUTABLE_SETTING,
                    field=name,
                )
            raise BadRequestError(
                f"{name!r} is not a known mutable setting",
                code=ErrorCode.INVALID_SETTING,
                field=name,
            )
        data_type, predicate, expectation = declaration
        if not predicate(value):
            raise BadRequestError(
                f"{name!r} {expectation}",
                code=ErrorCode.INVALID_SETTING,
                field=name,
            )
        prepared[name] = (_encode_value(value, data_type), data_type)
    return prepared


@router.put("", response_model=None)
def update_settings(
    body: SettingUpdateRequest,
    repository: SettingRepository = Depends(get_setting_repository),
) -> dict:
    """Validate and store a set of settings changes (M13.21).

    The whole request is validated first and written in one transaction, so it
    either applies completely or changes nothing. The response echoes what was
    actually persisted, read back from the store, and states ``restart_required``
    because stored settings are applied at application startup rather than to the
    running process.
    """
    prepared = _validated_update(repository, body.values)
    stored = repository.upsert(prepared)
    payload = SettingUpdateResult(
        updated=[_view(row) for row in stored],
        restart_required=True,
    )
    logger.info("Stored %d setting(s) via API", len(payload.updated))
    return success_payload("Settings updated", payload.model_dump(mode="json"))


__all__ = [
    "INTERNAL_ONLY_KEYS",
    "MUTABLE_KEYS",
    "MUTABLE_SETTINGS",
    "SECRET_NAME_MARKERS",
    "router",
]
