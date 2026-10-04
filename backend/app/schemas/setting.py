"""Wire schemas for application settings (M13.21).

The ``settings`` table is a key/value store, so a setting's wire value depends on
its ``data_type`` column. :class:`SettingView` reports the value *decoded* rather
than as the raw text the column holds, because a client asking for
``packet_retention_days`` should receive ``30`` and not ``"30"``.

Three sets are named in the API and two of them appear here (M13.21):

* **readable** — what a listing or a single read may return;
* **mutable** — what :class:`SettingUpdateRequest` may change;
* **internal-only** — never returned at all, and therefore not modelled. A model
  that could hold an internal key is a model that could leak one.
"""

from __future__ import annotations

from typing import Any, TypeAlias

from pydantic import BaseModel, Field

#: The value types a setting may carry. ``json`` settings are decoded too, so a
#: stored document arrives as an object rather than as a string to parse.
#:
#: The document case is typed as a plain ``dict``/``list`` of ``Any`` rather than
#: as a self-referential alias. A recursive alias would have to state a nesting
#: depth, and this layer imposes none: it decodes whatever the column holds and
#: hands it on. Declaring it as ``Any`` says exactly that, and avoids an alias
#: pydantic has to resolve against itself.
SettingValue: TypeAlias = (
    str | int | float | bool | dict[str, Any] | list[Any] | None
)


class SettingView(BaseModel):
    """One readable setting, decoded (M13.21)."""

    key: str
    value: SettingValue = Field(
        default=None, description="The stored value, decoded according to data_type"
    )
    data_type: str = Field(
        default="string", description="How the stored text is interpreted"
    )
    mutable: bool = Field(
        default=False, description="Whether PUT /settings will accept this key"
    )
    updated_at: str | None = Field(
        default=None, description="Last modification, as ISO-8601 UTC"
    )


class SettingListData(BaseModel):
    """Payload of ``GET /settings`` (M13.21)."""

    count: int = 0
    settings: list[SettingView] = Field(default_factory=list)
    mutable_keys: list[str] = Field(
        default_factory=list,
        description="Every key PUT /settings accepts, in a stable order",
    )
    internal_key_count: int = Field(
        default=0,
        description="How many stored keys are withheld as internal-only",
    )


class SettingUpdateRequest(BaseModel):
    """Body of ``PUT /settings`` (M13.21).

    A mapping of key to value, because several settings are normally changed
    together. Only keys the application declares mutable are accepted; an unknown
    key is a ``400`` and an immutable one is a ``409``, so a request cannot
    half-apply by silently skipping what it could not change.
    """

    values: dict[str, str | int | float | bool] = Field(
        description="Settings to change, by key"
    )


class SettingUpdateResult(BaseModel):
    """Payload returned by ``PUT /settings`` (M13.21).

    ``restart_required`` is stated rather than implied. Stored settings are read
    by the application **at startup** from the environment, so changing a stored
    value does not reconfigure a running service; a client that assumed otherwise
    would believe a change had taken effect when it had not.
    """

    updated: list[SettingView] = Field(default_factory=list)
    restart_required: bool = Field(
        default=True,
        description="True because stored settings are applied at startup",
    )


__all__ = [
    "SettingListData",
    "SettingUpdateRequest",
    "SettingUpdateResult",
    "SettingValue",
    "SettingView",
]
