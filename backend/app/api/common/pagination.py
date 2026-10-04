"""The one pagination contract for every collection endpoint (M13.24).

Before M13, five routers each declared their own ``limit``/``offset`` query
parameters. They happened to agree — default 100, maximum 1000, ``offset >= 0`` —
but the agreement was a coincidence of five copies rather than a contract. This
module is that contract, written once:

======================  ==========  ===========  ==========
parameter               default     minimum      maximum
======================  ==========  ===========  ==========
``limit``               100         1            1000
``offset``              0           0            unbounded
======================  ==========  ===========  ==========

Three properties follow, and they are the reason this is a dependency rather
than a convention:

* **A response is always bounded.** The default applies when the client asks for
  nothing, so no collection endpoint can be talked into returning every row.
* **An over-large page is rejected before a handler runs.** The maximum is
  declared on the FastAPI parameter, so ``limit=100000`` is a ``422`` produced by
  request validation, not a live query against the database.
* **The window is echoed back.** ``page_meta`` puts ``limit`` and ``offset`` in
  the payload beside ``count`` and ``total``, so a client can compute the next
  request without remembering what it asked for.

Ordering is *not* part of this module, because ordering belongs to each store:
what this module guarantees is that whatever order a store uses is total (it ends
in a unique key), so two identical requests return the same page.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, TypedDict

from fastapi import Query

#: Page size used when the client does not ask for one.
DEFAULT_PAGE_SIZE = 100

#: Largest page any endpoint will serve.
MAX_PAGE_SIZE = 1000


@dataclass(frozen=True)
class PageWindow:
    """A resolved ``limit``/``offset`` pair, after validation.

    Attributes:
        limit: How many rows this page may hold, ``1..MAX_PAGE_SIZE``.
        offset: How many matching rows to skip, ``>= 0``.
    """

    limit: int = DEFAULT_PAGE_SIZE
    offset: int = 0

    @property
    def end(self) -> int:
        """Return the exclusive index one past the last row of this page."""
        return self.offset + self.limit

    @property
    def next_offset(self) -> int:
        """Return the ``offset`` a client should send for the following page."""
        return self.end

    def slice(self, rows: list) -> list:
        """Return the ``[offset, offset + limit)`` slice of an in-memory list.

        Used by the endpoints over runtime registries, which hold their rows in
        memory and therefore page by slicing rather than by ``LIMIT``/``OFFSET``.
        A slice past the end returns an empty list rather than raising, which is
        the correct answer for a page beyond the last one.
        """
        return rows[self.offset : self.end]


def pagination_params(
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=MAX_PAGE_SIZE,
            description="Maximum number of items to return",
        ),
    ] = DEFAULT_PAGE_SIZE,
    offset: Annotated[
        int,
        Query(ge=0, description="Number of matching items to skip"),
    ] = 0,
) -> PageWindow:
    """FastAPI dependency resolving the shared page window (M13.24).

    Both bounds are enforced by FastAPI's own validation, so an out-of-range
    value is a ``422`` naming the parameter and a handler is never reached.
    """
    return PageWindow(limit=int(limit), offset=int(offset))


class _PageMetaRequired(TypedDict):
    """The pagination fields every collection payload always carries."""

    count: int
    limit: int
    offset: int


class PageMeta(_PageMetaRequired, total=False):
    """The pagination block, typed so a caller can unpack it into a schema.

    Declaring it as a ``TypedDict`` rather than ``dict[str, object]`` is what
    lets a route write ``Model(**page_meta(...), items=rows)`` and still be
    type-checked: the keys are known, so the unpacking is not a blind cast, and
    the response model remains the one place the wire shape is described.
    """

    total: int
    has_more: bool


def page_meta(
    count: int,
    window: PageWindow,
    *,
    total: int | None = None,
    has_more: bool | None = None,
) -> PageMeta:
    """Return the pagination block shared by every collection payload.

    Args:
        count: How many items are in this page.
        window: The window that produced the page.
        total: How many items match overall, when the store can count them
            cheaply. Omitted when it cannot, so the field is absent rather than
            guessed at.
        has_more: Whether further pages exist. Derived from ``total`` when it is
            supplied and from the page being full otherwise — a full page is
            reported as possibly having more, because a store that cannot count
            cannot promise otherwise.

    Returns:
        ``{"count", "limit", "offset"}`` plus ``total`` and ``has_more``.
    """
    block = PageMeta(
        count=int(count), limit=int(window.limit), offset=int(window.offset)
    )
    if total is not None:
        block["total"] = int(total)
        block["has_more"] = (window.offset + int(count)) < int(total)
    elif has_more is not None:
        block["has_more"] = bool(has_more)
    elif count >= window.limit:
        block["has_more"] = True
    return block


__all__ = [
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "PageMeta",
    "PageWindow",
    "page_meta",
    "pagination_params",
]
