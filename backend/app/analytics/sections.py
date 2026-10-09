"""Availability of database-derived analytics blocks (M16.8/M16.7).

An analytics response mixes two kinds of material: numbers read from in-process
services (the M6 statistics manager, the M8 registry, the M9 tracker, the M10
engine, the M12 registry) and numbers read from SQLite (the ``packets``,
``connections`` and ``alerts`` tables). Only the second kind can fail on its own.
A runtime service runs in this process and either answers or takes the request
down with it; a database read can fail for a reason that has nothing to do with
the rest of the response — a locked file, a full disk, a dropped connection.

So each database-derived block is read through :func:`read_section` and reported
as an *availability section*::

    {"available": true,  "error": null, "data": {...}}
    {"available": false, "error": "...", "data": null}

That shape is the dashboard's (M13.19/M13.29): every section is always present,
so a client renders a fixed layout, and a section that could not be read says so
rather than being silently zeroed. Zeroing is the outcome M16 explicitly forbids
— a missing value must never be presented as a measured zero — so "unavailable"
and "empty" are two different answers here and both are representable.

**What the client is told.** Exactly one constant sentence,
:data:`UNAVAILABLE_MESSAGE`. It names no table, no column, no query and no
exception text (M13.30/M16.8). The real exception is logged with the section's
own name, which is where an operator looks for it.

**Recovery.** A failed statement leaves a SQLAlchemy session in a state where
every later statement raises until the transaction is rolled back, so the session
is rolled back before the section is reported. Without that, one unavailable
block would silently make the following ones unavailable too, and the response
would blame three services for one fault.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

#: The one sentence a client is given when a block could not be read.
UNAVAILABLE_MESSAGE = "This section could not be read from the database"

#: The payload type a section carries.
PayloadT = TypeVar("PayloadT")


@dataclass(frozen=True)
class SectionOutcome(Generic[PayloadT]):
    """The result of reading one database-derived analytics block (M16.8).

    Attributes:
        available: True when the read succeeded. An available section with empty
            data is the honest answer for "there is nothing stored"; an
            unavailable one means the question could not be asked.
        error: A safe, constant sentence when ``available`` is False, else
            ``None``.
        data: The payload, or ``None`` when the block is unavailable.
    """

    available: bool
    error: str | None
    data: PayloadT | None


def read_section(
    loader: Callable[[], PayloadT], *, name: str, session: Session | None = None
) -> SectionOutcome[PayloadT]:
    """Run ``loader`` and return its value as a section, never raising.

    Args:
        loader: Reads one block. Any exception it raises is contained here.
        name: The block's name, used in the log line and never in the response.
        session: The session ``loader`` reads through, rolled back on failure so
            a fault in one block does not take the following ones with it. Pass
            ``None`` when the loader opens its own session.

    Returns:
        An available section holding the loader's value, or an unavailable one
        holding :data:`UNAVAILABLE_MESSAGE`. There is no third outcome and no
        exception path: this function is total, which is what lets a route build
        a complete response out of blocks that may individually fail.

    Notes:
        A bare ``except Exception`` is deliberate and is the only place in the
        analytics layer that catches broadly. The alternative — enumerating the
        failures a database can produce — would either let an unanticipated one
        escape into a 500 with no section information, or grow a list that is
        wrong the moment a new driver error appears. The failure is not hidden:
        it is logged with a traceback and named by section.
    """
    try:
        return SectionOutcome(available=True, error=None, data=loader())
    except Exception:  # noqa: BLE001 - see the docstring: contained, logged, named
        logger.exception("Analytics section %s could not be read", name)
        if session is not None:
            try:
                session.rollback()
            except Exception:  # noqa: BLE001 - recovery must not mask the cause
                logger.debug("Rollback after a failed analytics read failed too")
        return SectionOutcome(available=False, error=UNAVAILABLE_MESSAGE, data=None)


__all__ = ["UNAVAILABLE_MESSAGE", "SectionOutcome", "read_section"]
