"""The database session factory shared by the packet persistence layer (M7).

Persistence needs to build a **fresh** SQLAlchemy session per batch, because a
session is not thread-safe and the worker runs on its own thread. It therefore
takes a *factory* as a dependency, so tests can inject an isolated in-memory
database instead of the developer's live one.

This module exists for one reason: to keep the real engine out of import time.
``app.database.session`` builds the production ``Engine`` as a side effect of
being imported, so importing it at module scope here would mean that merely
importing the persistence package (or constructing it with an injected factory)
would open ``netwatch.db``. The import is therefore deferred into
:func:`app_session_factory` and happens only when a session is actually needed.
"""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.orm import Session

# Builds a new session bound to some database; injected into the worker and the
# retention service so both can be tested against an isolated database.
SessionFactory = Callable[[], Session]


def app_session_factory() -> Session:
    """Open a session bound to the application database.

    The ``SessionLocal`` import lives inside the function on purpose: importing
    this module must never create the production engine.
    """
    from app.database.session import SessionLocal

    return SessionLocal()
