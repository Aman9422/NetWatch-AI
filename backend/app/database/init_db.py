"""Database initialization for NetWatch AI.

Two responsibilities, in order:

1. **Create** any missing table (``create_all``).
2. **Upgrade** the constraints ``create_all`` cannot change (M11).

The second step is what makes M11 work against a database created by an earlier
milestone. ``create_all`` never alters an existing table, and SQLite cannot drop
a CHECK constraint, so the M2 ``alerts.status`` constraint — which predates the
M11 lifecycle and rejects ``open`` and ``dismissed`` — would otherwise make every
M11 alert write fail with an ``IntegrityError``. See
:mod:`app.database.upgrade` for the rebuild and why foreign keys are disabled
while it runs.

Upgrades run *after* ``create_all`` for two reasons: a brand-new database already
gets the current constraints from the model, so the upgrade finds nothing to do
and returns immediately; and a table that does not exist yet cannot be upgraded,
which is why the upgrade tolerates a missing table rather than requiring one.
"""

import logging

from app.database.base import Base
from app.database.session import engine
from app.database.upgrade import upgrade_alert_status_constraint

# Importing the models package registers every model with ``Base.metadata``.
# This is what lets ``create_all()`` discover and create all the tables.
# The import is intentionally inside the function so the module can be
# imported without requiring a working database at import time.
from app import models as _models  # noqa: F401  (import needed for metadata registration)

logger = logging.getLogger(__name__)


def init_db() -> None:
    """Create missing tables and apply the schema upgrades M11 requires.

    In development this gives a zero-friction experience: the schema is ready —
    and current — before the first request. A production deployment would manage
    this with Alembic migrations instead, in which case both calls here are the
    development equivalent of "run the migrations".

    The upgrades are deliberately **not** wrapped in a bare ``except``: a schema
    that fails to upgrade would make every subsequent alert write fail, so
    starting anyway would only move the failure somewhere less visible.
    """
    logger.info("Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    _apply_schema_upgrades()
    logger.info("Database schema ready.")


def _apply_schema_upgrades() -> None:
    """Apply the constraint upgrades ``create_all`` cannot perform."""
    if upgrade_alert_status_constraint(engine):
        # Logged at info by the upgrade itself only when it actually rebuilds;
        # this line makes the *reason* the rebuild happened visible at startup.
        logger.info("Applied the M11 alert status constraint upgrade.")
