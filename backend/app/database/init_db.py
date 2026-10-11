"""Database initialization for NetWatch AI.

Two responsibilities, in order:

1. **Create** any missing table (``create_all``).
2. **Upgrade** what ``create_all`` cannot change: the M11 ``alerts.status``
   constraint, which SQLite cannot drop, and the M17 additive report columns,
   which ``create_all`` never adds to an already-existing table.

The second step is what makes a milestone work against a database created by an
earlier one. ``create_all`` never alters an existing table, so the M2
``alerts.status`` constraint — which predates the M11 lifecycle and rejects
``open`` and ``dismissed`` — would otherwise make every M11 alert write fail with
an ``IntegrityError``, and a ``reports`` table created before M17 would have no
``period_start`` for M17 to write. See :mod:`app.database.upgrade` for both: the
table rebuild and why foreign keys are disabled while it runs, and the additive
column upgrade that needs no rebuild at all.

Upgrades run *after* ``create_all`` for two reasons: a brand-new database already
gets the current schema from the model, so an upgrade finds nothing to do and
returns immediately; and a table that does not exist yet cannot be upgraded,
which is why each upgrade tolerates a missing table rather than requiring one.
"""

import logging

from app.database.base import Base
from app.database.session import engine
from app.database.upgrade import (
    upgrade_alert_status_constraint,
    upgrade_report_metadata_columns,
)

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
    """Apply every upgrade ``create_all`` cannot perform.

    Each upgrade is independently idempotent and independently safe: it inspects
    the live schema, adds only what is missing, and returns whether it changed
    anything. None of them is wrapped in a bare ``except``, because a schema that
    failed to upgrade would make every later write fail, and starting anyway would
    only move the failure somewhere less visible.
    """
    if upgrade_alert_status_constraint(engine):
        # Logged at info by the upgrade itself only when it actually rebuilds;
        # this line makes the *reason* the rebuild happened visible at startup.
        logger.info("Applied the M11 alert status constraint upgrade.")
    if upgrade_report_metadata_columns(engine):
        logger.info("Applied the M17 report metadata column upgrade.")
