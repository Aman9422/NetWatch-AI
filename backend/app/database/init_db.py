"""Database initialization for NetWatch AI."""

import logging

from app.database.base import Base
from app.database.session import engine

# Importing the models package registers every model with ``Base.metadata``.
# This is what lets ``create_all()`` discover and create all the tables.
# The import is intentionally inside the function so the module can be
# imported without requiring a working database at import time.
from app import models as _models  # noqa: F401  (import needed for metadata registration)

logger = logging.getLogger(__name__)


def init_db() -> None:
    """Create any missing tables in the database.

    ``Base.metadata.create_all(engine)`` inspects the database and creates
    only the tables that do not already exist. It is therefore safe to call
    on every application start — it will not drop or overwrite existing data.

    In development this gives a zero-friction experience: the schema is ready
    before the first request. In production you would typically manage schema
    changes with Alembic migrations instead.
    """
    logger.info("Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database schema ready.")
