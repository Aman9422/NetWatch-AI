"""Database engine, session factory, and FastAPI dependency for NetWatch AI."""

import logging
from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config.settings import settings

logger = logging.getLogger(__name__)

# SQLite is embedded, so it may be accessed from multiple threads (e.g. the
# FastAPI thread pool). ``check_same_thread=False`` allows that.
# For PostgreSQL (future), no such argument is needed.
_is_sqlite = settings.database_url.startswith("sqlite")
_connect_args = {"check_same_thread": False} if _is_sqlite else {}

engine: Engine = create_engine(
    settings.database_url,
    connect_args=_connect_args,
    echo=settings.app_env == "development" and settings.log_level == "DEBUG",
)


def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
    """Enable foreign-key enforcement on every new SQLite connection.

    SQLite leaves foreign keys OFF by default. This event listener runs the
    ``PRAGMA foreign_keys = ON`` command each time a connection is opened,
    so orphaned records (e.g. a packet referencing a non-existent device)
    are rejected.

    Args:
        dbapi_connection: The raw DBAPI connection to configure.
        _connection_record: Connection record. Unused; the underscore prefix
            tells tools like Pylance/pylint that this argument is intentional.
    """
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys = ON")
    cursor.close()


if _is_sqlite:
    event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    logger.info("SQLite foreign-key enforcement enabled for %s", settings.database_url)

# Session factory. ``autoflush=False`` means SQLAlchemy will not automatically
# push pending changes to the database before a query runs; you explicitly call
# ``session.commit()`` to save changes. (In SQLAlchemy 2.0 ``autocommit`` was
# removed entirely — transactions are always explicit — so we omit it.)
SessionLocal = sessionmaker(bind=engine, autoflush=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session.

    Usage in an endpoint:

    .. code-block:: python

        @router.get("/devices")
        def list_devices(db: Session = Depends(get_db)):
            return db.query(Device).all()

    The session is always closed afterwards, even if an exception occurs,
    so connections are never leaked.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
