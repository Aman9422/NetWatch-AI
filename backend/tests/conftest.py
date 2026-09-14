"""Shared pytest fixtures for the NetWatch AI backend tests."""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.config.settings import settings
from app.main import app


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    """Return a FastAPI test client.

    The application lifespan creates tables when ``app_env == "development"``.
    For tests we temporarily set it to ``"test"`` so the lifespan skips
    ``init_db()`` and never touches the real ``netwatch.db``. The original
    value is restored afterwards so other tests still see the default.
    """
    original_env = settings.app_env
    settings.app_env = "test"
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        settings.app_env = original_env


@pytest.fixture
def db_engine():
    """Provide an isolated in-memory SQLite engine with foreign keys enabled.

    ``StaticPool`` ensures every connection reuses the same in-memory database
    within a single test, which is required for ``:memory:`` databases.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
        """Turn on foreign-key enforcement for this in-memory database."""
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.close()

    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine) -> Generator[Session, None, None]:
    """Provide a session bound to a fresh in-memory database.

    All model tables are created before the test and dropped afterwards, so
    each test starts from a clean, isolated state.
    """
    # Importing the models package registers every table with Base.metadata.
    from app import models as _models  # noqa: F401
    from app.database.base import Base

    Base.metadata.create_all(bind=db_engine)
    session = Session(bind=db_engine)
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=db_engine)


@pytest.fixture
def session_factory(db_engine):
    """Provide a factory of sessions bound to the isolated in-memory database.

    The M7 persistence layer takes a *factory* rather than a session, because a
    SQLAlchemy session is not thread-safe and the persistence worker runs on its
    own thread. This fixture supplies a factory pointing at the temporary engine
    so persistence tests never touch the developer's real ``netwatch.db``.
    """
    # Importing the models package registers every table with Base.metadata.
    from app import models as _models  # noqa: F401
    from app.database.base import Base

    Base.metadata.create_all(bind=db_engine)

    def factory() -> Session:
        return Session(bind=db_engine)

    try:
        yield factory
    finally:
        Base.metadata.drop_all(bind=db_engine)
