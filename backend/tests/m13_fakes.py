"""Shared builders and dependency overrides for the M13 API tests.

The M13 surface is wide — seventeen routers over the same handful of services —
and every test file needs the same three things: a client that never touches the
developer's real database, a capture manager over fake interfaces rather than
the network, and the overrides applied and unwound around each test.

Putting those here means a test file states *what it expects* and nothing about
how a session or a manager is built. It follows the convention the rest of the
suite already uses (``tests.fakes``, ``tests.detection_fakes``, ...): builders
live in a ``*_fakes`` module and hold no assertions.

Nothing here weakens a test. The overrides are applied to the *same* dependency
keys the application uses, so a route still resolves its collaborator through
FastAPI and the wiring under test is the real wiring.
"""

from __future__ import annotations

from collections.abc import Callable, Generator, Mapping
from contextlib import contextmanager
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.config.settings import settings
from app.main import app
from app.services.capture_manager import CaptureManager
from tests.fakes import make_interface_manager, make_sniffer_factory


def make_db_override(db_engine) -> Callable[[], Generator[Session, None, None]]:
    """Return a ``get_db`` override yielding sessions from ``db_engine``.

    The tables are created on the isolated engine so a route that reads a table
    finds it, and the session is closed when the request ends — the same
    lifetime :func:`app.database.session.get_db` gives a real request.
    """
    # Importing the models package registers every table with Base.metadata.
    from app import models as _models  # noqa: F401
    from app.database.base import Base

    Base.metadata.create_all(bind=db_engine)

    def override() -> Generator[Session, None, None]:
        session = Session(bind=db_engine)
        try:
            yield session
        finally:
            session.close()

    return override


def make_capture_manager(
    *,
    interfaces: list[dict] | None = None,
    registry: list | None = None,
) -> CaptureManager:
    """Return a capture manager over fake interfaces and a default pipeline.

    The pipeline is the real :class:`~app.services.packet_pipeline.PacketPipeline`
    with no persistence, connections, detection, alerting or correlation wired
    in, which is how the pipeline behaves when those layers are switched off.
    That keeps a system/dashboard test free of a database while still exercising
    the production class rather than a stub of it.
    """
    return CaptureManager(
        interface_manager=make_interface_manager(interfaces),
        sniffer_factory=make_sniffer_factory(registry=registry),
    )


def capture_manager_override() -> Callable[[], CaptureManager]:
    """Return a zero-argument ``get_capture_manager`` override (M13.22).

    A dependency override must be a callable FastAPI can invoke with *no*
    arguments. ``make_capture_manager`` takes keyword arguments, so passing it
    directly makes FastAPI read those parameters as request inputs — it demanded a
    form body the first time this was tried, and answered 500. This wrapper is the
    override; the builder stays a builder.
    """
    return lambda: make_capture_manager()


@contextmanager
def api_client(
    overrides: Mapping[Callable[..., Any], Callable[..., Any]] | None = None,
) -> Generator[TestClient, None, None]:
    """Yield a test client with ``overrides`` applied, then restore the app.

    ``overrides`` maps a FastAPI dependency — the function a route declares in
    ``Depends`` — to the value to serve in its place. It is a positional mapping
    rather than keyword arguments because that is what
    ``app.dependency_overrides`` is keyed by: a *function*, which cannot be a
    keyword name. Spelling the same mapping as keywords would silently turn each
    key into a string and no override would ever apply.

    The application environment is temporarily ``"test"`` so the lifespan skips
    ``init_db()`` and never touches the real database — the same precaution the
    rest of the suite takes. Every override is removed afterwards, so one test
    cannot leak a double into the next.
    """
    applied = dict(overrides or {})
    original_env = settings.app_env
    settings.app_env = "test"
    for dependency, value in applied.items():
        app.dependency_overrides[dependency] = value
    try:
        with TestClient(app) as client:
            yield client
    finally:
        for dependency in applied:
            app.dependency_overrides.pop(dependency, None)
        settings.app_env = original_env


__all__ = [
    "api_client",
    "capture_manager_override",
    "make_capture_manager",
    "make_db_override",
]
