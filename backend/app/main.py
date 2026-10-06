"""NetWatch AI — FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.common import register_exception_handlers
from app.api.v1 import api_router
from app.config.settings import settings
from app.database.init_db import init_db
from app.services.capture_manager import get_capture_manager
from app.utils.logging import configure_logging
from app.utils.runtime import mark_process_started
from app.websockets import shutdown_websockets, start_websockets, websocket_router

logger = logging.getLogger(__name__)

configure_logging()


def _stop_active_capture() -> None:
    """Gracefully stop an active packet capture during application shutdown."""
    manager = get_capture_manager()
    if not manager.is_running():
        return
    try:
        manager.stop()
    except Exception:  # noqa: BLE001 - shutdown must never raise
        logger.exception("Failed to stop packet capture during shutdown")


def _shutdown_persistence() -> None:
    """Flush buffered packets and stop the persistence worker (M7.18).

    Stopping capture already flushes, but this also covers the case where a
    persistence worker holds packets without an active capture session. The
    call is guarded because application shutdown must never raise.
    """
    from app.persistence.manager import get_packet_persistence

    try:
        get_packet_persistence().shutdown()
    except Exception:  # noqa: BLE001 - shutdown must never raise
        logger.exception("Failed to flush packet persistence during shutdown")


def _shutdown_connections() -> None:
    """Write the remaining connection aggregates and stop the sweep (M9.18).

    Stopping capture already flushes the conversations of that session, but a
    tracker that outlived a capture session (or never captured at all) may still
    hold conversations and a running cleanup thread. Shutting it down retires
    what is idle, writes the rest and joins the thread, so no daemon thread
    survives the application. Guarded because shutdown must never raise.
    """
    from app.connections.manager import get_connection_tracker

    try:
        get_connection_tracker().shutdown()
    except Exception:  # noqa: BLE001 - shutdown must never raise
        logger.exception("Failed to flush connection tracking during shutdown")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager.

    Runs startup and shutdown tasks.

    On startup, the database schema is created automatically during
    development, then the app is ready to accept requests. On shutdown, any
    active packet capture is stopped, the packet persistence layer is flushed
    and closed (M7.18), and the connection tracker writes its remaining
    aggregates and stops its cleanup sweep (M9.17/M9.18).
    """
    # Record the start before anything else, so the uptime /system reports is the
    # uptime of the application rather than of its first API request (M13.22).
    mark_process_started()
    logger.info("Starting %s (%s) — environment: %s", settings.app_name, settings.app_version, settings.app_env)
    if settings.app_env == "development":
        init_db()
    # The real-time layer (M14.20). Started after the schema exists and before
    # the application accepts traffic, so the loop is bound and the heartbeat and
    # dashboard tasks exist before the first client can dial in.
    await start_websockets()
    yield
    logger.info("Shutting down %s", settings.app_name)
    _stop_active_capture()
    _shutdown_persistence()
    _shutdown_connections()
    # The WebSocket layer is torn down *last* (M14.20): stopping capture publishes
    # the final capture.stopped event and the flushes above publish nothing, so
    # tearing the transport down first would lose the last events of the session.
    await shutdown_websockets()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="NetWatch AI — network monitoring and security detection platform.",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Configure CORS for the frontend development server (M15.3). The allowlist is
# configuration rather than a literal because the dev server's port is: a browser
# sends an `Origin` and refuses a response that does not name it, so the origins
# this project actually serves the frontend from have to be listed here or every
# page reads as an error state. `settings.cors_allow_origins` carries them.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API router under /api/v1.
app.include_router(api_router, prefix="/api/v1")

# Register the real-time channels (M14.3) at /ws/{channel}. Unversioned on
# purpose: /api/v1 is the versioned *resource* surface (M13.3), and a channel is
# neither a resource nor a versioned API — it is one of four named streams whose
# paths are declared once, in app.websockets.channels.
app.include_router(websocket_router)

# Translate every failure into the one documented error envelope (M13.5/M13.29).
# Registered once, after the routers, so an unrouted URL, a wrong verb and an
# unexpected exception all answer in the shape the rest of the API uses. An
# unexpected failure is rendered as an opaque 500: no traceback, no path and no
# query text reaches the client, and the API fault is contained here rather than
# left to reach the capture pipeline (M13.30).
register_exception_handlers(app)
