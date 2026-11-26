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


def _start_baseline_engine() -> None:
    """Start the M21 baseline flush thread (M21.9).

    Started first among the background components so a window that closes while
    the application is booting is written on the normal interval rather than
    waiting for capture to stop. Guarded: a learner that cannot start is a
    feature that will not run, which is worth a loud log line but is not a reason
    to refuse to start the application — capture, detection and the API all work
    without it.
    """
    from app.baselines import get_baseline_engine
    from app.config.settings import settings as _settings

    if not _settings.baseline_enabled:
        logger.info("Behavioural baseline learning disabled by configuration")
        return
    try:
        get_baseline_engine().start()
    except Exception:  # noqa: BLE001 - startup must not fail on the learner
        logger.exception("Failed to start the behavioural baseline engine")


def _stop_baseline_engine() -> None:
    """Flush every open behavioural window and stop the thread (M21.5).

    A partial window is still real observation, so it is written rather than
    discarded. Stopped *before* the other databases writers below, so the
    baseline flush does not overlap the packet or connection flush on one SQLite
    file. Guarded because shutdown must never raise.
    """
    from app.baselines import get_baseline_engine

    try:
        written = get_baseline_engine().flush_all()
    except Exception:  # noqa: BLE001 - shutdown must never raise
        logger.exception("Failed to flush baseline windows during shutdown")
        written = 0
    try:
        get_baseline_engine().stop(flush=False)
    except Exception:  # noqa: BLE001 - shutdown must never raise
        logger.exception("Failed to stop the behavioural baseline engine")
    if written:
        logger.info("Flushed %d baseline window(s) during shutdown", written)


def _enqueue_windows(windows: list) -> None:
    """Hand committed M21 windows to the anomaly engine (M22.8).

    A module-level function rather than a lambda so the listener contract is
    explicit: it returns ``None`` and never raises. ``enqueue`` cannot block and a
    window it drops is counted by the engine, so there is nothing here to retry —
    a stale evaluation is worth less than the newest one, and the queue is bounded
    so a slow model can never grow this process's memory.
    """
    from app.anomaly_detection import get_anomaly_engine, windows_from_counters

    get_anomaly_engine().enqueue(windows_from_counters(windows))


def _start_anomaly_engine() -> None:
    """Start the M22 anomaly worker and attach it to the learner (M22.8).

    The learner does not import this layer: the lifespan hands it a callable, so
    a build without scikit-learn still learns baselines and simply has no ML
    consumer. Attached *before* the flush thread starts, so no window written on
    the first interval is missed.

    Guarded: an ML layer that cannot start is a detection feature that will not
    run, which is worth a loud log line but is not a reason to refuse to start the
    application. Capture, statistics, M21 learning, deterministic detection,
    alerting and the API all work without it.
    """
    from app.anomaly_detection import get_anomaly_engine
    from app.baselines import get_baseline_engine

    if not settings.anomaly_detection_enabled:
        logger.info("ML anomaly detection disabled by configuration")
        return
    try:
        get_anomaly_engine().start()
        get_baseline_engine().attach_window_listener(_enqueue_windows)
    except Exception:  # noqa: BLE001 - startup must not fail on the ML layer
        logger.exception("Failed to start ML anomaly detection")


def _stop_anomaly_engine() -> None:
    """Detach, drain and stop the anomaly worker (M22.8).

    Called *after* the learner has flushed its final windows, so the last window of
    the session is evaluated rather than dropped, and before the other database
    writers, so two writers are never on one SQLite file at once. A failure to
    drain is logged and does not prevent stopping the thread. Guarded because
    shutdown must never raise.
    """
    from app.anomaly_detection import get_anomaly_engine
    from app.baselines import get_baseline_engine

    try:
        get_baseline_engine().attach_window_listener(None)
    except Exception:  # noqa: BLE001 - shutdown must never raise
        logger.exception("Failed to detach the baseline window listener")
    try:
        get_anomaly_engine().shutdown()
    except Exception:  # noqa: BLE001 - shutdown must never raise
        logger.exception("Failed to stop ML anomaly detection")


def _start_retention_sweep() -> None:
    """Start the periodic retention sweep (M19.5).

    Started after the schema exists and before the application accepts traffic, so
    a configured retention window is enforced for as long as the application runs.
    The first pass is one interval away, so startup never deletes anything.

    Guarded: a retention sweep that cannot start is a policy that will not be
    enforced, which is worth a loud log line but is not a reason to refuse to start
    the application — capture, detection and the API all work without it.
    """
    from app.services.retention_scheduler import get_retention_sweeper

    try:
        get_retention_sweeper().start()
    except Exception:  # noqa: BLE001 - startup must not fail on the sweep
        logger.exception("Failed to start the retention sweep")


def _stop_retention_sweep() -> None:
    """Stop the periodic retention sweep and join its thread (M19.4).

    Stopped *first* in the shutdown sequence: a pass drives the same database the
    flushes below use, and letting a cleanup run while the persistence layer is
    shutting down would put two writers on one SQLite file for no benefit. Guarded
    because shutdown must never raise, and the thread is a daemon if the join
    times out, so the process still exits.
    """
    from app.services.retention_scheduler import get_retention_sweeper

    try:
        get_retention_sweeper().stop()
    except Exception:  # noqa: BLE001 - shutdown must never raise
        logger.exception("Failed to stop the retention sweep")


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
    # The retention sweep (M19.5). Started here, after the schema exists, because
    # the policies it applies delete rows: running it against a database that has
    # not been initialized yet would only produce a failure it would then have to
    # contain. It is also started before the application serves traffic, so a
    # configured retention window is enforced from the first interval onwards.
    _start_retention_sweep()
    # The behavioural learner (M21.9). Its thread is what writes an observation
    # window, so it starts once the schema exists and before traffic can arrive.
    _start_baseline_engine()
    # ML anomaly detection (M22.8). Wired to the learner above as an additional
    # consumer of *completed* windows, so it never sits in the packet path.
    _start_anomaly_engine()
    # The real-time layer (M14.20). Started after the schema exists and before
    # the application accepts traffic, so the loop is bound and the heartbeat and
    # dashboard tasks exist before the first client can dial in.
    await start_websockets()
    yield
    logger.info("Shutting down %s", settings.app_name)
    _stop_retention_sweep()
    _stop_active_capture()
    # The learner is stopped after capture, so the final windows of the session
    # are already aggregated, and before the other flushes, so two writers are
    # never on the same SQLite file at once (M21.5).
    _stop_baseline_engine()
    # Evaluated once the learner has written the session's final windows, and
    # before the other writers, for the same single-writer reason (M22.8).
    _stop_anomaly_engine()
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
