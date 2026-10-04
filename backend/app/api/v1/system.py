"""System API endpoints for NetWatch AI (M13.22).

Answers "what is this process, and is everything it depends on working?" from
three angles, each with its own endpoint because they are consumed by different
things:

* ``/system/info`` — identity. What the application calls itself, which version
  is running and which environment it was started in. No dependency is touched,
  so it answers even when the rest of the application is unhappy.
* ``/system/health`` — a *probe*, one entry per dependency, with an aggregate
  verdict. It runs a real query against the database rather than asserting that
  the database exists, because a health check that cannot fail is not a check.
* ``/system/status`` — the consolidated picture: identity, capture, database,
  each pipeline stage and basic runtime metrics.

Three things are deliberately withheld, all for the same reason (M13.5/M13.30):

* the database URL, because it is a filesystem path or a credential-bearing DSN;
  the *dialect* is reported instead, which is what a client can act on anyway;
* any exception text, because a driver message can name a path or a host. A
  failed probe reports which dependency failed, never the driver's sentence;
* the capture interface list, packet payloads and anything else a caller would
  have to be entitled to. This is a local-application API with no authentication
  (M13.30), so it exposes state, not secrets.

Nothing here starts, stops or reconfigures anything. A read-only system surface
that could be talked into changing state would be a way to disturb capture from a
monitoring tool, which is the opposite of what it is for.
"""

from __future__ import annotations

import logging
import os
import platform
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.common import success_payload
from app.config.settings import settings
from app.database.session import engine, get_db
from app.schemas.alert import to_iso_timestamp
from app.schemas.system import (
    CaptureStateView,
    DatabaseStateView,
    HealthCheckView,
    RuntimeMetricsView,
    ServiceStateView,
    SystemHealthData,
    SystemInfoData,
    SystemStatusData,
)
from app.services.capture_manager import CaptureManager, get_capture_manager
from app.services.packet_pipeline import PacketPipeline
from app.utils import runtime

logger = logging.getLogger(__name__)

router = APIRouter()

#: Aggregate verdict when every probe passed.
STATUS_HEALTHY = "healthy"
#: Aggregate verdict when at least one probe failed.
STATUS_DEGRADED = "degraded"

#: The API speaks ISO-8601 in UTC (M13.26).
API_TIMEZONE = "UTC"

#: Base path every route in this API is served under (M13.3).
API_PREFIX = "/api/v1"

#: Version label, derived from the base path so the two cannot drift apart.
API_VERSION = API_PREFIX.rsplit("/", 1)[-1]


def _db_dialect() -> str:
    """Return the database engine family, never its URL (M13.22/M13.30)."""
    try:
        return str(engine.dialect.name)
    except Exception:  # noqa: BLE001 - a probe must never raise
        return "unknown"


def _database_reachable(db: Session) -> bool:
    """Return True when a trivial query succeeds (M13.22).

    ``SELECT 1`` is used rather than a table read on purpose: it proves the
    connection works without depending on any particular schema being present, so
    a fresh database that has not been initialised still reports reachable.
    """
    try:
        db.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001 - an unreachable database is a verdict
        logger.warning("Database health probe failed", exc_info=True)
        return False


def _capture_state(manager: CaptureManager) -> CaptureStateView:
    """Build the capture block, including the per-stage error counters (M13.22).

    The counters come from the pipeline rather than the manager where the
    pipeline can offer them, because the pipeline is where persistence errors are
    counted and the manager has no accessor for that stage.
    """
    status = manager.get_status()
    pipeline = manager.get_pipeline()
    errors = {
        "processing": manager.get_processing_error_count(),
        "persistence": pipeline.get_persistence_error_count(),
        "statistics": manager.get_statistics_error_count(),
        "devices": manager.get_device_error_count(),
        "connections": manager.get_connection_error_count(),
        "detection": manager.get_detection_error_count(),
        "alerts": manager.get_alert_error_count(),
        "correlation": manager.get_correlation_error_count(),
    }
    return CaptureStateView(
        running=manager.is_running(),
        status=status.status,
        interface=status.interface,
        packet_count=status.packet_count,
        processed_packet_count=manager.get_processed_packet_count(),
        error_counts={name: count for name, count in errors.items() if count},
    )


def _service_states(pipeline: PacketPipeline) -> list[ServiceStateView]:
    """Describe each pipeline stage and whether it is actually attached (M13.22).

    ``enabled`` is read from configuration and ``attached`` from the live
    pipeline object. They are collected together because the interesting case is
    exactly the one where they differ, and reporting only the configuration would
    hide it.
    """
    return [
        ServiceStateView(
            name="persistence",
            enabled=bool(settings.packet_persistence_enabled),
            attached=pipeline.persistence is not None,
        ),
        # Statistics and device discovery are built by the pipeline itself, so
        # they are attached whenever there is a pipeline at all. Reporting the
        # constant rather than comparing against it keeps the payload honest:
        # there is no configuration under which this could be False.
        ServiceStateView(name="statistics", enabled=True, attached=True),
        ServiceStateView(name="devices", enabled=True, attached=True),
        ServiceStateView(
            name="connections",
            enabled=bool(settings.connection_tracking_enabled),
            attached=pipeline.connections is not None,
        ),
        ServiceStateView(
            name="detection",
            enabled=bool(settings.detection_enabled),
            attached=pipeline.detection is not None,
        ),
        ServiceStateView(
            name="alerts",
            enabled=bool(settings.alerts_enabled),
            attached=pipeline.alerts is not None,
        ),
        ServiceStateView(
            name="correlation",
            enabled=bool(settings.correlation_enabled),
            attached=pipeline.correlation is not None,
        ),
    ]


def _runtime_metrics() -> RuntimeMetricsView:
    """Build the runtime block from the startup mark (M13.22)."""
    started = runtime.started_at()
    return RuntimeMetricsView(
        uptime_seconds=runtime.uptime_seconds(),
        started_at=to_iso_timestamp(started),
        generated_at=to_iso_timestamp(datetime.now(timezone.utc)) or "",
        python_version=platform.python_version(),
        pid=os.getpid(),
    )


#: The HTTP methods an OpenAPI path item may document. Listing them means a
#: path-level key such as ``parameters`` is not mistaken for an operation.
DOCUMENTED_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
)


def _api_route_count(app_request: Request) -> int | None:
    """Count the documented routes served under the API base path (M13.22).

    The count is read from the OpenAPI document, and that is not a shortcut —
    ``app.routes`` cannot answer this question. Since FastAPI 0.141 an included
    router stays *nested*: ``app.routes`` holds a single object standing for
    ``/api/v1`` rather than the sixty-one routes behind it, so walking it reports
    a number that is simply wrong. (It reported ``0`` when this was written.)

    The document is the right source for its own reason too: M13.27 requires it
    to list every endpoint, so counting it reports the surface a client can
    actually call. FastAPI caches the document after the first build, so every
    request after the first is a walk over a dictionary.

    Returns:
        The number of method/path routes under the prefix, or ``None`` when the
        document could not be built. ``None`` rather than ``0``: a surface that
        could not be counted and an empty surface are different statements, and
        only one of them is true when building the document raises.
    """
    try:
        document = app_request.app.openapi()
    except Exception:  # noqa: BLE001 - a metric must never fail its endpoint
        logger.warning("Could not build the OpenAPI document", exc_info=True)
        return None
    paths = document.get("paths") if isinstance(document, dict) else None
    if not isinstance(paths, dict):
        return None
    return sum(
        1
        for path, operations in paths.items()
        if str(path).startswith(API_PREFIX)
        for method in operations
        if str(method).lower() in DOCUMENTED_METHODS
    )


def _info(app_request: Request) -> SystemInfoData:
    """Build the identity block from configuration and the live app (M13.22)."""
    app = app_request.app
    return SystemInfoData(
        app_name=settings.app_name,
        app_version=settings.app_version,
        environment=settings.app_env,
        api_version=API_VERSION,
        timezone=API_TIMEZONE,
        platform=platform.platform(),
        database_dialect=_db_dialect(),
        registered_route_count=_api_route_count(app_request),
        docs_url=getattr(app, "docs_url", None),
        openapi_url=getattr(app, "openapi_url", None),
    )


def _health_checks(db: Session, manager: CaptureManager) -> list[HealthCheckView]:
    """Run every probe and return one verdict per dependency (M13.22).

    Two probes, both of which can genuinely fail:

    * the database, by running a query;
    * the capture subsystem, by asking the manager for a snapshot — a manager
      that cannot produce one is a real failure, not a formality.

    "Capture is not running" is *not* a failure. Capture is opt-in, so an idle
    application is healthy; the detail line says which state it is in so the
    distinction is visible without being treated as a fault.
    """
    reachable = _database_reachable(db)
    checks = [
        HealthCheckView(
            name="database",
            ok=reachable,
            detail="database responded to a trivial query"
            if reachable
            else "database did not respond",
        )
    ]
    try:
        running = manager.is_running()
        checks.append(
            HealthCheckView(
                name="capture",
                ok=True,
                detail="capture is running" if running else "capture is idle",
            )
        )
    except Exception:  # noqa: BLE001 - a probe reports, it does not raise
        logger.warning("Capture health probe failed", exc_info=True)
        checks.append(
            HealthCheckView(
                name="capture",
                ok=False,
                detail="capture subsystem did not report its state",
            )
        )
    return checks


def _overall_status(checks: list[HealthCheckView]) -> str:
    """Return the worst verdict across ``checks`` (M13.22)."""
    return STATUS_HEALTHY if all(check.ok for check in checks) else STATUS_DEGRADED


@router.get("/info", response_model=None)
def get_system_info(request: Request) -> dict:
    """Return application identity and environment (M13.22).

    Touches no dependency, so it answers even when the database or the capture
    subsystem is unavailable — which is exactly when a caller most wants to know
    which build it is talking to.
    """
    payload = _info(request)
    return success_payload("System info retrieved", payload.model_dump(mode="json"))


@router.get("/health", response_model=None)
def get_system_health(
    db: Session = Depends(get_db),
    manager: CaptureManager = Depends(get_capture_manager),
) -> dict:
    """Probe the dependencies and report an aggregate verdict (M13.22).

    Always answers ``200``: the endpoint reports health, it does not gate on it.
    A dependency being down is a *verdict* in the payload, not a failure of the
    request. Returning ``503`` here would make the caller unable to read which
    probe failed, which is the only useful part of the answer.

    The verdict is not part of the standard ``data``-only contract in spirit —
    but it is still delivered inside the standard envelope, so a client parses one
    shape.
    """
    checks = _health_checks(db, manager)
    payload = SystemHealthData(status=_overall_status(checks), checks=checks)
    if payload.status != STATUS_HEALTHY:
        logger.warning("System health is degraded: %s", payload.status)
    return success_payload("System health retrieved", payload.model_dump(mode="json"))


@router.get("/status", response_model=None)
def get_system_status(
    request: Request,
    db: Session = Depends(get_db),
    manager: CaptureManager = Depends(get_capture_manager),
) -> dict:
    """Return the consolidated process, database and pipeline state (M13.22).

    Assembled from the services that already own each fact — capture state from
    the capture manager, reachability from a query, stage configuration from
    settings, uptime from the startup mark — so this endpoint computes nothing of
    its own. That is what keeps it from drifting away from what the dedicated
    endpoints on ``/capture`` and ``/statistics`` report.
    """
    reachable = _database_reachable(db)
    payload = SystemStatusData(
        status=STATUS_HEALTHY if reachable else STATUS_DEGRADED,
        info=_info(request),
        capture=_capture_state(manager),
        database=DatabaseStateView(reachable=reachable, dialect=_db_dialect()),
        services=_service_states(manager.get_pipeline()),
        runtime=_runtime_metrics(),
    )
    return success_payload("System status retrieved", payload.model_dump(mode="json"))


__all__ = [
    "API_PREFIX",
    "API_TIMEZONE",
    "API_VERSION",
    "DOCUMENTED_METHODS",
    "STATUS_DEGRADED",
    "STATUS_HEALTHY",
    "router",
]
