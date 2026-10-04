"""API v1 package for NetWatch AI.

One router per resource, each mounted under its own prefix on a single
``api_router`` that :mod:`app.main` serves at ``/api/v1`` (M13.3). A resource's
paths are therefore decided in exactly one place — this file — so the OpenAPI
document and the running application cannot disagree about where anything lives.

The include order is the order the routers appear in the OpenAPI document. It is
deliberately the order the milestones were built in — capture, then the data it
produces, then the layers that reason over it, then the application-level
surfaces — because that is also the order a reader needs them in to understand
what the API is for.

Two notes on things that are *not* here:

* ``packets``, ``connections`` and ``detections`` keep the routers M7, M9 and M10
  already shipped. M13 extended them with paging, filters and the shared envelope
  rather than replacing them, so a path that worked before still works.
* There is no unversioned production route. ``/health`` (M1) is the one exception
  and is kept for operational use, as M13.3 allows.
"""

from fastapi import APIRouter

from app.api.v1 import (
    alerts,
    analytics,
    baselines,
    capture,
    connections,
    dashboard,
    detections,
    devices,
    evidence,
    health,
    incidents,
    notifications,
    packets,
    reports,
    settings,
    statistics,
    system,
)

api_router = APIRouter()

# Process and operational surfaces.
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(system.router, prefix="/system", tags=["system"])

# Capture and the data it produces (M4/M6/M7).
api_router.include_router(capture.router, prefix="/capture", tags=["capture"])
api_router.include_router(
    statistics.router, prefix="/statistics", tags=["statistics"]
)
api_router.include_router(packets.router, prefix="/packets", tags=["packets"])

# Tracked entities (M8/M9).
api_router.include_router(devices.router, prefix="/devices", tags=["devices"])
api_router.include_router(
    connections.router, prefix="/connections", tags=["connections"]
)

# Findings and the layers that reason over them (M10/M11/M12).
api_router.include_router(
    detections.router, prefix="/detections", tags=["detections"]
)
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(evidence.router, prefix="/evidence", tags=["evidence"])
api_router.include_router(
    incidents.router, prefix="/incidents", tags=["incidents"]
)

# Derived and application-level surfaces.
api_router.include_router(analytics.router, prefix="/analytics", tags=["analytics"])
api_router.include_router(
    dashboard.router, prefix="/dashboard", tags=["dashboard"]
)
api_router.include_router(baselines.router, prefix="/baselines", tags=["baselines"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(settings.router, prefix="/settings", tags=["settings"])
api_router.include_router(
    notifications.router, prefix="/notifications", tags=["notifications"]
)

__all__ = ["api_router"]
