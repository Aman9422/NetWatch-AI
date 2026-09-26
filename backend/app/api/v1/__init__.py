"""API v1 package for NetWatch AI."""

from fastapi import APIRouter

from app.api.v1 import (
    alerts,
    capture,
    connections,
    detections,
    devices,
    health,
    packets,
    statistics,
)

api_router = APIRouter()
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(capture.router, prefix="/capture", tags=["capture"])
api_router.include_router(
    statistics.router, prefix="/statistics", tags=["statistics"]
)
api_router.include_router(devices.router, prefix="/devices", tags=["devices"])
# Internal read-only packet endpoints (M7.16); the public packet API is M13.
api_router.include_router(packets.router, prefix="/packets", tags=["packets"])
# Internal read-only connection endpoints (M9.22); the public API is M13.
api_router.include_router(
    connections.router, prefix="/connections", tags=["connections"]
)
# Internal read-only detection endpoints (M10.22); the public alert and
# detection API is M13, and the alert API itself is M11.
api_router.include_router(
    detections.router, prefix="/detections", tags=["detections"]
)
# Alert lifecycle and read endpoints (M11.18/M11.19); the public alert API is
# M13, and the alert layer itself is M11.
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
