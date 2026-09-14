"""API v1 package for NetWatch AI."""

from fastapi import APIRouter

from app.api.v1 import capture, devices, health, packets, statistics

api_router = APIRouter()
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(capture.router, prefix="/capture", tags=["capture"])
api_router.include_router(
    statistics.router, prefix="/statistics", tags=["statistics"]
)
api_router.include_router(devices.router, prefix="/devices", tags=["devices"])
# Internal read-only packet endpoints (M7.16); the public packet API is M13.
api_router.include_router(packets.router, prefix="/packets", tags=["packets"])
