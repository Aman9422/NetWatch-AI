"""API v1 package for NetWatch AI."""

from fastapi import APIRouter

from app.api.v1 import capture, health, statistics

api_router = APIRouter()
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(capture.router, prefix="/capture", tags=["capture"])
api_router.include_router(
    statistics.router, prefix="/statistics", tags=["statistics"]
)
