"""Health endpoint for NetWatch AI."""

from fastapi import APIRouter

router = APIRouter()


@router.get("")
def health_check() -> dict[str, str]:
    """Return the application health status."""
    return {"status": "healthy"}
