"""Capture-related API endpoints for NetWatch AI."""

import logging

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.schemas.interface import InterfaceSelectionRequest
from app.services.capture_manager import CaptureManager, get_capture_manager
from app.services.capture_state import (
    CaptureAlreadyRunningError,
    CaptureError,
    CaptureInterfaceError,
    CaptureNotRunningError,
)
from app.services.interface_manager import (
    InterfaceManager,
    InterfaceValidationError,
    get_interface_manager,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# HTTP status code returned for each controlled capture error.
_CAPTURE_ERROR_STATUS: dict[type[CaptureError], int] = {
    CaptureAlreadyRunningError: 409,
    CaptureNotRunningError: 409,
    CaptureInterfaceError: 400,
}


def _capture_error_response(exc: CaptureError) -> JSONResponse:
    """Translate a controlled capture error into a JSON error response."""
    status_code = _CAPTURE_ERROR_STATUS.get(type(exc), 500)
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "message": exc.message,
            "errors": [{"field": "capture", "code": exc.code}],
        },
    )


@router.get("/interfaces")
def list_interfaces(manager: InterfaceManager = Depends(get_interface_manager)) -> dict:
    """Return all available network interfaces."""
    interfaces = manager.list_interfaces()
    logger.info("Returning %d interface(s) via API", len(interfaces))
    return {
        "success": True,
        "message": "Interfaces retrieved",
        "data": [interface.model_dump() for interface in interfaces],
    }


@router.get("/interface", response_model=None)
def get_selected_interface(manager: InterfaceManager = Depends(get_interface_manager)) -> dict | JSONResponse:
    """Return the currently selected interface."""
    selected = manager.get_selected_interface()
    if selected is None:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "message": "No interface selected",
                "errors": [{"field": "interface", "code": "NO_INTERFACE_SELECTED"}],
            },
        )
    return {
        "success": True,
        "message": "Interface retrieved",
        "data": selected.model_dump(),
    }


@router.put("/interface", response_model=None)
def select_interface(
    payload: InterfaceSelectionRequest,
    manager: InterfaceManager = Depends(get_interface_manager),
) -> dict | JSONResponse:
    """Select an interface for future packet capture."""
    try:
        selected = manager.select_interface(payload.name)
    except InterfaceValidationError as exc:
        logger.warning("Interface selection rejected: %s", exc.message)
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "message": exc.message,
                "errors": [{"field": "name", "code": exc.code}],
            },
        )

    return {
        "success": True,
        "message": "Interface selected",
        "data": {"name": selected.name},
    }


@router.get("/status")
def get_capture_status(manager: CaptureManager = Depends(get_capture_manager)) -> dict:
    """Return the current capture state."""
    return {
        "success": True,
        "message": "Capture status retrieved",
        "data": manager.get_status().model_dump(),
    }


@router.post("/start", response_model=None)
def start_capture(manager: CaptureManager = Depends(get_capture_manager)) -> dict | JSONResponse:
    """Start packet capture on the selected interface."""
    try:
        status = manager.start()
    except CaptureError as exc:
        logger.warning("Capture start rejected: %s", exc.message)
        return _capture_error_response(exc)

    return {
        "success": True,
        "message": "Packet capture started",
        "data": status.model_dump(),
    }


@router.post("/stop", response_model=None)
def stop_capture(manager: CaptureManager = Depends(get_capture_manager)) -> dict | JSONResponse:
    """Stop the active packet capture session."""
    try:
        status = manager.stop()
    except CaptureError as exc:
        logger.warning("Capture stop rejected: %s", exc.message)
        return _capture_error_response(exc)

    return {
        "success": True,
        "message": "Packet capture stopped",
        "data": status.model_dump(),
    }
