"""Read-only device discovery API endpoints for NetWatch AI (M8.18/M8.19).

These endpoints expose the live device registry maintained by the M8
:class:`~app.devices.manager.DeviceDiscoveryManager`. They are strictly
read-only: M8 discovers and tracks devices, it never edits or blocks them, so
no modification verbs are exposed.

Responses follow the same envelope as the rest of the API::

    {"success": true,  "message": "...", "data": {...}}
    {"success": false, "message": "...", "errors": [{"field": ..., "code": ...}]}
"""

import logging
from typing import Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from app.devices.identity import normalize_ip_address, normalize_mac_address
from app.devices.manager import DeviceDiscoveryManager, get_device_manager
from app.schemas.device import DeviceListData, DeviceView

logger = logging.getLogger(__name__)

router = APIRouter()

# Supported activity states, mirrored from ``DeviceStatus``. Using a Literal
# lets FastAPI reject an unknown state with a 422 before the handler runs.
DeviceStatusParam = Literal["active", "inactive", "unknown"]

# Bounds for the ``limit`` query parameter. The default keeps a response
# bounded even when thousands of devices are being tracked.
_MIN_LIMIT = 1
_MAX_LIMIT = 1000
DEFAULT_DEVICE_LIMIT = 100

# Error code returned when a device id is unknown.
_CODE_DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND"
# Error code returned when an address filter is not a valid address.
_CODE_INVALID_FILTER = "INVALID_FILTER"


def _error_response(
    status_code: int, message: str, field: str, code: str
) -> JSONResponse:
    """Build the standard error envelope used across the API."""
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "message": message,
            "errors": [{"field": field, "code": code}],
        },
    )


def _validate_address_filters(ip: str | None, mac: str | None) -> JSONResponse | None:
    """Validate address filters, returning an error response when unusable.

    A filter that cannot be parsed must fail loudly rather than be silently
    ignored, so a typo never turns into a request that returns every device.
    """
    if ip is not None and normalize_ip_address(ip) is None:
        return _error_response(
            400,
            f"'{ip}' is not a valid IP address",
            "ip",
            _CODE_INVALID_FILTER,
        )
    if mac is not None and normalize_mac_address(mac) is None:
        return _error_response(
            400,
            f"'{mac}' is not a valid MAC address",
            "mac",
            _CODE_INVALID_FILTER,
        )
    return None


@router.get("", response_model=None)
def list_devices(
    status: DeviceStatusParam | None = Query(
        default=None, description="Keep only devices in this activity state"
    ),
    ip: str | None = Query(
        default=None, description="Keep only the device currently owning this address"
    ),
    mac: str | None = Query(
        default=None, description="Keep only the device owning this MAC address"
    ),
    limit: int = Query(
        default=DEFAULT_DEVICE_LIMIT,
        ge=_MIN_LIMIT,
        le=_MAX_LIMIT,
        description="Maximum number of devices to return",
    ),
    manager: DeviceDiscoveryManager = Depends(get_device_manager),
) -> dict | JSONResponse:
    """Return the devices currently tracked, most recently seen first.

    Optional filters narrow the result by activity state, IP address or MAC
    address. An unparseable address filter is rejected with 400.
    """
    invalid_filter = _validate_address_filters(ip, mac)
    if invalid_filter is not None:
        return invalid_filter

    views: list[DeviceView] = manager.list_device_views(
        status=status, ip=ip, mac=mac, limit=limit
    )
    payload = DeviceListData(count=len(views), devices=views)
    logger.info("Returning %d device(s) via API", payload.count)
    return {
        "success": True,
        "message": "Devices retrieved",
        "data": payload.model_dump(mode="json"),
    }


@router.get("/{device_id}", response_model=None)
def get_device(
    device_id: str,
    manager: DeviceDiscoveryManager = Depends(get_device_manager),
) -> dict | JSONResponse:
    """Return one tracked device, or 404 when the id is unknown."""
    view = manager.get_device_view(device_id)
    if view is None:
        logger.info("Device lookup failed for id %r", device_id)
        return _error_response(
            404, "Device not found", "device_id", _CODE_DEVICE_NOT_FOUND
        )
    return {
        "success": True,
        "message": "Device retrieved",
        "data": view.model_dump(mode="json"),
    }
