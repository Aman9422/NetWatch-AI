"""Device API endpoints for NetWatch AI (M13.10).

Exposes the live device registry maintained by the M8
:class:`~app.devices.manager.DeviceDiscoveryManager`. Strictly read-only: M8
discovers and tracks devices, it never edits or blocks them, so no modification
verb is exposed.

A device carries identity, addresses, MAC, first/last seen, packet and byte
counts and an activity ``status``. **No risk score is returned**, because M8 does
not compute one: the ``devices.risk_score`` column belongs to the seed data
rather than to a runtime observation (M13.10).

An unparseable ``ip``/``mac`` filter is a ``400 INVALID_FILTER`` naming the field
it rejected, never a silently ignored parameter (M13.25). ``status`` is a closed
``Literal``, so FastAPI documents it in the OpenAPI schema and rejects an unknown
value with a ``422`` before the handler runs.

Paging uses the shared ``limit``/``offset`` contract (M13.24). The registry is
in memory, so the route resolves the whole filtered set once and then slices it:
that makes ``total`` the true size of the match set rather than "as many as the
page happened to hold", which a client needs in order to know whether another
page exists.
"""

import logging
from typing import Literal

from fastapi import APIRouter, Depends, Query

from app.api.common import (
    ErrorCode,
    InvalidFilterError,
    NotFoundError,
    PageWindow,
    normalize_filter_ip,
    normalize_filter_mac,
    page_meta,
    pagination_params,
    success_payload,
)
from app.devices.manager import DeviceDiscoveryManager, get_device_manager
from app.schemas.device import DeviceListData, DeviceView

logger = logging.getLogger(__name__)

router = APIRouter()

# Supported activity states, mirrored from ``DeviceStatus``. Using a Literal
# lets FastAPI reject an unknown state with a 422 before the handler runs.
DeviceStatusParam = Literal["active", "inactive", "unknown"]


def _reject_unusable_address_filters(ip: str | None, mac: str | None) -> None:
    """Reject an address filter that cannot be parsed (M13.25).

    A filter that cannot be parsed must fail loudly rather than be silently
    ignored, so a typo never turns into a request that returns every device.

    Raises:
        InvalidFilterError: If a supplied address is not a valid address.
    """
    if ip is not None and normalize_filter_ip(ip) is None:
        raise InvalidFilterError(f"'{ip}' is not a valid IP address", field="ip")
    if mac is not None and normalize_filter_mac(mac) is None:
        raise InvalidFilterError(f"'{mac}' is not a valid MAC address", field="mac")


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
    window: PageWindow = Depends(pagination_params),
    manager: DeviceDiscoveryManager = Depends(get_device_manager),
) -> dict:
    """Return the devices currently tracked, most recently seen first.

    Filters combine with AND. Ordering is ``last_seen DESC, device_id`` — total,
    so two identical requests return the same page in the same order (M13.24).
    The filtered set is resolved once without a limit and then sliced, so
    ``total`` is the real match count and ``has_more`` is exact.
    """
    _reject_unusable_address_filters(ip, mac)

    matched: list[DeviceView] = manager.list_device_views(
        status=status, ip=ip, mac=mac
    )
    page = window.slice(matched)
    payload = DeviceListData(
        **page_meta(len(page), window, total=len(matched)),
        devices=page,
    )
    logger.info("Returning %d of %d device(s) via API", payload.count, len(matched))
    return success_payload("Devices retrieved", payload.model_dump(mode="json"))


@router.get("/{device_id}", response_model=None)
def get_device(
    device_id: str,
    manager: DeviceDiscoveryManager = Depends(get_device_manager),
) -> dict:
    """Return one tracked device, or ``404`` when the id is unknown."""
    view = manager.get_device_view(device_id)
    if view is None:
        logger.info("Device lookup failed for id %r", device_id)
        raise NotFoundError(
            "Device not found",
            code=ErrorCode.DEVICE_NOT_FOUND,
            field="device_id",
        )
    return success_payload("Device retrieved", view.model_dump(mode="json"))
