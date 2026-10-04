"""Capture API endpoints for NetWatch AI (M13.7).

Exposes the M4 capture engine: which interfaces exist, which one is selected, and
whether a session is running. The routes validate and delegate; the interface and
capture managers own the state, so nothing here decides what a legal capture
transition is.

**The envelope is not built here.** Before M13 this module returned hand-written
``{"success": ..., "errors": [...]}`` dictionaries and carried a private
``_capture_error_response`` helper. Both are gone: successes go through
:func:`success_payload` and failures are raised as :class:`ApiError` subclasses,
which the registered handlers render (M13.4/M13.5). The wire shape is unchanged,
which is deliberate — M4's codes are part of the published contract and only the
way they are produced was duplicated.

**The interface listing is the one collection without a page window.** It is a
short, fixed enumeration of the machine's own NICs rather than a table that grows,
so it has no ``limit``/``offset`` and keeps returning a bare ``data`` list (M13.7).
The paginated collections are listed in
``docs/17_M13_REST_API_Design.md`` §7.3.
"""

import logging
from typing import NoReturn

from fastapi import APIRouter, Depends

from app.api.common import (
    ApiError,
    BadRequestError,
    ConflictError,
    ErrorCode,
    success_payload,
)
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

#: The API error class each controlled capture failure is rendered as.
#:
#: The class carries the status, which is what keeps the *reason* legible: two
#: sessions cannot both run and an interface was not chosen, so those are a
#: conflict (409) and a bad request (400). The mapping lives at the boundary
#: rather than on the M4 error classes, because M4 knows nothing about HTTP
#: (M13.1).
_CAPTURE_ERROR_CLASS: dict[type[CaptureError], type[ApiError]] = {
    CaptureAlreadyRunningError: ConflictError,
    CaptureNotRunningError: ConflictError,
    CaptureInterfaceError: BadRequestError,
}


def _raise_capture_error(exc: CaptureError) -> NoReturn:
    """Re-raise a controlled capture failure as the shared API error (M13.5).

    The M4 error already carries the machine-readable ``code`` the API has always
    returned, so the code is preserved exactly and only the transport changes: the
    route raises instead of assembling a :class:`~fastapi.responses.JSONResponse`
    by hand.

    An unrecognised capture failure falls back to the base :class:`ApiError`, which
    answers ``500`` — the same status the old mapping's default produced, and the
    right one for a failure the capture engine did not classify.
    """
    error_class = _CAPTURE_ERROR_CLASS.get(type(exc), ApiError)
    raise error_class(exc.message, code=exc.code, field="capture") from exc


@router.get("/interfaces", response_model=None)
def list_interfaces(
    manager: InterfaceManager = Depends(get_interface_manager),
) -> dict:
    """Return every network interface the machine offers (M13.7).

    Includes interfaces that are down, because "what exists" and "what can be
    captured on" are different questions and the payload answers both through each
    entry's ``is_up`` flag.
    """
    interfaces = manager.list_interfaces()
    logger.info("Returning %d interface(s) via API", len(interfaces))
    return success_payload(
        "Interfaces retrieved",
        [interface.model_dump() for interface in interfaces],
    )


@router.get("/interface", response_model=None)
def get_selected_interface(
    manager: InterfaceManager = Depends(get_interface_manager),
) -> dict:
    """Return the selected interface, or ``400`` when none has been chosen.

    A missing selection is the client's precondition to fix rather than a missing
    resource, so it is a ``400`` with M4's ``NO_INTERFACE_SELECTED`` code — the
    status and code the endpoint has always returned (M13.6).
    """
    selected = manager.get_selected_interface()
    if selected is None:
        raise BadRequestError(
            "No interface selected",
            code=ErrorCode.NO_INTERFACE_SELECTED,
            field="interface",
        )
    return success_payload("Interface retrieved", selected.model_dump())


@router.put("/interface", response_model=None)
def select_interface(
    payload: InterfaceSelectionRequest,
    manager: InterfaceManager = Depends(get_interface_manager),
) -> dict:
    """Select the interface future capture sessions will use (M13.7).

    An empty or missing ``name`` never reaches this function: the request model
    rejects it with a ``422`` first. A name that is well-formed but unknown, or
    known but down, is the manager's judgement and arrives as an
    :class:`InterfaceValidationError` carrying its own code — ``INTERFACE_NOT_FOUND``
    or ``INTERFACE_UNAVAILABLE`` — which is reported unchanged.
    """
    try:
        selected = manager.select_interface(payload.name)
    except InterfaceValidationError as exc:
        logger.warning("Interface selection rejected: %s", exc.message)
        raise BadRequestError(exc.message, code=exc.code, field="name") from exc

    return success_payload("Interface selected", {"name": selected.name})


@router.get("/status", response_model=None)
def get_capture_status(
    manager: CaptureManager = Depends(get_capture_manager),
) -> dict:
    """Return the live capture state: status, interface and packet count (M13.7)."""
    return success_payload(
        "Capture status retrieved", manager.get_status().model_dump()
    )


@router.post("/start", response_model=None)
def start_capture(
    manager: CaptureManager = Depends(get_capture_manager),
) -> dict:
    """Start packet capture on the selected interface (M13.7).

    Fails as ``400`` when no interface has been selected and as ``409`` when a
    session is already running. The second is a conflict rather than a bad request
    because the request itself was fine — it was the session's state that refused
    it — and the running session is left untouched.
    """
    try:
        status = manager.start()
    except CaptureError as exc:
        logger.warning("Capture start rejected: %s", exc.message)
        _raise_capture_error(exc)

    return success_payload("Packet capture started", status.model_dump())


@router.post("/stop", response_model=None)
def stop_capture(
    manager: CaptureManager = Depends(get_capture_manager),
) -> dict:
    """Stop the active capture session (M13.7).

    Stopping when nothing is running is a ``409``: the request cannot be honoured
    against the current state, and reporting success would claim a session was
    ended that never existed.
    """
    try:
        status = manager.stop()
    except CaptureError as exc:
        logger.warning("Capture stop rejected: %s", exc.message)
        _raise_capture_error(exc)

    return success_payload("Packet capture stopped", status.model_dump())
