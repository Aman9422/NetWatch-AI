"""The controlled API error hierarchy and its FastAPI handlers (M13.5/M13.29).

Two responsibilities, in one module because they are two halves of the same
contract: the exception a handler or a route may *raise*, and the translation
from any failure into the standard envelope.

**What a route may raise.** An :class:`ApiError` carries a status code, a
machine-readable code and the field that failed, so a route can say
``raise NotFoundError("Incident not found", code=ErrorCode.INCIDENT_NOT_FOUND,
field="incident_id")`` and get the documented response without building a
``JSONResponse`` by hand. That is what removes the five private
``_error_response`` helpers the audit found.

**What is translated, and what is deliberately not.** Three handlers are
registered:

* :class:`ApiError` → its own status code and code.
* Starlette's ``HTTPException`` → the standard envelope, preserving the status
  (404 for an unknown route, 405 for a wrong verb). FastAPI raises these itself,
  so an unrouted URL answers in the same shape as everything else.
* Any other ``Exception`` → an opaque ``500`` with no traceback, no path and no
  exception text (M13.29/M13.30).

FastAPI's own ``RequestValidationError`` handler is **left alone on purpose**.
It already returns ``422`` with a ``detail`` list naming every failing field,
which is both the documented status for a validation error (M13.6) and the shape
existing tests and clients already read. Replacing it with the envelope would
delete the per-field detail the request-validation case is the whole point of.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.common.envelope import ErrorCode, error_payload

logger = logging.getLogger(__name__)

#: Status used for a failure the application did not anticipate.
INTERNAL_ERROR_STATUS = 500

#: Message returned for an unanticipated failure. Deliberately constant: the
#: real message goes to the log, never to the client (M13.30).
INTERNAL_ERROR_MESSAGE = "The request could not be completed due to an internal error"


class ApiError(Exception):
    """A controlled API failure with a status code and a machine-readable code.

    Args:
        message: Human-readable description, safe to return to a client.
        code: Machine-readable code. Defaults to the class's ``default_code``.
        field: Which request field or path parameter failed. Defaults to the
            class's ``default_field``.
        errors: Explicit ``(field, code)`` pairs for a multi-field failure.

    Attributes:
        status_code: The HTTP status to answer with.
        message: The message as supplied.
        code: The resolved code.
        field: The resolved field.
        errors: The resolved pair list, or ``None``.
    """

    status_code: int = INTERNAL_ERROR_STATUS
    default_code: str = ErrorCode.INTERNAL_ERROR
    default_field: str = "request"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        field: str | None = None,
        errors: Iterable[tuple[str, str]] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = str(message)
        self.code = str(code or self.default_code)
        self.field = str(field or self.default_field)
        self.errors = list(errors) if errors is not None else None

    def to_payload(self) -> dict[str, object]:
        """Return this error as the standard error envelope."""
        if self.errors:
            return error_payload(self.message, self.code, errors=self.errors)
        return error_payload(self.message, self.code, self.field)


class BadRequestError(ApiError):
    """A request the server refuses because the client got it wrong (400)."""

    status_code = 400
    default_code = ErrorCode.INVALID_REQUEST
    default_field = "request"


class InvalidFilterError(BadRequestError):
    """An unusable query filter: an unknown severity, a bad address, a bad time.

    400 rather than 422 because the *shape* of the request was valid — it was the
    value that could not be honoured — and the existing API already answered 400
    for exactly this case (see the audit in ``docs/17`` §3.2).
    """

    default_code = ErrorCode.INVALID_FILTER


class NotFoundError(ApiError):
    """A resource that does not exist (404)."""

    status_code = 404
    default_code = ErrorCode.NOT_FOUND
    default_field = "id"


class ConflictError(ApiError):
    """A request that conflicts with the current state (409)."""

    status_code = 409
    default_code = ErrorCode.CONFLICT
    default_field = "request"


class FeatureNotImplementedError(ApiError):
    """A subsystem M13 exposes but does not implement (501) (M13.17/M13.20)."""

    status_code = 501
    default_code = ErrorCode.FEATURE_NOT_IMPLEMENTED
    default_field = "feature"


class ServiceUnavailableError(ApiError):
    """A dependency that is switched off or not reachable (503)."""

    status_code = 503
    default_code = ErrorCode.SERVICE_UNAVAILABLE
    default_field = "service"


def _http_exception_response(exc: StarletteHTTPException) -> JSONResponse:
    """Render a routing/HTTP exception in the standard envelope.

    The status is preserved — a 405 stays a 405 — and the code is derived from it
    so a client has something stable to branch on. Starlette's ``detail`` is used
    as the message only when it is a string: FastAPI's validation detail is a
    list, and that path is handled by FastAPI's own handler rather than here.
    """
    status = int(exc.status_code)
    message = exc.detail if isinstance(exc.detail, str) else _default_message(status)
    return JSONResponse(
        status_code=status,
        content=error_payload(message, _code_for_status(status), "request"),
    )


def _code_for_status(status: int) -> str:
    """Return the generic code matching an HTTP status."""
    return {
        400: ErrorCode.INVALID_REQUEST,
        404: ErrorCode.NOT_FOUND,
        405: ErrorCode.METHOD_NOT_ALLOWED,
        409: ErrorCode.CONFLICT,
        422: ErrorCode.INVALID_REQUEST,
        501: ErrorCode.FEATURE_NOT_IMPLEMENTED,
        503: ErrorCode.SERVICE_UNAVAILABLE,
    }.get(status, ErrorCode.INTERNAL_ERROR)


def _default_message(status: int) -> str:
    """Return a safe, generic message for an HTTP status."""
    return {
        400: "The request could not be understood",
        404: "The requested resource was not found",
        405: "The HTTP method is not allowed for this resource",
        409: "The request conflicts with the current state",
        422: "The request could not be validated",
        501: "This feature is not implemented",
        503: "The service is currently unavailable",
    }.get(status, "The request could not be completed")


def register_exception_handlers(app: FastAPI) -> None:
    """Attach the M13 error handlers to ``app``.

    Called once from ``app.main`` after the routers are registered. Registering
    them here rather than in each router is what makes the envelope uniform
    without a router having to know it exists.
    """

    @app.exception_handler(ApiError)
    async def _handle_api_error(
        _request: Request, exc: ApiError
    ) -> JSONResponse:  # pragma: no cover - exercised through the API tests
        if exc.status_code >= INTERNAL_ERROR_STATUS:
            # A 5xx means the application failed, so it is logged with its
            # context. A 4xx is the client's problem and is logged at info by the
            # route that raised it, if at all.
            logger.exception("API error: %s", exc.message)
        return JSONResponse(status_code=exc.status_code, content=exc.to_payload())

    @app.exception_handler(StarletteHTTPException)
    async def _handle_http_exception(
        _request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:  # pragma: no cover - exercised through the API tests
        return _http_exception_response(exc)

    @app.exception_handler(Exception)
    async def _handle_unexpected(
        _request: Request, exc: Exception
    ) -> JSONResponse:  # pragma: no cover - exercised through the API tests
        # The message is constant and the real one is logged. Nothing about the
        # failure — no traceback, no path, no query text — reaches the client
        # (M13.29/M13.30). The failure is contained here, which is what keeps an
        # API fault away from the capture pipeline.
        logger.exception("Unhandled API failure")
        return JSONResponse(
            status_code=INTERNAL_ERROR_STATUS,
            content=error_payload(
                INTERNAL_ERROR_MESSAGE, ErrorCode.INTERNAL_ERROR, "request"
            ),
        )


__all__ = [
    "INTERNAL_ERROR_MESSAGE",
    "INTERNAL_ERROR_STATUS",
    "ApiError",
    "BadRequestError",
    "ConflictError",
    "FeatureNotImplementedError",
    "InvalidFilterError",
    "NotFoundError",
    "RequestValidationError",
    "ServiceUnavailableError",
    "register_exception_handlers",
]
