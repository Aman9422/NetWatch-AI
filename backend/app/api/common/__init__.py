"""Shared API infrastructure for NetWatch AI (M13).

This package holds the parts of the HTTP surface that every router needs and
that must behave identically wherever they appear (M13.4/M13.5/M13.24/M13.25):

* :mod:`app.api.common.envelope` — the one success and error payload shape and
  the machine-readable error codes;
* :mod:`app.api.common.errors` — the controlled error hierarchy and the
  FastAPI exception handlers that render it;
* :mod:`app.api.common.pagination` — the shared ``limit``/``offset`` contract;
* :mod:`app.api.common.validation` — the shared filter parsers (addresses,
  ports, enumerations, timestamps, ranges).

Nothing here knows about a specific resource. A router imports what it needs and
delegates the actual work to the service that owns it.
"""

from app.api.common.envelope import (
    ErrorCode,
    error_payload,
    success_payload,
)
from app.api.common.errors import (
    ApiError,
    BadRequestError,
    ConflictError,
    FeatureNotImplementedError,
    InvalidFilterError,
    NotFoundError,
    ServiceUnavailableError,
    register_exception_handlers,
)
from app.api.common.pagination import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    PageMeta,
    PageWindow,
    page_meta,
    pagination_params,
)
from app.api.common.validation import (
    normalize_filter_ip,
    normalize_filter_mac,
    parse_datetime_filter,
    parse_epoch_filter,
    validate_choice,
    validate_risk_range,
    validate_time_range,
)

__all__ = [
    "ApiError",
    "BadRequestError",
    "ConflictError",
    "DEFAULT_PAGE_SIZE",
    "ErrorCode",
    "FeatureNotImplementedError",
    "InvalidFilterError",
    "MAX_PAGE_SIZE",
    "NotFoundError",
    "PageMeta",
    "PageWindow",
    "ServiceUnavailableError",
    "error_payload",
    "normalize_filter_ip",
    "normalize_filter_mac",
    "page_meta",
    "pagination_params",
    "parse_datetime_filter",
    "parse_epoch_filter",
    "register_exception_handlers",
    "success_payload",
    "validate_choice",
    "validate_risk_range",
    "validate_time_range",
]
