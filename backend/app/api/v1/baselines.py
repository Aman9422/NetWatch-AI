"""Baseline API endpoints for NetWatch AI (M13.17).

The behavioural baseline **engine** does not exist. M13.17 says so explicitly and
forbids implementing it here, so this module has nothing to expose — and it says
that rather than pretending otherwise.

Both routes answer ``501 FEATURE_NOT_IMPLEMENTED`` with a message naming the
subsystem and the milestone that owns it. The alternative — listing the seeded
``behavioral_baselines`` rows — was rejected deliberately: those rows are M2
development seed data (``status='learning'``, ``observation_count=0``), so serving
them would present a placeholder as an analysed behavioural profile. That is
exactly the "fake data" M13.17 forbids.

A ``501`` rather than a ``404`` is the point: the route exists and is documented,
and the client is told the *feature* is missing. A ``404`` would say the URL is
wrong, which it is not.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter

from app.api.common import ErrorCode, FeatureNotImplementedError

logger = logging.getLogger(__name__)

router = APIRouter()

#: What is missing, and who owns it. Stated once so both routes say the same
#: thing and a client can rely on the wording being stable.
MESSAGE = (
    "The behavioural baseline engine is not implemented. Baselines require an "
    "implemented learning subsystem, which this milestone does not provide."
)

#: The feature field reported in the error envelope, so a client can branch on
#: which subsystem refused rather than parsing the message.
FEATURE = "behavioral_baselines"


def _not_implemented() -> FeatureNotImplementedError:
    """Build the documented refusal for both routes."""
    return FeatureNotImplementedError(MESSAGE, field=FEATURE)


@router.get("", response_model=None)
def list_baselines() -> dict:
    """Refuse to list behavioural baselines (M13.17).

    Raises:
        FeatureNotImplementedError: Always. No baseline is computed anywhere in
            the base application, so there is nothing truthful to list.
    """
    logger.info("Baseline listing requested; the feature is not implemented")
    raise _not_implemented()


@router.get("/{device_id}", response_model=None)
def get_baseline(device_id: str) -> dict:
    """Refuse to return one device's behavioural baseline (M13.17).

    Raises:
        FeatureNotImplementedError: Always, for the same reason as the listing.
            The path parameter is accepted so the URL shape is the documented
            one; it is deliberately not looked up, because a lookup would imply
            a profile exists to find.
    """
    logger.info("Baseline lookup requested for %r; the feature is not implemented", device_id)
    raise _not_implemented()


__all__ = ["FEATURE", "MESSAGE", "router"]
