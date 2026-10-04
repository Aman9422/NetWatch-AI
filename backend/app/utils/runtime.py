"""Process-level runtime facts the system API reports (M13.22).

One question — "how long has this process been serving?" — needs a mark that is
set once when the application starts rather than when a module is imported. A
module-level ``time.time()`` would be close, but "close" is the problem: the
value would move with import order, so the same process could report a different
start depending on which router happened to be imported first.

The lifespan in :mod:`app.main` calls :func:`mark_process_started` at startup, so
the mark means exactly what the endpoint claims it means. If it is never called —
a test that builds the app without running its lifespan — :func:`is_started`
reports ``False`` and the uptime is reported as absent rather than as a
plausible-looking number.

Uptime is measured with :func:`time.monotonic` rather than wall-clock time: a
clock adjustment must not make a process appear to have run for a negative
duration. The wall-clock ``started_at`` is kept separately for display.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

#: Monotonic instant the application started, or ``None`` before startup.
_started_monotonic: float | None = None

#: Wall-clock instant the application started, or ``None`` before startup.
_started_at: datetime | None = None


def mark_process_started() -> None:
    """Record the moment the application started serving.

    Called once from the application lifespan. Calling it again replaces the
    mark, which is what a test that restarts the app in one process needs.
    """
    global _started_monotonic, _started_at
    _started_monotonic = time.monotonic()
    _started_at = datetime.now(timezone.utc)


def is_started() -> bool:
    """Return True once :func:`mark_process_started` has been called."""
    return _started_monotonic is not None


def uptime_seconds() -> float | None:
    """Return seconds since startup, or ``None`` when startup was not recorded.

    ``None`` rather than ``0.0``: zero would claim the process started this
    instant, which is a different statement from "this value was never recorded".
    """
    if _started_monotonic is None:
        return None
    return max(0.0, time.monotonic() - _started_monotonic)


def started_at() -> datetime | None:
    """Return the aware UTC instant the application started, or ``None``."""
    return _started_at


def reset_process_started() -> None:
    """Clear the startup mark. For tests that assert the unrecorded case."""
    global _started_monotonic, _started_at
    _started_monotonic = None
    _started_at = None


__all__ = [
    "is_started",
    "mark_process_started",
    "reset_process_started",
    "started_at",
    "uptime_seconds",
]
