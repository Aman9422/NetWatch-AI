"""The generation-status vocabulary a stored report row carries (M17.9).

Three values and no fourth, because a report row is only ever in one of three
states and collapsing any two of them would misreport what happened:

``GENERATING``
    The metadata row exists and the artifact is being produced. A row in this
    state describes an *intention*, and the API reports it as such rather than
    implying a file exists.
``COMPLETED``
    The artifact was written and its size recorded. This is the only state in
    which a download can succeed.
``FAILED``
    Generation was attempted and did not finish. ``error`` carries a safe
    sentence naming what failed, and any partial file has been removed.

The vocabulary lives in its own module rather than in the ORM model because both
the storage layer and the API schema need to compare against it, and a shared
module is what stops three modules from spelling "completed" three ways.
"""

from __future__ import annotations

#: Metadata written, artifact not yet produced.
GENERATING = "generating"

#: Artifact written and described by this row.
COMPLETED = "completed"

#: Generation was attempted and failed; no artifact is claimed.
FAILED = "failed"


class ReportStatus:
    """The three states a report row may hold (M17.9).

    Compared as plain strings by callers, so the class is a namespace rather than
    an ``Enum``: a value read out of SQLite is a string, and wrapping it in an
    enum would mean every read site constructs one before comparing. The
    :data:`ALL` tuple is what a validator iterates.
    """

    GENERATING = GENERATING
    COMPLETED = COMPLETED
    FAILED = FAILED

    #: Every value, in the order a help string should list them.
    ALL: tuple[str, ...] = (GENERATING, COMPLETED, FAILED)


#: The state a row is in once its artifact is safely on disk.
DEFAULT_STATUS = COMPLETED

__all__ = [
    "COMPLETED",
    "DEFAULT_STATUS",
    "FAILED",
    "GENERATING",
    "ReportStatus",
]
