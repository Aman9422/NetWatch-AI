"""Evidence API endpoints for NetWatch AI (M13.14).

Alert evidence is a *reference*: M11.13 stores the packet id, conversation id or
device id an alert rests on, plus a small JSON document describing why, and never
a copy of the resource. These endpoints expose exactly that, and nothing larger.

The per-alert view, ``GET /alerts/{alert_id}/evidence``, lives in
``app.api.v1.alerts`` beside the alert it belongs to. This module adds the one
thing evidence needs as a resource in its own right: ``GET /evidence/{id}``,
which returns a record *together with the alert that owns it*, so a client
holding an evidence reference can navigate to the alert rather than searching
every alert for it.

Nothing here resolves a packet. Returning the referenced resource would mean
joining a table that grows without bound, which M11.13 deliberately avoided on
the write path; the read path keeps that decision rather than undoing it.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends

from app.alerts.queries import AlertQueries
from app.api.common import ErrorCode, NotFoundError, success_payload
from app.api.v1.deps import get_alert_queries
from app.schemas.alert import AlertEvidenceView
from app.schemas.evidence import EvidenceDetailData

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/{evidence_id}", response_model=None)
def get_evidence(
    evidence_id: int,
    queries: AlertQueries = Depends(get_alert_queries),
) -> dict:
    """Return one evidence record and the alert it supports (M13.14).

    A record that has been pruned, or an id that never existed, is a ``404``
    rather than an empty object: the honest answer is that the reference is no
    longer resolvable, and an empty body would look like a record with no
    content.
    """
    record = queries.get_evidence_record(evidence_id)
    if record is None:
        logger.info("Evidence lookup failed for id %d", evidence_id)
        raise NotFoundError(
            "Evidence not found",
            code=ErrorCode.EVIDENCE_NOT_FOUND,
            field="evidence_id",
        )
    payload = EvidenceDetailData(
        evidence_id=int(evidence_id),
        alert_id=record.alert_id,
        evidence=AlertEvidenceView.from_record(record.evidence),
    )
    return success_payload("Evidence retrieved", payload.model_dump(mode="json"))
