"""Write a correlated incident's risk score onto its member alerts (M12.24).

M11 leaves ``alerts.risk_score`` at ``0`` on purpose: a risk score needs the
incident context and the historical context M12 owns, so M11 writing a number
there would be M11 inventing one (see ``app.alerts.persistence``). This module is
the other half of that decision — the writer that fills the column in once
correlation actually has something to say.

Three boundaries are respected here, and they are the reason this is its own
module rather than a method on the engine:

**The engine holds no session.** ``CorrelationEngine`` takes a *callable*
(``RiskPersistence``) and never imports SQLAlchemy or a repository. That keeps
the engine importable and testable without a database, and it keeps the choice of
storage in the layer that owns storage.

**One session per write, always closed.** The writer is called from the capture
path, and possibly from a background sweep, so it opens its own short-lived
session through the injected factory rather than holding one. A factory is
injected rather than imported so a test can point it at an isolated database,
exactly as the M7 persistence worker does (``app.persistence.session_factory``).

**A write failure changes nothing about the correlation.** The failure is counted
here and then deliberately allowed to propagate, because the *engine* is the layer
that owns containment on the capture path: it contains this call, counts it in
``stats()["persist_errors"]`` and logs it with the incident's own context, so a
locked database does not destroy an incident and does not stop packet capture
(M12.25). Swallowing the failure here as well would leave that counter
structurally unable to fire, and a run whose every write failed would still report
no persistence errors at all (M12.34). Returning a count rather than raising on
*success* is what lets the engine report how many rows were actually stamped.

**What is written, and what is not.** Only ``risk_score``. The alert's own
severity, confidence, status and evidence are M11's record of what was observed
and are not correlation's to revise — correlation records a *relationship*
between observations, it does not rewrite them (M12.10). ``updated_at`` is
likewise left alone, because that column dates a human's lifecycle actions and a
machine's grouping is not one of them.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

from app.correlation.incident import CorrelatedIncident
from app.persistence.session_factory import SessionFactory
from app.repositories.alert import RISK_UPDATE_CHUNK_SIZE, AlertRepository

logger = logging.getLogger(__name__)


class IncidentRiskWriter:
    """Propagate an incident's risk score onto its alerts (M12.24).

    An instance is a ``RiskPersistence`` callable — ``__call__`` takes the
    incident and returns how many alert rows were updated — so it can be handed
    straight to :class:`~app.correlation.engine.CorrelationEngine` without the
    engine knowing what it is.

    Args:
        session_factory: Builds a fresh session per write. Injected so tests can
            supply an isolated in-memory database.
        chunk_size: How many alert ids one ``UPDATE`` may carry. Bounds both the
            statement size and the time a single write can hold the session.
        clock: Unused by the write itself; accepted so a caller may pass the same
            clock it gave the engine and keep one time source in a run.

    Raises:
        ValueError: If ``chunk_size`` is below 1, which would make the write a
            no-op loop rather than a bounded write.
    """

    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        chunk_size: int = RISK_UPDATE_CHUNK_SIZE,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if int(chunk_size) < 1:
            raise ValueError("chunk_size must be at least 1")
        self._session_factory = session_factory
        self._chunk_size = int(chunk_size)
        self._clock = clock
        self._lock = threading.Lock()
        self._writes = 0
        self._rows_written = 0
        self._errors = 0

    # -- the RiskPersistence callable ---------------------------------------

    def __call__(self, incident: CorrelatedIncident) -> int:
        """Stamp ``incident``'s risk score onto its member alerts (M12.24).

        Returns:
            How many rows were updated. ``0`` is returned when the incident holds
            no alert ids: a findings-only incident has nothing in the ``alerts``
            table to stamp.

        Raises:
            Exception: Whatever the database raised. The failure is counted here
                first and then allowed to reach the caller, which is the layer
                that owns containment — see the module docstring. The engine
                contains it, counts it and logs it with the incident's own context
                (M12.25), and the incident keeps its score in memory regardless.
        """
        alert_ids = tuple(int(value) for value in incident.alert_ids)
        if not alert_ids:
            return 0
        try:
            written = self._write(alert_ids, int(incident.risk_score))
        except Exception:
            with self._lock:
                self._errors += 1
            # Logged at debug rather than as an error: the engine reports the same
            # failure at error level with the incident's own context, which is the
            # more useful message. This line is for a caller that drives the
            # writer directly and has no engine to report it for them.
            logger.debug(
                "Risk write failed for incident %s (%d alert(s))",
                incident.incident_id,
                len(alert_ids),
                exc_info=True,
            )
            raise
        with self._lock:
            self._writes += 1
            self._rows_written += written
        return written

    def _write(self, alert_ids: tuple[int, ...], risk_score: int) -> int:
        """Open a session, apply the write, and always close the session."""
        session = self._session_factory()
        try:
            repository = AlertRepository(session)
            return repository.update_risk_scores(
                alert_ids, risk_score=risk_score, chunk_size=self._chunk_size
            )
        finally:
            session.close()

    # -- diagnostics (M12.34) ----------------------------------------------

    def stats(self) -> dict[str, int]:
        """Return counters describing the writes this writer has performed."""
        with self._lock:
            return {
                "writes": self._writes,
                "rows_written": self._rows_written,
                "errors": self._errors,
            }

    def reset(self) -> None:
        """Clear the counters. Does not touch the database."""
        with self._lock:
            self._writes = 0
            self._rows_written = 0
            self._errors = 0


__all__ = ["IncidentRiskWriter"]
