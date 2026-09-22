"""Aggregated connection writes to the existing ``connections`` table (M9.17).

M9 does not rebuild M7. Packets are stored per packet by M7; a *connection* is
an aggregation, so this layer writes one row per conversation and reuses the M2
``ConnectionRepository`` for the statements and the M7 ``SessionFactory`` for
sessions.

Where it runs
-------------

Never on the capture path. The tracker calls this layer from its cleanup sweep
and from shutdown, so a slow or failing database can never stall packet capture,
processing, statistics, device discovery — or connection tracking itself.

A conversation keeps the ``connections.id`` it was first written to, so a second
write is an ``UPDATE`` rather than a duplicate ``INSERT``. A tuple reused after
``closed`` has a fresh record (its counters were restarted) and therefore gets a
fresh row, which is why the earlier conversation's aggregate is preserved.

Bounding
--------

Each call writes at most ``max_per_pass`` rows. Anything above the cap is counted
as *deferred* and picked up by the next sweep, so a flood of connections cannot
stall the cleanup thread. Failures are counted and logged, never raised.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Sequence

from sqlalchemy.orm import Session

from app.connections.connection import Connection
from app.connections.mapping import to_connection_values
from app.persistence.session_factory import SessionFactory, app_session_factory
from app.repositories.connection import ConnectionRepository

logger = logging.getLogger(__name__)

# Default cap on rows written per call (M9.17).
DEFAULT_MAX_PER_PASS = 500

# Maps a runtime M8 device id (for example ``mac:AA:BB:...``) to a persisted
# ``devices.id``. M9 ships none, because M8 devices are not persisted; a caller
# that starts persisting them can inject one.
DeviceIdResolver = Callable[[str | None], int | None]


class ConnectionPersistence:
    """Writes aggregated conversations to the ``connections`` table (M9.17)."""

    def __init__(
        self,
        *,
        session_factory: SessionFactory | None = None,
        enabled: bool = True,
        max_per_pass: int = DEFAULT_MAX_PER_PASS,
        device_id_resolver: DeviceIdResolver | None = None,
    ) -> None:
        """Create the persistence layer.

        Args:
            session_factory: Builds database sessions. Defaults to the
                application factory; tests inject an isolated one.
            enabled: When False nothing is written and every call is a no-op.
            max_per_pass: Upper bound on rows written per call.
            device_id_resolver: Optional mapping from a runtime device id to a
                ``devices.id`` row. Without it the foreign keys stay ``NULL``,
                exactly as M7 does for ``packets.device_id``.

        Raises:
            ValueError: If ``max_per_pass`` is not positive.
        """
        if max_per_pass < 1:
            raise ValueError("max_per_pass must be at least 1")

        self._session_factory = session_factory or app_session_factory
        self._enabled = enabled
        self._max_per_pass = max_per_pass
        self._device_id_resolver = device_id_resolver

        self._counter_lock = threading.Lock()
        self._created = 0
        self._updated = 0
        self._failed = 0
        self._skipped = 0
        self._deferred = 0

    # -- writing ----------------------------------------------------------

    def persist_many(self, connections: Sequence[Connection]) -> int:
        """Write a batch of conversations; return how many rows were written.

        Never raises: a database problem is counted and logged so the caller's
        sweep can continue (M9.20).
        """
        if not self._enabled or not connections:
            return 0

        ordered = list(connections)
        batch = ordered[: self._max_per_pass]
        if len(ordered) > len(batch):
            with self._counter_lock:
                self._deferred += len(ordered) - len(batch)

        session: Session | None = None
        written = 0
        try:
            session = self._session_factory()
            repository = ConnectionRepository(session)
            for connection in batch:
                try:
                    stored = self._write_one(repository, connection)
                except Exception:  # noqa: BLE001 - a DB failure must not propagate
                    session.rollback()
                    with self._counter_lock:
                        self._failed += 1
                    # The record keeps its dirty flag so a later sweep retries it.
                    logger.exception(
                        "Connection %s could not be persisted; tracking continues",
                        connection.connection_id,
                    )
                    continue
                if stored:
                    written += 1
                # The record has been accepted by this layer — written, or found
                # unmappable — so it is no longer pending. Only a failed write
                # stays dirty and is retried by the next sweep.
                connection.dirty = False
        except Exception:  # noqa: BLE001 - even opening a session can fail
            # A locked or unreachable database fails the whole pass. That is a
            # persistence failure like any other: counted, logged, never raised
            # into the capture path (M9.20). Every record keeps its dirty flag,
            # so the next sweep retries the batch.
            with self._counter_lock:
                self._failed += len(batch)
            logger.exception("Connection persistence pass could not run")
        finally:
            if session is not None:
                session.close()
        return written

    def persist(self, connection: Connection) -> bool:
        """Write one conversation; return True when a row was written."""
        return self.persist_many([connection]) > 0

    # -- configuration ----------------------------------------------------

    def is_enabled(self) -> bool:
        """Return True when the layer accepts writes."""
        return self._enabled

    def set_enabled(self, enabled: bool) -> None:
        """Turn the layer on or off."""
        self._enabled = enabled

    def set_session_factory(self, factory: SessionFactory) -> None:
        """Replace the session factory (used by tests and by late wiring)."""
        self._session_factory = factory

    # -- diagnostics ------------------------------------------------------

    def get_created_count(self) -> int:
        """Return how many ``INSERT`` statements succeeded."""
        with self._counter_lock:
            return self._created

    def get_updated_count(self) -> int:
        """Return how many ``UPDATE`` statements succeeded."""
        with self._counter_lock:
            return self._updated

    def get_failed_count(self) -> int:
        """Return how many conversations failed to persist."""
        with self._counter_lock:
            return self._failed

    def get_skipped_count(self) -> int:
        """Return how many conversations were unmappable and skipped."""
        with self._counter_lock:
            return self._skipped

    def get_deferred_count(self) -> int:
        """Return how many conversations exceeded a pass cap and waited."""
        with self._counter_lock:
            return self._deferred

    def get_written_count(self) -> int:
        """Return how many rows have been written in total."""
        with self._counter_lock:
            return self._created + self._updated

    def reset(self) -> None:
        """Clear the diagnostic counters."""
        with self._counter_lock:
            self._created = 0
            self._updated = 0
            self._failed = 0
            self._skipped = 0
            self._deferred = 0

    # -- internals --------------------------------------------------------

    def _write_one(
        self, repository: ConnectionRepository, connection: Connection
    ) -> bool:
        """Insert or update the row for ``connection``; return True if written.

        Raises whatever the repository raises — the caller isolates and counts
        it.
        """
        values = to_connection_values(
            connection,
            source_device_row_id=self._resolve_device_row_id(
                connection.source_device_id
            ),
            destination_device_row_id=self._resolve_device_row_id(
                connection.destination_device_id
            ),
        )
        if values is None:
            with self._counter_lock:
                self._skipped += 1
            return False

        row_id = connection.persisted_row_id
        existing = repository.get(row_id) if row_id is not None else None
        if existing is None:
            # Either the conversation has never been written, or the row it was
            # written to has since been removed (for example by retention). Both
            # cases are served by an insert, which keeps the aggregate complete.
            row = repository.create(**values)
            connection.persisted_row_id = row.id
            with self._counter_lock:
                self._created += 1
            return True

        repository.update(existing, **values)
        with self._counter_lock:
            self._updated += 1
        return True

    def _resolve_device_row_id(self, device_id: str | None) -> int | None:
        """Resolve a runtime device id to a ``devices.id``, when possible.

        A resolver failure is not a persistence failure: the conversation is
        still worth storing, so the foreign key is simply left empty.
        """
        resolver = self._device_id_resolver
        if resolver is None or device_id is None:
            return None
        try:
            return resolver(device_id)
        except Exception:  # noqa: BLE001 - linkage is enrichment, not data
            logger.debug("Device id %s could not be resolved to a row", device_id)
            return None
