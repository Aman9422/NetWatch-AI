"""Schema upgrades that ``create_all`` cannot perform (M11).

``Base.metadata.create_all()`` only creates *missing* tables. It never changes an
existing one, so a table created by an earlier milestone keeps its original
constraints forever — and SQLite has no ``ALTER TABLE ... DROP CONSTRAINT``.

M11 found one such constraint that genuinely blocks the milestone: the M2
``alerts.status`` CHECK allows
``('new', 'acknowledged', 'investigating', 'resolved', 'false_positive')``, while
the M11 lifecycle writes ``open`` and ``dismissed`` (M11.6). Persisting an M11
alert into a database created before M11 therefore fails with an
``IntegrityError``. That is not a text change — the constraint has to be rebuilt.

The only way to change a CHECK in SQLite is to rebuild the table, following
SQLite's documented sequence:

1. a ``ck_alerts_status`` CHECK that already accepts the M11 values → no-op;
2. otherwise: turn foreign keys **off**, open one transaction, create the
   replacement table with the corrected constraint, copy every row, drop the
   original, rename, recreate the indexes, commit;
3. turn foreign keys back on.

Foreign keys are disabled for the rebuild on purpose and it is not optional:
``alert_evidence.alert_id`` and ``ai_insights.alert_id`` both cascade on delete,
so dropping the ``alerts`` table with enforcement on would silently delete every
alert's evidence and insight rows. With enforcement off, child rows are untouched
and still reference the same primary keys afterwards.

This module deliberately does **not** rewrite the whole table definition. It
copies the existing DDL and replaces only the status CHECK, so an upgrade can
never alter a column, a foreign key or an index that M11 has no business
touching — the only thing that changes is the constraint that has to.
"""

from __future__ import annotations

import logging
import re

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from app.alerts.status import STORED_STATUS_VALUES

logger = logging.getLogger(__name__)

#: Table the upgrade operates on.
_ALERTS_TABLE = "alerts"

#: Temporary name the replacement table is built under, before it is renamed
#: onto the original. Namespaced so it cannot collide with a real table.
_REPLACEMENT_TABLE = "alerts_m11_upgrade"

#: The named CHECK that carries the status vocabulary. The clause is
#: ``CONSTRAINT ck_alerts_status CHECK (status IN (...))`` — one *nested*
#: parenthesised group, because the values live inside ``IN (...)``. The pattern
#: therefore consumes the inner value list **and** the CHECK's own closing
#: parenthesis. Stopping at the first ``)`` would end the match inside the
#: IN-list and leave the CHECK's closing parenthesis behind, producing invalid
#: DDL, so the nesting is matched explicitly.
_STATUS_CHECK_PATTERN = re.compile(
    r"CONSTRAINT\s+ck_alerts_status\s+CHECK\s*\([^()]*\([^()]*\)[^()]*\)",
    re.IGNORECASE,
)

#: Matches only the leading ``CREATE TABLE alerts`` clause of a statement.
_CREATE_TABLE_PATTERN = re.compile(
    rf"CREATE\s+TABLE\s+\"?{_ALERTS_TABLE}\"?", re.IGNORECASE
)


class SchemaUpgradeError(RuntimeError):
    """Raised when a required schema upgrade cannot be applied."""


def _status_check_clause(values: tuple[str, ...]) -> str:
    """Render the status CHECK clause for ``values`` (M11.6)."""
    rendered = ", ".join(f"'{value}'" for value in values)
    return f"CONSTRAINT ck_alerts_status CHECK (status IN ({rendered}))"


def _read_alerts_ddl(connection: Connection) -> str | None:
    """Return the stored ``CREATE TABLE alerts`` statement, or ``None``.

    ``None`` means the table does not exist, which is a legitimate state: a test
    may run the upgrade against an empty database.
    """
    row = connection.execute(
        text(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'table' AND name = :name"
        ),
        {"name": _ALERTS_TABLE},
    ).fetchone()
    if row is None or row[0] is None:
        return None
    return str(row[0])


def _read_alerts_index_ddl(connection: Connection) -> list[str]:
    """Return the ``CREATE INDEX`` statements belonging to ``alerts``.

    Only explicit indexes have a stored statement; the implicit
    ``sqlite_autoindex_*`` entries created for a PRIMARY KEY or UNIQUE constraint
    have ``sql IS NULL`` and are recreated by SQLite itself, so they are excluded
    by the ``IS NOT NULL`` filter rather than by matching on their names.
    """
    rows = connection.execute(
        text(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'index' AND tbl_name = :name AND sql IS NOT NULL"
        ),
        {"name": _ALERTS_TABLE},
    ).fetchall()
    return [str(row[0]) for row in rows if row[0]]


def _replace_table_name(ddl: str) -> str:
    """Point a ``CREATE TABLE alerts`` statement at the replacement table name.

    Only the leading ``CREATE TABLE`` clause is rewritten: the body's foreign
    keys reference ``detection_rules`` and ``devices``, never ``alerts``, so a
    blanket replacement would be both unnecessary and unsafe.
    """
    rewritten, count = _CREATE_TABLE_PATTERN.subn(
        f"CREATE TABLE {_REPLACEMENT_TABLE}", ddl, count=1
    )
    if count != 1:
        raise SchemaUpgradeError(
            f"Could not rewrite the CREATE TABLE clause of the {_ALERTS_TABLE} DDL"
        )
    return rewritten


def _rebuild_alerts_table(
    connection: Connection, replacement_ddl: str, index_ddl: list[str]
) -> None:
    """Rebuild ``alerts`` with ``replacement_ddl``, preserving every row.

    The connection must already be in AUTOCOMMIT isolation, which is what makes
    the foreign-key pragma effective: SQLite silently ignores the pragma inside a
    transaction, and dropping the parent table with enforcement on would
    cascade-delete every alert's evidence (see the module docstring). Atomicity
    is kept by opening an explicit transaction after the pragma — SQLite's DDL is
    transactional, so a failure rolls the drop back.

    Raises:
        Exception: Whatever SQLite raised. The transaction has been rolled back,
            so a failed rebuild leaves the original table intact.
    """
    connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
    try:
        connection.exec_driver_sql("BEGIN")
        try:
            connection.exec_driver_sql(replacement_ddl)
            connection.exec_driver_sql(
                f"INSERT INTO {_REPLACEMENT_TABLE} SELECT * FROM {_ALERTS_TABLE}"
            )
            connection.exec_driver_sql(f"DROP TABLE {_ALERTS_TABLE}")
            connection.exec_driver_sql(
                f"ALTER TABLE {_REPLACEMENT_TABLE} RENAME TO {_ALERTS_TABLE}"
            )
            for statement in index_ddl:
                connection.exec_driver_sql(statement)
            connection.exec_driver_sql("COMMIT")
        except Exception:
            connection.exec_driver_sql("ROLLBACK")
            raise
    finally:
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")


def upgrade_alert_status_constraint(engine: Engine) -> bool:
    """Widen the ``alerts.status`` CHECK to the M11 vocabulary (M11.6).

    Args:
        engine: The engine whose database should be upgraded.

    Returns:
        ``True`` when the table was rebuilt, ``False`` when it already accepted
        the M11 statuses (or did not exist). ``False`` is the common answer: a
        database created after M11 already carries the wider constraint, so the
        upgrade is a no-op and startup stays cheap.

    Raises:
        SchemaUpgradeError: If the table exists but its status CHECK cannot be
            found, because that means the schema is not the one this module
            understands and guessing at it would be worse than failing.
        Exception: Whatever SQLite raised during the rebuild, after rollback.
    """
    target_clause = _status_check_clause(STORED_STATUS_VALUES)
    with engine.connect() as connection:
        ddl = _read_alerts_ddl(connection)
        if ddl is None:
            logger.debug("No %s table to upgrade", _ALERTS_TABLE)
            return False
        if target_clause in ddl:
            logger.debug("%s.status already accepts the M11 values", _ALERTS_TABLE)
            return False
        if not _STATUS_CHECK_PATTERN.search(ddl):
            raise SchemaUpgradeError(
                f"The {_ALERTS_TABLE} table has no ck_alerts_status constraint to "
                "upgrade; refusing to rewrite a schema this upgrade does not know"
            )
        # A function replacement, not a template string: SQLite DDL carries no
        # backslashes today, but this keeps a future literal safe regardless.
        upgraded_ddl = _STATUS_CHECK_PATTERN.sub(lambda _: target_clause, ddl, count=1)
        replacement_ddl = _replace_table_name(upgraded_ddl)
        index_ddl = _read_alerts_index_ddl(connection)

    logger.info(
        "Upgrading %s.status to the M11 vocabulary (%d values), rebuilding the table",
        _ALERTS_TABLE,
        len(STORED_STATUS_VALUES),
    )
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        _rebuild_alerts_table(connection, replacement_ddl, index_ddl)
    logger.info("%s.status constraint upgraded", _ALERTS_TABLE)
    return True
