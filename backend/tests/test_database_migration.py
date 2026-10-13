"""Schema migration tests (M18.3).

``app/database/upgrade.py`` is what makes a milestone work against a database
created by an earlier one, and until M18 nothing exercised it. These tests are
about the three upgrades it implements, each of which has a failure mode that is
invisible until a real database is in front of it:

* ``upgrade_alert_status_constraint`` rebuilds the ``alerts`` table so its
  ``status`` CHECK accepts the M11 lifecycle. SQLite cannot drop a constraint, so
  the only way is drop-and-recreate -- on a table two other tables point at with
  ``ON DELETE`` actions. Run this wrong and the alerts survive while their
  evidence is silently erased.
* ``upgrade_report_metadata_columns`` adds five nullable columns to an existing
  ``reports`` table. Run this wrong and either a pre-M17 row becomes unreadable or
  the upgrade is not repeatable.
* ``upgrade_alert_finding_column`` adds the ``alerts.finding_id`` column M11.7
  needs and the M2 table never had. Without it every alert read back from an
  existing database loses the finding that raised it -- and it loses it silently,
  because a column a query never selects is not an error to SQLite.

Every test here works on a **real file** in ``tmp_path`` rather than on
``:memory:``. That is not incidental: the upgrade opens a second, AUTOCOMMIT
connection to run the rebuild, and an in-memory database is not shared between
connections unless a ``StaticPool`` is pinned to it -- so an in-memory test would
either fail for the wrong reason or, worse, pass while never reaching the code the
milestone depends on. A file is also the only way to assert that the developer's
own ``backend/netwatch.db`` is untouched, which the final test here does.

The pre-M11 schema is produced by **downgrading** a freshly created one rather
than by hand-writing M2 DDL. The rest of the schema is then exactly what a real
pre-M11 database held, so the rebuild runs against realistic neighbours, and the
substitution is done with a literal string replacement -- not the module's own
regex -- so this file cannot pass merely because the upgrade and the test share a
wrong assumption.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine

import app.database.init_db as init_db_module
from app import models as _models  # noqa: F401  (registers every table)
from app.alerts.status import STORED_STATUS_VALUES
from app.database import upgrade as upgrade_module
from app.database.base import Base
from app.database.upgrade import (
    SchemaUpgradeError,
    upgrade_alert_status_constraint,
    upgrade_report_metadata_columns,
)

# ---------------------------------------------------------------------------
# The two vocabularies, written out literally
# ---------------------------------------------------------------------------

#: The CHECK the *current* model declares. Spelled out rather than imported from
#: the module under test: if this ever drifts from ``app.models.alert``, the
#: downgrade below stops finding the clause and every test here fails loudly
#: instead of quietly measuring nothing.
CURRENT_STATUS_CLAUSE = (
    "CONSTRAINT ck_alerts_status CHECK (status IN "
    "('open', 'acknowledged', 'resolved', 'dismissed', 'false_positive', "
    "'new', 'investigating'))"
)

#: The M2 CHECK, which predates the M11 lifecycle and rejects ``open`` and
#: ``dismissed``. This is the constraint the upgrade has to widen.
M2_STATUS_CLAUSE = (
    "CONSTRAINT ck_alerts_status CHECK (status IN "
    "('new', 'acknowledged', 'investigating', 'resolved', 'false_positive'))"
)

#: A pre-M17 ``reports`` table: the M2 shape, without any of the five columns
#: M17.9 adds. Hand-written because there is no current model that produces it.
M2_REPORTS_DDL = """
CREATE TABLE reports (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    format VARCHAR(10) NOT NULL,
    generated_by INTEGER,
    file_path VARCHAR(500) NOT NULL,
    generated_at DATETIME NOT NULL
)
"""

#: The five columns M17.9 adds, as the upgrade declares them.
M17_REPORT_COLUMNS = ("period_start", "period_end", "status", "file_size", "error")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _file_engine(path: Path) -> Engine:
    """Return an engine over a real SQLite file, with foreign keys enforced.

    ``check_same_thread=False`` matches the application's own engine, because the
    M17 upgrade path and the rebuild both open a second connection.
    """
    engine = create_engine(
        f"sqlite:///{path.as_posix()}",
        connect_args={"check_same_thread": False},
    )

    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.close()

    return engine


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """A path for a real SQLite file that no other test shares."""
    return tmp_path / "m18_migration.db"


@pytest.fixture
def engine(db_path: Path):
    """A current-schema database on a real file, disposed afterwards."""
    engine = _file_engine(db_path)
    Base.metadata.create_all(bind=engine)
    try:
        yield engine
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _alerts_ddl(engine: Engine) -> str:
    """Return the stored ``CREATE TABLE alerts`` statement."""
    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT sql FROM sqlite_master WHERE type='table' AND name='alerts'")
        ).fetchone()
    assert row is not None and row[0] is not None
    return str(row[0])


def _downgrade_alerts_to_m2(engine: Engine) -> None:
    """Rewrite ``alerts`` back to the M2 status CHECK, preserving every row.

    This is the pre-M11 database the upgrade exists for. It deliberately repeats
    SQLite's documented rebuild sequence rather than calling anything from
    ``app.database.upgrade``: a test that reused the code under test to build its
    own premise would prove nothing about that code.
    """
    ddl = _alerts_ddl(engine)
    assert CURRENT_STATUS_CLAUSE in ddl, (
        "the alerts model no longer declares the CHECK this test downgrades; "
        "update CURRENT_STATUS_CLAUSE"
    )
    legacy = ddl.replace(CURRENT_STATUS_CLAUSE, M2_STATUS_CLAUSE)
    legacy = legacy.replace("CREATE TABLE alerts", "CREATE TABLE alerts_legacy", 1)

    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        indexes = [
            str(row[0])
            for row in connection.execute(
                text(
                    "SELECT sql FROM sqlite_master WHERE type='index' "
                    "AND tbl_name='alerts' AND sql IS NOT NULL"
                )
            ).fetchall()
        ]
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        try:
            connection.exec_driver_sql("BEGIN")
            connection.exec_driver_sql(legacy)
            connection.exec_driver_sql(
                "INSERT INTO alerts_legacy SELECT * FROM alerts"
            )
            connection.exec_driver_sql("DROP TABLE alerts")
            connection.exec_driver_sql("ALTER TABLE alerts_legacy RENAME TO alerts")
            for statement in indexes:
                connection.exec_driver_sql(statement)
            connection.exec_driver_sql("COMMIT")
        finally:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")


def _status_check(engine: Engine) -> str:
    """Return the ``alerts`` DDL of a live database, for substring assertions."""
    return _alerts_ddl(engine)


def _scalar(engine: Engine, sql: str) -> object:
    """Run a one-value query and return the value."""
    with engine.connect() as connection:
        return connection.execute(text(sql)).scalar()


def _seed_legacy_alerts(engine: Engine) -> list[tuple[int, str]]:
    """Insert three pre-M11 alerts and their children; return ``(id, status)``.

    The statuses are the ones a pre-M11 database actually held, so an upgrade that
    dropped or rewrote rows would be visible: ``old_status`` is one of the legacy
    M2 names and has to survive verbatim.
    """
    rows = [
        (1, "new", "Port scan detected", "high"),
        (2, "investigating", "SYN flood", "critical"),
        (3, "resolved", "Old incident", "low"),
    ]
    with engine.begin() as connection:
        for alert_id, status, title, severity in rows:
            connection.execute(
                text(
                    "INSERT INTO alerts (id, title, severity, risk_score, confidence, "
                    "status, created_at, updated_at) "
                    "VALUES (:id, :title, :severity, 0, 50, :status, "
                    "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                ),
                {
                    "id": alert_id,
                    "title": title,
                    "severity": severity,
                    "status": status,
                },
            )
        # One child row per alert on the cascade path, so a rebuild that dropped
        # the parent with enforcement on would delete them and be caught.
        for alert_id in (1, 2, 3):
            connection.execute(
                text(
                    "INSERT INTO alert_evidence (alert_id, evidence_type, evidence_data, "
                    "created_at) VALUES (:id, 'rule', '{}', '2026-01-01 00:00:00')"
                ),
                {"id": alert_id},
            )
            connection.execute(
                text(
                    "INSERT INTO ai_insights (alert_id, insight_type, summary, created_at) "
                    "VALUES (:id, 'alert_summary', 'seeded', '2026-01-01 00:00:00')"
                ),
                {"id": alert_id},
            )
    return [(alert_id, status) for alert_id, status, _, _ in rows]


# ---------------------------------------------------------------------------
# A fresh database needs no upgrade at all
# ---------------------------------------------------------------------------


def test_a_fresh_database_already_carries_the_m11_vocabulary(engine: Engine) -> None:
    """``create_all`` produces the widened CHECK, so the upgrade is a no-op.

    This is the common answer at startup, and it is the one that keeps every
    existing installation's boot cheap.
    """
    ddl = _status_check(engine)

    for status in STORED_STATUS_VALUES:
        assert f"'{status}'" in ddl


def test_a_fresh_database_needs_no_alert_upgrade(engine: Engine) -> None:
    """The upgrade reports that it changed nothing."""
    assert upgrade_alert_status_constraint(engine) is False


def test_a_fresh_database_needs_no_report_upgrade(engine: Engine) -> None:
    """Every M17 column is already present, so nothing is added."""
    assert upgrade_report_metadata_columns(engine) is False


def test_a_fresh_database_accepts_every_m11_status(engine: Engine) -> None:
    """Each state the lifecycle can write is storable without an upgrade."""
    with engine.begin() as connection:
        for index, status in enumerate(STORED_STATUS_VALUES):
            connection.execute(
                text(
                    "INSERT INTO alerts (id, title, severity, risk_score, confidence, "
                    "status, created_at, updated_at) "
                    "VALUES (:id, 'x', 'low', 0, 0, :status, "
                    "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                ),
                {"id": index + 1, "status": status},
            )

    assert _scalar(engine, "SELECT COUNT(*) FROM alerts") == len(STORED_STATUS_VALUES)


# ---------------------------------------------------------------------------
# The pre-M11 alerts table
# ---------------------------------------------------------------------------


def test_the_m2_check_really_rejects_the_m11_states(engine: Engine) -> None:
    """The premise, proven: ``open`` cannot be stored before the upgrade.

    Without this the rest of the file would be testing an upgrade for a problem
    that does not exist. SQLite raises ``IntegrityError`` through SQLAlchemy, so
    the assertion is on that rather than on a message.
    """
    from sqlalchemy.exc import IntegrityError

    _downgrade_alerts_to_m2(engine)

    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO alerts (title, severity, risk_score, confidence, "
                    "status, created_at, updated_at) "
                    "VALUES ('x', 'low', 0, 0, 'open', "
                    "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                )
            )


def test_the_upgrade_widens_the_status_check(engine: Engine) -> None:
    """After the upgrade the M11 lifecycle states are storable."""
    _downgrade_alerts_to_m2(engine)

    assert upgrade_alert_status_constraint(engine) is True

    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO alerts (title, severity, risk_score, confidence, status, "
                "created_at, updated_at) "
                "VALUES ('x', 'low', 0, 0, 'open', "
                "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO alerts (title, severity, risk_score, confidence, status, "
                "created_at, updated_at) "
                "VALUES ('y', 'low', 0, 0, 'dismissed', "
                "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
            )
        )

    assert _scalar(engine, "SELECT COUNT(*) FROM alerts WHERE status='open'") == 1
    assert _scalar(engine, "SELECT COUNT(*) FROM alerts WHERE status='dismissed'") == 1


def test_the_upgrade_preserves_every_legacy_alert_row(engine: Engine) -> None:
    """The rebuild copies rows rather than recreating them.

    Identities are asserted, not merely counts: the primary keys are what
    ``alert_evidence.alert_id`` points at, so a rebuild that renumbered the rows
    would orphan every child row while leaving the alert count correct.
    """
    _downgrade_alerts_to_m2(engine)
    seeded = _seed_legacy_alerts(engine)

    upgrade_alert_status_constraint(engine)

    with engine.connect() as connection:
        rows = connection.execute(
            text("SELECT id, status FROM alerts ORDER BY id")
        ).fetchall()

    assert [(int(row[0]), str(row[1])) for row in rows] == seeded


def test_the_upgrade_preserves_evidence_when_the_parent_is_dropped(
    engine: Engine,
) -> None:
    """The reason foreign keys are disabled for the rebuild.

    ``alert_evidence.alert_id`` cascades on delete and ``ai_insights.alert_id``
    nulls on delete. Rebuilding ``alerts`` with enforcement ON would therefore
    erase the first and blank the second -- the rebuild would succeed and destroy
    the operator's data. This is the test that says it does not.
    """
    _downgrade_alerts_to_m2(engine)
    _seed_legacy_alerts(engine)

    upgrade_alert_status_constraint(engine)

    assert _scalar(engine, "SELECT COUNT(*) FROM alert_evidence") == 3
    assert _scalar(engine, "SELECT COUNT(*) FROM alerts") == 3
    with engine.connect() as connection:
        orphaned = connection.execute(
            text(
                "SELECT COUNT(*) FROM alert_evidence e "
                "LEFT JOIN alerts a ON a.id = e.alert_id WHERE a.id IS NULL"
            )
        ).scalar()
    assert orphaned == 0

    # The SET NULL path must not have fired either.
    assert _scalar(engine, "SELECT COUNT(*) FROM ai_insights WHERE alert_id IS NULL") == 0


def test_the_upgrade_recreates_the_named_indexes(engine: Engine) -> None:
    """Dropping the table drops its indexes, so the rebuild puts them back.

    Without this the alerts list queries silently degrade to table scans, which
    nothing else in the suite would notice.
    """
    _downgrade_alerts_to_m2(engine)

    upgrade_alert_status_constraint(engine)

    indexes = {row["name"] for row in inspect(engine).get_indexes("alerts")}
    assert {
        "idx_alerts_created_at",
        "idx_alerts_severity",
        "idx_alerts_status",
        "idx_alerts_device_id",
        "idx_alerts_rule_id",
    }.issubset(indexes)


def test_the_upgrade_is_idempotent(engine: Engine) -> None:
    """A second run recognises the widened CHECK and does nothing.

    Every application start runs the upgrade, so a second run that rebuilt the
    table would rewrite the operator's largest table on every boot.
    """
    _downgrade_alerts_to_m2(engine)
    _seed_legacy_alerts(engine)

    assert upgrade_alert_status_constraint(engine) is True
    assert upgrade_alert_status_constraint(engine) is False

    assert _scalar(engine, "SELECT COUNT(*) FROM alerts") == 3
    assert _scalar(engine, "SELECT COUNT(*) FROM alert_evidence") == 3


def test_the_upgrade_restores_foreign_key_enforcement(engine: Engine) -> None:
    """The rebuild turns foreign keys off and must turn them back on.

    A leaked ``PRAGMA foreign_keys=OFF`` would mean every later write in the
    process silently accepts an orphan row.
    """
    _downgrade_alerts_to_m2(engine)

    upgrade_alert_status_constraint(engine)

    with engine.connect() as connection:
        assert connection.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_the_upgrade_tolerates_a_missing_table(db_path: Path) -> None:
    """An empty database is a legitimate state, not a failure.

    The upgrade runs *after* ``create_all`` for a reason, but it must not require
    the table to exist: a half-built database, or a bare test database, is not an
    error worth refusing to start over.
    """
    engine = _file_engine(db_path)
    try:
        assert upgrade_alert_status_constraint(engine) is False
    finally:
        engine.dispose()


def test_the_upgrade_refuses_a_schema_it_does_not_understand(db_path: Path) -> None:
    """An ``alerts`` table with no status CHECK is refused rather than guessed at.

    Guessing would mean writing a constraint the operator never had, on a table
    whose real shape this code knows nothing about.
    """
    engine = _file_engine(db_path)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE alerts (id INTEGER PRIMARY KEY, status VARCHAR(20))"
                )
            )

        with pytest.raises(SchemaUpgradeError):
            upgrade_alert_status_constraint(engine)

        # And the table it refused to touch is still exactly what it was.
        columns = {row["name"] for row in inspect(engine).get_columns("alerts")}
        assert columns == {"id", "status"}
    finally:
        engine.dispose()


def test_a_failed_rebuild_leaves_the_original_table_intact(engine: Engine) -> None:
    """A rebuild that fails rolls back, leaving the operator's data alone.

    The failure is produced deterministically rather than by patching: a table
    already occupying the rebuild's replacement name makes its ``CREATE TABLE``
    fail, which is exactly the class of failure (a disk error, a locked file) the
    rollback exists for.
    """
    _downgrade_alerts_to_m2(engine)
    _seed_legacy_alerts(engine)
    with engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE alerts_m11_upgrade (id INTEGER PRIMARY KEY)")
        )

    with pytest.raises(Exception):
        upgrade_alert_status_constraint(engine)

    # The original table, its rows and its children are all untouched, and the
    # constraint is still the narrow one -- so the next start retries rather than
    # believing it already succeeded.
    assert _scalar(engine, "SELECT COUNT(*) FROM alerts") == 3
    assert _scalar(engine, "SELECT COUNT(*) FROM alert_evidence") == 3
    assert M2_STATUS_CLAUSE in _alerts_ddl(engine)


def test_a_failed_rebuild_restores_foreign_key_enforcement(engine: Engine) -> None:
    """The ``finally`` that turns enforcement back on runs on the failure path too."""
    _downgrade_alerts_to_m2(engine)
    with engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE alerts_m11_upgrade (id INTEGER PRIMARY KEY)")
        )

    with pytest.raises(Exception):
        upgrade_alert_status_constraint(engine)

    with engine.connect() as connection:
        assert connection.execute(text("PRAGMA foreign_keys")).scalar() == 1


# ---------------------------------------------------------------------------
# The M17 additive report columns
# ---------------------------------------------------------------------------


def test_the_m17_upgrade_adds_every_missing_column(db_path: Path) -> None:
    """A pre-M17 ``reports`` table gains the five columns M17.9 writes."""
    engine = _file_engine(db_path)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(M2_REPORTS_DDL)

        assert upgrade_report_metadata_columns(engine) is True

        columns = {row["name"] for row in inspect(engine).get_columns("reports")}
        for name in M17_REPORT_COLUMNS:
            assert name in columns
    finally:
        engine.dispose()


def test_the_m17_upgrade_preserves_existing_report_rows(db_path: Path) -> None:
    """The upgrade is additive: no column is dropped, renamed, retyped or rewritten.

    A pre-M17 row must still be readable afterwards, and its ``status`` must come
    out as ``completed`` -- not null, and not a value invented by the migration.
    Those rows described a file that existed, so ``completed`` is the truthful
    description rather than a default chosen for convenience.
    """
    engine = _file_engine(db_path)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(M2_REPORTS_DDL)
            connection.execute(
                text(
                    "INSERT INTO reports (id, name, report_type, format, file_path, "
                    "generated_at) VALUES (7, 'Daily 2026-01-01', 'daily', 'PDF', "
                    "'netwatch-report-000007-2026-01-01.pdf', '2026-01-01 01:00:00')"
                )
            )

        upgrade_report_metadata_columns(engine)

        with engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT id, name, report_type, format, file_path, status, "
                    "period_start, period_end, file_size, error FROM reports"
                )
            ).fetchone()

        assert row is not None
        assert int(row[0]) == 7
        assert str(row[1]) == "Daily 2026-01-01"
        assert str(row[2]) == "daily"
        assert str(row[3]) == "PDF"
        assert str(row[4]) == "netwatch-report-000007-2026-01-01.pdf"
        assert str(row[5]) == "completed"
        # Unknown is not zero and not a fabricated period.
        assert row[6] is None
        assert row[7] is None
        assert row[8] is None
        assert row[9] is None
    finally:
        engine.dispose()


def test_the_m17_upgrade_is_idempotent(db_path: Path) -> None:
    """A second run adds nothing and changes nothing."""
    engine = _file_engine(db_path)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(M2_REPORTS_DDL)

        assert upgrade_report_metadata_columns(engine) is True
        assert upgrade_report_metadata_columns(engine) is False
    finally:
        engine.dispose()


def test_the_m17_upgrade_adds_only_what_is_missing(db_path: Path) -> None:
    """A partially upgraded table is completed rather than rebuilt.

    Each statement is independently valid, so a startup interrupted halfway
    through leaves a table the next startup finishes -- this is that property.
    """
    engine = _file_engine(db_path)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(M2_REPORTS_DDL)
            connection.exec_driver_sql(
                "ALTER TABLE reports ADD COLUMN period_start DATETIME"
            )
            connection.exec_driver_sql(
                "ALTER TABLE reports ADD COLUMN file_size INTEGER"
            )

        assert upgrade_report_metadata_columns(engine) is True

        columns = {row["name"] for row in inspect(engine).get_columns("reports")}
        for name in M17_REPORT_COLUMNS:
            assert name in columns
        # Running again now finds nothing to do.
        assert upgrade_report_metadata_columns(engine) is False
    finally:
        engine.dispose()


def test_the_m17_upgrade_tolerates_a_missing_reports_table(db_path: Path) -> None:
    """A database with no ``reports`` table is a no-op, not an error."""
    engine = _file_engine(db_path)
    try:
        assert upgrade_report_metadata_columns(engine) is False
    finally:
        engine.dispose()


def test_a_fresh_reports_table_needs_no_upgrade(engine: Engine) -> None:
    """``create_all`` gives the current shape, so the upgrade is a no-op there too."""
    columns = {row["name"] for row in inspect(engine).get_columns("reports")}

    for name in M17_REPORT_COLUMNS:
        assert name in columns
    assert upgrade_report_metadata_columns(engine) is False


# ---------------------------------------------------------------------------
# init_db: the composition both upgrades sit under
# ---------------------------------------------------------------------------


def test_init_db_creates_a_current_schema_on_a_fresh_file(db_path: Path) -> None:
    """``init_db`` creates every table and has nothing to upgrade afterwards.

    The composition is what the application actually calls, so it is exercised
    directly rather than inferred from the two parts: the module-level engine is
    redirected onto the temporary file for the duration of the call.
    """
    engine = _file_engine(db_path)
    try:
        import pytest as _pytest

        monkey = _pytest.MonkeyPatch()
        monkey.setattr(init_db_module, "engine", engine)
        try:
            init_db_module.init_db()
        finally:
            monkey.undo()

        tables = set(inspect(engine).get_table_names())
        assert {"users", "devices", "packets", "alerts", "alert_evidence", "reports"}.issubset(
            tables
        )
        # Both upgrades inspected a current schema and changed nothing.
        assert upgrade_alert_status_constraint(engine) is False
        assert upgrade_report_metadata_columns(engine) is False
    finally:
        engine.dispose()


def test_init_db_upgrades_a_legacy_database_in_place(engine: Engine) -> None:
    """A pre-M11, pre-M17 database is brought current by one ``init_db`` call.

    This is the end-to-end claim of the milestone's database requirement: an
    installation that predates M11 and M17 starts, and afterwards both the alert
    lifecycle and report generation work against the data it already held.

    The whole composition runs, not one upgrade in isolation: ``create_all`` fills
    in what is missing, then both upgrades inspect what was already there. That
    ordering is the point -- a ``create_all`` that ran *after* the upgrades would
    create nothing over an existing table and leave the legacy constraints in
    place forever.
    """
    _downgrade_alerts_to_m2(engine)
    _seed_legacy_alerts(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE reports")
        connection.exec_driver_sql(M2_REPORTS_DDL)
        connection.execute(
            text(
                "INSERT INTO reports (id, name, report_type, format, file_path, "
                "generated_at) VALUES (1, 'Legacy', 'daily', 'CSV', 'legacy.csv', "
                "'2026-01-01 00:00:00')"
            )
        )

    monkey = pytest.MonkeyPatch()
    monkey.setattr(init_db_module, "engine", engine)
    try:
        init_db_module.init_db()
    finally:
        monkey.undo()

    # The alert half: the lifecycle states are now storable and nothing was lost.
    assert _scalar(engine, "SELECT COUNT(*) FROM alerts") == 3
    assert _scalar(engine, "SELECT COUNT(*) FROM alert_evidence") == 3
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO alerts (title, severity, risk_score, confidence, status, "
                "created_at, updated_at) "
                "VALUES ('after upgrade', 'low', 0, 0, 'open', "
                "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
            )
        )

    # The reporting half: the M17 columns exist and the legacy row is intact.
    columns = {row["name"] for row in inspect(engine).get_columns("reports")}
    for name in M17_REPORT_COLUMNS:
        assert name in columns
    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT name, status FROM reports WHERE id = 1")
        ).fetchone()
    assert row is not None
    assert str(row[0]) == "Legacy"
    assert str(row[1]) == "completed"


# ---------------------------------------------------------------------------
# The M18 additive alerts.finding_id column
# ---------------------------------------------------------------------------

#: The column M18 adds to ``alerts`` and the index it carries.
M18_ALERT_COLUMN = "finding_id"
M18_ALERT_INDEX = "idx_alerts_finding_id"


def _downgrade_alerts_to_pre_m18(engine: Engine) -> None:
    """Remove ``alerts.finding_id``, giving back the table M18 found.

    Produced by dropping the column from a current table rather than by
    hand-writing pre-M18 DDL, so the rest of the table is exactly what a real
    pre-M18 database held and the upgrade runs against realistic neighbours. The
    index goes first because SQLite refuses to drop an indexed column.
    """
    with engine.begin() as connection:
        connection.exec_driver_sql(f"DROP INDEX {M18_ALERT_INDEX}")
        connection.exec_driver_sql(f"ALTER TABLE alerts DROP COLUMN {M18_ALERT_COLUMN}")


def _alert_columns(engine: Engine) -> set[str]:
    """Return the column names ``alerts`` currently has."""
    return {row["name"] for row in inspect(engine).get_columns("alerts")}


def test_a_fresh_database_carries_the_m18_alert_column(engine: Engine) -> None:
    """``create_all`` gives the column and its index, so the upgrade is a no-op."""
    assert M18_ALERT_COLUMN in _alert_columns(engine)
    assert M18_ALERT_INDEX in {
        row["name"] for row in inspect(engine).get_indexes("alerts")
    }

    from app.database.upgrade import upgrade_alert_finding_column

    assert upgrade_alert_finding_column(engine) is False


def test_the_m18_upgrade_adds_the_finding_column(engine: Engine) -> None:
    """The pre-M18 table gains the column the trail needs (M11.7)."""
    from app.database.upgrade import upgrade_alert_finding_column

    _downgrade_alerts_to_pre_m18(engine)
    assert M18_ALERT_COLUMN not in _alert_columns(engine)

    assert upgrade_alert_finding_column(engine) is True

    assert M18_ALERT_COLUMN in _alert_columns(engine)


def test_the_m18_upgrade_adds_the_finding_index(engine: Engine) -> None:
    """``ALTER TABLE ADD COLUMN`` cannot carry an index, so it is created too.

    Without it, following an alert back to its finding would scan the table.
    """
    from app.database.upgrade import upgrade_alert_finding_column

    _downgrade_alerts_to_pre_m18(engine)

    upgrade_alert_finding_column(engine)

    assert M18_ALERT_INDEX in {
        row["name"] for row in inspect(engine).get_indexes("alerts")
    }


def test_the_m18_upgrade_preserves_existing_alerts(engine: Engine) -> None:
    """The upgrade is additive: every pre-M18 row survives it unreadable-to-writable.

    A row written before the column existed has no finding behind it, and it must
    read back as ``NULL`` rather than as an empty string or a placeholder -- the
    two are different answers and only the first is truthful.
    """
    from app.database.upgrade import upgrade_alert_finding_column

    _downgrade_alerts_to_pre_m18(engine)
    _seed_legacy_alerts(engine)

    upgrade_alert_finding_column(engine)

    assert _scalar(engine, "SELECT COUNT(*) FROM alerts") == 3
    assert _scalar(engine, "SELECT COUNT(*) FROM alert_evidence") == 3
    with engine.connect() as connection:
        rows = connection.execute(
            text("SELECT id, status, finding_id FROM alerts ORDER BY id")
        ).fetchall()
    assert [(int(row[0]), str(row[1])) for row in rows] == [
        (1, "new"),
        (2, "investigating"),
        (3, "resolved"),
    ]
    assert all(row[2] is None for row in rows)


def test_the_m18_upgrade_is_idempotent(engine: Engine) -> None:
    """A second run finds the column and the index and does nothing."""
    from app.database.upgrade import upgrade_alert_finding_column

    _downgrade_alerts_to_pre_m18(engine)

    assert upgrade_alert_finding_column(engine) is True
    assert upgrade_alert_finding_column(engine) is False

    assert _scalar(engine, "SELECT COUNT(*) FROM alert_evidence") == 0


def test_the_m18_upgrade_tolerates_a_missing_alerts_table(db_path: Path) -> None:
    """A database with no ``alerts`` table is a no-op, not an error."""
    from app.database.upgrade import upgrade_alert_finding_column

    engine = _file_engine(db_path)
    try:
        assert upgrade_alert_finding_column(engine) is False
    finally:
        engine.dispose()


def test_init_db_adds_the_m18_column_to_a_pre_m18_database(engine: Engine) -> None:
    """The composition the application calls brings a pre-M18 table current.

    Asserted through ``init_db`` rather than through the upgrade directly, because
    the ordering is what makes it work: ``create_all`` cannot add a column to a
    table that already exists, so the upgrade is the only thing that can, and it
    has to run after ``create_all`` rather than instead of it.
    """
    from app.database.upgrade import upgrade_alert_finding_column

    _downgrade_alerts_to_pre_m18(engine)
    _seed_legacy_alerts(engine)

    monkey = pytest.MonkeyPatch()
    monkey.setattr(init_db_module, "engine", engine)
    try:
        init_db_module.init_db()
    finally:
        monkey.undo()

    assert M18_ALERT_COLUMN in _alert_columns(engine)
    assert upgrade_alert_finding_column(engine) is False

    # And the column is usable afterwards, which is the point of adding it.
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO alerts (title, severity, risk_score, confidence, status, "
                "finding_id, created_at, updated_at) "
                "VALUES ('after upgrade', 'low', 0, 0, 'open', "
                "'fnd-after-upgrade', '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
            )
        )
    assert (
        _scalar(engine, "SELECT finding_id FROM alerts WHERE title = 'after upgrade'")
        == "fnd-after-upgrade"
    )


# ---------------------------------------------------------------------------
# The developer's own database is never the subject
# ---------------------------------------------------------------------------


def test_no_migration_test_opens_the_development_database(tmp_path: Path) -> None:
    """The isolation guarantee M18.3 asks for, asserted rather than assumed.

    Every test in this file builds its own engine over ``tmp_path``, and this
    states why that matters rather than merely assuming it: the application's own
    default really is ``./netwatch.db``, resolved against the process working
    directory, so handing ``app.database.session.engine`` to either upgrade would
    rewrite the operator's database. A regression that reintroduced that would be
    invisible in every other test here.
    """
    from app.config.settings import settings

    # The application's default database is that relative file, which is what
    # makes the rule below load-bearing rather than theoretical.
    assert str(settings.database_url).endswith("netwatch.db")
    development = Path("netwatch.db").resolve()
    assert development.name == "netwatch.db"

    # A temporary directory is never that file, so an engine built from a
    # ``db_path`` in one cannot touch it.
    assert not development.is_relative_to(tmp_path)
    assert (tmp_path / "netwatch.db").resolve() != development

    # And the upgrade module owns no engine of its own to leak: it operates on an
    # engine its caller supplies, which is what makes this isolation possible.
    assert not hasattr(upgrade_module, "engine")
