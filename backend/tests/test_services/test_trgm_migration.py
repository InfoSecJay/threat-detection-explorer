"""Trigram GIN indexes for body search (`content:` / `raw:` / `logic:`)."""

from unittest.mock import MagicMock

from app import database


def _conn(dialect: str, fail_extension: bool = False):
    conn = MagicMock()
    conn.engine.dialect.name = dialect
    executed: list[str] = []

    def execute(stmt, *a, **k):
        sql = str(stmt)
        executed.append(sql)
        if fail_extension and "CREATE EXTENSION" in sql:
            raise RuntimeError("permission denied to create extension")
        return MagicMock()

    conn.execute.side_effect = execute
    # A real savepoint re-raises; MagicMock's __exit__ would swallow it.
    conn.begin_nested.return_value.__exit__.return_value = False
    return conn, executed


def test_postgres_gets_the_extension_and_both_indexes_under_a_lock():
    conn, executed = _conn("postgresql")
    database._migrate_trgm_indexes(conn)
    joined = "\n".join(executed)
    assert "pg_advisory_xact_lock" in joined
    assert "CREATE EXTENSION IF NOT EXISTS pg_trgm" in joined
    assert "CREATE INDEX IF NOT EXISTS ix_detections_raw_content_trgm ON detections USING GIN (raw_content gin_trgm_ops)" in joined
    assert "CREATE INDEX IF NOT EXISTS ix_detections_detection_logic_trgm ON detections USING GIN (detection_logic gin_trgm_ops)" in joined
    conn.begin_nested.assert_called_once()


def test_sqlite_is_untouched():
    conn, executed = _conn("sqlite")
    database._migrate_trgm_indexes(conn)
    assert executed == []


def test_missing_extension_privilege_keeps_the_scan_and_the_transaction(caplog):
    conn, executed = _conn("postgresql", fail_extension=True)
    with caplog.at_level("WARNING"):
        database._migrate_trgm_indexes(conn)
    assert not any("CREATE INDEX" in s for s in executed), "no index without the extension"
    assert "pg_trgm unavailable" in caplog.text
