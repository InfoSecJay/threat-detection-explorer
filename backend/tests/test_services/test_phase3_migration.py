"""Regression test for the Phase 3 taxonomy migration on SQLite (#37).

Pre-Phase-3 snapshots index the legacy single-value columns; SQLite
refuses DROP COLUMN while an index references the column, so the
migration used to fail with "error in index ix_detections_platform
after drop column" on every old dev snapshot restore.
"""

from __future__ import annotations

from sqlalchemy import create_engine, inspect, text

from app.database import _migrate_taxonomy_phase_3


def _legacy_schema(conn) -> None:
    conn.execute(text(
        """
        CREATE TABLE detections (
            id VARCHAR(36) PRIMARY KEY,
            title VARCHAR(500),
            platform VARCHAR(50),
            event_category VARCHAR(50),
            data_source_normalized VARCHAR(100),
            log_sources JSON,
            data_sources JSON,
            taxonomy_platforms JSON,
            taxonomy_data_sources JSON,
            taxonomy_event_types JSON
        )
        """
    ))
    conn.execute(text("CREATE INDEX ix_detections_platform ON detections (platform)"))
    conn.execute(text("CREATE INDEX ix_detections_event_category ON detections (event_category)"))
    conn.execute(text(
        "CREATE INDEX ix_detections_data_source_normalized ON detections (data_source_normalized)"
    ))
    # An unrelated index must survive.
    conn.execute(text("CREATE INDEX ix_detections_title ON detections (title)"))
    conn.execute(text(
        "INSERT INTO detections (id, title, platform, taxonomy_platforms, taxonomy_data_sources, "
        "taxonomy_event_types, data_sources) VALUES "
        "('r1', 'Rule', 'windows', '[\"windows\"]', '[\"sysmon\"]', '[\"process_creation\"]', '[\"raw\"]')"
    ))


def test_phase3_drops_indexed_legacy_columns_on_sqlite():
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        _legacy_schema(conn)

    with engine.begin() as conn:
        _migrate_taxonomy_phase_3(conn)  # used to raise OperationalError here

    inspector = inspect(engine)
    cols = {c["name"] for c in inspector.get_columns("detections")}
    assert cols == {"id", "title", "platforms", "data_sources", "event_types"}

    index_names = {i["name"] for i in inspector.get_indexes("detections")}
    assert "ix_detections_platform" not in index_names
    assert "ix_detections_title" in index_names, "unrelated indexes must be left alone"

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT platforms, data_sources, event_types FROM detections WHERE id='r1'")
        ).one()
    # Canonical data survived the rename; the raw data_sources column is gone.
    assert row == ('["windows"]', '["sysmon"]', '["process_creation"]')


def test_phase3_is_idempotent_on_migrated_schema():
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        _legacy_schema(conn)
    with engine.begin() as conn:
        _migrate_taxonomy_phase_3(conn)
    with engine.begin() as conn:
        _migrate_taxonomy_phase_3(conn)  # second run: nothing to do, no error

    cols = {c["name"] for c in inspect(engine).get_columns("detections")}
    assert cols == {"id", "title", "platforms", "data_sources", "event_types"}
