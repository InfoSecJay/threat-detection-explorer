"""Database configuration and session management."""

import logging
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""
    pass


engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
)

async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncSession:
    """Dependency for getting database sessions."""
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()


def _migrate_missing_columns(connection):
    """Add any missing columns to existing tables (lightweight migration)."""
    inspector = inspect(connection)
    for table_name, table in Base.metadata.tables.items():
        if not inspector.has_table(table_name):
            continue
        existing_cols = {col["name"] for col in inspector.get_columns(table_name)}
        for column in table.columns:
            if column.name not in existing_cols:
                col_type = column.type.compile(connection.engine.dialect)
                type_name = str(col_type).lower()
                server_default = getattr(getattr(column.server_default, "arg", None), "text", None)
                if isinstance(getattr(column.server_default, "arg", None), str):
                    server_default = column.server_default.arg
                if server_default is not None and "bool" not in type_name:
                    # Honour an explicit model default so existing rows are
                    # backfilled with it (rule_modality -> 'rule', #105)
                    # instead of a NULL every reader must coerce.
                    default = f"'{server_default}'"
                elif "json" in type_name or "text" in type_name:
                    default = "'[]'"
                elif "bool" in type_name:
                    # A NULL boolean is a third state every reader would
                    # have to special-case; backfill existing rows with
                    # FALSE (Postgres) / 0 (SQLite) instead.
                    default = "FALSE" if connection.engine.dialect.name == "postgresql" else "0"
                else:
                    default = "NULL"
                connection.execute(text(
                    f'ALTER TABLE {table_name} ADD COLUMN {column.name} {col_type} DEFAULT {default}'
                ))
                logger.info(f"Added missing column {table_name}.{column.name} ({col_type})")


def _migrate_taxonomy_phase_3(connection):
    """Phase 3 taxonomy migration -- idempotent.

    Drops the legacy single-value columns (`platform`,
    `event_category`, `data_source_normalized`) and the raw vendor
    list columns (`log_sources`, `data_sources`), then renames the
    canonical `taxonomy_*` columns to their final names
    (`platforms`, `data_sources`, `event_types`).

    Order matters: the raw `data_sources` column must be dropped
    before `taxonomy_data_sources` is renamed to `data_sources`,
    otherwise the rename collides.

    Runs on every startup. `data_sources` is the one name shared by
    the pre-migration raw column and the post-migration canonical
    column, so it is only treated as raw while `taxonomy_data_sources`
    still exists — without that guard, every restart drops the
    canonical column (wiping its data) and _migrate_missing_columns
    re-creates it empty.
    """
    inspector = inspect(connection)
    if not inspector.has_table("detections"):
        return

    cols = {col["name"] for col in inspector.get_columns("detections")}

    # SQLite refuses `DROP COLUMN` while an index references the column
    # ("error in index ix_detections_platform after drop column") and
    # the pre-Phase-3 legacy columns were indexed, so restoring an old
    # dev snapshot wedged here (#37). Postgres drops dependent indexes
    # automatically; doing it explicitly is harmless there.
    indexes_by_column: dict[str, list[str]] = {}
    for idx in inspector.get_indexes("detections"):
        for col_name in idx.get("column_names") or []:
            if col_name and idx.get("name"):
                indexes_by_column.setdefault(col_name, []).append(idx["name"])

    def _drop_column(name: str, kind: str) -> None:
        for index_name in indexes_by_column.pop(name, []):
            connection.execute(text(f'DROP INDEX IF EXISTS {index_name}'))
            logger.info(f"Phase 3: dropped index {index_name} before dropping detections.{name}")
        connection.execute(text(f'ALTER TABLE detections DROP COLUMN {name}'))
        logger.info(f"Phase 3: dropped {kind} column detections.{name}")
        cols.discard(name)

    # 1. Drop legacy single-value columns.
    for legacy in ("platform", "event_category", "data_source_normalized"):
        if legacy in cols:
            _drop_column(legacy, "legacy")

    # 2. Drop raw vendor list columns. `data_sources` is dropped here
    # so the canonical `taxonomy_data_sources` rename below can take
    # over the name. A bare `data_sources` with no `taxonomy_data_sources`
    # alongside it is the already-migrated canonical column — leave it.
    if "log_sources" in cols:
        _drop_column("log_sources", "raw")
    if "data_sources" in cols and "taxonomy_data_sources" in cols:
        _drop_column("data_sources", "raw")

    # 3. Rename `taxonomy_*` -> final names.
    renames = (
        ("taxonomy_platforms", "platforms"),
        ("taxonomy_data_sources", "data_sources"),
        ("taxonomy_event_types", "event_types"),
    )
    for old, new in renames:
        if old in cols and new not in cols:
            connection.execute(text(f'ALTER TABLE detections RENAME COLUMN {old} TO {new}'))
            logger.info(f"Phase 3: renamed detections.{old} -> detections.{new}")
            cols.discard(old)
            cols.add(new)


def _migrate_widen_rule_id(connection):
    """Widen `detections.rule_id` from VARCHAR(100) -> VARCHAR(200).

    Panther RuleIDs are human-readable dotted strings that can exceed
    100 characters (e.g.
    `Microsoft365.Audit.AzureActiveDirectory.SomeLongTechniqueName`).
    Idempotent: reads the current column length via the inspector and
    only issues the ALTER when a widen is actually needed.

    Postgres-only ALTER syntax; SQLite (dev) doesn't enforce VARCHAR
    length so the migration is a no-op there.
    """
    dialect_name = connection.engine.dialect.name
    if dialect_name != "postgresql":
        return

    inspector = inspect(connection)
    if not inspector.has_table("detections"):
        return

    for col in inspector.get_columns("detections"):
        if col["name"] != "rule_id":
            continue
        col_type = col.get("type")
        # SQLAlchemy exposes length on String types; None means unbounded.
        length = getattr(col_type, "length", None)
        if length is not None and length < 200:
            connection.execute(
                text("ALTER TABLE detections ALTER COLUMN rule_id TYPE VARCHAR(200)")
            )
            logger.info(
                f"Migrated detections.rule_id VARCHAR({length}) -> VARCHAR(200)"
            )
        break


def _migrate_sort_indexes(connection):
    """Indexes for the catalog's default orderings (#81 / S2.5).

    The teardown measured 1,278 ms for the default 25-row list: the
    sort columns had no indexes. Postgres-only (dev SQLite is small).
    """
    if connection.engine.dialect.name != "postgresql":
        return
    connection.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_detections_rule_created_date "
        "ON detections (rule_created_date DESC NULLS LAST)"
    ))
    connection.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_detections_quality_created "
        "ON detections (quality_score DESC NULLS LAST, rule_created_date DESC NULLS LAST)"
    ))


# Marker present only in the v2 expression; its absence on an existing
# column means the v1 vector and triggers a rebuild.
_SEARCH_VECTOR_V2_MARKER = "regexp_replace"

# Split path / file / dotted-tag punctuation into spaces before
# tokenizing. Postgres' parser otherwise keeps `lsass.exe` and
# `\Windows\system32\lsass.exe` as single file/path tokens, so a query
# for `lsass` never matched them (#125: 87 of 205 lsass rules and 105 of
# 155 certutil rules were reachable only by substring). The backslash
# is written as the POSIX collating element [.backslash.] -- it
# survives Python, SQL and ARE escaping unchanged (plain backslashes
# did not: verified against prod, 2026-09-02).
_SEARCH_VECTOR_SQL = """
    setweight(to_tsvector('english', coalesce(title, '')), 'A') ||
    setweight(to_tsvector('english', coalesce(rule_id, '')), 'B') ||
    setweight(to_tsvector('english', coalesce(description, '')), 'C') ||
    setweight(to_tsvector('english', regexp_replace(
        coalesce(use_cases::text, '') || ' ' || coalesce(tags::text, ''),
        '[[.backslash.]./_:-]+', ' ', 'g')), 'C') ||
    setweight(to_tsvector('english', regexp_replace(
        left(coalesce(detection_logic, ''), 16384),
        '[[.backslash.]./_:-]+', ' ', 'g')), 'D')
"""


def _migrate_search_vector(connection):
    """Weighted full-text search vector (#12 / teardown F13; v2 in #125).

    Postgres-only STORED generated column -- zero ingest-path changes,
    the DB keeps it current itself:

        title A > rule_id B > description, use_cases, tags C > logic D

    v2 (#125) adds the classification fields (Sublime's "Credential
    Phishing" use case made 978 phishing rules invisible to `q=`) and
    splits punctuation in logic and tags so process names inside paths
    match. `left(..., 16384)` caps pathological detection_logic bodies
    well under to_tsvector's 1MB document limit. Idempotent: the
    generation expression is inspected and a v1 column is rebuilt (a
    table rewrite, seconds at 15k rows). Serialized with an advisory
    lock so the API and worker cannot both rebuild at once. SQLite
    (dev) keeps the ILIKE path and never sees this column.
    """
    if connection.engine.dialect.name != "postgresql":
        return
    inspector = inspect(connection)
    if not inspector.has_table("detections"):
        return
    connection.execute(text("SELECT pg_advisory_xact_lock(7331001)"))
    expr = connection.execute(text(
        "SELECT generation_expression FROM information_schema.columns "
        "WHERE table_name = 'detections' AND column_name = 'search_vector'"
    )).scalar()
    if expr is not None and _SEARCH_VECTOR_V2_MARKER not in expr:
        connection.execute(text("DROP INDEX IF EXISTS ix_detections_search_vector"))
        connection.execute(text("ALTER TABLE detections DROP COLUMN search_vector"))
        logger.info("Dropped v1 detections.search_vector for rebuild (#125)")
        expr = None
    if expr is None:
        connection.execute(text(
            "ALTER TABLE detections ADD COLUMN search_vector tsvector "
            f"GENERATED ALWAYS AS ({_SEARCH_VECTOR_SQL}) STORED"
        ))
        logger.info("Added detections.search_vector (weighted tsvector, v2)")
    connection.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_detections_search_vector "
        "ON detections USING GIN (search_vector)"
    ))


async def init_db() -> None:
    """Initialize the database, creating all tables and migrating missing columns."""
    async with engine.begin() as conn:
        # Phase 3 migration runs FIRST so the column names are in
        # their final state before create_all / add-missing-columns
        # see the new model. Otherwise _migrate_missing_columns
        # would re-create the old `taxonomy_*` columns alongside the
        # renamed ones.
        await conn.run_sync(_migrate_taxonomy_phase_3)
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_migrate_missing_columns)
        # Rule_id column widen for Panther's dotted human-readable
        # RuleIDs — idempotent, Postgres-only.
        await conn.run_sync(_migrate_widen_rule_id)
        await conn.run_sync(_migrate_search_vector)
        await conn.run_sync(_migrate_sort_indexes)
