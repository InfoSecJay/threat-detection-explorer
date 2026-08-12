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
                default = "'[]'" if "json" in str(col_type).lower() or "text" in str(col_type).lower() else "NULL"
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

    # 1. Drop legacy single-value columns.
    for legacy in ("platform", "event_category", "data_source_normalized"):
        if legacy in cols:
            connection.execute(text(f'ALTER TABLE detections DROP COLUMN {legacy}'))
            logger.info(f"Phase 3: dropped legacy column detections.{legacy}")
            cols.discard(legacy)

    # 2. Drop raw vendor list columns. `data_sources` is dropped here
    # so the canonical `taxonomy_data_sources` rename below can take
    # over the name. A bare `data_sources` with no `taxonomy_data_sources`
    # alongside it is the already-migrated canonical column — leave it.
    if "log_sources" in cols:
        connection.execute(text('ALTER TABLE detections DROP COLUMN log_sources'))
        logger.info("Phase 3: dropped raw column detections.log_sources")
        cols.discard("log_sources")
    if "data_sources" in cols and "taxonomy_data_sources" in cols:
        connection.execute(text('ALTER TABLE detections DROP COLUMN data_sources'))
        logger.info("Phase 3: dropped raw column detections.data_sources")
        cols.discard("data_sources")

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
