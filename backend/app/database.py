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


async def init_db() -> None:
    """Initialize the database, creating all tables and migrating missing columns."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_migrate_missing_columns)
