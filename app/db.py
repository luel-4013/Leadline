"""
Leadline Database Configuration
Phase 7: Event Database - Async SQLAlchemy setup
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from app.config import settings

# Create async engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
)

# Session factory
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# Base class for models
Base = declarative_base()


async def get_db() -> AsyncSession:
    """Dependency for getting async database sessions."""
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_add_missing_columns)


def _add_missing_columns(sync_conn):
    """Best-effort migration for SQLite: add columns introduced on models
    after a table already existed (there's no alembic/migration framework
    here yet, and Base.metadata.create_all() only creates missing tables,
    not missing columns on ones that already exist). Idempotent -- safe to
    run on every startup, each ADD COLUMN is skipped if already present.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(sync_conn)
    existing_tables = set(inspector.get_table_names())

    # (table, column, SQL type incl. any DEFAULT) for columns added after
    # their table first shipped.
    new_columns = [
        ("targets", "custom_headers", "JSON"),
        ("scans", "evasion_enabled", "BOOLEAN DEFAULT 1"),
        ("scans", "request_delay", "FLOAT"),
        ("scans", "enable_external_lookups", "BOOLEAN DEFAULT 1"),
        ("scan_events", "findings_count", "INTEGER DEFAULT 0"),
        ("findings", "triage_status", "VARCHAR(30) DEFAULT 'open'"),
        ("findings", "triage_note", "TEXT"),
        ("findings", "triaged_at", "DATETIME"),
    ]

    for table, column, sql_type in new_columns:
        if table not in existing_tables:
            continue  # create_all() above already built it with every current column
        existing_columns = {c["name"] for c in inspector.get_columns(table)}
        if column not in existing_columns:
            sync_conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}"))


async def mark_interrupted_scans():
    """Fail scans left in a live state by a previous process.

    Scans currently run inside the FastAPI process (Starlette BackgroundTasks).
    If that process is killed or restarted, the database row stays in
    "running"/"stopping" forever. This is a small crash-recovery boundary: on
    startup, close those rows honestly instead of pretending they are alive.
    """
    from datetime import datetime
    from sqlalchemy import update
    from app.models import Scan

    async with async_session_maker() as session:
        await session.execute(
            update(Scan)
            .where(Scan.status.in_(("running", "stopping")))
            .values(
                status="failed",
                error_message="Scan interrupted by a server restart; start a new scan.",
                completed_at=datetime.now(),
            )
        )
        await session.commit()


async def close_db():
    """Close database connections."""
    await engine.dispose()
