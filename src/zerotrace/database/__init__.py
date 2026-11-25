"""Database engine and session factory for ZeroTrace."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from zerotrace.config import settings
from zerotrace.database.models import Base
from zerotrace.logging_config import get_logger

logger = get_logger("database")

# Module-level engine (created on first access)
_engine = None


def _get_engine():
    """Lazily initialize the async engine."""
    global _engine
    if _engine is None:
        db_path = settings.db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info("Initializing database at %s", db_path)
        _engine = create_async_engine(
            settings.database_url,
            echo=settings.debug,
            connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {},
        )
    return _engine


async def init_db() -> None:
    """Create all tables if they don't exist."""
    engine = _get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialized")


async def shutdown_db() -> None:
    """Dispose of the engine connection pool."""
    global _engine
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        logger.info("Database connection closed")


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async DB session with automatic cleanup."""
    engine = _get_engine()
    from sqlalchemy.ext.asyncio import async_sessionmaker
    async_session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# Export get_async_session as an alias for get_session
get_async_session = get_session