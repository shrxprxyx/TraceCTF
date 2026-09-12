"""
Async SQLAlchemy engine and session management for TraceCTF.
Uses aiosqlite as the async driver so FastAPI routes can await DB calls
without blocking the event loop (important since capture must never stall).
"""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import settings
from app.db.models import Base

# SQLite async URL format: sqlite+aiosqlite:///<path>
DATABASE_URL = f"sqlite+aiosqlite:///{settings.db_path}"

engine = create_async_engine(
    DATABASE_URL,
    echo=False,          # set True temporarily if you need to debug SQL statements
    future=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db() -> None:
    """
    Creates all tables if they don't already exist.
    Called once on FastAPI startup.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency — yields a DB session per-request, closed automatically after.
    Usage in routes:
        async def some_route(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        yield session