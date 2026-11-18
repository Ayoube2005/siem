"""Async SQLAlchemy engine, session factory and base model."""
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from .config import settings


class Base(DeclarativeBase):
    pass


_engine_kwargs: dict = {"echo": False, "pool_pre_ping": True}
if settings.database_url.startswith("postgresql"):
    # Connection pooling tuned for a 16 GB host (lightweight).
    _engine_kwargs.update(pool_size=5, max_overflow=10)
else:
    # SQLite (used by the test suite) doesn't accept pool sizing args.
    from sqlalchemy.pool import StaticPool

    _engine_kwargs.update(poolclass=StaticPool, connect_args={"check_same_thread": False})

engine = create_async_engine(settings.database_url, **_engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a scoped async session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def init_models() -> None:
    """Create tables if they do not exist (dev safety net; Alembic is primary)."""
    from . import models  # noqa: F401  ensure models are imported

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
