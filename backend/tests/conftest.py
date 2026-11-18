"""Pytest fixtures. Runs the whole app against a throwaway SQLite database.

Environment must be configured BEFORE importing the app, so this happens at the
top of conftest (pytest imports conftest before the test modules).
"""
import os
import pathlib
import tempfile

_db_path = pathlib.Path(tempfile.gettempdir()) / "siem_test.db"
if _db_path.exists():
    _db_path.unlink()
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_db_path.as_posix()}"
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["FIRST_ADMIN_USERNAME"] = "admin"
os.environ["FIRST_ADMIN_PASSWORD"] = "admin"
os.environ["AI_PROVIDER"] = "heuristic"
os.environ["INGEST_RATE_LIMIT"] = "100000/minute"
os.environ["AUTH_RATE_LIMIT"] = "100000/minute"

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.seed import ensure_first_admin  # noqa: E402


@pytest_asyncio.fixture(autouse=True)
async def _reset_db():
    """Fresh schema + seeded admin before every test for isolation."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        await ensure_first_admin(db)
    yield


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def session():
    async with AsyncSessionLocal() as s:
        yield s


@pytest_asyncio.fixture
async def auth_headers(client):
    resp = await client.post(
        "/api/auth/login", data={"username": "admin", "password": "admin"}
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}
