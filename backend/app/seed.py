"""Idempotent seeding of the first admin account."""
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import hash_password
from .config import settings
from .models import User


async def ensure_first_admin(db: AsyncSession) -> None:
    count = (await db.execute(select(func.count(User.id)))).scalar_one()
    if count > 0:
        return
    admin = User(
        username=settings.first_admin_username,
        hashed_password=hash_password(settings.first_admin_password),
        role="admin",
    )
    db.add(admin)
    await db.commit()
    print(f"[seed] Created first admin user '{settings.first_admin_username}'. "
          f"Change the password immediately.")
