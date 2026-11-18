"""Authentication endpoints."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    hash_password,
    require_role,
)
from ..config import settings
from ..database import get_db
from ..limiter import limiter
from ..models import AuditLog, User
from ..schemas import Token, UserOut

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=Token)
@limiter.limit(settings.auth_rate_limit)
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    user = await authenticate_user(db, form.username, form.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token(user.username, user.role)
    db.add(AuditLog(actor=user.username, action="login", target_type="user",
                    target_id=str(user.id)))
    await db.commit()
    return Token(access_token=token, role=user.role, username=user.username)


@router.get("/me", response_model=UserOut)
async def me(current: User = Depends(get_current_user)):
    return current


class _NewUser(dict):
    pass


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    """Admin-only: provision a new analyst/viewer account."""
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    role = payload.get("role", "analyst")
    if not username or not password:
        raise HTTPException(status_code=422, detail="username and password required")
    if role not in {"admin", "analyst", "viewer"}:
        raise HTTPException(status_code=422, detail="invalid role")
    exists = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=409, detail="username already exists")
    user = User(username=username, hashed_password=hash_password(password), role=role)
    db.add(user)
    db.add(AuditLog(actor=admin.username, action="create_user", target_type="user",
                    target_id=username, detail={"role": role}))
    await db.commit()
    await db.refresh(user)
    return user
