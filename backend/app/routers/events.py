"""Event ingestion and search endpoints."""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user, require_role
from ..config import settings
from ..database import get_db
from ..ingest import ingest_events
from ..limiter import limiter
from ..models import Event, User
from ..schemas import EventBatchIn, EventIn, EventOut, IngestResult

router = APIRouter(prefix="/api/events", tags=["events"])


@router.post("", response_model=IngestResult, status_code=201)
@limiter.limit(settings.ingest_rate_limit)
async def ingest_one(
    request: Request,
    event: EventIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("analyst")),
):
    return await ingest_events(db, [event])


@router.post("/batch", response_model=IngestResult, status_code=201)
@limiter.limit(settings.ingest_rate_limit)
async def ingest_batch(
    request: Request,
    batch: EventBatchIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("analyst")),
):
    return await ingest_events(db, batch.events)


@router.get("", response_model=list[EventOut])
async def search_events(
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    outcome: Optional[str] = None,
    q: Optional[str] = Query(default=None, description="free-text search in message"),
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    stmt = select(Event)
    if source:
        stmt = stmt.where(Event.source == source)
    if event_type:
        stmt = stmt.where(Event.event_type == event_type)
    if severity:
        stmt = stmt.where(Event.severity == severity)
    if source_ip:
        stmt = stmt.where(Event.source_ip == source_ip)
    if username:
        stmt = stmt.where(Event.username == username)
    if outcome:
        stmt = stmt.where(Event.outcome == outcome)
    if q:
        stmt = stmt.where(Event.message.ilike(f"%{q}%"))
    if start:
        stmt = stmt.where(Event.timestamp >= start)
    if end:
        stmt = stmt.where(Event.timestamp <= end)
    stmt = stmt.order_by(Event.timestamp.desc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    return rows
