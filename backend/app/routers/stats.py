"""Dashboard statistics endpoints."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..database import get_db
from ..models import Alert, Event, User
from ..schemas import StatsOverview

router = APIRouter(prefix="/api/stats", tags=["stats"])


def _utcnow():
    return datetime.now(timezone.utc)


@router.get("/overview", response_model=StatsOverview)
async def overview(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    total_events = (await db.execute(select(func.count(Event.id)))).scalar_one()
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar_one()
    open_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.status != "closed"))).scalar_one()
    critical = (await db.execute(
        select(func.count(Alert.id)).where(Alert.severity == "Critical"))).scalar_one()
    high = (await db.execute(
        select(func.count(Alert.id)).where(Alert.severity == "High"))).scalar_one()
    last_hour = (await db.execute(
        select(func.count(Event.id)).where(Event.ingested_at >= _utcnow() - timedelta(hours=1))
    )).scalar_one()
    return StatsOverview(
        total_events=total_events, total_alerts=total_alerts, open_alerts=open_alerts,
        critical_alerts=critical, high_alerts=high, events_last_hour=last_hour,
    )


@router.get("/events-timeline")
async def events_timeline(
    minutes: int = Query(default=60, le=1440),
    buckets: int = Query(default=30, le=120),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Event counts bucketed over the recent window (DB-agnostic, computed in Python)."""
    now = _utcnow()
    start = now - timedelta(minutes=minutes)
    rows = (await db.execute(
        select(Event.ingested_at).where(Event.ingested_at >= start)
    )).scalars().all()
    bucket_size = max(1, (minutes * 60) // buckets)
    counts = [0] * buckets
    for ts in rows:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        idx = int((ts - start).total_seconds() // bucket_size)
        if 0 <= idx < buckets:
            counts[idx] += 1
    return {
        "start": start, "bucket_seconds": bucket_size,
        "series": [
            {"t": (start + timedelta(seconds=i * bucket_size)).isoformat(), "count": c}
            for i, c in enumerate(counts)
        ],
    }


@router.get("/alerts-by-severity")
async def alerts_by_severity(db: AsyncSession = Depends(get_db),
                             user: User = Depends(get_current_user)):
    rows = (await db.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    )).all()
    order = ["Critical", "High", "Medium", "Low", "Informational"]
    data = {sev: 0 for sev in order}
    for sev, count in rows:
        data[sev] = count
    return [{"severity": s, "count": data[s]} for s in order]


@router.get("/top-source-ips")
async def top_source_ips(limit: int = Query(default=10, le=50),
                         db: AsyncSession = Depends(get_db),
                         user: User = Depends(get_current_user)):
    rows = (await db.execute(
        select(Event.source_ip, func.count(Event.id).label("c"))
        .where(Event.source_ip.isnot(None))
        .group_by(Event.source_ip).order_by(func.count(Event.id).desc()).limit(limit)
    )).all()
    return [{"source_ip": ip, "count": c} for ip, c in rows]


@router.get("/top-rules")
async def top_rules(limit: int = Query(default=10, le=50),
                    db: AsyncSession = Depends(get_db),
                    user: User = Depends(get_current_user)):
    rows = (await db.execute(
        select(Alert.rule_id, Alert.rule_name, func.count(Alert.id).label("c"))
        .group_by(Alert.rule_id, Alert.rule_name)
        .order_by(func.count(Alert.id).desc()).limit(limit)
    )).all()
    return [{"rule_id": r, "rule_name": n, "count": c} for r, n, c in rows]
