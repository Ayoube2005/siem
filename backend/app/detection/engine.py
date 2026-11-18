"""Detection engine: runs rules against an event, deduplicates, persists alerts."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Alert, Event
from .rules import ALL_RULES, AlertDraft

# How long an existing alert keeps absorbing matching events before a new one
# is opened for the same dedup_key.
DEDUP_COOLDOWN = timedelta(hours=1)


def _aware(dt: datetime) -> datetime:
    """Coerce to timezone-aware UTC. SQLite returns naive datetimes; Postgres
    returns aware. Normalizing here keeps the engine backend-agnostic."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def _upsert_alert(db: AsyncSession, draft: AlertDraft, event: Event) -> tuple[Optional[Alert], bool]:
    """Create a new alert or fold the event into a recent matching one.

    Returns (alert, created) where created is False when we deduplicated.
    """
    existing = (
        await db.execute(select(Alert).where(Alert.dedup_key == draft.dedup_key))
    ).scalar_one_or_none()

    if existing and (_aware(event.timestamp) - _aware(existing.last_seen)) <= DEDUP_COOLDOWN:
        # Deduplicate: update the running alert instead of spawning a new one.
        existing.event_count += 1
        existing.last_seen = event.timestamp
        existing.evidence = {**(existing.evidence or {}), **draft.evidence}
        if draft.risk_score > existing.risk_score:
            existing.risk_score = draft.risk_score
        return existing, False

    if existing:
        # Stale alert with same key — make this occurrence unique.
        draft.dedup_key = f"{draft.dedup_key}:{int(event.timestamp.timestamp())}"

    alert = Alert(
        dedup_key=draft.dedup_key,
        rule_id=draft.rule_id,
        rule_name=draft.rule_name,
        title=draft.title,
        description=draft.description,
        severity=draft.severity,
        risk_score=draft.risk_score,
        source_ip=draft.source_ip,
        dest_ip=draft.dest_ip,
        username=draft.username,
        evidence={**draft.evidence, "trigger_event_id": event.id},
        event_count=1,
        first_seen=event.timestamp,
        last_seen=event.timestamp,
    )
    db.add(alert)
    return alert, True


async def run_detection(db: AsyncSession, event: Event) -> list[Alert]:
    """Run every rule against a freshly stored event. Returns newly created alerts."""
    created: list[Alert] = []
    for rule in ALL_RULES:
        try:
            draft = await rule(event, db)
        except Exception:
            # A faulty rule must never break ingestion.
            continue
        if draft is None:
            continue
        alert, is_new = await _upsert_alert(db, draft, event)
        if is_new and alert is not None:
            await db.flush()  # assign alert.id
            created.append(alert)
    return created
