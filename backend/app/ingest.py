"""Ingestion service: persist an event, run detection, triage, and broadcast.

Shared by the HTTP router and the test suite so the full pipeline is exercised
in one place.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from .ai.triage import analyze_alert
from .detection.engine import run_detection
from .models import Alert, Event
from .schemas import EventIn
from .websocket import manager


def _to_event(data: EventIn) -> Event:
    ts = data.timestamp or datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return Event(
        timestamp=ts,
        source=data.source,
        event_type=data.event_type,
        action=data.action,
        outcome=data.outcome,
        hostname=data.hostname,
        source_ip=data.source_ip,
        dest_ip=data.dest_ip,
        dest_port=data.dest_port,
        username=data.username,
        severity=data.severity,
        message=data.message,
        raw=data.raw or {},
    )


async def ingest_events(db: AsyncSession, events: list[EventIn], broadcast: bool = True) -> dict:
    """Store events, run detection on each, triage new alerts. Returns a summary."""
    new_alerts: list[Alert] = []
    stored: list[Event] = []

    for data in events:
        event = _to_event(data)
        db.add(event)
        await db.flush()  # assign event.id and make it queryable by rules
        stored.append(event)
        alerts = await run_detection(db, event)
        new_alerts.extend(alerts)

    # Advisory AI triage for each new alert (offline heuristic by default).
    for alert in new_alerts:
        try:
            analysis = await analyze_alert(alert)
            alert.ai_classification = analysis["classification"]
            alert.ai_confidence = analysis["confidence"]
            alert.ai_analysis = analysis
        except Exception:
            pass  # triage is best-effort; never block alerting

    await db.commit()

    if broadcast:
        for event in stored:
            await manager.broadcast("event", _event_payload(event))
        for alert in new_alerts:
            await manager.broadcast("alert", _alert_payload(alert))

    return {
        "ingested": len(stored),
        "alerts_created": len(new_alerts),
        "alert_ids": [a.id for a in new_alerts],
    }


def _event_payload(e: Event) -> dict:
    return {
        "id": e.id, "timestamp": e.timestamp, "source": e.source,
        "event_type": e.event_type, "outcome": e.outcome, "severity": e.severity,
        "source_ip": e.source_ip, "dest_ip": e.dest_ip, "username": e.username,
        "hostname": e.hostname, "message": e.message,
    }


def _alert_payload(a: Alert) -> dict:
    return {
        "id": a.id, "created_at": a.created_at, "rule_id": a.rule_id,
        "rule_name": a.rule_name, "title": a.title, "severity": a.severity,
        "risk_score": a.risk_score, "source_ip": a.source_ip, "username": a.username,
        "status": a.status, "ai_classification": a.ai_classification,
        "ai_confidence": a.ai_confidence,
    }
