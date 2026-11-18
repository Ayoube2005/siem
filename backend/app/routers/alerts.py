"""Alert investigation, classification and AI triage endpoints."""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ai.triage import analyze_alert
from ..auth import get_current_user, require_role
from ..database import get_db
from ..models import Alert, AlertNote, AuditLog, User
from ..schemas import AlertNoteOut, AlertOut, AlertUpdate, NoteIn
from ..websocket import manager

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    rule_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    verdict: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    stmt = select(Alert)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if status:
        stmt = stmt.where(Alert.status == status)
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
    if source_ip:
        stmt = stmt.where(Alert.source_ip == source_ip)
    if verdict:
        stmt = stmt.where(Alert.analyst_verdict == verdict)
    if start:
        stmt = stmt.where(Alert.created_at >= start)
    if end:
        stmt = stmt.where(Alert.created_at <= end)
    stmt = stmt.order_by(Alert.created_at.desc()).limit(limit).offset(offset)
    return (await db.execute(stmt)).scalars().all()


async def _get_alert(db: AsyncSession, alert_id: int) -> Alert:
    alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db),
                    user: User = Depends(get_current_user)):
    return await _get_alert(db, alert_id)


@router.patch("/{alert_id}", response_model=AlertOut)
async def update_alert(
    alert_id: int,
    payload: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("analyst")),
):
    """Analyst updates status / confirms verdict. Every change is audited."""
    alert = await _get_alert(db, alert_id)
    changes = {}
    if payload.status is not None and payload.status != alert.status:
        changes["status"] = [alert.status, payload.status]
        alert.status = payload.status
    if payload.analyst_verdict is not None and payload.analyst_verdict != alert.analyst_verdict:
        changes["analyst_verdict"] = [alert.analyst_verdict, payload.analyst_verdict]
        alert.analyst_verdict = payload.analyst_verdict
    if payload.assigned_to is not None:
        changes["assigned_to"] = [alert.assigned_to, payload.assigned_to]
        alert.assigned_to = payload.assigned_to

    if changes:
        db.add(AuditLog(actor=user.username, action="update_alert",
                        target_type="alert", target_id=str(alert_id), detail=changes))
    await db.commit()
    await db.refresh(alert)
    await manager.broadcast("alert_update", {
        "id": alert.id, "status": alert.status,
        "analyst_verdict": alert.analyst_verdict, "assigned_to": alert.assigned_to,
    })
    return alert


@router.post("/{alert_id}/triage", response_model=AlertOut)
async def rerun_triage(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("analyst")),
):
    """Re-run AI triage on demand (e.g. after configuring a provider)."""
    alert = await _get_alert(db, alert_id)
    analysis = await analyze_alert(alert)
    alert.ai_classification = analysis["classification"]
    alert.ai_confidence = analysis["confidence"]
    alert.ai_analysis = analysis
    db.add(AuditLog(actor=user.username, action="rerun_triage",
                    target_type="alert", target_id=str(alert_id),
                    detail={"classification": analysis["classification"]}))
    await db.commit()
    await db.refresh(alert)
    return alert


@router.get("/{alert_id}/notes", response_model=list[AlertNoteOut])
async def list_notes(alert_id: int, db: AsyncSession = Depends(get_db),
                     user: User = Depends(get_current_user)):
    await _get_alert(db, alert_id)
    rows = (await db.execute(
        select(AlertNote).where(AlertNote.alert_id == alert_id).order_by(AlertNote.created_at)
    )).scalars().all()
    return rows


@router.post("/{alert_id}/notes", response_model=AlertNoteOut, status_code=201)
async def add_note(
    alert_id: int,
    payload: NoteIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("analyst")),
):
    await _get_alert(db, alert_id)
    note = AlertNote(alert_id=alert_id, author=user.username, body=payload.body)
    db.add(note)
    db.add(AuditLog(actor=user.username, action="add_note",
                    target_type="alert", target_id=str(alert_id)))
    await db.commit()
    await db.refresh(note)
    return note
