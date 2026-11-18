"""Database models: users, events, alerts, audit log."""
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="analyst")  # admin|analyst|viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Event(Base):
    """A normalized security event ingested from any source."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    # When the event actually happened (from the source).
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=utcnow)
    # When we received it.
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    source: Mapped[str] = mapped_column(String(32), index=True)  # windows|linux|syslog|firewall|web|custom
    event_type: Mapped[str] = mapped_column(String(48), index=True)  # login|process|network|access|...
    action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)  # success|failure

    hostname: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dest_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dest_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    severity: Mapped[str] = mapped_column(String(16), default="Informational")
    message: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[dict] = mapped_column(JSON, default=dict)

    __table_args__ = (
        Index("ix_events_ip_outcome_time", "source_ip", "outcome", "timestamp"),
    )


class Alert(Base):
    """An alert produced by the detection engine. Deduplicated by dedup_key."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    dedup_key: Mapped[str] = mapped_column(String(255), unique=True, index=True)

    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_name: Mapped[str] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")

    severity: Mapped[str] = mapped_column(String(16), index=True)  # Critical|High|Medium|Low|Informational
    risk_score: Mapped[int] = mapped_column(Integer, default=0)

    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dest_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)

    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Workflow
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # open|investigating|closed
    # Analyst's confirmed verdict. Starts unconfirmed; only a human sets TP/FP.
    analyst_verdict: Mapped[str] = mapped_column(String(24), default="unconfirmed")
    assigned_to: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # AI triage (suggestion only, never authoritative)
    ai_classification: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ai_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    ai_analysis: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    notes = relationship("AlertNote", back_populates="alert", cascade="all, delete-orphan")


class AlertNote(Base):
    __tablename__ = "alert_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    author: Mapped[str] = mapped_column(String(64))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    alert = relationship("Alert", back_populates="notes")


class AuditLog(Base):
    """Immutable record of analyst actions for accountability."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
