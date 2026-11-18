"""Pydantic schemas for request/response validation."""
from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

Severity = Literal["Critical", "High", "Medium", "Low", "Informational"]


# ---------- Auth ----------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: str
    is_active: bool


# ---------- Event ingestion ----------
class EventIn(BaseModel):
    """Incoming raw security event. Only `source` and `event_type` are required;
    everything else is optional so heterogeneous sources can be ingested."""

    model_config = ConfigDict(extra="allow")

    timestamp: Optional[datetime] = None
    source: str = Field(min_length=1, max_length=32)
    event_type: str = Field(min_length=1, max_length=48)
    action: Optional[str] = Field(default=None, max_length=64)
    outcome: Optional[Literal["success", "failure"]] = None
    hostname: Optional[str] = Field(default=None, max_length=128)
    source_ip: Optional[str] = Field(default=None, max_length=64)
    dest_ip: Optional[str] = Field(default=None, max_length=64)
    dest_port: Optional[int] = Field(default=None, ge=0, le=65535)
    username: Optional[str] = Field(default=None, max_length=128)
    severity: Severity = "Informational"
    message: str = Field(default="", max_length=8000)
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source_ip", "dest_ip")
    @classmethod
    def _validate_ip(cls, v):
        if v in (None, ""):
            return None
        try:
            IPvAnyAddress(v)  # raises if invalid
        except Exception:
            # Accept hostnames too, but reject obviously broken values.
            if len(v) > 64:
                raise ValueError("invalid ip/host")
        return v


class EventBatchIn(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=500)


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    timestamp: datetime
    ingested_at: datetime
    source: str
    event_type: str
    action: Optional[str]
    outcome: Optional[str]
    hostname: Optional[str]
    source_ip: Optional[str]
    dest_ip: Optional[str]
    dest_port: Optional[int]
    username: Optional[str]
    severity: str
    message: str


class IngestResult(BaseModel):
    ingested: int
    alerts_created: int
    alert_ids: list[int] = []


# ---------- Alerts ----------
class AIAnalysis(BaseModel):
    classification: Literal["Likely True Positive", "Likely False Positive", "Needs Investigation"]
    confidence: float
    explanation: str
    supporting_evidence: list[str]
    investigation_steps: list[str]
    response_actions: list[str]
    provider: str
    disclaimer: str


class AlertNoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    author: str
    body: str
    created_at: datetime


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime
    updated_at: datetime
    rule_id: str
    rule_name: str
    title: str
    description: str
    severity: str
    risk_score: int
    source_ip: Optional[str]
    dest_ip: Optional[str]
    username: Optional[str]
    evidence: dict
    event_count: int
    first_seen: datetime
    last_seen: datetime
    status: str
    analyst_verdict: str
    assigned_to: Optional[str]
    ai_classification: Optional[str]
    ai_confidence: Optional[float]
    ai_analysis: Optional[dict]


class AlertUpdate(BaseModel):
    status: Optional[Literal["open", "investigating", "closed"]] = None
    analyst_verdict: Optional[Literal["unconfirmed", "true_positive", "false_positive"]] = None
    assigned_to: Optional[str] = None


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


# ---------- Stats ----------
class StatsOverview(BaseModel):
    total_events: int
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    high_alerts: int
    events_last_hour: int
