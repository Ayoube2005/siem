"""Configurable, rule-based detection logic.

Each rule is an async callable: (event, db) -> AlertDraft | None.
Rules query recent persisted events within a sliding time window. Running on a
single worker keeps correlation state in PostgreSQL (durable across restarts)
instead of process memory.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import Event

SEVERITY_BASE_SCORE = {
    "Critical": 90,
    "High": 70,
    "Medium": 50,
    "Low": 30,
    "Informational": 10,
}

POWERSHELL_INDICATORS = [
    "-enc", "-encodedcommand", "-e ", "downloadstring", "iex", "invoke-expression",
    "-nop", "-noprofile", "-w hidden", "-windowstyle hidden", "frombase64string",
    "bypass", "webclient", "invoke-webrequest", "start-process -verb runas",
]

SENSITIVE_RESOURCE_KEYWORDS = [
    "shadow", "/etc/passwd", "sam", "ntds.dit", "secrets", "\\admin$",
    "credentials", "id_rsa", ".ssh", "wallet", "backup", "payroll", "finance",
]

LOGIN_TYPES = {"login", "authentication", "logon", "auth"}


@dataclass
class AlertDraft:
    rule_id: str
    rule_name: str
    title: str
    description: str
    severity: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    username: Optional[str] = None
    evidence: dict[str, Any] = field(default_factory=dict)
    dedup_key: str = ""

    @property
    def risk_score(self) -> int:
        score = SEVERITY_BASE_SCORE.get(self.severity, 10)
        # Correlation volume bumps the score.
        count = self.evidence.get("count") or self.evidence.get("distinct_users") or 0
        try:
            score = min(100, score + min(int(count), 10))
        except (TypeError, ValueError):
            pass
        return score


def _window_start(event: Event, seconds: int):
    return event.timestamp - timedelta(seconds=seconds)


def _is_login(event: Event) -> bool:
    return (event.event_type or "").lower() in LOGIN_TYPES


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
async def rule_bruteforce(event: Event, db: AsyncSession) -> Optional[AlertDraft]:
    """R001 — Brute force: many failed logins from one source IP."""
    if not _is_login(event) or event.outcome != "failure" or not event.source_ip:
        return None
    start = _window_start(event, settings.bruteforce_window_seconds)
    result = await db.execute(
        select(func.count(Event.id)).where(
            Event.source_ip == event.source_ip,
            Event.outcome == "failure",
            Event.event_type == event.event_type,
            Event.timestamp >= start,
        )
    )
    count = result.scalar_one()
    if count < settings.bruteforce_threshold:
        return None
    return AlertDraft(
        rule_id="R001",
        rule_name="Brute-force login attempts",
        title=f"Brute-force: {count} failed logins from {event.source_ip}",
        description=(
            f"{count} failed authentication attempts from {event.source_ip} within "
            f"{settings.bruteforce_window_seconds // 60} min (threshold "
            f"{settings.bruteforce_threshold})."
        ),
        severity="High",
        source_ip=event.source_ip,
        username=event.username,
        evidence={"count": count, "window_seconds": settings.bruteforce_window_seconds,
                  "target_user": event.username},
        dedup_key=f"R001:{event.source_ip}",
    )


async def rule_password_spray(event: Event, db: AsyncSession) -> Optional[AlertDraft]:
    """R002 — Password spray / repeated auth against multiple accounts."""
    if not _is_login(event) or event.outcome != "failure" or not event.source_ip:
        return None
    start = _window_start(event, settings.bruteforce_window_seconds)
    result = await db.execute(
        select(func.count(func.distinct(Event.username))).where(
            Event.source_ip == event.source_ip,
            Event.outcome == "failure",
            Event.timestamp >= start,
            Event.username.isnot(None),
        )
    )
    distinct_users = result.scalar_one()
    if distinct_users < settings.spray_distinct_users:
        return None
    return AlertDraft(
        rule_id="R002",
        rule_name="Password spray (multiple accounts)",
        title=f"Password spray from {event.source_ip}: {distinct_users} accounts targeted",
        description=(
            f"{event.source_ip} produced failed logins against {distinct_users} distinct "
            f"accounts within {settings.bruteforce_window_seconds // 60} min."
        ),
        severity="High",
        source_ip=event.source_ip,
        evidence={"distinct_users": distinct_users,
                  "window_seconds": settings.bruteforce_window_seconds},
        dedup_key=f"R002:{event.source_ip}",
    )


async def rule_success_after_failures(event: Event, db: AsyncSession) -> Optional[AlertDraft]:
    """R003 — Suspicious successful login following repeated failures."""
    if not _is_login(event) or event.outcome != "success" or not event.source_ip:
        return None
    start = _window_start(event, settings.bruteforce_window_seconds)
    result = await db.execute(
        select(func.count(Event.id)).where(
            Event.source_ip == event.source_ip,
            Event.outcome == "failure",
            Event.timestamp >= start,
            Event.timestamp < event.timestamp,
        )
    )
    prior_failures = result.scalar_one()
    if prior_failures < settings.bruteforce_threshold:
        return None
    return AlertDraft(
        rule_id="R003",
        rule_name="Successful login after brute-force",
        title=f"Possible account takeover: success from {event.source_ip} after {prior_failures} failures",
        description=(
            f"A successful login for '{event.username}' from {event.source_ip} occurred "
            f"after {prior_failures} failed attempts — possible credential compromise."
        ),
        severity="Critical",
        source_ip=event.source_ip,
        username=event.username,
        evidence={"prior_failures": prior_failures, "count": prior_failures},
        dedup_key=f"R003:{event.source_ip}:{event.username}",
    )


async def rule_privilege_escalation(event: Event, db: AsyncSession) -> Optional[AlertDraft]:
    """R004 — Privilege escalation."""
    et = (event.event_type or "").lower()
    action = (event.action or "").lower()
    msg = (event.message or "").lower()
    indicators = ["privilege_escalation", "sudo", "runas", "special privileges", "4672", "setuid"]
    hit = et == "privilege_escalation" or any(i in action or i in msg for i in indicators)
    if not hit:
        return None
    return AlertDraft(
        rule_id="R004",
        rule_name="Privilege escalation",
        title=f"Privilege escalation by '{event.username}' on {event.hostname or '?'}",
        description=f"Elevated-privilege activity detected: {event.message[:200]}",
        severity="High",
        source_ip=event.source_ip,
        username=event.username,
        evidence={"action": event.action, "hostname": event.hostname,
                  "message": event.message[:500]},
        dedup_key=f"R004:{event.username}:{event.hostname}",
    )


async def rule_suspicious_powershell(event: Event, db: AsyncSession) -> Optional[AlertDraft]:
    """R005 — Suspicious PowerShell / command execution."""
    if (event.event_type or "").lower() not in {"process", "process_creation", "command"}:
        return None
    blob = " ".join([
        event.message or "",
        str(event.raw.get("command_line", "")),
        str(event.raw.get("process", "")),
    ]).lower()
    if "powershell" not in blob and "pwsh" not in blob and "cmd.exe" not in blob:
        return None
    matched = [i for i in POWERSHELL_INDICATORS if i in blob]
    if not matched:
        return None
    return AlertDraft(
        rule_id="R005",
        rule_name="Suspicious PowerShell execution",
        title=f"Suspicious PowerShell on {event.hostname or '?'}",
        description=f"Suspicious command indicators: {', '.join(matched[:6])}",
        severity="High",
        source_ip=event.source_ip,
        username=event.username,
        evidence={"indicators": matched, "command": blob[:500], "hostname": event.hostname},
        dedup_key=f"R005:{event.hostname}:{event.username}:{'|'.join(sorted(matched))}",
    )


async def rule_port_scan(event: Event, db: AsyncSession) -> Optional[AlertDraft]:
    """R006 — Port scanning: many distinct destination ports from one source."""
    if (event.event_type or "").lower() not in {"network", "connection", "firewall"}:
        return None
    if not event.source_ip:
        return None
    start = _window_start(event, settings.portscan_window_seconds)
    result = await db.execute(
        select(func.count(func.distinct(Event.dest_port))).where(
            Event.source_ip == event.source_ip,
            Event.dest_port.isnot(None),
            Event.timestamp >= start,
        )
    )
    distinct_ports = result.scalar_one()
    if distinct_ports < settings.portscan_distinct_ports:
        return None
    return AlertDraft(
        rule_id="R006",
        rule_name="Port scanning",
        title=f"Port scan from {event.source_ip}: {distinct_ports} ports probed",
        description=(
            f"{event.source_ip} contacted {distinct_ports} distinct ports within "
            f"{settings.portscan_window_seconds}s."
        ),
        severity="Medium",
        source_ip=event.source_ip,
        dest_ip=event.dest_ip,
        evidence={"distinct_ports": distinct_ports, "count": distinct_ports,
                  "window_seconds": settings.portscan_window_seconds},
        dedup_key=f"R006:{event.source_ip}",
    )


async def rule_unusual_network(event: Event, db: AsyncSession) -> Optional[AlertDraft]:
    """R007 — Unusual network activity: abnormal connection volume from one source."""
    if (event.event_type or "").lower() not in {"network", "connection", "firewall"}:
        return None
    if not event.source_ip:
        return None
    start = _window_start(event, settings.portscan_window_seconds)
    result = await db.execute(
        select(func.count(Event.id)).where(
            Event.source_ip == event.source_ip,
            Event.timestamp >= start,
        )
    )
    volume = result.scalar_one()
    threshold = 100
    if volume < threshold:
        return None
    return AlertDraft(
        rule_id="R007",
        rule_name="Unusual network activity",
        title=f"High connection volume from {event.source_ip} ({volume} events)",
        description=f"{volume} network events from {event.source_ip} in {settings.portscan_window_seconds}s.",
        severity="Medium",
        source_ip=event.source_ip,
        evidence={"count": volume, "window_seconds": settings.portscan_window_seconds},
        dedup_key=f"R007:{event.source_ip}",
    )


async def rule_sensitive_access(event: Event, db: AsyncSession) -> Optional[AlertDraft]:
    """R008 — Access to sensitive resources."""
    if (event.event_type or "").lower() not in {"access", "file_access", "object_access"}:
        return None
    resource = str(event.raw.get("resource") or event.raw.get("object") or event.message or "").lower()
    matched = [k for k in SENSITIVE_RESOURCE_KEYWORDS if k in resource]
    if not matched:
        return None
    severity = "High" if event.outcome == "success" else "Medium"
    return AlertDraft(
        rule_id="R008",
        rule_name="Sensitive resource access",
        title=f"Sensitive resource access by '{event.username}'",
        description=f"Access ({event.outcome or 'attempt'}) to sensitive resource: {matched}",
        severity=severity,
        source_ip=event.source_ip,
        username=event.username,
        evidence={"matched": matched, "resource": resource[:300], "outcome": event.outcome},
        dedup_key=f"R008:{event.username}:{'|'.join(sorted(matched))}",
    )


# Registry — order matters only for readability; all rules run per event.
ALL_RULES: list[Callable] = [
    rule_bruteforce,
    rule_password_spray,
    rule_success_after_failures,
    rule_privilege_escalation,
    rule_suspicious_powershell,
    rule_port_scan,
    rule_unusual_network,
    rule_sensitive_access,
]
