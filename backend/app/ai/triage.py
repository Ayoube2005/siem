"""AI-assisted alert triage.

Design principles:
  * Modular & optional — the SIEM runs with no provider/API key. The default
    'heuristic' engine is fully offline and deterministic.
  * Advisory only — output is always a *suggestion* ("Likely ..."), never a
    confirmed verdict. Only a human analyst can confirm TP/FP.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from ..config import settings
from ..models import Alert

DISCLAIMER = (
    "AI assessment is advisory only and may be wrong. It is NOT a confirmed "
    "verdict. An analyst must review the evidence and set the final True/False "
    "Positive classification."
)

# Suggestion labels — deliberately hedged.
TRUE_POS = "Likely True Positive"
FALSE_POS = "Likely False Positive"
INVESTIGATE = "Needs Investigation"


def _is_private(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _base_response(classification: str, confidence: float, explanation: str,
                   evidence: list[str], steps: list[str], actions: list[str],
                   provider: str) -> dict[str, Any]:
    return {
        "classification": classification,
        "confidence": round(max(0.0, min(1.0, confidence)), 2),
        "explanation": explanation,
        "supporting_evidence": evidence,
        "investigation_steps": steps,
        "response_actions": actions,
        "provider": provider,
        "disclaimer": DISCLAIMER,
    }


# --------------------------------------------------------------------------- #
# Heuristic engine (default, offline)
# --------------------------------------------------------------------------- #
def heuristic_triage(alert: Alert) -> dict[str, Any]:
    ev = alert.evidence or {}
    count = int(ev.get("count") or ev.get("distinct_users") or ev.get("prior_failures")
                or ev.get("distinct_ports") or alert.event_count or 0)
    private_src = _is_private(alert.source_ip)

    classification = INVESTIGATE
    confidence = 0.5
    reasons: list[str] = []

    # Rule-specific reasoning.
    if alert.rule_id in {"R001", "R002"}:
        if count >= 20:
            classification, confidence = TRUE_POS, 0.8
            reasons.append(f"High volume ({count}) consistent with automated attack.")
        elif count >= 8:
            classification, confidence = TRUE_POS, 0.65
            reasons.append(f"Sustained failed logins ({count}).")
        else:
            classification, confidence = INVESTIGATE, 0.5
            reasons.append(f"Moderate failed logins ({count}); could be a locked-out user.")
        if private_src:
            confidence -= 0.1
            reasons.append("Source IP is internal/private — possibly a misconfigured service.")

    elif alert.rule_id == "R003":
        classification, confidence = TRUE_POS, 0.85
        reasons.append("Successful login after many failures is a strong takeover signal.")

    elif alert.rule_id == "R004":
        classification, confidence = INVESTIGATE, 0.55
        reasons.append("Privilege escalation is routine for admins but abused by attackers.")
        if private_src:
            reasons.append("Internal host — correlate with change tickets.")

    elif alert.rule_id == "R005":
        inds = ev.get("indicators", [])
        high_risk = any(i in str(inds).lower() for i in ["-enc", "downloadstring", "frombase64string", "iex"])
        if high_risk:
            classification, confidence = TRUE_POS, 0.8
            reasons.append(f"Obfuscation/download indicators present: {inds}.")
        else:
            classification, confidence = INVESTIGATE, 0.55
            reasons.append(f"PowerShell flags of interest: {inds}.")

    elif alert.rule_id == "R006":
        classification, confidence = TRUE_POS, 0.75
        reasons.append(f"{count} distinct ports probed — characteristic of scanning.")
        if private_src:
            confidence -= 0.15
            reasons.append("Internal scanner (vuln scan?) could be benign.")

    elif alert.rule_id == "R007":
        classification, confidence = INVESTIGATE, 0.5
        reasons.append(f"High connection volume ({count}); could be backup/replication.")

    elif alert.rule_id == "R008":
        if ev.get("outcome") == "success":
            classification, confidence = TRUE_POS, 0.7
            reasons.append("Successful access to sensitive resource.")
        else:
            classification, confidence = INVESTIGATE, 0.55
            reasons.append("Attempted access to sensitive resource (denied).")

    # Severity nudges confidence.
    if alert.severity == "Critical":
        confidence += 0.05

    steps = [
        f"Review all events from source IP {alert.source_ip or 'N/A'} around {alert.first_seen}.",
        f"Check whether user '{alert.username or 'N/A'}' activity is expected (HR/on-call status).",
        "Correlate with other alerts sharing this IP or user.",
        "Verify geolocation/ASN of the source IP against known-good baselines.",
    ]
    actions = _recommended_actions(alert, classification)

    reasons.append(f"Risk score {alert.risk_score}/100, severity {alert.severity}.")
    explanation = " ".join(reasons)
    return _base_response(classification, confidence, explanation, reasons, steps, actions, "heuristic")


def _recommended_actions(alert: Alert, classification: str) -> list[str]:
    actions: list[str] = []
    if classification == TRUE_POS:
        if alert.source_ip:
            actions.append(f"Consider blocking source IP {alert.source_ip} at the firewall.")
        if alert.username:
            actions.append(f"Force password reset / disable account '{alert.username}' pending review.")
        actions.append("Preserve relevant logs and open an incident ticket.")
    else:
        actions.append("Gather more context before taking disruptive action.")
        actions.append("Add to watchlist and monitor for escalation.")
    actions.append("Do not take automated destructive action without analyst confirmation.")
    return actions


# --------------------------------------------------------------------------- #
# Optional LLM provider (never required)
# --------------------------------------------------------------------------- #
async def _llm_triage(alert: Alert) -> dict[str, Any] | None:
    """Best-effort call to an external LLM. Returns None on any failure so the
    caller falls back to the heuristic engine."""
    if not settings.ai_api_key:
        return None
    try:
        import httpx  # local import keeps it optional
    except Exception:
        return None

    prompt = _build_prompt(alert)
    try:
        if settings.ai_provider == "anthropic":
            return await _call_anthropic(prompt, alert)
        if settings.ai_provider == "openai":
            return await _call_openai(prompt, alert)
    except Exception:
        return None
    return None


def _build_prompt(alert: Alert) -> str:
    return (
        "You are a SOC analyst assistant. Given this SIEM alert, respond ONLY with "
        "a JSON object with keys: classification (one of 'Likely True Positive', "
        "'Likely False Positive', 'Needs Investigation'), confidence (0-1), "
        "explanation, supporting_evidence (list), investigation_steps (list), "
        "response_actions (list). Never claim a confirmed verdict.\n\n"
        f"Alert: rule={alert.rule_id} {alert.rule_name}; severity={alert.severity}; "
        f"risk={alert.risk_score}; source_ip={alert.source_ip}; user={alert.username}; "
        f"evidence={alert.evidence}"
    )


async def _call_anthropic(prompt: str, alert: Alert) -> dict[str, Any] | None:
    import json
    import httpx

    model = settings.ai_model or "claude-haiku-5-5"
    async with httpx.AsyncClient(timeout=settings.ai_timeout_seconds) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": settings.ai_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 700,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        resp.raise_for_status()
        text = resp.json()["content"][0]["text"]
    return _coerce_llm_json(text, alert, f"anthropic:{model}")


async def _call_openai(prompt: str, alert: Alert) -> dict[str, Any] | None:
    import httpx

    model = settings.ai_model or "gpt-4o-mini"
    async with httpx.AsyncClient(timeout=settings.ai_timeout_seconds) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {settings.ai_api_key}"},
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
            },
        )
        resp.raise_for_status()
        text = resp.json()["choices"][0]["message"]["content"]
    return _coerce_llm_json(text, alert, f"openai:{model}")


def _coerce_llm_json(text: str, alert: Alert, provider: str) -> dict[str, Any] | None:
    import json
    import re

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    allowed = {TRUE_POS, FALSE_POS, INVESTIGATE}
    classification = data.get("classification")
    if classification not in allowed:
        classification = INVESTIGATE
    return _base_response(
        classification,
        float(data.get("confidence", 0.5) or 0.5),
        str(data.get("explanation", "")),
        list(data.get("supporting_evidence", [])),
        list(data.get("investigation_steps", [])),
        list(data.get("response_actions", [])),
        provider,
    )


# --------------------------------------------------------------------------- #
# Public entrypoint
# --------------------------------------------------------------------------- #
async def analyze_alert(alert: Alert) -> dict[str, Any]:
    """Return an advisory triage assessment for an alert.

    Always succeeds: falls back to the offline heuristic engine when no provider
    is configured or the external call fails.
    """
    if not settings.ai_enabled:
        return _base_response(
            INVESTIGATE, 0.0, "AI triage disabled by configuration.",
            [], ["Enable AI triage in configuration for automated suggestions."],
            ["Analyst review required."], "disabled",
        )
    if settings.ai_provider in {"anthropic", "openai"}:
        llm = await _llm_triage(alert)
        if llm is not None:
            return llm
        # fall through to heuristic on failure
    return heuristic_triage(alert)
