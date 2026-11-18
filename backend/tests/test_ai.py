"""AI triage tests — advisory only, never a confirmed verdict."""
from app.ai.triage import FALSE_POS, INVESTIGATE, TRUE_POS, analyze_alert, heuristic_triage
from app.models import Alert


def _alert(**kw) -> Alert:
    base = dict(rule_id="R001", rule_name="Brute-force", title="t", description="d",
                severity="High", risk_score=75, source_ip="203.0.113.5",
                username="root", evidence={"count": 25}, event_count=25)
    base.update(kw)
    return Alert(**base)


async def test_triage_returns_hedged_suggestion():
    result = await analyze_alert(_alert())
    assert result["classification"] in {TRUE_POS, FALSE_POS, INVESTIGATE}
    # Never a confirmed verdict.
    assert "confirmed" not in result["classification"].lower()
    assert "disclaimer" in result and result["disclaimer"]


async def test_triage_high_volume_bruteforce_likely_tp():
    result = heuristic_triage(_alert(evidence={"count": 30}))
    assert result["classification"] == TRUE_POS
    assert result["confidence"] >= 0.6


async def test_triage_has_actionable_output():
    result = await analyze_alert(_alert())
    assert result["investigation_steps"]
    assert result["response_actions"]
    # Safety: must warn against automated destructive action.
    joined = " ".join(result["response_actions"]).lower()
    assert "analyst" in joined or "confirmation" in joined


async def test_triage_internal_ip_lowers_confidence():
    external = heuristic_triage(_alert(source_ip="203.0.113.5", evidence={"count": 10}))
    internal = heuristic_triage(_alert(source_ip="10.0.0.5", evidence={"count": 10}))
    assert internal["confidence"] <= external["confidence"]
