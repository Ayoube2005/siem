"""Detection engine rule tests + deduplication."""
from sqlalchemy import func, select

from app.ingest import ingest_events
from app.models import Alert
from .helpers import ev, failed_login, ok_login


async def _count_alerts(session, rule_id=None):
    stmt = select(func.count(Alert.id))
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
    return (await session.execute(stmt)).scalar_one()


async def test_bruteforce_creates_alert(session):
    events = [failed_login("198.51.100.7") for _ in range(5)]
    res = await ingest_events(session, events, broadcast=False)
    assert res["alerts_created"] >= 1
    assert await _count_alerts(session, "R001") == 1


async def test_bruteforce_dedup_no_duplicate(session):
    await ingest_events(session, [failed_login("198.51.100.8") for _ in range(5)], broadcast=False)
    # More failures from the same IP must NOT create a second R001 alert.
    await ingest_events(session, [failed_login("198.51.100.8") for _ in range(5)], broadcast=False)
    assert await _count_alerts(session, "R001") == 1
    alert = (await session.execute(select(Alert).where(Alert.rule_id == "R001"))).scalar_one()
    assert alert.event_count > 1  # subsequent hits folded in


async def test_password_spray(session):
    events = [failed_login("203.0.113.9", user=u) for u in
              ["a", "b", "c", "d", "e", "f"]]
    await ingest_events(session, events, broadcast=False)
    assert await _count_alerts(session, "R002") == 1


async def test_success_after_failures_is_critical(session):
    events = [failed_login("203.0.113.10") for _ in range(5)] + [ok_login("203.0.113.10")]
    await ingest_events(session, events, broadcast=False)
    alert = (await session.execute(select(Alert).where(Alert.rule_id == "R003"))).scalar_one()
    assert alert.severity == "Critical"


async def test_port_scan(session):
    events = [ev(source="firewall", event_type="network", action="connect",
                 outcome="failure", source_ip="203.0.113.11", dest_ip="10.0.0.5",
                 dest_port=p) for p in range(20, 40)]
    await ingest_events(session, events, broadcast=False)
    assert await _count_alerts(session, "R006") == 1


async def test_suspicious_powershell(session):
    e = ev(source="windows", event_type="process", action="process_creation",
           outcome="success", hostname="WIN-1", username="jdoe",
           message="powershell -enc ABC",
           raw={"command_line": "powershell.exe -nop -enc ABCDEF DownloadString"})
    await ingest_events(session, [e], broadcast=False)
    assert await _count_alerts(session, "R005") == 1


async def test_sensitive_resource(session):
    e = ev(source="linux", event_type="access", action="read", outcome="success",
           username="www-data", message="read /etc/shadow", raw={"resource": "/etc/shadow"})
    await ingest_events(session, [e], broadcast=False)
    assert await _count_alerts(session, "R008") == 1


async def test_benign_events_no_alert(session):
    events = [ok_login(f"10.0.0.{i}", user=f"user{i}") for i in range(2, 8)]
    res = await ingest_events(session, events, broadcast=False)
    assert res["alerts_created"] == 0
