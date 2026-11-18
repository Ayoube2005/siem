"""End-to-end API tests: ingestion, persistence, alert workflow, stats, AI."""
from .helpers import failed_login, ok_login


async def _ingest(client, headers, events):
    payload = {"events": [e.model_dump(mode="json") for e in events]}
    return await client.post("/api/events/batch", headers=headers, json=payload)


async def test_ingestion_and_persistence(client, auth_headers):
    resp = await _ingest(client, auth_headers, [failed_login("45.33.1.1") for _ in range(5)])
    assert resp.status_code == 201
    assert resp.json()["ingested"] == 5
    # Events are queryable (persisted).
    events = await client.get("/api/events", headers=auth_headers, params={"source_ip": "45.33.1.1"})
    assert events.status_code == 200
    assert len(events.json()) == 5


async def test_alert_created_and_listed(client, auth_headers):
    await _ingest(client, auth_headers, [failed_login("45.33.2.2") for _ in range(6)])
    alerts = await client.get("/api/alerts", headers=auth_headers, params={"rule_id": "R001"})
    assert alerts.status_code == 200
    assert len(alerts.json()) == 1
    alert = alerts.json()[0]
    assert alert["severity"] == "High"
    assert alert["risk_score"] > 0


async def test_ai_triage_attached(client, auth_headers):
    await _ingest(client, auth_headers, [failed_login("45.33.3.3") for _ in range(10)])
    alerts = (await client.get("/api/alerts", headers=auth_headers,
                               params={"rule_id": "R001"})).json()
    alert = alerts[0]
    assert alert["ai_classification"] is not None
    assert 0 <= alert["ai_confidence"] <= 1
    assert "disclaimer" in alert["ai_analysis"]


async def test_analyst_classifies_alert(client, auth_headers):
    await _ingest(client, auth_headers, [failed_login("45.33.4.4") for _ in range(6)])
    alert = (await client.get("/api/alerts", headers=auth_headers)).json()[0]
    aid = alert["id"]
    # AI never confirms — verdict starts unconfirmed.
    assert alert["analyst_verdict"] == "unconfirmed"
    patch = await client.patch(f"/api/alerts/{aid}", headers=auth_headers,
                               json={"status": "investigating",
                                     "analyst_verdict": "true_positive"})
    assert patch.status_code == 200
    assert patch.json()["analyst_verdict"] == "true_positive"
    assert patch.json()["status"] == "investigating"


async def test_stats_overview(client, auth_headers):
    await _ingest(client, auth_headers, [failed_login("45.33.5.5") for _ in range(6)])
    stats = await client.get("/api/stats/overview", headers=auth_headers)
    assert stats.status_code == 200
    body = stats.json()
    assert body["total_events"] >= 6
    assert body["total_alerts"] >= 1


async def test_health(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
