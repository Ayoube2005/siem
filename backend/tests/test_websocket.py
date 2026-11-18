"""Real-time broadcast tests using the ConnectionManager directly."""
import json

from app.ingest import ingest_events
from app.websocket import ConnectionManager, manager
from .helpers import failed_login


class FakeWS:
    def __init__(self):
        self.sent = []
        self.accepted = False

    async def accept(self):
        self.accepted = True

    async def send_text(self, data):
        self.sent.append(json.loads(data))


async def test_manager_broadcasts_to_clients():
    mgr = ConnectionManager()
    ws = FakeWS()
    await mgr.connect(ws)
    assert ws.accepted
    await mgr.broadcast("event", {"id": 1})
    assert ws.sent[-1]["type"] == "event"
    assert ws.sent[-1]["data"]["id"] == 1


async def test_dead_socket_is_dropped():
    mgr = ConnectionManager()

    class Dead(FakeWS):
        async def send_text(self, data):
            raise RuntimeError("closed")

    dead = Dead()
    await mgr.connect(dead)
    await mgr.broadcast("event", {"x": 1})
    assert mgr.count == 0


async def test_ingest_pushes_realtime_updates(session):
    """Alerts/events reach a connected client in real time during ingestion."""
    ws = FakeWS()
    await manager.connect(ws)
    try:
        await ingest_events(session, [failed_login("198.51.100.42") for _ in range(5)],
                            broadcast=True)
    finally:
        await manager.disconnect(ws)
    types = [m["type"] for m in ws.sent]
    assert "event" in types
    assert "alert" in types  # brute-force alert pushed live
