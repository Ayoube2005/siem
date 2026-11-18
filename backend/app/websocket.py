"""In-process WebSocket broadcast manager for real-time dashboard updates."""
import asyncio
import json
from datetime import datetime
from typing import Any

from fastapi import WebSocket


def _json_default(o: Any):
    if isinstance(o, datetime):
        return o.isoformat()
    return str(o)


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)

    async def broadcast(self, message_type: str, payload: Any) -> None:
        """Send a typed message to all connected clients. Dead sockets are dropped."""
        data = json.dumps({"type": message_type, "data": payload}, default=_json_default)
        async with self._lock:
            targets = list(self._connections)
        dead = []
        for ws in targets:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)

    @property
    def count(self) -> int:
        return len(self._connections)


manager = ConnectionManager()
