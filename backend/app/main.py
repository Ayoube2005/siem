"""FastAPI application entrypoint."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .auth import get_user_from_token
from .config import settings
from .database import AsyncSessionLocal, init_models
from .limiter import limiter
from .routers import alerts, auth, events, stats
from .seed import ensure_first_admin
from .websocket import manager

logging.basicConfig(
    level=logging.INFO,
    format='{"level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
log = logging.getLogger("siem")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_models()
    async with AsyncSessionLocal() as db:
        await ensure_first_admin(db)
    log.info("SIEM backend started (env=%s)", settings.environment)
    yield
    log.info("SIEM backend shutting down")


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(stats.router)


@app.get("/api/health", tags=["health"])
async def health():
    return {"status": "ok", "app": settings.app_name, "ws_clients": manager.count}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time stream of events and alerts. Requires a valid JWT via ?token=."""
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4401)
        return
    async with AsyncSessionLocal() as db:
        user = await get_user_from_token(db, token)
    if not user or not user.is_active:
        await websocket.close(code=4401)
        return

    await manager.connect(websocket)
    try:
        await websocket.send_json({"type": "connected", "data": {"user": user.username}})
        while True:
            # Keep the connection open; ignore/echo client pings.
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception:
        await manager.disconnect(websocket)
