"""
WebSocket endpoint and connection manager.

A single manager instance is shared across the FastAPI app.
The Celery worker broadcasts progress updates via Redis pub/sub;
FastAPI subscribes and forwards to connected browsers.

Authentication: JWT token must be passed as ?token=<jwt> query parameter.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Dict, Set

import redis as sync_redis
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.config import settings
from app.core.security import decode_access_token

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Connection Manager
# ---------------------------------------------------------------------------


class ConnectionManager:
    """Manages active WebSocket connections, keyed by scan_id."""

    def __init__(self) -> None:
        self._connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.setdefault(scan_id, set()).add(websocket)
        logger.info("WS connected: scan_id=%s total=%d", scan_id, len(self._connections[scan_id]))

    def disconnect(self, scan_id: str, websocket: WebSocket) -> None:
        if scan_id in self._connections:
            self._connections[scan_id].discard(websocket)
            if not self._connections[scan_id]:
                del self._connections[scan_id]
        logger.info("WS disconnected: scan_id=%s", scan_id)

    async def broadcast(self, scan_id: str, payload: dict) -> None:
        """Send payload to all clients watching this scan."""
        if scan_id not in self._connections:
            return
        dead: Set[WebSocket] = set()
        for ws in list(self._connections[scan_id]):
            try:
                await ws.send_json(payload)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self._connections[scan_id].discard(ws)


manager = ConnectionManager()


# ---------------------------------------------------------------------------
# Redis subscriber (runs as a background task)
# ---------------------------------------------------------------------------


async def _redis_listener() -> None:
    """
    Subscribe to the 'scan_progress' Redis channel.
    When a message arrives, forward it to the relevant WebSocket clients.
    """
    loop = asyncio.get_running_loop()  # safe in async context (Python 3.10+)
    r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    pubsub.subscribe("scan_progress")
    logger.info("Redis listener subscribed to 'scan_progress' channel")

    try:
        while True:
            try:
                message = await loop.run_in_executor(None, pubsub.get_message, True, 0.1)
                if message and message["type"] == "message":
                    data = json.loads(message["data"])
                    scan_id = data.get("scan_id")
                    if scan_id:
                        await manager.broadcast(scan_id, data)
            except Exception as exc:
                logger.error("Redis listener error: %s", exc)
                await asyncio.sleep(1)
    finally:
        r.close()


# ---------------------------------------------------------------------------
# WebSocket route
# ---------------------------------------------------------------------------


@router.websocket("/ws/{scan_id}")
async def websocket_endpoint(
    scan_id: str,
    websocket: WebSocket,
    token: str = Query(default=""),
) -> None:
    email = decode_access_token(token) if token else None
    if not email:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    await manager.connect(scan_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)
