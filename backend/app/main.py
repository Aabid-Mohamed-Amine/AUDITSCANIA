"""
AuditScan IA – FastAPI application entry point.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.core.limiter import limiter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lifespan (startup / shutdown)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ---------- Startup ----------
    logger.info("Starting AuditScan IA backend…")

    # Start the Redis → WebSocket listener as a background task
    from app.api.websocket import _redis_listener
    listener_task = asyncio.create_task(_redis_listener())
    logger.info("Redis pub/sub listener started")

    yield  # ← application runs here

    # ---------- Shutdown ----------
    listener_task.cancel()
    try:
        await listener_task
    except asyncio.CancelledError:
        pass
    logger.info("AuditScan IA backend stopped")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


app = FastAPI(
    title="AuditScan IA",
    description="SaaS security audit platform – passive & active recon pipeline",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---- CORS ----
_cors_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# ---- Global exception handler (ensures CORS headers on 500) ----
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )

# ---- Routes ----
from app.api.router import api_router  # noqa: E402
app.include_router(api_router, prefix="/api")


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@app.get("/health", tags=["health"])
async def health_check() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "auditscan-backend"})


@app.get("/", tags=["root"])
async def root() -> JSONResponse:
    return JSONResponse({"message": "AuditScan IA API", "docs": "/docs"})
