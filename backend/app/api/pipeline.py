"""
Pipeline monitoring API — health checks, queue depths, active scans, phase timings.

Endpoints :
  GET /pipeline/status       → global pipeline status
  GET /pipeline/scans/active → list of currently running scans
  GET /pipeline/scans/{id}/logs → structured logs for a scan
  GET /pipeline/health        → all microservices health
  GET /pipeline/metrics       → performance metrics
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List

import httpx
import redis as sync_redis
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db

logger = logging.getLogger(__name__)
router = APIRouter()

# Microservices to health-check
_SERVICES = {
    "nmap":      f"{settings.NMAP_URL}/health",
    "nuclei":    f"{settings.NUCLEI_URL}/health",
    "zap":       f"{settings.ZAP_URL}/health",
    "subfinder": f"{settings.SUBFINDER_URL}/health",
    "dalfox":    f"{settings.DALFOX_URL}/health",
    "ffuf":      f"{settings.FFUF_URL}/health",
    "sqlmap":    f"{settings.SQLMAP_URL}/health",
    "gitleaks":  f"{settings.GITLEAKS_URL}/health",
    "katana":    f"{settings.KATANA_URL}/health",
}


async def _check_service(name: str, url: str, timeout: float = 3.0) -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
            return {
                "name":    name,
                "status":  "healthy" if resp.status_code == 200 else "degraded",
                "latency_ms": int(resp.elapsed.total_seconds() * 1000),
                "http_status": resp.status_code,
            }
    except httpx.ConnectError:
        return {"name": name, "status": "unreachable", "latency_ms": None}
    except httpx.TimeoutException:
        return {"name": name, "status": "timeout", "latency_ms": None}
    except Exception as exc:
        return {"name": name, "status": "error", "error": str(exc)[:100]}


@router.get("/status")
async def pipeline_status(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Global pipeline status: active scans, queue depths, worker health."""
    from app.models.scan import Scan, ScanStatus

    # Active scans
    try:
        running_scans = (
            db.query(Scan)
            .filter(Scan.status.in_([ScanStatus.running, ScanStatus.pending]))
            .order_by(Scan.created_at.desc())
            .limit(20)
            .all()
        )
        active = [
            {
                "id":       str(s.id),
                "target":   s.target,
                "status":   s.status.value,
                "progress": s.progress,
                "phase":    s.current_phase,
                "started":  s.created_at.isoformat() if s.created_at else None,
            }
            for s in running_scans
        ]
    except Exception:
        active = []

    # Redis queue depths
    queue_depths: Dict[str, int] = {}
    try:
        r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
        for q in ["priority", "default", "slow"]:
            queue_depths[q] = r.llen(q) or 0
        r.close()
    except Exception:
        queue_depths = {"error": "Redis unavailable"}

    # Service health checks (parallel)
    health_results = await asyncio.gather(
        *[_check_service(n, u) for n, u in _SERVICES.items()],
        return_exceptions=True,
    )
    services = {}
    for r in health_results:
        if isinstance(r, dict):
            services[r["name"]] = r
        elif isinstance(r, Exception):
            services["unknown"] = {"status": "error", "error": str(r)}

    healthy_count   = sum(1 for s in services.values() if s.get("status") == "healthy")
    unhealthy_count = len(services) - healthy_count

    return {
        "status":         "healthy" if unhealthy_count == 0 else "degraded",
        "active_scans":   len(active),
        "running_scans":  active,
        "queue_depths":   queue_depths,
        "services":       services,
        "services_ok":    healthy_count,
        "services_down":  unhealthy_count,
    }


@router.get("/scans/active")
async def active_scans(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """List currently running or pending scans with phase info."""
    from app.models.scan import Scan, ScanStatus
    scans = (
        db.query(Scan)
        .filter(Scan.status.in_([ScanStatus.running, ScanStatus.pending]))
        .order_by(Scan.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "id":       str(s.id),
            "target":   s.target,
            "status":   s.status.value,
            "progress": s.progress,
            "phase":    s.current_phase,
            "risk":     s.risk_score,
            "started":  s.created_at.isoformat() if s.created_at else None,
            "updated":  s.updated_at.isoformat() if s.updated_at else None,
        }
        for s in scans
    ]


@router.get("/scans/{scan_id}/logs")
async def scan_pipeline_logs(scan_id: str) -> Dict[str, Any]:
    """Retrieve structured pipeline logs for a scan from Redis."""
    try:
        r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
        raw_logs = r.lrange(f"pipeline:logs:{scan_id}", 0, -1)
        r.close()
        logs = []
        for raw in raw_logs:
            try:
                logs.append(json.loads(raw))
            except json.JSONDecodeError:
                pass
        return {"scan_id": scan_id, "count": len(logs), "logs": logs}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {exc}")


@router.get("/health")
async def services_health() -> Dict[str, Any]:
    """Health check all scanner microservices in parallel."""
    results = await asyncio.gather(
        *[_check_service(n, u, timeout=5.0) for n, u in _SERVICES.items()],
        return_exceptions=True,
    )
    services = {}
    for r in results:
        if isinstance(r, dict):
            services[r["name"]] = r

    all_healthy = all(s.get("status") == "healthy" for s in services.values())
    return {
        "overall":   "healthy" if all_healthy else "degraded",
        "services":  services,
        "total":     len(services),
        "healthy":   sum(1 for s in services.values() if s.get("status") == "healthy"),
        "unhealthy": sum(1 for s in services.values() if s.get("status") != "healthy"),
    }


@router.get("/metrics")
async def pipeline_metrics() -> Dict[str, Any]:
    """Performance metrics from Redis (phase timings, scan counts)."""
    try:
        r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)

        # Phase timing leaderboard (slowest phases)
        phase_times_raw = r.zrevrange("pipeline:phase_times", 0, 19, withscores=True)
        phase_times = [
            {"key": k, "duration_s": round(v, 1)}
            for k, v in phase_times_raw
        ]

        # Recent scan count from last 24h
        # (approximate from Redis keys)
        pipeline_keys = r.keys("pipeline:logs:*")
        recent_scans = len(pipeline_keys)

        r.close()
        return {
            "recent_scans_24h":  recent_scans,
            "slowest_phases":    phase_times[:10],
        }
    except Exception as exc:
        return {"error": f"Metrics unavailable: {exc}"}
