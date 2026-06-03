"""
PipelineLogger — structured JSON logging for scan pipeline.

Émet des événements structurés avec :
  - scan_id, phase, tool, severity
  - duration_ms, findings_count
  - Redis pub/sub channel: pipeline_logs
  - Enrichit les logs Celery avec le contexte scan
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

import redis as sync_redis

_LEVEL_MAP = {"debug": 10, "info": 20, "warning": 30, "error": 40, "critical": 50}


class PipelineLogger:
    """
    Structured logger that writes JSON events to:
      1. Python logging (standard Celery log)
      2. Redis pub/sub channel `pipeline_logs` (real-time monitoring)
      3. Redis list `pipeline:logs:{scan_id}` (queryable history, TTL 24h)
    """

    def __init__(
        self,
        scan_id:      str,
        redis_client: Optional[sync_redis.Redis] = None,
    ) -> None:
        self.scan_id = scan_id
        self._redis  = redis_client
        self._logger = logging.getLogger(f"pipeline.{scan_id[:8]}")
        self._phase  = "init"
        self._phase_start = time.monotonic()

    def set_phase(self, phase: str) -> None:
        self._phase       = phase
        self._phase_start = time.monotonic()

    def _emit(
        self,
        level:    str,
        message:  str,
        tool:     Optional[str]       = None,
        findings: Optional[int]       = None,
        extra:    Optional[Dict]      = None,
    ) -> None:
        duration_ms = int((time.monotonic() - self._phase_start) * 1000)
        event: Dict[str, Any] = {
            "scan_id":     self.scan_id,
            "phase":       self._phase,
            "level":       level,
            "message":     message,
            "duration_ms": duration_ms,
        }
        if tool:
            event["tool"] = tool
        if findings is not None:
            event["findings_count"] = findings
        if extra:
            event.update(extra)

        # 1. Standard Python logging
        py_level = _LEVEL_MAP.get(level, 20)
        self._logger.log(py_level, "[%s|%s] %s", self._phase, tool or "", message)

        # 2. Redis pub/sub (real-time)
        if self._redis:
            try:
                serialized = json.dumps(event, default=str)
                self._redis.publish("pipeline_logs", serialized)
                # 3. Redis list (queryable history)
                key = f"pipeline:logs:{self.scan_id}"
                self._redis.rpush(key, serialized)
                self._redis.expire(key, 86400)
                # Keep only last 500 entries
                self._redis.ltrim(key, -500, -1)
            except Exception:
                pass

    # ── Public logging methods ────────────────────────────────────────────────

    def info(self, message: str, tool: str = "", findings: Optional[int] = None, **kw) -> None:
        self._emit("info", message, tool or None, findings, kw or None)

    def warning(self, message: str, tool: str = "", findings: Optional[int] = None, **kw) -> None:
        self._emit("warning", message, tool or None, findings, kw or None)

    def error(self, message: str, tool: str = "", **kw) -> None:
        self._emit("error", message, tool or None, None, kw or None)

    def tool_result(
        self,
        tool:        str,
        findings:    int,
        severity:    Optional[str]        = None,
        critical:    int = 0,
        high:        int = 0,
        extra:       Optional[Dict] = None,
    ) -> None:
        """Log a tool completion event with finding counts."""
        msg = f"{tool}: {findings} findings"
        if critical or high:
            msg += f" (critical={critical} high={high})"
        extra_data = {"severity": severity} if severity else {}
        if extra:
            extra_data.update(extra)
        self._emit(
            "warning" if (critical + high) > 0 else "info",
            msg, tool, findings, extra_data or None,
        )

    def phase_summary(
        self,
        phase:    str,
        tools:    List[str],
        total:    int,
        duration: float,
    ) -> None:
        self._emit("info", f"Phase complete: {total} total findings", extra={
            "tools": tools, "total_findings": total, "phase_duration_s": round(duration, 1),
        })


# ── Factory ────────────────────────────────────────────────────────────────────


def make_pipeline_logger(
    scan_id: str,
    redis_url: Optional[str] = None,
) -> PipelineLogger:
    redis_client = None
    if redis_url:
        try:
            redis_client = sync_redis.from_url(redis_url, decode_responses=True)
        except Exception:
            pass
    return PipelineLogger(scan_id, redis_client)
