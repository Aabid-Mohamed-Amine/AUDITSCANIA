"""
PipelineContext — 3-level shared store for scan pipeline steps.

Write path:  in-memory dict  →  Redis (TTL 24h)  →  PostgreSQL
Read path:   memory          →  Redis             →  PostgreSQL

This lets any step read results from any prior step, and survives
Celery task retries (Redis/DB persist across worker restarts).
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

import redis as sync_redis
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

_PREFIX = "pipeline"
_TTL = 86_400  # 24 h


class PipelineContext:
    def __init__(self, scan_id: str, redis_url: str, db: Session) -> None:
        self._scan_id = scan_id
        self._db = db
        self._cache: Dict[str, Any] = {}
        try:
            self._r: sync_redis.Redis = sync_redis.from_url(redis_url, decode_responses=True)
        except Exception as exc:
            logger.warning("PipelineContext: Redis init failed: %s", exc)
            self._r = None  # type: ignore[assignment]

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _rkey(self, step: str) -> str:
        return f"{_PREFIX}:{self._scan_id}:{step}"

    def _pg_get(self, step: str) -> Optional[Dict[str, Any]]:
        from app.models.step_result import ScanStepResult
        try:
            row = (
                self._db.query(ScanStepResult)
                .filter(
                    ScanStepResult.scan_id == uuid.UUID(self._scan_id),
                    ScanStepResult.step == step,
                )
                .first()
            )
            return row.data if row else None
        except Exception as exc:
            logger.warning("PipelineContext PG read failed (step=%s): %s", step, exc)
            return None

    def _pg_save(self, step: str, data: Dict[str, Any]) -> None:
        from app.models.step_result import ScanStepResult
        try:
            row = (
                self._db.query(ScanStepResult)
                .filter(
                    ScanStepResult.scan_id == uuid.UUID(self._scan_id),
                    ScanStepResult.step == step,
                )
                .first()
            )
            now = datetime.utcnow()
            if row:
                row.data = data
                row.updated_at = now
            else:
                self._db.add(
                    ScanStepResult(
                        id=uuid.uuid4(),
                        scan_id=uuid.UUID(self._scan_id),
                        step=step,
                        data=data,
                        created_at=now,
                        updated_at=now,
                    )
                )
            self._db.flush()  # stage within the current transaction; caller commits
        except Exception as exc:
            logger.warning("PipelineContext PG write failed (step=%s): %s", step, exc)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def save_step_result(self, step: str, data: Dict[str, Any]) -> None:
        """Write to memory, Redis, and PostgreSQL."""
        # 1. Memory
        self._cache[step] = data

        # 2. Redis
        if self._r is not None:
            try:
                self._r.setex(self._rkey(step), _TTL, json.dumps(data, default=str))
            except Exception as exc:
                logger.warning("PipelineContext Redis write failed (step=%s): %s", step, exc)

        # 3. PostgreSQL (flushed; committed by _update_scan caller)
        self._pg_save(step, data)

    def get_step_result(self, step: str) -> Optional[Dict[str, Any]]:
        """Read from memory → Redis → PostgreSQL."""
        # 1. Memory
        if step in self._cache:
            return self._cache[step]

        # 2. Redis
        if self._r is not None:
            try:
                raw = self._r.get(self._rkey(step))
                if raw:
                    data = json.loads(raw)
                    self._cache[step] = data
                    return data
            except Exception as exc:
                logger.warning("PipelineContext Redis read failed (step=%s): %s", step, exc)

        # 3. PostgreSQL
        data = self._pg_get(step)
        if data is not None:
            self._cache[step] = data
        return data

    def close(self) -> None:
        if self._r is not None:
            try:
                self._r.close()
            except Exception:
                pass
