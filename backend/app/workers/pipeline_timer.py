"""
PipelineTimer — gestion des timeouts et du budget temps du pipeline.

Usage:
    timer = PipelineTimer(total_budget=3000)
    with timer.phase("asset_discovery"):
        ...  # timed block

    # Ajuste les timeouts des outils dynamiquement
    zap_timeout = timer.tool_timeout("zap", default=900, min_val=120)

    # Vérifie s'il reste assez de budget
    if timer.has_budget(min_seconds=60):
        ...
"""
from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional

import redis as sync_redis

logger = logging.getLogger(__name__)


class PipelineTimer:
    """
    Manages the time budget for a scan pipeline.

    - Tracks start time and deadline
    - Records phase durations
    - Provides dynamic timeout calculation for each tool
    - Publishes timing metrics to Redis for monitoring
    """

    def __init__(
        self,
        scan_id:       str,
        total_budget:  int = 3000,    # seconds total budget
        redis_client:  Optional[sync_redis.Redis] = None,
    ) -> None:
        self.scan_id      = scan_id
        self.total_budget = total_budget
        self._start       = time.monotonic()
        self._deadline    = self._start + total_budget
        self._phases:     List[Dict[str, Any]] = []
        self._current:    Optional[str] = None
        self._phase_start: float = 0.0
        self._redis       = redis_client

    # ── Time helpers ─────────────────────────────────────────────────────────

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start

    @property
    def remaining(self) -> float:
        return max(0.0, self._deadline - time.monotonic())

    @property
    def elapsed_pct(self) -> float:
        return min(100.0, (self.elapsed / self.total_budget) * 100)

    def has_budget(self, min_seconds: float = 30.0) -> bool:
        return self.remaining >= min_seconds

    # ── Phase tracking ────────────────────────────────────────────────────────

    def start_phase(self, name: str) -> None:
        if self._current:
            self._end_phase()
        self._current    = name
        self._phase_start = time.monotonic()
        logger.info(
            "[%s] Phase START: %s | elapsed=%.0fs remaining=%.0fs",
            self.scan_id[:8], name, self.elapsed, self.remaining,
        )

    def _end_phase(self) -> None:
        if not self._current:
            return
        duration = time.monotonic() - self._phase_start
        entry = {
            "phase":    self._current,
            "duration": round(duration, 1),
            "elapsed":  round(self.elapsed, 1),
        }
        self._phases.append(entry)
        logger.info(
            "[%s] Phase END:   %s | duration=%.0fs elapsed=%.0fs",
            self.scan_id[:8], self._current, duration, self.elapsed,
        )
        self._publish_metric("phase_complete", entry)
        self._current = None

    def end_phase(self, name: Optional[str] = None) -> None:
        if name and name != self._current:
            logger.warning("end_phase(%s) called but current is %s", name, self._current)
        self._end_phase()

    @contextmanager
    def phase(self, name: str) -> Generator[None, None, None]:
        self.start_phase(name)
        try:
            yield
        finally:
            self._end_phase()

    # ── Dynamic timeout calculation ───────────────────────────────────────────

    def tool_timeout(
        self,
        tool_name: str,
        default:   int,
        min_val:   int = 30,
        fraction:  float = 0.8,
    ) -> int:
        """
        Calculate a safe timeout for a tool given the remaining budget.

        Args:
            tool_name: name for logging
            default:   ideal timeout if budget allows
            min_val:   minimum acceptable timeout (below this = skip the tool)
            fraction:  max fraction of remaining budget to use for this tool

        Returns the timeout to use. Call has_budget(min_val) first to decide
        whether to run the tool at all.
        """
        remaining      = self.remaining
        budget_share   = int(remaining * fraction)
        timeout        = min(default, budget_share)
        timeout        = max(timeout, min_val)

        if timeout < default:
            logger.warning(
                "[%s] Tool %s: reduced timeout %ds→%ds (remaining=%.0fs)",
                self.scan_id[:8], tool_name, default, timeout, remaining,
            )
        return timeout

    # ── Phase report ─────────────────────────────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        if self._current:
            self._end_phase()
        slowest = sorted(self._phases, key=lambda p: p["duration"], reverse=True)
        return {
            "scan_id":          self.scan_id,
            "total_elapsed":    round(self.elapsed, 1),
            "total_budget":     self.total_budget,
            "budget_used_pct":  round(self.elapsed_pct, 1),
            "phases":           self._phases,
            "slowest_phase":    slowest[0]["phase"] if slowest else None,
            "slowest_duration": slowest[0]["duration"] if slowest else 0,
        }

    # ── Metrics emission ──────────────────────────────────────────────────────

    def _publish_metric(self, event: str, data: Dict[str, Any]) -> None:
        if not self._redis:
            return
        import json
        try:
            payload = {"event": event, "scan_id": self.scan_id, **data}
            self._redis.publish("pipeline_metrics", json.dumps(payload))
            # Store timing in Redis sorted set for monitoring dashboard
            self._redis.zadd(
                "pipeline:phase_times",
                {f"{self.scan_id}:{data.get('phase', '?')}": data.get("duration", 0)},
            )
            self._redis.expire("pipeline:phase_times", 86400)
        except Exception:
            pass
