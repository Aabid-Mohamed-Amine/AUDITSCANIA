"""
Celery application — configuration multi-queues et workers séparés.

Architecture des queues :
  priority  → scans urgents / retries (traités en premier)
  default   → scans standards
  slow      → scans longs (ZAP alone, Nuclei full coverage)

Workers :
  worker-fast  (concurrency=4) → queues: priority, default
  worker-slow  (concurrency=2) → queues: slow, default

Routing :
  run_scan        → default
  run_scan.retry  → priority  (automatique sur retry)
"""
from celery import Celery
from app.config import settings

celery_app = Celery(
    "auditscan",
    broker  = settings.REDIS_URL,
    backend = settings.REDIS_URL,
    include = ["app.workers.scan_tasks"],
)

celery_app.conf.update(
    # ── Serialization ────────────────────────────────────────────────────────
    task_serializer   = "json",
    result_serializer = "json",
    accept_content    = ["json"],

    # ── Timezone ─────────────────────────────────────────────────────────────
    timezone          = "UTC",
    enable_utc        = True,

    # ── Task behaviour ────────────────────────────────────────────────────────
    task_track_started            = True,
    task_acks_late                = True,
    worker_prefetch_multiplier    = 1,      # one task per worker slot (fair)
    task_reject_on_worker_lost    = True,   # re-queue if worker crashes mid-task

    # ── Timeouts ─────────────────────────────────────────────────────────────
    # Soft limit: task receives SoftTimeLimitExceeded → can clean up
    # Hard limit: SIGKILL after this
    task_soft_time_limit = 3600,  # 60 min soft limit
    task_time_limit      = 3900,  # 65 min hard limit (5 min grace)

    # ── Retry defaults ────────────────────────────────────────────────────────
    task_max_retries          = 3,
    task_default_retry_delay  = 30,

    # ── Result expiry ─────────────────────────────────────────────────────────
    result_expires = 7200,   # 2h — results stored in Redis

    # ── Queues & routing ─────────────────────────────────────────────────────
    task_default_queue = "default",
    task_queues        = {
        "priority": {"exchange": "priority", "routing_key": "priority"},
        "default":  {"exchange": "default",  "routing_key": "default"},
        "slow":     {"exchange": "slow",     "routing_key": "slow"},
    },
    task_routes = {
        "scan_tasks.run_scan": {"queue": "default"},
    },

    # ── Worker events (Flower monitoring) ────────────────────────────────────
    worker_send_task_events  = True,
    task_send_sent_event     = True,

    # ── Broker ────────────────────────────────────────────────────────────────
    broker_connection_retry_on_startup       = True,
    broker_connection_max_retries            = 10,
    broker_transport_options = {
        "visibility_timeout": 4000,  # seconds — re-queue if not acked in this time
    },

    # ── Logging ───────────────────────────────────────────────────────────────
    worker_hijack_root_logger = False,  # don't override our structured logger
    worker_log_color          = False,
)
