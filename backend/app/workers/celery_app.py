from celery import Celery
from app.config import settings

celery_app = Celery(
    "auditscan",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.workers.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    # Retry configuration
    task_max_retries=3,
    task_default_retry_delay=30,
    # Result expiry
    result_expires=3600,
)
