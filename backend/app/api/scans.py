from __future__ import annotations

import uuid
import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import Scan, ScanStatus
from app.models.log import ScanLog
from app.models.user import User
from app.core.deps import get_current_user
from app.schemas.scan import ScanCreate, ScanResponse, ScanListResponse, ScanDetailResponse, ScanLogEntry

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# POST /api/scans
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new scan",
)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> ScanResponse:
    # Persist the scan record
    scan = Scan(
        id=uuid.uuid4(),
        target=payload.target,
        status=ScanStatus.pending,
        progress=0,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Fire-and-forget Celery task
    try:
        from app.workers.scan_tasks import run_scan  # avoid circular import at module load
        run_scan.delay(str(scan.id))
        logger.info("Celery task queued for scan %s", scan.id)
    except Exception as exc:
        logger.error("Failed to enqueue task for scan %s: %s", scan.id, exc)
        # Don't fail the HTTP request – the scan record is created;
        # the user can retry or check status later.

    return ScanResponse.model_validate(scan)


# ---------------------------------------------------------------------------
# GET /api/scans
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=ScanListResponse,
    summary="List all scans",
)
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> ScanListResponse:
    total: int = db.query(Scan).count()
    items: List[Scan] = (
        db.query(Scan)
        .order_by(Scan.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return ScanListResponse(
        total=total,
        items=[ScanResponse.model_validate(s) for s in items],
    )


# ---------------------------------------------------------------------------
# GET /api/scans/{scan_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Get a single scan by ID with logs",
)
def get_scan(scan_id: str, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> ScanDetailResponse:
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    scan = db.query(Scan).filter(Scan.id == scan_uuid).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    logs = db.query(ScanLog).filter(ScanLog.scan_id == scan_uuid).order_by(ScanLog.created_at).all()
    result = ScanDetailResponse.model_validate(scan)
    result.logs = [ScanLogEntry.model_validate(l) for l in logs]
    return result


@router.get(
    "/{scan_id}/logs",
    response_model=List[ScanLogEntry],
    summary="Get live logs for a scan",
)
def get_scan_logs(scan_id: str, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> List[ScanLogEntry]:
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    logs = db.query(ScanLog).filter(ScanLog.scan_id == scan_uuid).order_by(ScanLog.created_at).all()
    return [ScanLogEntry.model_validate(l) for l in logs]


# ---------------------------------------------------------------------------
# POST /api/scans/{scan_id}/retry
# ---------------------------------------------------------------------------


@router.post(
    "/{scan_id}/retry",
    response_model=ScanResponse,
    summary="Retry a failed scan",
)
def retry_scan(scan_id: str, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> ScanResponse:
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    scan = db.query(Scan).filter(Scan.id == scan_uuid).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in (ScanStatus.failed, ScanStatus.completed):
        raise HTTPException(status_code=409, detail="Only failed or completed scans can be retried")

    # Reset scan state
    scan.status = ScanStatus.pending
    scan.progress = 0
    scan.risk_score = None
    scan.error_message = None
    scan.shodan_data = None
    scan.virustotal_data = None
    scan.abuseipdb_data = None
    scan.nmap_data = None
    scan.ai_analysis = None
    db.commit()
    db.refresh(scan)

    # Delete old logs so live logs panel is clean
    db.query(ScanLog).filter(ScanLog.scan_id == scan_uuid).delete()
    db.commit()

    try:
        from app.workers.scan_tasks import run_scan
        run_scan.delay(str(scan.id))
        logger.info("Retry task queued for scan %s", scan.id)
    except Exception as exc:
        logger.error("Failed to enqueue retry task for scan %s: %s", scan.id, exc)

    return ScanResponse.model_validate(scan)


# ---------------------------------------------------------------------------
# DELETE /api/scans/{scan_id}
# ---------------------------------------------------------------------------


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Delete a scan",
)
def delete_scan(scan_id: str, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> None:
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    scan = db.query(Scan).filter(Scan.id == scan_uuid).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    db.delete(scan)
    db.commit()
