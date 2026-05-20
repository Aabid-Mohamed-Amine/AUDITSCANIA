"""
Celery scan task.

Pipeline:
  1. Shodan      → 25%
  2. VirusTotal  → 50%
  3. AbuseIPDB   → 75%
  4. Nmap        → 90%
  5. Risk score  → 100%

Progress is persisted to PostgreSQL and broadcast via Redis pub/sub.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

import redis as sync_redis
from sqlalchemy.exc import OperationalError as SAOperationalError

from app.workers.celery_app import celery_app
from app.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _get_db_session():
    from app.database import SessionLocal
    return SessionLocal()


def _add_log(db, scan_id: str, message: str, level: str = "info") -> None:
    """Stage a log entry — committed atomically with the next _update_scan."""
    from app.models.log import ScanLog
    log = ScanLog(
        id=uuid.uuid4(),
        scan_id=uuid.UUID(scan_id),
        level=level,
        message=message,
        created_at=datetime.utcnow(),
    )
    db.add(log)
    db.flush()  # visible to current transaction; committed by next _update_scan


def _update_scan(db, scan, **kwargs) -> None:
    for key, value in kwargs.items():
        setattr(scan, key, value)
    scan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)


# ---------------------------------------------------------------------------
# Redis helper
# ---------------------------------------------------------------------------


def _publish(r: sync_redis.Redis, scan_id: str, status: str, progress: int, message: str, data: Optional[Dict[str, Any]] = None) -> None:
    payload = {
        "scan_id": scan_id,
        "status": status,
        "progress": progress,
        "message": message,
        "data": data or {},
        "timestamp": datetime.utcnow().isoformat(),
    }
    r.publish("scan_progress", json.dumps(payload))


# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------


def _compute_risk_score(
    shodan_data: dict,
    virustotal_data: dict,
    abuseipdb_data: dict,
    nmap_data: dict,
) -> int:
    """
    Risk score 0-100 from weighted signals:
    - AbuseIPDB confidence score : 40%
    - VirusTotal malicious ratio  : 30%
    - Port exposure (open ports)  : 20%
    - Known risky ports           : 10%
    """
    score = 0.0

    # AbuseIPDB (0-100) → 40%
    abuse_score = 0.0
    if abuseipdb_data and not abuseipdb_data.get("error"):
        abuse_score = float(abuseipdb_data.get("data", {}).get("abuse_confidence_score", 0))
    score += abuse_score * 0.40

    # VirusTotal: malicious / total vendors → 30%
    vt_score = 0.0
    if virustotal_data and not virustotal_data.get("error"):
        vt_data = virustotal_data.get("data", {})
        malicious = vt_data.get("malicious", 0)
        total = (
            vt_data.get("malicious", 0) + vt_data.get("suspicious", 0)
            + vt_data.get("harmless", 0) + vt_data.get("undetected", 0)
        )
        if not total:
            domain_s = vt_data.get("domain", {})
            url_s = vt_data.get("url", {})
            malicious = max(domain_s.get("malicious", 0), url_s.get("malicious", 0))
            domain_total = (
                domain_s.get("malicious", 0) + domain_s.get("suspicious", 0)
                + domain_s.get("harmless", 0) + domain_s.get("undetected", 0)
            )
            url_total = (
                url_s.get("malicious", 0) + url_s.get("suspicious", 0)
                + url_s.get("harmless", 0) + url_s.get("undetected", 0)
            )
            total = max(domain_total, url_total)
        if total > 0:
            vt_score = (malicious / total) * 100
    score += vt_score * 0.30

    # Port exposure → 20%
    risky_ports = {21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 5432, 6379, 27017}
    port_count = 0
    risky_found = 0
    if nmap_data and not nmap_data.get("error"):
        hosts = nmap_data.get("data", {}).get("hosts", [])
        all_ports = [p for host in hosts for p in host.get("ports", [])]
        port_count = len([p for p in all_ports if p.get("state") == "open"])
        risky_found = sum(
            1 for p in all_ports
            if p.get("port") in risky_ports and p.get("state") == "open"
        )
    score += min(port_count * 5, 100) * 0.20
    score += min(risky_found * 15, 100) * 0.10

    return min(int(score), 100)


# ---------------------------------------------------------------------------
# Celery task
# ---------------------------------------------------------------------------


@celery_app.task(
    bind=True,
    name="scan_tasks.run_scan",
    max_retries=2,
    default_retry_delay=10,
)
def run_scan(self, scan_id: str) -> Dict[str, Any]:
    from app.models.scan import Scan, ScanStatus
    from app.models.recon_result import ReconnaissanceResult

    db = _get_db_session()
    r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
    # Single event loop reused across all async service calls (QUAL-02)
    loop = asyncio.new_event_loop()

    scan = None
    try:
        scan = db.query(Scan).filter(Scan.id == uuid.UUID(scan_id)).first()
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return {"error": "scan not found"}

        target = scan.target

        # 0. Start
        _update_scan(db, scan, status=ScanStatus.running, progress=0)
        _publish(r, scan_id, "running", 0, "Scan started")
        _add_log(db, scan_id, f"Scan started for target: {target}")

        # 1. Shodan 0→25%
        _publish(r, scan_id, "running", 5, "Starting Shodan passive recon...")
        _add_log(db, scan_id, "Starting Shodan passive recon...")
        shodan_result: dict = {}
        try:
            from app.services.shodan_service import query_shodan
            shodan_result = loop.run_until_complete(query_shodan(target))
            _add_log(db, scan_id, f"Shodan: found {len(shodan_result.get('ports', []))} ports")
        except Exception as exc:
            shodan_result = {"error": str(exc)}
            _add_log(db, scan_id, f"Shodan error: {exc}", level="error")
            logger.exception("Shodan failed for %s", target)

        _update_scan(db, scan, shodan_data=shodan_result, progress=25)
        _publish(r, scan_id, "running", 25, "Shodan recon complete", {"shodan": shodan_result})

        # 2. VirusTotal 25→50%
        _publish(r, scan_id, "running", 30, "Starting VirusTotal analysis...")
        _add_log(db, scan_id, "Starting VirusTotal analysis...")
        vt_result: dict = {}
        try:
            from app.services.virustotal_service import query_virustotal
            vt_result = loop.run_until_complete(query_virustotal(target))
            malicious = vt_result.get("last_analysis_stats", {}).get("malicious", 0)
            _add_log(
                db, scan_id,
                f"VirusTotal: {malicious} malicious detections",
                level="warning" if malicious > 0 else "info",
            )
        except Exception as exc:
            vt_result = {"error": str(exc)}
            _add_log(db, scan_id, f"VirusTotal error: {exc}", level="error")
            logger.exception("VirusTotal failed for %s", target)

        _update_scan(db, scan, virustotal_data=vt_result, progress=50)
        _publish(r, scan_id, "running", 50, "VirusTotal analysis complete", {"virustotal": vt_result})

        # 3. AbuseIPDB 50→75%
        _publish(r, scan_id, "running", 55, "Starting AbuseIPDB check...")
        _add_log(db, scan_id, "Starting AbuseIPDB check...")
        abuse_result: dict = {}
        try:
            from app.services.abuseipdb_service import query_abuseipdb
            abuse_result = loop.run_until_complete(query_abuseipdb(target))
            conf = abuse_result.get("data", {}).get("abuse_confidence_score", 0)
            level = "error" if conf > 60 else "warning" if conf > 20 else "info"
            _add_log(db, scan_id, f"AbuseIPDB: confidence score {conf}%", level=level)
        except Exception as exc:
            abuse_result = {"error": str(exc)}
            _add_log(db, scan_id, f"AbuseIPDB error: {exc}", level="error")
            logger.exception("AbuseIPDB failed for %s", target)

        _update_scan(db, scan, abuseipdb_data=abuse_result, progress=75)
        _publish(r, scan_id, "running", 75, "AbuseIPDB check complete", {"abuseipdb": abuse_result})

        # 4. Nmap 75→90%
        _publish(r, scan_id, "running", 78, "Launching Nmap active scan...")
        _add_log(db, scan_id, "Launching Nmap active scan via Docker container...")
        nmap_result: dict = {}
        try:
            from app.services.nmap_service import run_nmap_scan
            nmap_result = loop.run_until_complete(run_nmap_scan(target))
            hosts = nmap_result.get("data", {}).get("hosts", [])
            all_ports = [p for h in hosts for p in h.get("ports", [])]
            open_ports = [p for p in all_ports if p.get("state") == "open"]
            _add_log(db, scan_id, f"Nmap: {len(open_ports)} open ports discovered")
            for p in open_ports[:10]:
                _add_log(db, scan_id, f"  Port {p.get('port')}/{p.get('protocol')} - {p.get('service', 'unknown')} {p.get('version', '')}")
        except Exception as exc:
            nmap_result = {"error": str(exc)}
            _add_log(db, scan_id, f"Nmap error: {exc}", level="error")
            logger.exception("Nmap failed for %s", target)

        _update_scan(db, scan, nmap_data=nmap_result, progress=90)
        _publish(r, scan_id, "running", 90, "Nmap scan complete", {"nmap": nmap_result})

        # 5. Risk score + ReconResult
        risk_score = _compute_risk_score(shodan_result, vt_result, abuse_result, nmap_result)
        _add_log(
            db, scan_id,
            f"Risk score computed: {risk_score}/100",
            level="warning" if risk_score > 50 else "info",
        )

        recon = ReconnaissanceResult(
            id=uuid.uuid4(),
            scan_id=uuid.UUID(scan_id),
            shodan_data=shodan_result,
            virustotal_data=vt_result,
            abuseipdb_data=abuse_result,
            nmap_data=nmap_result,
            risk_score=risk_score,
            abuseipdb_score=float(abuse_result.get("data", {}).get("abuse_confidence_score", 0)),
            virustotal_score=float(
                vt_result.get("data", {}).get("malicious", 0)
                or max(
                    vt_result.get("data", {}).get("domain", {}).get("malicious", 0),
                    vt_result.get("data", {}).get("url", {}).get("malicious", 0),
                )
            ),
        )
        db.add(recon)

        _update_scan(db, scan, status=ScanStatus.completed, progress=100, risk_score=risk_score)
        _publish(r, scan_id, "completed", 100, f"Scan completed — Risk score: {risk_score}/100", {
            "shodan": shodan_result,
            "virustotal": vt_result,
            "abuseipdb": abuse_result,
            "nmap": nmap_result,
            "risk_score": risk_score,
        })
        _add_log(db, scan_id, "Scan completed successfully")
        logger.info("Scan %s completed (risk=%d) for %s", scan_id, risk_score, target)
        return {"scan_id": scan_id, "status": "completed", "risk_score": risk_score}

    except Exception as exc:
        logger.exception("Unhandled error in run_scan for %s", scan_id)
        try:
            if scan is not None:
                _update_scan(db, scan, status=ScanStatus.failed, error_message=str(exc))
                _publish(r, scan_id, "failed", scan.progress, f"Scan failed: {exc}")
                _add_log(db, scan_id, f"Scan failed: {exc}", level="error")
        except Exception:
            pass

        # Only retry on transient infrastructure failures (SEC-02)
        if isinstance(exc, (sync_redis.ConnectionError, sync_redis.TimeoutError, SAOperationalError)):
            raise self.retry(exc=exc)
        raise

    finally:
        loop.close()
        r.close()
        db.close()
