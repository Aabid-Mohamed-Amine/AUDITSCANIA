"""
Celery scan task — PipelineContext-aware pipeline.

Step order (context flows downward):
  1. Shodan      →  12%   passive recon (initial target)
  2. ZAP         →  30%   web spider — discovers endpoints & implicit ports
  3. Nmap        →  52%   active scan, reads ZAP ports; builds structured summary
  4. VirusTotal  →  65%   initial target + Nmap-discovered IPs
  5. AbuseIPDB   →  75%   initial target + Nmap-discovered IPs
  6. Nuclei      →  90%   CVE scan, templates derived from Nmap services
  7. Risk score  → 100%   weighted aggregate read from PipelineContext
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
import redis as sync_redis
from sqlalchemy.exc import OperationalError as SAOperationalError

from app.workers.celery_app import celery_app
from app.workers.pipeline_context import PipelineContext
from app.config import settings


# ---------------------------------------------------------------------------
# Scanner microservice callers (nmap / nuclei / zap)
# ---------------------------------------------------------------------------


async def _call_nmap(target: str, additional_ports: Optional[List[int]] = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"target": target}
    if additional_ports:
        payload["additional_ports"] = additional_ports
    default = {"target": target, "error": None, "data": {}, "summary": {}, "additional_ports_from_zap": additional_ports or []}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(360.0)) as client:
            resp = await client.post(f"{settings.NMAP_URL}/scan", json=payload)
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "Nmap service unavailable (container not running?)"
    except httpx.TimeoutException:
        default["error"] = "Nmap service HTTP request timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_zap(target: str) -> Dict[str, Any]:
    default = {"target": target, "error": None, "alerts": [], "total": 0, "by_risk": {}, "endpoints": [], "form_params": [], "abnormal_headers": [], "implicit_ports": []}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(960.0)) as client:
            resp = await client.post(f"{settings.ZAP_URL}/scan", json={"target": target, "spider_minutes": 2, "timeout": 900})
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "ZAP service unavailable (container not running?)"
    except httpx.TimeoutException:
        default["error"] = "ZAP service HTTP request timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_nuclei(
    target: str,
    templates: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"target": target, "timeout": 600}
    if templates:
        payload["templates"] = templates
    if tags:
        payload["tags"] = tags
    default = {"target": target, "error": None, "findings": [], "total": 0, "by_severity": {}, "max_cvss": None, "templates_used": templates or [], "tags_used": tags or []}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(660.0)) as client:
            resp = await client.post(f"{settings.NUCLEI_URL}/scan", json=payload)
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "Nuclei service unavailable (container not running?)"
    except httpx.TimeoutException:
        default["error"] = "Nuclei service HTTP request timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _get_db_session():
    from app.database import SessionLocal
    return SessionLocal()


def _add_log(db, scan_id: str, message: str, level: str = "info") -> None:
    from app.models.log import ScanLog
    log = ScanLog(
        id=uuid.uuid4(),
        scan_id=uuid.UUID(scan_id),
        level=level,
        message=message,
        created_at=datetime.utcnow(),
    )
    db.add(log)
    db.flush()


def _update_scan(db, scan, **kwargs) -> None:
    for key, value in kwargs.items():
        setattr(scan, key, value)
    scan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)


# ---------------------------------------------------------------------------
# Redis publish helper
# ---------------------------------------------------------------------------


def _publish(
    r: sync_redis.Redis,
    scan_id: str,
    status: str,
    progress: int,
    message: str,
    data: Optional[Dict[str, Any]] = None,
) -> None:
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
# Pipeline helpers
# ---------------------------------------------------------------------------


def _extract_discovered_ips(nmap_result: Dict[str, Any], initial_target: str) -> List[str]:
    """Return IPv4 addresses discovered by Nmap that differ from the initial target."""
    ips: set = set()
    hosts = nmap_result.get("data", {}).get("hosts", [])
    for host in hosts:
        for addr in host.get("addresses", []):
            ip = addr.get("addr", "")
            if addr.get("addrtype") == "ipv4" and ip and ip != initial_target:
                ips.add(ip)
    return list(ips)


def _extract_ports_from_zap(zap_result: Dict[str, Any]) -> List[int]:
    """Return non-standard ports embedded in ZAP-discovered endpoint URLs."""
    return zap_result.get("implicit_ports", [])


# ---------------------------------------------------------------------------
# Nuclei context builder (Nmap services → tags + template IDs)
# ---------------------------------------------------------------------------

# service name → Nuclei tags
_SVC_TAGS: Dict[str, List[str]] = {
    "http":     ["http", "exposures", "misconfiguration"],
    "https":    ["http", "ssl"],
    "ftp":      ["ftp", "network", "default-logins"],
    "ssh":      ["ssh", "network"],
    "smtp":     ["smtp", "network"],
    "smb":      ["smb", "network"],
    "mysql":    ["mysql", "network", "default-logins"],
    "postgres": ["postgresql", "network"],
    "redis":    ["redis", "network"],
    "mongodb":  ["mongodb", "network"],
    "rdp":      ["rdp", "network"],
    "telnet":   ["telnet", "network", "default-logins"],
    "vnc":      ["vnc", "network"],
    "ldap":     ["ldap", "network"],
    "elastic":  ["elasticsearch", "network"],
}

# product keyword → (extra_tags, template_ids)
_PRODUCT_MAP: Dict[str, tuple] = {
    "apache":       (["apache"], []),
    "nginx":        (["nginx"], []),
    "iis":          (["iis", "microsoft"], []),
    "jenkins":      (["jenkins"], ["CVE-2019-1003000", "CVE-2018-1000861"]),
    "wordpress":    (["wordpress"], []),
    "jboss":        (["jboss"], ["CVE-2017-12149"]),
    "tomcat":       (["apache", "tomcat"], ["CVE-2020-1938", "CVE-2019-0232"]),
    "weblogic":     (["oracle", "weblogic"], ["CVE-2020-14882", "CVE-2019-2725"]),
    "drupal":       (["drupal"], ["CVE-2018-7600", "CVE-2019-6340"]),
    "exchange":     (["microsoft", "exchange"], ["CVE-2021-34473", "CVE-2021-26855"]),
    "spring":       (["spring", "springboot"], ["CVE-2022-22965", "CVE-2022-22950"]),
    "log4j":        (["log4j"], ["CVE-2021-44228", "CVE-2021-45046"]),
    "laravel":      (["laravel", "php"], ["CVE-2021-3129"]),
    "grafana":      (["grafana"], ["CVE-2021-43798"]),
    "gitlab":       (["gitlab"], ["CVE-2021-22205", "CVE-2022-2884"]),
    "kibana":       (["kibana", "elasticsearch"], []),
    "redis":        (["redis"], ["redis-unauthenticated-access"]),
    "mongodb":      (["mongodb"], ["mongodb-unauth"]),
    "openssh":      (["ssh", "openssh"], []),
    "php":          (["php"], []),
}

# (product_keyword, version_prefix) → critical CVE template IDs
_VERSION_CVE_MAP: List[tuple] = [
    ("apache",  "2.4.49",  ["CVE-2021-41773", "CVE-2021-42013"]),
    ("apache",  "2.4.50",  ["CVE-2021-41773", "CVE-2021-42013"]),
    ("log4",    "2.",      ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"]),
    ("spring",  "5.",      ["CVE-2022-22965"]),
    ("openssh", "7.2",     ["CVE-2016-0777"]),
    ("openssh", "8.",      ["CVE-2023-38408"]),
    ("php",     "7.1",     ["CVE-2019-11043"]),
    ("php",     "7.2",     ["CVE-2019-11043"]),
    ("php",     "7.3",     ["CVE-2019-11043"]),
]


def _build_nuclei_context(nmap_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Derive Nuclei tags and targeted CVE template IDs from Nmap port scan results.
    Used to focus Nuclei on services actually running on the target.
    """
    tags: set = set()
    template_ids: set = set()
    service_summary: List[str] = []

    hosts = nmap_result.get("data", {}).get("hosts", [])
    for host in hosts:
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue

            svc     = port.get("service", "").lower()
            product = port.get("product", "").lower()
            version = port.get("version", "").lower()
            port_num = port.get("port", 0)

            # Service-based tags
            for svc_key, svc_tags in _SVC_TAGS.items():
                if svc_key in svc or svc_key in product:
                    tags.update(svc_tags)

            # Product-based mapping
            for prod_key, (prod_tags, prod_templates) in _PRODUCT_MAP.items():
                if prod_key in product:
                    tags.update(prod_tags)
                    template_ids.update(prod_templates)

            # Version-specific CVEs
            for prod_key, ver_prefix, ver_templates in _VERSION_CVE_MAP:
                if prod_key in product and version.startswith(ver_prefix):
                    template_ids.update(ver_templates)

            # SMB / EternalBlue
            if port_num in (445, 139) or "smb" in svc:
                tags.update(["smb", "network"])
                template_ids.update(["CVE-2017-0143", "CVE-2017-0144"])

            if product or svc:
                service_summary.append(f"{port_num}/{svc} {product} {version}".strip())

    return {
        "tags": sorted(tags),
        "template_ids": sorted(template_ids),
        "service_summary": service_summary[:20],
    }


# ---------------------------------------------------------------------------
# Risk score — reads entirely from PipelineContext
# ---------------------------------------------------------------------------


def _compute_risk_score(ctx: PipelineContext) -> int:
    """
    Weighted risk score (0-100) aggregated from PipelineContext:
      Nuclei critical CVEs / CVSS  30%
      ZAP web vulnerabilities       25%
      AbuseIPDB confidence          20%
      VirusTotal malicious ratio    15%
      Nmap port exposure            10%
    """
    nuclei_data  = ctx.get_step_result("nuclei")  or {}
    zap_data     = ctx.get_step_result("zap")     or {}
    abuse_data   = ctx.get_step_result("abuseipdb") or {}
    vt_data      = ctx.get_step_result("virustotal") or {}
    nmap_data    = ctx.get_step_result("nmap")    or {}

    score = 0.0

    # ── Nuclei 30% ─────────────────────────────────────────────
    nuclei_score = 0.0
    if not nuclei_data.get("error"):
        by_sev = nuclei_data.get("by_severity", {})
        max_cvss = nuclei_data.get("max_cvss") or 0.0
        if max_cvss >= 9.0:
            # CVSS-based: critical-severity finding drives the score
            nuclei_score = min(max_cvss * 10, 100)
        else:
            nuclei_score = min(
                by_sev.get("critical", 0) * 25
                + by_sev.get("high", 0) * 10
                + by_sev.get("medium", 0) * 3
                + by_sev.get("low", 0) * 1,
                100,
            )
    score += nuclei_score * 0.30

    # ── ZAP 25% ────────────────────────────────────────────────
    zap_score = 0.0
    if not zap_data.get("error"):
        by_risk = zap_data.get("by_risk", {})
        zap_score = min(
            by_risk.get("Critical", 0) * 25
            + by_risk.get("High", 0) * 15
            + by_risk.get("Medium", 0) * 6
            + by_risk.get("Low", 0) * 2,
            100,
        )
    score += zap_score * 0.25

    # ── AbuseIPDB 20% (worst case: initial + discovered IPs) ───
    abuse_conf = float(abuse_data.get("data", {}).get("abuse_confidence_score", 0))
    enrichment = abuse_data.get("discovered", {})
    for ip_abuse in enrichment.values():
        conf = ip_abuse.get("data", {}).get("abuse_confidence_score", 0) if isinstance(ip_abuse, dict) else 0
        if conf > abuse_conf:
            abuse_conf = float(conf)
    score += abuse_conf * 0.20

    # ── VirusTotal 15% (worst case across all queried IPs) ─────
    vt_score = 0.0

    def _vt_ratio(vt_inner: Dict[str, Any]) -> float:
        malicious = vt_inner.get("malicious", 0)
        total = sum(vt_inner.get(k, 0) for k in ["malicious", "suspicious", "harmless", "undetected"])
        if not total:
            domain_s = vt_inner.get("domain", {})
            url_s    = vt_inner.get("url", {})
            malicious = max(domain_s.get("malicious", 0), url_s.get("malicious", 0))
            total = max(
                sum(domain_s.get(k, 0) for k in ["malicious", "suspicious", "harmless", "undetected"]),
                sum(url_s.get(k, 0)    for k in ["malicious", "suspicious", "harmless", "undetected"]),
            )
        return (malicious / total * 100) if total > 0 else 0.0

    if not vt_data.get("error"):
        vt_score = _vt_ratio(vt_data.get("data", {}))
    for ip_vt in vt_data.get("discovered", {}).values():
        if isinstance(ip_vt, dict) and not ip_vt.get("error"):
            vt_score = max(vt_score, _vt_ratio(ip_vt.get("data", {})))
    score += vt_score * 0.15

    # ── Nmap port exposure 10% ──────────────────────────────────
    port_score = 0.0
    risky_ports = {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 6379, 27017}
    if not nmap_data.get("error"):
        summary = nmap_data.get("summary", {})
        open_ports = summary.get("ports", [])
        risky_found = sum(1 for p in open_ports if p in risky_ports)
        port_score = min(len(open_ports) * 3 + risky_found * 15, 100)
    score += port_score * 0.10

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
    from app.services.shodan_service import query_shodan
    from app.services.virustotal_service import query_virustotal
    from app.services.abuseipdb_service import query_abuseipdb

    db = _get_db_session()
    r  = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
    loop = asyncio.new_event_loop()
    ctx: Optional[PipelineContext] = None

    scan = None
    try:
        scan = db.query(Scan).filter(Scan.id == uuid.UUID(scan_id)).first()
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return {"error": "scan not found"}

        target = scan.target
        ctx = PipelineContext(scan_id, settings.REDIS_URL, db)

        # ── 0. Start ──────────────────────────────────────────────────────
        _update_scan(db, scan, status=ScanStatus.running, progress=0)
        _publish(r, scan_id, "running", 0, "Scan started")
        _add_log(db, scan_id, f"Scan started for target: {target}")

        # ── 1. Shodan  0 → 12% ────────────────────────────────────────────
        _publish(r, scan_id, "running", 3, "Starting Shodan passive recon...")
        _add_log(db, scan_id, "Starting Shodan passive recon...")
        shodan_result: Dict[str, Any] = {}
        try:
            shodan_result = loop.run_until_complete(query_shodan(target))
            ports_found = len(
                shodan_result.get("data", {}).get("internetdb", {}).get("ports", [])
            )
            _add_log(db, scan_id, f"Shodan: {ports_found} ports in public index")
        except Exception as exc:
            shodan_result = {"error": str(exc)}
            _add_log(db, scan_id, f"Shodan error: {exc}", level="error")

        ctx.save_step_result("shodan", shodan_result)
        _update_scan(db, scan, shodan_data=shodan_result, progress=12)
        _publish(r, scan_id, "running", 12, "Shodan recon complete")

        # ── 2. ZAP  12 → 30% ──────────────────────────────────────────────
        # ZAP runs first: discovers endpoints and implicit ports for Nmap
        _publish(r, scan_id, "running", 14, "Starting OWASP ZAP web spider...")
        _add_log(db, scan_id, "Launching OWASP ZAP baseline web scan...")
        zap_result: Dict[str, Any] = {}
        try:
            zap_result = loop.run_until_complete(_call_zap(target))
            total = zap_result.get("total", 0)
            by_risk = zap_result.get("by_risk", {})
            endpoints_found = len(zap_result.get("endpoints", []))
            implicit_ports = zap_result.get("implicit_ports", [])
            _add_log(
                db, scan_id,
                f"ZAP: {total} alerts — high={by_risk.get('High', 0)} "
                f"medium={by_risk.get('Medium', 0)} | "
                f"{endpoints_found} endpoints, {len(implicit_ports)} implicit ports",
                level="error"   if by_risk.get("High", 0)   > 0
                else "warning" if by_risk.get("Medium", 0) > 0
                else "info",
            )
            for a in zap_result.get("alerts", []):
                if a.get("risk_code", 0) >= 3:
                    _add_log(
                        db, scan_id,
                        f"  [HIGH] {a.get('name')} — CWE-{a.get('cwe_id', '?')} "
                        f"({a.get('count', 0)} instance(s))",
                        level="error",
                    )
            for h in zap_result.get("abnormal_headers", []):
                _add_log(
                    db, scan_id,
                    f"  [HEADER] {h.get('header_issue')} — risk: {h.get('risk')}",
                    level="warning",
                )
        except Exception as exc:
            zap_result = {"error": str(exc)}
            _add_log(db, scan_id, f"ZAP error: {exc}", level="error")
            logger.exception("ZAP failed for %s", target)

        ctx.save_step_result("zap", zap_result)
        _update_scan(db, scan, zap_data=zap_result, progress=30)
        _publish(r, scan_id, "running", 30, "ZAP web scan complete")

        # ── 3. Nmap  30 → 52% ─────────────────────────────────────────────
        # Nmap reads ZAP implicit ports to extend its own scan
        zap_ports = _extract_ports_from_zap(zap_result)
        _publish(
            r, scan_id, "running", 32,
            f"Starting Nmap active scan"
            + (f" + {len(zap_ports)} ZAP ports" if zap_ports else "") + "...",
        )
        _add_log(
            db, scan_id,
            "Launching Nmap active scan"
            + (f" (ZAP extra ports: {zap_ports})" if zap_ports else "") + "...",
        )
        nmap_result: Dict[str, Any] = {}
        try:
            nmap_result = loop.run_until_complete(_call_nmap(target, additional_ports=zap_ports))
            summary = nmap_result.get("summary", {})
            open_ports = summary.get("ports", [])
            _add_log(db, scan_id, f"Nmap: {len(open_ports)} open ports, {summary.get('host_count', 0)} host(s)")
            svc_map = summary.get("services", {})
            for port_num in list(open_ports)[:10]:
                svc = svc_map.get(str(port_num), {})
                _add_log(
                    db, scan_id,
                    f"  Port {port_num}/{svc.get('protocol', 'tcp')} — "
                    f"{svc.get('name', 'unknown')} {svc.get('product', '')} {svc.get('version', '')}".strip(),
                )
        except Exception as exc:
            nmap_result = {"error": str(exc)}
            _add_log(db, scan_id, f"Nmap error: {exc}", level="error")

        ctx.save_step_result("nmap", nmap_result)
        _update_scan(db, scan, nmap_data=nmap_result, progress=52)
        _publish(r, scan_id, "running", 52, "Nmap scan complete")

        discovered_ips = _extract_discovered_ips(nmap_result, target)
        if discovered_ips:
            _add_log(db, scan_id, f"[NETWORK] {len(discovered_ips)} additional IP(s) discovered: {', '.join(discovered_ips[:5])}")

        # ── 4. VirusTotal  52 → 65% ───────────────────────────────────────
        # Reads Nmap context: queries initial target + discovered IPs
        _publish(r, scan_id, "running", 54, "Starting VirusTotal analysis...")
        _add_log(db, scan_id, "Starting VirusTotal analysis...")
        vt_result: Dict[str, Any] = {}
        try:
            vt_result = loop.run_until_complete(query_virustotal(target))
            malicious = vt_result.get("data", {}).get("malicious", 0)
            _add_log(
                db, scan_id,
                f"VirusTotal (initial): {malicious} malicious detections",
                level="warning" if malicious > 0 else "info",
            )
            if discovered_ips:
                _add_log(db, scan_id, f"VirusTotal: enriching {len(discovered_ips[:5])} discovered IP(s)...")
                discovered_vt: Dict[str, Any] = {}
                for ip in discovered_ips[:5]:
                    try:
                        ip_vt = loop.run_until_complete(query_virustotal(ip))
                        discovered_vt[ip] = ip_vt
                        ip_mal = ip_vt.get("data", {}).get("malicious", 0)
                        if ip_mal > 0:
                            _add_log(db, scan_id, f"  VT {ip}: {ip_mal} malicious detections", level="warning")
                    except Exception as exc:
                        discovered_vt[ip] = {"error": str(exc)}
                vt_result["discovered"] = discovered_vt
        except Exception as exc:
            vt_result = {"error": str(exc)}
            _add_log(db, scan_id, f"VirusTotal error: {exc}", level="error")

        ctx.save_step_result("virustotal", vt_result)
        _update_scan(db, scan, virustotal_data=vt_result, progress=65)
        _publish(r, scan_id, "running", 65, "VirusTotal analysis complete")

        # ── 5. AbuseIPDB  65 → 75% ────────────────────────────────────────
        # Reads Nmap context: queries initial target + discovered IPs
        _publish(r, scan_id, "running", 67, "Starting AbuseIPDB check...")
        _add_log(db, scan_id, "Starting AbuseIPDB check...")
        abuse_result: Dict[str, Any] = {}
        try:
            abuse_result = loop.run_until_complete(query_abuseipdb(target))
            conf = abuse_result.get("data", {}).get("abuse_confidence_score", 0)
            level = "error" if conf > 60 else "warning" if conf > 20 else "info"
            _add_log(db, scan_id, f"AbuseIPDB (initial): confidence score {conf}%", level=level)
            if discovered_ips:
                _add_log(db, scan_id, f"AbuseIPDB: enriching {len(discovered_ips[:5])} discovered IP(s)...")
                discovered_abuse: Dict[str, Any] = {}
                for ip in discovered_ips[:5]:
                    try:
                        ip_abuse = loop.run_until_complete(query_abuseipdb(ip))
                        discovered_abuse[ip] = ip_abuse
                        ip_conf = ip_abuse.get("data", {}).get("abuse_confidence_score", 0)
                        if ip_conf > 20:
                            _add_log(
                                db, scan_id,
                                f"  AbuseIPDB {ip}: {ip_conf}% confidence",
                                level="error" if ip_conf > 60 else "warning",
                            )
                    except Exception as exc:
                        discovered_abuse[ip] = {"error": str(exc)}
                abuse_result["discovered"] = discovered_abuse
        except Exception as exc:
            abuse_result = {"error": str(exc)}
            _add_log(db, scan_id, f"AbuseIPDB error: {exc}", level="error")

        ctx.save_step_result("abuseipdb", abuse_result)
        _update_scan(db, scan, abuseipdb_data=abuse_result, progress=75)
        _publish(r, scan_id, "running", 75, "AbuseIPDB check complete")

        # ── 6. Nuclei  75 → 90% ───────────────────────────────────────────
        # Reads Nmap context: generates targeted template list from services
        nuclei_ctx = _build_nuclei_context(nmap_result)
        n_templates = len(nuclei_ctx["template_ids"])
        n_tags      = len(nuclei_ctx["tags"])
        _publish(
            r, scan_id, "running", 77,
            f"Starting Nuclei scan ({n_templates} targeted CVEs, {n_tags} service tags)...",
        )
        _add_log(
            db, scan_id,
            f"Launching Nuclei — {n_templates} targeted CVEs: {nuclei_ctx['template_ids'][:5]}",
        )
        if nuclei_ctx["service_summary"]:
            _add_log(db, scan_id, f"  Services detected: {', '.join(nuclei_ctx['service_summary'][:5])}")

        nuclei_result: Dict[str, Any] = {}
        try:
            nuclei_result = loop.run_until_complete(
                _call_nuclei(
                    target,
                    templates=nuclei_ctx["template_ids"] or None,
                    tags=nuclei_ctx["tags"] or None,
                )
            )
            total = nuclei_result.get("total", 0)
            by_sev = nuclei_result.get("by_severity", {})
            max_cvss = nuclei_result.get("max_cvss")
            _add_log(
                db, scan_id,
                f"Nuclei: {total} findings — "
                f"critical={by_sev.get('critical', 0)} "
                f"high={by_sev.get('high', 0)} "
                f"medium={by_sev.get('medium', 0)}"
                + (f" | max CVSS: {max_cvss}" if max_cvss else ""),
                level="error"   if by_sev.get("critical", 0) > 0
                else "warning" if by_sev.get("high", 0)     > 0
                else "info",
            )
            for f in nuclei_result.get("findings", []):
                sev = f.get("severity", "")
                if sev in ("critical", "high"):
                    cves = ", ".join(f.get("cve_ids", [])) or "n/a"
                    cvss = f.get("cvss_score")
                    _add_log(
                        db, scan_id,
                        f"  [{sev.upper()}] {f.get('name')} — CVE: {cves}"
                        + (f" | CVSS: {cvss}" if cvss else "")
                        + f" @ {f.get('matched_at')}",
                        level="error" if sev == "critical" else "warning",
                    )
        except Exception as exc:
            nuclei_result = {"error": str(exc)}
            _add_log(db, scan_id, f"Nuclei error: {exc}", level="error")
            logger.exception("Nuclei failed for %s", target)

        ctx.save_step_result("nuclei", nuclei_result)
        _update_scan(db, scan, nuclei_data=nuclei_result, progress=90)
        _publish(r, scan_id, "running", 90, "Nuclei scan complete")

        # ── 7. Risk score  90 → 100% ──────────────────────────────────────
        risk_score = _compute_risk_score(ctx)
        _add_log(
            db, scan_id,
            f"Risk score computed: {risk_score}/100",
            level="error" if risk_score >= 70 else "warning" if risk_score >= 40 else "info",
        )

        recon = ReconnaissanceResult(
            id=uuid.uuid4(),
            scan_id=uuid.UUID(scan_id),
            shodan_data=shodan_result,
            virustotal_data=vt_result,
            abuseipdb_data=abuse_result,
            nmap_data=nmap_result,
            nuclei_data=nuclei_result,
            zap_data=zap_result,
            risk_score=risk_score,
            abuseipdb_score=float(abuse_result.get("data", {}).get("abuse_confidence_score", 0)),
            virustotal_score=float(
                vt_result.get("data", {}).get("malicious", 0)
                or max(
                    vt_result.get("data", {}).get("domain", {}).get("malicious", 0),
                    vt_result.get("data", {}).get("url", {}).get("malicious", 0),
                )
            ),
            nuclei_score=float(nuclei_result.get("total", 0)),
            zap_score=float(zap_result.get("total", 0)),
        )
        db.add(recon)

        _update_scan(
            db, scan,
            status=ScanStatus.completed,
            progress=100,
            risk_score=risk_score,
        )
        _publish(
            r, scan_id, "completed", 100,
            f"Scan completed — Risk score: {risk_score}/100",
            {"risk_score": risk_score},
        )
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

        if isinstance(exc, (sync_redis.ConnectionError, sync_redis.TimeoutError, SAOperationalError)):
            raise self.retry(exc=exc)
        raise

    finally:
        loop.close()
        r.close()
        if ctx is not None:
            ctx.close()
        db.close()
