"""
Pipeline de scan professionnel — architecture SaaS cybersécurité.

Phases :
  1. Asset Discovery          Shodan           0 →  12%
  2. Active Recon             OWASP ZAP       12 →  27%
  3. Fingerprinting           Nmap            27 →  44%
  4. Vulnerability Scanning   Nuclei          44 →  60%
  5. Threat Intelligence      VT + AbuseIPDB  60 →  78%
  6. Correlation Engine       correlator      78 →  88%
  7. Risk Scoring             risk_engine     88 →  94%
  8. SOC Dashboard Output     soc_report      94 → 100%
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

logger = logging.getLogger(__name__)


# ── Appels aux microservices scanners ────────────────────────────────────────


async def _call_nmap(target: str, additional_ports: Optional[List[int]] = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"target": target}
    if additional_ports:
        payload["additional_ports"] = additional_ports
    default = {
        "target": target, "error": None, "data": {}, "summary": {},
        "additional_ports_from_zap": additional_ports or [],
    }
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
    default = {
        "target": target, "error": None, "alerts": [], "total": 0,
        "by_risk": {}, "endpoints": [], "form_params": [],
        "abnormal_headers": [], "implicit_ports": [],
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(960.0)) as client:
            resp = await client.post(
                f"{settings.ZAP_URL}/scan",
                json={"target": target, "spider_minutes": 2, "timeout": 900},
            )
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
    default = {
        "target": target, "error": None, "findings": [], "total": 0,
        "by_severity": {}, "max_cvss": None,
        "templates_used": templates or [], "tags_used": tags or [],
    }
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


# ── Helpers DB ───────────────────────────────────────────────────────────────


def _get_db_session():
    from app.database import SessionLocal
    return SessionLocal()


def _add_log(db, scan_id: str, message: str, level: str = "info") -> None:
    from app.models.log import ScanLog
    db.add(ScanLog(
        id=uuid.uuid4(),
        scan_id=uuid.UUID(scan_id),
        level=level,
        message=message,
        created_at=datetime.utcnow(),
    ))
    db.flush()


def _update_scan(db, scan, **kwargs) -> None:
    for key, value in kwargs.items():
        setattr(scan, key, value)
    scan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)


# ── Redis publish ─────────────────────────────────────────────────────────────


def _publish(
    r: sync_redis.Redis,
    scan_id: str,
    status: str,
    progress: int,
    message: str,
    data: Optional[Dict[str, Any]] = None,
) -> None:
    r.publish("scan_progress", json.dumps({
        "scan_id":   scan_id,
        "status":    status,
        "progress":  progress,
        "message":   message,
        "data":      data or {},
        "timestamp": datetime.utcnow().isoformat(),
    }))


# ── Helpers pipeline ──────────────────────────────────────────────────────────


def _extract_discovered_ips(nmap_result: Dict[str, Any], initial_target: str) -> List[str]:
    ips: set = set()
    for host in nmap_result.get("data", {}).get("hosts", []):
        for addr in host.get("addresses", []):
            ip = addr.get("addr", "")
            if addr.get("addrtype") == "ipv4" and ip and ip != initial_target:
                ips.add(ip)
    return list(ips)


def _extract_ports_from_zap(zap_result: Dict[str, Any]) -> List[int]:
    return zap_result.get("implicit_ports", [])


# ── Nuclei context builder (Nmap services → tags + template IDs) ─────────────

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

_PRODUCT_MAP: Dict[str, tuple] = {
    "apache":    (["apache"], []),
    "nginx":     (["nginx"], []),
    "iis":       (["iis", "microsoft"], []),
    "jenkins":   (["jenkins"], ["CVE-2019-1003000", "CVE-2018-1000861"]),
    "wordpress": (["wordpress"], []),
    "jboss":     (["jboss"], ["CVE-2017-12149"]),
    "tomcat":    (["apache", "tomcat"], ["CVE-2020-1938", "CVE-2019-0232"]),
    "weblogic":  (["oracle", "weblogic"], ["CVE-2020-14882", "CVE-2019-2725"]),
    "drupal":    (["drupal"], ["CVE-2018-7600", "CVE-2019-6340"]),
    "exchange":  (["microsoft", "exchange"], ["CVE-2021-34473", "CVE-2021-26855"]),
    "spring":    (["spring", "springboot"], ["CVE-2022-22965", "CVE-2022-22950"]),
    "log4j":     (["log4j"], ["CVE-2021-44228", "CVE-2021-45046"]),
    "laravel":   (["laravel", "php"], ["CVE-2021-3129"]),
    "grafana":   (["grafana"], ["CVE-2021-43798"]),
    "gitlab":    (["gitlab"], ["CVE-2021-22205", "CVE-2022-2884"]),
    "kibana":    (["kibana", "elasticsearch"], []),
    "redis":     (["redis"], ["redis-unauthenticated-access"]),
    "mongodb":   (["mongodb"], ["mongodb-unauth"]),
    "openssh":   (["ssh", "openssh"], []),
    "php":       (["php"], []),
}

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
    tags: set = set()
    template_ids: set = set()
    service_summary: List[str] = []

    for host in nmap_result.get("data", {}).get("hosts", []):
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            svc      = port.get("service", "").lower()
            product  = port.get("product", "").lower()
            version  = port.get("version", "").lower()
            port_num = port.get("port", 0)

            for svc_key, svc_tags in _SVC_TAGS.items():
                if svc_key in svc or svc_key in product:
                    tags.update(svc_tags)

            for prod_key, (prod_tags, prod_templates) in _PRODUCT_MAP.items():
                if prod_key in product:
                    tags.update(prod_tags)
                    template_ids.update(prod_templates)

            for prod_key, ver_prefix, ver_templates in _VERSION_CVE_MAP:
                if prod_key in product and version.startswith(ver_prefix):
                    template_ids.update(ver_templates)

            if port_num in (445, 139) or "smb" in svc:
                tags.update(["smb", "network"])
                template_ids.update(["CVE-2017-0143", "CVE-2017-0144"])

            if product or svc:
                service_summary.append(f"{port_num}/{svc} {product} {version}".strip())

    return {
        "tags":            sorted(tags),
        "template_ids":    sorted(template_ids),
        "service_summary": service_summary[:20],
    }


# ── SOC Dashboard Report builder ─────────────────────────────────────────────


def _build_soc_report(
    target: str,
    scan_id: str,
    risk_report: Dict[str, Any],
    correlation_report: Dict[str, Any],
    ctx: PipelineContext,
) -> Dict[str, Any]:
    risk_score = risk_report["final_score"]
    by_sev     = correlation_report.get("by_severity", {})
    total_f    = correlation_report.get("total_findings", 0)

    if risk_score >= 80:
        risk_level = "CRITICAL"
    elif risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    elif risk_score >= 20:
        risk_level = "LOW"
    else:
        risk_level = "INFORMATIONAL"

    executive_summary = (
        f"Target {target} presents a {risk_level} risk (score: {risk_score}/100). "
        f"{total_f} correlated findings: "
        f"{by_sev.get('critical', 0)} critical, "
        f"{by_sev.get('high', 0)} high, "
        f"{by_sev.get('medium', 0)} medium. "
        f"Exploitability: {risk_report.get('exploitability_score', 0):.0f}/100 | "
        f"Confidence: {risk_report.get('confidence_score', 0):.0f}%."
    )

    # Top 10 findings sorted by severity then exploitability
    _sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}
    sorted_findings = sorted(
        correlation_report.get("correlated_findings", []),
        key=lambda f: (
            _sev_rank.get(f.get("severity", "info"), 0),
            f.get("exploitability_score", 0),
        ),
        reverse=True,
    )
    top_findings = [
        {k: v for k, v in f.items() if k != "source_data"}
        for f in sorted_findings[:10]
    ]

    # Recommendations
    recommendations: List[str] = []
    if by_sev.get("critical", 0) > 0:
        recommendations.append(
            "IMMEDIATE ACTION: Patch or isolate services with critical CVEs"
        )
    if by_sev.get("high", 0) > 0:
        recommendations.append(
            "URGENT (24-72h): Remediate high-severity findings"
        )

    nmap_data  = ctx.get_step_result("nmap") or {}
    open_ports = nmap_data.get("summary", {}).get("ports", [])
    risky_open = [p for p in open_ports if p in {23, 445, 3389, 5900, 6379, 27017, 1433}]
    if risky_open:
        recommendations.append(
            f"HIGH PRIORITY: Firewall or close high-risk exposed ports: {risky_open}"
        )

    abuse_conf = (ctx.get_step_result("abuseipdb") or {}).get("data", {}).get("abuse_confidence_score", 0)
    if abuse_conf > 60:
        recommendations.append(
            "ALERT: IP actively flagged as malicious (AbuseIPDB) — investigate for compromise"
        )

    if risk_report.get("exploitability_score", 0) > 70:
        recommendations.append(
            "HIGH: Multiple exploitable services detected — prioritize patch management"
        )

    recommendations.append(
        "ONGOING: Enable continuous monitoring and schedule periodic rescans"
    )

    shodan_data = ctx.get_step_result("shodan") or {}
    zap_data    = ctx.get_step_result("zap")    or {}
    nuclei_data = ctx.get_step_result("nuclei") or {}
    vt_data     = ctx.get_step_result("virustotal") or {}

    return {
        "scan_id":            scan_id,
        "target":             target,
        "risk_level":         risk_level,
        "risk_score":         risk_score,
        "executive_summary":  executive_summary,
        "component_scores":   risk_report.get("component_scores", {}),
        "confidence_score":   risk_report.get("confidence_score", 0),
        "exploitability_score": risk_report.get("exploitability_score", 0),
        "threat_intelligence_factor": risk_report.get("threat_intelligence_factor", 0),
        "cve_severity_factor": risk_report.get("cve_severity_factor", 0),
        "service_exposure_factor": risk_report.get("service_exposure_factor", 0),
        "top_findings":       top_findings,
        "attack_paths":       correlation_report.get("attack_paths", []),
        "recommendations":    recommendations,
        "phases_summary": {
            "asset_discovery": {
                "phase":      "Asset Discovery",
                "tool":       "Shodan",
                "status":     "error" if shodan_data.get("error") else "complete",
                "ports_found": len(
                    shodan_data.get("data", {}).get("internetdb", {}).get("ports", [])
                ),
            },
            "active_recon": {
                "phase":           "Active Recon",
                "tool":            "OWASP ZAP",
                "status":          "error" if zap_data.get("error") else "complete",
                "endpoints_found": len(zap_data.get("endpoints", [])),
                "alerts_found":    zap_data.get("total", 0),
            },
            "fingerprinting": {
                "phase":       "Fingerprinting",
                "tool":        "Nmap",
                "status":      "error" if nmap_data.get("error") else "complete",
                "open_ports":  len(open_ports),
                "hosts_found": nmap_data.get("summary", {}).get("host_count", 0),
            },
            "vulnerability_scanning": {
                "phase":    "Vulnerability Scanning",
                "tool":     "Nuclei",
                "status":   "error" if nuclei_data.get("error") else "complete",
                "findings": nuclei_data.get("total", 0),
                "max_cvss": nuclei_data.get("max_cvss"),
            },
            "threat_intelligence": {
                "phase":          "Threat Intelligence",
                "tools":          ["VirusTotal", "AbuseIPDB"],
                "status":         "complete",
                "abuse_confidence": abuse_conf,
                "vt_malicious":   vt_data.get("data", {}).get("malicious", 0),
            },
            "correlation": {
                "phase":               "Correlation Engine",
                "status":              "complete",
                "total_correlated":    total_f,
                "sources_used":        correlation_report.get("correlated_sources", []),
                "attack_paths_found":  len(correlation_report.get("attack_paths", [])),
                "service_vuln_pairs":  len(correlation_report.get("service_vuln_map", {})),
            },
        },
        "generated_at": datetime.utcnow().isoformat(),
    }


# ── Celery task ───────────────────────────────────────────────────────────────


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
    from app.correlation_engine.correlator import correlate
    from app.risk_engine.scorer import compute_enhanced_risk_score

    db   = _get_db_session()
    r    = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
    loop = asyncio.new_event_loop()
    ctx: Optional[PipelineContext] = None
    scan = None

    try:
        scan = db.query(Scan).filter(Scan.id == uuid.UUID(scan_id)).first()
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return {"error": "scan not found"}

        target = scan.target
        ctx    = PipelineContext(scan_id, settings.REDIS_URL, db)

        # ── 0. Démarrage ──────────────────────────────────────────────────────
        _update_scan(db, scan, status=ScanStatus.running, progress=0, current_phase="initializing")
        _publish(r, scan_id, "running", 0, "Scan pipeline started")
        _add_log(db, scan_id, f"Scan started for target: {target}")

        # ════════════════════════════════════════════════════════════════════
        # PHASE 1 — Asset Discovery  (Shodan)  0 → 12%
        # ════════════════════════════════════════════════════════════════════
        _update_scan(db, scan, current_phase="asset_discovery", progress=2)
        _publish(r, scan_id, "running", 2, "[Phase 1/8] Asset Discovery — Shodan passive recon...")
        _add_log(db, scan_id, "═══ Phase 1/8: Asset Discovery (Shodan) ═══")

        shodan_result: Dict[str, Any] = {}
        try:
            shodan_result = loop.run_until_complete(query_shodan(target))
            ports_found = len(
                shodan_result.get("data", {}).get("internetdb", {}).get("ports", [])
            )
            vulns_found = len(
                shodan_result.get("data", {}).get("internetdb", {}).get("vulns", [])
            )
            _add_log(
                db, scan_id,
                f"Shodan: {ports_found} ports in public index"
                + (f", {vulns_found} known CVEs" if vulns_found else ""),
            )
        except Exception as exc:
            shodan_result = {"error": str(exc)}
            _add_log(db, scan_id, f"Shodan error: {exc}", level="error")

        ctx.save_step_result("shodan", shodan_result)
        _update_scan(db, scan, shodan_data=shodan_result, progress=12)
        _publish(r, scan_id, "running", 12, "Asset Discovery complete")

        # ════════════════════════════════════════════════════════════════════
        # PHASE 2 — Active Recon  (OWASP ZAP)  12 → 27%
        # ════════════════════════════════════════════════════════════════════
        _update_scan(db, scan, current_phase="active_recon", progress=14)
        _publish(r, scan_id, "running", 14, "[Phase 2/8] Active Recon — OWASP ZAP web spider...")
        _add_log(db, scan_id, "═══ Phase 2/8: Active Recon (OWASP ZAP) ═══")

        zap_result: Dict[str, Any] = {}
        try:
            zap_result = loop.run_until_complete(_call_zap(target))
            total         = zap_result.get("total", 0)
            by_risk       = zap_result.get("by_risk", {})
            endpoints_cnt = len(zap_result.get("endpoints", []))
            implicit_ports = zap_result.get("implicit_ports", [])
            _add_log(
                db, scan_id,
                f"ZAP: {total} alerts — high={by_risk.get('High', 0)} "
                f"medium={by_risk.get('Medium', 0)} | "
                f"{endpoints_cnt} endpoints, {len(implicit_ports)} implicit ports",
                level=(
                    "error"   if by_risk.get("High",   0) > 0 else
                    "warning" if by_risk.get("Medium", 0) > 0 else
                    "info"
                ),
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
        _update_scan(db, scan, zap_data=zap_result, progress=27)
        _publish(r, scan_id, "running", 27, "Active Recon complete")

        # ════════════════════════════════════════════════════════════════════
        # PHASE 3 — Fingerprinting  (Nmap)  27 → 44%
        # ════════════════════════════════════════════════════════════════════
        zap_ports = _extract_ports_from_zap(zap_result)
        _update_scan(db, scan, current_phase="fingerprinting", progress=29)
        _publish(
            r, scan_id, "running", 29,
            "[Phase 3/8] Fingerprinting — Nmap active scan"
            + (f" + {len(zap_ports)} ZAP ports" if zap_ports else "") + "...",
        )
        _add_log(db, scan_id, "═══ Phase 3/8: Fingerprinting (Nmap) ═══")

        nmap_result: Dict[str, Any] = {}
        try:
            nmap_result = loop.run_until_complete(_call_nmap(target, additional_ports=zap_ports))
            summary    = nmap_result.get("summary", {})
            open_ports = summary.get("ports", [])
            _add_log(
                db, scan_id,
                f"Nmap: {len(open_ports)} open ports, {summary.get('host_count', 0)} host(s)"
                + (f" (+ ZAP ports: {zap_ports})" if zap_ports else ""),
            )
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
        _update_scan(db, scan, nmap_data=nmap_result, progress=44)
        _publish(r, scan_id, "running", 44, "Fingerprinting complete")

        discovered_ips = _extract_discovered_ips(nmap_result, target)
        if discovered_ips:
            _add_log(
                db, scan_id,
                f"[NETWORK] {len(discovered_ips)} additional IP(s) discovered: "
                f"{', '.join(discovered_ips[:5])}",
            )

        # ════════════════════════════════════════════════════════════════════
        # PHASE 4 — Vulnerability Scanning  (Nuclei)  44 → 60%
        # ════════════════════════════════════════════════════════════════════
        nuclei_ctx  = _build_nuclei_context(nmap_result)
        n_templates = len(nuclei_ctx["template_ids"])
        n_tags      = len(nuclei_ctx["tags"])

        _update_scan(db, scan, current_phase="vulnerability_scanning", progress=46)
        _publish(
            r, scan_id, "running", 46,
            f"[Phase 4/8] Vulnerability Scanning — Nuclei "
            f"({n_templates} targeted CVEs, {n_tags} service tags)...",
        )
        _add_log(db, scan_id, "═══ Phase 4/8: Vulnerability Scanning (Nuclei) ═══")
        _add_log(
            db, scan_id,
            f"Nuclei: {n_templates} targeted CVEs: {nuclei_ctx['template_ids'][:5]}",
        )
        if nuclei_ctx["service_summary"]:
            _add_log(db, scan_id, f"  Services: {', '.join(nuclei_ctx['service_summary'][:5])}")

        nuclei_result: Dict[str, Any] = {}
        try:
            nuclei_result = loop.run_until_complete(
                _call_nuclei(
                    target,
                    templates=nuclei_ctx["template_ids"] or None,
                    tags=nuclei_ctx["tags"] or None,
                )
            )
            total    = nuclei_result.get("total", 0)
            by_sev   = nuclei_result.get("by_severity", {})
            max_cvss = nuclei_result.get("max_cvss")
            _add_log(
                db, scan_id,
                f"Nuclei: {total} findings — "
                f"critical={by_sev.get('critical', 0)} "
                f"high={by_sev.get('high', 0)} "
                f"medium={by_sev.get('medium', 0)}"
                + (f" | max CVSS: {max_cvss}" if max_cvss else ""),
                level=(
                    "error"   if by_sev.get("critical", 0) > 0 else
                    "warning" if by_sev.get("high",     0) > 0 else
                    "info"
                ),
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
        _update_scan(db, scan, nuclei_data=nuclei_result, progress=60)
        _publish(r, scan_id, "running", 60, "Vulnerability Scanning complete")

        # ════════════════════════════════════════════════════════════════════
        # PHASE 5 — Threat Intelligence  (VirusTotal + AbuseIPDB)  60 → 78%
        # ════════════════════════════════════════════════════════════════════
        _update_scan(db, scan, current_phase="threat_intelligence", progress=62)
        _publish(r, scan_id, "running", 62, "[Phase 5/8] Threat Intelligence — VirusTotal + AbuseIPDB...")
        _add_log(db, scan_id, "═══ Phase 5/8: Threat Intelligence Enrichment ═══")

        # ── VirusTotal ──────────────────────────────────────────────────────
        vt_result: Dict[str, Any] = {}
        try:
            vt_result  = loop.run_until_complete(query_virustotal(target))
            malicious  = vt_result.get("data", {}).get("malicious", 0)
            _add_log(
                db, scan_id,
                f"VirusTotal: {malicious} malicious detections",
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
                            _add_log(db, scan_id, f"  VT {ip}: {ip_mal} malicious", level="warning")
                    except Exception as exc:
                        discovered_vt[ip] = {"error": str(exc)}
                vt_result["discovered"] = discovered_vt
        except Exception as exc:
            vt_result = {"error": str(exc)}
            _add_log(db, scan_id, f"VirusTotal error: {exc}", level="error")

        ctx.save_step_result("virustotal", vt_result)
        _update_scan(db, scan, virustotal_data=vt_result, progress=69)
        _publish(r, scan_id, "running", 69, "VirusTotal analysis complete")

        # ── AbuseIPDB ───────────────────────────────────────────────────────
        abuse_result: Dict[str, Any] = {}
        try:
            abuse_result = loop.run_until_complete(query_abuseipdb(target))
            conf  = abuse_result.get("data", {}).get("abuse_confidence_score", 0)
            level = "error" if conf > 60 else "warning" if conf > 20 else "info"
            _add_log(db, scan_id, f"AbuseIPDB: confidence score {conf}%", level=level)
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
        _update_scan(db, scan, abuseipdb_data=abuse_result, progress=78)
        _publish(r, scan_id, "running", 78, "Threat Intelligence Enrichment complete")

        # ════════════════════════════════════════════════════════════════════
        # PHASE 6 — Correlation Engine  78 → 88%
        # ════════════════════════════════════════════════════════════════════
        _update_scan(db, scan, current_phase="correlation_engine", progress=80)
        _publish(r, scan_id, "running", 80, "[Phase 6/8] Correlation Engine — fusing all findings...")
        _add_log(db, scan_id, "═══ Phase 6/8: Correlation Engine ═══")

        correlation_report: Dict[str, Any] = {}
        try:
            correlation_report = correlate(
                nmap_data=nmap_result,
                zap_data=zap_result,
                nuclei_data=nuclei_result,
                shodan_data=shodan_result,
                vt_data=vt_result,
                abuse_data=abuse_result,
            )
            summary_str = correlation_report.get("summary", "")
            _add_log(db, scan_id, f"Correlation: {summary_str}")

            svm = correlation_report.get("service_vuln_map", {})
            if svm:
                _add_log(db, scan_id, f"  Service→CVE map: {len(svm)} service(s) with known CVEs")

            for ap in correlation_report.get("attack_paths", [])[:5]:
                _add_log(db, scan_id, f"  [PATH] {ap}", level="warning")

        except Exception as exc:
            correlation_report = {"error": str(exc), "correlated_findings": []}
            _add_log(db, scan_id, f"Correlation Engine error: {exc}", level="error")
            logger.exception("Correlation Engine failed for %s", target)

        ctx.save_step_result("correlation", correlation_report)
        _update_scan(db, scan, correlated_data=correlation_report, progress=88)
        _publish(r, scan_id, "running", 88, "Correlation Engine complete")

        # ════════════════════════════════════════════════════════════════════
        # PHASE 7 — Risk Scoring  88 → 94%
        # ════════════════════════════════════════════════════════════════════
        _update_scan(db, scan, current_phase="risk_scoring", progress=90)
        _publish(r, scan_id, "running", 90, "[Phase 7/8] Risk Scoring — multi-factor analysis...")
        _add_log(db, scan_id, "═══ Phase 7/8: Enhanced Risk Scoring ═══")

        risk_report = compute_enhanced_risk_score(ctx, correlation_report)
        risk_score  = risk_report["final_score"]

        components  = risk_report.get("component_scores", {})
        _add_log(
            db, scan_id,
            f"Risk Score: {risk_score}/100 | "
            f"nuclei={components.get('nuclei_cve', 0):.0f} "
            f"zap={components.get('zap_web', 0):.0f} "
            f"exploit={components.get('exploitability', 0):.0f} "
            f"port={components.get('port_exposure', 0):.0f}",
            level="error" if risk_score >= 70 else "warning" if risk_score >= 40 else "info",
        )
        _add_log(
            db, scan_id,
            f"  Exploitability: {risk_report.get('exploitability_score', 0):.0f}/100 | "
            f"Confidence: {risk_report.get('confidence_score', 0):.0f}% | "
            f"Threat Intel: {risk_report.get('threat_intelligence_factor', 0):.0f}/100",
        )

        _update_scan(db, scan, progress=94)
        _publish(r, scan_id, "running", 94, f"Risk Score computed: {risk_score}/100")

        # ════════════════════════════════════════════════════════════════════
        # PHASE 8 — SOC Dashboard Output  94 → 100%
        # ════════════════════════════════════════════════════════════════════
        _update_scan(db, scan, current_phase="soc_output", progress=96)
        _publish(r, scan_id, "running", 96, "[Phase 8/8] Building SOC Dashboard report...")
        _add_log(db, scan_id, "═══ Phase 8/8: SOC Dashboard Output ═══")

        soc_report: Dict[str, Any] = {}
        try:
            soc_report = _build_soc_report(target, scan_id, risk_report, correlation_report, ctx)
            risk_level = soc_report.get("risk_level", "UNKNOWN")
            recs_count = len(soc_report.get("recommendations", []))
            _add_log(
                db, scan_id,
                f"SOC Report: Risk Level={risk_level} | "
                f"{soc_report.get('top_findings', []).__len__()} top findings | "
                f"{recs_count} recommendations",
                level="error" if risk_level in ("CRITICAL", "HIGH") else "info",
            )
            for rec in soc_report.get("recommendations", [])[:3]:
                _add_log(db, scan_id, f"  → {rec}", level="warning")
        except Exception as exc:
            soc_report = {"error": str(exc)}
            _add_log(db, scan_id, f"SOC report error: {exc}", level="error")
            logger.exception("SOC report build failed for %s", target)

        # ── Persistance finale ────────────────────────────────────────────
        recon = ReconnaissanceResult(
            id=uuid.uuid4(),
            scan_id=uuid.UUID(scan_id),
            shodan_data=shodan_result,
            virustotal_data=vt_result,
            abuseipdb_data=abuse_result,
            nmap_data=nmap_result,
            nuclei_data=nuclei_result,
            zap_data=zap_result,
            # Legacy scores
            risk_score=risk_score,
            abuseipdb_score=float(
                abuse_result.get("data", {}).get("abuse_confidence_score", 0)
            ),
            virustotal_score=float(
                vt_result.get("data", {}).get("malicious", 0)
                or max(
                    vt_result.get("data", {}).get("domain", {}).get("malicious", 0),
                    vt_result.get("data", {}).get("url",    {}).get("malicious", 0),
                )
            ),
            nuclei_score=float(nuclei_result.get("total", 0)),
            zap_score=float(zap_result.get("total", 0)),
            # New enhanced fields
            correlated_data=correlation_report,
            exploitability_score=risk_report.get("exploitability_score"),
            confidence_score=risk_report.get("confidence_score"),
            correlation_score=correlation_report.get("confidence_score"),
            risk_component_scores=risk_report.get("component_scores"),
            threat_intelligence_factor=risk_report.get("threat_intelligence_factor"),
            cve_severity_factor=risk_report.get("cve_severity_factor"),
            service_exposure_factor=risk_report.get("service_exposure_factor"),
            soc_report=soc_report,
        )
        db.add(recon)

        _update_scan(
            db, scan,
            status=ScanStatus.completed,
            progress=100,
            risk_score=risk_score,
            correlated_data=correlation_report,
            soc_report=soc_report,
            current_phase="complete",
        )
        _publish(
            r, scan_id, "completed", 100,
            f"Scan completed — Risk: {soc_report.get('risk_level', 'N/A')} ({risk_score}/100)",
            {
                "risk_score":          risk_score,
                "risk_level":          soc_report.get("risk_level"),
                "exploitability":      risk_report.get("exploitability_score"),
                "confidence":          risk_report.get("confidence_score"),
                "correlated_findings": correlation_report.get("total_findings", 0),
            },
        )
        _add_log(db, scan_id, f"✔ Scan completed — {soc_report.get('executive_summary', '')}")

        logger.info(
            "Scan %s completed (risk=%d, level=%s, findings=%d) for %s",
            scan_id, risk_score,
            soc_report.get("risk_level", "?"),
            correlation_report.get("total_findings", 0),
            target,
        )
        return {
            "scan_id":    scan_id,
            "status":     "completed",
            "risk_score": risk_score,
            "risk_level": soc_report.get("risk_level"),
            "correlated_findings": correlation_report.get("total_findings", 0),
        }

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
