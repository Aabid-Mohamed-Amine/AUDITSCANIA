"""
Pipeline de scan professionnel — architecture SaaS cybersécurité.

5 phases nettes :
  Phase 1 — Recon          Shodan ∥ Subfinder ∥ Nmap ∥ AbuseIPDB ∥ VT     0 →  25%
  Phase 2 — Active Scan    ZAP ∥ Nuclei (enrichi Nmap P1) ∥ Dalfox        25 →  55%
  Phase 3 — Exploitation   FFUF ∥ Katana ∥ GitLeaks + SQLMap (conditionnel) 55 →  75%
  Phase 4 — Correlation    Correlator → FP Reduction → Risk Scoring        75 →  90%
  Phase 5 — SOC Dashboard  AI Analysis + SOC Report + recommandations       90 → 100%

SQLMap ne tourne qu'en Phase 3 si ZAP (Phase 2) détecte des paramètres injectables.
Nuclei en Phase 2 est enrichi par les données Nmap (Phase 1).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
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


async def _call_subfinder(target: str, timeout: int = 120) -> Dict[str, Any]:
    """Asset Discovery: Subfinder (subdomains) + httpx (HTTP probing)."""
    # Subfinder needs a bare hostname/IP — strip scheme, port, and path.
    subfinder_host = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    default = {
        "target": target, "error": None,
        "subdomains": [], "subdomains_count": 0,
        "http_probes": [], "live_hosts": [], "live_count": 0,
        "technologies": [], "is_ip": False,
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 30))) as client:
            resp = await client.post(
                f"{settings.SUBFINDER_URL}/discover",
                json={"target": subfinder_host, "timeout": timeout, "passive_only": True},
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "Subfinder service unavailable (container not running?)"
    except httpx.TimeoutException:
        default["error"] = "Subfinder service HTTP request timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_ffuf(
    target:       str,
    timeout:      int = 120,
    auth_headers: Optional[Dict[str, Any]] = None,
    auth_cookies: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Endpoint/directory discovery via FFUF."""
    default = {"target": target, "error": None, "endpoints": [], "total": 0, "by_status": {}, "by_category": {}}
    payload: Dict[str, Any] = {"target": target, "timeout": timeout, "threads": 30}
    if auth_headers:
        payload["headers"] = auth_headers
    if auth_cookies:
        payload["cookies"] = auth_cookies
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 30))) as client:
            resp = await client.post(
                f"{settings.FFUF_URL}/scan",
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "FFUF service unavailable"
    except httpx.TimeoutException:
        default["error"] = "FFUF service timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_sqlmap_enriched(
    target:       str,
    zap_result:   Dict[str, Any],
    ffuf_result:  Dict[str, Any],
    katana_result: Dict[str, Any],
    timeout:      int = 150,
    auth_headers: Optional[Dict[str, Any]] = None,
    auth_cookies: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    SQL injection assessment via SQLMap — enriched with params from ZAP/FFUF/Katana.
    Runs AFTER the parallel group so it has real endpoint/param data.
    """
    default = {"target": target, "error": None, "vulnerable": False, "findings": [], "total": 0}

    # ── Build endpoints list from ZAP spider results ─────────────────────────
    from urllib.parse import urlparse, parse_qs
    endpoints = []
    for ep in zap_result.get("endpoints", [])[:40]:
        url    = ep.get("url", "")
        method = ep.get("method", "GET")
        param  = ep.get("param", "")
        if not url:
            continue
        try:
            get_params = [k for k in parse_qs(urlparse(url).query).keys()]
        except Exception:
            get_params = []
        all_params = list(dict.fromkeys(get_params + ([param] if param else [])))
        if all_params or method.upper() == "POST":
            endpoints.append({"url": url, "method": method, "params": all_params, "data": ""})

    # ── Form params from ZAP ─────────────────────────────────────────────────
    form_params = zap_result.get("form_params", [])[:20]

    # ── Extra URLs from FFUF sensitive + Katana API + Katana params ──────────
    extra_urls: List[str] = []
    # FFUF sensitive paths (admin, config, etc.)
    extra_urls += [ep.get("url", "") for ep in
                   (ffuf_result.get("by_severity", {}).get("critical", []) +
                    ffuf_result.get("by_severity", {}).get("high", []))[:10]]
    # Katana API endpoints
    extra_urls += katana_result.get("api_endpoints", [])[:10]
    # Katana endpoints with GET params
    for ep in katana_result.get("endpoints", [])[:30]:
        if ep.get("params"):
            extra_urls.append(ep.get("url", ""))
    extra_urls = [u for u in list(dict.fromkeys(extra_urls)) if u][:20]

    try:
        _sqlmap_payload: Dict[str, Any] = {
            "target":      target,
            "timeout":     timeout,
            "endpoints":   endpoints[:15],
            "form_params": form_params,
            "extra_urls":  extra_urls,
        }
        if auth_headers:
            _sqlmap_payload["headers"] = auth_headers
        if auth_cookies:
            _sqlmap_payload["cookies"] = auth_cookies
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 30))) as client:
            resp = await client.post(
                f"{settings.SQLMAP_URL}/scan",
                json=_sqlmap_payload,
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "SQLMap service unavailable"
    except httpx.TimeoutException:
        default["error"] = "SQLMap service timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_gitleaks(target: str, timeout: int = 120) -> Dict[str, Any]:
    """Secrets detection via GitLeaks."""
    default = {"target": target, "error": None, "findings": [], "total": 0, "by_severity": {}}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 30))) as client:
            resp = await client.post(
                f"{settings.GITLEAKS_URL}/scan",
                json={"target": target, "timeout": timeout},
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "GitLeaks service unavailable"
    except httpx.TimeoutException:
        default["error"] = "GitLeaks service timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_katana(target: str, timeout: int = 90) -> Dict[str, Any]:
    """JS/SPA web crawling via Katana — extracts hidden endpoints and API calls."""
    default = {
        "target": target, "error": None,
        "endpoints": [], "js_files": [], "api_endpoints": [],
        "params": [], "total": 0, "by_category": {},
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 30))) as client:
            resp = await client.post(
                f"{settings.KATANA_URL}/scan",
                json={"target": target, "timeout": timeout, "depth": 3, "js_crawl": True},
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "Katana service unavailable (container not running?)"
    except httpx.TimeoutException:
        default["error"] = "Katana service HTTP request timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_dalfox(target: str, timeout: int = 120) -> Dict[str, Any]:
    """XSS detection via Dalfox (défensif, assessment uniquement)."""
    default = {
        "target": target, "error": None,
        "findings": [], "total": 0, "by_severity": {},
    }
    # Uniquement pour les cibles web
    if not target.startswith(("http://", "https://")):
        target_url = f"http://{target}"
    else:
        target_url = target

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 30))) as client:
            resp = await client.post(
                f"{settings.DALFOX_URL}/scan",
                json={"target": target_url, "timeout": timeout, "deep_mode": False},
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "Dalfox service unavailable (container not running?)"
    except httpx.TimeoutException:
        default["error"] = "Dalfox service HTTP request timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


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


async def _call_zap(
    target:       str,
    auth_headers: Optional[Dict[str, Any]] = None,
    auth_cookies: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    default = {
        "target": target, "error": None, "alerts": [], "total": 0,
        "by_risk": {}, "endpoints": [], "form_params": [],
        "abnormal_headers": [], "implicit_ports": [],
    }
    payload: Dict[str, Any] = {"target": target, "spider_minutes": 2, "timeout": 900}
    if auth_headers:
        payload["headers"] = auth_headers
    if auth_cookies:
        payload["cookies"] = auth_cookies
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(960.0)) as client:
            resp = await client.post(f"{settings.ZAP_URL}/scan", json=payload)
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
    target:          str,
    templates:       Optional[List[str]] = None,
    tags:            Optional[List[str]] = None,
    extra_targets:   Optional[List[str]] = None,
    tech_stack:      Optional[List[str]] = None,
    scan_categories: Optional[List[str]] = None,
    auth_headers:    Optional[Dict[str, Any]] = None,
    auth_cookies:    Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"target": target, "timeout": 600}
    if templates:
        payload["templates"] = templates
    if tags:
        payload["tags"] = tags
    if extra_targets:
        payload["extra_targets"] = extra_targets
    if tech_stack:
        payload["tech_stack"] = tech_stack
    if scan_categories:
        payload["scan_categories"] = scan_categories
    if auth_headers:
        payload["headers"] = auth_headers
    if auth_cookies:
        payload["cookies"] = auth_cookies
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


# ── Nuclei context builder v2 ─────────────────────────────────────────────────
# Uses ALL available sources: Nmap, Subfinder, FFUF, Katana, Nmap HTTP probes

# Service name → base tags
_SVC_TAGS: Dict[str, List[str]] = {
    "http":          ["http", "exposures", "misconfiguration"],
    "https":         ["http", "ssl", "tls"],
    "ftp":           ["ftp", "network", "default-logins"],
    "ssh":           ["ssh", "network"],
    "smtp":          ["smtp", "network"],
    "smb":           ["smb", "network"],
    "mysql":         ["mysql", "network", "default-logins"],
    "postgres":      ["postgresql", "network"],
    "postgresql":    ["postgresql", "network"],
    "redis":         ["redis", "network"],
    "mongodb":       ["mongodb", "network"],
    "rdp":           ["rdp", "network"],
    "telnet":        ["telnet", "network", "default-logins"],
    "vnc":           ["vnc", "network"],
    "ldap":          ["ldap", "network"],
    "ldaps":         ["ldap", "network"],
    "elastic":       ["elasticsearch", "network"],
    "elasticsearch": ["elasticsearch", "network"],
    "kafka":         ["network"],
    "amqp":          ["network"],
    "docker":        ["docker", "network"],
    "kubernetes":    ["kubernetes", "k8s"],
    "jenkins":       ["jenkins", "default-logins"],
    "grafana":       ["grafana"],
    "kibana":        ["kibana", "elasticsearch"],
    "etcd":          ["network", "etcd"],
}

# Product keyword → (tags, CVE template IDs)
_PRODUCT_MAP: Dict[str, tuple] = {
    # Web servers
    "apache":       (["apache", "http"], []),
    "nginx":        (["nginx", "http"], []),
    "iis":          (["iis", "microsoft", "http"], []),
    "litespeed":    (["litespeed", "http"], []),
    "openresty":    (["nginx", "lua", "http"], []),
    "caddy":        (["http"], []),
    # App servers
    "tomcat":       (["tomcat", "apache", "java"], ["CVE-2020-1938", "CVE-2019-0232", "CVE-2017-12615"]),
    "jboss":        (["jboss", "java"],            ["CVE-2017-12149", "CVE-2015-7501"]),
    "weblogic":     (["oracle", "weblogic", "java"],["CVE-2020-14882", "CVE-2019-2725", "CVE-2018-2628"]),
    "websphere":    (["ibm", "websphere", "java"], ["CVE-2020-4450"]),
    "glassfish":    (["glassfish", "java"],        ["CVE-2017-1000028"]),
    "jetty":        (["jetty", "java"],            []),
    # CMS
    "wordpress":    (["wordpress", "wp-plugin"],   []),
    "drupal":       (["drupal"],                   ["CVE-2018-7600", "CVE-2019-6340", "CVE-2021-41182"]),
    "joomla":       (["joomla"],                   ["CVE-2015-8562", "CVE-2019-10945"]),
    "magento":      (["magento"],                  ["CVE-2019-8118", "CVE-2022-24086"]),
    "typo3":        (["typo3"],                    ["CVE-2019-12747"]),
    # Languages / frameworks
    "php":          (["php"],                      []),
    "laravel":      (["laravel", "php"],           ["CVE-2021-3129", "CVE-2018-15133"]),
    "symfony":      (["symfony", "php"],           ["CVE-2021-41268"]),
    "spring":       (["spring", "springboot", "java"], ["CVE-2022-22965", "CVE-2022-22950", "CVE-2022-22963"]),
    "log4j":        (["log4j", "java"],            ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"]),
    "struts":       (["struts", "java"],           ["CVE-2017-5638", "CVE-2018-11776"]),
    "rails":        (["rails", "ruby"],            ["CVE-2019-5418"]),
    "node":         (["nodejs", "node"],           []),
    "express":      (["express", "nodejs"],        []),
    "django":       (["django", "python"],         []),
    "flask":        (["flask", "python"],          []),
    "dotnet":       (["asp", "dotnet"],            []),
    # Email
    "exchange":     (["microsoft", "exchange"],    ["CVE-2021-34473", "CVE-2021-26855", "CVE-2022-41082"]),
    "postfix":      (["smtp", "network"],          []),
    "sendmail":     (["smtp", "network"],          []),
    # DevOps / CI
    "jenkins":      (["jenkins", "default-logins"],["CVE-2019-1003000", "CVE-2018-1000861", "CVE-2024-23897"]),
    "gitlab":       (["gitlab"],                   ["CVE-2021-22205", "CVE-2022-2884", "CVE-2023-7028"]),
    "github":       (["github"],                   []),
    "grafana":      (["grafana"],                  ["CVE-2021-43798", "CVE-2022-31107"]),
    "kibana":       (["kibana", "elasticsearch"],  ["CVE-2019-7609"]),
    "prometheus":   (["prometheus", "misconfiguration"], []),
    "sonarqube":    (["sonarqube"],                []),
    "nexus":        (["nexus"],                    ["CVE-2019-7238", "CVE-2020-10199"]),
    "artifactory":  (["jfrog"],                    ["CVE-2020-7931"]),
    # Infrastructure
    "openssh":      (["ssh", "openssh"],           []),
    "openssl":      (["ssl", "tls"],               []),
    "redis":        (["redis"],                    ["redis-unauthenticated-access"]),
    "mongodb":      (["mongodb"],                  ["mongodb-unauth"]),
    "elastic":      (["elasticsearch", "network"], ["CVE-2014-3120", "CVE-2015-1427"]),
    "rabbitmq":     (["network", "default-logins"],["CVE-2023-46118"]),
    "consul":       (["network", "misconfiguration"], []),
    "vault":        (["network"],                  []),
    "etcd":         (["network", "misconfiguration"], []),
    "docker":       (["docker"],                   ["CVE-2019-5736"]),
    "kubernetes":   (["kubernetes", "k8s"],        ["CVE-2018-1002105"]),
    # Cloud-specific
    "minio":        (["cloud", "s3"],              ["CVE-2023-28432"]),
    "keycloak":     (["keycloak"],                 ["CVE-2023-6927", "CVE-2022-4361"]),
    "confluence":   (["confluence", "atlassian"],  ["CVE-2022-26134", "CVE-2023-22515"]),
    "jira":         (["jira", "atlassian"],        ["CVE-2021-26086"]),
    "zimbra":       (["zimbra"],                   ["CVE-2022-37042"]),
    "citrix":       (["citrix"],                   ["CVE-2023-3519", "CVE-2019-19781"]),
    "fortinet":     (["fortinet"],                 ["CVE-2022-40684", "CVE-2018-13382"]),
    "palo-alto":    (["paloalto"],                 ["CVE-2020-2021"]),
    "vmware":       (["vmware"],                   ["CVE-2021-21985", "CVE-2021-22005"]),
}

# Version prefix → CVE IDs when product detected with specific version
_VERSION_CVE_MAP: List[tuple] = [
    ("apache",   "2.4.49", ["CVE-2021-41773", "CVE-2021-42013"]),
    ("apache",   "2.4.50", ["CVE-2021-41773", "CVE-2021-42013"]),
    ("log4",     "2.",     ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"]),
    ("spring",   "5.",     ["CVE-2022-22965"]),
    ("spring",   "2.",     ["CVE-2022-22963"]),
    ("openssh",  "7.2",    ["CVE-2016-0777"]),
    ("openssh",  "8.",     ["CVE-2023-38408"]),
    ("php",      "7.1",    ["CVE-2019-11043"]),
    ("php",      "7.2",    ["CVE-2019-11043"]),
    ("php",      "7.3",    ["CVE-2019-11043"]),
    ("php",      "8.0",    []),
    ("openssl",  "1.0",    ["CVE-2014-0160"]),   # Heartbleed
    ("openssl",  "1.1",    ["CVE-2022-0778"]),
    ("drupal",   "7.",     ["CVE-2014-3704", "CVE-2018-7600"]),
    ("drupal",   "8.",     ["CVE-2018-7600", "CVE-2019-6340"]),
    ("jenkins",  "2.",     ["CVE-2024-23897"]),
]

# Scan categories to always include for web targets
_BASE_WEB_SCAN_CATEGORIES: List[str] = [
    "exposures",
    "misconfigurations",
    "panels",
    "api",
]

# FFUF category → Nuclei tags
_FFUF_TO_NUCLEI: Dict[str, List[str]] = {
    "admin_panel":   ["panels", "default-logins"],
    "git_exposure":  ["git-config", "exposures"],
    "config_file":   ["exposures", "misconfiguration"],
    "backup_file":   ["exposures"],
    "secret_file":   ["exposures"],
    "api_docs":      ["api", "swagger"],
    "api_route":     ["api"],
    "debug_endpoint":["misconfiguration", "exposures"],
    "installer":     ["misconfiguration"],
    "credentials":   ["exposures", "default-logins"],
    "backup_archive":["exposures"],
}

# Tech string → Nuclei tags (for Subfinder/Katana/HTTP probe technologies)
_TECH_TO_NUCLEI: Dict[str, List[str]] = {
    "wordpress":   ["wordpress", "wp-plugin", "cve"],
    "drupal":      ["drupal", "cve"],
    "joomla":      ["joomla", "cve"],
    "apache":      ["apache", "cve", "misconfiguration"],
    "nginx":       ["nginx", "cve", "misconfiguration"],
    "iis":         ["iis", "microsoft", "cve"],
    "php":         ["php", "cve"],
    "laravel":     ["laravel", "php", "cve"],
    "django":      ["django", "misconfiguration"],
    "spring":      ["spring", "java", "cve"],
    "tomcat":      ["tomcat", "apache", "cve"],
    "jenkins":     ["jenkins", "cve", "default-logins"],
    "gitlab":      ["gitlab", "cve"],
    "grafana":     ["grafana", "cve"],
    "react":       ["api", "javascript"],
    "angular":     ["api", "javascript"],
    "vue":         ["api", "javascript"],
    "next.js":     ["api", "javascript"],
    "cloudflare":  ["cloudflare", "waf-bypass"],
    "aws":         ["aws", "cloud", "s3"],
    "azure":       ["azure", "cloud"],
    "asp.net":     ["asp", "dotnet", "cve"],
    "node":        ["nodejs", "node"],
    "express":     ["express", "nodejs"],
    "flask":       ["flask", "python"],
    "confluence":  ["confluence", "atlassian", "cve"],
    "jira":        ["jira", "atlassian", "cve"],
    "elasticsearch":["elasticsearch", "network", "cve"],
    "kibana":      ["kibana", "elasticsearch"],
    "redis":       ["redis", "network"],
    "mongodb":     ["mongodb", "network"],
    "keycloak":    ["keycloak", "cve"],
    "vmware":      ["vmware", "cve"],
    "citrix":      ["citrix", "cve"],
}


def _build_nuclei_context(
    nmap_result:      Dict[str, Any],
    subfinder_result: Optional[Dict[str, Any]] = None,
    ffuf_result:      Optional[Dict[str, Any]] = None,
    katana_result:    Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build enriched Nuclei context from ALL available scanner data.
    Returns tags, template_ids, tech_stack, scan_categories, service_summary.
    """
    tags:             set = set()
    template_ids:     set = set()
    service_summary:  List[str] = []
    tech_stack:       List[str] = []

    # ── 1. Nmap service/product → tags + CVEs ────────────────────────────────
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
                if prod_key in product or prod_key in svc:
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

        # ── 2. Nmap HTTP probe technologies (from our enhanced nmap/server.py) ──
        for port in host.get("ports", []):
            for tech in port.get("technologies", []):
                tech_lower = tech.lower()
                tech_stack.append(tech)
                for kw, kw_tags in _TECH_TO_NUCLEI.items():
                    if kw in tech_lower or tech_lower in kw:
                        tags.update(kw_tags)
                        break
            # CDN info from HTTP probe
            probe = port.get("http_probe") or {}
            cdn = probe.get("cloud") or probe.get("cdn") or ""
            if cdn:
                for kw, kw_tags in _TECH_TO_NUCLEI.items():
                    if kw in cdn.lower():
                        tags.update(kw_tags)

    # ── 3. Subfinder technologies ─────────────────────────────────────────────
    for tech in (subfinder_result or {}).get("technologies", []):
        tech_lower = tech.lower()
        tech_stack.append(tech)
        for kw, kw_tags in _TECH_TO_NUCLEI.items():
            if kw in tech_lower or tech_lower in kw:
                tags.update(kw_tags)
                break

    # CDN providers from Nmap summary
    for cdn in nmap_result.get("summary", {}).get("cdn_providers", []):
        tech_stack.append(cdn)
        for kw, kw_tags in _TECH_TO_NUCLEI.items():
            if kw in cdn.lower():
                tags.update(kw_tags)
                break

    # ── 4. FFUF severity findings → targeted tags ─────────────────────────────
    ffuf_by_sev = (ffuf_result or {}).get("by_severity", {})
    for severity_level in ("critical", "high", "medium"):
        for ep in ffuf_by_sev.get(severity_level, [])[:15]:
            cat = ep.get("category", "")
            if cat in _FFUF_TO_NUCLEI:
                tags.update(_FFUF_TO_NUCLEI[cat])
            # If admin panel found → add panels + default-logins
            if "admin" in ep.get("url", "").lower():
                tags.update(["panels", "default-logins"])

    # ── 5. Katana JS framework detection ──────────────────────────────────────
    for ep in (katana_result or {}).get("endpoints", [])[:50]:
        cat = ep.get("category", "")
        if cat in ("api", "js"):
            tags.update(["api", "javascript"])

    # ── 6. Scan categories: always include base coverage for web targets ───────
    # Added when there's any HTTP service or the target has web endpoints
    has_web = any(
        "http" in str(nmap_result.get("summary", {}).get("services", {}).get(str(p), {}).get("name", "")).lower()
        or p in {80, 443, 8080, 8443, 8888, 3000}
        for p in nmap_result.get("summary", {}).get("ports", [])
    )
    if has_web or not nmap_result.get("summary", {}).get("ports"):
        tags.update(["exposures", "misconfiguration", "panels", "api"])

    # ── 7. Ensure cloud bucket scanning if any cloud provider detected ─────────
    if any(k in " ".join(tech_stack).lower() for k in ["aws", "azure", "gcp", "s3", "cloud"]):
        tags.update(["cloud", "aws", "azure", "s3", "bucket"])

    tech_stack = list(dict.fromkeys(tech_stack))  # deduplicate

    return {
        "tags":             sorted(tags),
        "template_ids":     sorted(template_ids),
        "service_summary":  service_summary[:20],
        "tech_stack":       tech_stack[:20],
        "scan_categories":  _BASE_WEB_SCAN_CATEGORIES,
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

    # ── Retrieve all phase results from context ───────────────────────────────
    shodan_data    = ctx.get_step_result("shodan")       or {}
    subfinder_data = ctx.get_step_result("subfinder")    or {}
    nmap_data      = ctx.get_step_result("nmap")         or {}
    vt_data        = ctx.get_step_result("virustotal")   or {}
    abuse_data     = ctx.get_step_result("abuseipdb")    or {}
    zap_data       = ctx.get_step_result("zap")          or {}
    nuclei_data    = ctx.get_step_result("nuclei")       or {}
    dalfox_data    = ctx.get_step_result("dalfox")       or {}
    ffuf_data      = ctx.get_step_result("ffuf")         or {}
    katana_data    = ctx.get_step_result("katana")       or {}
    gitleaks_data  = ctx.get_step_result("gitleaks")     or {}
    sqlmap_data    = ctx.get_step_result("sqlmap")       or {}
    fp_data        = ctx.get_step_result("fp_reduction") or {}
    auth_data      = ctx.get_step_result("auth_context") or {}

    open_ports   = nmap_data.get("summary", {}).get("ports", [])
    abuse_conf   = abuse_data.get("data", {}).get("abuse_confidence_score", 0)
    secrets_crit = gitleaks_data.get("by_severity", {}).get("critical", 0)
    secrets_high = gitleaks_data.get("by_severity", {}).get("high", 0)
    secrets_total = gitleaks_data.get("total", 0)

    ffuf_by_sev   = ffuf_data.get("by_severity", {})
    ffuf_critical = len(ffuf_by_sev.get("critical", []))
    ffuf_high     = len(ffuf_by_sev.get("high", []))

    sqlmap_vuln   = sqlmap_data.get("vulnerable", False)
    sqlmap_skip   = sqlmap_data.get("skipped", False)

    # ── Executive summary (enriched with Phase 3) ─────────────────────────────
    p3_extra = []
    if secrets_total > 0:
        p3_extra.append(f"{secrets_total} secret(s) exposed")
    if sqlmap_vuln:
        p3_extra.append(f"{sqlmap_data.get('total', 0)} SQL injection(s)")
    if ffuf_critical + ffuf_high > 0:
        p3_extra.append(f"{ffuf_critical + ffuf_high} sensitive path(s)")

    executive_summary = (
        f"Target {target} presents a {risk_level} risk (score: {risk_score}/100). "
        f"{total_f} correlated findings: "
        f"{by_sev.get('critical', 0)} critical, "
        f"{by_sev.get('high', 0)} high, "
        f"{by_sev.get('medium', 0)} medium. "
        + (f"Exploitation findings: {', '.join(p3_extra)}. " if p3_extra else "")
        + f"Exploitability: {risk_report.get('exploitability_score', 0):.0f}/100 | "
        f"Confidence: {risk_report.get('confidence_score', 0):.0f}%."
    )

    # ── Top 10 findings sorted by severity then exploitability ────────────────
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

    # ── Recommendations (ordered by priority, enriched with Phase 3) ─────────
    recommendations: List[str] = []

    # Phase 3 — exploitation findings first (highest priority)
    if secrets_crit > 0:
        recommendations.append(
            f"CRITICAL: {secrets_crit} critical secret(s) exposed (API keys, private keys) — "
            "rotate immediately and audit access logs"
        )
    if sqlmap_vuln:
        sqli_params = ", ".join(sqlmap_data.get("vulnerable_params", [])[:5])
        recommendations.append(
            f"CRITICAL: SQL injection confirmed — parameter(s): {sqli_params or 'see findings'}. "
            "Apply parameterized queries immediately"
        )
    if secrets_high > 0:
        recommendations.append(
            f"HIGH: {secrets_high} high-severity secret(s) detected — audit and rotate affected credentials"
        )
    if ffuf_critical > 0:
        crit_urls = [ep.get("url", "") for ep in ffuf_by_sev.get("critical", [])[:3]]
        recommendations.append(
            f"CRITICAL: {ffuf_critical} critical path(s) exposed ({', '.join(crit_urls[:2]) or 'see FFUF findings'}) — "
            "restrict access immediately"
        )
    if ffuf_high > 0:
        recommendations.append(
            f"HIGH: {ffuf_high} sensitive path(s) accessible (admin panels, config files) — "
            "restrict or remove from public access"
        )

    # Phase 1/2 — standard vuln recommendations
    if by_sev.get("critical", 0) > 0:
        recommendations.append(
            "IMMEDIATE ACTION: Patch or isolate services with critical CVEs"
        )
    if by_sev.get("high", 0) > 0:
        recommendations.append(
            "URGENT (24-72h): Remediate high-severity findings"
        )

    risky_open = [p for p in open_ports if p in {23, 445, 3389, 5900, 6379, 27017, 1433}]
    if risky_open:
        recommendations.append(
            f"HIGH PRIORITY: Firewall or close high-risk exposed ports: {risky_open}"
        )

    if abuse_conf > 60:
        recommendations.append(
            "ALERT: IP actively flagged as malicious (AbuseIPDB) — investigate for compromise"
        )

    api_count = len(katana_data.get("api_endpoints", []))
    if api_count > 0:
        recommendations.append(
            f"MEDIUM: {api_count} API endpoint(s) discovered via JS crawling — "
            "verify authentication and authorization controls"
        )

    if risk_report.get("exploitability_score", 0) > 70:
        recommendations.append(
            "HIGH: Multiple exploitable services detected — prioritize patch management"
        )

    recommendations.append(
        "ONGOING: Enable continuous monitoring and schedule periodic rescans"
    )

    # ── Phases summary — aligned on the 5-phase pipeline ─────────────────────
    fp_reduction = correlation_report.get("fp_reduction", {})

    phases_summary = {
        "auth": {
            "phase":      "Auth Detection",
            "auth_type":  auth_data.get("auth_type", "none"),
            "detected":   auth_data.get("detected", False),
            "authenticated": auth_data.get("has_auth", False),
            "login_url":  auth_data.get("login_url"),
            "notes":      auth_data.get("notes", ""),
            "status":     "error" if auth_data.get("error") else "complete",
        },
        "phase_1_recon": {
            "phase":            "Phase 1 — Recon",
            "tools":            ["Shodan", "Subfinder", "Nmap", "AbuseIPDB", "VirusTotal"],
            "status":           "error" if (nmap_data.get("error") and subfinder_data.get("error")) else "complete",
            # Shodan
            "shodan_ports":     len(shodan_data.get("data", {}).get("internetdb", {}).get("ports", [])),
            "shodan_cves":      len(shodan_data.get("data", {}).get("internetdb", {}).get("vulns", [])),
            # Subfinder / httpx
            "subdomains_found": subfinder_data.get("subdomains_count", 0),
            "live_hosts":       subfinder_data.get("live_count", 0),
            "technologies":     subfinder_data.get("technologies", []),
            # Nmap
            "open_ports":       len(open_ports),
            "hosts_found":      nmap_data.get("summary", {}).get("host_count", 0),
            "nmap_error":       nmap_data.get("error"),
            # Threat Intel
            "abuse_confidence": abuse_conf,
            "vt_malicious":     vt_data.get("data", {}).get("malicious", 0),
        },
        "phase_2_active_scan": {
            "phase":            "Phase 2 — Active Scan",
            "tools":            ["OWASP ZAP", "Nuclei", "Dalfox"],
            "status":           "error" if (zap_data.get("error") and nuclei_data.get("error")) else "complete",
            # ZAP
            "zap_alerts":       zap_data.get("total", 0),
            "zap_high":         zap_data.get("by_risk", {}).get("High", 0),
            "zap_medium":       zap_data.get("by_risk", {}).get("Medium", 0),
            "zap_endpoints":    len(zap_data.get("endpoints", [])),
            "zap_error":        zap_data.get("error"),
            # Nuclei
            "nuclei_findings":  nuclei_data.get("total", 0),
            "nuclei_critical":  nuclei_data.get("by_severity", {}).get("critical", 0),
            "nuclei_high":      nuclei_data.get("by_severity", {}).get("high", 0),
            "max_cvss":         nuclei_data.get("max_cvss"),
            "nuclei_error":     nuclei_data.get("error"),
            # Dalfox
            "dalfox_xss":       dalfox_data.get("total", 0),
            "dalfox_error":     dalfox_data.get("error"),
        },
        "phase_3_exploitation": {
            "phase":            "Phase 3 — Exploitation",
            "tools":            ["FFUF", "Katana", "GitLeaks", "SQLMap"],
            "status":           "complete",
            # FFUF
            "ffuf_total":       ffuf_data.get("total", 0),
            "ffuf_critical":    ffuf_critical,
            "ffuf_high":        ffuf_high,
            "ffuf_error":       ffuf_data.get("error"),
            # Katana
            "katana_endpoints": katana_data.get("total", 0),
            "katana_api":       api_count,
            "katana_error":     katana_data.get("error"),
            # GitLeaks
            "secrets_total":    secrets_total,
            "secrets_critical": secrets_crit,
            "secrets_high":     secrets_high,
            "gitleaks_error":   gitleaks_data.get("error"),
            # SQLMap
            "sqlmap_ran":       not sqlmap_skip,
            "sqlmap_vulnerable": sqlmap_vuln,
            "sqlmap_findings":  sqlmap_data.get("total", 0),
            "sqlmap_params":    sqlmap_data.get("vulnerable_params", []),
            "sqlmap_skip_reason": sqlmap_data.get("reason") if sqlmap_skip else None,
            "sqlmap_error":     sqlmap_data.get("error"),
        },
        "phase_4_correlation": {
            "phase":            "Phase 4 — Correlation",
            "tools":            ["Correlation Engine", "FP Reduction", "Risk Scoring"],
            "status":           "error" if correlation_report.get("error") else "complete",
            "total_correlated": total_f,
            "sources_used":     correlation_report.get("correlated_sources", []),
            "attack_paths":     len(correlation_report.get("attack_paths", [])),
            "service_vuln_map": len(correlation_report.get("service_vuln_map", {})),
            # FP Reduction
            "fp_original":      fp_data.get("original_count", 0),
            "fp_final":         fp_data.get("final_count", total_f),
            "fp_confirmed":     fp_reduction.get("confirmed", 0),
            "fp_suspicious":    fp_reduction.get("suspicious", 0),
            "fp_reduction_rate": fp_data.get("fp_reduction_rate", 0),
            # Risk Scoring
            "risk_score":       risk_score,
            "risk_level":       risk_level,
            "exploitability":   risk_report.get("exploitability_score", 0),
            "confidence":       risk_report.get("confidence_score", 0),
        },
        "phase_5_soc_dashboard": {
            "phase":            "Phase 5 — SOC Dashboard",
            "tools":            ["SOC Report", "AI Analysis"],
            "status":           "complete",
            "top_findings_count": len(top_findings),
            "recommendations_count": len(recommendations),
            "attack_paths_count": len(correlation_report.get("attack_paths", [])),
        },
    }

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
        "phases_summary":     phases_summary,
        "generated_at":       datetime.utcnow().isoformat(),
    }


# ── Fallback AI analysis (rule-based, no LLM needed) ─────────────────────────


def _build_fallback_ai_analysis(
    target: str,
    risk_score: int,
    correlation_report: Dict[str, Any],
    soc_report: Dict[str, Any],
    reason: str = "",
) -> Dict[str, Any]:
    """
    Génère une analyse structurée sans LLM.
    Appelé quand Gemini est indisponible, désactivé, ou retourne une erreur.
    Ne retourne jamais N/A — utilise les findings corrélatés comme source.
    Produit la même structure JSON qu'une vraie réponse IA.
    """
    by_sev       = correlation_report.get("by_severity", {})
    findings     = correlation_report.get("correlated_findings", [])
    confirmed    = [f for f in findings if f.get("fp_status") == "confirmed"]
    attack_paths = correlation_report.get("attack_paths", [])
    recs         = soc_report.get("recommendations", [])

    # Risk level from score
    if risk_score >= 80:   risk_level = "Critical"
    elif risk_score >= 60: risk_level = "High"
    elif risk_score >= 40: risk_level = "Medium"
    elif risk_score >= 20: risk_level = "Low"
    else:                  risk_level = "Informational"

    n_crit = by_sev.get("critical", 0)
    n_high = by_sev.get("high",     0)
    n_med  = by_sev.get("medium",   0)
    n_conf = len(confirmed)

    soc_summary = (
        f"Target {target}: {risk_level} risk (score {risk_score}/100). "
        f"{n_conf} confirmed finding(s) — critical: {n_crit}, high: {n_high}, medium: {n_med}. "
        + (f"Primary vector: {attack_paths[0][:120]}." if attack_paths else "No active attack paths.")
    )

    exec_summary = soc_report.get("executive_summary") or soc_summary

    # Top findings sorted by severity
    _rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}
    top = sorted(confirmed[:6], key=lambda f: _rank.get(f.get("severity", "info"), 0), reverse=True)
    top_vulns = []
    for i, f in enumerate(top, 1):
        sev  = f.get("severity", "info")
        port = f.get("affected_port", "")
        svc  = f.get("affected_service", "")
        component = f"{svc} port {port}".strip() if port else svc or f.get("matched_at", "")[:60]
        top_vulns.append({
            "rank":               i,
            "title":              f.get("title", "Unknown finding"),
            "severity":           sev,
            "cvss_score":         f.get("cvss_score"),
            "cve_ids":            f.get("cve_ids", []),
            "affected_component": component,
            "technical_explanation": (
                f.get("attack_path") or
                f"Detected by {', '.join(f.get('sources', []))}. See scan details."
            ),
            "business_impact": (
                "Potential unauthorized access, data exfiltration, or service disruption."
                if sev in ("critical", "high") else
                "Information disclosure or potential attack surface expansion."
            ),
            "remediation":        "Apply vendor patches and review service configuration.",
            "remediation_effort": "4h" if sev in ("critical", "high") else "1day",
            "priority":           "immediate" if sev == "critical" else "72h" if sev == "high" else "1week",
        })

    # Roadmap from SOC recommendations
    immediate = [r for r in recs if any(k in r for k in ("CRITICAL", "IMMEDIATE", "SQL", "secret"))][:3]
    urgent    = [r for r in recs if any(k in r for k in ("URGENT", "HIGH", "72h"))][:3]
    ongoing   = [r for r in recs if "ONGOING" in r][:2]

    return {
        "risk_level":          risk_level,
        "soc_summary":         soc_summary,
        "executive_summary":   exec_summary,
        "risk_score_analysis": (
            f"Score {risk_score}/100 — rule-based derivation from {n_conf} confirmed findings "
            f"(AI analysis unavailable: {reason or 'no key or disabled'})."
        ),
        "attack_narrative": (
            attack_paths[0] if attack_paths else
            f"No exploitable attack chain identified for {target} in this scan."
        ),
        "attack_phases": [],
        "top_vulnerabilities": top_vulns,
        "remediation_roadmap": [
            {"phase": "Immediate (0-24h)",       "actions": immediate or ["Review critical findings immediately"]},
            {"phase": "Short-term (72h-1 week)", "actions": urgent    or ["Patch high-severity issues"]},
            {"phase": "Ongoing",                 "actions": ongoing   or ["Enable continuous monitoring"]},
        ],
        "compliance_violations": [],
        "headers_analysis":      "Manual review of security headers recommended.",
        "false_positive_assessment": (
            f"Rule-based classification: {n_conf} confirmed, "
            f"{len([f for f in findings if f.get('fp_status') == 'suspicious'])} suspicious."
        ),
        "detection_confidence": "medium",
        "model_used":           "rule-based-fallback",
        "provider":             "fallback",
        "fallback":             True,
        "fallback_reason":      reason or "AI analysis not available",
    }


# ── Celery task ───────────────────────────────────────────────────────────────


@celery_app.task(
    bind=True,
    name="scan_tasks.run_scan",
    max_retries=3,
    default_retry_delay=30,
    soft_time_limit=3600,
    time_limit=3900,
    queue="default",
)
def run_scan(self, scan_id: str, credentials: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from app.models.scan import Scan, ScanStatus
    from app.models.recon_result import ReconnaissanceResult
    from app.services.shodan_service import query_shodan
    from app.services.virustotal_service import query_virustotal
    from app.services.abuseipdb_service import query_abuseipdb
    from app.correlation_engine.correlator import correlate
    from app.risk_engine.scorer import compute_enhanced_risk_score
    from app.workers.pipeline_timer import PipelineTimer
    from app.workers.pipeline_logger import make_pipeline_logger
    from app.services.auth_detector import (
        detect_and_authenticate, AuthCredentials, AuthContext, AuthType,
    )

    db   = _get_db_session()
    r    = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
    loop = asyncio.new_event_loop()
    ctx: Optional[PipelineContext] = None
    scan = None

    timer = PipelineTimer(scan_id, total_budget=3000, redis_client=r)
    plog  = make_pipeline_logger(scan_id, settings.REDIS_URL)

    try:
        scan = db.query(Scan).filter(Scan.id == uuid.UUID(scan_id)).first()
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return {"error": "scan not found"}

        target = scan.target
        ctx    = PipelineContext(scan_id, settings.REDIS_URL, db)
        plog.info(f"Scan started for target: {target}", tool="orchestrator")

        _update_scan(db, scan, status=ScanStatus.running, progress=0, current_phase="initializing")
        _publish(r, scan_id, "running", 0, "Scan pipeline started")
        _add_log(db, scan_id, f"Scan started for target: {target}")

        # ════════════════════════════════════════════════════════════════════
        # PHASE 1 — RECON  (0 → 25%)
        # Parallel: Shodan ∥ Subfinder ∥ Nmap ∥ AbuseIPDB ∥ VirusTotal
        # ════════════════════════════════════════════════════════════════════
        _update_scan(db, scan, current_phase="recon", progress=2)
        _publish(r, scan_id, "running", 2,
                 "[Phase 1/5] Recon — Shodan ∥ Subfinder ∥ Nmap ∥ AbuseIPDB ∥ VirusTotal (parallel)...")
        _add_log(db, scan_id,
                 "═══ Phase 1/5: Recon (Shodan ∥ Subfinder ∥ Nmap ∥ AbuseIPDB ∥ VirusTotal) ═══")

        async def _do_phase1():
            async def _safe_shodan():
                try:
                    return await query_shodan(target)
                except Exception as exc:
                    return {"error": str(exc), "data": {}}

            async def _safe_vt():
                try:
                    return await query_virustotal(target)
                except Exception as exc:
                    return {"error": str(exc), "data": {}}

            async def _safe_abuse():
                try:
                    return await query_abuseipdb(target)
                except Exception as exc:
                    return {"error": str(exc), "data": {}}

            return await asyncio.gather(
                _safe_shodan(),
                _call_subfinder(target, timeout=90),
                _call_nmap(target),
                _safe_vt(),
                _safe_abuse(),
            )

        (
            shodan_result, subfinder_result, nmap_result, vt_result, abuse_result
        ) = loop.run_until_complete(_do_phase1())

        # Log Shodan
        if shodan_result.get("error"):
            _add_log(db, scan_id, f"[P1] Shodan error: {shodan_result['error']}", level="error")
        else:
            ports_found = len(shodan_result.get("data", {}).get("internetdb", {}).get("ports", []))
            vulns_found = len(shodan_result.get("data", {}).get("internetdb", {}).get("vulns", []))
            _add_log(db, scan_id,
                     f"[P1] Shodan: {ports_found} ports in public index"
                     + (f", {vulns_found} known CVEs" if vulns_found else ""))
        ctx.save_step_result("shodan", shodan_result)
        _update_scan(db, scan, shodan_data=shodan_result, progress=7)

        # Log Subfinder
        if subfinder_result.get("error"):
            _add_log(db, scan_id, f"[P1] Subfinder error: {subfinder_result['error']}", level="error")
        else:
            sub_count  = subfinder_result.get("subdomains_count", 0)
            live_count = subfinder_result.get("live_count", 0)
            techs      = subfinder_result.get("technologies", [])
            _add_log(db, scan_id,
                     f"[P1] Subfinder: {sub_count} subdomains | httpx: {live_count} live hosts"
                     + (f" | Tech: {', '.join(techs[:5])}" if techs else ""))
            for h in subfinder_result.get("live_hosts", [])[:5]:
                _add_log(db, scan_id, f"  [LIVE] {h}")
        ctx.save_step_result("subfinder", subfinder_result)
        _update_scan(db, scan, progress=11)

        # Log Nmap
        if nmap_result.get("error"):
            _add_log(db, scan_id, f"[P1] Nmap error: {nmap_result['error']}", level="error")
        else:
            summary    = nmap_result.get("summary", {})
            open_ports = summary.get("ports", [])
            cdn_note   = summary.get("cloud_note", "")
            _add_log(db, scan_id,
                     f"[P1] Nmap: {len(open_ports)} open ports, {summary.get('host_count', 0)} host(s)")
            if cdn_note:
                _add_log(db, scan_id, f"  [CDN] {cdn_note[:120]}", level="warning")
            svc_map = summary.get("services", {})
            for port_num in list(open_ports)[:10]:
                svc   = svc_map.get(str(port_num), {})
                techs = svc.get("technologies", [])
                _add_log(db, scan_id,
                         f"  Port {port_num}/{svc.get('protocol', 'tcp')} — "
                         f"{svc.get('name', 'unknown')} {svc.get('product', '')} {svc.get('version', '')}".strip()
                         + (f" | techs: {', '.join(techs[:3])}" if techs else ""))
        ctx.save_step_result("nmap", nmap_result)
        _update_scan(db, scan, nmap_data=nmap_result, progress=16)

        # Log VirusTotal
        if vt_result.get("error"):
            _add_log(db, scan_id, f"[P1] VirusTotal error: {vt_result['error']}", level="error")
        else:
            malicious = vt_result.get("data", {}).get("malicious", 0)
            _add_log(db, scan_id,
                     f"[P1] VirusTotal: {malicious} malicious detections",
                     level="warning" if malicious > 0 else "info")
        ctx.save_step_result("virustotal", vt_result)
        _update_scan(db, scan, virustotal_data=vt_result, progress=20)

        # Log AbuseIPDB
        if abuse_result.get("error"):
            _add_log(db, scan_id, f"[P1] AbuseIPDB error: {abuse_result['error']}", level="error")
        else:
            conf_abuse = abuse_result.get("data", {}).get("abuse_confidence_score", 0)
            _add_log(db, scan_id,
                     f"[P1] AbuseIPDB: confidence score {conf_abuse}%",
                     level="error" if conf_abuse > 60 else "warning" if conf_abuse > 20 else "info")
        ctx.save_step_result("abuseipdb", abuse_result)
        _update_scan(db, scan, abuseipdb_data=abuse_result, progress=22)

        # ── ThreatIntel enrichment for IPs discovered by Nmap ────────────────
        discovered_ips = _extract_discovered_ips(nmap_result, target)
        if discovered_ips:
            _add_log(db, scan_id,
                     f"[P1] {len(discovered_ips)} additional IP(s) from Nmap: "
                     f"{', '.join(discovered_ips[:5])}")
            _add_log(db, scan_id,
                     f"[P1] ThreatIntel: enriching {len(discovered_ips[:5])} discovered IP(s)...")

            async def _enrich_discovered_ips():
                ips_slice   = discovered_ips[:5]
                vt_coros    = [query_virustotal(ip) for ip in ips_slice]
                abuse_coros = [query_abuseipdb(ip) for ip in ips_slice]
                return await asyncio.gather(*vt_coros, *abuse_coros, return_exceptions=True)

            enrichments   = loop.run_until_complete(_enrich_discovered_ips())
            n_ips         = len(discovered_ips[:5])
            discovered_vt:    Dict[str, Any] = {}
            discovered_abuse: Dict[str, Any] = {}
            for i, ip in enumerate(discovered_ips[:5]):
                vt_r    = enrichments[i]         if not isinstance(enrichments[i],         Exception) else {"error": str(enrichments[i])}
                abuse_r = enrichments[n_ips + i] if not isinstance(enrichments[n_ips + i], Exception) else {"error": str(enrichments[n_ips + i])}
                discovered_vt[ip]    = vt_r
                discovered_abuse[ip] = abuse_r
                if vt_r.get("data", {}).get("malicious", 0) > 0:
                    _add_log(db, scan_id, f"  VT {ip}: {vt_r['data']['malicious']} malicious", level="warning")
                ip_conf = abuse_r.get("data", {}).get("abuse_confidence_score", 0)
                if ip_conf > 20:
                    _add_log(db, scan_id, f"  AbuseIPDB {ip}: {ip_conf}%",
                             level="error" if ip_conf > 60 else "warning")
            vt_result["discovered"]    = discovered_vt
            abuse_result["discovered"] = discovered_abuse
            _update_scan(db, scan, virustotal_data=vt_result, abuseipdb_data=abuse_result)

        _update_scan(db, scan, progress=25)
        _publish(r, scan_id, "running", 25, "Phase 1/5 — Recon complete ✔")
        _add_log(db, scan_id, "Phase 1/5 complete ✔")

        # ════════════════════════════════════════════════════════════════════
        # PHASE 1.5 — AUTH DETECTION + AUTO-AUTH  (25 → 27%)
        # Détecte le type d'auth puis, sans intervention :
        #   - utilise les credentials fournis (si présents), OU
        #   - enregistre un compte aléatoire + login, OU teste des creds par défaut.
        # Le AuthContext résultant est injecté dans tous les scanners P2 et P3.
        # ════════════════════════════════════════════════════════════════════
        _add_log(db, scan_id,
                 "═══ Auth Detection — détection + authentification automatique ═══")
        if settings.AUTO_AUTH_ENABLED and not credentials:
            _add_log(db, scan_id,
                     "[Auth] Mode automatique : détection du type + tentative "
                     "d'enregistrement d'un compte aléatoire / credentials par défaut")
        auth_ctx: AuthContext = AuthContext.empty()
        try:
            creds = AuthCredentials.from_dict(credentials) if credentials else None
            auth_ctx = loop.run_until_complete(
                detect_and_authenticate(
                    target, creds,
                    timeout=25.0,
                    auto_auth=settings.AUTO_AUTH_ENABLED,
                )
            )
            auth_summary = (
                f"Auth: {auth_ctx.auth_type}"
                + (f" | login={auth_ctx.login_url}" if auth_ctx.login_url else "")
                + (f" | {len(auth_ctx.headers)} header(s), {len(auth_ctx.cookies)} cookie(s)"
                   if auth_ctx.has_auth() else " | unauthenticated scan")
                + (f" | ⚠ {auth_ctx.error}" if auth_ctx.error else "")
            )
            _add_log(db, scan_id, f"[Auth] {auth_summary}",
                     level="warning" if auth_ctx.error else "info")
            if auth_ctx.notes:
                _add_log(db, scan_id, f"[Auth] {auth_ctx.notes}")
            if auth_ctx.has_auth():
                _add_log(db, scan_id,
                         "[Auth] ✔ Session obtenue — injection dans ZAP, Nuclei, FFUF, SQLMap",
                         level="info")
            else:
                _add_log(db, scan_id,
                         "[Auth] Aucune session obtenue — scan non authentifié",
                         level="warning")
        except Exception as _auth_exc:
            _add_log(db, scan_id, f"[Auth] Detection error: {_auth_exc} — scan continues unauthenticated",
                     level="warning")
            auth_ctx = AuthContext.empty()

        ctx.save_step_result("auth_context", auth_ctx.to_dict())
        _update_scan(db, scan, auth_config=auth_ctx.to_dict(), progress=27)

        # ════════════════════════════════════════════════════════════════════
        # PHASE 2 — ACTIVE SCAN  (27 → 55%)
        # Parallel: ZAP ∥ Nuclei (enriched with Nmap Phase 1) ∥ Dalfox
        # ════════════════════════════════════════════════════════════════════
        _update_scan(db, scan, current_phase="active_scan", progress=27)
        _publish(r, scan_id, "running", 27,
                 "[Phase 2/5] Active Scan — ZAP ∥ Nuclei (enriched Nmap) ∥ Dalfox (parallel)...")
        _add_log(db, scan_id, "═══ Phase 2/5: Active Scan (ZAP ∥ Nuclei ∥ Dalfox) ═══")

        # Nuclei context built from Nmap (Phase 1) + Subfinder — FFUF/Katana not yet run
        nuclei_ctx  = _build_nuclei_context(
            nmap_result      = nmap_result,
            subfinder_result = subfinder_result,
            ffuf_result      = None,
            katana_result    = None,
        )
        n_templates = len(nuclei_ctx["template_ids"])
        n_tags      = len(nuclei_ctx["tags"])
        tech_stack  = nuclei_ctx.get("tech_stack", [])
        scan_cats   = nuclei_ctx.get("scan_categories", [])

        if tech_stack:
            _add_log(db, scan_id, f"[P2] Nuclei tech stack from Nmap: {', '.join(tech_stack[:8])}")
        _add_log(db, scan_id,
                 f"[P2] Nuclei: {n_templates} targeted CVEs, {n_tags} tags from Nmap context")

        _auth_h = auth_ctx.headers or None
        _auth_c = auth_ctx.cookies or None

        async def _do_phase2():
            return await asyncio.gather(
                _call_zap(target, auth_headers=_auth_h, auth_cookies=_auth_c),
                _call_nuclei(
                    target,
                    templates       = nuclei_ctx["template_ids"] or None,
                    tags            = nuclei_ctx["tags"] or None,
                    extra_targets   = None,
                    tech_stack      = tech_stack or None,
                    scan_categories = scan_cats or None,
                    auth_headers    = _auth_h,
                    auth_cookies    = _auth_c,
                ),
                _call_dalfox(target, timeout=90),
            )

        zap_result, nuclei_result, dalfox_result = loop.run_until_complete(_do_phase2())

        # Log ZAP
        if zap_result.get("error"):
            _add_log(db, scan_id, f"[P2] ZAP error: {zap_result['error']}", level="error")
        else:
            total_z        = zap_result.get("total", 0)
            by_risk        = zap_result.get("by_risk", {})
            endpoints_cnt  = len(zap_result.get("endpoints", []))
            implicit_ports = zap_result.get("implicit_ports", [])
            _add_log(db, scan_id,
                     f"[P2] ZAP: {total_z} alerts — high={by_risk.get('High', 0)} "
                     f"medium={by_risk.get('Medium', 0)} | "
                     f"{endpoints_cnt} endpoints, {len(implicit_ports)} implicit ports",
                     level=("error"   if by_risk.get("High",   0) > 0 else
                            "warning" if by_risk.get("Medium", 0) > 0 else "info"))
            for a in zap_result.get("alerts", []):
                if a.get("risk_code", 0) >= 3:
                    _add_log(db, scan_id,
                             f"  [HIGH] {a.get('name')} — CWE-{a.get('cwe_id', '?')} "
                             f"({a.get('count', 0)} instance(s))", level="error")
            for h in zap_result.get("abnormal_headers", []):
                _add_log(db, scan_id,
                         f"  [HEADER] {h.get('header_issue')} — risk: {h.get('risk')}",
                         level="warning")
        ctx.save_step_result("zap", zap_result)
        _update_scan(db, scan, zap_data=zap_result, progress=35)

        # Log Nuclei
        if nuclei_result.get("error"):
            _add_log(db, scan_id, f"[P2] Nuclei error: {nuclei_result['error']}", level="error")
            logger.error("Nuclei failed for %s: %s", target, nuclei_result["error"])
        else:
            total_n  = nuclei_result.get("total", 0)
            by_sev   = nuclei_result.get("by_severity", {})
            max_cvss = nuclei_result.get("max_cvss")
            _add_log(db, scan_id,
                     f"[P2] Nuclei: {total_n} findings — "
                     f"critical={by_sev.get('critical', 0)} "
                     f"high={by_sev.get('high', 0)} "
                     f"medium={by_sev.get('medium', 0)}"
                     + (f" | max CVSS: {max_cvss}" if max_cvss else ""),
                     level=("error"   if by_sev.get("critical", 0) > 0 else
                            "warning" if by_sev.get("high",     0) > 0 else "info"))
            for f in nuclei_result.get("findings", []):
                sev = f.get("severity", "")
                if sev in ("critical", "high"):
                    cves = ", ".join(f.get("cve_ids", [])) or "n/a"
                    cvss = f.get("cvss_score")
                    _add_log(db, scan_id,
                             f"  [{sev.upper()}] {f.get('name')} — CVE: {cves}"
                             + (f" | CVSS: {cvss}" if cvss else "")
                             + f" @ {f.get('matched_at')}",
                             level="error" if sev == "critical" else "warning")
        ctx.save_step_result("nuclei", nuclei_result)
        _update_scan(db, scan, nuclei_data=nuclei_result, progress=45)

        # Log Dalfox
        if dalfox_result.get("error"):
            _add_log(db, scan_id, f"[P2] Dalfox error: {dalfox_result['error']}", level="error")
        else:
            xss_total = dalfox_result.get("total", 0)
            xss_sev   = dalfox_result.get("by_severity", {})
            if xss_total > 0:
                _add_log(db, scan_id,
                         f"[P2] Dalfox XSS: {xss_total} findings — "
                         f"high={xss_sev.get('high', 0)} medium={xss_sev.get('medium', 0)}",
                         level="error" if xss_sev.get("high", 0) > 0 else "warning")
            else:
                _add_log(db, scan_id, "[P2] Dalfox XSS: No XSS vectors detected")
        ctx.save_step_result("dalfox", dalfox_result)
        _update_scan(db, scan, progress=55)
        _publish(r, scan_id, "running", 55, "Phase 2/5 — Active Scan complete ✔")
        _add_log(db, scan_id, "Phase 2/5 complete ✔")

        # ════════════════════════════════════════════════════════════════════
        # PHASE 3 — EXPLOITATION  (55 → 75%)
        # Step 3a (parallel): FFUF ∥ GitLeaks   [Katana retiré]
        # Step 3b (conditional): SQLMap — only if ZAP detected injectable params
        # ════════════════════════════════════════════════════════════════════
        _update_scan(db, scan, current_phase="exploitation", progress=57)
        _publish(r, scan_id, "running", 57,
                 "[Phase 3/5] Exploitation — FFUF ∥ GitLeaks (parallel) + SQLMap (conditionnel)...")
        _add_log(db, scan_id,
                 "═══ Phase 3/5: Exploitation (FFUF ∥ GitLeaks + SQLMap conditionnel) ═══")

        # katana_result vide — Katana retiré du pipeline
        katana_result: Dict[str, Any] = {"target": target, "skipped": True,
                                         "api_endpoints": [], "endpoints": [],
                                         "js_files": [], "params": []}

        # ── Step 3a: FFUF ∥ GitLeaks (parallel) ──────────────────────────────
        async def _do_phase3a():
            return await asyncio.gather(
                _call_ffuf(target, timeout=200, auth_headers=_auth_h, auth_cookies=_auth_c),
                _call_gitleaks(target, timeout=100),
            )

        ffuf_result, gitleaks_result = loop.run_until_complete(_do_phase3a())

        # Log FFUF
        if ffuf_result.get("error"):
            _add_log(db, scan_id, f"[P3] FFUF error: {ffuf_result['error']}", level="error")
        else:
            ep_total  = ffuf_result.get("total", 0)
            by_cat    = ffuf_result.get("by_category", {})
            sensitive = by_cat.get("sensitive", 0)
            _add_log(db, scan_id,
                     f"[P3] FFUF: {ep_total} endpoints discovered"
                     + (f" | {sensitive} sensitive paths" if sensitive else ""),
                     level="warning" if sensitive > 0 else "info")
            for ep in ffuf_result.get("categorized", {}).get("sensitive", [])[:5]:
                _add_log(db, scan_id,
                         f"  [SENSITIVE] {ep.get('url')} [{ep.get('status')}]", level="warning")
        ctx.save_step_result("ffuf", ffuf_result)
        _update_scan(db, scan, ffuf_data=ffuf_result, progress=64)

        # Log GitLeaks
        if gitleaks_result.get("error"):
            _add_log(db, scan_id, f"[P3] GitLeaks error: {gitleaks_result['error']}", level="error")
        else:
            secrets_total = gitleaks_result.get("total", 0)
            by_sev_gl     = gitleaks_result.get("by_severity", {})
            _add_log(db, scan_id,
                     f"[P3] GitLeaks: {secrets_total} secret(s) detected"
                     + (f" | critical={by_sev_gl.get('critical', 0)} high={by_sev_gl.get('high', 0)}"
                        if secrets_total else ""),
                     level=("error"   if by_sev_gl.get("critical", 0) > 0 else
                            "warning" if secrets_total > 0 else "info"))
            for leak in gitleaks_result.get("findings", [])[:3]:
                _add_log(db, scan_id,
                         f"  [SECRET] {leak.get('rule_id')} in {leak.get('file', '?')}",
                         level="error" if leak.get("severity") == "critical" else "warning")
        ctx.save_step_result("gitleaks", gitleaks_result)
        _update_scan(db, scan, gitleaks_data=gitleaks_result, progress=70)

        # ── Step 3b: SQLMap — conditionnel (params détectés par ZAP) ─────────
        from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs

        has_injectable_params = (
            len(zap_result.get("form_params", [])) > 0 or
            any(
                _parse_qs(_urlparse(ep.get("url", "")).query)
                for ep in zap_result.get("endpoints", [])[:30]
            )
        )

        if has_injectable_params:
            _add_log(db, scan_id,
                     f"[P3] SQLMap: params détectés — "
                     f"{len(zap_result.get('endpoints', []))} endpoints ZAP, "
                     f"{len(zap_result.get('form_params', []))} form params. Lancement...")
            sqlmap_result = loop.run_until_complete(
                _call_sqlmap_enriched(target, zap_result, ffuf_result, katana_result,
                                      timeout=150, auth_headers=_auth_h, auth_cookies=_auth_c)
            )
            if sqlmap_result.get("error"):
                _add_log(db, scan_id, f"[P3] SQLMap error: {sqlmap_result['error']}", level="error")
            else:
                vulnerable     = sqlmap_result.get("vulnerable", False)
                sqli_total     = sqlmap_result.get("total", 0)
                targets_tested = sqlmap_result.get("targets_tested", 0)
                _add_log(db, scan_id,
                         f"[P3] SQLMap: tested {targets_tested} targets — "
                         + ("VULNERABLE — " + str(sqli_total) + " injection(s) found"
                            if vulnerable else "No SQL injection detected"),
                         level="error" if vulnerable else "info")
                for f in sqlmap_result.get("findings", [])[:3]:
                    _add_log(db, scan_id,
                             f"  [SQLI] Param: {f.get('parameter')} | "
                             f"{f.get('technique')} | {f.get('target_url', '')[:60]}",
                             level="error")
        else:
            sqlmap_result = {
                "target":     target,
                "skipped":    True,
                "reason":     "No injectable params detected by ZAP — SQLMap skipped (FP reduction)",
                "vulnerable": False,
                "findings":   [],
                "total":      0,
            }
            _add_log(db, scan_id,
                     "[P3] SQLMap: SKIPPED — aucun paramètre injectable détecté par ZAP (réduction FP)",
                     level="info")

        ctx.save_step_result("sqlmap", sqlmap_result)
        _update_scan(db, scan, sqlmap_data=sqlmap_result, progress=75)
        _publish(r, scan_id, "running", 75, "Phase 3/5 — Exploitation complete ✔")
        _add_log(db, scan_id, "Phase 3/5 complete ✔")

        # ════════════════════════════════════════════════════════════════════
        # PHASE 4 — CORRELATION ENGINE  (75 → 90%)
        # Sequential: Correlator → FP Reduction → Risk Scoring
        # ════════════════════════════════════════════════════════════════════
        _update_scan(db, scan, current_phase="correlation", progress=77)
        _publish(r, scan_id, "running", 77,
                 "[Phase 4/5] Correlation — dedup + FP reduction + risk scoring...")
        _add_log(db, scan_id,
                 "═══ Phase 4/5: Correlation Engine (dedup + FP reduction + risk scoring) ═══")

        # ── 4a: Correlation ──────────────────────────────────────────────────
        _add_log(db, scan_id, "[P4] Corrélation de tous les findings des phases 1-3...")
        correlation_report: Dict[str, Any] = {}
        try:
            dalfox_findings = dalfox_result.get("findings", [])
            nuclei_for_corr = dict(nuclei_result)
            if dalfox_findings:
                existing_findings = list(nuclei_for_corr.get("findings", []))
                for df in dalfox_findings:
                    existing_findings.append({
                        "name":       df.get("title", "XSS"),
                        "severity":   df.get("severity", "medium"),
                        "cve_ids":    [],
                        "cwe_ids":    ["CWE-79"],
                        "cvss_score": None,
                        "matched_at": df.get("url", target),
                        "source":     "dalfox",
                    })
                nuclei_for_corr["findings"] = existing_findings

            correlation_report = correlate(
                nmap_data    = nmap_result,
                zap_data     = zap_result,
                nuclei_data  = nuclei_for_corr,
                shodan_data  = shodan_result,
                vt_data      = vt_result,
                abuse_data   = abuse_result,
                ffuf_data    = ffuf_result,
                katana_data  = katana_result,
            )
            summary_str = correlation_report.get("summary", "")
            _add_log(db, scan_id, f"[P4] Correlation: {summary_str}")

            svm = correlation_report.get("service_vuln_map", {})
            if svm:
                _add_log(db, scan_id, f"  Service→CVE map: {len(svm)} service(s) avec CVEs connus")
            for ap in correlation_report.get("attack_paths", [])[:5]:
                _add_log(db, scan_id, f"  [PATH] {ap}", level="warning")

        except Exception as exc:
            correlation_report = {"error": str(exc), "correlated_findings": []}
            _add_log(db, scan_id, f"[P4] Correlation Engine error: {exc}", level="error")
            logger.exception("Correlation Engine failed for %s", target)

        ctx.save_step_result("correlation", correlation_report)
        _update_scan(db, scan, correlated_data=correlation_report, progress=80)

        # ── 4b: FP Reduction ─────────────────────────────────────────────────
        _add_log(db, scan_id, "[P4] Classification FP (confirmed / suspicious / informational)...")
        fp_report: Dict[str, Any] = {}
        try:
            from app.fp_engine import reduce_false_positives
            from app.correlation_engine.correlator import _build_nmap_service_map
            import re as _re
            import ipaddress as _ipaddress

            service_map  = _build_nmap_service_map(nmap_result)
            raw_findings = correlation_report.get("correlated_findings", [])

            _target_host = _re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
            _is_internal = False
            try:
                _ip = _ipaddress.ip_address(_target_host)
                _is_internal = _ip.is_private or _ip.is_loopback
            except ValueError:
                _is_internal = "." not in _target_host or _target_host == "localhost"

            fp_report = reduce_false_positives(
                findings    = raw_findings,
                service_map = service_map,
                config      = {
                    "ignore_low_confidence": (
                        False if _is_internal else settings.FP_IGNORE_LOW_CONFIDENCE
                    ),
                    "require_active_source_for_medium_plus": (
                        False if _is_internal else settings.FP_REQUIRE_ACTIVE_SOURCE
                    ),
                },
            )

            correlation_report["correlated_findings"] = fp_report["filtered_findings"]
            correlation_report["fp_reduction"] = {
                "original_count":    fp_report["original_count"],
                "final_count":       fp_report["final_count"],
                "merged_total":      fp_report.get("merged_total", 0),
                "removed_total":     fp_report.get("merged_total", 0),
                "removed_by_layer":  fp_report["removed_by_layer"],
                "fp_reduction_rate": fp_report["fp_reduction_rate"],
                "by_tier":           fp_report.get("by_tier", {}),
                "confirmed":         len(fp_report.get("confirmed", [])),
                "suspicious":        len(fp_report.get("suspicious", [])),
                "informational":     len(fp_report.get("informational", [])),
            }

            by_sev_fp: Dict[str, int] = {}
            for f in fp_report["filtered_findings"]:
                sev = f.get("severity", "info")
                by_sev_fp[sev] = by_sev_fp.get(sev, 0) + 1
            correlation_report["by_severity"]    = by_sev_fp
            correlation_report["total_findings"] = fp_report["final_count"]

            by_tier = fp_report.get("by_tier", {})
            _add_log(db, scan_id,
                     f"[P4] FP Classification: {fp_report['summary']}"
                     + (" [lab mode]" if _is_internal else ""),
                     level="info")
            _add_log(db, scan_id,
                     f"  Tiers: confirmed={by_tier.get('confirmed', 0)} "
                     f"suspicious={by_tier.get('suspicious', 0)} "
                     f"informational={by_tier.get('informational', 0)} "
                     f"| merged={fp_report.get('merged_total', 0)}")
            for f in fp_report.get("suspicious", [])[:3]:
                _add_log(db, scan_id,
                         f"  [SUSPICIOUS] {f.get('title', '?')} — flags: {f.get('fp_flags', [])}",
                         level="warning")

        except Exception as exc:
            fp_report = {"error": str(exc)}
            _add_log(db, scan_id, f"[P4] FP Reduction error: {exc}", level="error")
            logger.exception("FP Reduction failed for %s", target)

        ctx.save_step_result("fp_reduction", fp_report)
        _update_scan(db, scan, correlated_data=correlation_report, progress=84)

        # ── 4c: Risk Scoring ─────────────────────────────────────────────────
        _add_log(db, scan_id, "[P4] Calcul du risk score multi-facteurs...")
        risk_report = compute_enhanced_risk_score(ctx, correlation_report)
        risk_score  = risk_report["final_score"]
        components  = risk_report.get("component_scores", {})
        _add_log(db, scan_id,
                 f"[P4] Risk Score: {risk_score}/100 | "
                 f"nuclei={components.get('nuclei_cve', 0):.0f} "
                 f"zap={components.get('zap_web', 0):.0f} "
                 f"exploit={components.get('exploitability', 0):.0f} "
                 f"port={components.get('port_exposure', 0):.0f}",
                 level="error" if risk_score >= 70 else "warning" if risk_score >= 40 else "info")
        _add_log(db, scan_id,
                 f"  Exploitability: {risk_report.get('exploitability_score', 0):.0f}/100 | "
                 f"Confidence: {risk_report.get('confidence_score', 0):.0f}% | "
                 f"Threat Intel: {risk_report.get('threat_intelligence_factor', 0):.0f}/100")

        _update_scan(db, scan, progress=90)
        _publish(r, scan_id, "running", 90,
                 f"Phase 4/5 — Correlation complete ✔ (risk={risk_score}/100)")
        _add_log(db, scan_id, "Phase 4/5 complete ✔")

        # ════════════════════════════════════════════════════════════════════
        # PHASE 5 — SOC DASHBOARD  (90 → 100%)
        # AI Analysis (optional) + SOC Report final + recommandations
        # ════════════════════════════════════════════════════════════════════
        _update_scan(db, scan, current_phase="soc_dashboard", progress=92)
        _publish(r, scan_id, "running", 92,
                 "[Phase 5/5] SOC Dashboard — top findings + rapport + recommandations...")
        _add_log(db, scan_id,
                 "═══ Phase 5/5: SOC Dashboard (top findings + rapport + recommandations) ═══")

        # ── AI Analysis ───────────────────────────────────────────────────────
        # Règle : ne jamais retourner N/A si findings > 0 ou risk_score > 0.
        # Si Gemini est indisponible/désactivé → fallback rule-based.
        ai_result: Dict[str, Any] = {}
        _gemini_key    = settings.GEMINI_API_KEY
        _anthropic_key = settings.ANTHROPIC_API_KEY
        _ai_key        = _gemini_key or _anthropic_key
        _ai_provider   = "gemini" if _gemini_key else "anthropic"
        _total_findings = correlation_report.get("total_findings", 0)

        # SOC report est déjà construit plus bas, on le passe vide au fallback
        # s'il n'est pas encore disponible — il sera complété après.
        _soc_for_fallback: Dict[str, Any] = {}

        if settings.AI_ANALYSIS_ENABLED and _ai_key:
            try:
                from app.services.ai_service import analyze_with_ai
                _all_findings  = correlation_report.get("correlated_findings", [])
                _confirmed_f   = [f for f in _all_findings if f.get("fp_status") == "confirmed"]
                _suspicious_f  = [f for f in _all_findings if f.get("fp_status") == "suspicious"]
                _ffuf_by_sev   = ffuf_result.get("by_severity", {})
                _sensitive_eps = (
                    _ffuf_by_sev.get("critical", []) + _ffuf_by_sev.get("high", [])
                ) or ffuf_result.get("categorized", {}).get("sensitive", [])
                _auth_eps      = _ffuf_by_sev.get("medium", [])
                _nmap_services = nmap_result.get("summary", {}).get("services", {})

                scan_summary = {
                    "correlated_findings":   _all_findings,
                    "confirmed_findings":    _confirmed_f,
                    "suspicious_findings":   _suspicious_f,
                    "risk_score":            risk_score,
                    "risk_components":       risk_report.get("component_scores", {}),
                    "open_ports":            nmap_result.get("summary", {}).get("ports", []),
                    "nmap_services":         _nmap_services,
                    "cdn_providers":         nmap_result.get("summary", {}).get("cdn_providers", []),
                    "tech_stack":            nuclei_ctx.get("tech_stack", []) or subfinder_result.get("technologies", []),
                    "zap_alerts":            zap_result.get("alerts", []),
                    "abnormal_headers":      zap_result.get("abnormal_headers", []),
                    "sqli_findings":         sqlmap_result.get("findings", []),
                    "xss_findings":          dalfox_result.get("findings", []),
                    "nuclei_findings":       nuclei_result.get("findings", []),
                    "endpoints_discovered":  ffuf_result.get("endpoints", []),
                    "sensitive_endpoints":   _sensitive_eps,
                    "auth_endpoints":        _auth_eps,
                    "api_endpoints":         [],   # Katana retiré du pipeline
                    "endpoint_risk_ranking": correlation_report.get("endpoint_risk_ranking", []),
                    "secrets_found":         gitleaks_result.get("findings", []),
                    "vt_malicious":          vt_result.get("data", {}).get("malicious", 0),
                    "abuse_confidence":      abuse_result.get("data", {}).get("abuse_confidence_score", 0),
                    "attack_paths":          correlation_report.get("attack_paths", []),
                }

                raw_ai = loop.run_until_complete(
                    analyze_with_ai(target, scan_summary, _ai_key,
                                    model=settings.AI_MODEL, provider=_ai_provider)
                )

                # Si l'IA retourne une erreur ou manque risk_level → fallback
                if raw_ai.get("error") or not raw_ai.get("risk_level"):
                    _reason = raw_ai.get("error", "missing risk_level in AI response")
                    _add_log(db, scan_id,
                             f"[P5] AI response incomplete ({_reason[:80]}) — fallback activé",
                             level="warning")
                    ai_result = _build_fallback_ai_analysis(
                        target, risk_score, correlation_report, _soc_for_fallback, reason=_reason
                    )
                    ai_result["ai_raw_error"] = _reason
                else:
                    ai_result = raw_ai
                    _add_log(db, scan_id,
                             f"[P5] AI ({_ai_provider}/{ai_result.get('model_used', '?')}): "
                             f"{ai_result.get('risk_level')} — "
                             f"{ai_result.get('executive_summary', '')[:100]}",
                             level="info")

            except Exception as exc:
                _add_log(db, scan_id, f"[P5] AI exception: {exc} — fallback activé", level="warning")
                ai_result = _build_fallback_ai_analysis(
                    target, risk_score, correlation_report, _soc_for_fallback, reason=str(exc)
                )
                ai_result["ai_exception"] = str(exc)
        else:
            # AI désactivé ou pas de clé — fallback si findings ou score > 0
            if _total_findings > 0 or risk_score > 0:
                _add_log(db, scan_id,
                         "[P5] AI désactivé → génération analyse rule-based (findings trouvés)",
                         level="info")
                ai_result = _build_fallback_ai_analysis(
                    target, risk_score, correlation_report, _soc_for_fallback,
                    reason="AI_ANALYSIS_ENABLED=false or no GEMINI_API_KEY",
                )
            else:
                ai_result = {"enabled": False,
                             "note": "No findings and AI disabled — set GEMINI_API_KEY to activate"}
                _add_log(db, scan_id, "[P5] AI Analysis: désactivé, aucun finding")

        _update_scan(db, scan, current_phase="soc_output", progress=96)

        # ── SOC Report final ──────────────────────────────────────────────────
        soc_report: Dict[str, Any] = {}
        try:
            soc_report = _build_soc_report(target, scan_id, risk_report, correlation_report, ctx)
            risk_level = soc_report.get("risk_level", "UNKNOWN")
            recs_count = len(soc_report.get("recommendations", []))
            top_count  = len(soc_report.get("top_findings", []))
            _add_log(db, scan_id,
                     f"[P5] SOC Report: Risk Level={risk_level} | "
                     f"{top_count} top findings | {recs_count} recommandations",
                     level="error" if risk_level in ("CRITICAL", "HIGH") else "info")
            for rec in soc_report.get("recommendations", [])[:3]:
                _add_log(db, scan_id, f"  → {rec}", level="warning")
        except Exception as exc:
            soc_report = {"error": str(exc)}
            _add_log(db, scan_id, f"[P5] SOC report error: {exc}", level="error")
            logger.exception("SOC report build failed for %s", target)

        # ── Persistance finale ────────────────────────────────────────────────
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
            correlated_data=correlation_report,
            exploitability_score=risk_report.get("exploitability_score"),
            confidence_score=risk_report.get("confidence_score"),
            correlation_score=correlation_report.get("confidence_score"),
            risk_component_scores=risk_report.get("component_scores"),
            threat_intelligence_factor=risk_report.get("threat_intelligence_factor"),
            cve_severity_factor=risk_report.get("cve_severity_factor"),
            service_exposure_factor=risk_report.get("service_exposure_factor"),
            soc_report=soc_report,
            subfinder_data=subfinder_result,
            dalfox_data=dalfox_result,
            fp_reduction_data=fp_report if not fp_report.get("error") else None,
            fp_reduction_rate=fp_report.get("fp_reduction_rate") if not fp_report.get("error") else None,
            false_positive_count=fp_report.get("removed_total") if not fp_report.get("error") else None,
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
            subfinder_data=subfinder_result,
            dalfox_data=dalfox_result,
            fp_reduction_data=fp_report if not fp_report.get("error") else None,
            ffuf_data=ffuf_result,
            sqlmap_data=sqlmap_result,
            gitleaks_data=gitleaks_result,
            katana_data=katana_result,
            ai_analysis_data=ai_result if ai_result else None,
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
        _add_log(db, scan_id,
                 f"[P5] ✔ Scan completed — {soc_report.get('executive_summary', '')}")
        _add_log(db, scan_id, "Phase 5/5 complete ✔ — Pipeline 5 phases terminé avec succès")

        logger.info(
            "Scan %s completed (risk=%d, level=%s, findings=%d) for %s",
            scan_id, risk_score,
            soc_report.get("risk_level", "?"),
            correlation_report.get("total_findings", 0),
            target,
        )
        timing_summary = timer.summary()
        plog.info(
            f"Scan completed — risk={risk_score} level={soc_report.get('risk_level')} "
            f"total_elapsed={timing_summary['total_elapsed']}s "
            f"slowest={timing_summary.get('slowest_phase')}({timing_summary.get('slowest_duration')}s)",
            tool="orchestrator",
        )

        return {
            "scan_id":             scan_id,
            "status":              "completed",
            "risk_score":          risk_score,
            "risk_level":          soc_report.get("risk_level"),
            "correlated_findings": correlation_report.get("total_findings", 0),
            "timing":              timing_summary,
        }

    except Exception as exc:
        logger.exception("Unhandled error in run_scan for %s", scan_id)
        plog.error(f"Scan failed: {exc}", tool="orchestrator")
        try:
            if scan is not None:
                _update_scan(db, scan, status=ScanStatus.failed, error_message=str(exc))
                _publish(r, scan_id, "failed", scan.progress, f"Scan failed: {exc}")
                _add_log(db, scan_id, f"Scan failed: {exc}", level="error")
        except Exception:
            pass

        if isinstance(exc, (sync_redis.ConnectionError, sync_redis.TimeoutError, SAOperationalError)):
            retry_num = self.request.retries
            countdown = 30 * (2 ** retry_num)
            logger.warning("Retrying scan %s (attempt %d/3) in %ds", scan_id, retry_num + 1, countdown)
            raise self.retry(exc=exc, countdown=countdown)
        raise

    finally:
        loop.close()
        r.close()
        if ctx is not None:
            ctx.close()
        db.close()
