"""
Correlation Engine — fusionne et corrèle les résultats de tous les scanners.

Phases :
  A) Nuclei findings      → corrélés aux services Nmap (port matching + CVE enrichment)
  B) ZAP alerts           → fusionnés si même port, ou ajoutés comme web findings
  C) Services risqués     → findings d'exposition depuis Nmap open ports
  D) FFUF sensitive paths → findings endpoint sensible avec risk ranking
  E) Katana API endpoints → findings surface d'attaque étendue
  F) Scores agrégés       → exploitability, confidence, threat intel
"""
from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ── Services à risque connus ─────────────────────────────────────────────────

RISKY_SERVICES: Dict[int, str] = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    53:    "dns",
    389:   "ldap",
    445:   "smb",
    1433:  "mssql",
    3306:  "mysql",
    3389:  "rdp",
    5432:  "postgresql",
    5900:  "vnc",
    6379:  "redis",
    8080:  "http-proxy",
    9200:  "elasticsearch",
    27017: "mongodb",
}

# Ports that are extremely high-risk when unauthenticated
_CRITICAL_EXPOSURE_PORTS = {22, 23, 389, 445, 1433, 3389, 5432, 5900, 6379, 9200, 27017}

_SEVERITY_SCORE: Dict[str, float] = {
    "critical":      95.0,
    "high":          75.0,
    "medium":        45.0,
    "low":           20.0,
    "info":          5.0,
    "informational": 5.0,
}

_RISK_CODE_TO_SEVERITY: Dict[int, str] = {
    3: "high",
    2: "medium",
    1: "low",
    0: "info",
}

# Keywords that elevate a sensitive endpoint finding from medium → high
_HIGH_RISK_ENDPOINT_KW = {
    "admin", "administrator", ".env", ".git", "config", "backup",
    "credentials", "passwd", "secret", "private", "phpmyadmin",
    "adminer", "wp-admin", "dump", "database", "db", "sql",
}


# ── Helpers ──────────────────────────────────────────────────────────────────


def _extract_port_from_url(url: str) -> Optional[int]:
    m = re.search(r":(\d{2,5})(?:/|$)", url)
    if m:
        p = int(m.group(1))
        return p if 1 <= p <= 65535 else None
    if url.startswith("https"):
        return 443
    if url.startswith("http"):
        return 80
    return None


def _build_nmap_service_map(nmap_data: Dict[str, Any]) -> Dict[int, Dict[str, str]]:
    """port → {service, product, version, protocol, http_title, banner}"""
    service_map: Dict[int, Dict[str, str]] = {}

    for host in nmap_data.get("data", {}).get("hosts", []):
        for port_info in host.get("ports", []):
            if port_info.get("state") != "open":
                continue
            port_num = int(port_info.get("port", 0))
            if port_num:
                service_map[port_num] = {
                    "service":       port_info.get("service", ""),
                    "product":       port_info.get("product", ""),
                    "version":       port_info.get("version", ""),
                    "protocol":      port_info.get("protocol", "tcp"),
                    "http_title":    port_info.get("http_title", ""),
                    "server_header": port_info.get("server_header", ""),
                    "banner":        port_info.get("banner", ""),
                }

    for port_str, svc_info in nmap_data.get("summary", {}).get("services", {}).items():
        port_num = int(port_str) if str(port_str).isdigit() else 0
        if port_num and port_num not in service_map:
            service_map[port_num] = {
                "service":       svc_info.get("name", ""),
                "product":       svc_info.get("product", ""),
                "version":       svc_info.get("version", ""),
                "protocol":      svc_info.get("protocol", "tcp"),
                "http_title":    svc_info.get("http_title", ""),
                "server_header": svc_info.get("server_header", ""),
                "banner":        "",
            }

    return service_map


def _build_attack_path(
    port: Optional[int],
    service_info: Optional[Dict[str, str]],
    cve_ids: List[str],
    cvss: Optional[float],
    finding_type: str,
    extra_context: str = "",
) -> str:
    parts: List[str] = []

    if port and service_info:
        svc   = service_info.get("service", "unknown")
        prod  = service_info.get("product", "")
        ver   = service_info.get("version", "")
        proto = service_info.get("protocol", "tcp")
        title = service_info.get("http_title", "")
        label = f"Port {port}/{proto} ({svc}"
        if prod:
            label += f" {prod}"
        if ver:
            label += f" {ver}"
        label += ")"
        if title:
            label += f' ["{title}"]'
        parts.append(label)
    elif port:
        parts.append(f"Port {port}")

    if cve_ids:
        parts.append(" / ".join(cve_ids[:3]))
        if cvss:
            parts.append(f"CVSS {cvss:.1f}")

    suffix_map = {
        "web_vulnerability":  "→ Web attack vector (HTTP/HTTPS) → potential data exfiltration/RCE",
        "exposure":           "→ Unauthenticated service exposure → initial foothold",
        "misconfig":          "→ Misconfiguration → information disclosure / privilege escalation",
        "vulnerability":      "→ Exploitable CVE → potential RCE / privilege escalation",
        "sensitive_endpoint": "→ Sensitive path accessible → unauthorized access / data leak",
        "api_endpoint":       "→ Exposed API surface → enumeration / injection / auth bypass",
    }
    suffix = suffix_map.get(finding_type, "")
    if suffix:
        parts.append(suffix)
    if extra_context:
        parts.append(extra_context)

    return " ".join(parts) if parts else "Unknown attack path"


def _severity_from_endpoint(url: str, status: int) -> str:
    url_lower = url.lower()
    if any(k in url_lower for k in _HIGH_RISK_ENDPOINT_KW):
        return "high"
    if status in {200, 201}:
        return "medium"
    return "low"


# ── Moteur de corrélation principal ─────────────────────────────────────────


def correlate(
    nmap_data:    Dict[str, Any],
    zap_data:     Dict[str, Any],
    nuclei_data:  Dict[str, Any],
    shodan_data:  Dict[str, Any],
    vt_data:      Dict[str, Any],
    abuse_data:   Dict[str, Any],
    ffuf_data:    Optional[Dict[str, Any]] = None,
    katana_data:  Optional[Dict[str, Any]] = None,
    lab_challenges_data: Optional[Dict[str, Any]] = None,
    nikto_data:   Optional[Dict[str, Any]] = None,
    wapiti_data:  Optional[Dict[str, Any]] = None,
    sqlmap_data:  Optional[Dict[str, Any]] = None,
    idor_data:    Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Fusionne et corrèle les résultats du pipeline de scan.

    Retourne un CorrelationReport contenant :
      - correlated_findings   : liste dédupliquée enrichie
      - service_vuln_map      : service → CVEs
      - attack_paths          : chemins d'attaque lisibles
      - endpoint_risk_ranking : endpoints classés par risque
      - exploitability_score  : 0-100
      - confidence_score      : 0-100
      - threat_intel_factor   : 0-100
      - total_findings, by_severity, summary
    """
    ffuf_data   = ffuf_data   or {}
    katana_data = katana_data or {}
    lab_challenges_data = lab_challenges_data or {}
    nikto_data  = nikto_data  or {}
    wapiti_data = wapiti_data or {}
    sqlmap_data = sqlmap_data or {}
    idor_data   = idor_data   or {}

    service_map = _build_nmap_service_map(nmap_data)
    findings: List[Dict[str, Any]] = []
    seen_cve_sets: List[frozenset]  = []
    service_vuln_map: Dict[str, List[str]] = {}
    attack_paths: List[str] = []

    # ── Phase A : Findings Nuclei → corrélation services Nmap ────────────────
    for idx, nf in enumerate(nuclei_data.get("findings", [])):
        cve_ids:    List[str]    = nf.get("cve_ids") or []
        # FIX 8 — Normaliser en majuscules pour éviter CVE-2021-1234 ≠ cve-2021-1234
        cve_ids = [c.upper() for c in cve_ids]
        cvss:       Optional[float] = nf.get("cvss_score")
        severity:   str          = nf.get("severity", "info")
        matched_at: str          = nf.get("matched_at", "")
        name:       str          = nf.get("name", "Unknown finding")
        tags:       List[str]    = nf.get("tags", [])

        cve_key = frozenset(cve_ids)
        if cve_ids and any(cve_key <= existing for existing in seen_cve_sets):
            continue
        seen_cve_sets.append(cve_key)

        port         = _extract_port_from_url(matched_at)
        service_info = service_map.get(port) if port else None

        # Confidence: higher when Nmap confirms the service, and when CVEs present
        confidence = 0.92 if service_info else (0.82 if cve_ids else 0.72)

        if service_info and cve_ids:
            svc_key = f"{port}/{service_info.get('service', 'unknown')}"
            service_vuln_map.setdefault(svc_key, []).extend(cve_ids)

        # Attack path includes http_title and banner for richer context
        extra = ""
        if service_info:
            title = service_info.get("http_title", "")
            banner = service_info.get("banner", "")
            if title:
                extra = f'(page: "{title[:60]}")'
            elif banner:
                extra = f'(banner: "{banner[:60]}")'

        attack_path = _build_attack_path(port, service_info, cve_ids, cvss, "vulnerability", extra)
        attack_paths.append(attack_path)

        exploit_score = (
            min((cvss or 0) * 10, 100) if cvss else _SEVERITY_SCORE.get(severity, 10.0)
        )

        findings.append({
            "id":                   f"nuclei-{idx}",
            "type":                 "vulnerability",
            "title":                name,
            "severity":             severity,
            "sources":              ["nuclei"] + (["nmap"] if service_info else []),
            "affected_service":     (
                f"{service_info.get('product', '')} {service_info.get('version', '')}".strip()
                if service_info else ""
            ),
            "affected_port":        port,
            "cve_ids":              cve_ids,
            "cwe_ids":              nf.get("cwe_ids", []),
            "cvss_score":           cvss,
            "epss_score":           nf.get("epss_score"),
            "tags":                 tags,
            "exploitability_score": exploit_score,
            "confidence_score":     confidence,
            "attack_path":          attack_path,
            "matched_at":           matched_at,
        })

    # ── Phase B : Alertes ZAP → fusion avec Nuclei si même port ──────────────
    for idx, za in enumerate(zap_data.get("alerts", [])):
        risk_code:   int = za.get("risk_code", 0)
        if risk_code == 0:
            continue

        name_zap:    str = za.get("name", "ZAP Alert")
        cwe_id            = za.get("cwe_id")
        severity_zap      = _RISK_CODE_TO_SEVERITY.get(risk_code, "info")

        # Derive port from first instance URI
        instances  = za.get("instances", [])
        url_zap    = instances[0].get("uri", "") if instances else ""
        port_zap   = _extract_port_from_url(url_zap) or 80

        # Merge with existing finding on same port only if type-compatible
        merged = False
        for f in findings:
            if (
                f.get("affected_port") == port_zap
                and f.get("type") in ("vulnerability", "web_vulnerability")
                and f.get("severity") == severity_zap
            ):
                f["sources"] = list(set(f["sources"] + ["zap"]))
                f["confidence_score"] = min(f["confidence_score"] + 0.10, 1.0)
                if cwe_id and str(cwe_id) not in f.get("cwe_ids", []):
                    f.setdefault("cwe_ids", []).append(str(cwe_id))
                merged = True
                break

        if not merged:
            service_info_zap = service_map.get(port_zap) if port_zap else None
            attack_path = _build_attack_path(
                port_zap, service_info_zap, [], None, "web_vulnerability",
            )
            attack_paths.append(attack_path)

            zap_conf = 0.82 if service_info_zap else 0.72

            findings.append({
                "id":                   f"zap-{idx}",
                "type":                 "web_vulnerability",
                "title":                name_zap,
                "severity":             severity_zap,
                "sources":              ["zap"] + (["nmap"] if service_info_zap else []),
                "affected_service":     service_info_zap.get("service", "web") if service_info_zap else "web",
                "affected_port":        port_zap,
                "cve_ids":              [],
                "cwe_ids":              [str(cwe_id)] if cwe_id else [],
                "cvss_score":           None,
                "epss_score":           None,
                "tags":                 ["web", "zap"],
                "exploitability_score": _SEVERITY_SCORE.get(severity_zap, 10.0),
                "confidence_score":     zap_conf,
                "attack_path":          attack_path,
                "matched_at":           url_zap,
            })

    # ── Phase C : Services risqués exposés (Nmap) ────────────────────────────
    open_ports = set(nmap_data.get("summary", {}).get("ports", []))
    for port_num in open_ports:
        if port_num not in RISKY_SERVICES:
            continue
        already_covered = any(f.get("affected_port") == port_num for f in findings)
        if already_covered:
            continue

        svc_label    = RISKY_SERVICES[port_num]
        service_info = service_map.get(port_num, {})
        is_critical  = port_num in _CRITICAL_EXPOSURE_PORTS
        severity     = "high" if is_critical else "medium"
        exploit      = 70.0 if is_critical else 45.0

        attack_path = _build_attack_path(port_num, service_info, [], None, "exposure")
        attack_paths.append(attack_path)

        findings.append({
            "id":                   f"exposure-{port_num}",
            "type":                 "exposure",
            "title":                f"Exposed {svc_label.upper()} service (port {port_num})",
            "severity":             severity,
            "sources":              ["nmap"],
            "affected_service":     svc_label,
            "affected_port":        port_num,
            "cve_ids":              [],
            "cwe_ids":              [],
            "cvss_score":           None,
            "epss_score":           None,
            "tags":                 ["network", "exposure"],
            "exploitability_score": exploit,
            "confidence_score":     0.95,
            "attack_path":          attack_path,
            "matched_at":           f"port:{port_num}",
        })

    # ── Phase D : FFUF endpoints → findings (severity-aware) ────────────────
    # Prefer new by_severity structure, fallback to old categorized.sensitive
    ffuf_by_sev   = ffuf_data.get("by_severity", {})
    sensitive_eps = (
        ffuf_by_sev.get("critical", []) + ffuf_by_sev.get("high", [])
        if ffuf_by_sev
        else ffuf_data.get("categorized", {}).get("sensitive", [])
    )
    auth_eps = (
        ffuf_by_sev.get("medium", [])
        if ffuf_by_sev
        else ffuf_data.get("categorized", {}).get("auth", [])
    )
    endpoint_risk_ranking: List[Dict[str, Any]] = []

    for ep in sensitive_eps[:50]:
        url    = ep.get("url", "")
        status = ep.get("status", 200)
        sev    = _severity_from_endpoint(url, status)
        port   = _extract_port_from_url(url) or 80
        exploit = 70.0 if sev == "high" else 45.0

        attack_path = _build_attack_path(
            port, service_map.get(port), [], None, "sensitive_endpoint",
            f"[HTTP {status}] {url}",
        )
        attack_paths.append(attack_path)

        finding = {
            "id":                   f"ffuf-sensitive-{len(findings)}",
            "type":                 "sensitive_endpoint",
            "title":                f"Sensitive path exposed: /{url.rstrip('/').rsplit('/', 1)[-1]}",
            "severity":             sev,
            "sources":              ["ffuf"],
            "affected_service":     "web",
            "affected_port":        port,
            "cve_ids":              [],
            "cwe_ids":              ["CWE-538", "CWE-200"],
            "cvss_score":           None,
            "epss_score":           None,
            "tags":                 ["web", "ffuf", "sensitive"],
            "exploitability_score": exploit,
            "confidence_score":     0.90,
            "attack_path":          attack_path,
            "matched_at":           url,
        }
        findings.append(finding)
        endpoint_risk_ranking.append({
            "url": url, "status": status, "severity": sev,
            "category": "sensitive", "risk_score": exploit,
        })

    for ep in auth_eps[:10]:
        url    = ep.get("url", "")
        status = ep.get("status", 200)
        port   = _extract_port_from_url(url) or 80
        endpoint_risk_ranking.append({
            "url": url, "status": status, "severity": "medium",
            "category": "auth", "risk_score": 40.0,
        })

    # ── Phase E : Katana API endpoints → surface d'attaque ───────────────────
    katana_apis = katana_data.get("api_endpoints", [])
    for idx, api_url in enumerate(katana_apis[:20]):
        port = _extract_port_from_url(api_url) or 80
        attack_path = _build_attack_path(
            port, service_map.get(port), [], None, "api_endpoint",
            f"Discovered via JS crawl: {api_url[:80]}",
        )
        attack_paths.append(attack_path)

        findings.append({
            "id":                   f"katana-api-{idx}",
            "type":                 "api_endpoint",
            "title":                f"API endpoint discovered: {api_url.split('/')[-1] or api_url[-40:]}",
            "severity":             "low",
            "sources":              ["katana"],
            "affected_service":     "web-api",
            "affected_port":        port,
            "cve_ids":              [],
            "cwe_ids":              ["CWE-200"],
            "cvss_score":           None,
            "epss_score":           None,
            "tags":                 ["web", "katana", "api"],
            "exploitability_score": 30.0,
            "confidence_score":     0.75,
            "attack_path":          attack_path,
            "matched_at":           api_url,
        })
        endpoint_risk_ranking.append({
            "url": api_url, "status": 0, "severity": "low",
            "category": "api", "risk_score": 30.0,
        })

    # ── Phase G : Findings Nikto → misconfigs / server issues ───────────────
    for idx, nk in enumerate(nikto_data.get("findings", [])):
        url      = nk.get("url", "")
        severity = nk.get("severity", "low")
        title    = nk.get("title", "Nikto finding")
        port     = _extract_port_from_url(url) or 80
        svc_info = service_map.get(port)

        # Boost confidence of an existing same-severity finding on the same port
        merged = False
        if severity in ("medium", "high", "critical"):
            for f in findings:
                if f.get("affected_port") == port and "nikto" not in f.get("sources", []):
                    if f.get("severity") in ("medium", "high", "critical"):
                        f["sources"] = list(set(f["sources"] + ["nikto"]))
                        f["confidence_score"] = min(f["confidence_score"] + 0.08, 1.0)
                        merged = True
                        break

        if not merged:
            attack_path = _build_attack_path(port, svc_info, [], None, "web_vulnerability")
            attack_paths.append(attack_path)
            findings.append({
                "id":                   f"nikto-{idx}",
                "type":                 "web_vulnerability",
                "title":                title,
                "severity":             severity,
                "sources":              ["nikto"] + (["nmap"] if svc_info else []),
                "affected_service":     svc_info.get("service", "web") if svc_info else "web",
                "affected_port":        port,
                "cve_ids":              [],
                "cwe_ids":              [],
                "cvss_score":           None,
                "epss_score":           None,
                "tags":                 ["web", "nikto", "misconfig"],
                "exploitability_score": _SEVERITY_SCORE.get(severity, 10.0),
                "confidence_score":     0.80,
                "attack_path":          attack_path,
                "matched_at":           url,
            })

    # ── Phase H : Findings Wapiti → SQLi / XSS / CSRF / LFI / redirect ──────
    for idx, wp in enumerate(wapiti_data.get("findings", [])):
        url      = wp.get("url", "")
        severity = wp.get("severity", "low")
        title    = wp.get("title", "Wapiti finding")
        category = wp.get("category", "")
        port     = _extract_port_from_url(url) or 80
        svc_info = service_map.get(port)

        # Boost confidence of an existing same-severity finding on the same port
        merged = False
        if severity in ("medium", "high", "critical"):
            for f in findings:
                if f.get("affected_port") == port and "wapiti" not in f.get("sources", []):
                    if f.get("severity") in ("medium", "high", "critical"):
                        f["sources"] = list(set(f["sources"] + ["wapiti"]))
                        f["confidence_score"] = min(f["confidence_score"] + 0.08, 1.0)
                        merged = True
                        break

        if not merged:
            attack_path = _build_attack_path(port, svc_info, [], None, "web_vulnerability")
            attack_paths.append(attack_path)
            cat_tag = category.lower().replace(" ", "_") if category else "web"
            findings.append({
                "id":                   f"wapiti-{idx}",
                "type":                 "web_vulnerability",
                "title":                title,
                "severity":             severity,
                "sources":              ["wapiti"] + (["nmap"] if svc_info else []),
                "affected_service":     svc_info.get("service", "web") if svc_info else "web",
                "affected_port":        port,
                "cve_ids":              [],
                "cwe_ids":              [],
                "cvss_score":           None,
                "epss_score":           None,
                "tags":                 ["web", "wapiti", cat_tag],
                "exploitability_score": _SEVERITY_SCORE.get(severity, 10.0),
                "confidence_score":     0.82,
                "attack_path":          attack_path,
                "matched_at":           url,
            })

    # ── Phase SQLMap : Findings SQLMap (injection confirmée) ────────────────────
    for idx, sf in enumerate(sqlmap_data.get("findings", [])):
        port        = _extract_port_from_url(sf.get("target_url", ""))
        sev         = sf.get("severity", "high")
        # CVSS v3.1 for SQL injection: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
        # Auth-bypass SQLi: Critical (CWE-89 + CWE-287) → 9.8
        # Standard SQLi: Critical → 9.8 (network-exploitable, no auth required)
        cvss_sqli   = 9.8 if sev == "critical" else 8.8
        attack_path = f"SQLi confirmed: {sf.get('target_url', '')} — param={sf.get('parameter', '')} [{sf.get('technique', '')}]"
        attack_paths.append(attack_path)

        findings.append({
            "id":                   f"sqlmap-{idx}",
            "type":                 "vulnerability",
            "title":                sf.get("title", "SQL Injection"),
            "severity":             sev,
            "sources":              ["sqlmap"],
            "affected_service":     "web",
            "affected_port":        port,
            "cve_ids":              [],
            "cwe_ids":              sf.get("cwe_ids", ["CWE-89"]),
            "cvss_score":           cvss_sqli,
            "epss_score":           None,
            "tags":                 ["sqli", "injection", "confirmed"],
            "exploitability_score": 98.0,
            "confidence_score":     0.98,
            "evidence":             {
                "parameter": sf.get("parameter", ""),
                "technique":  sf.get("technique", ""),
                "payload":    sf.get("payload_example", ""),
                "dbms":       sf.get("dbms", ""),
                "target_url": sf.get("target_url", ""),
            },
            "attack_path":  attack_path,
            "matched_at":   sf.get("target_url", ""),
        })

    # ── IDOR / Broken Access Control findings ────────────────────────────────
    for idx, idf in enumerate(idor_data.get("findings", [])):
        port = _extract_port_from_url(idf.get("target_url", ""))
        sev  = idf.get("severity", "high")
        # CVSS v3.1 IDOR: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5
        # With data modification: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = 8.1
        cvss_idor = 8.1 if sev in ("critical", "high") else 6.5
        exploit   = 95.0 if sev == "critical" else 82.0
        attack_path = (
            f"IDOR confirmed: {idf.get('target_url', '')} — "
            f"user A token accessed user B resource — {idf.get('evidence', 'cross-account data access')}"
        )
        attack_paths.append(attack_path)

        findings.append({
            "id":                   f"idor-{idx}",
            "type":                 "idor",
            "title":                idf.get("title", "IDOR: Unauthorized cross-account access"),
            "severity":             sev,
            "sources":              ["idor_tester"],
            "affected_service":     "web-api",
            "affected_port":        port,
            "cve_ids":              [],
            "cwe_ids":              idf.get("cwe_ids", ["CWE-639", "CWE-284"]),
            "cvss_score":           cvss_idor,
            "epss_score":           None,
            "tags":                 ["idor", "broken_access_control", "authorization", "confirmed"],
            "exploitability_score": exploit,
            "confidence_score":     0.97,
            "evidence":             idf.get("evidence", ""),
            "attack_path":          attack_path,
            "matched_at":           idf.get("target_url", ""),
        })

    # ── Phase F : Lab challenges — contexte informatif uniquement ───────────────
    # Lab challenges (OWASP Juice Shop /api/Challenges) sont des MÉTADONNÉES
    # de l'application, pas des vulnérabilités confirmées par test actif.
    # Ils ne sont PAS ajoutés aux findings correlated pour ne pas gonfler
    # les scores ni le rapport avec des résultats non prouvés.
    # Ils apparaissent dans lab_context (section annexe du rapport).
    # matched_lab_challenges contient UNIQUEMENT ceux confirmés par un scanner actif.
    lab_context: Dict[str, Any] = {}
    matched_lab_challenges: List[Dict[str, Any]] = []

    if lab_challenges_data.get("detected"):
        platform = lab_challenges_data.get("platform") or "vulnerable lab"
        all_challenges = lab_challenges_data.get("challenges", [])

        # Build keyword index from active scanner findings for cross-referencing
        _active_titles_lower = [
            f.get("title", "").lower() for f in findings
            if f.get("type") not in ("lab_challenge",)
               and f.get("sources") != ["lab_challenge_api"]
        ]
        _active_tags_lower = [
            t.lower()
            for f in findings
            for t in f.get("tags", [])
            if f.get("type") not in ("lab_challenge",)
        ]
        _CATEGORY_TO_TAGS: Dict[str, List[str]] = {
            "sql injection":             ["sqli", "sql", "injection"],
            "xss":                       ["xss", "cross-site scripting"],
            "broken access control":     ["idor", "access_control", "authorization"],
            "broken authentication":     ["auth", "jwt", "token", "login"],
            "sensitive data exposure":   ["exposure", "data", "sensitive"],
            "security misconfiguration": ["misconfig", "cors", "headers"],
            "vulnerable components":     ["cve", "vulnerability"],
            "improper input validation": ["injection", "input", "validation"],
        }

        for challenge in all_challenges:
            name     = (challenge.get("name") or "").lower()
            category = (challenge.get("category") or "").lower()
            cat_tags = _CATEGORY_TO_TAGS.get(category, [category.replace(" ", "_")])

            confirmed = (
                any(name in t or any(kw in t for kw in cat_tags) for t in _active_titles_lower)
                or any(tag in _active_tags_lower for tag in cat_tags)
            )
            if confirmed:
                matched_lab_challenges.append({
                    **challenge,
                    "confirmed_by": [
                        f.get("sources", []) for f in findings
                        if any(kw in f.get("title", "").lower() for kw in [name] + cat_tags)
                    ][:3],
                })

        lab_context = {
            "platform":  platform,
            "total":     len(all_challenges),
            "endpoint":  lab_challenges_data.get("endpoint", ""),
            "note":      "Known challenge list — informational only, not confirmed by active scanning",
        }
        logger.info(
            "[Correlator] Lab challenges: %d total, %d matched by active scanners",
            len(all_challenges), len(matched_lab_challenges),
        )
    elif lab_challenges_data.get("skipped"):
        logger.info("[Correlator] Lab Challenge API skippée (lab_mode=false) — corrélation active uniquement")

    # Exploitability: weighted blend of top score + average
    exploit_scores = [f.get("exploitability_score", 0.0) for f in findings]
    if exploit_scores:
        top = sorted(exploit_scores, reverse=True)
        base_exploit = top[0] * 0.70 + (sum(top) / len(top)) * 0.30
        sensitive_paths_count = (
            len(ffuf_data.get("by_severity", {}).get("critical", []))
            + len(ffuf_data.get("by_severity", {}).get("high", []))
            + len(ffuf_data.get("by_severity", {}).get("medium", []))
        )
        medium_findings_count = sum(1 for f in findings if f.get("severity") == "medium")
        if sensitive_paths_count >= 7:
            base_exploit = min(base_exploit + 15, 100)
        if medium_findings_count >= 2:
            base_exploit = min(base_exploit + 10, 100)
        exploitability_score = min(base_exploit, 100.0)
    else:
        exploitability_score = 0.0

    # Confidence: average across all findings
    conf_scores = [f.get("confidence_score", 0.0) for f in findings]
    confidence_score = (sum(conf_scores) / len(conf_scores) * 100) if conf_scores else 50.0

    # Threat Intel factor
    abuse_conf = float(abuse_data.get("data", {}).get("abuse_confidence_score", 0))
    for ip_abuse in abuse_data.get("discovered", {}).values():
        if isinstance(ip_abuse, dict):
            ip_conf = ip_abuse.get("data", {}).get("abuse_confidence_score", 0)
            abuse_conf = max(abuse_conf, float(ip_conf))

    vt_malicious = vt_data.get("data", {}).get("malicious", 0)
    vt_total = sum(
        vt_data.get("data", {}).get(k, 0)
        for k in ["malicious", "suspicious", "harmless", "undetected"]
    )
    if not vt_total:
        dom   = vt_data.get("data", {}).get("domain", {})
        url_d = vt_data.get("data", {}).get("url", {})
        vt_malicious = max(dom.get("malicious", 0), url_d.get("malicious", 0))
        vt_total = max(
            sum(dom.get(k, 0) for k in ["malicious", "suspicious", "harmless", "undetected"]),
            sum(url_d.get(k, 0) for k in ["malicious", "suspicious", "harmless", "undetected"]),
        )
    vt_pct = (vt_malicious / vt_total * 100) if vt_total else 0.0
    threat_intel_factor = min(abuse_conf * 0.60 + vt_pct * 0.40, 100.0)

    # Deduplicate attack paths
    seen_paths: Set[str] = set()
    unique_paths: List[str] = []
    for p in attack_paths:
        if p not in seen_paths and p != "Unknown attack path":
            seen_paths.add(p)
            unique_paths.append(p)

    by_severity: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    correlated_sources = list({s for f in findings for s in f.get("sources", [])})

    # Sort endpoint risk ranking by risk_score descending
    endpoint_risk_ranking.sort(key=lambda x: x["risk_score"], reverse=True)

    # Findings confirmed by active scanners only (no lab_challenge type)
    active_findings = [f for f in findings if f.get("type") != "lab_challenge"]
    by_severity_active: Dict[str, int] = {}
    for f in active_findings:
        sev = f.get("severity", "info")
        by_severity_active[sev] = by_severity_active.get(sev, 0) + 1

    return {
        "correlated_findings":    active_findings,
        "service_vuln_map":       {k: list(set(v)) for k, v in service_vuln_map.items()},
        "attack_paths":           unique_paths[:30],
        "endpoint_risk_ranking":  endpoint_risk_ranking[:20],
        "exploitability_score":   round(exploitability_score, 2),
        "confidence_score":       round(confidence_score, 2),
        "threat_intel_factor":    round(threat_intel_factor, 2),
        "total_findings":         len(active_findings),
        "by_severity":            by_severity_active,
        "correlated_sources":     correlated_sources,
        "lab_context":            lab_context,
        "matched_lab_challenges": matched_lab_challenges,
        "generated_at":           datetime.utcnow().isoformat(),
        "summary": (
            f"{len(active_findings)} correlated findings "
            f"(critical={by_severity_active.get('critical', 0)}, "
            f"high={by_severity_active.get('high', 0)}, "
            f"medium={by_severity_active.get('medium', 0)}) | "
            f"exploitability={exploitability_score:.0f}/100 | "
            f"confidence={confidence_score:.0f}%"
            + (f" | {len(matched_lab_challenges)} lab challenges confirmed" if matched_lab_challenges else "")
        ),
    }
