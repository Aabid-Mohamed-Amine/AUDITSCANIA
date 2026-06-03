"""
Contextual Filter — élimine les findings incohérents avec le contexte du service.

Exemples de faux positifs contextuels :
  - Alerte SQL Injection sur un port 22 (SSH)
  - XSS sur un service SMTP
  - Finding "web" sur un port non-HTTP
  - CVE de type "remote code execution via web" sur un service FTP sans accès HTTP

Ce filtre est conservateur : il ne supprime que les incohérences claires.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# Ports HTTP connus
_HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 4000, 5000, 9000, 9001, 9002}

# Services qui n'exposent pas d'interface web
_NON_WEB_SERVICES = {
    "ftp", "ssh", "smtp", "pop3", "imap", "rdp", "vnc", "telnet",
    "mssql", "mysql", "postgresql", "mongodb", "redis", "ldap",
    "smb", "dns", "ntp", "snmp",
}

# Types de findings qui ne font sens que sur du web
_WEB_ONLY_TYPES = {"web_vulnerability", "xss", "sqli", "ssti", "nosqli"}

# Keywords dans les titres indiquant un vecteur web-only
_WEB_ONLY_KEYWORDS = [
    "xss", "cross-site", "sql injection", "sqli", "ssti", "template injection",
    "csrf", "open redirect", "ssrf", "server-side request",
    "path traversal via url", "directory listing", "http header",
]


def _is_web_port(port: Optional[int], service: Optional[str]) -> bool:
    if port in _HTTP_PORTS:
        return True
    if service and any(
        web_svc in service.lower()
        for web_svc in ["http", "web", "nginx", "apache", "tomcat", "iis"]
    ):
        return True
    return False


def _is_clearly_non_web(port: Optional[int], service: Optional[str]) -> bool:
    if port is None:
        return False
    if port in _HTTP_PORTS:
        return False
    svc = (service or "").lower()
    return any(s in svc for s in _NON_WEB_SERVICES)


def _title_has_web_keyword(title: str) -> bool:
    t = title.lower()
    return any(kw in t for kw in _WEB_ONLY_KEYWORDS)


def is_contextually_valid(finding: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Vérifie la cohérence contextuelle d'un finding.

    Retourne (is_valid, reason).
    """
    finding_type = (finding.get("type") or "").lower()
    severity = (finding.get("severity") or "info").lower()
    port = finding.get("affected_port")
    service = finding.get("affected_service") or ""
    title = finding.get("title") or ""

    # Les exposures (services risqués exposés) sont toujours valides
    if finding_type == "exposure":
        return True, "exposure_always_valid"

    # Finding de type web_vulnerability sur un service clairement non-web → FP probable
    # Seulement si la confiance est très basse (scanner passif seul sans confirmation)
    if finding_type in _WEB_ONLY_TYPES or _title_has_web_keyword(title):
        if _is_clearly_non_web(port, service):
            confidence = finding.get("confidence_score", 0)
            conf_norm = confidence if isinstance(confidence, float) and confidence <= 1.0 else (confidence / 100.0 if isinstance(confidence, (int, float)) else 0.0)
            if conf_norm < 0.50:
                return False, f"web_finding_on_non_web_service: port={port} service={service}"

    return True, "context_ok"


def filter_by_context(
    findings: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Applique le filtre contextuel à une liste de findings.

    Retourne (valid_findings, removed_count).
    """
    valid: List[Dict[str, Any]] = []
    removed = 0

    for finding in findings:
        is_valid, reason = is_contextually_valid(finding)
        finding["_fp_context_validation"] = reason
        if is_valid:
            valid.append(finding)
        else:
            removed += 1

    return valid, removed
