"""
Correlation Engine — fusionne et corrèle les résultats de tous les scanners.

Position dans le pipeline : après tous les scanners, avant le Risk Scoring.

Logique :
  A) Findings Nuclei  → corrélés aux services Nmap (port matching)
  B) Alertes ZAP      → fusionnées avec Nuclei si même port/endpoint
  C) Services risqués Nmap exposés → ajoutés comme findings d'exposition
  D) Threat Intel (VT + AbuseIPDB) → factor de menace global

Outputs :
  correlated_findings   — liste dédupliquée de findings enrichis
  service_vuln_map      — service:port → [CVE-ids]
  attack_paths          — chemins d'attaque lisibles
  exploitability_score  — 0-100
  confidence_score      — 0-100 (confiance moyenne)
  threat_intel_factor   — 0-100 (VT + AbuseIPDB blend)
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set


# ── Services à risque connus ─────────────────────────────────────────────────

RISKY_SERVICES: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    389: "ldap",
    445: "smb",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    9200: "elasticsearch",
    27017: "mongodb",
}

_SEVERITY_SCORE: Dict[str, float] = {
    "critical": 95.0,
    "high": 75.0,
    "medium": 45.0,
    "low": 20.0,
    "info": 5.0,
    "informational": 5.0,
}

_RISK_CODE_TO_SEVERITY: Dict[int, str] = {
    3: "high",
    2: "medium",
    1: "low",
    0: "info",
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
    """port → {service, product, version, protocol}"""
    service_map: Dict[int, Dict[str, str]] = {}

    for host in nmap_data.get("data", {}).get("hosts", []):
        for port_info in host.get("ports", []):
            if port_info.get("state") != "open":
                continue
            port_num = int(port_info.get("port", 0))
            if port_num:
                service_map[port_num] = {
                    "service":  port_info.get("service", ""),
                    "product":  port_info.get("product", ""),
                    "version":  port_info.get("version", ""),
                    "protocol": port_info.get("protocol", "tcp"),
                }

    for port_str, svc_info in nmap_data.get("summary", {}).get("services", {}).items():
        port_num = int(port_str) if str(port_str).isdigit() else 0
        if port_num and port_num not in service_map:
            service_map[port_num] = {
                "service":  svc_info.get("name", ""),
                "product":  svc_info.get("product", ""),
                "version":  svc_info.get("version", ""),
                "protocol": svc_info.get("protocol", "tcp"),
            }

    return service_map


def _build_attack_path(
    port: Optional[int],
    service_info: Optional[Dict[str, str]],
    cve_ids: List[str],
    cvss: Optional[float],
    finding_type: str,
) -> str:
    parts: List[str] = []

    if port and service_info:
        svc  = service_info.get("service", "unknown")
        prod = service_info.get("product", "")
        ver  = service_info.get("version", "")
        proto = service_info.get("protocol", "tcp")
        label = f"Port {port}/{proto} ({svc}"
        if prod:
            label += f" {prod}"
        if ver:
            label += f" {ver}"
        label += ")"
        parts.append(label)
    elif port:
        parts.append(f"Port {port}")

    if cve_ids:
        parts.append(" / ".join(cve_ids[:3]))
        if cvss:
            parts.append(f"CVSS {cvss:.1f}")

    suffix_map = {
        "web_vulnerability": "Web attack vector (HTTP/HTTPS)",
        "exposure":          "Unauthenticated service exposure → initial access",
        "misconfig":         "Misconfiguration → information disclosure",
        "vulnerability":     "Exploitable vulnerability → potential RCE/privilege escalation",
    }
    suffix = suffix_map.get(finding_type)
    if suffix:
        parts.append(suffix)

    return " → ".join(parts) if parts else "Unknown attack path"


# ── Moteur de corrélation principal ─────────────────────────────────────────


def correlate(
    nmap_data:    Dict[str, Any],
    zap_data:     Dict[str, Any],
    nuclei_data:  Dict[str, Any],
    shodan_data:  Dict[str, Any],
    vt_data:      Dict[str, Any],
    abuse_data:   Dict[str, Any],
) -> Dict[str, Any]:
    """
    Fusionne et corrèle tous les résultats du pipeline de scan.

    Retourne un CorrelationReport sérialisable (dict) contenant :
      - correlated_findings   : liste dédupliquée
      - service_vuln_map      : service → CVEs
      - attack_paths          : chemins d'attaque lisibles
      - exploitability_score  : 0-100
      - confidence_score      : 0-100
      - threat_intel_factor   : 0-100
      - total_findings, by_severity, summary
    """
    service_map = _build_nmap_service_map(nmap_data)
    findings: List[Dict[str, Any]] = []
    seen_cve_sets: List[frozenset] = []
    service_vuln_map: Dict[str, List[str]] = {}
    attack_paths: List[str] = []

    # ── Phase A : Findings Nuclei → corrélation avec services Nmap ──────────
    for idx, nf in enumerate(nuclei_data.get("findings", [])):
        cve_ids: List[str]     = nf.get("cve_ids") or []
        cvss: Optional[float]  = nf.get("cvss_score")
        severity: str          = nf.get("severity", "info")
        matched_at: str        = nf.get("matched_at", "")
        name: str              = nf.get("name", "Unknown finding")

        # Déduplication par ensemble de CVEs
        cve_key = frozenset(cve_ids)
        if cve_ids and any(cve_key <= existing for existing in seen_cve_sets):
            continue
        seen_cve_sets.append(cve_key)

        port = _extract_port_from_url(matched_at)
        service_info = service_map.get(port) if port else None

        # Confiance plus élevée si Nmap confirme le service
        confidence = 0.90 if service_info else 0.70

        if service_info and cve_ids:
            svc_key = f"{port}/{service_info.get('service', 'unknown')}"
            service_vuln_map.setdefault(svc_key, []).extend(cve_ids)

        attack_path = _build_attack_path(port, service_info, cve_ids, cvss, "vulnerability")
        attack_paths.append(attack_path)

        exploit_score = (
            min((cvss or 0) * 10, 100) if cvss else _SEVERITY_SCORE.get(severity, 10.0)
        )

        findings.append({
            "id":                 f"nuclei-{idx}",
            "type":               "vulnerability",
            "title":              name,
            "severity":           severity,
            "sources":            ["nuclei"] + (["nmap"] if service_info else []),
            "affected_service":   (
                f"{service_info.get('product', '')} {service_info.get('version', '')}".strip()
                if service_info else ""
            ),
            "affected_port":      port,
            "cve_ids":            cve_ids,
            "cwe_ids":            [],
            "cvss_score":         cvss,
            "exploitability_score": exploit_score,
            "confidence_score":   confidence,
            "attack_path":        attack_path,
            "matched_at":         matched_at,
        })

    # ── Phase B : Alertes ZAP → fusion avec Nuclei si même port ─────────────
    for idx, za in enumerate(zap_data.get("alerts", [])):
        risk_code: int = za.get("risk_code", 0)
        if risk_code == 0:
            continue

        name_zap: str           = za.get("name", "ZAP Alert")
        cwe_id: Optional[int]   = za.get("cwe_id")
        url: str                = za.get("url", "")
        severity_zap            = _RISK_CODE_TO_SEVERITY.get(risk_code, "info")

        port_zap = _extract_port_from_url(url)

        # Si un finding Nuclei couvre déjà ce port → augmenter la confiance
        merged = False
        for f in findings:
            if f.get("affected_port") == port_zap and port_zap is not None:
                f["sources"] = list(set(f["sources"] + ["zap"]))
                f["confidence_score"] = min(f["confidence_score"] + 0.10, 1.0)
                merged = True
                break

        if not merged:
            service_info_zap = service_map.get(port_zap) if port_zap else None
            attack_path = _build_attack_path(
                port_zap, service_info_zap, [], None, "web_vulnerability"
            )
            attack_paths.append(attack_path)

            findings.append({
                "id":                 f"zap-{idx}",
                "type":               "web_vulnerability",
                "title":              name_zap,
                "severity":           severity_zap,
                "sources":            ["zap"] + (["nmap"] if service_info_zap else []),
                "affected_service":   (
                    service_info_zap.get("service", "web") if service_info_zap else "web"
                ),
                "affected_port":      port_zap,
                "cve_ids":            [],
                "cwe_ids":            [str(cwe_id)] if cwe_id else [],
                "cvss_score":         None,
                "exploitability_score": _SEVERITY_SCORE.get(severity_zap, 10.0),
                "confidence_score":   0.75 if service_info_zap else 0.60,
                "attack_path":        attack_path,
                "matched_at":         url,
            })

    # ── Phase C : Services risqués exposés (Nmap) → findings d'exposition ───
    open_ports = set(nmap_data.get("summary", {}).get("ports", []))
    for port_num in open_ports:
        if port_num not in RISKY_SERVICES:
            continue
        already_covered = any(f.get("affected_port") == port_num for f in findings)
        if already_covered:
            continue

        svc_label   = RISKY_SERVICES[port_num]
        service_info = service_map.get(port_num, {})
        attack_path  = _build_attack_path(port_num, service_info, [], None, "exposure")
        attack_paths.append(attack_path)

        findings.append({
            "id":                 f"exposure-{port_num}",
            "type":               "exposure",
            "title":              f"Exposed {svc_label.upper()} service (port {port_num})",
            "severity":           "medium",
            "sources":            ["nmap"],
            "affected_service":   svc_label,
            "affected_port":      port_num,
            "cve_ids":            [],
            "cwe_ids":            [],
            "cvss_score":         None,
            "exploitability_score": 45.0,
            "confidence_score":   0.95,
            "attack_path":        attack_path,
            "matched_at":         f"port:{port_num}",
        })

    # ── Phase D : Calcul des scores agrégés ─────────────────────────────────

    # Score d'exploitabilité : top score pondéré + moyenne
    exploit_scores = [f.get("exploitability_score", 0.0) for f in findings]
    if exploit_scores:
        top = sorted(exploit_scores, reverse=True)
        exploitability_score = top[0] * 0.70 + (sum(top) / len(top)) * 0.30
        exploitability_score = min(exploitability_score, 100.0)
    else:
        exploitability_score = 0.0

    # Score de confiance : moyenne des findings
    conf_scores = [f.get("confidence_score", 0.0) for f in findings]
    confidence_score = (sum(conf_scores) / len(conf_scores) * 100) if conf_scores else 50.0

    # Threat Intel factor : blend VT + AbuseIPDB
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
        dom = vt_data.get("data", {}).get("domain", {})
        url_d = vt_data.get("data", {}).get("url", {})
        vt_malicious = max(dom.get("malicious", 0), url_d.get("malicious", 0))
        vt_total = max(
            sum(dom.get(k, 0) for k in ["malicious", "suspicious", "harmless", "undetected"]),
            sum(url_d.get(k, 0) for k in ["malicious", "suspicious", "harmless", "undetected"]),
        )
    vt_pct = (vt_malicious / vt_total * 100) if vt_total else 0.0
    threat_intel_factor = min(abuse_conf * 0.60 + vt_pct * 0.40, 100.0)

    # Dédupliquer attack_paths
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

    return {
        "correlated_findings":  findings,
        "service_vuln_map":     {k: list(set(v)) for k, v in service_vuln_map.items()},
        "attack_paths":         unique_paths[:20],
        "exploitability_score": round(exploitability_score, 2),
        "confidence_score":     round(confidence_score, 2),
        "threat_intel_factor":  round(threat_intel_factor, 2),
        "total_findings":       len(findings),
        "by_severity":          by_severity,
        "correlated_sources":   correlated_sources,
        "generated_at":         datetime.utcnow().isoformat(),
        "summary": (
            f"{len(findings)} correlated findings "
            f"(critical={by_severity.get('critical', 0)}, "
            f"high={by_severity.get('high', 0)}, "
            f"medium={by_severity.get('medium', 0)}) | "
            f"exploitability={exploitability_score:.0f}/100 | "
            f"confidence={confidence_score:.0f}%"
        ),
    }
