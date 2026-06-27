"""
Risk Engine — scoring multi-facteurs v6.

Basé uniquement sur findings CONFIRMÉS par scanners actifs (pas de lab challenges).

Formule pondérée (total = 100%) :
  SQLMap SQLi confirmé         22%  ← finding le plus probant
  Exploitability (Correl.)     18%
  Nuclei CVE/misconfig         14%
  ZAP web vulnerabilities      13%
  IDOR Broken Access Control   10%
  Nikto server misconfigs       7%
  Wapiti web app vulns          6%
  Sensitive endpoints (FFUF)    5%
  AbuseIPDB threat intel        3%
  VirusTotal threat intel       2%
                               ───
                               100%

Guards (findings confirmés uniquement) :
  SQLi confirmé (f_sqlmap ≥ 80)   → score min 90 (Critical)
  IDOR confirmé (f_idor ≥ 60)     → score min 70 (High)
  CVE critique (CVSS ≥ 9)         → score min 75
  AbuseIPDB > 80% ou VT > 50%     → score min 60
  Service dangereux exposé        → score min 50
  Corr. high confirmé             → score min 50
  Corr. critical confirmé         → score min 75
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

import ipaddress

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from app.workers.pipeline_context import PipelineContext


# ── Facteurs individuels ─────────────────────────────────────────────────────


def _f_nuclei(nuclei_data: Dict[str, Any]) -> float:
    if str(nuclei_data.get("error", "")).startswith("Nuclei timeout after"):
        return 50.0   # timeout != no vulns -- use neutral score
    if nuclei_data.get("error"):
        return 0.0
    by_sev   = nuclei_data.get("by_severity", {})
    max_cvss = float(nuclei_data.get("max_cvss") or 0.0)
    # If critical CVSS, cap-up directly
    if max_cvss >= 9.0:
        return min(max_cvss * 10.0, 100.0)
    return min(
        by_sev.get("critical", 0) * 30
        + by_sev.get("high",     0) * 12
        + by_sev.get("medium",   0) * 4
        + by_sev.get("low",      0) * 1
        + by_sev.get("info",     0) * 0.5,
        100.0,
    )


def _f_zap(zap_data: Dict[str, Any]) -> float:
    if zap_data.get("error"):
        return 0.0
    by_risk = zap_data.get("by_risk", {})
    return min(
        by_risk.get("Critical", 0) * 30
        + by_risk.get("High",   0) * 18
        + by_risk.get("Medium", 0) * 7
        + by_risk.get("Low",    0) * 2,
        100.0,
    )


def _f_abuseipdb(abuse_data: Dict[str, Any]) -> float:
    score = float(abuse_data.get("data", {}).get("abuse_confidence_score", 0))
    for ip_abuse in abuse_data.get("discovered", {}).values():
        if isinstance(ip_abuse, dict):
            conf = ip_abuse.get("data", {}).get("abuse_confidence_score", 0)
            score = max(score, float(conf))
    return min(score, 100.0)


def _f_virustotal(vt_data: Dict[str, Any]) -> float:
    def _ratio(d: Dict[str, Any]) -> float:
        malicious = d.get("malicious", 0)
        total = sum(d.get(k, 0) for k in ["malicious", "suspicious", "harmless", "undetected"])
        if not total:
            dom   = d.get("domain", {})
            url_d = d.get("url", {})
            malicious = max(dom.get("malicious", 0), url_d.get("malicious", 0))
            total = max(
                sum(dom.get(k, 0) for k in ["malicious", "suspicious", "harmless", "undetected"]),
                sum(url_d.get(k, 0) for k in ["malicious", "suspicious", "harmless", "undetected"]),
            )
        return (malicious / total * 100.0) if total > 0 else 0.0

    if vt_data.get("error"):
        return 0.0
    score = _ratio(vt_data.get("data", {}))
    for ip_vt in vt_data.get("discovered", {}).values():
        if isinstance(ip_vt, dict) and not ip_vt.get("error"):
            score = max(score, _ratio(ip_vt.get("data", {})))
    return min(score, 100.0)


def _f_port_exposure(nmap_data: Dict[str, Any]) -> float:
    if nmap_data.get("error"):
        return 0.0
    risky_ports = {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 6379, 27017}
    open_ports  = nmap_data.get("summary", {}).get("ports", [])
    risky_found = sum(1 for p in open_ports if p in risky_ports)
    # Each open port = 3pts, each risky port = 15pts bonus, cap 100
    return min(len(open_ports) * 3 + risky_found * 15, 100.0)


def _f_cve_severity(nuclei_data: Dict[str, Any]) -> float:
    if nuclei_data.get("error"):
        return 0.0
    max_cvss = float(nuclei_data.get("max_cvss") or 0.0)
    if max_cvss >= 9.0:
        return 100.0
    if max_cvss >= 7.0:
        return 75.0
    if max_cvss >= 4.0:
        return 45.0
    return max_cvss * 10.0


def _f_service_exposure(nmap_data: Dict[str, Any]) -> float:
    if nmap_data.get("error"):
        return 0.0
    HIGH_RISK   = {23: 100, 445: 90, 3389: 85, 5900: 80, 6379: 80, 27017: 80, 1433: 75, 9200: 75}
    MEDIUM_RISK = {21: 55, 22: 40, 3306: 65, 5432: 65, 8080: 30}
    open_ports  = set(nmap_data.get("summary", {}).get("ports", []))
    score = 0.0
    for port, weight in HIGH_RISK.items():
        if port in open_ports:
            score = max(score, float(weight))
    for port, weight in MEDIUM_RISK.items():
        if port in open_ports:
            score = max(score, float(weight) * 0.5)
    return min(score, 100.0)


def _f_sensitive_endpoints(ffuf_data: Dict[str, Any]) -> float:
    """
    Score basé sur la criticité des endpoints FFUF (nouvelle classification v3).
    Utilise by_severity si disponible, sinon fallback sur by_category.
    """
    if ffuf_data.get("error") or not ffuf_data:
        return 0.0

    by_sev = ffuf_data.get("by_severity", {})
    if by_sev:
        # New severity-based scoring
        n_critical = len(by_sev.get("critical", []))
        n_high     = len(by_sev.get("high", []))
        n_medium   = len(by_sev.get("medium", []))
        score = n_critical * 40 + n_high * 20 + n_medium * 5
    else:
        # Legacy fallback
        cats      = ffuf_data.get("by_category", {})
        sensitive = cats.get("sensitive", 0)
        auth      = cats.get("auth", 0)
        api       = cats.get("api", 0)
        _HIGH_RISK_KW = {"admin", ".env", ".git", "config", "backup", "credentials", "passwd", "dump"}
        dangerous = sum(
            1 for ep in ffuf_data.get("categorized", {}).get("sensitive", [])
            if any(k in ep.get("url", "").lower() for k in _HIGH_RISK_KW)
        )
        score = dangerous * 35 + (sensitive - dangerous) * 15 + auth * 5 + api * 3

    return min(float(score), 100.0)


def _f_network_reachability(nmap_data: Dict[str, Any]) -> float:
    """
    Bonus si la cible est réellement joignable et a des ports ouverts.
    Évite de sous-estimer les cibles actives vs cibles down.
    """
    if nmap_data.get("error"):
        return 0.0
    host_count  = nmap_data.get("summary", {}).get("host_count", 0)
    open_count  = nmap_data.get("summary", {}).get("open_port_count", 0)
    hosts_down  = nmap_data.get("summary", {}).get("hosts_down", 0)

    if host_count > 0 and open_count > 0:
        return min(30.0 + open_count * 2.0, 100.0)
    if hosts_down > 0 and host_count == 0:
        return 5.0   # target unreachable → minimal exposure
    return 10.0


def _f_nikto(nikto_data: Dict[str, Any]) -> float:
    if nikto_data.get("error") or nikto_data.get("skipped"):
        return 0.0
    by_sev = nikto_data.get("by_severity", {})
    return min(
        by_sev.get("critical", 0) * 30
        + by_sev.get("high",    0) * 15
        + by_sev.get("medium",  0) * 5
        + by_sev.get("low",     0) * 1,
        100.0,
    )


def _f_wapiti(wapiti_data: Dict[str, Any]) -> float:
    if wapiti_data.get("error") or wapiti_data.get("skipped"):
        return 0.0
    by_sev = wapiti_data.get("by_severity", {})
    return min(
        by_sev.get("critical", 0) * 30
        + by_sev.get("high",    0) * 15
        + by_sev.get("medium",  0) * 5
        + by_sev.get("low",     0) * 1,
        100.0,
    )


def _f_sqlmap(sqlmap_data: Dict[str, Any]) -> float:
    """SQL injection confirmed by SQLMap — highest severity indicator."""
    if sqlmap_data.get("skipped") or sqlmap_data.get("error"):
        return 0.0
    if not sqlmap_data.get("vulnerable"):
        return 0.0
    findings = sqlmap_data.get("findings", [])
    score = 0.0
    for f in findings:
        sev = f.get("severity", "high")
        if sev == "critical":
            score += 100.0
        elif sev == "high":
            score += 80.0
        else:
            score += 50.0
    return min(score, 100.0)


def _f_idor(idor_data: Dict[str, Any]) -> float:
    """IDOR / Broken Access Control confirmed by cross-account testing."""
    if idor_data.get("skipped") or idor_data.get("error"):
        return 0.0
    total = idor_data.get("total", 0)
    if total == 0:
        return 0.0
    findings = idor_data.get("findings", [])
    score = 0.0
    for f in findings:
        sev = f.get("severity", "high")
        score += 80.0 if sev in ("critical", "high") else 50.0
    return min(score, 100.0)


# ── Scoring principal ────────────────────────────────────────────────────────


def _target_ip_is_private(abuse_data: Dict[str, Any]) -> bool:
    """Return True if the IP queried for AbuseIPDB/VirusTotal is private (RFC1918/loopback)."""
    ip_str = abuse_data.get("data", {}).get("ip_address")
    if not ip_str:
        return False
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def compute_enhanced_risk_score(
    ctx: "PipelineContext",
    correlation_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Scoring multi-facteurs v2 avec anti-underestimation.

    Returns dict avec :
      final_score              int  0-100
      component_scores         dict par facteur
      confidence_score         float
      exploitability_score     float
      threat_intelligence_factor float
      cve_severity_factor      float
      service_exposure_factor  float
      endpoint_risk_factor     float
    """
    nuclei_data  = ctx.get_step_result("nuclei")     or {}
    zap_data     = ctx.get_step_result("zap")        or {}
    abuse_data   = ctx.get_step_result("abuseipdb")  or {}
    vt_data      = ctx.get_step_result("virustotal") or {}
    nmap_data    = ctx.get_step_result("nmap")       or {}
    ffuf_data    = ctx.get_step_result("ffuf")       or {}
    nikto_data   = ctx.get_step_result("nikto")      or {}
    wapiti_data  = ctx.get_step_result("wapiti")     or {}
    idor_data    = ctx.get_step_result("idor")       or {}
    sqlmap_data  = ctx.get_step_result("sqlmap")     or {}

    cr = correlation_report or {}

    f_nuclei    = _f_nuclei(nuclei_data)
    f_zap       = _f_zap(zap_data)
    f_abuse     = _f_abuseipdb(abuse_data)
    f_vt        = _f_virustotal(vt_data)
    f_port      = _f_port_exposure(nmap_data)
    f_cve_sev   = _f_cve_severity(nuclei_data)
    f_svc_exp   = _f_service_exposure(nmap_data)
    f_endpoints = _f_sensitive_endpoints(ffuf_data)
    f_network   = _f_network_reachability(nmap_data)
    f_nikto     = _f_nikto(nikto_data)
    f_wapiti    = _f_wapiti(wapiti_data)
    f_sqlmap    = _f_sqlmap(sqlmap_data)
    f_idor      = _f_idor(idor_data)

    # Facteurs du Correlation Engine
    f_exploit    = float(cr.get("exploitability_score", 0.0))
    confidence   = float(cr.get("confidence_score", 50.0))
    threat_intel = float(cr.get("threat_intel_factor", 0.0))

    # Formule pondérée v6 — basée uniquement sur findings confirmés (= 100%)
    # SQLMap / IDOR : facteurs dominants car preuves directes (exploit confirmé)
    # Nuclei/ZAP    : scanners actifs fiables
    # Nikto/Wapiti  : misconfigs serveur
    # Threat Intel  : contexte IP (0 pour cibles privées → renormalisé)
    score = (
        f_sqlmap    * 0.22    # SQL injection confirmé = indicateur le plus fort
        + f_exploit * 0.18    # score d'exploitabilité du corrélateur
        + f_nuclei  * 0.14    # templates CVE / misconfig
        + f_zap     * 0.13    # alertes web actives
        + f_idor    * 0.10    # broken access control confirmé
        + f_nikto   * 0.07    # misconfigs serveur
        + f_wapiti  * 0.06    # web app vulns
        + f_endpoints * 0.05  # endpoints sensibles exposés
        + f_abuse   * 0.03    # threat intel AbuseIPDB
        + f_vt      * 0.02    # threat intel VirusTotal
    )

    # Renormalize when AbuseIPDB+VirusTotal are structurally zero (private IP)
    # These factors total 5% (0.03 + 0.02) in the v6 formula
    if _target_ip_is_private(abuse_data):
        score = score / (1 - 0.05)

    # ── Guards basés sur findings confirmés uniquement ───────────────────────
    corr_by_sev = cr.get("by_severity", {})

    # SQLi confirmé → minimum CRITICAL (90)
    if f_sqlmap >= 80.0:
        score = max(score, 90.0)
    # IDOR confirmé → minimum HIGH (70)
    if f_idor >= 60.0:
        score = max(score, 70.0)
    # CVE critique (CVSS ≥ 9) → minimum HIGH (75)
    if f_cve_sev >= 100.0:
        score = max(score, 75.0)
    # Abuse/VT actifs → minimum MEDIUM-HIGH (60)
    if f_abuse > 80.0 or f_vt > 50.0:
        score = max(score, 60.0)
    # Services dangereux exposés → minimum MEDIUM (50)
    if f_svc_exp > 70.0:
        score = max(score, 50.0)
    # Cible joignable avec ports ouverts → minimum minimal (10)
    if f_network > 30.0 and score < 10.0:
        score = 10.0

    # Guards sur findings corrélés confirmés (pas de lab_challenges)
    if corr_by_sev.get("medium", 0) >= 1:
        score = max(score, 25.0)
    if corr_by_sev.get("high", 0) >= 1:
        score = max(score, 50.0)
    if corr_by_sev.get("critical", 0) >= 1:
        score = max(score, 75.0)

    correlated_findings = cr.get("total_findings", 0)
    medium_count = corr_by_sev.get("medium", 0)
    if correlated_findings >= 10 and medium_count >= 2:
        score = max(score, 45.0)

    final = min(int(score), 100)

    return {
        "final_score": final,
        "component_scores": {
            "sqlmap_sqli":      round(f_sqlmap,    2),
            "idor_bac":         round(f_idor,      2),
            "nuclei_cve":       round(f_nuclei,    2),
            "zap_web":          round(f_zap,       2),
            "exploitability":   round(f_exploit,   2),
            "nikto":            round(f_nikto,     2),
            "wapiti":           round(f_wapiti,    2),
            "endpoint_risk":    round(f_endpoints, 2),
            "abuseipdb":        round(f_abuse,     2),
            "virustotal":       round(f_vt,        2),
        },
        "confidence_score":           round(confidence,   2),
        "exploitability_score":       round(f_exploit,    2),
        "threat_intelligence_factor": round(threat_intel, 2),
        "cve_severity_factor":        round(f_cve_sev,    2),
        "service_exposure_factor":    round(f_svc_exp,    2),
        "endpoint_risk_factor":       round(f_endpoints,  2),
    }
