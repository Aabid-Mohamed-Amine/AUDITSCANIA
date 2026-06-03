"""
Risk Engine — scoring multi-facteurs amélioré v2.

Formule pondérée (total = 100%) :
  Nuclei CVE findings          28%
  ZAP web vulnerabilities      18%
  AbuseIPDB threat intel       13%
  VirusTotal threat intel       8%
  Exploitability (Correl.)     10%
  Port exposure                 7%
  CVE severity factor           5%
  Service exposure factor       4%
  Sensitive endpoints (FFUF)    4%
  Network reachability bonus    3%
                               ───
                               100%

Anti-underestimation : si un facteur est critique (ex : CVE 9.0, AbuseIPDB >80%),
le score final est relevé au moins au niveau MEDIUM (40).
"""
from __future__ import annotations

from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from app.workers.pipeline_context import PipelineContext


# ── Facteurs individuels ─────────────────────────────────────────────────────


def _f_nuclei(nuclei_data: Dict[str, Any]) -> float:
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
        + by_sev.get("low",      0) * 1,
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


# ── Scoring principal ────────────────────────────────────────────────────────


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

    # Facteurs du Correlation Engine
    f_exploit    = float(cr.get("exploitability_score", 0.0))
    confidence   = float(cr.get("confidence_score", 50.0))
    threat_intel = float(cr.get("threat_intel_factor", 0.0))

    # Formule pondérée (= 100%)
    score = (
        f_nuclei    * 0.28
        + f_zap     * 0.18
        + f_abuse   * 0.13
        + f_vt      * 0.08
        + f_exploit * 0.10
        + f_port    * 0.07
        + f_cve_sev * 0.05
        + f_svc_exp * 0.04
        + f_endpoints * 0.04
        + f_network * 0.03
    )

    # ── Anti-underestimation guards — scanners (CVE / threat intel) ─────────
    # Critical CVE always yields at least HIGH score (60)
    if f_cve_sev >= 100.0:
        score = max(score, 65.0)
    # Active abuse signals → at least MEDIUM (40)
    if f_abuse > 80.0 or f_vt > 50.0:
        score = max(score, 45.0)
    # Dangerous exposed services → at least LOW (20)
    if f_svc_exp > 70.0:
        score = max(score, 30.0)
    # Accessible target with open ports and no findings → at least minimal
    if f_network > 30.0 and score < 10.0:
        score = 10.0

    # ── Anti-underestimation guards — correlated findings severity ───────────
    # Si le Correlation Engine a confirmé des findings, le score ne peut pas
    # rester sous le seuil correspondant à leur sévérité maximale.
    corr_by_sev = cr.get("by_severity", {})
    if corr_by_sev.get("medium", 0) >= 1:
        score = max(score, 20.0)   # medium confirmed → au moins LOW (20)
    if corr_by_sev.get("high", 0) >= 1:
        score = max(score, 40.0)   # high confirmed   → au moins MEDIUM (40)
    if corr_by_sev.get("critical", 0) >= 1:
        score = max(score, 60.0)   # critical          → au moins HIGH (60)

    final = min(int(score), 100)

    return {
        "final_score": final,
        "component_scores": {
            "nuclei_cve":       round(f_nuclei,    2),
            "zap_web":          round(f_zap,       2),
            "abuseipdb":        round(f_abuse,     2),
            "virustotal":       round(f_vt,        2),
            "exploitability":   round(f_exploit,   2),
            "port_exposure":    round(f_port,      2),
            "cve_severity":     round(f_cve_sev,   2),
            "service_exposure": round(f_svc_exp,   2),
            "endpoint_risk":    round(f_endpoints, 2),
            "network_reach":    round(f_network,   2),
        },
        "confidence_score":           round(confidence,   2),
        "exploitability_score":       round(f_exploit,    2),
        "threat_intelligence_factor": round(threat_intel, 2),
        "cve_severity_factor":        round(f_cve_sev,    2),
        "service_exposure_factor":    round(f_svc_exp,    2),
        "endpoint_risk_factor":       round(f_endpoints,  2),
    }
