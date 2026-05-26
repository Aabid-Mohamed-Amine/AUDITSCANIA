"""
Risk Engine — scoring multi-facteurs amélioré.

Formule (poids = 100%) :
  Nuclei CVE findings        30%   ─┐
  ZAP web vulnerabilities    20%    │  Base scanners
  AbuseIPDB threat intel     15%    │
  VirusTotal threat intel    10%   ─┘
  Exploitability (Correl.)   10%   ─┐  Nouveaux facteurs
  Port exposure               7%    │
  CVE severity factor         5%    │
  Service exposure factor     3%   ─┘
                             ─────
                             100%

Retourne un dict RiskReport avec score final + scores par composant.
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
    if max_cvss >= 9.0:
        return min(max_cvss * 10.0, 100.0)
    return min(
        by_sev.get("critical", 0) * 25
        + by_sev.get("high",     0) * 10
        + by_sev.get("medium",   0) * 3
        + by_sev.get("low",      0) * 1,
        100.0,
    )


def _f_zap(zap_data: Dict[str, Any]) -> float:
    if zap_data.get("error"):
        return 0.0
    by_risk = zap_data.get("by_risk", {})
    return min(
        by_risk.get("Critical", 0) * 25
        + by_risk.get("High",   0) * 15
        + by_risk.get("Medium", 0) * 6
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
    return min(len(open_ports) * 3 + risky_found * 15, 100.0)


def _f_cve_severity(nuclei_data: Dict[str, Any]) -> float:
    """Score basé sur le CVSS maximum trouvé (facteur qualitatif)."""
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
    """Score basé sur l'exposition de services critiques sur internet."""
    if nmap_data.get("error"):
        return 0.0
    HIGH_RISK   = {23: 100, 445: 90, 3389: 85, 5900: 80, 6379: 80, 27017: 80, 1433: 75}
    MEDIUM_RISK = {21: 55, 22: 40, 3306: 65, 5432: 65}
    open_ports  = set(nmap_data.get("summary", {}).get("ports", []))
    score = 0.0
    for port, weight in HIGH_RISK.items():
        if port in open_ports:
            score = max(score, float(weight))
    for port, weight in MEDIUM_RISK.items():
        if port in open_ports:
            score = max(score, float(weight) * 0.5)
    return min(score, 100.0)


# ── Scoring principal ────────────────────────────────────────────────────────


def compute_enhanced_risk_score(
    ctx: "PipelineContext",
    correlation_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Scoring multi-facteurs amélioré.

    Returns dict avec :
      final_score              int  0-100
      component_scores         dict par facteur
      confidence_score         float (depuis Correlation Engine)
      exploitability_score     float (depuis Correlation Engine)
      threat_intelligence_factor float
      cve_severity_factor      float
      service_exposure_factor  float
    """
    nuclei_data  = ctx.get_step_result("nuclei")     or {}
    zap_data     = ctx.get_step_result("zap")        or {}
    abuse_data   = ctx.get_step_result("abuseipdb")  or {}
    vt_data      = ctx.get_step_result("virustotal") or {}
    nmap_data    = ctx.get_step_result("nmap")       or {}

    cr = correlation_report or {}

    f_nuclei   = _f_nuclei(nuclei_data)
    f_zap      = _f_zap(zap_data)
    f_abuse    = _f_abuseipdb(abuse_data)
    f_vt       = _f_virustotal(vt_data)
    f_port     = _f_port_exposure(nmap_data)
    f_cve_sev  = _f_cve_severity(nuclei_data)
    f_svc_exp  = _f_service_exposure(nmap_data)

    # Facteurs issus du Correlation Engine
    f_exploit      = float(cr.get("exploitability_score", 0.0))
    confidence     = float(cr.get("confidence_score", 50.0))
    threat_intel   = float(cr.get("threat_intel_factor", 0.0))

    # Formule pondérée (total = 100%)
    score = (
        f_nuclei  * 0.30
        + f_zap   * 0.20
        + f_abuse * 0.15
        + f_vt    * 0.10
        + f_exploit * 0.10
        + f_port  * 0.07
        + f_cve_sev * 0.05
        + f_svc_exp * 0.03
    )

    final = min(int(score), 100)

    return {
        "final_score": final,
        "component_scores": {
            "nuclei_cve":       round(f_nuclei,  2),
            "zap_web":          round(f_zap,     2),
            "abuseipdb":        round(f_abuse,   2),
            "virustotal":       round(f_vt,      2),
            "exploitability":   round(f_exploit, 2),
            "port_exposure":    round(f_port,    2),
            "cve_severity":     round(f_cve_sev, 2),
            "service_exposure": round(f_svc_exp, 2),
        },
        "confidence_score":           round(confidence,   2),
        "exploitability_score":       round(f_exploit,    2),
        "threat_intelligence_factor": round(threat_intel, 2),
        "cve_severity_factor":        round(f_cve_sev,    2),
        "service_exposure_factor":    round(f_svc_exp,    2),
    }
