"""
Multi-Source Validator — un finding n'est retenu que s'il est confirmé
par au moins `min_sources` sources indépendantes (sauf si la sévérité
est CRITICAL, auquel qu'une seule source suffit).

Sources reconnues : nuclei, nmap, zap, shodan, virustotal, abuseipdb,
                    httpx, subfinder, dalfox, sqlmap, trivy
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

# Seuils par sévérité : (min_sources_requis)
_SEVERITY_MIN_SOURCES: Dict[str, int] = {
    "critical":      1,  # Critical → 1 source suffit
    "high":          1,  # High     → 1 source suffit
    "medium":        1,  # Medium   → 1 source suffit (mais confidence sera filtrée)
    "low":           1,  # Low      → confiance filter fera le tri
    "info":          2,  # Info     → 2 sources pour éviter le bruit
    "informational": 2,
}

# Sources considérées comme "actives" (interaction directe avec la cible)
_ACTIVE_SOURCES = {"nuclei", "nmap", "zap", "dalfox", "sqlmap", "httpx"}

# Sources "passives" (pas d'interaction directe)
_PASSIVE_SOURCES = {"shodan", "virustotal", "abuseipdb", "subfinder", "trivy"}


def validate_finding_sources(
    finding: Dict[str, Any],
    require_active_source: bool = False,
) -> Tuple[bool, str]:
    """
    Valide qu'un finding a suffisamment de sources.

    Args:
        finding: le finding corrigé
        require_active_source: si True, exige au moins 1 source active

    Retourne (is_valid, reason).
    """
    sources = set(finding.get("sources") or [])
    severity = (finding.get("severity") or "info").lower()
    min_sources = _SEVERITY_MIN_SOURCES.get(severity, 1)

    if len(sources) < min_sources:
        return False, f"insufficient_sources: {len(sources)}/{min_sources} for severity={severity}"

    if require_active_source:
        has_active = bool(sources & _ACTIVE_SOURCES)
        if not has_active:
            return False, "no_active_source_confirmation"

    return True, f"sources_ok: {sorted(sources)}"


def filter_by_source_validation(
    findings: List[Dict[str, Any]],
    require_active_for_medium_plus: bool = True,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Filtre une liste de findings par validation des sources.

    require_active_for_medium_plus : les findings medium/high/critical
    doivent avoir au moins une source active.

    Retourne (valid_findings, removed_count).
    """
    valid: List[Dict[str, Any]] = []
    removed = 0

    for finding in findings:
        severity = (finding.get("severity") or "info").lower()
        require_active = require_active_for_medium_plus and severity in {
            "medium", "high", "critical"
        }

        is_valid, reason = validate_finding_sources(
            finding, require_active_source=require_active
        )
        finding["_fp_source_validation"] = reason
        if is_valid:
            valid.append(finding)
        else:
            removed += 1

    return valid, removed
