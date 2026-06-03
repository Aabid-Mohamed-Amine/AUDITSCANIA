"""
Confidence Filter — élimine les findings dont la confiance est trop basse.

Seuils configurables par sévérité :
  critical → 0.35  (un seul scanner actif suffit)
  high     → 0.45
  medium   → 0.55  (ZAP solo = 0.70, Nuclei solo = 0.75 → passe)
  low      → 0.60
  info     → 0.70  (filtre le bruit passif)
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

_DEFAULT_THRESHOLDS: Dict[str, float] = {
    "critical":      0.35,
    "high":          0.45,
    "medium":        0.55,
    "low":           0.60,
    "info":          0.70,
    "informational": 0.70,
}


def get_confidence_threshold(severity: str, custom_thresholds: Dict[str, float] | None = None) -> float:
    thresholds = _DEFAULT_THRESHOLDS.copy()
    if custom_thresholds:
        thresholds.update(custom_thresholds)
    return thresholds.get(severity.lower(), 0.65)


def filter_by_confidence(
    findings: List[Dict[str, Any]],
    custom_thresholds: Dict[str, float] | None = None,
    ignore_low_confidence: bool = True,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Filtre les findings selon leur score de confiance.

    Args:
        findings: liste de findings corrigés
        custom_thresholds: seuils personnalisés par sévérité
        ignore_low_confidence: si False, retourne tous les findings (désactive le filtre)

    Retourne (valid_findings, removed_count).
    """
    if not ignore_low_confidence:
        return findings, 0

    valid: List[Dict[str, Any]] = []
    removed = 0

    for finding in findings:
        severity = (finding.get("severity") or "info").lower()
        confidence = finding.get("confidence_score", 0)

        # Normalisation : confidence peut être en 0-1 ou 0-100
        if isinstance(confidence, (int, float)):
            conf_normalized = confidence if confidence <= 1.0 else confidence / 100.0
        else:
            conf_normalized = 0.0

        threshold = get_confidence_threshold(severity, custom_thresholds)
        finding["_fp_confidence_threshold"] = threshold
        finding["_fp_confidence_normalized"] = conf_normalized

        if conf_normalized >= threshold:
            valid.append(finding)
        else:
            removed += 1

    return valid, removed
