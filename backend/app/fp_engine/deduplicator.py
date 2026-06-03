"""
Deduplicator — détection et fusion des doublons cross-sources.

Stratégie de déduplication par priorité :
  1. CVE IDs identiques          → doublon certain
  2. CWE IDs + port identiques   → doublon probable
  3. Titre similaire (≥85%)      → doublon probable (si même port)
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple


def _normalize_title(title: str) -> str:
    """Normalise un titre pour comparaison."""
    title = title.lower()
    title = re.sub(r"[^a-z0-9\s]", " ", title)
    title = re.sub(r"\s+", " ", title).strip()
    return title


def _title_similarity(a: str, b: str) -> float:
    """Similarité de Jaro-Winkler simplifiée (0.0 → 1.0)."""
    a, b = _normalize_title(a), _normalize_title(b)
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0

    words_a = set(a.split())
    words_b = set(b.split())
    if not words_a or not words_b:
        return 0.0

    intersection = words_a & words_b
    union = words_a | words_b
    return len(intersection) / len(union)


def _get_cve_key(finding: Dict[str, Any]) -> Optional[frozenset]:
    cves = finding.get("cve_ids") or []
    if isinstance(cves, str):
        cves = [cves]
    cves = [c.upper() for c in cves if c]
    return frozenset(cves) if cves else None


def _get_cwe_port_key(finding: Dict[str, Any]) -> Optional[Tuple]:
    cwes = finding.get("cwe_ids") or []
    if isinstance(cwes, str):
        cwes = [cwes]
    port = finding.get("affected_port")
    if cwes and port is not None:
        return (frozenset(str(c) for c in cwes), port)
    return None


def deduplicate_findings(
    findings: List[Dict[str, Any]],
    title_similarity_threshold: float = 0.85,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Déduplique une liste de findings corrigés.

    Stratégie : lorsqu'un doublon est détecté, on fusionne les sources et on
    prend le score de confiance le plus élevé. Le finding restant est celui
    avec la confiance initiale la plus haute.

    Retourne (deduplicated_findings, removed_count).
    """
    deduplicated: List[Dict[str, Any]] = []
    seen_cve_keys: List[Tuple[frozenset, int]] = []  # (cve_set, index_in_result)
    seen_cwe_port_keys: Dict[Tuple, int] = {}         # (cwe_set, port) → index
    removed = 0

    for finding in sorted(findings, key=lambda f: -f.get("confidence_score", 0)):
        cve_key = _get_cve_key(finding)
        cwe_port_key = _get_cwe_port_key(finding)
        port = finding.get("affected_port")
        title = finding.get("title", "")

        # ── 1. Doublon par CVE exact ──────────────────────────────────────────
        if cve_key:
            merged = False
            for existing_cve_key, idx in seen_cve_keys:
                if cve_key & existing_cve_key:  # intersection non vide
                    # Fusionner sources
                    existing = deduplicated[idx]
                    existing["sources"] = list(set(existing.get("sources", []) + finding.get("sources", [])))
                    existing["confidence_score"] = max(
                        existing.get("confidence_score", 0),
                        finding.get("confidence_score", 0),
                    )
                    existing["cve_ids"] = list(existing_cve_key | cve_key)
                    merged = True
                    removed += 1
                    break
            if merged:
                continue
            seen_cve_keys.append((cve_key, len(deduplicated)))

        # ── 2. Doublon par CWE + port ─────────────────────────────────────────
        elif cwe_port_key:
            if cwe_port_key in seen_cwe_port_keys:
                idx = seen_cwe_port_keys[cwe_port_key]
                existing = deduplicated[idx]
                existing["sources"] = list(set(existing.get("sources", []) + finding.get("sources", [])))
                existing["confidence_score"] = max(
                    existing.get("confidence_score", 0),
                    finding.get("confidence_score", 0),
                )
                removed += 1
                continue
            seen_cwe_port_keys[cwe_port_key] = len(deduplicated)

        # ── 3. Doublon par titre similaire + même port ────────────────────────
        else:
            title_merged = False
            for existing in deduplicated:
                if existing.get("affected_port") != port:
                    continue
                sim = _title_similarity(title, existing.get("title", ""))
                if sim >= title_similarity_threshold:
                    existing["sources"] = list(set(existing.get("sources", []) + finding.get("sources", [])))
                    existing["confidence_score"] = max(
                        existing.get("confidence_score", 0),
                        finding.get("confidence_score", 0),
                    )
                    removed += 1
                    title_merged = True
                    break
            if title_merged:
                continue

        deduplicated.append(finding)

    return deduplicated, removed
