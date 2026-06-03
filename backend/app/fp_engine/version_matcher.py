"""
Version Matcher — vérifie si un CVE affecte réellement la version détectée.

Utilise le version_range du finding (versionEndIncluding / affected_versions)
pour valider que la version du service cible est dans la plage vulnérable.

Retourne True si la version est confirmée vulnérable (ou si pas d'info version).
Retourne False si la version du service est clairement hors de la plage vulnérable.
"""
from __future__ import annotations

import re
from typing import Optional


def _parse_version(v: str) -> tuple[int, ...]:
    """Extrait les composants numériques d'une version string."""
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts[:4])


def _cmp_versions(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Compare deux tuples de version. Retourne -1, 0, 1."""
    for x, y in zip(a, b):
        if x < y:
            return -1
        if x > y:
            return 1
    if len(a) < len(b):
        return -1
    if len(a) > len(b):
        return 1
    return 0


def is_version_vulnerable(
    detected_version: Optional[str],
    version_end_including: Optional[str] = None,
    version_end_excluding: Optional[str] = None,
    version_start_including: Optional[str] = None,
    affected_versions: Optional[list[str]] = None,
) -> bool:
    """
    Retourne True si la version détectée est dans la plage vulnérable,
    ou True si on n'a pas assez d'info pour décider (bénéfice du doute).
    """
    if not detected_version or not detected_version.strip():
        return True  # Pas d'info version → on garde le finding

    d_ver = _parse_version(detected_version)
    if not d_ver:
        return True

    # Si liste de versions affectées explicite → vérification directe
    if affected_versions:
        for av in affected_versions:
            av_parsed = _parse_version(av)
            if av_parsed and _cmp_versions(d_ver, av_parsed) == 0:
                return True
        # Liste fournie mais version non trouvée → probablement FP
        return False

    # Plage versionStart → versionEnd
    start_ok = True
    end_ok = True

    if version_start_including:
        s_ver = _parse_version(version_start_including)
        if s_ver:
            start_ok = _cmp_versions(d_ver, s_ver) >= 0

    if version_end_including:
        e_ver = _parse_version(version_end_including)
        if e_ver:
            end_ok = _cmp_versions(d_ver, e_ver) <= 0
    elif version_end_excluding:
        e_ver = _parse_version(version_end_excluding)
        if e_ver:
            end_ok = _cmp_versions(d_ver, e_ver) < 0

    if not any([version_start_including, version_end_including, version_end_excluding]):
        return True  # Pas de plage spécifiée → bénéfice du doute

    return start_ok and end_ok


def check_finding_version(finding: dict, service_version: Optional[str]) -> tuple[bool, str]:
    """
    Vérifie si un finding est applicable à la version du service détecté.

    Retourne (is_valid, reason).
    """
    if not service_version:
        return True, "no_service_version"

    ver_end_incl = finding.get("version_end_including")
    ver_end_excl = finding.get("version_end_excluding")
    ver_start_incl = finding.get("version_start_including")
    affected = finding.get("affected_versions")

    is_vuln = is_version_vulnerable(
        detected_version=service_version,
        version_end_including=ver_end_incl,
        version_end_excluding=ver_end_excl,
        version_start_including=ver_start_incl,
        affected_versions=affected,
    )

    if is_vuln:
        return True, "version_confirmed"
    return False, f"version_mismatch: detected={service_version}"
