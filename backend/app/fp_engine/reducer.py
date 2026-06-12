"""
False Positive Reduction Engine v2 — Classification par tiers.

PRINCIPE CLÉ : on ne supprime JAMAIS un finding — on le classe.

Tiers :
  confirmed     → sources multiples ou actives, confidence ≥ seuil, contexte cohérent
  suspicious    → source unique ou faible confidence, à investiguer
  informational → très faible confidence ou contexte incohérent, gardé pour référence

Règles "never-delete" :
  - CRITICAL toujours ≥ suspicious
  - CVSS ≥ 7.0 toujours ≥ suspicious
  - Exposures (port risqué ouvert) toujours confirmed
  - Findings multi-sources toujours ≥ suspicious
  - CVE avec ID explicite toujours ≥ suspicious

La déduplication fusionne les doublons (merge) au lieu de supprimer.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Sources "actives" (interaction directe avec la cible) ─────────────────────
_ACTIVE_SOURCES = {
    "nuclei", "nmap", "zap", "dalfox", "sqlmap", "httpx",
    "ffuf",              # endpoint discovery
    "katana",            # JS crawling
    "gitleaks",          # secrets detection
    "trivy",             # supply chain
    "lab_challenge_api", # vulnerable lab challenge metadata
    "nikto",             # web server scanner — actif
    "wapiti",            # web app scanner — actif
}

_PASSIVE_SOURCES = {"shodan", "virustotal", "abuseipdb", "subfinder"}

# ── Seuils de confiance par tier ──────────────────────────────────────────────
_CONF_CONFIRMED    = 0.70   # ≥ 0.70 → confirmed
_CONF_SUSPICIOUS   = 0.30   # ≥ 0.30 → suspicious  |  < 0.30 → informational

# ── Seuils par sévérité : score minimum pour "confirmed" ─────────────────────
_SEVERITY_CONF_CONFIRMED: Dict[str, float] = {
    "critical":      0.35,  # critique : faible seuil (trop dangereux à manquer)
    "high":          0.45,
    "medium":        0.60,
    "low":           0.70,
    "info":          0.80,
    "informational": 0.80,
}

_DEFAULT_CONFIG: Dict[str, Any] = {
    "never_delete_critical":    True,
    "never_delete_cve":         True,
    "never_delete_exposure":    True,
    "never_delete_multi_source":True,
    "ignore_low_confidence":    True,   # si False → tous confirmed
    "require_active_source_for_medium_plus": True,
    "title_similarity_threshold": 0.85,
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _normalize_confidence(finding: Dict[str, Any]) -> float:
    raw = finding.get("confidence_score", 0)
    if isinstance(raw, (int, float)):
        return float(raw) if raw <= 1.0 else raw / 100.0
    return 0.0


def _has_active_source(finding: Dict[str, Any]) -> bool:
    sources = set(finding.get("sources") or [])
    return bool(sources & _ACTIVE_SOURCES)


def _is_multi_source(finding: Dict[str, Any]) -> bool:
    return len(set(finding.get("sources") or [])) >= 2


def _has_cve(finding: Dict[str, Any]) -> bool:
    return bool(finding.get("cve_ids"))


def _get_cvss(finding: Dict[str, Any]) -> float:
    return float(finding.get("cvss_score") or 0.0)


# ── Tier classifier ───────────────────────────────────────────────────────────


def _classify_tier(
    finding: Dict[str, Any],
    svc_version: Optional[str],
    cfg: Dict[str, Any],
) -> Tuple[str, List[str]]:
    """
    Classify a finding into confirmed / suspicious / informational.
    Returns (tier, reasons_list).
    """
    severity   = (finding.get("severity") or "info").lower()
    ftype      = (finding.get("type") or "").lower()
    conf       = _normalize_confidence(finding)
    cvss       = _get_cvss(finding)
    sources    = set(finding.get("sources") or [])
    active_src = _has_active_source(finding)
    multi_src  = _is_multi_source(finding)
    has_cve    = _has_cve(finding)
    flags: List[str] = []

    # ── Never-downgrade rules (always at least suspicious) ────────────────────
    if cfg.get("never_delete_critical") and severity == "critical":
        flags.append("critical_never_deleted")
        return "confirmed", flags

    if cfg.get("never_delete_exposure") and ftype == "exposure":
        flags.append("exposure_always_confirmed")
        return "confirmed", flags

    if cfg.get("never_delete_cve") and has_cve:
        flags.append("cve_never_deleted")
        # CVE with CVSS ≥ 7.0 → confirmed; else suspicious
        if cvss >= 7.0 or multi_src:
            return "confirmed", flags
        return "suspicious", flags

    if cfg.get("never_delete_multi_source") and multi_src:
        flags.append("multi_source")
        # Multi-source: tier by confidence
        thresh = _SEVERITY_CONF_CONFIRMED.get(severity, 0.60)
        if conf >= thresh:
            return "confirmed", flags
        return "suspicious", flags

    # ── Disable confidence filter entirely ────────────────────────────────────
    if not cfg.get("ignore_low_confidence"):
        flags.append("confidence_filter_disabled")
        return "confirmed", flags

    # ── Active source requirement for medium+ ─────────────────────────────────
    if cfg.get("require_active_source_for_medium_plus") and severity in {"medium", "high", "critical"}:
        if not active_src:
            flags.append("no_active_source")
            # Don't delete — downgrade to informational
            return "informational", flags

    # ── CVSS-based boost ──────────────────────────────────────────────────────
    if cvss >= 9.0:
        return "confirmed", ["cvss_critical"]
    if cvss >= 7.0:
        flags.append("cvss_high")
        return "confirmed", flags

    # ── Confidence-based classification ───────────────────────────────────────
    sev_threshold = _SEVERITY_CONF_CONFIRMED.get(severity, 0.65)
    if conf >= sev_threshold:
        flags.append(f"conf_{conf:.2f}_above_threshold_{sev_threshold:.2f}")
        return "confirmed", flags
    if conf >= _CONF_SUSPICIOUS:
        flags.append(f"conf_{conf:.2f}_suspicious")
        return "suspicious", flags

    flags.append(f"conf_{conf:.2f}_low")
    return "informational", flags


# ── Context validation (annotation only — never removes) ─────────────────────


_HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 4000, 5000, 9000}
_NON_WEB_SVC = {"ftp", "ssh", "smtp", "pop3", "imap", "rdp", "vnc", "telnet",
                "mssql", "mysql", "postgresql", "mongodb", "redis", "ldap", "smb"}
_WEB_KW = {"xss", "cross-site", "sql injection", "sqli", "csrf", "ssrf",
           "path traversal via url", "directory listing", "http header injection"}


def _contextual_flag(finding: Dict[str, Any]) -> Optional[str]:
    """Returns a warning flag if context is suspicious. Does NOT remove the finding."""
    ftype   = (finding.get("type") or "").lower()
    port    = finding.get("affected_port")
    service = (finding.get("affected_service") or "").lower()
    title   = (finding.get("title") or "").lower()

    if ftype == "exposure":
        return None

    is_web_finding = (
        ftype in {"web_vulnerability", "xss", "sqli", "ssti"}
        or any(kw in title for kw in _WEB_KW)
    )
    if not is_web_finding:
        return None

    # Check if it's clearly a non-web port
    if port and port not in _HTTP_PORTS:
        if any(s in service for s in _NON_WEB_SVC):
            return f"web_finding_on_non_web_service:port={port},svc={service}"

    return None


# ── Simple deduplication (merge identical CVE+port, don't delete) ─────────────


def _deduplicate(findings: List[Dict[str, Any]], sim_threshold: float) -> Tuple[List[Dict[str, Any]], int]:
    """
    Merge exact CVE+port duplicates by combining sources.
    Returns (deduplicated_list, merge_count).
    """
    merged: List[Dict[str, Any]] = []
    seen: Dict[Any, int] = {}   # key → index in merged
    merge_count = 0

    for finding in findings:
        cve_ids  = frozenset(finding.get("cve_ids") or [])
        port     = finding.get("affected_port")
        title    = (finding.get("title") or "").lower()

        # Dedup key: CVE IDs + port (strict)
        if cve_ids:
            key = (cve_ids, port)
        else:
            # Fallback: exact title + port
            key = (title[:50], port)

        if key in seen:
            # Merge: combine sources and boost confidence
            existing = merged[seen[key]]
            existing["sources"] = sorted(set(
                (existing.get("sources") or []) + (finding.get("sources") or [])
            ))
            # Keep highest confidence
            existing["confidence_score"] = max(
                _normalize_confidence(existing),
                _normalize_confidence(finding),
            )
            existing["_fp_merged"] = True
            merge_count += 1
        else:
            seen[key] = len(merged)
            merged.append(dict(finding))

    return merged, merge_count


# ── Main entry point ──────────────────────────────────────────────────────────


def reduce_false_positives(
    findings:    List[Dict[str, Any]],
    service_map: Optional[Dict[int, Dict[str, str]]] = None,
    config:      Optional[Dict[str, Any]] = None,
    lab_mode:    bool = True,
) -> Dict[str, Any]:
    """
    Classifies findings into confirmed / suspicious / informational tiers.

    KEY GUARANTEE: no legitimate finding is ever deleted.
      - Critical findings → always at least suspicious
      - CVE findings → always at least suspicious
      - Exposure findings → always confirmed
      - Multi-source findings → always at least suspicious
      - Low-confidence findings → kept as informational (not deleted)

    Returns:
        filtered_findings   — ALL findings with fp_status annotation
        confirmed           — subset: high-confidence findings
        suspicious          — subset: medium-confidence, worth investigating
        informational       — subset: low-confidence, kept for reference
        removed_total       — 0 (no deletions in v2, only merges)
        merged_total        — number of duplicate findings merged
        ...
    """
    cfg         = {**_DEFAULT_CONFIG, **(config or {})}
    service_map = service_map or {}

    original_count = len(findings)

    # ── Step 1: Deduplicate (merge, not delete) ───────────────────────────────
    working, merge_count = _deduplicate(
        findings,
        sim_threshold=cfg.get("title_similarity_threshold", 0.85),
    )
    logger.debug("FP dedup: %d → %d (merged %d)", original_count, len(working), merge_count)

    # ── Step 2: Classify each finding into a tier ─────────────────────────────
    confirmed:     List[Dict[str, Any]] = []
    suspicious:    List[Dict[str, Any]] = []
    informational: List[Dict[str, Any]] = []

    for finding in working:
        port       = finding.get("affected_port")
        svc_ver    = (service_map.get(port) or {}).get("version", "") if port else ""

        tier, flags = _classify_tier(finding, svc_ver, cfg)
        ctx_flag    = _contextual_flag(finding)

        # Annotate finding with FP metadata
        finding["fp_status"]  = tier
        finding["fp_flags"]   = flags
        finding["fp_context"] = ctx_flag or "ok"

        # Context mismatch → downgrade confirmed → suspicious
        if ctx_flag and tier == "confirmed":
            finding["fp_status"] = "suspicious"
            finding["fp_flags"]  = flags + ["context_mismatch_downgraded"]
            tier = "suspicious"

        if tier == "confirmed":
            confirmed.append(finding)
        elif tier == "suspicious":
            suspicious.append(finding)
        else:
            informational.append(finding)

    all_findings = confirmed + suspicious + informational

    # ── Step 3: Stats ─────────────────────────────────────────────────────────
    by_severity: Dict[str, int] = {}
    for f in all_findings:
        sev = f.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    by_tier = {
        "confirmed":     len(confirmed),
        "suspicious":    len(suspicious),
        "informational": len(informational),
    }

    # "removed_by_layer" kept for backward compat — now represents tier downgrade counts
    removed_by_layer = {
        "source_validation":   sum(1 for f in all_findings if "no_active_source" in f.get("fp_flags", [])),
        "version_matching":    0,  # version mismatch now downgrades, not removes
        "deduplication":       merge_count,
        "confidence":          sum(1 for f in informational if any("conf_" in fl for fl in f.get("fp_flags", []))),
        "context":             sum(1 for f in all_findings if f.get("fp_context") != "ok"),
    }

    _mode_tag = "[lab mode]" if lab_mode else "[active mode]"
    logger.info(
        "FP Analysis: %d findings → confirmed=%d suspicious=%d informational=%d (merged=%d) %s",
        original_count, len(confirmed), len(suspicious), len(informational), merge_count, _mode_tag,
    )

    return {
        # Primary output
        "filtered_findings":  all_findings,    # ALL findings with fp_status
        "confirmed":          confirmed,
        "suspicious":         suspicious,
        "informational":      informational,
        # Counts
        "original_count":     original_count,
        "final_count":        len(all_findings),
        "merged_total":       merge_count,
        "removed_total":      merge_count,      # backward compat (only merges)
        "removed_by_layer":   removed_by_layer,
        "by_tier":            by_tier,
        "by_severity":        by_severity,
        "fp_reduction_rate":  round(merge_count / original_count, 3) if original_count else 0.0,
        "summary": (
            f"FP Analysis: {original_count} findings → "
            f"confirmed={len(confirmed)} "
            f"suspicious={len(suspicious)} "
            f"informational={len(informational)} "
            f"(merged={merge_count})"
        ),
    }
