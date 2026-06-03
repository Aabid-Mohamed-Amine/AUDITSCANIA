"""
Report generation service.

build_report_json  → JSON structuré complet (LLM + download)
generate_pdf       → PDF professionnel avec logo BDO

Chaque finding inclut :
  - detected_by     : liste des outils qui l'ont détecté  (["nuclei", "nmap"])
  - detection_tools : détail outil principal + corroboration

Logo BDO : backend/static/bdo_logo.png  (à placer par l'utilisateur)
"""
from __future__ import annotations

import io
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Logo path ─────────────────────────────────────────────────────────────────
_STATIC_DIR = Path(__file__).parent.parent.parent / "static"
_LOGO_PATH  = _STATIC_DIR / "bdo_logo.png"

# ── Tool display names ────────────────────────────────────────────────────────
_TOOL_DISPLAY: Dict[str, str] = {
    "nuclei":     "Nuclei",
    "nmap":       "Nmap",
    "zap":        "OWASP ZAP",
    "ffuf":       "FFUF",
    "katana":     "Katana",
    "dalfox":     "Dalfox (XSS)",
    "sqlmap":     "SQLMap",
    "gitleaks":   "GitLeaks",
    "shodan":     "Shodan",
    "virustotal": "VirusTotal",
    "abuseipdb":  "AbuseIPDB",
    "subfinder":  "Subfinder",
}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}


# ─────────────────────────────────────────────────────────────────────────────
# JSON BUILDER
# ─────────────────────────────────────────────────────────────────────────────


def _tool_names(sources: List[str]) -> List[str]:
    return [_TOOL_DISPLAY.get(s, s.capitalize()) for s in sources]


def _detection_detail(finding: Dict[str, Any]) -> Dict[str, Any]:
    sources = finding.get("sources") or []
    primary = sources[0] if sources else "unknown"
    corroborated = sources[1:] if len(sources) > 1 else []
    return {
        "primary_tool":       _TOOL_DISPLAY.get(primary, primary.capitalize()),
        "corroborated_by":    _tool_names(corroborated),
        "total_sources":      len(sources),
        "multi_tool_confirm": len(sources) > 1,
    }


def _count_by_tool(findings: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        for src in (f.get("sources") or []):
            counts[src] = counts.get(src, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


def _count_by_type(findings: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        t = f.get("type", "unknown")
        counts[t] = counts.get(t, 0) + 1
    return counts


def build_report_json(scan: Any) -> Dict[str, Any]:
    """
    Build the complete structured report JSON.
    Each finding includes detected_by (list of tools) and detection_detail.
    This JSON is used for:
      - PDF generation
      - LLM prompt enrichment
      - Direct download from the UI
    """
    soc    = (scan.soc_report or {})
    corr   = (scan.correlated_data or {})
    ai     = (scan.ai_analysis_data or {})
    phases = soc.get("phases_summary", {})

    # ── Findings with detected_by ─────────────────────────────────────────────
    raw_findings = corr.get("correlated_findings", [])
    findings: List[Dict[str, Any]] = []
    for f in sorted(raw_findings, key=lambda x: _SEV_ORDER.get(x.get("severity", "info"), 4)):
        sources = f.get("sources") or []
        findings.append({
            "id":                  f.get("id", ""),
            "title":               f.get("title", "Unknown"),
            "severity":            f.get("severity", "info"),
            "type":                f.get("type", ""),
            # ── Tool attribution ──
            "detected_by":         sources,
            "detected_by_display": _tool_names(sources),
            "detection_detail":    _detection_detail(f),
            # ── Technical details ──
            "cve_ids":             f.get("cve_ids") or [],
            "cwe_ids":             f.get("cwe_ids") or [],
            "cvss_score":          f.get("cvss_score"),
            "epss_score":          f.get("epss_score"),
            "affected_port":       f.get("affected_port"),
            "affected_service":    f.get("affected_service", ""),
            "matched_at":          f.get("matched_at", ""),
            "attack_path":         f.get("attack_path", ""),
            "tags":                f.get("tags") or [],
            # ── Risk metrics ──
            "exploitability_score": f.get("exploitability_score", 0),
            "confidence_score":     f.get("confidence_score", 0),
            "fp_status":           f.get("fp_status", ""),
        })

    # ── Threat intel summary ──────────────────────────────────────────────────
    abuse_data = scan.abuseipdb_data or {}
    vt_data    = scan.virustotal_data or {}
    threat_intel = {
        "abuseipdb_confidence": (abuse_data.get("data") or {}).get("abuse_confidence_score", 0),
        "abuseipdb_reports":    (abuse_data.get("data") or {}).get("total_reports", 0),
        "virustotal_malicious": (
            (vt_data.get("data") or {}).get("malicious", 0) or
            max(
                ((vt_data.get("data") or {}).get("domain") or {}).get("malicious", 0),
                ((vt_data.get("data") or {}).get("url") or {}).get("malicious", 0),
            )
        ),
        "shodan_ports": len(
            ((scan.shodan_data or {}).get("data") or {})
            .get("internetdb", {}).get("ports", [])
        ),
        "shodan_cves": len(
            ((scan.shodan_data or {}).get("data") or {})
            .get("internetdb", {}).get("vulns", [])
        ),
    }

    # ── Network summary ───────────────────────────────────────────────────────
    nmap_summary = (scan.nmap_data or {}).get("summary", {})
    network = {
        "open_ports":  nmap_summary.get("ports", []),
        "host_count":  nmap_summary.get("host_count", 0),
        "services":    nmap_summary.get("services", {}),
        "cdn_providers": nmap_summary.get("cdn_providers", []),
        "subdomains":  (scan.subfinder_data or {}).get("subdomains_count", 0),
        "live_hosts":  (scan.subfinder_data or {}).get("live_count", 0),
        "technologies": (scan.subfinder_data or {}).get("technologies", []),
    }

    # ── Phase 3 exploitation summary ─────────────────────────────────────────
    exploitation = {
        "ffuf_critical":    len((((scan.ffuf_data or {}).get("by_severity") or {}).get("critical") or [])),
        "ffuf_high":        len((((scan.ffuf_data or {}).get("by_severity") or {}).get("high") or [])),
        "ffuf_total":       (scan.ffuf_data or {}).get("total", 0),
        "secrets_total":    (scan.gitleaks_data or {}).get("total", 0),
        "secrets_critical": ((scan.gitleaks_data or {}).get("by_severity") or {}).get("critical", 0),
        "secrets_high":     ((scan.gitleaks_data or {}).get("by_severity") or {}).get("high", 0),
        "secrets_findings": (scan.gitleaks_data or {}).get("findings", []),
        "sqlmap_vulnerable": (scan.sqlmap_data or {}).get("vulnerable", False),
        "sqlmap_skipped":   (scan.sqlmap_data or {}).get("skipped", False),
        "sqlmap_findings":  (scan.sqlmap_data or {}).get("findings", []),
        "katana_api_count": len((scan.katana_data or {}).get("api_endpoints", [])),
    }

    return {
        "report_metadata": {
            "scan_id":          str(scan.id),
            "target":           scan.target,
            "generated_at":     datetime.utcnow().isoformat() + "Z",
            "risk_level":       soc.get("risk_level", "UNKNOWN"),
            "risk_score":       scan.risk_score or 0,
            "scan_status":      str(scan.status),
            "pipeline_version": "5-phase",
            "report_version":   "2.0",
        },
        "executive_summary":   soc.get("executive_summary", ""),
        "risk_analysis": {
            "risk_score":               scan.risk_score or 0,
            "risk_level":               soc.get("risk_level", "UNKNOWN"),
            "exploitability_score":     soc.get("exploitability_score", 0),
            "confidence_score":         soc.get("confidence_score", 0),
            "threat_intelligence_factor": soc.get("threat_intelligence_factor", 0),
            "cve_severity_factor":      soc.get("cve_severity_factor", 0),
            "service_exposure_factor":  soc.get("service_exposure_factor", 0),
            "component_scores":         soc.get("component_scores", {}),
        },
        "pipeline_summary":    phases,
        "network":             network,
        "threat_intelligence": threat_intel,
        "exploitation":        exploitation,
        "findings":            findings,
        "findings_stats": {
            "total":       len(findings),
            "by_severity": corr.get("by_severity", {}),
            "by_tool":     _count_by_tool(findings),
            "by_type":     _count_by_type(findings),
            "confirmed":   len([f for f in findings if f.get("fp_status") == "confirmed"]),
            "suspicious":  len([f for f in findings if f.get("fp_status") == "suspicious"]),
        },
        "top_findings":        soc.get("top_findings", []),
        "attack_paths":        corr.get("attack_paths", []),
        "endpoint_risk_ranking": corr.get("endpoint_risk_ranking", []),
        "recommendations":     soc.get("recommendations", []),
        "ai_analysis":         {k: v for k, v in ai.items() if k not in ("model_used", "provider")},
        "service_vuln_map":    corr.get("service_vuln_map", {}),
    }


# ─────────────────────────────────────────────────────────────────────────────
# PDF GENERATOR
# ─────────────────────────────────────────────────────────────────────────────


def generate_pdf(report: Dict[str, Any]) -> bytes:
    """Generate a professional SOC PDF report. Returns raw bytes."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor, white, black
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Table, TableStyle,
            Spacer, HRFlowable, Image, KeepTogether,
        )
        from reportlab.lib.units import cm, mm
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
        from reportlab.platypus import PageBreak
    except ImportError:
        raise RuntimeError("reportlab is not installed. Add 'reportlab==4.2.2' to requirements.txt")

    # ── BDO brand colors ──────────────────────────────────────────────────────
    BDO_NAVY   = HexColor("#003A70")
    BDO_GOLD   = HexColor("#C8A04F")
    BDO_LIGHT  = HexColor("#EDF2F7")
    BDO_BORDER = HexColor("#CBD5E0")

    SEV_COLORS = {
        "critical":      HexColor("#DC2626"),
        "high":          HexColor("#EA580C"),
        "medium":        HexColor("#CA8A04"),
        "low":           HexColor("#2563EB"),
        "info":          HexColor("#64748B"),
        "informational": HexColor("#64748B"),
    }
    RISK_COLORS = {
        "CRITICAL":      HexColor("#DC2626"),
        "HIGH":          HexColor("#EA580C"),
        "MEDIUM":        HexColor("#CA8A04"),
        "LOW":           HexColor("#2563EB"),
        "INFORMATIONAL": HexColor("#64748B"),
        "UNKNOWN":       HexColor("#64748B"),
    }

    W, H = A4
    buf  = io.BytesIO()

    # ── Page layout ───────────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.5*cm, bottomMargin=2*cm,
        title="AuditSCAN Security Report",
        author="AuditSCAN Platform",
        subject=f"Security Assessment — {report['report_metadata']['target']}",
    )

    # ── Styles ────────────────────────────────────────────────────────────────
    styles = getSampleStyleSheet()

    def _style(name, **kw):
        base = styles["Normal"]
        s = ParagraphStyle(name, parent=base, **kw)
        return s

    S_TITLE     = _style("Title2",    fontSize=26, textColor=BDO_NAVY, spaceAfter=6, fontName="Helvetica-Bold", alignment=TA_CENTER)
    S_SUBTITLE  = _style("Subtitle2", fontSize=13, textColor=BDO_GOLD,  spaceAfter=4, fontName="Helvetica",     alignment=TA_CENTER)
    S_H1        = _style("H1",        fontSize=14, textColor=BDO_NAVY,  spaceBefore=14, spaceAfter=6, fontName="Helvetica-Bold")
    S_H2        = _style("H2",        fontSize=11, textColor=BDO_NAVY,  spaceBefore=8,  spaceAfter=4, fontName="Helvetica-Bold")
    S_BODY      = _style("Body2",     fontSize=9,  textColor=HexColor("#2D3748"), leading=14, spaceAfter=4)
    S_SMALL     = _style("Small2",    fontSize=8,  textColor=HexColor("#4A5568"), leading=12)
    S_MONO      = _style("Mono2",     fontSize=8,  fontName="Courier",  textColor=HexColor("#2D3748"), leading=12)
    S_CAPTION   = _style("Caption2",  fontSize=8,  textColor=HexColor("#718096"), alignment=TA_CENTER)
    S_CENTER    = _style("Center2",   fontSize=9,  alignment=TA_CENTER, textColor=HexColor("#2D3748"))
    S_BOLD      = _style("Bold2",     fontSize=9,  fontName="Helvetica-Bold", textColor=HexColor("#1A202C"))

    def hr(color=BDO_BORDER, thickness=0.5):
        return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=8, spaceBefore=4)

    def sp(h=6):
        return Spacer(1, h)

    meta   = report["report_metadata"]
    risk   = report["risk_analysis"]
    target = meta["target"]
    date   = meta["generated_at"][:10]
    rlevel = meta["risk_level"]
    rscore = meta["risk_score"]

    story: list = []

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 1 — COVER
    # ══════════════════════════════════════════════════════════════════════════

    # Logo BDO (if exists)
    if _LOGO_PATH.exists():
        try:
            logo = Image(str(_LOGO_PATH), width=5*cm, height=2.5*cm, kind="proportional")
            logo.hAlign = "RIGHT"
            story.append(logo)
        except Exception:
            pass

    story += [
        sp(30),
        # ── Cover box ────────────────────────────────────────────────────────
        Table(
            [[Paragraph("SECURITY ASSESSMENT REPORT", S_TITLE)]],
            colWidths=[W - 4*cm],
            style=TableStyle([
                ("BACKGROUND",  (0, 0), (-1, -1), BDO_NAVY),
                ("TOPPADDING",  (0, 0), (-1, -1), 18),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
                ("LEFTPADDING",  (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TEXTCOLOR",   (0, 0), (-1, -1), white),
            ]),
        ),
        sp(8),
        Paragraph(f"Target: {target}", S_SUBTITLE),
        Paragraph(f"Date: {date}", S_SUBTITLE),
        sp(24),
    ]

    # Risk level badge
    risk_color = RISK_COLORS.get(rlevel, RISK_COLORS["UNKNOWN"])
    story.append(
        Table(
            [[Paragraph(f"Risk Level: {rlevel}  |  Score: {rscore}/100", _style(
                "RiskBadge", fontSize=16, fontName="Helvetica-Bold",
                textColor=white, alignment=TA_CENTER,
            ))]],
            colWidths=[W - 4*cm],
            style=TableStyle([
                ("BACKGROUND",  (0, 0), (-1, -1), risk_color),
                ("TOPPADDING",  (0, 0), (-1, -1), 14),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
                ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [risk_color]),
            ]),
        )
    )

    story += [
        sp(20),
        Paragraph("CONFIDENTIAL — FOR AUTHORIZED RECIPIENTS ONLY", _style(
            "Conf", fontSize=9, textColor=HexColor("#718096"),
            alignment=TA_CENTER, fontName="Helvetica-Bold",
        )),
        sp(8),
        Paragraph(
            f"Report generated by AuditSCAN Platform · Scan ID: {meta['scan_id'][:16]}…",
            S_CAPTION,
        ),
        PageBreak(),
    ]

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 2 — EXECUTIVE SUMMARY + RISK DASHBOARD
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("1. Executive Summary", S_H1))
    story.append(hr(BDO_GOLD, 1.5))

    exec_text = (
        report.get("ai_analysis", {}).get("executive_summary")
        or report.get("executive_summary", "No executive summary available.")
    )
    story.append(Paragraph(exec_text, S_BODY))

    # AI SOC summary
    soc_sum = report.get("ai_analysis", {}).get("soc_summary", "")
    if soc_sum:
        story += [sp(6), Paragraph("<b>SOC Operational Note:</b>", S_BOLD),
                  Paragraph(soc_sum, S_BODY)]

    story += [sp(10), Paragraph("2. Risk Score Dashboard", S_H1), hr(BDO_GOLD, 1.5)]

    # Risk components table
    comp_scores = risk.get("component_scores", {})
    if comp_scores:
        comp_data = [
            [Paragraph("<b>Factor</b>", S_BOLD), Paragraph("<b>Score</b>", S_BOLD),
             Paragraph("<b>Weight</b>", S_BOLD)],
        ]
        _weights = {
            "nuclei_cve": "28%", "zap_web": "18%", "abuseipdb": "13%",
            "virustotal": "8%",  "exploitability": "10%", "port_exposure": "7%",
            "cve_severity": "5%", "service_exposure": "4%",
            "endpoint_risk": "4%", "network_reach": "3%",
        }
        for key, val in comp_scores.items():
            color = HexColor("#DC2626") if val > 70 else HexColor("#EA580C") if val > 40 else HexColor("#2563EB")
            comp_data.append([
                Paragraph(key.replace("_", " ").title(), S_SMALL),
                Paragraph(f"<b>{val:.0f}/100</b>", _style(f"cv_{key}", fontSize=9, textColor=color, fontName="Helvetica-Bold")),
                Paragraph(_weights.get(key, ""), S_SMALL),
            ])
        story.append(Table(
            comp_data, colWidths=[9*cm, 4*cm, 3.5*cm],
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0),  BDO_NAVY),
                ("TEXTCOLOR",     (0, 0), (-1, 0),  white),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [BDO_LIGHT, white]),
                ("GRID",          (0, 0), (-1, -1), 0.4, BDO_BORDER),
                ("FONTSIZE",      (0, 0), (-1, -1), 9),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ]),
        ))

    story.append(sp(6))
    # Metrics row
    metrics = [
        ("Exploitability", f"{risk.get('exploitability_score', 0):.0f}/100"),
        ("Confidence",     f"{risk.get('confidence_score', 0):.0f}%"),
        ("Threat Intel",   f"{risk.get('threat_intelligence_factor', 0):.0f}/100"),
        ("CVE Severity",   f"{risk.get('cve_severity_factor', 0):.0f}/100"),
    ]
    story.append(Table(
        [[Paragraph(f"<b>{v}</b><br/><font size='7' color='#718096'>{k}</font>", S_CENTER) for k, v in metrics]],
        colWidths=[(W - 4*cm) / 4] * 4,
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), BDO_LIGHT),
            ("BOX",           (0, 0), (-1, -1), 0.5, BDO_BORDER),
            ("INNERGRID",     (0, 0), (-1, -1), 0.3, BDO_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ]),
    ))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 3 — FINDINGS
    # ══════════════════════════════════════════════════════════════════════════
    findings    = report.get("findings", [])
    stats       = report.get("findings_stats", {})
    by_sev      = stats.get("by_severity", {})

    story.append(Paragraph("3. Vulnerability Findings", S_H1))
    story.append(hr(BDO_GOLD, 1.5))

    # Stats summary bar
    sev_items = [
        ("Critical", by_sev.get("critical", 0), HexColor("#DC2626")),
        ("High",     by_sev.get("high",     0), HexColor("#EA580C")),
        ("Medium",   by_sev.get("medium",   0), HexColor("#CA8A04")),
        ("Low",      by_sev.get("low",      0), HexColor("#2563EB")),
    ]
    story.append(Table(
        [[Paragraph(
            f"<b>{cnt}</b><br/><font size='7'>{lbl}</font>",
            _style(f"si_{lbl}", fontSize=11, alignment=TA_CENTER,
                   textColor=white, fontName="Helvetica-Bold"),
        ) for lbl, cnt, _ in sev_items]],
        colWidths=[(W - 4*cm) / 4] * 4,
        style=TableStyle([
            *[("BACKGROUND", (i, 0), (i, 0), col) for i, (_, _, col) in enumerate(sev_items)],
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("BOX",           (0, 0), (-1, -1), 0.5, white),
            ("INNERGRID",     (0, 0), (-1, -1), 0.5, white),
        ]),
    ))
    story.append(sp(10))

    if not findings:
        story.append(Paragraph("No findings detected.", S_BODY))
    else:
        # Findings table header
        tbl_header = [
            Paragraph("<b>#</b>",           S_BOLD),
            Paragraph("<b>Severity</b>",    S_BOLD),
            Paragraph("<b>Title</b>",       S_BOLD),
            Paragraph("<b>Detected by</b>", S_BOLD),
            Paragraph("<b>CVE / CWE</b>",   S_BOLD),
            Paragraph("<b>Port / Service</b>", S_BOLD),
            Paragraph("<b>Confidence</b>",  S_BOLD),
        ]
        tbl_data = [tbl_header]

        for i, f in enumerate(findings[:50], 1):
            sev   = f.get("severity", "info").lower()
            sev_c = SEV_COLORS.get(sev, SEV_COLORS["info"])
            cves  = ", ".join(f.get("cve_ids", [])[:2]) or ""
            cwes  = ", ".join(f"CWE-{c}" for c in (f.get("cwe_ids") or [])[:2])
            cve_text = "\n".join(filter(None, [cves, cwes]))
            tools = ", ".join(f.get("detected_by_display") or f.get("detected_by") or [])
            port  = str(f.get("affected_port") or "")
            svc   = str(f.get("affected_service") or "")
            port_svc = f"{port}/{svc}" if port and svc else port or svc or "—"
            conf  = f.get("fp_status", "")
            conf_disp = {"confirmed": "✓ Confirmed", "suspicious": "? Suspicious"}.get(conf, conf or "—")

            tbl_data.append([
                Paragraph(str(i), S_SMALL),
                Paragraph(f"<b>{sev.upper()}</b>", _style(
                    f"sev_{i}", fontSize=8, textColor=sev_c, fontName="Helvetica-Bold", alignment=TA_CENTER,
                )),
                Paragraph(f.get("title", ""), S_SMALL),
                Paragraph(tools, S_SMALL),
                Paragraph(cve_text or "—", S_MONO),
                Paragraph(port_svc, S_MONO),
                Paragraph(conf_disp, S_SMALL),
            ])

        row_styles = []
        for i in range(1, len(tbl_data)):
            bg = BDO_LIGHT if i % 2 == 0 else white
            row_styles.append(("ROWBACKGROUNDS", (0, i), (-1, i), [bg]))

        story.append(Table(
            tbl_data,
            colWidths=[0.7*cm, 1.8*cm, 5.5*cm, 3.5*cm, 2.5*cm, 2.2*cm, 2.0*cm],
            repeatRows=1,
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0),  BDO_NAVY),
                ("TEXTCOLOR",     (0, 0), (-1, 0),  white),
                ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("GRID",          (0, 0), (-1, -1), 0.3, BDO_BORDER),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 4),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                *row_styles,
            ]),
        ))

    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 4 — PHASE 3 EXPLOITATION DETAILS
    # ══════════════════════════════════════════════════════════════════════════
    expl = report.get("exploitation", {})
    story += [Paragraph("4. Exploitation Findings (Phase 3)", S_H1), hr(BDO_GOLD, 1.5)]

    # Secrets
    secrets = expl.get("secrets_findings", [])
    story.append(Paragraph(f"4.1 Secrets Detected — GitLeaks ({expl.get('secrets_total', 0)} findings)", S_H2))
    if secrets:
        sec_data = [[Paragraph("<b>Severity</b>", S_BOLD), Paragraph("<b>Rule</b>", S_BOLD),
                     Paragraph("<b>File / Location</b>", S_BOLD), Paragraph("<b>Description</b>", S_BOLD)]]
        for s in secrets[:10]:
            sev = (s.get("severity") or "medium").lower()
            sec_data.append([
                Paragraph(sev.upper(), _style(f"ss_{sev}", fontSize=8, textColor=SEV_COLORS.get(sev, BDO_NAVY), fontName="Helvetica-Bold")),
                Paragraph(s.get("rule_id", ""), S_MONO),
                Paragraph(str(s.get("file", ""))[:50], S_MONO),
                Paragraph(str(s.get("description", ""))[:60], S_SMALL),
            ])
        story.append(Table(sec_data, colWidths=[2*cm, 4*cm, 6*cm, 5.7*cm],
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), BDO_NAVY),
                ("TEXTCOLOR",     (0, 0), (-1, 0), white),
                ("GRID",          (0, 0), (-1, -1), 0.3, BDO_BORDER),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [BDO_LIGHT, white]),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 4),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ])))
    else:
        story.append(Paragraph("✓ No secrets detected by GitLeaks.", S_BODY))

    story.append(sp(8))

    # SQLMap
    story.append(Paragraph("4.2 SQL Injection — SQLMap", S_H2))
    if expl.get("sqlmap_skipped"):
        story.append(Paragraph("SQLMap not executed — no injectable parameters detected by ZAP (false positive reduction).", S_BODY))
    elif expl.get("sqlmap_vulnerable"):
        sqli = expl.get("sqlmap_findings", [])
        story.append(Paragraph(f"⚠ SQL Injection CONFIRMED — {len(sqli)} injection point(s) detected.", _style("sqli_warn", fontSize=10, textColor=HexColor("#DC2626"), fontName="Helvetica-Bold")))
        for f in sqli[:5]:
            story.append(Paragraph(
                f"• Parameter: <b>{f.get('parameter', '?')}</b> | Technique: {f.get('technique', '?')} | DBMS: {f.get('dbms', '?')} | URL: {str(f.get('target_url', ''))[:60]}",
                S_SMALL,
            ))
    else:
        story.append(Paragraph("✓ No SQL injection vulnerabilities detected.", S_BODY))

    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 5 — ATTACK PATHS + RECOMMENDATIONS
    # ══════════════════════════════════════════════════════════════════════════
    attack_paths = report.get("attack_paths", [])
    story += [Paragraph("5. Attack Paths Identified", S_H1), hr(BDO_GOLD, 1.5)]
    if attack_paths:
        for i, ap in enumerate(attack_paths[:10], 1):
            story.append(Paragraph(f"<b>{i}.</b> {ap}", S_SMALL))
            story.append(sp(3))
    else:
        story.append(Paragraph("No attack paths identified.", S_BODY))

    story += [sp(10), Paragraph("6. Recommendations", S_H1), hr(BDO_GOLD, 1.5)]
    recs = report.get("recommendations", [])
    ai_recs = report.get("ai_analysis", {}).get("remediation_roadmap", [])

    if ai_recs:
        for phase_item in ai_recs:
            story.append(Paragraph(phase_item.get("phase", ""), S_H2))
            for action in (phase_item.get("actions") or []):
                story.append(Paragraph(f"→ {action}", S_SMALL))
            story.append(sp(4))
    elif recs:
        priority_colors = {
            "CRITICAL":       HexColor("#DC2626"),
            "IMMEDIATE":      HexColor("#DC2626"),
            "URGENT":         HexColor("#EA580C"),
            "HIGH PRIORITY":  HexColor("#EA580C"),
            "HIGH":           HexColor("#CA8A04"),
            "MEDIUM":         HexColor("#2563EB"),
            "ONGOING":        HexColor("#64748B"),
        }
        for rec in recs:
            prefix = rec.split(":")[0].upper() if ":" in rec else ""
            color  = next((v for k, v in priority_colors.items() if k in prefix), BDO_NAVY)
            story.append(Paragraph(f"→ {rec}", _style(
                f"rec_{hash(rec)}", fontSize=9, textColor=color, leading=14, spaceAfter=5,
            )))

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 6 — COMPLIANCE (if AI available)
    # ══════════════════════════════════════════════════════════════════════════
    compliance = report.get("ai_analysis", {}).get("compliance_violations", [])
    if compliance:
        story += [PageBreak(), Paragraph("7. Compliance Mapping", S_H1), hr(BDO_GOLD, 1.5)]
        comp_tbl = [[
            Paragraph("<b>Standard</b>",  S_BOLD),
            Paragraph("<b>Category</b>",  S_BOLD),
            Paragraph("<b>Findings</b>",  S_BOLD),
            Paragraph("<b>Impact</b>",    S_BOLD),
        ]]
        for c in compliance:
            comp_tbl.append([
                Paragraph(c.get("standard", ""), S_SMALL),
                Paragraph(c.get("category", ""), S_SMALL),
                Paragraph(", ".join(c.get("finding_refs", [])), S_SMALL),
                Paragraph(c.get("impact", ""), S_SMALL),
            ])
        story.append(Table(
            comp_tbl, colWidths=[3.5*cm, 4.5*cm, 5.5*cm, 4.2*cm],
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), BDO_NAVY),
                ("TEXTCOLOR",     (0, 0), (-1, 0), white),
                ("GRID",          (0, 0), (-1, -1), 0.3, BDO_BORDER),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [BDO_LIGHT, white]),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]),
        ))

    # ── Footer on every page ──────────────────────────────────────────────────
    def _add_page_number(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(HexColor("#718096"))
        canvas.drawString(2*cm, 1.2*cm, f"AuditSCAN Security Report — {target} — {date} — CONFIDENTIAL")
        canvas.drawRightString(W - 2*cm, 1.2*cm, f"Page {doc.page}")
        canvas.setStrokeColor(BDO_GOLD)
        canvas.setLineWidth(0.5)
        canvas.line(2*cm, 1.8*cm, W - 2*cm, 1.8*cm)
        canvas.restoreState()

    doc.build(story, onFirstPage=_add_page_number, onLaterPages=_add_page_number)
    return buf.getvalue()
