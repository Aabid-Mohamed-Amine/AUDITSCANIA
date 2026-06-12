"""
AI Analysis service v3 — SOC-grade analysis.

Envoie au LLM :
  - Findings détaillés (CVE, CVSS, EPSS, attack paths, fp_status)
  - Endpoints (sensibles, API, auth) avec statuts HTTP
  - Security headers manquants / problématiques
  - Technologies détectées (stack complète)
  - Injections détectées (SQLi params, XSS endpoints)
  - Secrets trouvés (GitLeaks)
  - Services réseau exposés (Nmap services + bannières)
  - Threat Intel (VT + AbuseIPDB)
  - Risk score + composants

Génère :
  - SOC summary (opérationnel)
  - Executive summary (management)
  - Attack narrative (chaîne d'attaque réaliste avec MITRE ATT&CK)
  - Analyse par vulnérabilité (explication technique + impact métier + remédiation)
  - Matrice de priorisation (immediate / 72h / 1 semaine / 1 mois)
  - Roadmap remédiation
  - Mapping conformité (OWASP, PCI-DSS, GDPR, ISO27001)
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

GEMINI_BASE    = "https://generativelanguage.googleapis.com/v1beta/models"
ANTHROPIC_BASE = "https://api.anthropic.com/v1/messages"


# ── Prompt builder ────────────────────────────────────────────────────────────


def _fmt_list(items: List[str], prefix: str = "  • ", max_items: int = 10) -> str:
    if not items:
        return "  None.\n"
    return "".join(f"{prefix}{item}\n" for item in items[:max_items])


def _build_findings_block(findings: List[Dict], max_items: int = 25) -> str:
    if not findings:
        return "  None detected.\n"
    lines = []
    for f in findings[:max_items]:
        sev     = (f.get("severity") or "?").upper()
        title   = f.get("title", "Unknown")
        sources = ", ".join(f.get("sources") or [])
        cves    = ", ".join(f.get("cve_ids") or [])
        cvss    = f.get("cvss_score")
        epss    = f.get("epss_score")
        port    = f.get("affected_port")
        svc     = f.get("affected_service", "")
        fp_st   = f.get("fp_status", "")
        url     = f.get("matched_at", "")

        line = f"  [{sev}] {title}"
        if port:
            line += f" | port:{port}"
        if svc:
            line += f"/{svc}"
        if cves:
            line += f" | CVE: {cves}"
        if cvss:
            line += f" | CVSS:{cvss}"
        if epss:
            line += f" | EPSS:{epss:.3f}"
        if url:
            line += f" | @{url[:60]}"
        if fp_st:
            line += f" [{fp_st}]"
        line += f" (src:{sources})"
        lines.append(line)
    return "\n".join(lines) + "\n"


def _build_services_block(nmap_services: Dict[str, Any]) -> str:
    if not nmap_services:
        return "  No service data.\n"
    lines = []
    for port, svc in list(nmap_services.items())[:15]:
        name    = svc.get("name", "?")
        product = svc.get("product", "")
        version = svc.get("version", "")
        title   = svc.get("http_title", "")
        server  = svc.get("server_header", "")
        cdn     = svc.get("cdn", "")
        techs   = ", ".join(svc.get("technologies") or [])
        line = f"  Port {port}/{name}"
        if product:
            line += f" ({product}"
            if version:
                line += f" {version}"
            line += ")"
        if title:
            line += f' ["{title[:40]}"]'
        if server:
            line += f" server:{server[:30]}"
        if cdn:
            line += f" CDN:{cdn}"
        if techs:
            line += f" techs:{techs[:50]}"
        lines.append(line)
    return "\n".join(lines) + "\n"


def _build_endpoints_block(sensitive_eps: List, api_eps: List, auth_eps: List) -> str:
    block = ""
    if sensitive_eps:
        block += "  SENSITIVE/CRITICAL:\n"
        for ep in sensitive_eps[:8]:
            url    = ep.get("url", ep) if isinstance(ep, dict) else str(ep)
            status = ep.get("status", "") if isinstance(ep, dict) else ""
            sev    = (ep.get("severity", "") if isinstance(ep, dict) else "").upper()
            cat    = ep.get("category", "") if isinstance(ep, dict) else ""
            desc   = ep.get("description", "") if isinstance(ep, dict) else ""
            block += f"    [{sev}] {url}"
            if status:
                block += f" [HTTP {status}]"
            if cat:
                block += f" ({cat})"
            if desc:
                block += f" — {desc[:60]}"
            block += "\n"
    if api_eps:
        block += "  API ENDPOINTS:\n"
        for ep in api_eps[:6]:
            block += f"    {ep}\n"
    if auth_eps:
        block += "  AUTH ENDPOINTS:\n"
        for ep in auth_eps[:4]:
            url = ep.get("url", ep) if isinstance(ep, dict) else str(ep)
            block += f"    {url}\n"
    return block or "  None discovered.\n"


def _build_headers_block(abnormal_headers: List) -> str:
    if not abnormal_headers:
        return "  No header issues.\n"
    lines = []
    for h in abnormal_headers[:8]:
        issue = h.get("header_issue", "?")
        risk  = h.get("risk", "?")
        cwe   = h.get("cwe_id", "")
        lines.append(f"  [{risk.upper()}] {issue}" + (f" (CWE-{cwe})" if cwe else ""))
    return "\n".join(lines) + "\n"


def _build_injections_block(sqli: List, xss: List) -> str:
    block = ""
    if sqli:
        block += "  SQL INJECTION:\n"
        for f in sqli[:5]:
            param = f.get("parameter", "?")
            tech  = f.get("technique", "?")
            sev   = (f.get("severity", "?")).upper()
            url   = f.get("target_url", "")
            block += f"    [{sev}] param:{param} | technique:{tech}"
            if url:
                block += f" | url:{url[:50]}"
            block += "\n"
    if xss:
        block += "  XSS (Cross-Site Scripting):\n"
        for f in xss[:5]:
            param = f.get("parameter", "?")
            sev   = (f.get("severity", "?")).upper()
            url   = f.get("url", "")
            poc   = f.get("poc_type", "")
            block += f"    [{sev}] param:{param}"
            if poc:
                block += f" poc:{poc}"
            if url:
                block += f" | {url[:50]}"
            block += "\n"
    return block or "  None detected.\n"


def _build_secrets_block(secrets: List) -> str:
    if not secrets:
        return "  None detected.\n"
    lines = []
    for s in secrets[:6]:
        rule_id  = s.get("rule_id", "?")
        sev      = (s.get("severity", "?")).upper()
        file_    = s.get("file", "?")
        desc     = s.get("description", "")
        lines.append(f"  [{sev}] {rule_id} in {file_}" + (f" — {desc[:50]}" if desc else ""))
    return "\n".join(lines) + "\n"


def _build_prompt(target: str, scan_summary: Dict[str, Any]) -> str:
    # ── Extract all data sections ─────────────────────────────────────────────
    risk_score       = scan_summary.get("risk_score", 0)
    tech_stack       = scan_summary.get("tech_stack", [])
    open_ports       = scan_summary.get("open_ports", [])
    nmap_services    = scan_summary.get("nmap_services", {})
    cdn_providers    = scan_summary.get("cdn_providers", [])

    # Findings
    all_findings     = scan_summary.get("correlated_findings", [])
    confirmed        = [f for f in all_findings if f.get("fp_status") == "confirmed"]
    suspicious       = [f for f in all_findings if f.get("fp_status") == "suspicious"]
    informational_f  = [f for f in all_findings if f.get("fp_status") == "informational"]

    # Endpoints
    sensitive_eps    = scan_summary.get("sensitive_endpoints", [])
    api_endpoints    = scan_summary.get("api_endpoints", [])
    auth_endpoints   = scan_summary.get("auth_endpoints", [])
    endpoint_ranking = scan_summary.get("endpoint_risk_ranking", [])

    # Injection & web
    sqli_findings    = scan_summary.get("sqli_findings", [])
    xss_findings     = scan_summary.get("xss_findings", [])
    zap_alerts       = scan_summary.get("zap_alerts", [])
    abnormal_headers = scan_summary.get("abnormal_headers", [])

    # Secrets
    secrets          = scan_summary.get("secrets_found", [])

    # Threat intel
    vt_malicious     = scan_summary.get("vt_malicious", 0)
    abuse_confidence = scan_summary.get("abuse_confidence", 0)

    # Attack paths
    attack_paths     = scan_summary.get("attack_paths", [])

    # Risk components
    risk_components  = scan_summary.get("risk_components", {})

    # Stats
    zap_high = [a for a in zap_alerts if a.get("risk_code", 0) >= 3]
    zap_med  = [a for a in zap_alerts if a.get("risk_code", 0) == 2]

    tech_text    = ", ".join(tech_stack[:12]) if tech_stack else "Not detected"
    cdn_text     = ", ".join(cdn_providers) if cdn_providers else "None"
    ports_text   = ", ".join(str(p) for p in open_ports[:20]) if open_ports else "None found"

    # Risk component summary
    comp_text = ""
    if risk_components:
        comp_text = " | ".join(f"{k}:{v:.0f}" for k, v in list(risk_components.items())[:6])

    return f"""You are a senior penetration tester and SOC analyst with 15+ years of experience.
Analyze the following automated pentest results and produce a comprehensive security report.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TARGET PROFILE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target:          {target}
Risk Score:      {risk_score}/100
Tech Stack:      {tech_text}
CDN/WAF:         {cdn_text}
Open Ports:      {ports_text}
Risk Components: {comp_text or "N/A"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NETWORK SERVICES (Nmap + HTTP Probing)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{_build_services_block(nmap_services)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONFIRMED FINDINGS ({len(confirmed)}) — high confidence, ready to report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{_build_findings_block(confirmed, max_items=20)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SUSPICIOUS FINDINGS ({len(suspicious)}) — medium confidence, worth investigating
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{_build_findings_block(suspicious, max_items=10)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ENDPOINT EXPOSURE (FFUF + Katana)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{_build_endpoints_block(sensitive_eps, api_endpoints, auth_endpoints)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INJECTION FINDINGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{_build_injections_block(sqli_findings, xss_findings)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECURITY HEADERS (ZAP Analysis)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ZAP Alerts: {len(zap_alerts)} total | HIGH: {len(zap_high)} | MEDIUM: {len(zap_med)}
{_build_headers_block(abnormal_headers)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECRETS DETECTED (GitLeaks)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{_build_secrets_block(secrets)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THREAT INTELLIGENCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VirusTotal malicious detections: {vt_malicious}
AbuseIPDB confidence score:      {abuse_confidence}%
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ATTACK PATHS IDENTIFIED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{_fmt_list(attack_paths[:8])}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INSTRUCTIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Produce a professional security analysis. Be SPECIFIC — reference actual findings, ports, CVEs, and endpoints above.
Do NOT give generic security advice. Every remediation must reference the specific technology/version/config from the findings.

Respond ONLY with valid JSON (no markdown, no text outside JSON):
{{
  "soc_summary": "3-4 sentences for SOC daily ops — operational threats, what to monitor, what to block immediately",
  "executive_summary": "3-4 sentences for management — business risk, data exposure risk, regulatory implications",
  "risk_level": "Critical|High|Medium|Low|Informational",
  "risk_score_analysis": "2 sentences: why the score {risk_score}/100 is justified, what drives it up or down",
  "attack_narrative": "3-4 sentences describing the most realistic adversary attack chain using the specific findings above",
  "attack_phases": [
    {{
      "phase": "Reconnaissance|Initial Access|Execution|Persistence|Lateral Movement|Privilege Escalation|Exfiltration",
      "description": "specific description using actual findings",
      "evidence": "specific finding title or endpoint from the data above",
      "mitre_technique": "T1xxx (optional)"
    }}
  ],
  "top_vulnerabilities": [
    {{
      "rank": 1,
      "title": "exact finding title from the data",
      "severity": "critical|high|medium|low",
      "cvss_score": 0.0,
      "cve_ids": [],
      "affected_component": "specific service/port/endpoint",
      "technical_explanation": "2-3 sentences: WHY this is dangerous, HOW it can be exploited",
      "business_impact": "concrete data/service/financial impact",
      "remediation": "specific fix: version to upgrade to, config line to change, patch to apply",
      "remediation_effort": "15min|1h|4h|1day|1week",
      "priority": "immediate|72h|1week|1month"
    }}
  ],
  "remediation_roadmap": [
    {{
      "phase": "Immediate (0-24h)",
      "actions": ["specific action 1 referencing actual findings", "specific action 2"]
    }},
    {{
      "phase": "Short-term (72h-1 week)",
      "actions": ["specific action 1", "specific action 2"]
    }},
    {{
      "phase": "Medium-term (1 month)",
      "actions": ["specific action 1", "specific action 2"]
    }}
  ],
  "compliance_violations": [
    {{
      "standard": "OWASP Top 10 2021|PCI-DSS 4.0|GDPR|ISO27001|NIST",
      "category": "e.g. A03:2021 – Injection",
      "finding_refs": ["specific finding titles from above"],
      "impact": "specific compliance impact"
    }}
  ],
  "headers_analysis": "2-3 sentences on missing security headers and their specific risk for this target",
  "false_positive_assessment": "Assessment of result reliability: confirmed={len(confirmed)} suspicious={len(suspicious)} informational={len(informational_f)}",
  "detection_confidence": "low|medium|high"
}}"""


# ── JSON extractor ────────────────────────────────────────────────────────────


def _extract_json(raw: str) -> Dict[str, Any]:
    import re as _re
    text = raw.strip()
    text = _re.sub(r"```json\s*", "", text)
    text = _re.sub(r"```\s*",     "", text)
    text = text.strip()
    start = text.find("{")
    if start != -1:
        text = text[start:]
    # Si JSON tronqué → reculer depuis le dernier } jusqu'à trouver un parse valide (max 100 essais)
    attempts = 0
    for i in range(len(text) - 1, -1, -1):
        if text[i] == "}":
            try:
                return json.loads(text[:i + 1])
            except json.JSONDecodeError:
                attempts += 1
                if attempts >= 100:
                    break
    return json.loads(text)  # laisse remonter JSONDecodeError → fallback dans analyze_with_ai


# ── Modèles Gemini (ordre de priorité, vérifié disponible juin 2026) ──────────
_GEMINI_FALLBACK_CHAIN: List[str] = [
    "gemini-2.5-flash",          # ← recommandé : disponible + gratuit
    "gemini-2.0-flash-lite",
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-1.5-flash-latest",
]


def _key_hint(api_key: str) -> str:
    """Return a human-readable hint if the key format looks wrong."""
    if not api_key:
        return "GEMINI_API_KEY is empty."
    if not api_key.startswith("AIza"):
        return (
            f"La clé '{api_key[:6]}…' ne ressemble pas à une clé Gemini valide. "
            "Une clé Google AI Studio commence toujours par 'AIzaSy' (39 caractères). "
            "Obtenez une clé gratuite sur : https://aistudio.google.com/app/apikey"
        )
    return ""


# ── Gemini caller with retry + model fallback ────────────────────────────────


async def _call_gemini(prompt: str, api_key: str, model: str) -> Dict[str, Any]:
    import asyncio

    # ── Validate key format before any HTTP call ──────────────────────────────
    hint = _key_hint(api_key)
    if hint and not api_key.startswith("AIza"):
        raise ValueError(hint)

    # ── Build ordered model list: requested model first, then fallbacks ────────
    chain = [model] + [m for m in _GEMINI_FALLBACK_CHAIN if m != model]

    last_error: Exception = Exception("No Gemini model succeeded")

    for attempt_model in chain:
        url = f"{GEMINI_BASE}/{attempt_model}:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature":      0.10,
                "maxOutputTokens":  8192,
                "responseMimeType": "application/json",
            },
        }

        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=120.0) as client:
                    resp = await client.post(url, json=payload)

                # ── 429 Rate-limit ou quota épuisé ───────────────────────────
                if resp.status_code == 429:
                    body_429 = ""
                    try:
                        body_429 = resp.text
                    except Exception:
                        pass
                    # "limit: 0" = quota définitivement épuisé sur ce modèle
                    # → passer au modèle suivant IMMÉDIATEMENT (pas la peine d'attendre)
                    quota_exhausted = "limit: 0" in body_429 or "quota" in body_429.lower()
                    if quota_exhausted:
                        logger.warning(
                            "Gemini %s quota épuisé (free tier limit=0) → modèle suivant",
                            attempt_model,
                        )
                        last_error = httpx.HTTPStatusError(
                            f"429 quota exhausted on {attempt_model}",
                            request=resp.request, response=resp,
                        )
                        break  # → next model, pas d'attente
                    # Sinon : rate-limit temporaire → attendre et réessayer
                    wait = [15, 45, 90][attempt]
                    logger.warning("Gemini 429 rate-limit on %s (attempt %d/3) — waiting %ds",
                                   attempt_model, attempt + 1, wait)
                    await asyncio.sleep(wait)
                    last_error = httpx.HTTPStatusError(
                        "429 Too Many Requests", request=resp.request, response=resp,
                    )
                    continue

                # ── 404 Model not found → try next model immediately ──────────
                if resp.status_code == 404:
                    logger.warning("Gemini model %s → 404 (retiré ou inexistant), essai du suivant",
                                   attempt_model)
                    last_error = httpx.HTTPStatusError(
                        f"404 model not found: {attempt_model}",
                        request=resp.request, response=resp,
                    )
                    break  # break inner loop → next model in chain

                # ── 400/401/403 Auth error → fail fast with clear message ─────
                if resp.status_code in (400, 401, 403):
                    body = ""
                    try:
                        body = resp.json().get("error", {}).get("message", "")
                    except Exception:
                        pass
                    hint = _key_hint(api_key)
                    raise ValueError(
                        f"Gemini API erreur d'authentification (HTTP {resp.status_code}). "
                        + (f"Message: {body}. " if body else "")
                        + (hint or "Vérifiez GEMINI_API_KEY dans votre .env.")
                    )

                # ── 5xx serveur temporairement indisponible → retry + fallback ──
                if resp.status_code >= 500:
                    wait = [10, 30, 60][attempt]
                    logger.warning("Gemini %s HTTP %d (tentative %d/3) — attente %ds",
                                   attempt_model, resp.status_code, attempt + 1, wait)
                    last_error = httpx.HTTPStatusError(
                        f"HTTP {resp.status_code} on {attempt_model}",
                        request=resp.request, response=resp,
                    )
                    if attempt == 2:
                        break  # 3 tentatives épuisées → modèle suivant
                    await asyncio.sleep(wait)
                    continue

                resp.raise_for_status()

                data = resp.json()
                raw  = data["candidates"][0]["content"]["parts"][0]["text"].strip()
                analysis = _extract_json(raw)
                analysis["model_used"]  = attempt_model
                analysis["provider"]    = "gemini"
                if attempt_model != model:
                    analysis["model_fallback"] = f"fell back from {model} to {attempt_model}"
                logger.info("Gemini success — model=%s", attempt_model)
                return analysis

            except ValueError:
                raise   # clé invalide → échec immédiat
            except httpx.HTTPStatusError:
                raise   # déjà géré au-dessus (400/401/403 → raise, reste → break)
            except Exception as exc:
                last_error = exc
                logger.warning("Gemini %s tentative %d erreur: %s", attempt_model, attempt + 1, exc)
                if attempt == 2:
                    break  # 3 tentatives → modèle suivant
                await asyncio.sleep(5)

        logger.warning("Gemini model %s echec, essai du suivant dans la chaine", attempt_model)

    raise last_error


# ── Anthropic caller ──────────────────────────────────────────────────────────


async def _call_anthropic(prompt: str, api_key: str, model: str) -> Dict[str, Any]:
    import asyncio
    last_error: Exception = Exception("Anthropic: no attempt succeeded")
    for attempt in range(3):
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    ANTHROPIC_BASE,
                    headers={
                        "x-api-key":         api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type":      "application/json",
                    },
                    json={
                        "model":      model,
                        "max_tokens": 8192,
                        "messages":   [{"role": "user", "content": prompt}],
                    },
                )

            if resp.status_code in (400, 401, 403):
                body = ""
                try:
                    body = resp.json().get("error", {}).get("message", "")
                except Exception:
                    pass
                raise ValueError(f"Anthropic auth error HTTP {resp.status_code}: {body}")

            if resp.status_code == 529 or resp.status_code >= 500:
                wait = [10, 30, 60][attempt]
                logger.warning("Anthropic HTTP %d (attempt %d/3) — retry in %ds",
                               resp.status_code, attempt + 1, wait)
                last_error = httpx.HTTPStatusError(
                    f"HTTP {resp.status_code}", request=resp.request, response=resp,
                )
                if attempt < 2:
                    await asyncio.sleep(wait)
                    continue
                resp.raise_for_status()

            resp.raise_for_status()
            data     = resp.json()
            raw      = data["content"][0]["text"].strip()
            analysis = _extract_json(raw)
            analysis["model_used"] = model
            analysis["provider"]   = "anthropic"
            return analysis

        except ValueError:
            raise
        except httpx.TimeoutException as exc:
            last_error = exc
            logger.warning("Anthropic timeout (attempt %d/3)", attempt + 1)
            if attempt < 2:
                await asyncio.sleep(10)
        except Exception as exc:
            last_error = exc
            logger.warning("Anthropic attempt %d error: %s", attempt + 1, exc)
            if attempt < 2:
                await asyncio.sleep(5)

    raise last_error


# ── Structured fallback from pipeline data ────────────────────────────────────


def _build_ai_fallback_from_summary(scan_summary: Dict[str, Any]) -> Dict[str, Any]:
    """Fallback structuré depuis les données brutes du pipeline.
    Garantit que JSONDecodeError ne retourne jamais INFORMATIONAL/0 findings."""
    risk_score   = scan_summary.get("risk_score", 0)
    all_findings = scan_summary.get("correlated_findings", [])
    confirmed    = [f for f in all_findings if f.get("fp_status") == "confirmed"]
    attack_paths = scan_summary.get("attack_paths", [])
    sqli         = scan_summary.get("sqli_findings", [])
    xss          = scan_summary.get("xss_findings", [])
    secrets      = scan_summary.get("secrets_found", [])

    if risk_score >= 80:   risk_level = "Critical"
    elif risk_score >= 60: risk_level = "High"
    elif risk_score >= 40: risk_level = "Medium"
    elif risk_score >= 20: risk_level = "Low"
    else:                  risk_level = "Informational"

    _rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    top   = sorted(confirmed[:6], key=lambda f: _rank.get(f.get("severity", "info"), 0), reverse=True)

    top_vulns = []
    for i, f in enumerate(top, 1):
        sev  = f.get("severity", "info")
        port = f.get("affected_port", "")
        svc  = f.get("affected_service", "")
        comp = (f"{svc} port {port}".strip() if port else svc) or f.get("matched_at", "")[:60]
        top_vulns.append({
            "rank":                 i,
            "title":                f.get("title", "Unknown finding"),
            "severity":             sev,
            "cvss_score":           f.get("cvss_score"),
            "cve_ids":              f.get("cve_ids", []),
            "affected_component":   comp,
            "technical_explanation": f"Detected by {', '.join(f.get('sources', []))}.",
            "business_impact":      (
                "Potential unauthorized access or data exfiltration."
                if sev in ("critical", "high") else
                "Information disclosure or attack surface expansion."
            ),
            "remediation":          "Apply vendor patches and review service configuration.",
            "remediation_effort":   "4h" if sev in ("critical", "high") else "1day",
            "priority":             "immediate" if sev == "critical" else "72h" if sev == "high" else "1week",
        })

    by_sev    = scan_summary.get("by_severity", {})
    n_crit    = by_sev.get("critical", 0)
    n_high    = by_sev.get("high", 0)
    n_med     = by_sev.get("medium", 0)
    n_confirm = len(confirmed)

    immediate = []
    short     = []
    for f in confirmed[:5]:
        sev   = f.get("severity", "")
        title = f.get("title", "")
        if sev in ("critical", "high"):
            immediate.append(f"Remediate: {title}")
        elif sev == "medium":
            short.append(f"Address: {title}")
    if sqli:
        immediate.insert(0, "Patch SQL injection — validated by SQLMap")
    if xss:
        short.insert(0, "Fix XSS sinks — validated by Dalfox")
    if secrets:
        immediate.insert(0, f"Revoke {len(secrets)} exposed secret(s) detected by GitLeaks")
    if not immediate:
        immediate = ["Review all confirmed findings and apply available patches."]
    if not short:
        short = ["Schedule remediation window for medium-severity findings."]

    return {
        "soc_summary": (
            f"Target presents a {risk_level} risk (score {risk_score}/100). "
            f"{n_confirm} confirmed findings: critical={n_crit}, high={n_high}, medium={n_med}. "
            f"{'Immediate containment required.' if risk_level in ('Critical','High') else 'Monitor and schedule remediation.'}"
        ),
        "executive_summary": (
            f"Automated assessment identified {len(all_findings)} total findings "
            f"with a {risk_level} risk profile (score {risk_score}/100). "
            f"{n_crit} critical and {n_high} high severity issues require priority remediation."
        ),
        "risk_level":          risk_level,
        "risk_score_analysis": (
            f"Score {risk_score}/100 computed from {n_confirm} confirmed findings "
            f"({n_crit} critical, {n_high} high, {n_med} medium). AI narrative unavailable."
        ),
        "attack_narrative":    attack_paths[0] if attack_paths else "No active attack chain identified.",
        "attack_phases":       [],
        "top_vulnerabilities": top_vulns,
        "remediation_roadmap": [
            {"phase": "Immediate (0-24h)",       "actions": immediate[:3]},
            {"phase": "Short-term (72h-1 week)", "actions": short[:3]},
            {"phase": "Medium-term (1 month)",   "actions": ["Enable continuous security monitoring."]},
        ],
        "compliance_violations":     [],
        "headers_analysis":          "Manual review of security headers recommended.",
        "false_positive_assessment": f"Rule-based: {n_confirm} confirmed findings from pipeline.",
        "detection_confidence":      "medium",
        "model_used":                "rule-based-fallback",
        "provider":                  "fallback",
        "fallback":                  True,
        "fallback_reason":           "AI JSON parse error — structured fallback from pipeline data",
    }


# ── Main entry point ──────────────────────────────────────────────────────────


async def analyze_with_ai(
    target:       str,
    scan_summary: Dict[str, Any],
    api_key:      str,
    model:        str = "gemini-2.0-flash",
    provider:     str = "gemini",
) -> Dict[str, Any]:
    """Call Gemini or Anthropic and return structured SOC-grade analysis."""
    if not api_key:
        return {"error": "No API key configured", "enabled": False}

    prompt = _build_prompt(target, scan_summary)
    logger.info(
        "AI analysis — provider=%s model=%s prompt_chars=%d",
        provider, model, len(prompt),
    )

    try:
        if provider == "gemini":
            return await _call_gemini(prompt, api_key, model)
        else:
            return await _call_anthropic(prompt, api_key, model)

    except json.JSONDecodeError as exc:
        logger.warning("AI JSON parse error — fallback structuré activé: %s", exc)
        return _build_ai_fallback_from_summary(scan_summary)
    except Exception as exc:
        logger.error("AI analysis failed (%s): %s", provider, exc)
        return {"error": str(exc), "enabled": True, "provider": provider}
