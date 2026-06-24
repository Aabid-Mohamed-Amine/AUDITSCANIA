"""
Agent IA de decision -- orchestration intelligente des outils de scan.

Analyse les resultats Nmap + headers HTTP de la cible pour decider :
  - quels outils lancer / ignorer
  - tags Nuclei adaptes a la technologie detectee
  - mode AJAX ZAP (active automatiquement pour les SPA/port 3000)
  - priorite du scan (web / network / api)

Strategie :
  1. Appel Gemini 2.5 Flash si GEMINI_API_KEY + AI_ANALYSIS_ENABLED
  2. Fallback rule-based local (meme regles encodees en dur)
  3. Hard-rules appliquees en post-processing sur la reponse Gemini
     pour garantir les contraintes de securite (IP privee, etc.)

Outils geres par l'agent (tools_to_run) :
  - subfinder  Phase 1   -- asset/subdomain discovery (skip si IP privee)
  - zap        Phase 3   -- web scanner actif (skip si pas de port web)
  - nuclei     Phase 2   -- CVE/template scanner (toujours actif)
  - dalfox     Phase 2   -- XSS scanner (skip si pas de params)
  - ffuf       Phase 2+3 -- directory/endpoint fuzzing (skip si pas de port web)
  - sqlmap     Phase 3   -- SQL injection (conditionnel)
  - gitleaks   Phase 3   -- secrets detection (toujours actif)
  - katana     Phase 3   -- JS/SPA crawler (skip si reseau pur)
  - nikto      Phase 3   -- server misconfig / backup files
  - wapiti     Phase 3   -- SQLi/XSS/CSRF/LFI/redirect
  - trivy      Phase 3   -- CVE/SCA container scanner (skip tant que non integre)

NON geres par l'agent (toujours lances dans leur phase) :
  - nmap       Phase 1   -- port scan obligatoire, resultat alimentant l'agent
  - shodan     Phase 1   -- threat intel (toujours actif)
  - abuseipdb  Phase 1   -- reputation (toujours actif)
  - virustotal Phase 1   -- reputation (toujours actif)

Fix v2 :
  - Rule 4b : port 3000 sans tech detectee -> SPA Node.js probable -> zap_ajax=True
  - Rule 4c : port 4200 -> Angular dev server -> zap_ajax=True
  - Rule 3b : postgres container detecte dans le reseau -> sqlmap force actif
  - http_probe data exploitee (title, server, powered_by) pour enrichir le contexte
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
from typing import Any, Dict, List, Set

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

# -- Outils geres par l'agent -------------------------------------------------
# nmap, shodan, abuseipdb, virustotal = toujours lances -> hors liste
ALL_TOOLS: List[str] = [
    "subfinder",   # Phase 1   -- subdomain discovery
    "zap",         # Phase 3   -- web active scanner
    "nuclei",      # Phase 2   -- CVE/template scanner
    "dalfox",      # Phase 2   -- XSS scanner
    "ffuf",        # Phase 2+3 -- directory/endpoint fuzzing
    "sqlmap",      # Phase 3   -- SQL injection (conditionnel)
    "gitleaks",    # Phase 3   -- secrets detection
    "katana",      # Phase 3   -- JS/SPA crawler
    "nikto",       # Phase 3   -- server misconfig/backup files
    "wapiti",      # Phase 3   -- SQLi/XSS/CSRF/LFI/redirect
    "trivy",       # Phase 3   -- CVE/SCA container scanner
]


# -- Context extraction --------------------------------------------------------


def _is_private_ip(target: str) -> bool:
    host = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        # hostname Docker interne (ex: auditscania-juiceshop-1) -> prive
        return "localhost" == host or "." not in host


def _extract_tech_context(
    nmap_result: Dict[str, Any],
    headers: Dict[str, str],
) -> Dict[str, Any]:
    """
    Extrait le contexte technologique depuis :
      - nmap_result : ports, services, products, technologies, http_probe
      - headers     : Server, X-Powered-By (depuis _fetch_server_tags Phase 1.2)
    """
    services: List[str] = []
    products: List[str] = []
    techs:    List[str] = []
    ports:    List[int] = []
    http_titles: List[str] = []

    for host in nmap_result.get("data", {}).get("hosts", []):
        for port_data in host.get("ports", []):
            if port_data.get("state") != "open":
                continue
            p  = port_data.get("port", 0)
            s  = port_data.get("service", "").lower()
            pr = port_data.get("product", "").lower()
            if p:
                ports.append(p)
            if s:
                services.append(s)
            if pr:
                products.append(pr)
            for t in port_data.get("technologies", []):
                techs.append(t.lower())

            # -- http_probe enrichment (donnees HTTP directes de Nmap) ---------
            probe = port_data.get("http_probe", {})
            if isinstance(probe, dict):
                title      = probe.get("title", "").lower()
                srv        = probe.get("server", "").lower()
                powered    = probe.get("powered_by", "").lower()
                probe_tech = probe.get("techs", [])

                if title:
                    http_titles.append(title)
                if srv:
                    services.append(srv)
                if powered:
                    products.append(powered)
                for t in probe_tech:
                    techs.append(t.lower())

    # Headers HTTP depuis _fetch_server_tags (Phase 1.2)
    server     = (headers.get("server")       or headers.get("Server")       or "").lower()
    powered_by = (headers.get("x-powered-by") or headers.get("X-Powered-By") or "").lower()

    # Deduplication
    all_blob_parts = services + products + techs + http_titles + [server, powered_by]
    blob = " ".join(p for p in all_blob_parts if p)

    return {
        "ports":       list(dict.fromkeys(ports)),
        "services":    list(dict.fromkeys(services)),
        "products":    list(dict.fromkeys(products)),
        "techs":       list(dict.fromkeys(techs)),
        "http_titles": list(dict.fromkeys(http_titles)),
        "server":      server,
        "powered_by":  powered_by,
        "blob":        blob,
    }


# -- Rule-based decision -------------------------------------------------------

_WEB_PORTS:    Set[int]  = {80, 443, 8080, 8443, 8000, 8888, 3000, 3001, 5000, 4200, 4000}
_SPA_PORTS:    Set[int]  = {3000, 3001, 4200, 5173, 8100}   # ports typiques SPA/Node.js
_ORM_KW:       List[str] = [
    "sqlite", "sequelize", "typeorm", "prisma", "mongoose",
    "knex", "bookshelf", "waterline",
]
_RDBMS_KW:     List[str] = ["mysql", "mariadb", "postgres", "postgresql", "mssql", "oracle"]
_SPA_KW:       List[str] = ["angular", "react", "vue", "next.js", "nuxt", "ember", "svelte",
                             "juice shop", "juiceshop", "owasp juice"]
_PHP_KW:       List[str] = ["php", "laravel", "symfony", "wordpress", "drupal", "joomla", "magento"]
_JAVA_KW:      List[str] = ["java", "spring", "tomcat", "jetty", "jboss", "wildfly"]
_CONTAINER_KW: List[str] = ["docker", "container", "k8s", "kubernetes", "alpine", "debian", "ubuntu"]
_NODE_KW:      List[str] = ["node", "express", "koa", "fastify", "nestjs"]
_DEVOPS_KW:    List[str] = ["jenkins", "gitlab", "jira", "confluence", "sonar", "nexus", "artifactory", "bamboo", "teamcity"]
_CMS_KW:       List[str] = ["wordpress", "drupal", "joomla", "typo3", "magento", "prestashop"]
_APACHE_KW:    List[str] = ["apache", "nginx", "lighttpd", "iis"]

_PROFILE_CONFIG: Dict[str, Any] = {
    "web_spa":         {"nuclei_tags": ["xss", "cors", "headers", "exposure", "misconfig", "token", "swagger", "unauth"], "nuclei_timeout": 120, "dalfox_timeout": 0, "ffuf_timeout": 90},
    "web_traditional": {"nuclei_tags": ["sqli", "lfi", "rce", "misconfig", "exposure"],       "nuclei_timeout": 180, "dalfox_timeout": 200, "ffuf_timeout": 120},
    "devops_tool":     {"nuclei_tags": ["panel", "unauth", "exposure", "token", "misconfig"], "nuclei_timeout": 180, "dalfox_timeout": 0,   "ffuf_timeout": 90},
    "cms":             {"nuclei_tags": ["wordpress", "drupal", "sqli", "xss", "exposure"],    "nuclei_timeout": 180, "dalfox_timeout": 180, "ffuf_timeout": 90},
    "web_generic":     {"nuclei_tags": ["cors", "csp", "headers", "unauth", "sqli", "xss"],  "nuclei_timeout": 150, "dalfox_timeout": 150, "ffuf_timeout": 90},
}


def _select_probe_packs(
    ctx: Dict[str, Any],
    is_private: bool,
) -> Dict[str, Any]:
    """
    Selects probe pack IDs based on the detected tech stack.
    Returns {"pack_ids": [...], "reason": "..."} for inclusion in agent_decide output.
    Fallback: generic_rest_api -- never returns an empty list.
    """
    blob        = ctx["blob"]
    ports       = list(ctx["ports"])
    titles_blob = " ".join(ctx.get("http_titles", [])).lower()
    powered_by  = ctx.get("powered_by", "").lower()
    server_hdr  = ctx.get("server",     "").lower()

    pack_ids: List[str] = []
    detected: List[str] = []

    # -- Express / Node.js ----------------------------------------------------
    _node_signals = (
        "express" in powered_by
        or "express" in server_hdr
        or any(k in blob for k in _NODE_KW)
        or any(p in _SPA_PORTS for p in ports)
        or any(k in titles_blob for k in ["juice", "owasp"])
    )
    if _node_signals:
        pack_ids.append("express_nodejs")
        _why: List[str] = []
        if "express" in powered_by:
            _why.append("X-Powered-By: Express header")
        if any(k in blob for k in _NODE_KW):
            _why.append("Node.js/Express keywords in tech stack")
        if any(p in _SPA_PORTS for p in ports):
            _why.append(f"SPA port {[p for p in ports if p in _SPA_PORTS]}")
        if any(k in titles_blob for k in ["juice", "owasp"]):
            _why.append("Juice Shop/OWASP page title")
        detected.append("express_nodejs (" + (", ".join(_why) if _why else "heuristic") + ")")

    # -- WordPress ------------------------------------------------------------
    if any(k in blob for k in ["wordpress", "wp-content", "wp-login", "wp-admin"]):
        pack_ids.append("wordpress")
        detected.append("wordpress (WordPress keywords in tech stack)")

    # -- Django ---------------------------------------------------------------
    if "django" in blob:
        pack_ids.append("django")
        detected.append("django (Django framework keywords)")

    # -- PHP generique  (skip si WordPress deja couvert) ----------------------
    if (any(k in blob for k in ["php", "laravel", "symfony"])
            and "wordpress" not in pack_ids):
        pack_ids.append("php_generic")
        detected.append("php_generic (PHP framework keywords)")

    # -- Fallback -------------------------------------------------------------
    if not pack_ids:
        pack_ids.append("generic_rest_api")
        detected.append("generic_rest_api (no specific stack detected)")

    return {
        "pack_ids": pack_ids,
        "reason":   " | ".join(detected),
    }


def _detect_target_profile(ctx: Dict[str, Any]) -> str:
    """Classifies the target into a scan profile from detected tech stack."""
    blob  = ctx["blob"]
    ports = ctx["ports"]
    if any(k in blob for k in _DEVOPS_KW):
        return "devops_tool"
    if any(k in blob for k in _CMS_KW):
        return "cms"
    if (any(k in blob for k in _NODE_KW + _SPA_KW)
            or any(p in _SPA_PORTS for p in ports)):
        return "web_spa"
    if any(k in blob for k in _APACHE_KW + _PHP_KW + _JAVA_KW):
        return "web_traditional"
    return "web_generic"


def _rule_based_decision(
    target: str,
    ctx: Dict[str, Any],
    is_private: bool,
    status_code: int = 0,
) -> Dict[str, Any]:
    skip:     Dict[str, str] = {}
    ajax:     bool           = False
    priority: str            = "web"

    blob        = ctx["blob"]
    ports       = list(ctx["ports"])   # mutable copy -- may be extended by URL inference
    http_titles = ctx.get("http_titles", [])
    titles_blob = " ".join(http_titles)

    # -- RULE 1: Target profile detection --------------------------------------
    profile  = _detect_target_profile(ctx)
    prof_cfg = _PROFILE_CONFIG[profile]
    tags: List[str] = list(prof_cfg["nuclei_tags"])
    logger.info("[AgentDecide] Target profile: %s | nuclei_tags=%s", profile, tags)

    # -- Juice Shop / OWASP detection -> override nuclei_tags ------------------
    _titles_lower = titles_blob.lower()
    _is_juiceshop = (
        "juice shop" in _titles_lower
        or "owasp" in _titles_lower
        or "juiceshop" in blob.lower()
        or (profile == "web_spa" and 3000 in ports)
    )
    if _is_juiceshop:
        tags = ["exposure", "misconfig", "sqli", "token", "swagger", "xss", "cors", "unauth", "redirect"]
        logger.info("[AgentDecide] Juice Shop detected -- nuclei_tags overridden for OWASP app profile")

    # -- URL-based port inference ----------------------------------------------
    # Nmap can return 0 ports for Docker-internal targets (DNS not ready yet,
    # target still booting, or port not in top-1000 list). If the target URL
    # contains an explicit port, use it so web scanners are not skipped.
    if not ports and target.startswith(("http://", "https://")):
        _m = re.match(r"https?://[^/:]+:(\d+)", target)
        if _m:
            _inferred = int(_m.group(1))
        else:
            _inferred = 443 if target.startswith("https://") else 80
        ports = [_inferred]
        logger.info(
            "[AgentDecide] URL-port inference: Nmap returned 0 ports -> "
            "inferred port %d from target URL %s", _inferred, target,
        )

    # -- Rule 1 -- IP privee / hostname Docker -> skip subfinder ----------------
    if is_private:
        skip["subfinder"] = "Private/loopback/internal hostname -- subfinder not relevant"

    # -- Detections technologiques ---------------------------------------------
    has_rdbms     = any(k in blob for k in _RDBMS_KW)
    has_orm       = any(k in blob for k in _ORM_KW)
    has_node      = any(k in blob for k in _NODE_KW)
    has_spa       = any(k in blob for k in _SPA_KW) or any(k in titles_blob for k in _SPA_KW)
    has_php       = any(k in blob for k in _PHP_KW)
    has_java      = any(k in blob for k in _JAVA_KW)
    has_container = any(k in blob for k in _CONTAINER_KW)
    has_web       = bool(ports) and any(p in _WEB_PORTS for p in ports)
    has_spa_port  = bool(ports) and any(p in _SPA_PORTS for p in ports)

    # -- Rule 2 -- SQLite / ORM -> skip sqlmap ----------------------------------
    if has_orm:
        skip["sqlmap"] = "ORM/SQLite detected -- SQLMap not relevant"

    # -- Rule 2b -- Node.js sans RDBMS explicite -> skip sqlmap -----------------
    # SAUF si postgres container dans le reseau (cas JuiceShop + postgres-1)
    elif has_node and not has_rdbms:
        # JuiceShop utilise SQLite en interne -> pas de SQLi classique detectable
        skip["sqlmap"] = "Node.js without detected relational DB -- skipping SQLMap"

    # -- Rule 3 -- RDBMS detecte -> sqlmap prioritaire (annule rules 2/2b) ------
    if has_rdbms:
        skip.pop("sqlmap", None)
        tags += ["sql", "sqli"]
        if "mysql" in blob or "mariadb" in blob:
            tags += ["mysql"]
        if "postgres" in blob or "postgresql" in blob:
            tags += ["postgresql"]

    # -- Rule 4 -- SPA detectee dans blob -> zap_ajax=True + tags JS -----------
    # ZAP Ajax Spider ET Katana sont complementaires : ZAP trouve les vulns de
    # formulaires JS, Katana extrait les endpoints. Les deux sont actives.
    if has_spa:
        ajax = True
        tags += ["exposure", "misconfig", "xss"]
        logger.info("[AgentDecide] SPA detectee via blob -> zap_ajax=True (Ajax Spider + Katana)")

    # -- Rule 4b -- Port SPA (3000/4200/5173) sans tech detectee ---------------
    # Nmap ne reconnait pas Angular (service=ppp sur port 3000) ->
    # heuristique port : probablement SPA Node.js -> ZAP Ajax Spider utile
    elif has_spa_port and not has_php and not has_java:
        ajax = True   # Active l'Ajax Spider ZAP pour crawler les routes Angular
        tags += ["exposure", "misconfig"]
        logger.info(
            "[AgentDecide] Port SPA detecte (%s) sans tech explicite -> "
            "zap_ajax=True (heuristique Node.js/Angular)",
            [p for p in ports if p in _SPA_PORTS],
        )

    # -- Rule 5 -- PHP -> nikto + wapiti + tags php -----------------------------
    if has_php:
        tags += ["php", "cve", "wordpress"]

    # -- Rule 6 -- Java/Spring -> tags java -------------------------------------
    if has_java:
        tags += ["java", "spring", "tomcat"]

    # -- Rule 7 -- Pas de port web -> reseau pur --------------------------------
    if ports and not has_web:
        priority = "network"
        for t in ["zap", "dalfox", "nikto", "wapiti", "ffuf", "katana"]:
            skip[t] = "No web port detected -- tool not relevant for pure network scan"

    # -- Rule 8 -- Pas de web et pas de framework connu -> skip sqlmap+dalfox ---
    if not has_web and not has_php and not has_java and not has_rdbms:
        skip["sqlmap"] = "No injectable parameters expected on pure network target"
        skip["dalfox"] = "No web forms expected on pure network target"

    # -- RULE 2: Smart skip -- devops_tool profile -> skip dalfox (no forms) ----
    if profile == "devops_tool" and "dalfox" not in skip:
        skip["dalfox"] = "devops_tool profile -- no user input forms expected"
        logger.info("[AGENT SKIP] dalfox: no forms detected in devops_tool profile -- dalfox not relevant")

    # -- RULE 2: Smart skip -- WAF detected (HTTP 403) -> skip nuclei ----------
    if status_code == 403 and "nuclei" not in skip:
        skip["nuclei"] = "Target returned 403 (WAF detected) -- nuclei templates likely blocked"
        logger.info("[AGENT SKIP] nuclei: target returned 403 (WAF) -- skipping nuclei")

    # -- Rule 9: Trivy skip silencieux tant que non integre --------------------
    skip["trivy"] = "not yet integrated"

    tools_to_run = [t for t in ALL_TOOLS if t not in skip]

    _probe_sel = _select_probe_packs(ctx, is_private)

    return {
        "tools":              tools_to_run,
        "skip":               list(skip.keys()),
        "reasons":            skip,
        "nuclei_tags":        sorted(set(tags)),
        "zap_ajax":           ajax,
        "priority":           priority,
        "probe_pack_ids":     _probe_sel["pack_ids"],
        "probe_pack_reasons": _probe_sel["reason"],
        "target_profile":     profile,
        "nuclei_timeout":     prof_cfg["nuclei_timeout"],
        "dalfox_timeout":     prof_cfg["dalfox_timeout"],
        "ffuf_timeout":       prof_cfg["ffuf_timeout"],
    }


# -- JSON extraction -----------------------------------------------------------


def _extract_json(text: str) -> dict:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find('{')
    if start == -1:
        raise ValueError("No JSON object found in response")

    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                candidate = text[start:i+1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    break

    clean = re.sub(r'```(?:json)?', '', text).strip()
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        raise ValueError("No valid JSON in Gemini response")


# -- Gemini prompt -------------------------------------------------------------


def _build_prompt(
    target: str,
    ctx: Dict[str, Any],
    is_private: bool,
) -> str:
    titles_str = ", ".join(ctx.get("http_titles", [])) or "none"
    return (
        f"Target: {target}\n"
        f"Private/internal: {is_private}\n"
        f"Open ports: {ctx['ports']}\n"
        f"Services: {ctx['services']}\n"
        f"Technologies: {ctx['techs']}\n"
        f"HTTP titles: {titles_str}\n"
        f"Server header: {ctx['server'] or 'none'}\n"
        f"X-Powered-By: {ctx['powered_by'] or 'none'}\n\n"
        "Available tools: subfinder, zap, nuclei, dalfox, ffuf, sqlmap, gitleaks, katana, nikto, wapiti, trivy\n\n"
        "Rules:\n"
        "- Private/internal hostname -> skip subfinder\n"
        "- ORM/SQLite detected -> skip sqlmap\n"
        "- Node.js without relational DB -> skip sqlmap\n"
        "- No web ports -> skip zap, dalfox, nikto, wapiti, ffuf, katana; priority=network\n"
        "- PHP/WordPress detected -> keep nikto and wapiti\n"
        "- MySQL/PostgreSQL detected -> keep sqlmap\n"
        "- trivy: skip unless Docker/container detected\n\n"
        "Return this JSON:\n"
        "{\n"
        '  "profile": "web_spa|web_traditional|devops_tool|cms|web_generic",\n'
        '  "tools": ["tools to run"],\n'
        '  "skip": ["tools to skip"],\n'
        '  "nuclei_tags": ["tag1", "tag2"],\n'
        '  "nuclei_timeout": 120,\n'
        '  "dalfox_timeout": 0,\n'
        '  "ffuf_timeout": 90,\n'
        '  "reason": "one line explanation"\n'
        "}"
    )


# -- Main entry point ----------------------------------------------------------


async def agent_decide(
    target:      str,
    nmap_result: Dict[str, Any],
    headers:     Dict[str, str],
) -> Dict[str, Any]:
    """
    AI decision agent -- decides which tools to run based on Nmap results
    and HTTP response headers.

    Returns dict with keys:
      tools       -- list of tools to run
      skip        -- list of tools to skip
      reasons     -- {tool: reason} for each skipped tool
      nuclei_tags -- Nuclei tags adapted to the detected technology
      zap_ajax    -- True/False for ZAP AJAX spider mode
      priority    -- "web" | "network" | "api"
      source      -- "gemini" | "rule-based" | "rule-based-fallback"

    Note: nmap, shodan, abuseipdb, virustotal are NOT in ALL_TOOLS --
    they are always executed unconditionally in Phase 1.
    """
    ctx         = _extract_tech_context(nmap_result, headers)
    is_private  = _is_private_ip(target)
    status_code = int(headers.get("_status_code", 0) or 0)

    logger.info(
        "[AgentDecide] ctx -- ports=%s services=%s techs=%s titles=%s server='%s' powered_by='%s'",
        ctx["ports"], ctx["services"], ctx["techs"],
        ctx.get("http_titles", []), ctx["server"], ctx["powered_by"],
    )

    rule_decision = _rule_based_decision(target, ctx, is_private, status_code=status_code)

    api_key = settings.GEMINI_API_KEY
    if not api_key or not settings.AI_ANALYSIS_ENABLED:
        logger.info("[AgentDecide] Gemini disabled -- rule-based decision for %s", target)
        rule_decision["source"] = "rule-based"
        return rule_decision

    prompt  = _build_prompt(target, ctx, is_private)
    model   = getattr(settings, "AI_MODEL", None) or "gemini-2.5-flash"
    url     = f"{GEMINI_BASE}/{model}:generateContent?key={api_key}"
    payload = {
        "systemInstruction": {
            "parts": [{"text": (
                "You are a security scan decision engine. "
                "Respond ONLY with a single valid JSON object. "
                "No markdown. No code blocks. No explanation. "
                "The JSON must be complete and properly closed."
            )}],
        },
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature":      0.1,
            "maxOutputTokens":  512,
            "responseMimeType": "application/json",
        },
    }

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()

        raw = (
            data.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
        )
        logger.debug("[AgentDecide] Gemini raw response (first 200 chars): %s", raw[:200])
        decision = _extract_json(raw)

        # Set defaults for fields not in the simplified prompt schema
        decision.setdefault("reasons", {})
        decision.setdefault("zap_ajax", False)
        decision.setdefault("priority", "web")

        required = {"tools", "skip", "nuclei_tags"}
        missing  = required - decision.keys()
        if missing:
            raise ValueError(f"Missing keys in Gemini response: {missing}")

        # -- Hard-rules post-processing (garanties absolues) -------------------

        # Hard-rule A -- IP privee/interne -> subfinder toujours skip
        if is_private and "subfinder" not in decision.get("skip", []):
            decision["skip"].append("subfinder")
            decision["reasons"]["subfinder"] = "Internal hostname -- enforced by hard rule"
            decision["tools"] = [t for t in decision["tools"] if t != "subfinder"]

        # Hard-rule B -- Trivy skip silencieux tant que non integre
        if "trivy" not in decision.get("skip", []):
            decision["skip"].append("trivy")
            decision["reasons"]["trivy"] = "not yet integrated"
            decision["tools"] = [t for t in decision["tools"] if t != "trivy"]

        # Hard-rule C -- Port SPA detecte -> forcer zap_ajax=True si Gemini l'a oublie
        has_spa_port = bool(ctx["ports"]) and any(
            p in _SPA_PORTS for p in ctx["ports"]
        )
        titles_blob = " ".join(ctx.get("http_titles", []))
        is_juiceshop = "juice" in titles_blob or "owasp" in titles_blob
        if (has_spa_port or is_juiceshop) and not decision.get("zap_ajax"):
            # Seulement si pas de SPA framework explicitement detecte
            # (si SPA detecte -> Katana gere, ZAP Ajax non necessaire)
            spa_in_blob = any(k in ctx["blob"] for k in _SPA_KW)
            if not spa_in_blob:
                decision["zap_ajax"] = True
                logger.info(
                    "[AgentDecide] Hard-rule C: zap_ajax force True "
                    "(port SPA=%s juiceshop=%s)", has_spa_port, is_juiceshop,
                )

        # Hard-rule D -- Valider que tous les tools sont dans ALL_TOOLS
        decision["tools"] = [t for t in decision["tools"] if t in ALL_TOOLS]
        decision["skip"]  = [t for t in decision["skip"]  if t in ALL_TOOLS]

        # Hard-rule E -- S'assurer que tools + skip couvrent tous ALL_TOOLS
        covered = set(decision["tools"]) | set(decision["skip"])
        for t in ALL_TOOLS:
            if t not in covered:
                decision["tools"].append(t)
                logger.warning("[AgentDecide] Tool '%s' missing from Gemini response -- added to tools", t)

        # Hard-rule F -- Probe packs selection (always overrides Gemini)
        _probe_sel = _select_probe_packs(ctx, is_private)
        decision["probe_pack_ids"]     = _probe_sel["pack_ids"]
        decision["probe_pack_reasons"] = _probe_sel["reason"]

        # Hard-rule G -- Target profile + timeouts (always override Gemini)
        _prof     = _detect_target_profile(ctx)
        _prof_cfg = _PROFILE_CONFIG.get(_prof, _PROFILE_CONFIG["web_generic"])
        decision["target_profile"] = _prof
        decision["nuclei_timeout"] = _prof_cfg["nuclei_timeout"]
        decision["dalfox_timeout"] = _prof_cfg["dalfox_timeout"]
        decision["ffuf_timeout"]   = _prof_cfg["ffuf_timeout"]
        if _prof == "devops_tool" and "dalfox" not in decision.get("skip", []):
            decision["skip"].append("dalfox")
            decision["reasons"]["dalfox"] = "devops_tool profile -- no user input forms expected"
            decision["tools"] = [t for t in decision["tools"] if t != "dalfox"]

        decision["source"] = "gemini"
        logger.info(
            "[AgentDecide] Gemini OK -- target=%s tools=%s skip=%s priority=%s ajax=%s probe_packs=%s",
            target, decision["tools"], decision["skip"],
            decision["priority"], decision["zap_ajax"], decision["probe_pack_ids"],
        )
        return decision

    except (json.JSONDecodeError, ValueError, KeyError, IndexError) as exc:
        logger.warning("[AgentDecide] Gemini parse error (%s) -- rule-based fallback", exc)
    except httpx.HTTPStatusError as exc:
        logger.warning("[AgentDecide] Gemini HTTP %s -- rule-based fallback", exc.response.status_code)
    except httpx.HTTPError as exc:
        logger.warning("[AgentDecide] Gemini HTTP error (%s) -- rule-based fallback", exc)
    except Exception as exc:
        logger.warning("[AgentDecide] Gemini unexpected error (%s) -- rule-based fallback", exc)

    # Enhanced skip rules for fallback path
    _fb_profile  = _detect_target_profile(ctx)
    _dalfox_skip = _fb_profile in ("web_spa", "devops_tool") or not ctx.get("has_forms", False)
    _sqlmap_skip = (_fb_profile == "devops_tool")

    _new_skips: List[str] = []
    if _dalfox_skip and "dalfox" not in rule_decision.get("skip", []):
        _new_skips.append("dalfox")
    if _sqlmap_skip and "sqlmap" not in rule_decision.get("skip", []):
        _new_skips.append("sqlmap")
    if is_private and "subfinder" not in rule_decision.get("skip", []):
        _new_skips.append("subfinder")

    if _new_skips:
        rule_decision["skip"]  = list(set(rule_decision.get("skip", [])) | set(_new_skips))
        rule_decision["tools"] = [t for t in rule_decision.get("tools", []) if t not in set(_new_skips)]

    rule_decision["dalfox_skip"]    = _dalfox_skip
    rule_decision["dalfox_timeout"] = 0 if _dalfox_skip else rule_decision.get("dalfox_timeout", 300)
    rule_decision["profile"]        = _fb_profile

    for tool in _new_skips:
        logger.info("[AGENT SKIP] %s: rule-based skip for profile=%s", tool, _fb_profile)
    logger.info("[AGENT DECISION] profile=%s | skipped=%s", _fb_profile, rule_decision.get("skip", []))

    rule_decision["source"] = "rule-based-fallback"
    return rule_decision