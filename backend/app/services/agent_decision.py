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


def _rule_based_decision(
    target: str,
    ctx: Dict[str, Any],
    is_private: bool,
) -> Dict[str, Any]:
    skip:     Dict[str, str] = {}
    tags:     List[str]      = ["exposure", "misconfig", "xss", "sqli", "unauth", "panel", "discovery", "tech", "headers", "cors", "csp", "redirect"]
    ajax:     bool           = False
    priority: str            = "web"

    blob        = ctx["blob"]
    ports       = list(ctx["ports"])   # mutable copy -- may be extended by URL inference
    http_titles = ctx.get("http_titles", [])
    titles_blob = " ".join(http_titles)

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

    # ---- Rule 9 -- Trivy : skip silencieux tant que non integre dans scan_tasks.py ------------
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
    }


# -- Gemini prompt -------------------------------------------------------------


def _build_prompt(
    target: str,
    ctx: Dict[str, Any],
    is_private: bool,
) -> str:
    titles_str = ", ".join(ctx.get("http_titles", [])) or "none"
    return f"""You are a cybersecurity orchestration agent for the AUDITSCANIA scanner.
Analyze the target context and decide which security tools to run.

## Available tools and their roles
- subfinder  : subdomain/asset discovery
- zap        : web active scanner (XSS, SQLi, CSRF on forms) -- use ajax_spider=true for SPA
- nuclei     : CVE template scanner (always useful)
- dalfox     : XSS parameter scanner
- ffuf       : directory and endpoint fuzzer
- sqlmap     : SQL injection exploitation
- gitleaks   : secrets/credentials detection in responses
- katana     : JS/SPA crawler (extracts hidden API endpoints)
- nikto      : web server misconfig, backup files, admin panels
- wapiti     : web app auditor (SQLi, XSS, CSRF, LFI, Open Redirect)
- trivy      : CVE/SCA scanner for containers and dependencies

## Tools NOT in this list (always run, never skip)
nmap, shodan, abuseipdb, virustotal

## Target context
- Target: {target}
- Private/internal hostname or IP: {is_private}
- Open ports: {ctx['ports']}
- Detected services: {ctx['services']}
- Detected products: {ctx['products']}
- Detected technologies: {ctx['techs']}
- HTTP page titles: "{titles_str}"
- HTTP Server header: "{ctx['server'] or 'none'}"
- HTTP X-Powered-By: "{ctx['powered_by'] or 'none'}"

## Mandatory rules (apply ALL without exception)
1.  Private/internal hostname or IP -> skip "subfinder"
2.  SQLite or ORM keywords (sequelize, typeorm, prisma, mongoose) -> skip "sqlmap"
3.  Node.js WITHOUT a detected relational DB (MySQL/PostgreSQL/MSSQL) -> skip "sqlmap"
4.  No GET/POST parameters expected (pure network, no HTTP) -> skip "sqlmap" AND "dalfox"
5a. SPA framework detected in blob (Angular, React, Vue, Next.js, Nuxt, Juice Shop) -> zap_ajax=false (Katana handles JS crawl)
5b. Port 3000/4200/5173 open with no explicit PHP/Java tech -> probably Node.js SPA -> zap_ajax=true
6.  PHP detected (Laravel, Symfony, WordPress, Drupal, Joomla) -> keep "nikto" AND "wapiti", add php tags
7.  MySQL or PostgreSQL detected -> keep "sqlmap" (overrides rules 2 and 3)
8.  No web ports (80/443/8080/8443/3000/8000) -> skip "zap","dalfox","nikto","wapiti","ffuf","katana" -> priority="network"
9.  Container/Docker/Alpine indicators -> keep "trivy"; otherwise skip "trivy"
10. Page title contains "Juice Shop" or "OWASP" -> set zap_ajax=true, keep nikto+wapiti+dalfox

## Output (JSON only -- no markdown, no explanation, no extra text)
{{
  "tools": ["list", "of", "tools", "to", "run"],
  "skip": ["list", "of", "tools", "to", "skip"],
  "reasons": {{"tool_name": "short reason why skipped"}},
  "nuclei_tags": ["relevant", "nuclei", "tags"],
  "zap_ajax": false,
  "priority": "web"
}}

priority must be exactly one of: "web", "network", "api"
Output valid JSON only, starting with {{ and ending with }}."""


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
    ctx        = _extract_tech_context(nmap_result, headers)
    is_private = _is_private_ip(target)

    logger.info(
        "[AgentDecide] ctx -- ports=%s services=%s techs=%s titles=%s server='%s' powered_by='%s'",
        ctx["ports"], ctx["services"], ctx["techs"],
        ctx.get("http_titles", []), ctx["server"], ctx["powered_by"],
    )

    rule_decision = _rule_based_decision(target, ctx, is_private)

    api_key = settings.GEMINI_API_KEY
    if not api_key or not settings.AI_ANALYSIS_ENABLED:
        logger.info("[AgentDecide] Gemini disabled -- rule-based decision for %s", target)
        rule_decision["source"] = "rule-based"
        return rule_decision

    prompt  = _build_prompt(target, ctx, is_private)
    model   = getattr(settings, "AI_MODEL", None) or "gemini-2.5-flash"
    url     = f"{GEMINI_BASE}/{model}:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature":     0.0,
            "maxOutputTokens": 1024,
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
        clean    = re.sub(r"```(?:json)?\s*|\s*```", "", raw).strip()
        decision = json.loads(clean)

        required = {"tools", "skip", "reasons", "nuclei_tags", "zap_ajax", "priority"}
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

    rule_decision["source"] = "rule-based-fallback"
    return rule_decision