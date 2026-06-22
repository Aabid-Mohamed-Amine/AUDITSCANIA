from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import tempfile
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

logger = logging.getLogger("nuclei-service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="Nuclei Scanner Microservice", version="2.0.0")

# â”€â”€ Base tags always included for any web target â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# These cover the most common, highest-value findings regardless of tech stack
_BASE_WEB_TAGS: List[str] = [
    "exposures",          # exposed sensitive files (.env, keys, creds, backups)
    "misconfiguration",   # CORS, security headers, SSL misconfigs
    "default-logins",     # admin:admin, root:root, etc.
    "panels",             # admin/login panels
    "api",                # exposed API endpoints
    "token-spray",        # API token exposure
]

_BASE_NETWORK_TAGS: List[str] = [
    "network",
    "default-logins",
]

# â”€â”€ Technology â†’ Nuclei tags mapping â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_TECH_TAGS: Dict[str, List[str]] = {
    # CMS
    "WordPress":    ["wordpress", "cve", "wp-plugin", "misconfiguration"],
    "Drupal":       ["drupal", "cve"],
    "Joomla":       ["joomla", "cve"],
    "Magento":      ["magento", "cve"],
    "Shopify":      ["shopify"],
    "Ghost":        ["ghost", "cve"],

    # Web servers
    "Apache":       ["apache", "cve", "misconfiguration"],
    "Nginx":        ["nginx", "cve", "misconfiguration"],
    "IIS":          ["iis", "microsoft", "cve"],
    "LiteSpeed":    ["litespeed"],
    "OpenResty":    ["nginx", "lua"],
    "Tomcat":       ["tomcat", "apache", "cve"],
    "Jetty":        ["jetty", "java", "cve"],
    "Caddy":        ["caddy"],

    # Languages / frameworks
    "PHP":          ["php", "cve"],
    "Laravel":      ["laravel", "php", "cve"],
    "Symfony":      ["symfony", "php"],
    "Django":       ["django", "python", "misconfiguration"],
    "Flask":        ["flask", "python"],
    "Spring":       ["spring", "java", "cve", "springboot"],
    "ASP.NET":      ["asp", "dotnet", "iis", "cve"],
    "Node.js":      ["node", "nodejs"],
    "Express":      ["express", "nodejs"],
    "Ruby on Rails":["rails", "ruby", "cve"],

    # Frontend frameworks (JS bundles may expose endpoints)
    "React":        ["react", "javascript", "api"],
    "Angular":      ["angular", "javascript", "api"],
    "Vue.js":       ["vue", "javascript", "api"],
    "Next.js":      ["next", "javascript", "api"],

    # Databases (exposed services)
    "MySQL":        ["mysql", "network", "default-logins"],
    "PostgreSQL":   ["postgresql", "network"],
    "MongoDB":      ["mongodb", "network"],
    "Redis":        ["redis", "network"],
    "Elasticsearch":["elasticsearch", "network", "cve", "misconfiguration"],

    # DevOps / infrastructure
    "Jenkins":      ["jenkins", "cve", "default-logins"],
    "GitLab":       ["gitlab", "cve"],
    "GitHub":       ["github"],
    "Grafana":      ["grafana", "cve"],
    "Kibana":       ["kibana", "elasticsearch"],
    "Prometheus":   ["prometheus", "misconfiguration"],
    "Docker":       ["docker", "kubernetes"],
    "Kubernetes":   ["kubernetes", "k8s"],

    # Cloud / CDN
    "Cloudflare":   ["cloudflare", "waf-bypass"],
    "AWS CloudFront":["aws", "cloud", "s3"],
    "AWS":          ["aws", "cloud", "s3", "amazon"],
    "Azure CDN":    ["azure", "cloud", "microsoft"],
    "Azure":        ["azure", "cloud", "microsoft"],
    "Fastly":       ["fastly"],
    "Akamai":       ["akamai"],

    # Specific products
    "Confluence":   ["confluence", "atlassian", "cve"],
    "Jira":         ["jira", "atlassian", "cve"],
    "Bitbucket":    ["bitbucket", "atlassian"],
    "Splunk":       ["splunk"],
    "SonarQube":    ["sonarqube"],
    "Keycloak":     ["keycloak", "cve"],
    "Vault":        ["vault", "hashicorp"],
    "Consul":       ["consul", "hashicorp"],
    "RabbitMQ":     ["rabbitmq", "network"],
    "Kafka":        ["kafka", "network"],
}

# â”€â”€ Scan category â†’ tags â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_CATEGORY_TAGS: Dict[str, List[str]] = {
    "exposures":       ["exposures", "exposure"],
    "misconfigurations":["misconfiguration", "misconfig"],
    "cves":            ["cve"],
    "panels":          ["panels", "login", "admin"],
    "cloud":           ["cloud", "aws", "azure", "gcp", "s3", "bucket"],
    "api":             ["api", "graphql", "swagger", "openapi", "rest"],
    "default-logins":  ["default-logins"],
    "network":         ["network"],
    "ssl":             ["ssl", "tls"],
    "xss":             ["xss"],
    "sqli":            ["sqli", "sql-injection"],
    "ssrf":            ["ssrf"],
    "lfi":             ["lfi", "path-traversal"],
    "rce":             ["rce", "injection"],
    "idor":            ["idor", "access-control"],
    "open-redirect":   ["redirect"],
}


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target:          str
    severity:        str            = "info,low,medium,high,critical"
    timeout:         int            = 600
    templates:       Optional[List[str]] = None
    tags:            Optional[List[str]] = None
    extra_targets:   Optional[List[str]] = None
    tech_stack:      Optional[List[str]] = None
    scan_categories: Optional[List[str]] = None
    # Auth injection (optional)
    headers:         Optional[Dict[str, str]] = None
    cookies:         Optional[Dict[str, str]] = None


# ---------------------------------------------------------------------------
# Tech detection (Python httpx â€” no binary dependency)
# ---------------------------------------------------------------------------


async def _detect_tech(target: str, timeout: float = 10.0) -> List[str]:
    """
    Detect technologies from HTTP response headers and body.
    Used as fallback when no tech_stack provided by caller.
    """
    techs: List[str] = []
    url = target if target.startswith(("http://", "https://")) else f"http://{target}"

    _SERVER_MAP = {
        "nginx": "Nginx", "apache": "Apache", "iis": "IIS",
        "cloudflare": "Cloudflare", "litespeed": "LiteSpeed",
        "openresty": "OpenResty", "caddy": "Caddy",
        "gunicorn": "Gunicorn", "uvicorn": "Uvicorn",
        "tomcat": "Tomcat", "jetty": "Jetty",
    }
    _POWERED_MAP = {
        "php": "PHP", "asp.net": "ASP.NET", "express": "Express",
        "django": "Django", "flask": "Flask", "ruby": "Ruby on Rails",
        "laravel": "Laravel", "next.js": "Next.js",
    }
    _BODY_PATTERNS = [
        (r"wp-content|wp-includes|wordpress", "WordPress"),
        (r"drupal", "Drupal"),
        (r"joomla", "Joomla"),
        (r"__NEXT_DATA__|_next/", "Next.js"),
        (r"ng-version|angular\.js", "Angular"),
        (r"react\.js|__reactFiber", "React"),
        (r"vue\.js|__vue_", "Vue.js"),
        (r"laravel_session|XSRF-TOKEN", "Laravel"),
        (r"csrfmiddlewaretoken", "Django"),
        (r"PHPSESSID", "PHP"),
        (r"ASP\.NET_SessionId", "ASP.NET"),
        (r"X-Jenkins|Jenkins", "Jenkins"),
        (r"Atlassian|JIRA", "Jira"),
        (r"grafana", "Grafana"),
        (r"kibana", "Kibana"),
    ]

    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; AuditScan/2.0)"},
        ) as client:
            resp = await client.get(url)

        server  = resp.headers.get("server", "").lower()
        powered = resp.headers.get("x-powered-by", "").lower()
        body    = ""
        try:
            body = resp.text[:5000]
        except Exception:
            pass

        for kw, name in _SERVER_MAP.items():
            if kw in server:
                techs.append(name)
                break
        for kw, name in _POWERED_MAP.items():
            if kw in powered:
                techs.append(name)

        # CDN detection
        if resp.headers.get("cf-ray"):
            techs.append("Cloudflare")
        if resp.headers.get("x-amz-cf-id"):
            techs.append("AWS CloudFront")
        if resp.headers.get("x-azure-ref"):
            techs.append("Azure CDN")

        for pattern, name in _BODY_PATTERNS:
            if re.search(pattern, body, re.I) and name not in techs:
                techs.append(name)

    except Exception as exc:
        logger.debug("Tech detection failed for %s: %s", target, exc)

    return list(dict.fromkeys(techs))  # deduplicate preserving order


# ---------------------------------------------------------------------------
# Tag builder
# ---------------------------------------------------------------------------


def _build_tag_set(
    req_tags:        Optional[List[str]],
    tech_stack:      Optional[List[str]],
    scan_categories: Optional[List[str]],
    is_web_target:   bool,
) -> List[str]:
    """
    Build final Nuclei tag list by merging:
      - caller-provided tags (from Nmap/Subfinder context)
      - tech_stack â†’ _TECH_TAGS mapping
      - scan_categories â†’ _CATEGORY_TAGS mapping
      - base tags for web/network
    """
    tag_set: set = set()

    # Base coverage
    if is_web_target:
        tag_set.update(_BASE_WEB_TAGS)
    else:
        tag_set.update(_BASE_NETWORK_TAGS)

    # Caller-provided tags (from Nmap service detection)
    if req_tags:
        tag_set.update(req_tags)

    # Tech-based tags
    if tech_stack:
        for tech in tech_stack:
            for name, tags in _TECH_TAGS.items():
                if name.lower() in tech.lower() or tech.lower() in name.lower():
                    tag_set.update(tags)
                    break

    # Category-based tags
    if scan_categories:
        for cat in scan_categories:
            if cat in _CATEGORY_TAGS:
                tag_set.update(_CATEGORY_TAGS[cat])

    # Deduplicate and return sorted for reproducibility
    return sorted(tag_set)


def _build_base_cmd(output_path: str, severity: str) -> List[str]:
    """Construit les arguments communs Ã  toutes les commandes Nuclei."""
    return [
        "nuclei",
        "-o",            output_path,
        "-jsonl",
        "-severity",     severity,
        "-silent",
        "-no-color",
        "-no-interactsh",
        "-timeout",      "10",
        "-rate-limit",   "20",
        "-bulk-size",    "10",
        "-c",            "10",
        "-retries",      "1",
    ]


def _add_auth_flags(cmd: List[str], headers: Optional[Dict[str, str]], cookies: Optional[Dict[str, str]]) -> None:
    """Injecte les headers d'auth dans une commande Nuclei (modification en place)."""
    if headers:
        for hname, hval in headers.items():
            cmd.extend(["-H", f"{hname}: {hval}"])
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        cmd.extend(["-H", f"Cookie: {cookie_str}"])


def _build_cmd_templates(
    req:           ScanRequest,
    output_path:   str,
    targets_file:  Optional[str] = None,
) -> List[str]:
    cmd = _build_base_cmd(output_path, req.severity)
    if targets_file:
        cmd.extend(["-l", targets_file])
    else:
        cmd.extend(["-u", req.target])
    cmd += ["-t", "http/misconfiguration/"]
    _add_auth_flags(cmd, req.headers, req.cookies)
    return cmd


def _build_cmd_tags(
    req:           ScanRequest,
    output_path:   str,
    tags:          List[str],
    targets_file:  Optional[str] = None,
) -> List[str]:
    cmd = _build_base_cmd(output_path, req.severity)
    if targets_file:
        cmd.extend(["-l", targets_file])
    else:
        cmd.extend(["-u", req.target])
    if tags:
        cmd.extend(["-tags", ",".join(tags)])
    if req.templates:
        cmd.extend(["-id", ",".join(req.templates)])
    _add_auth_flags(cmd, req.headers, req.cookies)
    return cmd


def _is_web_target(target: str) -> bool:
    return target.startswith(("http://", "https://"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _aggregate_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _slim_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    info           = raw.get("info", {})
    classification = info.get("classification", {})
    return {
        "template_id":      raw.get("template-id", ""),
        "name":             info.get("name", ""),
        "severity":         info.get("severity", "unknown"),
        "description":      info.get("description", ""),
        "tags":             info.get("tags", []),
        "cve_ids":          classification.get("cve-id") or [],
        "cwe_ids":          classification.get("cwe-id") or [],
        "cvss_score":       classification.get("cvss-score"),
        "cvss_metrics":     classification.get("cvss-metrics", ""),
        "epss_score":       classification.get("epss-score"),
        "epss_percentile":  classification.get("epss-percentile"),
        "reference":        info.get("reference", []),
        "matched_at":       raw.get("matched-at", ""),
        "host":             raw.get("host", ""),
        "ip":               raw.get("ip", ""),
        "type":             raw.get("type", ""),
        "matcher_name":     raw.get("matcher-name", ""),
        "timestamp":        raw.get("timestamp", ""),
        "extracted_results": raw.get("extracted-results", []),
    }


# ---------------------------------------------------------------------------
# FastAPI endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "nuclei"}


@app.post("/scan")
async def scan(req: ScanRequest) -> Dict[str, Any]:
    logger.info(
        "Scan started â€” target=%s severity=%s templates=%d tags=%s tech=%s",
        req.target, req.severity,
        len(req.templates or []),
        req.tags,
        req.tech_stack,
    )

    result: Dict[str, Any] = {
        "target":          req.target,
        "findings":        [],
        "total":           0,
        "by_severity":     {},
        "templates_used":  req.templates or [],
        "tags_used":       [],
        "tech_detected":   req.tech_stack or [],
        "error":           None,
    }

    # â€”â€” 1. Tech detection if not provided â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”
    tech_stack = req.tech_stack or []
    if not tech_stack and _is_web_target(req.target):
        try:
            tech_stack = await _detect_tech(req.target)
            logger.info("Auto-detected tech: %s", tech_stack)
            result["tech_detected"] = tech_stack
        except Exception as exc:
            logger.warning("Tech detection failed: %s", exc)

    # â€”â€” 2. Build tag set â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”
    tags = _build_tag_set(
        req_tags        = req.tags,
        tech_stack      = tech_stack,
        scan_categories = req.scan_categories,
        is_web_target   = _is_web_target(req.target),
    )
    result["tags_used"] = tags
    logger.info("Final Nuclei tags (%d): %s", len(tags), tags)

    # â€”â€” 3. Build targets file â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”
    targets_file: Optional[str] = None
    if req.extra_targets:
        all_targets = [req.target] + [t for t in req.extra_targets if t and t != req.target]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(all_targets[:100]))
            targets_file = tf.name
        logger.info("Scanning %d targets", len(all_targets))

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp1:
        output_path1 = tmp1.name
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp2:
        output_path2 = tmp2.name

    cmd1 = _build_cmd_templates(req, output_path1, targets_file)

    _GENERIC_TAGS = {"http", "javascript"}
    useful_tags = [t for t in tags if t not in _GENERIC_TAGS]
    if len(useful_tags) < 2:
        logger.info(
            "[Nuclei] cmd2 skipped â€” only %d useful tags after filtering generic tags (http, javascript)",
            len(useful_tags),
        )
        cmd2: Optional[List[str]] = None
    else:
        cmd2 = _build_cmd_tags(req, output_path2, useful_tags, targets_file)

    logger.info("Nuclei cmd1 (templates): %s", " ".join(cmd1[:15]) + "...")
    if cmd2:
        logger.info("Nuclei cmd2 (tags):      %s", " ".join(cmd2[:15]) + "...")
    else:
        logger.info("Nuclei cmd2 (tags):      skipped (insufficient useful tags)")

    errors: List[str] = []
    # cmd1/cmd2 run in parallel via asyncio.gather, so each can use nearly
    # the full request budget. 90s was a hardcoded leftover that killed both
    # commands mid-scan regardless of the timeout the pipeline requested
    # (e.g. 600s) -- with 27 tags, nuclei needs much more than 90s just to
    # load templates and start matching.
    _CMD_TIMEOUT = max(90, req.timeout - 15)

    async def _run_cmd(cmd: List[str], label: str) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=_CMD_TIMEOUT)
            stderr_text = (stderr_bytes or b"").decode(errors="replace").strip()
            if stderr_text:
                logger.debug("Nuclei %s stderr: %s", label, stderr_text[:300])
            if proc.returncode == 2:
                # exit 2 = target unresponsive/skipped â€” rÃ©sultats partiels conservÃ©s
                logger.warning("[Nuclei] %s exited with code 2 (target unresponsive or no templates matched)", label)
            elif proc.returncode not in (0, 1):
                errors.append(f"{label}: exit {proc.returncode} â€” {stderr_text[:200]}")
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            # RÃ©sultats partiels dÃ©jÃ  streamÃ©s dans le fichier de sortie â€” pas un Ã©chec total
            logger.warning("[Nuclei] cmd timeout 90s â€” rÃ©sultats partiels conservÃ©s (%s)", label)
        except Exception as exc:
            errors.append(f"{label}: {exc}")
            logger.exception("Nuclei %s failed for %s", label, req.target)

    # Lancer les commandes (cmd2 peut Ãªtre sautÃ©e)
    gather_tasks = [_run_cmd(cmd1, "cmd1-templates")]
    if cmd2:
        gather_tasks.append(_run_cmd(cmd2, "cmd2-tags"))
    await asyncio.gather(*gather_tasks)

    if errors:
        result["error"] = " | ".join(errors)

    # â€”â€” 5. Parse + fusion + dÃ©duplication par template_id â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”â€”
    findings: List[Dict[str, Any]] = []
    seen_template_ids: set = set()

    def _parse_output(path: str) -> None:
        try:
            if os.path.exists(path) and os.path.getsize(path) > 0:
                with open(path, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            raw = json.loads(line)
                            slim = _slim_finding(raw)
                            tid = slim.get("template_id", "")
                            matcher = slim.get("matcher_name", "")
                            matched_at = slim.get("matched_at", "")
                            dedup_key = (tid, matcher, matched_at)
                            if tid and dedup_key in seen_template_ids:
                                continue  # dÃ©duplication par template_id
                            if tid:
                                seen_template_ids.add(dedup_key)
                            findings.append(slim)
                        except (json.JSONDecodeError, KeyError):
                            pass
        finally:
            try: os.unlink(path)
            except Exception: pass

    _parse_output(output_path1)
    _parse_output(output_path2)

    if targets_file:
        try: os.unlink(targets_file)
        except Exception: pass

    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    findings.sort(key=lambda f: _sev_order.get(f.get("severity", "unknown"), 5))

    cvss_scores = [f["cvss_score"] for f in findings if f.get("cvss_score")]

    result.update({
        "findings":    findings,
        "total":       len(findings),
        "by_severity": _aggregate_by_severity(findings),
        "max_cvss":    max(cvss_scores, default=None),
    })

    logger.info(
        "Scan complete â€” target=%s findings=%d critical=%d high=%d tags=%d",
        req.target, len(findings),
        result["by_severity"].get("critical", 0),
        result["by_severity"].get("high", 0),
        len(tags),
    )
    return result
