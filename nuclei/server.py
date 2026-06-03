"""
Nuclei vulnerability scanner microservice v2.

Améliorations :
  - Tech detection intégrée via httpx Python (si aucun contexte fourni)
  - Tags ET template IDs combinés (Nuclei supporte les deux simultanément)
  - Couverture élargie : exposures, misconfigurations, CVEs, panels,
    cloud buckets, API exposure, default-logins
  - Mapping tech → tags pour templates pertinents uniquement
  - Corrélation CVE ↔ technologie détectée
"""
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

# ── Base tags always included for any web target ──────────────────────────────
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

# ── Technology → Nuclei tags mapping ─────────────────────────────────────────
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

# ── Scan category → tags ──────────────────────────────────────────────────────
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
    severity:        str            = "low,medium,high,critical"
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
# Tech detection (Python httpx — no binary dependency)
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
      - tech_stack → _TECH_TAGS mapping
      - scan_categories → _CATEGORY_TAGS mapping
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


def _is_web_target(target: str) -> bool:
    return target.startswith(("http://", "https://"))


# ---------------------------------------------------------------------------
# Nuclei command builder
# ---------------------------------------------------------------------------


def _build_cmd(
    req:           ScanRequest,
    output_path:   str,
    tags:          List[str],
    targets_file:  Optional[str] = None,
) -> List[str]:
    cmd: List[str] = [
        "nuclei",
        "-o",            output_path,
        "-json",
        "-severity",     req.severity,
        "-silent",
        "-no-color",
        "-timeout",      "10",
        "-rate-limit",   "100",
        "-bulk-size",    "25",
        "-c",            "25",
        "-retries",      "1",
    ]

    if targets_file:
        cmd.extend(["-l", targets_file])
    else:
        cmd.extend(["-u", req.target])

    if req.templates and tags:
        cmd.extend(["-id", ",".join(req.templates)])
        cmd.extend(["-tags", ",".join(tags)])
    elif req.templates:
        cmd.extend(["-id", ",".join(req.templates)])
    elif tags:
        cmd.extend(["-tags", ",".join(tags)])

    # ── Auth injection via -H flags ────────────────────────────────────────
    if req.headers:
        for hname, hval in req.headers.items():
            cmd.extend(["-H", f"{hname}: {hval}"])
    if req.cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in req.cookies.items())
        cmd.extend(["-H", f"Cookie: {cookie_str}"])

    return cmd


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
        "cve_ids":          classification.get("cve-id", []),
        "cwe_ids":          classification.get("cwe-id", []),
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
        "Scan started — target=%s severity=%s templates=%d tags=%s tech=%s",
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

    # ── 1. Tech detection if not provided ────────────────────────────────────
    tech_stack = req.tech_stack or []
    if not tech_stack and _is_web_target(req.target):
        try:
            tech_stack = await _detect_tech(req.target)
            logger.info("Auto-detected tech: %s", tech_stack)
            result["tech_detected"] = tech_stack
        except Exception as exc:
            logger.warning("Tech detection failed: %s", exc)

    # ── 2. Build tag set ──────────────────────────────────────────────────────
    tags = _build_tag_set(
        req_tags        = req.tags,
        tech_stack      = tech_stack,
        scan_categories = req.scan_categories,
        is_web_target   = _is_web_target(req.target),
    )
    result["tags_used"] = tags
    logger.info("Final Nuclei tags (%d): %s", len(tags), tags)

    # ── 3. Build targets file ─────────────────────────────────────────────────
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        output_path = tmp.name

    targets_file: Optional[str] = None
    if req.extra_targets:
        all_targets = [req.target] + [t for t in req.extra_targets if t and t != req.target]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(all_targets[:100]))  # cap at 100 targets
            targets_file = tf.name
        logger.info("Scanning %d targets", len(all_targets))

    # ── 4. Run Nuclei ─────────────────────────────────────────────────────────
    cmd = _build_cmd(req, output_path, tags, targets_file)
    logger.info("Nuclei cmd: %s", " ".join(cmd[:20]) + "...")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=req.timeout)

        stderr_text = (stderr_bytes or b"").decode(errors="replace").strip()
        if stderr_text:
            logger.debug("Nuclei stderr: %s", stderr_text[:500])

        if proc.returncode not in (0, 1):
            result["error"] = stderr_text[:500]

    except asyncio.TimeoutError:
        try: proc.kill()
        except Exception: pass
        result["error"] = f"Nuclei scan timed out after {req.timeout}s"
        logger.warning("Scan timed out for %s", req.target)
        return result
    except Exception as exc:
        result["error"] = str(exc)
        logger.exception("Nuclei scan failed for %s", req.target)
        return result

    # ── 5. Parse output ───────────────────────────────────────────────────────
    findings: List[Dict[str, Any]] = []
    try:
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            with open(output_path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(_slim_finding(json.loads(line)))
                        except (json.JSONDecodeError, KeyError):
                            pass
    finally:
        try: os.unlink(output_path)
        except Exception: pass
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
        "Scan complete — target=%s findings=%d critical=%d high=%d tags=%d",
        req.target, len(findings),
        result["by_severity"].get("critical", 0),
        result["by_severity"].get("high", 0),
        len(tags),
    )
    return result
