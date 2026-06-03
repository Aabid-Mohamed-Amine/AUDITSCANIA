"""
FFUF — endpoint/directory discovery microservice v3.

Améliorations anti-bruit :
  1. Baseline comparison : probe d'un chemin inexistant → filtre -fs/-fw/-fl
  2. Auto-calibration intelligente : -ac + filtres baseline combinés
  3. Cluster deduplication : supprime les pages similaires (même taille ±5%)
  4. Severity classification : critical / high / medium / informational
  5. Détection spécialisée : .git, backups, admin panels, config, debug, API
  6. Filtre CDN : désactive -ac sur les CDN (Cloudflare, etc.)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import uuid
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

logger = logging.getLogger("ffuf-service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="FFUF Discovery Microservice", version="3.0.0")

WORDLIST_MAIN     = "/wordlists/common.txt"
WORDLIST_FALLBACK = "/wordlists/fallback.txt"

_CLOUD_HOSTS = {
    "herokuapp.com", "vercel.app", "netlify.app", "azurewebsites.net",
    "cloudfront.net", "fastly.net", "github.io", "pages.dev",
    "fly.dev", "render.com", "railway.app", "onrender.com",
}

_STATIC_EXT = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webp", ".pdf",
}

# ── Severity classification rules ────────────────────────────────────────────
# Each rule: (regex_pattern, severity, category_label, description)
# Evaluated in order — first match wins.

_SEVERITY_RULES: List[Tuple[str, str, str, str]] = [
    # CRITICAL — secret/credential exposure
    (r"(\.git/(config|HEAD|COMMIT_EDITMSG|packed-refs|index)|\.gitconfig)$",
     "critical", "git_exposure",      "Git repository internals exposed"),
    (r"\.env(\.(local|production|staging|backup|test|example))?$",
     "critical", "secret_file",       "Environment file — may contain secrets/API keys"),
    (r"(id_rsa|\.ssh/|credentials\.json|\.aws/credentials|\.aws/config)$",
     "critical", "credentials",       "SSH key or cloud credentials file"),
    (r"(database|db)\.(sql|dump|bak|backup|gz)$",
     "critical", "db_dump",           "Database dump file"),
    (r"wp-config\.php$",
     "critical", "config_file",       "WordPress config with DB credentials"),
    (r"(docker-compose|\.dockerenv)(\.yml|\.yaml)?$",
     "critical", "infra_config",      "Docker configuration — may reveal internal services"),
    (r"\.htpasswd$",
     "critical", "credentials",       "Apache password file"),
    (r"(secrets|private|confidential)\.(yml|yaml|json|txt|env|php)$",
     "critical", "secret_file",       "Secrets file"),
    (r"(config|application)\.(yml|yaml)$",
     "critical", "config_file",       "Application config — may contain DB/API credentials"),

    # HIGH — admin panels & sensitive config
    (r"(phpmyadmin|pma|adminer|dbadmin)(/?|\.php)$",
     "high", "admin_panel",   "Database admin panel"),
    (r"wp-admin/?$",
     "high", "admin_panel",   "WordPress admin panel"),
    (r"(cpanel|whm|plesk|directadmin|ispmanager)/?$",
     "high", "admin_panel",   "Hosting control panel"),
    (r"(admin|administrator|administration|manage|management|backend)(/?|\.php|\.html|\.aspx)$",
     "high", "admin_panel",   "Admin panel"),
    (r"\.(bak|backup|old|orig|copy|save|~|\d+)$",
     "high", "backup_file",   "Backup file — may expose source code"),
    (r"(backup|bak)\.(zip|tar\.gz|tgz|tar|7z|rar|sql)$",
     "high", "backup_archive","Backup archive"),
    (r"(web\.config|\.htaccess)$",
     "high", "config_file",   "Web server config"),
    (r"(config|settings|configuration)\.(php|asp|aspx|ini|conf)$",
     "high", "config_file",   "Application config file"),
    (r"(install|installer|setup|upgrade)(/?|\.php|\.asp)$",
     "high", "installer",     "Installer — may allow re-installation"),
    (r"(xmlrpc\.php|wp-cron\.php)$",
     "high", "wordpress",     "WordPress attack surface"),

    # MEDIUM — debug / info disclosure / test endpoints
    (r"(phpinfo|php-info|php_info)(/?|\.php)$",
     "medium", "debug_endpoint", "PHP info — full server configuration exposed"),
    (r"server-(status|info)/?$",
     "medium", "debug_endpoint", "Apache server status/info"),
    (r"(actuator|manage)(/?|/health|/env|/info|/metrics|/dump|/heapdump|/loggers)$",
     "medium", "debug_endpoint", "Spring Boot Actuator endpoint"),
    (r"(debug|_debug|__debug__)(/?|\.php|\.asp)$",
     "medium", "debug_endpoint", "Debug interface"),
    (r"(console|rails/info|django-admin|_profiler)/?$",
     "medium", "debug_endpoint", "Framework console/profiler"),
    (r"(swagger|swagger-ui|api-docs|openapi|redoc)(/?|\.json|\.yaml)$",
     "medium", "api_docs",    "API documentation — full endpoint listing"),
    (r"(graphql|graphiql|playground)/?$",
     "medium", "api_endpoint","GraphQL endpoint"),
    (r"(test|tests|testing|dev|staging|demo)(/?|\.php)$",
     "medium", "test_env",    "Test/development environment"),
    (r"(trace|\.trace)$",
     "medium", "debug_endpoint", "HTTP TRACE enabled"),
    (r"(crossdomain\.xml|clientaccesspolicy\.xml)$",
     "medium", "policy_file", "Cross-domain policy — check for overly permissive rules"),

    # HIGH — API routes (elevated because auth bypass risk)
    (r"/(api|rest|v\d+)(/|$)",
     "high", "api_route",    "API route — injection/auth bypass surface"),
    (r"/(webhook|webhooks)/?$",
     "high", "api_route",    "Webhook endpoint"),

    # MEDIUM — auth endpoints
    (r"/(login|signin|sign-in|auth|oauth|sso|saml)(/?|\.php|\.html|\.aspx)$",
     "medium", "auth_endpoint", "Authentication endpoint"),
    (r"/(register|signup|sign-up)(/?|\.php|\.html)$",
     "medium", "auth_endpoint", "Registration endpoint"),
    (r"/(reset|forgot|recover)-?(password)?(/?|\.php)$",
     "medium", "auth_endpoint", "Password reset endpoint"),

    # INFORMATIONAL
    (r"(robots\.txt|sitemap.*\.xml|\.well-known/.*)$",
     "informational", "recon",       "Recon file — reveals paths/subdomains"),
    (r"(readme|changelog|license|authors?)(\.txt|\.md|\.html)?$",
     "informational", "disclosure",  "Version/tech disclosure"),
    (r"(upload|uploads|files|media|assets|static)/?$",
     "informational", "upload_dir",  "Upload/file directory"),
]

# Pre-compile regex patterns
_COMPILED_RULES = [(re.compile(pat, re.I), sev, cat, desc) for pat, sev, cat, desc in _SEVERITY_RULES]


# ── Helpers ───────────────────────────────────────────────────────────────────


class ScanRequest(BaseModel):
    target:     str
    timeout:    int              = 120
    threads:    int              = 40
    extensions: List[str]        = []
    # Auth injection (optional)
    headers:    Optional[Dict[str, str]] = None
    cookies:    Optional[Dict[str, str]] = None


def _wordlist() -> str:
    return (
        WORDLIST_MAIN
        if os.path.exists(WORDLIST_MAIN) and os.path.getsize(WORDLIST_MAIN) > 1000
        else WORDLIST_FALLBACK
    )


def _normalize(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    return target.rstrip("/")


def _is_cloud(target: str) -> bool:
    host = target.lower().split("//")[-1].split("/")[0].split(":")[0]
    return any(host.endswith(c) for c in _CLOUD_HOSTS)


# ── Baseline probe ────────────────────────────────────────────────────────────


async def _get_baseline(target: str) -> Dict[str, Any]:
    """
    Request a guaranteed-nonexistent path to capture the server's 'real 404' response.
    Returns size/words/lines used to build FFUF filter flags.
    """
    probe_path = f"/{uuid.uuid4().hex}_auditscan_probe"
    url        = f"{target}{probe_path}"
    baseline   = {"status": None, "size": None, "words": None, "lines": None, "error": None}
    try:
        async with httpx.AsyncClient(
            timeout=8.0, verify=False, follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; AuditScan/3.0)"},
        ) as client:
            resp = await client.get(url)
            body = resp.content
            text = body.decode(errors="replace")
            baseline.update({
                "status": resp.status_code,
                "size":   len(body),
                "words":  len(text.split()),
                "lines":  text.count("\n"),
            })
            logger.info("Baseline: %s → %d size=%d words=%d",
                        url, resp.status_code, baseline["size"], baseline["words"])
    except Exception as exc:
        baseline["error"] = str(exc)
        logger.warning("Baseline probe failed: %s", exc)
    return baseline


def _build_filter_flags(baseline: Dict[str, Any], is_cloud: bool) -> List[str]:
    """
    Build FFUF -fs/-fw/-fl flags from baseline response.
    Only filter if the baseline returned 200/301/302 (custom 404 pattern).
    """
    flags: List[str] = []
    status = baseline.get("status")
    if status is None or baseline.get("error"):
        return flags
    # If the server returns 404 or 400 → standard behavior, let FFUF handle it
    if status in (404, 400, 410, 501):
        return flags
    # Custom 404 (returns 200/301/302) → filter by size and words
    size  = baseline.get("size")
    words = baseline.get("words")
    if size is not None and size > 0:
        flags += ["-fs", str(size)]
    if words is not None and words > 0 and not is_cloud:
        flags += ["-fw", str(words)]
    return flags


# ── Cluster deduplication (similar-page filter) ───────────────────────────────


def _cluster_filter(results: List[Dict]) -> List[Dict]:
    """
    Remove results whose size clusters with a dominant group (>60% of total).
    This eliminates noise from servers that return the same generic page for
    many paths (soft-404, WAF block pages, catch-all templates).
    """
    if len(results) < 8:
        return results

    # Group by size rounded to nearest 50 bytes
    def _bucket(size: int) -> int:
        return (size // 50) * 50

    bucket_counter = Counter(_bucket(r.get("length", 0)) for r in results)
    total = len(results)
    dominant = {b for b, cnt in bucket_counter.items() if cnt / total > 0.60}

    if not dominant:
        return results

    filtered = [r for r in results if _bucket(r.get("length", 0)) not in dominant]
    removed  = total - len(filtered)
    logger.info("Cluster filter: removed %d/%d results in dominant size buckets %s",
                removed, total, dominant)
    return filtered


# ── Severity classification ───────────────────────────────────────────────────


def _classify_severity(ep: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Returns (severity, category, description) for an endpoint.
    Falls back to status-based classification if no pattern matches.
    """
    url    = ep.get("url", "")
    path   = url.lower().split("?")[0]
    last   = path.rstrip("/").rsplit("/", 1)[-1]
    _, ext = os.path.splitext(last)

    if ext in _STATIC_EXT:
        return "informational", "static_asset", "Static file"

    for pattern, severity, category, description in _COMPILED_RULES:
        if pattern.search(path):
            return severity, category, description

    # Fallback: classify by HTTP status
    status = ep.get("status", 200)
    if status == 200:
        return "informational", "page",    "Accessible page"
    if status in (401, 403):
        return "medium", "restricted",     "Restricted — may be bypassable"
    if status in (301, 302, 307):
        return "informational", "redirect","Redirect"
    if status == 500:
        return "medium", "server_error",   "Server error — may reveal stack trace"
    return "informational", "other", "Endpoint"


def _build_classified(endpoints: List[Dict]) -> Dict[str, Any]:
    """
    Build severity-keyed classification with full metadata per endpoint.
    Returns both severity buckets and legacy category buckets.
    """
    by_severity: Dict[str, List[Dict]] = {
        "critical": [], "high": [], "medium": [], "informational": [],
    }
    by_category: Dict[str, List[Dict]] = {}

    for ep in endpoints:
        sev, cat, desc = _classify_severity(ep)
        enriched = dict(ep, severity=sev, category=cat, description=desc)
        by_severity[sev].append(enriched)
        by_category.setdefault(cat, []).append(enriched)

    return {"by_severity": by_severity, "by_category": by_category}


# ── FFUF runner ───────────────────────────────────────────────────────────────


async def _run_ffuf(
    fuzz_url:      str,
    wordlist:      str,
    threads:       int,
    exts:          str,
    timeout:       int,
    output_file:   str,
    auto_calibrate: bool,
    extra_filters: Optional[List[str]] = None,
    auth_headers:  Optional[Dict[str, str]] = None,
    auth_cookies:  Optional[Dict[str, str]] = None,
) -> bytes:
    cmd = [
        "ffuf",
        "-u",       fuzz_url,
        "-w",       wordlist,
        "-o",       output_file,
        "-of",      "json",
        "-t",       str(threads),
        "-timeout", "10",
        "-mc",      "200,201,204,301,302,307,401,403,405,500",
        "-s",
    ]
    if auto_calibrate:
        cmd.append("-ac")
    if exts:
        cmd += ["-e", exts]
    if extra_filters:
        cmd += extra_filters
    # ── Auth injection ────────────────────────────────────────────────────
    if auth_headers:
        for hname, hval in auth_headers.items():
            cmd += ["-H", f"{hname}: {hval}"]
    if auth_cookies:
        cmd += ["-b", "; ".join(f"{k}={v}" for k, v in auth_cookies.items())]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    return stderr


def _read_results(output_file: str) -> List[Dict[str, Any]]:
    if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
        return []
    try:
        with open(output_file) as fh:
            data = json.load(fh)
        return data.get("results", [])
    except Exception:
        return []


# ── Main endpoint ─────────────────────────────────────────────────────────────


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "ffuf"}


@app.post("/scan")
async def scan(req: ScanRequest) -> Dict[str, Any]:
    target_url   = _normalize(req.target)
    fuzz_url     = f"{target_url}/FUZZ"
    is_cloud     = _is_cloud(target_url)
    logger.info("FFUF scan — target=%s cloud=%s", target_url, is_cloud)

    result: Dict[str, Any] = {
        "target":      target_url,
        "endpoints":   [],
        "total":       0,
        "by_status":   {},
        "by_severity": {"critical": [], "high": [], "medium": [], "informational": []},
        "by_category": {},
        "severity_counts": {},
        "sensitive_urls":  [],
        "baseline":    {},
        "error":       None,
    }

    wordlist = _wordlist()
    exts     = ",".join(f".{e.lstrip('.')}" for e in req.extensions) if req.extensions else ""

    # ── 1. Baseline probe ────────────────────────────────────────────────────
    baseline       = await _get_baseline(target_url)
    result["baseline"] = baseline
    filter_flags   = _build_filter_flags(baseline, is_cloud)
    logger.info("Filter flags from baseline: %s", filter_flags)

    output_file = f"/tmp/ffuf_{uuid.uuid4().hex[:12]}.json"
    raw_results: List[Dict] = []

    try:
        # ── 2. Strategy selection ────────────────────────────────────────────
        # Cloud CDN: no -ac (CDN normalizes responses → over-filters)
        # Otherwise: -ac + baseline filters for best coverage
        use_ac = not is_cloud

        stderr = await _run_ffuf(
            fuzz_url, wordlist, req.threads, exts,
            req.timeout, output_file, use_ac, filter_flags,
            auth_headers=req.headers, auth_cookies=req.cookies,
        )

        raw_results = _read_results(output_file)

        # ── 3. Retry without -ac if 0 results (over-calibrated) ─────────────
        if use_ac and not raw_results:
            logger.info("FFUF -ac returned 0 results, retrying without -ac (keeping size filters)")
            try: os.unlink(output_file)
            except Exception: pass
            output_file = f"/tmp/ffuf_{uuid.uuid4().hex[:12]}.json"
            stderr = await _run_ffuf(
                fuzz_url, wordlist, req.threads, exts,
                req.timeout, output_file, False, filter_flags,
                auth_headers=req.headers, auth_cookies=req.cookies,
            )
            raw_results = _read_results(output_file)

        # ── 4. Retry without any filter if still 0 (very strict server) ─────
        if not raw_results and filter_flags:
            logger.info("FFUF still 0 results, retrying without filters")
            try: os.unlink(output_file)
            except Exception: pass
            output_file = f"/tmp/ffuf_{uuid.uuid4().hex[:12]}.json"
            stderr = await _run_ffuf(
                fuzz_url, wordlist, req.threads, exts,
                req.timeout, output_file, False, None,
                auth_headers=req.headers, auth_cookies=req.cookies,
            )
            raw_results = _read_results(output_file)

        if not raw_results:
            err = stderr.decode(errors="replace").strip() if stderr else ""
            if err:
                result["error"] = err[:500]
            logger.info("FFUF: no results for %s", target_url)
            return result

        # ── 5. Parse raw results ─────────────────────────────────────────────
        raw_endpoints: List[Dict] = []
        by_status: Dict[int, int]  = {}
        for r in raw_results:
            status = int(r.get("status", 0))
            ep = {
                "url":      r.get("url", ""),
                "status":   status,
                "length":   r.get("length", 0),
                "words":    r.get("words", 0),
                "lines":    r.get("lines", 0),
                "redirect": r.get("redirectlocation", ""),
            }
            raw_endpoints.append(ep)
            by_status[status] = by_status.get(status, 0) + 1

        # ── 6. Post-processing filters ───────────────────────────────────────
        # 6a. Cluster deduplication (similar-page filter)
        endpoints = _cluster_filter(raw_endpoints)

        # 6b. Dominant-size filter (catches -ac misses on some servers)
        size_counts = Counter(ep["length"] for ep in endpoints)
        total = len(endpoints)
        dominant_exact = {
            sz for sz, cnt in size_counts.items()
            if cnt / total > 0.65 and sz > 0
        }
        if dominant_exact:
            before = len(endpoints)
            endpoints = [ep for ep in endpoints if ep["length"] not in dominant_exact]
            logger.info("Dominant-size filter: %d → %d", before, len(endpoints))

        # Sort: 200s first, then by status, then alphabetically
        endpoints.sort(key=lambda x: (
            x["status"] not in {200, 201},
            x["status"],
            x.get("url", ""),
        ))

        # ── 7. Severity classification ───────────────────────────────────────
        classified   = _build_classified(endpoints)
        by_severity  = classified["by_severity"]
        by_category  = classified["by_category"]

        severity_counts = {k: len(v) for k, v in by_severity.items() if v}
        sensitive_urls  = [
            ep["url"] for ep in (
                by_severity["critical"] + by_severity["high"]
            )
        ]

        result.update({
            "endpoints":      endpoints,
            "total":          len(endpoints),
            "by_status":      {str(k): v for k, v in by_status.items()},
            "by_severity":    by_severity,
            "by_category":    {k: len(v) for k, v in by_category.items() if v},
            "categorized":    by_category,
            "severity_counts": severity_counts,
            "sensitive_urls":  sensitive_urls,
        })

    except asyncio.TimeoutError:
        result["error"] = f"FFUF timed out after {req.timeout}s"
    except Exception as exc:
        result["error"] = str(exc)
        logger.exception("FFUF scan failed for %s", target_url)
    finally:
        try: os.unlink(output_file)
        except Exception: pass

    logger.info(
        "FFUF done — %s | total=%d critical=%d high=%d medium=%d",
        target_url, result["total"],
        result["severity_counts"].get("critical", 0),
        result["severity_counts"].get("high", 0),
        result["severity_counts"].get("medium", 0),
    )
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9006)
