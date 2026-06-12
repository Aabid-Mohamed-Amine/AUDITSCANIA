"""
SQLMap — SQL injection assessment microservice v2.

Pipeline endpoint → params → SQLMap :
  1. Extraction automatique des params GET depuis les URLs
  2. Extraction depuis les form_params ZAP (POST)
  3. Extraction depuis les API endpoints Katana/FFUF
  4. Scoring et priorisation des cibles injectables
  5. Filtrage des endpoints non pertinents
  6. Sélection de payload adaptée au type de paramètre
  7. Runs parallèles sur les N meilleures cibles (budget timeout)
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

from fastapi import FastAPI
from pydantic import BaseModel

logger = logging.getLogger("sqlmap-service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="SQLMap Assessment Microservice", version="2.0.0")

# ── Safe assessment flags (no data extraction, no destructive payloads) ──────
_BASE_FLAGS = [
    "--batch",
    "--level=2",           # level 2: more params, cookies (vs 1)
    "--risk=1",            # safest: no heavy UPDATE/INSERT payloads
    "--no-cast",
    "--fresh-queries",
    "--disable-coloring",
    "--timeout=15",        # per-request timeout
    "--retries=1",
    "--threads=1",
    "--delay=2",
]

# Extensions to skip (static assets)
_SKIP_EXT = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".map",
}

# Param names highly likely to be injectable (score boost)
_HIGH_VALUE_PARAMS = {
    "id", "user_id", "product_id", "item_id", "post_id", "article_id",
    "category_id", "order_id", "page_id", "news_id", "blog_id",
    "uid", "pid", "cid", "aid", "tid", "nid",
    "user", "username", "login", "email",
    "search", "query", "q", "keyword", "term", "filter",
    "name", "title", "slug", "type", "cat", "tag",
    "from", "to", "start", "end", "date", "year", "month",
    "file", "path", "url", "redirect", "next", "return", "ref",
    "action", "cmd", "command", "exec", "run",
    "token", "key", "api_key", "secret",
    "code", "ref", "session",
}

# Params that are never injectable (tracking, analytics, etc.)
_SKIP_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "_ga", "_gid", "_fbp", "_fbc",
    "ref", "source",  # low value
    "lang", "locale", "language",
    "format", "output", "_", "callback", "jsonp",
}


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class EndpointInput(BaseModel):
    url:    str
    method: str       = "GET"
    params: List[str] = []
    data:   str       = ""      # POST body template


class ScanRequest(BaseModel):
    target:      str
    timeout:     int               = 180
    test_forms:  bool              = True
    # Enriched inputs from ZAP / FFUF / Katana
    endpoints:   List[EndpointInput] = []
    form_params: List[str]           = []
    extra_urls:  List[str]           = []
    # Auth injection (optional)
    headers:     Optional[Dict[str, str]] = None
    cookies:     Optional[Dict[str, str]] = None


# ---------------------------------------------------------------------------
# URL / param helpers
# ---------------------------------------------------------------------------


def _normalize(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"http://{target}"
    return target


def _extract_get_params(url: str) -> List[str]:
    try:
        return [k for k in parse_qs(urlparse(url).query).keys()
                if k.lower() not in _SKIP_PARAMS]
    except Exception:
        return []


def _inject_dummy_values(url: str, params: List[str]) -> str:
    """
    Add dummy test values for known param names when the URL has no query string.
    Allows SQLMap to target those params directly.
    Example: /search + ["q"] → /search?q=test
    """
    if "?" in url:
        return url  # already has query string
    if not params:
        return url
    dummy = {p: "1" for p in params[:8]}
    return f"{url}?{urlencode(dummy)}"


def _has_injectable_ext(url: str) -> bool:
    path = urlparse(url).path.lower()
    _, ext = os.path.splitext(path)
    return ext not in _SKIP_EXT


def _score_target(url: str, params: List[str], method: str) -> int:
    """
    Score a target for injection likelihood (higher = test first).
    """
    score = 0
    url_lower = url.lower()
    params_lower = {p.lower() for p in params}

    # High-value params
    matched = params_lower & {p.lower() for p in _HIGH_VALUE_PARAMS}
    score += len(matched) * 20

    # ID-pattern in params → very likely injectable
    if any(re.search(r'\bid\b|_id$|^id_', p) for p in params_lower):
        score += 30

    # API endpoints
    if any(k in url_lower for k in ["/api/", "/v1/", "/v2/", "/rest/"]):
        score += 15

    # Search/filter params
    if any(p in params_lower for p in {"q", "query", "search", "keyword", "filter"}):
        score += 15

    # Forms (POST with data)
    if method.upper() == "POST":
        score += 10

    # Penalize tracking-only params
    if params and all(p.lower() in _SKIP_PARAMS for p in params):
        score -= 100

    return score


def _select_technique(params: List[str], url: str) -> str:
    """Choose SQLMap technique based on param semantics."""
    params_lower = {p.lower() for p in params}
    url_lower    = url.lower()

    # Numeric ID params → Union-based detection often works best
    if any(re.search(r'\bid\b|_id$|^id_', p) for p in params_lower):
        return "BEU"

    # Search params → Boolean-based is stealthy and effective
    if any(p in params_lower for p in {"q", "search", "query", "keyword"}):
        return "BEU"

    # File/path params → error-based often reveals backend
    if any(p in params_lower for p in {"file", "path", "dir", "include", "page"}):
        return "BE"

    return "BEU"   # default: Boolean + Error + Union


# ---------------------------------------------------------------------------
# Target list builder
# ---------------------------------------------------------------------------


def _build_target_list(
    base_target:  str,
    endpoints:    List[EndpointInput],
    form_params:  List[str],
    extra_urls:   List[str],
) -> List[Dict[str, Any]]:
    """
    Build a de-duplicated, scored list of injection targets from all sources.
    Returns sorted list (highest score first).
    """
    seen:    set              = set()
    targets: List[Dict]       = []

    def _add(url: str, method: str, params: List[str], data: str = "", source: str = ""):
        clean_params = [p for p in params if p.lower() not in _SKIP_PARAMS]
        if not _has_injectable_ext(url):
            return
        key = f"{method.upper()}:{url}"
        if key in seen:
            return
        seen.add(key)
        score = _score_target(url, clean_params, method)
        if score < -50:
            return  # skip tracking-only targets
        targets.append({
            "url":     url,
            "method":  method.upper(),
            "params":  clean_params,
            "data":    data,
            "source":  source,
            "score":   score,
            "technique": _select_technique(clean_params, url),
        })

    # 1. Primary target — check if it has GET params
    base_params = _extract_get_params(base_target)
    if base_params:
        _add(base_target, "GET", base_params, source="primary")

    # 2. Explicit endpoints from ZAP/Katana (with known params)
    for ep in endpoints:
        url    = ep.url
        method = ep.method or "GET"
        params = ep.params or _extract_get_params(url)
        data   = ep.data or ""

        if method.upper() == "GET" and not params:
            continue  # no params, skip

        # For POST endpoints, inject dummy form if no data
        if method.upper() == "POST" and not data and params:
            data = "&".join(f"{p}=test" for p in params[:8])

        _add(url, method, params, data, source="zap_endpoint")

    # 3. ZAP form params on the base target (POST injection)
    if form_params and base_target:
        clean = [p for p in form_params if p.lower() not in _SKIP_PARAMS]
        if clean:
            post_data = "&".join(f"{p}=test" for p in clean[:10])
            _add(base_target, "POST", clean, post_data, source="zap_forms")

    # 4. Extra URLs from FFUF/Katana that have GET params
    for url in extra_urls:
        if not url.startswith(("http://", "https://")):
            continue
        params = _extract_get_params(url)
        if params:
            _add(url, "GET", params, source="ffuf_katana")
        else:
            # URL has no params — try to inject common ones if it looks like an endpoint
            path = urlparse(url).path.lower()
            if any(k in path for k in ["/api/", "/search", "/filter", "/list", "/get"]):
                # Skip — would just be guessing
                pass

    targets.sort(key=lambda t: t["score"], reverse=True)
    logger.info(
        "Target list: %d candidates (sources: primary, zap_endpoints, zap_forms, ffuf_katana)",
        len(targets),
    )
    for t in targets[:5]:
        logger.info("  [score=%d] %s %s params=%s", t["score"], t["method"], t["url"][:80], t["params"][:5])

    return targets


# ---------------------------------------------------------------------------
# SQLMap runner
# ---------------------------------------------------------------------------


async def _run_sqlmap_single(
    target:      Dict[str, Any],
    output_dir:  str,
    timeout:     int,
    auth_headers: Optional[Dict[str, str]] = None,
    auth_cookies: Optional[Dict[str, str]] = None,
) -> str:
    url       = target["url"]
    method    = target["method"]
    params    = target["params"]
    data      = target["data"]
    technique = target.get("technique", "BEU")

    if method == "GET" and params:
        url = _inject_dummy_values(url, params)

    cmd = [
        "python", "-m", "sqlmap",
        "-u", url,
        "--output-dir", output_dir,
        f"--technique={technique}",
    ] + _BASE_FLAGS

    # ── Auth injection ────────────────────────────────────────────────────
    if auth_headers:
        header_str = "\\n".join(f"{k}: {v}" for k, v in auth_headers.items())
        cmd += ["--headers", header_str]
    if auth_cookies:
        cmd += ["--cookie", "; ".join(f"{k}={v}" for k, v in auth_cookies.items())]

    # Add explicit param targeting
    if params and method == "GET":
        # Only test high-value params explicitly (max 5)
        test_params = [p for p in params if p.lower() in {x.lower() for x in _HIGH_VALUE_PARAMS}]
        if not test_params:
            test_params = params
        cmd += ["-p", ",".join(test_params[:5])]

    if method == "POST":
        if data:
            cmd += ["--data", data]
        cmd += ["--method=POST"]
        # Don't use --forms for POST (we already know the data)
    else:
        if target.get("source") in ("primary",) and not params:
            cmd += ["--forms", "--crawl=1"]   # base target fallback

    logger.info("SQLMap cmd (%s %s): %s", method, url[:60], " ".join(cmd[5:]))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, "PYTHONPATH": ""},
        )
        stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout_bytes.decode(errors="replace")
    except asyncio.TimeoutError:
        try: proc.kill()
        except Exception: pass
        return f"[TIMEOUT after {timeout}s on {url}]"
    except Exception as exc:
        return f"[ERROR: {exc}]"


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------


def _parse_sqlmap_output(output: str, target_url: str = "") -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    dbms_match = re.search(r"back-end DBMS[^:]*:\s*(.+)", output, re.IGNORECASE)
    dbms = dbms_match.group(1).strip() if dbms_match else ""

    for match in re.finditer(
        r"Parameter:\s*(.+?)\s*\(.+?\)\s+Type:\s*(.+?)\s+Title:\s*(.+?)\s+Payload:\s*(.+?)(?=\n\n|\nParameter:|\Z)",
        output, re.DOTALL,
    ):
        param, technique, title, payload = match.groups()
        sev = "high"
        findings.append({
            "parameter":       param.strip(),
            "technique":       technique.strip(),
            "title":           title.strip(),
            "payload_example": payload.strip()[:200],
            "severity":        sev,
            "cwe_id":          "89",
            "dbms":            dbms,
            "target_url":      target_url,
            "description":     f"SQL injection via {technique.strip()} on '{param.strip()}'",
        })

    return findings


# ---------------------------------------------------------------------------
# FastAPI endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "sqlmap"}


@app.post("/scan")
async def scan(req: ScanRequest) -> Dict[str, Any]:
    base_target = _normalize(req.target)
    logger.info(
        "SQLMap scan — target=%s endpoints=%d form_params=%d extra_urls=%d",
        base_target, len(req.endpoints), len(req.form_params), len(req.extra_urls),
    )

    result: Dict[str, Any] = {
        "target":           base_target,
        "vulnerable":       False,
        "findings":         [],
        "vulnerable_params": [],
        "dbms":             "",
        "total":            0,
        "targets_tested":   0,
        "error":            None,
    }

    # ── 1. Build prioritized target list ────────────────────────────────────
    all_targets = _build_target_list(
        base_target,
        req.endpoints,
        req.form_params,
        req.extra_urls,
    )

    # Fallback: if no targets with params, test base target with --forms
    if not all_targets:
        logger.info("No param-bearing targets found — falling back to base target with --forms")
        all_targets = [{
            "url":       base_target,
            "method":    "GET",
            "params":    [],
            "data":      "",
            "source":    "fallback",
            "score":     0,
            "technique": "BEU",
        }]

    # Budget: limit to top N targets within timeout
    # Each target gets a proportional timeout slice
    max_targets    = min(len(all_targets), 6)
    targets_to_run = all_targets[:max_targets]
    per_target_timeout = max(30, req.timeout // max(len(targets_to_run), 1) - 10)

    logger.info(
        "Testing %d/%d targets, %ds each",
        len(targets_to_run), len(all_targets), per_target_timeout,
    )

    # ── 2. Run SQLMap on each target ─────────────────────────────────────────
    all_findings: List[Dict[str, Any]] = []
    all_dbms:     List[str]            = []

    for i, target in enumerate(targets_to_run):
        output_dir = f"/tmp/sqlmap_{uuid.uuid4().hex[:10]}"
        os.makedirs(output_dir, exist_ok=True)
        try:
            logger.info(
                "[%d/%d] Testing %s %s params=%s",
                i + 1, len(targets_to_run),
                target["method"], target["url"][:70], target["params"][:5],
            )
            output = await _run_sqlmap_single(
                target, output_dir, per_target_timeout,
                auth_headers=req.headers, auth_cookies=req.cookies,
            )
            findings = _parse_sqlmap_output(output, target["url"])
            all_findings.extend(findings)

            dbms_m = re.search(r"back-end DBMS[^:]*:\s*(.+)", output, re.IGNORECASE)
            if dbms_m:
                all_dbms.append(dbms_m.group(1).strip())

            if findings:
                logger.warning(
                    "[VULNERABLE] %s %s — %d injection(s)",
                    target["method"], target["url"][:60], len(findings),
                )
        finally:
            shutil.rmtree(output_dir, ignore_errors=True)

    # ── 3. Aggregate results ─────────────────────────────────────────────────
    # Deduplicate by (param, technique)
    seen_keys: set = set()
    deduped: List[Dict] = []
    for f in all_findings:
        key = (f["parameter"], f["technique"][:30])
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(f)

    vulnerable_params = list(dict.fromkeys(f["parameter"] for f in deduped))

    result.update({
        "vulnerable":        len(deduped) > 0,
        "findings":          deduped,
        "vulnerable_params": vulnerable_params,
        "dbms":              next(iter(all_dbms), ""),
        "total":             len(deduped),
        "targets_tested":    len(targets_to_run),
    })

    logger.info(
        "SQLMap done — vulnerable=%s findings=%d targets_tested=%d",
        result["vulnerable"], result["total"], result["targets_tested"],
    )
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9007)
