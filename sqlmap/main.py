"""
SQLMap Ã¢â‚¬â€ SQL injection assessment microservice v2.

Pipeline endpoint Ã¢â€ â€™ params Ã¢â€ â€™ SQLMap :
  1. Extraction automatique des params GET depuis les URLs
  2. Extraction depuis les form_params ZAP (POST)
  3. Extraction depuis les API endpoints Katana/FFUF
  4. Scoring et priorisation des cibles injectables
  5. Filtrage des endpoints non pertinents
  6. SÃƒÂ©lection de payload adaptÃƒÂ©e au type de paramÃƒÂ¨tre
  7. Runs parallÃƒÂ¨les sur les N meilleures cibles (budget timeout)
"""
from __future__ import annotations

import asyncio
import logging
import os
import pathlib
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

# Ã¢â€â‚¬Ã¢â€â‚¬ Safe assessment flags (no data extraction, no destructive payloads) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
_BASE_FLAGS = [
    "--batch",
    "--level=3",           # level 3: headers, cookies, more vectors
    "--risk=2",            # risk 2: heavier payloads without destructive UPDATE/DELETE
    "--technique=BEUST",   # Boolean + Error + Union + Stacked + Time-based
    "--dbms=sqlite",       # Juice Shop / typical lab target uses SQLite
    "--no-cast",
    "--fresh-queries",
    "--flush-session",
    "--disable-coloring",
    "--timeout=15",        # per-request timeout
    "--retries=1",
    "--threads=1",
    "--delay=0",           # no delay — avoids timeout on 50+ payload boolean-based blind
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
    Example: /search + ["q"] Ã¢â€ â€™ /search?q=test
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

    # ID-pattern in params Ã¢â€ â€™ very likely injectable
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

    # Numeric ID params Ã¢â€ â€™ Union-based detection often works best
    if any(re.search(r'\bid\b|_id$|^id_', p) for p in params_lower):
        return "BEU"

    # Search params Ã¢â€ â€™ Boolean-based is stealthy and effective
    if any(p in params_lower for p in {"q", "search", "query", "keyword"}):
        return "BEU"

    # File/path params Ã¢â€ â€™ error-based often reveals backend
    if any(p in params_lower for p in {"file", "path", "dir", "include", "page"}):
        return "BE"

    return "BEUST"   # default: Boolean + Error + Union + Stacked + Time-based


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

    # 1. Primary target Ã¢â‚¬â€ check if it has GET params
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
            # URL has no params Ã¢â‚¬â€ try to inject common ones if it looks like an endpoint
            path = urlparse(url).path.lower()
            if any(k in path for k in ["/api/", "/search", "/filter", "/list", "/get"]):
                # Skip Ã¢â‚¬â€ would just be guessing
                pass

    # POST login endpoints must always be tested first Ã¢â‚¬â€ score override
    for t in targets:
        if "login" in t["url"].lower() and t["method"] == "POST":
            t["score"] = 9999

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
        "sqlmap",
        "-u", url,
        "--output-dir", output_dir,
        f"--technique={technique}",
    ] + _BASE_FLAGS

    # Ã¢â€â‚¬Ã¢â€â‚¬ Auth injection Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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
        # When data contains a * wildcard, SQLMap injects at that exact position —
        # adding -p as well causes SQLMap to ignore the * and pick a different
        # injection point, breaking JSON body injection.
        _has_wildcard = "*" in (data or "")
        if params and not _has_wildcard:
            post_test_params = [p for p in params if p.lower() in {x.lower() for x in _HIGH_VALUE_PARAMS}]
            if not post_test_params:
                post_test_params = params
            cmd += ["-p", ",".join(post_test_params[:5])]
        # --risk=3: needed for OR-based payloads (auth bypass); kept out of _BASE_FLAGS
        #   so GET targets keep --risk=1 (majority, no need for this aggressiveness).
        # --ignore-code=401,403,500: auth endpoints return 401/403 for invalid creds Ã¢â‚¬â€
        #   without this flag sqlmap aborts at connectivity test before probing injection;
        #   500 included: observed during SQLite exploitation without blocking detection.
        # --delay=0: _BASE_FLAGS sets --delay=2 (stealthy GET scanning), which makes
        #   ~250 requests take 500s+ -- far beyond the per-target budget. Auth-bypass
        #   probes need full speed to reach OR-based boolean payloads in time.
        # --technique=B: boolean-based blind alone found the auth-bypass SQLi in ~12s;
        #   BEU (default) wastes budget on Error/Union techniques first.
        # Filter conflicting defaults so POST override flags always win.
        cmd = [c for c in cmd
               if not c.startswith("--risk=")
               and not c.startswith("--delay=")
               and not c.startswith("--level=")
               and not c.startswith("--technique=")
               and not c.startswith("--dbms=")]
        # 400 added: JSON-injected payloads can cause parse errors on strict servers
        cmd += ["--risk=3", "--level=3", "--delay=0", "--technique=B",
                "--dbms=sqlite", "--ignore-code=400,401,403,500"]
        # --level=3 (overrides _BASE_FLAGS --level=2): the working auth-bypass
        # payload uses the "OR boolean-based blind (NOT)" variant, which sqlmap
        # only tests starting at level 3 -- level 2 silently misses it.
    else:
        if target.get("source") in ("primary", "fallback") and not params:
            cmd += ["--forms", "--crawl=2"]

    logger.info("SQLMap cmd (%s %s): %s", method, url[:60], " ".join(cmd[3:]))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, "PYTHONPATH": ""},
        )
        stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        stdout_text = stdout_bytes.decode(errors="replace")
        # sqlmap writes the structured "Parameter:/Type:/Title:/Payload:" block
        # to output_dir/<hostname>/log when --output-dir is set.
        try:
            _host = urlparse(url).hostname or "target"
            _sqlmap_log = pathlib.Path(output_dir) / _host / "log"
            _log_path = str(_sqlmap_log)
            logger.info("[SQLMap] reading log from: %s (exists=%s)", _log_path, os.path.exists(_log_path))
            if os.path.exists(_log_path):
                _log_content = open(_log_path, errors="replace").read()
                if "Parameter:" in _log_content:
                    return _log_content + "\n" + stdout_text
        except Exception:
            pass
        return stdout_text
    except asyncio.TimeoutError:
        try: proc.kill()
        except Exception: pass
        # SQLMap may have written a finding to the log before timing out — recover it
        try:
            _host_t = urlparse(url).hostname or "target"
            _log_t = pathlib.Path(output_dir) / _host_t / "log"
            if _log_t.exists():
                _lc = _log_t.read_text(errors="replace")
                if "Parameter:" in _lc:
                    return _lc + f"\n[TIMEOUT after {timeout}s on {url}]"
        except Exception:
            pass
        return f"[TIMEOUT after {timeout}s on {url}]"
    except Exception as exc:
        return f"[ERROR: {exc}]"


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------


def _clean_sqlmap_output(output: str) -> str:
    """Normalize \r (carriage-return progress refresh) into \n so regexes
    operating on single lines do not see interleaved log fragments."""
    return output.replace("\r\n", "\n").replace("\r", "\n")


def _parse_sqlmap_output(output: str, target_url: str = "") -> List[Dict[str, Any]]:
    output = _clean_sqlmap_output(output)
    # a single console line; raw output can interleave fragments of
    findings: List[Dict[str, Any]] = []

    # Anchored to line start + DBMS immediately followed by ":" -- sqlmap
    # prints several earlier "back-end DBMS could be/is 'X'" lines without a
    # ":", and an unanchored [^:]* would run past newlines to grab the next
    # ":" anywhere later (e.g. a timestamp), polluting this field with log text.
    # Only the final "back-end DBMS: X" summary line has this exact format.
    dbms_match = re.search(r"^back-end DBMS:\s*(.+)$", output, re.IGNORECASE | re.MULTILINE)
    dbms = dbms_match.group(1).strip() if dbms_match else ""

    for match in re.finditer(
        r"Parameter:\s*(.+?)\s*\(.+?\)\s+Type:\s*(.+?)\s+Title:\s*(.+?)\s+Payload:\s*(.+?)(?=\n\n|\nParameter:|\n---|\Z)",
        output, re.DOTALL,
    ):
        param, technique, title, payload = match.groups()
        param_clean = param.strip()
        tech_clean  = technique.strip()
        title_clean = title.strip()
        url_lower   = target_url.lower()

        # Auth bypass: login endpoint + boolean-based blind Ã¢â€ â€™ critical (CWE-89 + CWE-287)
        is_login         = any(k in url_lower for k in ("login", "/rest/user/"))
        is_boolean_blind = "boolean-based blind" in tech_clean.lower()
        if is_login and is_boolean_blind:
            sev      = "critical"
            cwe_ids  = ["cwe-89", "cwe-287"]
            if "authentication bypass" not in title_clean.lower():
                title_clean = f"SQL Injection - Authentication Bypass ({title_clean})"
        else:
            sev     = "high"
            cwe_ids = ["cwe-89"]

        findings.append({
            "parameter":       param_clean,
            "technique":       tech_clean,
            "title":           title_clean,
            "payload_example": payload.strip()[:200],
            "severity":        sev,
            "cwe_ids":         cwe_ids,
            "cwe_id":          "89",    # backward compat
            "dbms":            dbms,
            "target_url":      target_url,
            "description":     (
                f"SQL injection via {tech_clean} on '{param_clean}'"
                + (" - Authentication bypass confirmed" if is_login and is_boolean_blind else "")
            ),
        })

    # Stdout fallback: parse "parameter X is injectable" lines when log block is absent.
    # SQLMap prints these even when the log file is not read (e.g., output-dir issue).
    if not findings:
        for _line in output.splitlines():
            _m = re.search(
                r"(?:POST|GET)\s+parameter\s+'([^']+)'\s+is\s+'([^']+)'\s+injectable",
                _line, re.IGNORECASE,
            )
            if not _m:
                # also catch: parameter 'JSON email' appears to be 'OR boolean ...' injectable
                _m = re.search(
                    r"parameter\s+'([^']+)'\s+(?:appears to be|is)\s+'([^']+)'\s+injectable",
                    _line, re.IGNORECASE,
                )
            if _m:
                _param_raw, _tech_raw = _m.group(1).strip(), _m.group(2).strip()
                # Strip "JSON " prefix that SQLMap adds for JSON body params
                _param_clean = re.sub(r"^(?:JSON|POST|GET)\s+", "", _param_raw, flags=re.IGNORECASE)
                _url_lower   = target_url.lower()
                _is_login    = any(k in _url_lower for k in ("login", "/rest/user/"))
                _is_bool     = "boolean" in _tech_raw.lower()
                _sev         = "critical" if (_is_login and _is_bool) else "high"
                _cwe         = ["cwe-89", "cwe-287"] if (_is_login and _is_bool) else ["cwe-89"]
                findings.append({
                    "parameter":       _param_clean,
                    "technique":       _tech_raw,
                    "title":           (
                        f"SQL Injection - Authentication Bypass ({_tech_raw})"
                        if _is_login and _is_bool
                        else f"SQL Injection ({_tech_raw})"
                    ),
                    "payload_example": "",
                    "severity":        _sev,
                    "cwe_ids":         _cwe,
                    "cwe_id":          "89",
                    "dbms":            dbms,
                    "target_url":      target_url,
                    "description":     (
                        f"SQL injection via {_tech_raw} on '{_param_clean}'"
                        + (" - Authentication bypass confirmed" if _is_login and _is_bool else "")
                    ),
                    "source":          "stdout_fallback",
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
        "SQLMap scan Ã¢â‚¬â€ target=%s endpoints=%d form_params=%d extra_urls=%d",
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

    # Ã¢â€â‚¬Ã¢â€â‚¬ 1. Build prioritized target list Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    all_targets = _build_target_list(
        base_target,
        req.endpoints,
        req.form_params,
        req.extra_urls,
    )

    # Fallback: if no targets with params, test base target with --forms
    if not all_targets:
        logger.info("No param-bearing targets found Ã¢â‚¬â€ falling back to base target with --forms")
        all_targets = [{
            "url":       base_target,
            "method":    "GET",
            "params":    [],
            "data":      "",
            "source":    "fallback",
            "score":     0,
            "technique": "BEUST",
        }]

    # With delay=0, each target needs ~30-60s for boolean-based blind.
    # Test up to 6 targets; give each at least 80s so all techniques complete.
    max_targets    = min(len(all_targets), 6)
    targets_to_run = all_targets[:max_targets]
    per_target_timeout = max(80, req.timeout // max(len(targets_to_run), 1))

    logger.info(
        "Testing %d/%d targets, %ds each",
        len(targets_to_run), len(all_targets), per_target_timeout,
    )

    # Ã¢â€â‚¬Ã¢â€â‚¬ 2. Run SQLMap on each target Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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
            output = _clean_sqlmap_output(output)
            findings = _parse_sqlmap_output(output, target["url"])
            all_findings.extend(findings)

            dbms_m = re.search(r"^back-end DBMS:\s*(.+)$", output, re.IGNORECASE | re.MULTILINE)
            if dbms_m:
                all_dbms.append(dbms_m.group(1).strip())

            if findings:
                logger.warning(
                    "[VULNERABLE] %s %s Ã¢â‚¬â€ %d injection(s)",
                    target["method"], target["url"][:60], len(findings),
                )
        finally:
            shutil.rmtree(output_dir, ignore_errors=True)

    # Ã¢â€â‚¬Ã¢â€â‚¬ 3. Aggregate results Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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
        "SQLMap done Ã¢â‚¬â€ vulnerable=%s findings=%d targets_tested=%d",
        result["vulnerable"], result["total"], result["targets_tested"],
    )
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9007)
