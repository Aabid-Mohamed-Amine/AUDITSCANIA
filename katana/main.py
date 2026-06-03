"""
Katana — next-gen web crawler microservice v2.

Fixes:
  - Capture stdout directly (no temp file) — more reliable in Docker
  - Pre-flight HTTP check before launching Katana
  - Full stderr logging for debugging
  - Retry logic (2 attempts)
  - Headless mode via Chromium (-hl flag)
  - Python fallback crawler when Katana produces no output
  - DNS resolvers explicitly set (8.8.8.8, 1.1.1.1) for Docker networking
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

logger = logging.getLogger("katana-service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="Katana Crawler Microservice", version="2.0.0")

_EXCLUDE_EXTENSIONS = "woff,woff2,ttf,eot,png,jpg,jpeg,gif,ico,svg,css,mp4,webm,webp,pdf,zip,tar,gz"

_API_PATTERNS = [
    r"/api/", r"/v\d+/", r"/graphql", r"/rest/", r"/ws/", r"/webhook",
    r"\.json$", r"\.xml$", r"\.yaml$", r"\.yml$", r"/swagger", r"/openapi",
    r"/rpc", r"/grpc",
]
_SENSITIVE_KW = {
    "admin", "config", ".env", ".git", "backup", "secret", "private",
    "internal", "debug", "actuator", "management", "credentials", "token",
    "passwd", "dump", "database",
}
_AUTH_KW = {
    "login", "signin", "auth", "oauth", "session", "logout", "register",
    "signup", "2fa", "mfa", "sso", "saml", "password", "reset",
}


class ScanRequest(BaseModel):
    target:   str
    timeout:  int  = 90
    depth:    int  = 3
    js_crawl: bool = True   # -jc: extract endpoints from JS bundles
    headless: bool = False  # -hl: headless Chromium (SPA heavy rendering)


def _normalize(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"http://{target}"
    return target.rstrip("/")


def _classify_url(url: str) -> str:
    path = url.lower().split("?")[0]
    _, ext = os.path.splitext(path.rstrip("/").rsplit("/", 1)[-1])
    if ext in {".js", ".ts", ".jsx", ".tsx", ".mjs"}:
        return "js"
    if any(re.search(p, path) for p in _API_PATTERNS):
        return "api"
    if any(k in path for k in _SENSITIVE_KW):
        return "sensitive"
    if any(k in path for k in _AUTH_KW):
        return "auth"
    return "other"


def _same_domain(url: str, base: str) -> bool:
    try:
        return urlparse(url).netloc == urlparse(base).netloc
    except Exception:
        return False


def _extract_params(url: str) -> List[str]:
    from urllib.parse import parse_qs
    try:
        return list(parse_qs(urlparse(url).query).keys())
    except Exception:
        return []


# ── Pre-flight check ─────────────────────────────────────────────────────────


async def _check_reachable(target: str, timeout: float = 10.0) -> tuple[bool, str]:
    """Verify the target responds to HTTP before running Katana."""
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            resp = await client.get(target)
            return True, f"HTTP {resp.status_code}"
    except httpx.ConnectError as exc:
        return False, f"Connection refused: {exc}"
    except httpx.TimeoutException:
        return False, "Connection timed out"
    except Exception as exc:
        return False, str(exc)


# ── Fallback crawler (pure Python) ───────────────────────────────────────────


async def _fallback_crawl(target: str, timeout: int = 30) -> List[Dict[str, Any]]:
    """
    Simple regex-based link extractor used when Katana produces no output.
    Crawls up to 3 levels deep, max 200 URLs.
    """
    found:    Dict[str, Dict[str, Any]] = {}
    to_visit: List[str] = [target]
    visited:  set = set()
    base_netloc = urlparse(target).netloc

    async with httpx.AsyncClient(
        timeout=timeout / 10,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; AuditScan/2.0)"},
    ) as client:
        for url in to_visit[:50]:
            if url in visited or len(found) >= 200:
                break
            visited.add(url)
            try:
                resp = await client.get(url)
                content_type = resp.headers.get("content-type", "")
                if "html" not in content_type and "javascript" not in content_type:
                    continue
                text = resp.text

                # Extract href / src / action links
                links = re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', text)
                # Extract from JS strings that look like paths
                links += re.findall(r'["\`](/[a-zA-Z0-9_/\-\.?=&%#]{3,100})["\`]', text)

                for raw in links:
                    abs_url = urljoin(url, raw.strip()).split("#")[0]
                    if not abs_url.startswith(("http://", "https://")):
                        continue
                    if urlparse(abs_url).netloc != base_netloc:
                        continue
                    if abs_url not in found:
                        found[abs_url] = {
                            "url":      abs_url,
                            "method":   "GET",
                            "source":   "fallback_crawler",
                            "category": _classify_url(abs_url),
                            "params":   _extract_params(abs_url),
                        }
                        if _same_domain(abs_url, target):
                            to_visit.append(abs_url)
            except Exception:
                continue

    logger.info("Fallback crawler found %d URLs for %s", len(found), target)
    return list(found.values())


# ── Katana runner ─────────────────────────────────────────────────────────────


async def _run_katana(
    target: str, depth: int, js_crawl: bool, headless: bool, timeout: int,
) -> tuple[List[str], str]:
    """
    Run Katana and capture stdout line by line.
    Returns (lines, stderr_text).
    """
    cmd = [
        "katana",
        "-u",         target,
        "-d",         str(depth),
        "-timeout",   "15",
        "-c",         "15",          # concurrent requests
        "-rl",        "60",          # rate limit req/sec
        "-resolvers", "8.8.8.8,1.1.1.1",  # explicit DNS — fixes Docker networking
        "-no-color",
        "-silent",
        "-kf",        "all",
        "-ef",        _EXCLUDE_EXTENSIONS,
        "-H",         "User-Agent: Mozilla/5.0 (compatible; AuditScan/2.0)",
    ]
    if js_crawl:
        cmd += ["-jc"]
    if headless:
        cmd += ["-hl", "-hlx", "--headless-options=--no-sandbox,--disable-gpu,--disable-dev-shm-usage"]

    logger.info("Katana cmd: %s", " ".join(cmd))

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        raise

    stdout_text = stdout_bytes.decode(errors="replace") if stdout_bytes else ""
    stderr_text = stderr_bytes.decode(errors="replace") if stderr_bytes else ""

    if stderr_text.strip():
        logger.info("Katana stderr:\n%s", stderr_text[:2000])

    lines = [l.strip() for l in stdout_text.splitlines() if l.strip()]
    return lines, stderr_text


def _parse_katana_lines(lines: List[str], base_netloc: str) -> List[Dict[str, Any]]:
    endpoints:  List[Dict[str, Any]] = []
    seen:       set = set()

    for line in lines:
        # Each line is either a JSON object or a plain URL
        url = ""
        method = "GET"
        source = ""
        try:
            entry = json.loads(line)
            url    = entry.get("endpoint") or entry.get("request", {}).get("endpoint", "")
            method = entry.get("request", {}).get("method", "GET")
            source = entry.get("source", "")
        except (json.JSONDecodeError, TypeError):
            url = line  # plain URL output

        url = url.strip()
        if not url or not url.startswith(("http://", "https://")):
            continue
        # Keep only same-domain URLs
        try:
            if urlparse(url).netloc != base_netloc:
                continue
        except Exception:
            continue
        if url in seen:
            continue
        seen.add(url)

        endpoints.append({
            "url":      url,
            "method":   method,
            "source":   source,
            "category": _classify_url(url),
            "params":   _extract_params(url),
        })

    return endpoints


# ── FastAPI endpoints ─────────────────────────────────────────────────────────


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "katana"}


@app.post("/scan")
async def scan(req: ScanRequest) -> Dict[str, Any]:
    target_url  = _normalize(req.target)
    base_netloc = urlparse(target_url).netloc
    logger.info(
        "Katana scan — target=%s depth=%d js=%s headless=%s",
        target_url, req.depth, req.js_crawl, req.headless,
    )

    result: Dict[str, Any] = {
        "target":        target_url,
        "endpoints":     [],
        "js_files":      [],
        "api_endpoints": [],
        "params":        [],
        "total":         0,
        "by_category":   {},
        "used_fallback": False,
        "preflight":     {},
        "error":         None,
    }

    # ── 1. Pre-flight: verify target is reachable ────────────────────────────
    reachable, preflight_msg = await _check_reachable(target_url, timeout=10.0)
    result["preflight"] = {"reachable": reachable, "message": preflight_msg}
    logger.info("Pre-flight %s → %s (%s)", target_url, reachable, preflight_msg)

    if not reachable:
        result["error"] = f"Target unreachable before scan: {preflight_msg}"
        return result

    # ── 2. Run Katana (up to 2 attempts) ────────────────────────────────────
    endpoints: List[Dict[str, Any]] = []
    last_stderr = ""

    for attempt in range(1, 3):
        logger.info("Katana attempt %d/2 for %s", attempt, target_url)
        try:
            lines, last_stderr = await _run_katana(
                target_url, req.depth, req.js_crawl, req.headless,
                timeout=req.timeout,
            )
            logger.info(
                "Katana attempt %d: %d raw lines, stderr_len=%d",
                attempt, len(lines), len(last_stderr),
            )
            endpoints = _parse_katana_lines(lines, base_netloc)
            if endpoints:
                break
            # No results — try headless on second attempt
            if attempt == 1 and not req.headless:
                logger.info("Katana produced 0 results, retrying with headless=True")
                req.headless = True
        except asyncio.TimeoutError:
            logger.warning("Katana attempt %d timed out", attempt)
            last_stderr += f"\n[Attempt {attempt} timed out after {req.timeout}s]"
        except FileNotFoundError:
            result["error"] = "katana binary not found in PATH"
            return result
        except Exception as exc:
            logger.exception("Katana attempt %d failed: %s", attempt, exc)
            last_stderr += f"\n[Exception: {exc}]"

    # ── 3. Fallback crawler if Katana still empty ────────────────────────────
    if not endpoints:
        logger.info("Katana produced no output — activating Python fallback crawler")
        result["used_fallback"] = True
        try:
            endpoints = await _fallback_crawl(target_url, timeout=min(req.timeout, 30))
        except Exception as exc:
            logger.error("Fallback crawler failed: %s", exc)
            result["error"] = (
                f"Katana produced no output and fallback crawler also failed. "
                f"Katana stderr: {last_stderr[:500] or 'empty'}"
            )

    if not endpoints and not result["error"]:
        result["error"] = (
            f"No endpoints found (Katana stderr: {last_stderr[:300] or 'empty'}). "
            "Target may have no crawlable content or block automated crawlers."
        )

    # ── 4. Build result ──────────────────────────────────────────────────────
    if endpoints:
        categories: Dict[str, int] = {}
        js_files:      List[str] = []
        api_endpoints: List[str] = []
        all_params:    set = set()

        for ep in endpoints[:500]:
            cat = ep.get("category", "other")
            categories[cat] = categories.get(cat, 0) + 1
            all_params.update(ep.get("params", []))
            if cat == "js":
                js_files.append(ep["url"])
            elif cat == "api":
                api_endpoints.append(ep["url"])

        result["endpoints"]     = endpoints[:500]
        result["js_files"]      = list(dict.fromkeys(js_files))[:50]
        result["api_endpoints"] = list(dict.fromkeys(api_endpoints))[:100]
        result["params"]        = sorted(all_params)[:100]
        result["total"]         = len(endpoints)
        result["by_category"]   = categories

    logger.info(
        "Katana done — target=%s total=%d api=%d js=%d fallback=%s",
        target_url, result["total"],
        len(result["api_endpoints"]), len(result["js_files"]),
        result["used_fallback"],
    )
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9009)
