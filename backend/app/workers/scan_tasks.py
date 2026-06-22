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
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 30))) as client:
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
    default = {"target": target, "error": None, "vulnerable": False, "findings": [], "total": 0}

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

    try:
        _sqlmap_payload: Dict[str, Any] = {
            "target":      target,
            "timeout":     timeout,
            "endpoints":   endpoints[:20],
            "form_params": form_params,
            "extra_urls":  extra_urls,
            "technique":   "BEU",
            "threads":     1,
            "delay":       2,
            "retries":     1,
        }
        if auth_headers:
            _sqlmap_payload["headers"] = auth_headers
        if auth_cookies:
            _sqlmap_payload["cookies"] = auth_cookies
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 30))) as client:
            resp = await client.post(
                f"{settings.SQLMAP_URL}/scan",
                json=_sqlmap_payload,
            )
            resp.raise_for_status()
            return resp.json()
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
                for idx, raw in enumerate(challenges[:80]):
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

    payload: Dict[str, Any] = {"target": target_url, "timeout": timeout, "deep_mode": True}
    if urls:
        payload["urls"] = urls
    if auth_headers:
        payload["auth_headers"] = auth_headers
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 30))) as client:
            resp = await client.post(
                f"{settings.DALFOX_URL}/scan",
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        default["error"] = "Dalfox service unavailable (container not running?)"
    except httpx.TimeoutException:
        default["error"] = "Dalfox service HTTP request timed out"
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
    out: Dict[str, Any] = {"tags": [], "server": "", "powered_by": "", "tech": []}
    tags: set = set(_ALWAYS_INCLUDE_TAGS)
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(float(timeout + 10)), verify=False, follow_redirects=True,
        ) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 (compatible; AuditScan/3.0)"})
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
    }

    # Whitelist 2: concrete endpoint/route names.
    # Rule: the keyword must appear in matched_at URL (path segment), NOT just
    # in the finding title -- a title can mention "login" in an advisory context
    # while testing a completely different endpoint.
    _ENDPOINT_TERMS: set = {
        "feedback", "search", "login", "register", "whoami", "challenges",
        "basket", "checkout", "profile", "payment", "upload", "download",
        "complaint", "tracking", "coupon", "invoice", "review",
    }

    # Whitelist 3: precise vulnerability technique identifiers that are
    # sufficiently rare and specific to not appear in unrelated findings.
    _VULN_SPECIFIC: set = {
        "jwt", "deserialization", "xxe", "ssti", "ssrf", "ldap",
        "xpath", "nosql", "graphql", "prototype",
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

        async def _do_phase1():
            async def _safe_shodan():
                try:
                    return await query_shodan(target)
                except Exception as exc:
                    return {"error": str(exc), "data": {}}

            async def _safe_vt():
                try:
                    return await query_virustotal(target)
                except Exception as exc:
                    return {"error": str(exc), "data": {}}

            async def _safe_abuse():
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
        if shodan_result.get("error"):
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
        if vt_result.get("error"):
            _add_log(db, scan_id, f"[P1] VirusTotal error: {vt_result['error']}", level="error")
        else:
            malicious = vt_result.get("data", {}).get("malicious", 0)
            _add_log(db, scan_id,
                     f"[P1] VirusTotal: {malicious} malicious detections",
                     level="warning" if malicious > 0 else "info")
        ctx.save_step_result("virustotal", vt_result)
        _update_scan(db, scan, virustotal_data=vt_result, progress=20)

        # Log AbuseIPDB
        if abuse_result.get("error"):
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
            "server":       server_tags_info.get("server", ""),
            "x-powered-by": server_tags_info.get("powered_by", ""),
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
        _NUCLEI_QUICK_TAGS = ["exposure", "misconfig", "headers", "csp", "cors", "tech", "discovery"]
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
            _dalfox_fallback_urls = [
                f"{_base.rstrip('/')}/?q=test",
                f"{_base.rstrip('/')}/search?q=test",
                f"{_base.rstrip('/')}/api/search?q=test",
                f"{_base.rstrip('/')}/api/v1/search?q=test",
            ]

            async def _p2_nuclei():
                if "nuclei" not in tools_to_run:
                    return {
                        "target": target, "skipped": True, "findings": [], "total": 0,
                        "by_severity": {}, "error": None,
                        "reason": agent_decision["reasons"].get("nuclei", "skipped by agent decision"),
                    }
                return await _call_nuclei(
                    target,
                    templates       = _nuclei_templates or None,
                    tags            = nuclei_ctx["tags"] or None,
                    extra_targets   = None,
                    tech_stack      = tech_stack or None,
                    scan_categories = scan_cats or None,
                    auth_headers    = _auth_h,
                    auth_cookies    = _auth_c,
                    severity        = _nuclei_severity,
                )

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
                return await _call_ffuf(
                    target, timeout=60, wordlist="fallback",
                    auth_headers=_auth_h, auth_cookies=_auth_c,
                )

            async def _p2_dalfox():
                if "dalfox" not in tools_to_run:
                    return {
                        "target": target, "skipped": True, "findings": [], "total": 0,
                        "by_severity": {}, "error": None,
                        "reason": agent_decision["reasons"].get("dalfox", "skipped by agent decision"),
                    }
                # Meme delai que FFUF : demarre apres 20s pour eviter contention initiale.
                await asyncio.sleep(20)
                logger.info("[Dalfox] Phase 2 parallel -- using %d generic fallback URLs",
                            len(_dalfox_fallback_urls))
                return await _call_dalfox(
                    target, timeout=180, urls=_dalfox_fallback_urls, auth_headers=_auth_h or None,
                )

            _r2 = await asyncio.gather(
                _p2_nuclei(), _p2_ffuf(), _p2_dalfox(),
                return_exceptions=True,
            )

            _def_nuclei = {"target": target, "skipped": True, "findings": [], "total": 0,
                           "by_severity": {}, "error": None}
            _def_ffuf   = {"target": target, "skipped": True, "endpoints": [], "total": 0,
                           "by_status": {}, "by_category": {}, "by_severity": {}, "error": None}
            _def_dalfox = {"target": target, "skipped": True, "findings": [], "total": 0,
                           "by_severity": {}, "error": None}

            _nuclei_r = _r2[0] if not isinstance(_r2[0], Exception) else {**_def_nuclei, "error": str(_r2[0])}
            _ffuf_q   = _r2[1] if not isinstance(_r2[1], Exception) else {**_def_ffuf,   "error": str(_r2[1])}
            _dalfox_r = _r2[2] if not isinstance(_r2[2], Exception) else {**_def_dalfox, "error": str(_r2[2])}

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

        # a"EURa"EUR Katana wrapper: timeout DUR de 90s, ne bloque JAMAIS SQLMap a"EURa"EURa"EURa"EURa"EURa"EUR
        # 90s = le temps de reellement crawler une SPA (JS/API endpoints) tout en
        # restant borne. En cas de timeout/erreur -> stub vide, la Phase 3 continue.
        async def _safe_katana() -> Dict[str, Any]:
            stub: Dict[str, Any] = {
                "target": target, "skipped": False, "timed_out": False,
                "api_endpoints": [], "endpoints": [], "js_files": [], "params": [], "urls_with_params": [],
                "total": 0, "error": None,
            }
            try:
                return await asyncio.wait_for(_call_katana(target, timeout=13), timeout=15)
            except asyncio.TimeoutError:
                stub["timed_out"] = True
                stub["skipped"]   = True
                stub["error"]     = "Katana timed out (15s)  --  Phase 3 continues without Katana"
                return stub
            except Exception as exc:
                stub["skipped"] = True
                stub["error"]   = str(exc)
                return stub

        # a"EURa"EUR Step 3a: ZAP -> FFUF -> wait -> GitLeaks -> Katana -> lab -> Nikto -> Wapiti a"EUR
        # ZAP passe EN PREMIER sur cible saine ; FFUF apres (evite que ZAP
        # herite d'une cible epuisee). Pause 30s apres FFUF pour laisser
        # la cible (ex: Juice Shop) recuperer avant Katana/Nikto/Wapiti.
        # Fix 2: Phase 3 Groupe A PARALLELE -- ZAP || FFUF || GitLeaks || Katana || Lab || Nikto || Wapiti
        # Tous independants entre eux -- aucun ne depend des resultats des autres.
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

            # Etape 1: gather LEGER -- GitLeaks + Lab (peu de requetes HTTP, pas de saturation)
            async def _p3_gitleaks():
                if "gitleaks" not in tools_to_run:
                    return _gl_skip
                return await _call_gitleaks(target, timeout=120)

            async def _p3_lab():
                if not lab_mode:
                    logger.info("[P3] Lab Challenge API: DESACTIVE (lab_mode=false)")
                    return _lab_skip
                logger.info("[P3] Lab Challenge API: ACTIVE (lab_mode=true)")
                return await _call_lab_challenges(target, timeout=20)

            _r3_light = await asyncio.gather(
                _p3_gitleaks(), _p3_lab(),
                return_exceptions=True,
            )
            _gl  = _r3_light[0] if not isinstance(_r3_light[0], Exception) else {**_gl_skip,  "error": str(_r3_light[0])}
            _lab = _r3_light[1] if not isinstance(_r3_light[1], Exception) else {**_lab_skip, "error": str(_r3_light[1])}

            # Etape 2: sequentiel LOURD -- ZAP -> FFUF -> Katana -> Nikto -> Wapiti
            # (outils HTTP intensifs : sequentiel pour ne pas saturer la cible)
            await _wait_for_target(target)
            if "zap" in tools_to_run:
                _zap = await _call_zap(
                    target, auth_headers=_auth_h, auth_cookies=_auth_c,
                    ajax_spider=agent_decision.get("zap_ajax", False),
                )
            else:
                _zap = _zap_skip

            await _wait_for_target(target)
            if "ffuf" in tools_to_run:
                _ffuf = await _call_ffuf(
                    target, timeout=90, wordlist="fallback",
                    auth_headers=_auth_h, auth_cookies=_auth_c,
                )
            else:
                _ffuf = _ffuf_skip

            if "katana" in tools_to_run:
                _kat = await _safe_katana()
            else:
                _kat = _kat_skip

            await _wait_for_target(target)
            if "nikto" in tools_to_run:
                _nikto = await _call_nikto(target, timeout=130, auth_headers=_auth_h, auth_cookies=_auth_c)
            else:
                _nikto = _nikto_skip

            if "wapiti" in tools_to_run:
                _wapiti = await _call_wapiti(target, timeout=130, auth_headers=_auth_h, auth_cookies=_auth_c)
            else:
                _wapiti = _wapiti_skip

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
                     "[P3] Katana: TIMEOUT 15s  --  Phase 3 continue sans Katana", level="warning")
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
            _add_log(db, scan_id,
                     f"[P3] Wapiti: {_wapiti_total} finding(s)"
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
                await _wait_for_target(target)
                return await _call_sqlmap_enriched(
                    target, zap_result, ffuf_result, katana_result,
                    timeout=300, auth_headers=_auth_h, auth_cookies=_auth_c,
                    probe_pack_ids=agent_decision.get("probe_pack_ids") or ["generic_rest_api"],
                )

            async def _p3b_idor():
                if not auth_ctx.has_auth():
                    return _idor_skip_default
                try:
                    return await asyncio.wait_for(
                        _call_idor(
                            target,
                            endpoints=_idor_eps_dedup[:40],
                            timeout=90,
                            auth_headers=_auth_h or None,
                            auth_cookies=_auth_c or None,
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
            vulnerable     = sqlmap_result.get("vulnerable", False)
            sqli_total     = sqlmap_result.get("total", 0)
            targets_tested = sqlmap_result.get("targets_tested", 0)
            _add_log(db, scan_id,
                     f"[P3] SQLMap: tested {targets_tested} targets  --  "
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
                        "cve_ids":          [],
                        "cwe_ids":          ["CWE-79"],
                        "cvss_score":       None,
                        "matched_at":       df.get("url", target),
                        "sources":          ["dalfox"],
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
