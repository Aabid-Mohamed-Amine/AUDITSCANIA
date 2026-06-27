from __future__ import annotations

import asyncio
import base64
import json
import logging
import random
import re
import secrets
import string
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="AuditScan IDOR Tester", version="1.0.0")

_URL_PATTERN = re.compile(r"^https?://[a-zA-Z0-9._\-]+(:\d+)?(/[^\s]*)?$")
_UA = "Mozilla/5.0 (compatible; AuditScan/3.0; +https://github.com/auditscan)"

# Registration paths to probe (ordered by specificity)
_REGISTER_PATHS = [
    "/api/Users",
    "/api/register",
    "/api/auth/register",
    "/api/v1/register",
    "/register",
    "/signup",
    "/api/users",
    "/users",
    "/api/account/register",
]

# Login paths to probe
_LOGIN_PATHS = [
    "/rest/user/login",
    "/api/login",
    "/api/auth/login",
    "/api/v1/login",
    "/login",
    "/auth/login",
    "/api/authenticate",
    "/api/sessions",
    "/api/token",
]

# Standard resource paths to probe for IDOR (substituted with numeric IDs).
# Covers common REST API patterns -- on non-matching targets these return 404
# (ignored). Juice Shop-specific paths (/rest/basket, /api/Feedbacks, etc.) are
# included because they represent real-world broken access control patterns found
# in many REST APIs.
_NUMERIC_RESOURCE_PATHS = [
    "/api/Users/{id}",
    "/api/users/{id}",
    "/users/{id}",
    "/user/{id}",
    "/api/profile/{id}",
    "/api/accounts/{id}",
    "/api/Accounts/{id}",
    "/rest/user/{id}",
]

# Additional REST resource patterns known to expose IDOR vulnerabilities.
# Substituted with user_b_id and tested with user A's token.
IDOR_PROBE_PATTERNS = [
    "/rest/basket/{id}",
    "/api/Reviews/{id}",
    "/api/Feedbacks/{id}",
    "/api/Orders/{id}",
    "/api/Users/{id}",
    "/api/Addresss/{id}",
    "/rest/products/{id}/reviews",
]

# Token field names to search in JSON responses
_TOKEN_KEYS = {"token", "jwt", "access_token", "accesstoken", "id_token", "auth_token", "bearer"}

# Numeric ID segment in URL paths: matches /123 followed by / or end
_NUM_SEG_RE = re.compile(r"/(\d+)(?=[/?#]|$)")


class ScanRequest(BaseModel):
    target: str
    timeout: int = 120
    endpoints: List[str] = []
    auth_headers: Optional[Dict[str, str]] = None
    auth_cookies: Optional[Dict[str, str]] = None
    user_a_email: Optional[str] = None
    user_a_id: Optional[int] = None

    @field_validator("target")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not _URL_PATTERN.match(v):
            raise ValueError("target must be a valid HTTP/HTTPS URL")
        return v


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "idor-tester"}


@app.post("/scan")
async def scan(req: ScanRequest) -> JSONResponse:
    result = await _run_idor_scan(req)
    return JSONResponse(content=result)


# ── Identity helpers ────────────────────────────────────────────────────────────


def _make_identity(role: str) -> Dict[str, str]:
    ts = int(time.time())
    rand = ''.join(random.choices(string.ascii_lowercase, k=6))
    suffix = f"{ts}_{rand}"
    pwd = "Aud1t!" + secrets.token_hex(8)
    email = f"auditscan_idor_test_{role}_{suffix}@auditscan-test.local"
    return {
        "email":    email,
        "username": f"auditscan_idor_test_{role}_{suffix}",
        "password": pwd,
    }


def _registration_payloads(id_: Dict[str, str]) -> List[Dict[str, Any]]:
    e, u, p = id_["email"], id_["username"], id_["password"]
    return [
        {"email": e, "password": p, "passwordRepeat": p},
        {"email": e, "password": p, "password_confirmation": p},
        {"username": u, "email": e, "password": p, "passwordRepeat": p},
        {"email": e, "password": p},
        {"username": u, "password": p},
    ]


def _login_payloads(id_: Dict[str, str]) -> List[Dict[str, Any]]:
    e, u, p = id_["email"], id_["username"], id_["password"]
    return [
        {"email": e, "password": p},
        {"username": u, "password": p},
        {"username": e, "password": p},
    ]


# ── JSON response parsers ────────────────────────────────────────────────────────


def _find_id(data: Any, depth: int = 0) -> Optional[int]:
    if depth > 6:
        return None
    if isinstance(data, dict):
        for k, v in data.items():
            if str(k).lower() in {"id", "userid", "user_id", "uid", "account_id"}:
                try:
                    val = int(v)
                    if val > 0:
                        return val
                except (TypeError, ValueError):
                    pass
        for v in data.values():
            result = _find_id(v, depth + 1)
            if result is not None:
                return result
    elif isinstance(data, list):
        for item in data[:5]:
            result = _find_id(item, depth + 1)
            if result is not None:
                return result
    return None


def _decode_jwt_id(token: str) -> Optional[int]:
    """Extract user ID from JWT payload without signature verification.
    Juice Shop JWT: {"data": {"id": N, "email": "...", ...}, "iat": ..., "exp": ...}
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        pad = 4 - len(parts[1]) % 4
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * pad).decode("utf-8"))
        return _find_id(payload)
    except Exception:
        return None


def _find_token(data: Any, depth: int = 0) -> Optional[str]:
    if depth > 6:
        return None
    if isinstance(data, dict):
        for k, v in data.items():
            if str(k).lower().replace("-", "_") in _TOKEN_KEYS:
                if isinstance(v, str) and len(v) >= 20:
                    return v
        for v in data.values():
            t = _find_token(v, depth + 1)
            if t:
                return t
    elif isinstance(data, list):
        for item in data[:10]:
            t = _find_token(item, depth + 1)
            if t:
                return t
    return None


# ── URL ID substitution ─────────────────────────────────────────────────────────


def _sub_id(url: str, new_id: int) -> Optional[str]:
    q = url.find("?")
    path = url[:q] if q >= 0 else url
    qs = url[q:] if q >= 0 else ""
    matches = list(_NUM_SEG_RE.finditer(path))
    if not matches:
        return None
    last = matches[-1]
    return path[:last.start(1)] + str(new_id) + path[last.end(1):] + qs


# ── Account registration + login ────────────────────────────────────────────────


async def _register(
    client: httpx.AsyncClient,
    base: str,
    identity: Dict[str, str],
) -> Optional[int]:
    for path in _REGISTER_PATHS:
        url = base + path
        for payload in _registration_payloads(identity):
            try:
                resp = await client.post(url, json=payload)
            except Exception:
                break
            if resp.status_code in (200, 201):
                logger.info("IDOR: registered %s via %s", identity["email"], path)
                try:
                    data = resp.json()
                    uid = _find_id(data)
                    return uid  # may be None if ID not in response
                except Exception:
                    return None
            if resp.status_code in (400, 409, 422):
                continue  # wrong field names -- try next payload
            break  # 404/405/5xx -- not a registration endpoint
    return None


async def _login(
    client: httpx.AsyncClient,
    base: str,
    identity: Dict[str, str],
) -> Tuple[Optional[str], Optional[Dict[str, str]], Optional[int]]:
    """Returns (jwt_token, session_cookies, user_id)."""
    for path in _LOGIN_PATHS:
        url = base + path
        for payload in _login_payloads(identity):
            try:
                resp = await client.post(url, json=payload)
            except Exception:
                break
            if resp.status_code in (200, 201):
                try:
                    data = resp.json()
                    token = _find_token(data)
                    uid = _find_id(data)
                    cookies = dict(client.cookies)
                    if token or cookies:
                        logger.info("IDOR: logged in %s via %s (uid=%s)", identity["email"], path, uid)
                        return token, (cookies if cookies else None), uid
                except Exception:
                    pass
                # No JSON token -- check for session cookies set directly
                cookies = dict(client.cookies)
                if cookies:
                    return None, cookies, None
                break  # 200 but no auth material
            if resp.status_code in (400, 401, 422):
                continue
            break  # 404/405/5xx
    return None, None, None


# ── Candidate URL builder ────────────────────────────────────────────────────────


def _build_candidates(
    base_origin: str,
    endpoints: List[str],
    user_b_id: Optional[int],
    user_a_id: Optional[int],
) -> List[str]:
    seen: set = set()
    result: List[str] = []

    def _add(u: str) -> None:
        if u and u not in seen:
            seen.add(u)
            result.append(u)

    # Priority 1: direct paths with known user_b_id
    if user_b_id:
        # Standard resource paths
        for pattern in _NUMERIC_RESOURCE_PATHS:
            _add(base_origin + pattern.replace("{id}", str(user_b_id)))
        # Extra IDOR probe patterns (basket, reviews, feedbacks, orders, etc.)
        for pattern in IDOR_PROBE_PATTERNS:
            _add(base_origin + pattern.replace("{id}", str(user_b_id)))
        # Replace numeric segments in discovered endpoints with user_b_id
        for ep in endpoints:
            subbed = _sub_id(ep, user_b_id)
            if subbed:
                _add(subbed)

    # Priority 2: id_A +/- delta heuristic (neighboring resource IDs)
    if user_a_id:
        for delta in (1, -1, 2, -2):
            test_id = user_a_id + delta
            if test_id <= 0:
                continue
            for pattern in _NUMERIC_RESOURCE_PATHS:
                _add(base_origin + pattern.replace("{id}", str(test_id)))
            for ep in endpoints:
                if _NUM_SEG_RE.search(ep.split("?")[0]):
                    subbed = _sub_id(ep, test_id)
                    if subbed:
                        _add(subbed)

    return result[:20]


# ── IDOR response analysis ───────────────────────────────────────────────────────


def _check_idor(
    data: Any,
    user_a_email: Optional[str],
    user_b_email: str,
) -> Tuple[bool, str]:
    """Returns (confirmed, evidence_string)."""
    resp_str = json.dumps(data) if not isinstance(data, str) else data

    # Strongest signal: B's email appears in response with A's token
    if user_b_email.lower() in resp_str.lower():
        return True, f"Response contains user B email: {user_b_email}"

    # Secondary: any email other than A's appears in response
    emails = re.findall(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        resp_str,
    )
    for em in emails:
        if user_a_email and em.lower() == user_a_email.lower():
            continue
        # Exclude our own test account A prefix
        if "auditscan_idor_test_a_" in em.lower():
            continue
        return True, f"Response contains email not belonging to user A: {em}"

    return False, ""


# ── Main scan coroutine ─────────────────────────────────────────────────────────


async def _run_idor_scan(req: ScanRequest) -> Dict[str, Any]:
    base = req.target.rstrip("/")
    parsed = urlparse(base)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    findings: List[Dict[str, Any]] = []
    start = time.monotonic()
    timeout_s = req.timeout

    identity_b = _make_identity("b")
    identity_a = _make_identity("a")

    has_existing_auth = bool(req.auth_headers or req.auth_cookies)

    user_a_token: Optional[str] = None
    user_a_cookies: Optional[Dict[str, str]] = None
    user_a_id: Optional[int] = req.user_a_id
    user_a_email: Optional[str] = req.user_a_email

    user_b_token: Optional[str] = None
    user_b_cookies: Optional[Dict[str, str]] = None
    user_b_id: Optional[int] = None
    registration_possible = False

    # ── Step 1: Create accounts and authenticate ────────────────────────────────
    account_timeout = min(40, timeout_s // 3)
    try:
        async with httpx.AsyncClient(
            timeout=account_timeout,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": _UA, "Accept": "application/json"},
        ) as client:
            # Always create user B -- retry up to 3 times with a fresh unique email on collision
            for _b_attempt in range(3):
                if _b_attempt > 0:
                    identity_b = _make_identity("b")
                    logger.info("IDOR: user B retry %d -- new email %s", _b_attempt, identity_b["email"])
                uid_b = await _register(client, base, identity_b)
                if uid_b is not None:
                    registration_possible = True
                    user_b_id = uid_b
                    logger.info("IDOR: user B id=%d", user_b_id)
                else:
                    # registered but no ID in response, or failed -- still attempt login
                    registration_possible = True

                await asyncio.sleep(1)

                user_b_token, user_b_cookies, uid_b_login = await _login(client, base, identity_b)
                if uid_b_login and not user_b_id:
                    user_b_id = uid_b_login
                # Fallback: decode JWT to extract ID when registration/login didn't return it
                if not user_b_id and user_b_token:
                    user_b_id = _decode_jwt_id(user_b_token)
                    if user_b_id:
                        logger.info("IDOR: user B id=%d (from JWT decode)", user_b_id)

                if user_b_token or user_b_cookies or user_b_id:
                    break
            else:
                logger.warning("IDOR: user B creation failed after 3 attempts -- IDOR test will be skipped")

            # Only create user A if pipeline didn't provide existing auth
            if not has_existing_auth:
                uid_a = await _register(client, base, identity_a)
                if uid_a is not None:
                    registration_possible = True
                    user_a_id = uid_a

                await asyncio.sleep(1)

                user_a_token, user_a_cookies, uid_a_login = await _login(client, base, identity_a)
                if uid_a_login and not user_a_id:
                    user_a_id = uid_a_login
                if not user_a_id and user_a_token:
                    user_a_id = _decode_jwt_id(user_a_token)
                user_a_email = identity_a["email"]
            else:
                # Pipeline provided user A's auth -- extract token from headers
                auth_h = req.auth_headers or {}
                raw_auth = auth_h.get("Authorization", "")
                parts = raw_auth.split(" ", 1)
                user_a_token = parts[1] if len(parts) == 2 else (raw_auth or None)
                user_a_cookies = req.auth_cookies or None
                user_a_email = req.user_a_email
                user_a_id = req.user_a_id
                # Decode JWT to get user_a_id if not provided by pipeline
                if not user_a_id and user_a_token:
                    user_a_id = _decode_jwt_id(user_a_token)
                    if user_a_id:
                        logger.info("IDOR: user A id=%d (from pipeline JWT decode)", user_a_id)

    except asyncio.TimeoutError:
        logger.warning("IDOR: account setup timed out after %ds", account_timeout)
    except Exception as exc:
        logger.warning("IDOR: account setup error: %s", exc)

    # ── Step 2: Validate we have enough material ────────────────────────────────
    a_has_auth = bool(
        (has_existing_auth and (req.auth_headers or req.auth_cookies))
        or user_a_token
        or user_a_cookies
    )
    b_was_created = bool(user_b_token or user_b_cookies or user_b_id)

    if not a_has_auth:
        reason = (
            "No authentication available for user A -- "
            "registration/login failed and no pipeline auth provided"
        )
        if not registration_possible:
            reason = "No registration endpoint detected on target -- IDOR test skipped"
        return _skip_result(req.target, reason)

    if not b_was_created:
        return _skip_result(
            req.target,
            "Could not create or authenticate user B -- IDOR test skipped",
        )

    # ── Step 3: Build candidate URLs to test ────────────────────────────────────
    candidate_urls = _build_candidates(
        base_origin=base_origin,
        endpoints=req.endpoints,
        user_b_id=user_b_id,
        user_a_id=user_a_id,
    )

    if not candidate_urls:
        return _skip_result(
            req.target,
            "No numeric-ID resource candidates found -- provide Katana/FFUF endpoints",
        )

    # ── Step 4: Build user A's request headers/cookies ──────────────────────────
    a_hdrs: Dict[str, str] = {
        "User-Agent": _UA,
        "Accept": "application/json",
    }
    a_cookies: Dict[str, str] = {}

    if has_existing_auth:
        a_hdrs.update(req.auth_headers or {})
        a_cookies.update(req.auth_cookies or {})
    elif user_a_token:
        a_hdrs["Authorization"] = f"Bearer {user_a_token}"
    elif user_a_cookies:
        a_cookies.update(user_a_cookies)

    # ── Step 5: Cross-account access test ──────────────────────────────────────
    elapsed = time.monotonic() - start
    remaining = max(timeout_s - elapsed - 5, 10)
    per_req_timeout = min(10.0, remaining / max(len(candidate_urls), 1))

    try:
        async with httpx.AsyncClient(
            timeout=per_req_timeout,
            verify=False,
            follow_redirects=False,
            headers=a_hdrs,
            cookies=a_cookies,
        ) as client:
            for url in candidate_urls:
                if time.monotonic() - start > timeout_s - 5:
                    break
                try:
                    resp = await client.get(url)
                except Exception as exc:
                    logger.debug("IDOR probe %s: %s", url, exc)
                    continue

                if resp.status_code != 200:
                    continue

                try:
                    data = resp.json()
                except Exception:
                    continue

                confirmed, evidence = _check_idor(data, user_a_email, identity_b["email"])
                if not confirmed:
                    continue

                resp_str = json.dumps(data)
                severity = (
                    "critical"
                    if re.search(r'"password"|"hash"|"token"|"secret"', resp_str, re.I)
                    else "high"
                )
                excerpt = resp_str[:500] + ("..." if len(resp_str) > 500 else "")

                findings.append({
                    "title":    f"IDOR: Unauthorized cross-account access at {url}",
                    "type":     "idor",
                    "severity": severity,
                    "target_url": url,
                    "evidence": evidence,
                    "user_a_email":  user_a_email or "pipeline_auth",
                    "user_b_id":     user_b_id,
                    "user_b_email":  identity_b["email"],
                    "response_excerpt": excerpt,
                    "description": (
                        f"User A ({user_a_email or 'pipeline auth'}) accessed resource "
                        f"belonging to user B at {url}. {evidence}"
                    ),
                    "cwe_ids":  ["CWE-639", "CWE-284"],
                    "tags":     ["idor", "broken_access_control", "authorization"],
                })
                logger.info("IDOR CONFIRMED: %s -- %s", url, evidence)

    except asyncio.TimeoutError:
        logger.warning("IDOR: scan phase timed out")
    except Exception as exc:
        logger.error("IDOR: scan error: %s", exc)

    by_sev: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "high")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    return {
        "target":            req.target,
        "skipped":           False,
        "reason":            None,
        "findings":          findings,
        "total":             len(findings),
        "by_severity":       by_sev,
        "user_b_email":      identity_b["email"] if b_was_created else None,
        "user_b_id":         user_b_id,
        "candidates_tested": len(candidate_urls),
        "error":             None,
    }


def _skip_result(target: str, reason: str) -> Dict[str, Any]:
    return {
        "target":            target,
        "skipped":           True,
        "reason":            reason,
        "findings":          [],
        "total":             0,
        "by_severity":       {},
        "user_b_email":      None,
        "user_b_id":         None,
        "candidates_tested": 0,
        "error":             None,
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=9012, log_level="info")
