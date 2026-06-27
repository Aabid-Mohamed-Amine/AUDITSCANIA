"""
Auth Detection & Authentication Manager

Détecte automatiquement le type d'authentification d'une application web
et effectue le login si des credentials sont fournis.

Types supportés :
  - none           : pas d'auth nécessaire
  - jwt_bearer     : JWT / OAuth2 Bearer token
  - session_cookie : login par formulaire → cookie de session
  - http_basic     : HTTP Basic Authentication
  - api_key_header : API key dans un header custom

Flux :
  1. credentials.token       → AuthContext direct (JWT/Bearer)
  2. credentials.cookie      → AuthContext direct (session cookie)
  3. credentials.user+pass   → détection form → login → cookies
  4. aucun credentials       → détection seulement (informatif)

AuthContext.headers + AuthContext.cookies sont ready-to-inject
dans ZAP, Nuclei, FFUF et SQLMap.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)


# ── Auth type constants ───────────────────────────────────────────────────────

class AuthType:
    NONE           = "none"
    JWT_BEARER     = "jwt_bearer"
    SESSION_COOKIE = "session_cookie"
    FORM_LOGIN     = "form_login"
    HTTP_BASIC     = "http_basic"
    API_KEY_HEADER = "api_key_header"


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class AuthCredentials:
    """Credentials fournis par l'utilisateur (optionnels)."""
    username:       Optional[str] = None
    password:       Optional[str] = None
    token:          Optional[str] = None   # JWT ou API key déjà obtenu
    cookie:         Optional[str] = None   # ex: "session=abc; other=xyz"
    login_url:      Optional[str] = None   # override URL de login auto-détectée
    header_name:    str = "Authorization"  # header pour le token
    header_prefix:  str = "Bearer"         # préfixe ("Bearer", "Token", "")

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> Optional["AuthCredentials"]:
        if not d:
            return None
        return cls(
            username      = d.get("username"),
            password      = d.get("password"),
            token         = d.get("token"),
            cookie        = d.get("cookie"),
            login_url     = d.get("login_url"),
            header_name   = d.get("header_name", "Authorization"),
            header_prefix = d.get("header_prefix", "Bearer"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username":      self.username,
            # password non exporté pour sécurité
            "token":         self.token,
            "cookie":        self.cookie,
            "login_url":     self.login_url,
            "header_name":   self.header_name,
            "header_prefix": self.header_prefix,
        }

    def has_credentials(self) -> bool:
        return bool(self.token or self.cookie or (self.username and self.password))


@dataclass
class AuthContext:
    """
    Contexte d'authentification prêt à l'emploi.
    headers et cookies sont injectés directement dans tous les scanners.
    """
    auth_type:  str                = AuthType.NONE
    headers:    Dict[str, str]     = field(default_factory=dict)
    cookies:    Dict[str, str]     = field(default_factory=dict)
    detected:   bool               = False
    login_url:  Optional[str]      = None
    notes:      str                = ""
    success:    bool               = True
    error:      Optional[str]      = None

    def has_auth(self) -> bool:
        return bool(self.headers or self.cookies)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "auth_type":  self.auth_type,
            "headers":    self.headers,
            "cookies":    self.cookies,
            "detected":   self.detected,
            "login_url":  self.login_url,
            "notes":      self.notes,
            "success":    self.success,
            "error":      self.error,
            "has_auth":   self.has_auth(),
        }

    @classmethod
    def empty(cls) -> "AuthContext":
        return cls(auth_type=AuthType.NONE, notes="No authentication")

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuthContext":
        return cls(
            auth_type  = d.get("auth_type", AuthType.NONE),
            headers    = d.get("headers", {}),
            cookies    = d.get("cookies", {}),
            detected   = d.get("detected", False),
            login_url  = d.get("login_url"),
            notes      = d.get("notes", ""),
            success    = d.get("success", True),
            error      = d.get("error"),
        )


# ── Common login paths ────────────────────────────────────────────────────────

_LOGIN_PATHS = [
    "/login", "/signin", "/sign-in",
    "/auth", "/auth/login", "/auth/signin",
    "/api/login", "/api/auth", "/api/auth/login", "/api/v1/login", "/api/v1/auth",
    "/user/login", "/users/login", "/users/sign_in",
    "/account/login", "/accounts/login",
    "/portal/login", "/portal",
    "/admin/login", "/admin",
    "/wp-login.php",
    "/console", "/dashboard/login",
]

_UA = "Mozilla/5.0 (compatible; AuditScan/3.0; +https://github.com/auditscan)"


# ── HTML form parsing ─────────────────────────────────────────────────────────

def _parse_login_form(html: str) -> Optional[Dict[str, str]]:
    """
    Analyse le HTML d'une page pour extraire les noms de champs d'un formulaire de login.
    Retourne None si aucun champ password trouvé.
    """
    # Attributs HTML avec OU sans guillemets (q = quote optionnelle, V = valeur)
    # tolère type=password, type="password", type='password'
    if not re.search(r'<input[^>]+type=["\']?password\b', html, re.I):
        return None

    fields: Dict[str, str] = {}
    _V = r'["\']?([A-Za-z0-9_\-\[\].]+)["\']?'   # valeur d'attribut (quote optionnelle)

    # Champ password
    for pat in [
        rf'<input[^>]+type=["\']?password\b[^>]*(?:name|id)={_V}',
        rf'<input[^>]+(?:name|id)={_V}[^>]*type=["\']?password\b',
    ]:
        m = re.search(pat, html, re.I)
        if m:
            fields["password"] = m.group(1).strip()
            break

    # Champ username / email
    for pat in [
        rf'<input[^>]+type=["\']?email\b[^>]*(?:name|id)={_V}',
        rf'<input[^>]+(?:name|id)=["\']?([A-Za-z0-9_\-\[\].]*(?:email|user|login|username|mail|account)[A-Za-z0-9_\-\[\].]*)["\']?[^>]*type=["\']?(?:text|email)\b',
        rf'(?:name|id)=["\']?([A-Za-z0-9_\-\[\].]*(?:email|username|user)[A-Za-z0-9_\-\[\].]*)["\']?',
    ]:
        m = re.search(pat, html, re.I)
        if m:
            candidate = m.group(1).strip()
            if candidate != fields.get("password", ""):
                fields["username"] = candidate
                break

    # CSRF token (si présent)
    for pat in [
        r'<input[^>]+name=["\']([^"\']*(?:csrf|_token|authenticity_token|xsrf)[^"\']*)["\'][^>]*value=["\']([^"\']+)["\']',
        r'<meta[^>]+name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
    ]:
        m = re.search(pat, html, re.I)
        if m:
            groups = m.groups()
            if len(groups) == 2:
                fields["_csrf_name"]  = groups[0]
                fields["_csrf_value"] = groups[1]
            else:
                fields["_csrf_value"] = groups[0]
            break

    if not fields:
        return None

    fields.setdefault("password", "password")
    fields.setdefault("username", "username")
    return fields


# ── HTTP probing ──────────────────────────────────────────────────────────────

async def _get(url: str, timeout: float = 15.0, follow: bool = True) -> Optional[httpx.Response]:
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False,
            follow_redirects=follow,
            headers={"User-Agent": _UA},
        ) as client:
            return await client.get(url)
    except Exception:
        return None


# ── Auth type detection ───────────────────────────────────────────────────────

async def detect_auth_type(target: str, timeout: float = 10.0) -> Dict[str, Any]:
    """
    Détecte automatiquement le type d'auth d'une application web.

    Retourne:
        {
            "type":        AuthType,
            "login_url":   str | None,
            "form_fields": {"username": "...", "password": "...", ...},
            "cookie_names": [...],
            "realm":       str | None,
            "notes":       str,
        }
    """
    base = target if target.startswith(("http://", "https://")) else f"http://{target}"

    info: Dict[str, Any] = {
        "type": AuthType.NONE, "login_url": None,
        "form_fields": {}, "cookie_names": [], "realm": None, "notes": "",
        "is_juice_shop": False,
    }

    resp = await _get(base, timeout=timeout, follow=True)
    if resp is None:
        info["notes"] = "Target unreachable during auth detection"
        return info

    # ── WWW-Authenticate header ───────────────────────────────────────────
    www_auth = resp.headers.get("www-authenticate", "")
    if "bearer" in www_auth.lower():
        info["type"]  = AuthType.JWT_BEARER
        info["notes"] = f"WWW-Authenticate: Bearer detected"
        return info
    if "basic" in www_auth.lower():
        info["type"] = AuthType.HTTP_BASIC
        m = re.search(r'realm=["\']?([^"\'>,\s]+)', www_auth)
        info["realm"] = m.group(1) if m else ""
        info["notes"] = f"HTTP Basic auth (realm={info['realm']!r})"
        return info

    # ── Collect cookie names from response ────────────────────────────────
    for name in resp.cookies:
        info["cookie_names"].append(name)

    # ── Login form on the landing page ───────────────────────────────────
    ct = resp.headers.get("content-type", "")
    if "text/html" in ct:
        ff = _parse_login_form(resp.text)
        if ff:
            info["type"]        = AuthType.FORM_LOGIN
            info["form_fields"] = ff
            info["login_url"]   = str(resp.url)
            info["notes"]       = "Login form on main page"
            return info

    # ── Redirect to login page ────────────────────────────────────────────
    if resp.history:
        final = str(resp.url).lower()
        if any(k in final for k in ("/login", "/signin", "/auth", "/account")):
            info["type"]      = AuthType.FORM_LOGIN
            info["login_url"] = str(resp.url)
            info["notes"]     = f"Redirected to login: {resp.url}"
            ff = _parse_login_form(resp.text)
            if ff:
                info["form_fields"] = ff
            return info

    # ── Détection app type avant probe — évite de spammer des chemins inconnus
    # qui génèrent des erreurs fatales (ex: Juice Shop Node.js heap OOM).
    # Si la page d'accueil mentionne "juice" ou "owasp" → Juice Shop détecté :
    # on ne teste que /rest/user/login au lieu des ~20 chemins génériques.
    _body_lower = (resp.text or "").lower() if resp else ""
    _is_juice_shop = "juice" in _body_lower or "owasp" in _body_lower
    info["is_juice_shop"] = _is_juice_shop
    if _is_juice_shop:
        logger.info("Auth detect: Juice Shop/OWASP détecté sur %s", base)

    # ── Probe common login paths ──────────────────────────────────────────
    probed = await _probe_login_paths(base, timeout=min(timeout, 15.0),
                                      juice_shop=_is_juice_shop)
    if probed["type"] != AuthType.NONE:
        return {**info, **probed}

    # ── Session cookies present ───────────────────────────────────────────
    if info["cookie_names"]:
        info["type"]  = AuthType.SESSION_COOKIE
        info["notes"] = f"Session cookies: {info['cookie_names']}"

    return info


async def _probe_login_paths(
    base_url:   str,
    timeout:    float = 15.0,
    juice_shop: bool  = False,
) -> Dict[str, Any]:
    """Teste les chemins de login courants pour trouver un formulaire.

    Si juice_shop=True, teste uniquement /rest/user/login (évite de spammer
    ~20 chemins inconnus qui saturent le heap Node.js de Juice Shop).
    Sinon, teste _LOGIN_PATHS complet avec 1s entre chaque requête.
    """
    result: Dict[str, Any] = {
        "type": AuthType.NONE, "login_url": None, "form_fields": {}, "notes": "",
    }
    if juice_shop:
        paths_to_test = ["/rest/user/login"]
        logger.info("Auth probe: Juice Shop/OWASP détecté — restriction à /rest/user/login")
    else:
        paths_to_test = _LOGIN_PATHS

    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True,
            headers={"User-Agent": _UA},
        ) as client:
            for i, path in enumerate(paths_to_test):
                # Pause 1s entre chaque tentative (sauf la première) pour ne pas
                # saturer la cible — critique sur apps Node.js/PHP à faible RAM.
                if i > 0:
                    await asyncio.sleep(1)
                url = f"{base_url.rstrip('/')}{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
                        ff = _parse_login_form(resp.text)
                        if ff:
                            result["type"]        = AuthType.FORM_LOGIN
                            result["login_url"]   = str(resp.url)
                            result["form_fields"] = ff
                            result["notes"]       = f"Login form at {path}"
                            return result
                except (httpx.ConnectError, httpx.TimeoutException):
                    continue
    except Exception as exc:
        result["notes"] = f"Path probe error: {exc}"
    return result


# ── Form login ────────────────────────────────────────────────────────────────

async def _perform_json_login(
    login_url: str,
    username:  str,
    password:  str,
    timeout:   float = 20.0,
) -> Optional["AuthContext"]:
    """JSON REST login (Juice Shop /rest/user/login → JWT in response body)."""
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True,
            headers={"User-Agent": _UA, "Content-Type": "application/json"},
        ) as client:
            resp = await client.post(login_url, json={"email": username, "password": password})
            if resp.status_code not in (200, 201):
                logger.debug("JSON login %s → HTTP %d", login_url, resp.status_code)
                return None
            data = resp.json()
            # Juice Shop: {"authentication": {"token": "...", "bid": N}}
            auth_obj = data.get("authentication") or {}
            token = auth_obj.get("token") or data.get("token")
            if not token:
                return None
            logger.info("JSON login OK — JWT obtained from %s", login_url)
            return AuthContext(
                auth_type = AuthType.JWT_BEARER,
                headers   = {"Authorization": f"Bearer {token}"},
                cookies   = {},
                detected  = True,
                login_url = login_url,
                notes     = f"JSON REST login OK at {login_url}",
            )
    except Exception as exc:
        logger.debug("JSON login failed at %s: %s", login_url, exc)
        return None


async def _perform_form_login(
    login_url:   str,
    username:    str,
    password:    str,
    form_fields: Dict[str, str],
    timeout:     float = 20.0,
) -> Dict[str, str]:
    """
    Effectue un login par formulaire HTML et retourne les cookies de session.
    Gère automatiquement le token CSRF si présent.
    """
    username_field = form_fields.get("username", "username")
    password_field = form_fields.get("password", "password")

    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True,
            headers={"User-Agent": _UA},
        ) as client:
            # GET pour obtenir le CSRF token et les cookies initiaux
            get_resp = await client.get(login_url)

            post_data: Dict[str, str] = {
                username_field: username,
                password_field: password,
            }

            # Injecter CSRF s'il est dans le formulaire
            csrf_name  = form_fields.get("_csrf_name")
            csrf_value = form_fields.get("_csrf_value")
            if csrf_name and csrf_value:
                post_data[csrf_name] = csrf_value
            else:
                # Extraire CSRF depuis la réponse GET
                for pat in [
                    r'<input[^>]+name=["\']([^"\']*(?:csrf|_token|authenticity_token)[^"\']*)["\'][^>]*value=["\']([^"\']+)["\']',
                    r'<meta[^>]+name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
                ]:
                    m = re.search(pat, get_resp.text, re.I)
                    if m:
                        groups = m.groups()
                        if len(groups) == 2:
                            post_data[groups[0]] = groups[1]
                        break

            post_resp = await client.post(
                login_url,
                data=post_data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer":      login_url,
                },
            )

            # Collecter tous les cookies de la session httpx
            cookies: Dict[str, str] = {}
            for name, val in client.cookies.items():
                cookies[name] = val
            for name, val in post_resp.cookies.items():
                cookies[name] = val

            if cookies:
                logger.info("Form login OK — %d cookie(s): %s", len(cookies), list(cookies.keys()))
            else:
                logger.warning("Form login at %s returned no cookies", login_url)

            return cookies

    except Exception as exc:
        logger.warning("Form login failed at %s: %s", login_url, exc)
        return {}


# ── Cookie string parser ──────────────────────────────────────────────────────

def _parse_cookie_string(cookie_str: str) -> Dict[str, str]:
    """Parse 'name=value; name2=value2' → {'name': 'value', ...}"""
    cookies: Dict[str, str] = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, val = part.partition("=")
            cookies[name.strip()] = val.strip()
    return cookies


# ── Auto-authentication (aucun credential fourni) ─────────────────────────────
# Stratégie 100% automatique :
#   1. Enregistrer un compte aléatoire (champs random) via API JSON ou form HTML
#   2. Se connecter avec ce compte → récupérer JWT ou cookie de session
#   3. Fallback : tester des credentials par défaut (admin:admin, etc.)
# Couvre les SPA / apps JSON où la détection HTML ne voit aucun formulaire.

_REGISTER_PATHS = [
    "/api/register", "/api/auth/register", "/api/v1/register",
    "/register", "/signup", "/sign-up", "/auth/register",
    "/api/users", "/api/Users", "/users", "/api/account/register",
]

_LOGIN_API_PATHS = [
    "/api/login", "/api/auth/login", "/api/v1/login",
    "/rest/user/login", "/login", "/auth/login",
    "/api/authenticate", "/api/sessions", "/api/token",
]

_DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("administrator", "administrator"), ("root", "root"),
    ("test", "test"), ("guest", "guest"), ("admin", "123456"),
]

_TOKEN_KEYS = {
    "token", "jwt", "access_token", "accesstoken", "id_token",
    "auth_token", "authtoken", "bearer",
}


def _generate_random_identity() -> Dict[str, str]:
    """Génère une identité aléatoire (email/username/password fort)."""
    suffix = secrets.token_hex(6)
    return {
        "email":    f"auditscan_{suffix}@auditscan-test.local",
        "username": f"auditscan_{suffix}",
        "password": "Aud1t!" + secrets.token_hex(8),   # >12 chars, complexité OK
    }


def _find_token(obj: Any, depth: int = 0) -> Optional[str]:
    """Recherche récursive d'un token dans une réponse JSON."""
    if depth > 6:
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k).lower().replace("-", "_")
            if key in _TOKEN_KEYS and isinstance(v, str) and len(v) >= 20:
                return v
        for v in obj.values():
            t = _find_token(v, depth + 1)
            if t:
                return t
    elif isinstance(obj, list):
        for v in obj[:20]:
            t = _find_token(v, depth + 1)
            if t:
                return t
    return None


def _registration_payloads(identity: Dict[str, str]) -> List[Dict[str, str]]:
    e, u, p = identity["email"], identity["username"], identity["password"]
    return [
        {"email": e, "password": p, "passwordRepeat": p},
        {"email": e, "password": p, "password_confirmation": p},
        {"username": u, "email": e, "password": p},
        {"email": e, "password": p},
    ]


def _login_payloads(identity: Dict[str, str]) -> List[Dict[str, str]]:
    e, u, p = identity["email"], identity["username"], identity["password"]
    return [
        {"email": e, "password": p},
        {"username": u, "password": p},
        {"username": e, "password": p},
    ]


def _ctx_from_login_response(resp: httpx.Response, client: httpx.AsyncClient, source: str) -> Optional[AuthContext]:
    """Construit un AuthContext depuis une réponse de login (token JSON ou cookie)."""
    try:
        data = resp.json()
    except Exception:
        data = None
    if data is not None:
        token = _find_token(data)
        if token:
            return AuthContext(
                auth_type = AuthType.JWT_BEARER,
                headers   = {"Authorization": f"Bearer {token}"},
                detected  = True, success = True,
                notes     = f"Auto-auth: JWT via {source}",
            )
    cookies = {n: v for n, v in client.cookies.items()}
    if cookies:
        return AuthContext(
            auth_type = AuthType.SESSION_COOKIE,
            cookies   = cookies,
            detected  = True, success = True,
            notes     = f"Auto-auth: session cookie via {source}",
        )
    return None


async def _json_login(client: httpx.AsyncClient, base: str, identity: Dict[str, str]) -> Optional[AuthContext]:
    """Tente un login JSON sur les chemins d'API courants."""
    for path in _LOGIN_API_PATHS:
        url = base.rstrip("/") + path
        for payload in _login_payloads(identity):
            try:
                resp = await client.post(url, json=payload)
            except Exception:
                break  # chemin injoignable → suivant
            if resp.status_code in (200, 201):
                ctx = _ctx_from_login_response(resp, client, f"POST {path}")
                if ctx:
                    ctx.login_url = url
                    return ctx
                break  # 200 mais pas de token/cookie → chemin suivant
            if resp.status_code in (400, 401, 422):
                continue  # mauvais nom de champ → essayer un autre payload
            break  # 404/405/5xx → chemin suivant
    return None


async def _attempt_register_and_login(base: str, identity: Dict[str, str], timeout: float) -> Optional[AuthContext]:
    """Enregistre un compte aléatoire puis se connecte (API JSON best-effort)."""
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True,
            headers={"User-Agent": _UA},
        ) as client:
            # A. Enregistrement via API JSON
            for path in _REGISTER_PATHS:
                url = base.rstrip("/") + path
                for payload in _registration_payloads(identity):
                    try:
                        resp = await client.post(url, json=payload)
                    except Exception:
                        break  # chemin injoignable
                    if resp.status_code in (200, 201):
                        logger.info("Auto-auth: compte enregistré via %s", path)
                        # token directement dans la réponse d'enregistrement ?
                        ctx = _ctx_from_login_response(resp, client, f"register {path}")
                        if ctx:
                            ctx.notes = f"Auto-registered random account via {path}"
                            ctx.login_url = url
                            return ctx
                        # sinon : login avec le compte créé
                        ctx = await _json_login(client, base, identity)
                        if ctx:
                            ctx.notes = f"Auto-registered ({path}) + logged in"
                            return ctx
                        break
                    if resp.status_code in (400, 409, 422):
                        continue  # validation/déjà existant → autre combo de champs
                    break  # 404/405/5xx → ce n'est pas un endpoint d'enregistrement

            # B. Login direct (au cas où l'enregistrement a réussi silencieusement)
            ctx = await _json_login(client, base, identity)
            if ctx:
                return ctx
    except Exception as exc:
        logger.debug("Auto register/login error: %s", exc)
    return None


async def _try_default_credentials(base: str, auth_info: Dict[str, Any], timeout: float) -> Optional[AuthContext]:
    """Teste des credentials par défaut (form HTML détecté + API JSON)."""
    # B1. Form HTML détecté → login form avec creds par défaut
    login_url   = auth_info.get("login_url")
    form_fields = auth_info.get("form_fields", {})
    if login_url and auth_info.get("type") == AuthType.FORM_LOGIN:
        for user, pw in _DEFAULT_CREDS[:6]:
            cookies = await _perform_form_login(login_url, user, pw, form_fields, timeout=timeout)
            if cookies:
                return AuthContext(
                    auth_type = AuthType.FORM_LOGIN, cookies = cookies,
                    detected  = True, login_url = login_url, success = True,
                    notes     = f"Auto-auth: default creds {user}:{pw} accepted (form)",
                )

    # B2. API JSON → login avec creds par défaut
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True,
            headers={"User-Agent": _UA},
        ) as client:
            for path in _LOGIN_API_PATHS[:6]:
                url = base.rstrip("/") + path
                for user, pw in _DEFAULT_CREDS[:6]:
                    try:
                        resp = await client.post(url, json={"email": user, "username": user, "password": pw})
                    except Exception:
                        break  # chemin injoignable
                    if resp.status_code in (200, 201):
                        ctx = _ctx_from_login_response(resp, client, f"default-creds {path}")
                        if ctx:
                            ctx.login_url = url
                            ctx.notes = f"Auto-auth: default creds {user}:{pw} via {path}"
                            return ctx
                    elif resp.status_code in (400, 401, 422):
                        continue
                    else:
                        break  # 404/405 → chemin suivant
    except Exception:
        pass
    return None


async def _auto_authenticate(
    base:          str,
    auth_info:     Dict[str, Any],
    timeout:       float = 20.0,
    is_juice_shop: bool  = False,
) -> Optional[AuthContext]:
    """
    Authentification 100% automatique, sans credential fourni.
    Si is_juice_shop=True : restreint à /api/register + /rest/user/login
    pour éviter de spammer ~20 chemins qui saturent le heap Node.js.
    """
    identity = _generate_random_identity()

    if is_juice_shop:
        logger.info("Auto-auth: Juice Shop — restriction à /api/Users + /rest/user/login")
        try:
            async with httpx.AsyncClient(
                timeout=timeout, verify=False, follow_redirects=True,
                headers={"User-Agent": _UA},
            ) as client:
                # 1. Enregistrement via /api/Users (POST /api/register → HTTP:000 sur Juice Shop)
                url_reg = base.rstrip("/") + "/api/Users"
                for payload in _registration_payloads(identity):
                    try:
                        resp = await client.post(url_reg, json=payload)
                    except Exception:
                        break
                    if resp.status_code in (200, 201):
                        logger.info("Auto-auth: compte Juice Shop enregistré")
                        ctx = _ctx_from_login_response(resp, client, "register /api/Users")
                        if ctx:
                            ctx.notes = "Auto-registered Juice Shop account"
                            ctx.login_url = url_reg
                            return ctx
                        break
                    if resp.status_code in (400, 409, 422):
                        continue
                    break
                # Pause entre enregistrement et login
                await asyncio.sleep(1)
                # 2. Login via /rest/user/login uniquement
                url_login = base.rstrip("/") + "/rest/user/login"
                for payload in _login_payloads(identity):
                    try:
                        resp = await client.post(url_login, json=payload)
                    except Exception:
                        break
                    if resp.status_code in (200, 201):
                        ctx = _ctx_from_login_response(resp, client, "login /rest/user/login")
                        if ctx:
                            ctx.login_url = url_login
                            ctx.notes = "Auto-auth Juice Shop: register + /rest/user/login"
                            return ctx
                        break
                    if resp.status_code in (400, 401, 422):
                        continue
                    break
        except Exception as exc:
            logger.debug("Juice Shop auto-auth error: %s", exc)
        return None

    # ── Mode générique : register aléatoire + login + credentials par défaut ──
    ctx = await _attempt_register_and_login(base, identity, timeout)
    if ctx and ctx.has_auth():
        return ctx

    ctx = await _try_default_credentials(base, auth_info, timeout)
    if ctx and ctx.has_auth():
        return ctx

    return None


# ── Main entry point ──────────────────────────────────────────────────────────

async def detect_and_authenticate(
    target:      str,
    credentials: Optional[AuthCredentials] = None,
    timeout:     float = 60.0,
    auto_auth:   bool = True,
) -> AuthContext:
    """
    Point d'entrée principal du auth manager.

    Priorité :
      1. token fourni       → AuthContext JWT immédiat (pas de détection)
      2. cookie fourni      → AuthContext cookie immédiat
      3. user + password    → détection form → login → cookies session
      4. aucun credential   → si auto_auth: enregistrement auto d'un compte
                              aléatoire + login, puis fallback creds par défaut.
                              Sinon: détection seulement.

    Returns AuthContext avec headers + cookies prêts à injecter dans les scanners.
    """
    base = target if target.startswith(("http://", "https://")) else f"http://{target}"

    # ── 1. Token pré-fourni ───────────────────────────────────────────────
    if credentials and credentials.token:
        val = f"{credentials.header_prefix} {credentials.token}".strip() \
              if credentials.header_prefix else credentials.token
        logger.info("Auth: token direct via %s", credentials.header_name)
        return AuthContext(
            auth_type = AuthType.JWT_BEARER,
            headers   = {credentials.header_name: val},
            cookies   = {},
            detected  = False,
            notes     = f"User-provided token ({credentials.header_name})",
        )

    # ── 2. Cookie pré-fourni ──────────────────────────────────────────────
    if credentials and credentials.cookie:
        cookies = _parse_cookie_string(credentials.cookie)
        logger.info("Auth: cookie direct (%d cookies)", len(cookies))
        return AuthContext(
            auth_type = AuthType.SESSION_COOKIE,
            headers   = {},
            cookies   = cookies,
            detected  = False,
            notes     = f"User-provided cookies: {list(cookies.keys())}",
        )

    # ── 3. Username + Password → détection form + login ───────────────────
    if credentials and credentials.username and credentials.password:
        logger.info("Auth: detecting form for %s", base)
        auth_info = await detect_auth_type(base, timeout=timeout / 2)

        # HTTP Basic
        if auth_info["type"] == AuthType.HTTP_BASIC:
            creds_b64 = base64.b64encode(
                f"{credentials.username}:{credentials.password}".encode()
            ).decode()
            logger.info("Auth: HTTP Basic for %s", base)
            return AuthContext(
                auth_type = AuthType.HTTP_BASIC,
                headers   = {"Authorization": f"Basic {creds_b64}"},
                cookies   = {},
                detected  = True,
                notes     = f"HTTP Basic (realm: {auth_info.get('realm', '?')})",
            )

        # Form login
        login_url   = credentials.login_url or auth_info.get("login_url")
        form_fields = auth_info.get("form_fields", {})

        if login_url:
            # Try JSON login first for REST endpoints (Juice Shop, JSON APIs)
            _is_rest = "/rest/" in login_url or auth_info.get("is_juice_shop", False)
            if _is_rest:
                json_ctx = await _perform_json_login(
                    login_url, credentials.username, credentials.password, timeout=timeout,
                )
                if json_ctx and json_ctx.has_auth():
                    return json_ctx

            form_fields.setdefault("username", "username")
            form_fields.setdefault("password", "password")
            logger.info("Auth: form login at %s", login_url)
            cookies = await _perform_form_login(
                login_url   = login_url,
                username    = credentials.username,
                password    = credentials.password,
                form_fields = form_fields,
                timeout     = timeout,
            )
            if cookies:
                return AuthContext(
                    auth_type = AuthType.FORM_LOGIN,
                    headers   = {},
                    cookies   = cookies,
                    detected  = True,
                    login_url = login_url,
                    notes     = f"Form login OK at {login_url} ({len(cookies)} cookies)",
                )
            return AuthContext(
                auth_type = AuthType.FORM_LOGIN,
                headers   = {},
                cookies   = {},
                detected  = True,
                login_url = login_url,
                success   = False,
                error     = "Login returned no cookies — check credentials",
                notes     = f"Form login failed at {login_url}",
            )

        # Credentials mais pas de form trouvé
        logger.warning("Auth: credentials provided but no login form found at %s", base)
        return AuthContext(
            auth_type = auth_info["type"],
            detected  = True,
            success   = False,
            error     = "Credentials provided but no login form detected",
            notes     = auth_info.get("notes", ""),
        )

    # ── 4. Aucun credential → détection + auto-authentification ──────────
    logger.info("Auth: auto mode (no credentials) for %s", base)
    auth_info = await detect_auth_type(base, timeout=min(timeout, 15.0))
    is_juice_shop = auth_info.get("is_juice_shop", False)

    if auto_auth:
        # Tente register-aléatoire + login, puis credentials par défaut.
        # Couvre aussi les SPA/JSON où auth_info['type'] == 'none'.
        auto_ctx = await _auto_authenticate(
            base, auth_info,
            timeout=min(timeout, 20.0),
            is_juice_shop=is_juice_shop,
        )
        if auto_ctx and auto_ctx.has_auth():
            auto_ctx.detected = True
            logger.info("Auto-auth success: %s", auto_ctx.notes)
            return auto_ctx

    return AuthContext(
        auth_type = auth_info["type"],
        headers   = {},
        cookies   = {},
        detected  = True,
        login_url = auth_info.get("login_url"),
        notes     = (
            f"Detected: {auth_info['type']} — auto-auth tenté, aucune session obtenue"
            if auto_auth else
            f"Detected: {auth_info['type']} (no credentials — unauthenticated)"
        ),
    )
