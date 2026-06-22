"""
Registre de probe packs par stack technique.

Chaque pack associe une signature de detection (stack detectee par agent_decision)
a une liste de probes generiques pertinentes pour cette stack.
Utilise en Phase 3 par _call_sqlmap_enriched pour remplacer les chemins hardcodes.
"""
from __future__ import annotations

from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Registre principal
# ---------------------------------------------------------------------------
# Structure d'une probe :
#   path   : chemin relatif (peut inclure une query string : /search?q=test)
#   method : HTTP method (GET / POST)
#   params : parametres a tester par SQLMap
#   data   : body pour les requetes POST (string JSON ou form-encoded)
# ---------------------------------------------------------------------------

PROBE_PACKS: Dict[str, Dict[str, Any]] = {
    # -----------------------------------------------------------------------
    # Express / Node.js  (couvre Juice Shop et les API REST Express classiques)
    # -----------------------------------------------------------------------
    "express_nodejs": {
        "description": "Express/Node.js REST API -- includes Juice Shop-compatible routes",
        "probes": [
            {
                "path":   "/rest/user/login",
                "method": "POST",
                "params": ["email"],
                "data":   '{"email":"test@test.com","password":"wrongpass123"}',
            },
            {
                "path":   "/rest/products/search?q=test",
                "method": "GET",
                "params": ["q"],
                "data":   "",
            },
            {
                "path":   "/api/Feedbacks",
                "method": "POST",
                "params": ["comment"],
                "data":   '{"captchaId":0,"captcha":"a","rating":1,"comment":"test"}',
            },
            {
                "path":   "/api/login",
                "method": "POST",
                "params": ["email", "username"],
                "data":   '{"email":"test@test.com","password":"test"}',
            },
            {
                "path":   "/api/search?q=test",
                "method": "GET",
                "params": ["q"],
                "data":   "",
            },
        ],
    },

    # -----------------------------------------------------------------------
    # WordPress
    # -----------------------------------------------------------------------
    "wordpress": {
        "description": "WordPress CMS",
        "probes": [
            {
                "path":   "/wp-login.php",
                "method": "POST",
                "params": ["log", "pwd"],
                "data":   "log=admin&pwd=admin",
            },
            {
                "path":   "/wp-json/wp/v2/users",
                "method": "GET",
                "params": [],
                "data":   "",
            },
            {
                "path":   "/?s=test",
                "method": "GET",
                "params": ["s"],
                "data":   "",
            },
            {
                "path":   "/?p=1",
                "method": "GET",
                "params": ["p"],
                "data":   "",
            },
        ],
    },

    # -----------------------------------------------------------------------
    # Django
    # -----------------------------------------------------------------------
    "django": {
        "description": "Django REST framework / Django admin",
        "probes": [
            {
                "path":   "/admin/login/",
                "method": "POST",
                "params": ["username", "password"],
                "data":   "username=admin&password=admin",
            },
            {
                "path":   "/api/v1/users/?id=1",
                "method": "GET",
                "params": ["id", "search"],
                "data":   "",
            },
            {
                "path":   "/accounts/login/",
                "method": "POST",
                "params": ["username"],
                "data":   "username=test&password=test",
            },
            {
                "path":   "/api/v1/?search=test",
                "method": "GET",
                "params": ["search"],
                "data":   "",
            },
        ],
    },

    # -----------------------------------------------------------------------
    # PHP generique  (Laravel, Symfony, apps PHP custom)
    # -----------------------------------------------------------------------
    "php_generic": {
        "description": "Generic PHP application (Laravel, Symfony, custom)",
        "probes": [
            {
                "path":   "/login",
                "method": "POST",
                "params": ["email", "username"],
                "data":   "email=test%40test.com&password=test",
            },
            {
                "path":   "/search?q=test",
                "method": "GET",
                "params": ["q", "search"],
                "data":   "",
            },
            {
                "path":   "/index.php?id=1",
                "method": "GET",
                "params": ["id", "page"],
                "data":   "",
            },
            {
                "path":   "/user/profile?id=1",
                "method": "GET",
                "params": ["id"],
                "data":   "",
            },
        ],
    },

    # -----------------------------------------------------------------------
    # Fallback generique  (aucune stack connue detectee)
    # -----------------------------------------------------------------------
    "generic_rest_api": {
        "description": "Generic REST API fallback -- used when no specific stack is detected",
        "probes": [
            {
                "path":   "/api/login",
                "method": "POST",
                "params": ["username", "email"],
                "data":   '{"username":"test","password":"test"}',
            },
            {
                "path":   "/login",
                "method": "POST",
                "params": ["username"],
                "data":   "username=admin&password=admin",
            },
            {
                "path":   "/api/search?q=test",
                "method": "GET",
                "params": ["q", "search"],
                "data":   "",
            },
            {
                "path":   "/search?q=test",
                "method": "GET",
                "params": ["q"],
                "data":   "",
            },
            {
                "path":   "/api/users?id=1",
                "method": "GET",
                "params": ["id"],
                "data":   "",
            },
            {
                "path":   "/users?id=1",
                "method": "GET",
                "params": ["id", "page"],
                "data":   "",
            },
        ],
    },
}


def resolve_probes(pack_ids: List[str], base_url: str) -> List[Dict[str, Any]]:
    """
    Instancie les probes d'une liste de pack IDs sur base_url.
    Retourne des dicts {url, method, params, data} prets a etre inseres dans endpoints.
    Les doublons (meme URL+methode) sont dedupliques.
    """
    base_url = base_url.rstrip("/")
    result: List[Dict[str, Any]] = []
    seen: set = set()

    for pack_id in pack_ids:
        pack = PROBE_PACKS.get(pack_id)
        if not pack:
            continue
        for probe in pack["probes"]:
            path = probe["path"]
            # Build full URL -- path may already contain a query string
            url = f"{base_url}{path}"
            key = (url, probe["method"].upper())
            if key in seen:
                continue
            seen.add(key)
            result.append({
                "url":    url,
                "method": probe["method"].upper(),
                "params": list(probe.get("params", [])),
                "data":   probe.get("data", ""),
            })

    return result
