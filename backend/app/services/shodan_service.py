"""
Shodan passive recon service.

Queries the Shodan REST API for information about an IP address.
Falls back gracefully when the API key is missing or the target is a domain.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

import httpx

from app.config import settings
from app.utils.net import resolve_hostname

logger = logging.getLogger(__name__)


async def query_shodan(target: str) -> Dict[str, Any]:
    """
    Query Shodan InternetDB (free, no key required) for basic info,
    and the full /shodan/host endpoint if an API key is available.
    """
    result: Dict[str, Any] = {"target": target, "error": None, "data": {}}

    if not settings.SHODAN_API_KEY:
        logger.warning("SHODAN_API_KEY not set – using InternetDB (limited data)")

    try:
        ip = await resolve_hostname(target)
        result["resolved_ip"] = ip
    except Exception as exc:
        result["error"] = f"DNS resolution failed: {exc}"
        return result

    async with httpx.AsyncClient(timeout=15) as client:
        # --- Always try InternetDB (no key needed) ---
        try:
            resp = await client.get(f"https://internetdb.shodan.io/{ip}")
            if resp.status_code == 200:
                result["data"]["internetdb"] = resp.json()
            else:
                result["data"]["internetdb"] = {"status": resp.status_code}
        except Exception as exc:
            result["data"]["internetdb"] = {"error": str(exc)}

        # --- Full Shodan API (requires key) ---
        if settings.SHODAN_API_KEY:
            try:
                resp = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": settings.SHODAN_API_KEY},
                )
                if resp.status_code == 200:
                    raw = resp.json()
                    result["data"]["full"] = {
                        "ports": raw.get("ports", []),
                        "vulns": raw.get("vulns", []),
                        "hostnames": raw.get("hostnames", []),
                        "org": raw.get("org"),
                        "isp": raw.get("isp"),
                        "country_name": raw.get("country_name"),
                        "os": raw.get("os"),
                        "last_update": raw.get("last_update"),
                    }
                elif resp.status_code == 404:
                    result["data"]["full"] = {"message": "No information available"}
                else:
                    result["data"]["full"] = {"status": resp.status_code, "body": resp.text}
            except Exception as exc:
                result["data"]["full"] = {"error": str(exc)}

    return result
