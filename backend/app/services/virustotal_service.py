"""
VirusTotal passive recon service.

Uses the public v3 API to check IPs and URLs/domains.
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Dict

import httpx

from app.config import settings
from app.utils.net import is_ip, extract_hostname

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"


def _url_id(url: str) -> str:
    """VirusTotal URL identifier: base64url(url) without padding."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


def _extract_stats(attributes: Dict[str, Any]) -> Dict[str, Any]:
    stats = attributes.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "timeout": stats.get("timeout", 0),
        "reputation": attributes.get("reputation", 0),
        "tags": attributes.get("tags", []),
        "country": attributes.get("country"),
        "as_owner": attributes.get("as_owner"),
        "network": attributes.get("network"),
    }


async def query_virustotal(target: str) -> Dict[str, Any]:
    """Query VirusTotal for the given IP / URL / domain."""
    result: Dict[str, Any] = {"target": target, "error": None, "data": {}}

    if not settings.VIRUSTOTAL_API_KEY:
        result["error"] = "VIRUSTOTAL_API_KEY not configured"
        return result

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

    async with httpx.AsyncClient(timeout=20, headers=headers) as client:
        if is_ip(target):
            # ---- IP address lookup ----
            try:
                resp = await client.get(f"{VT_BASE}/ip_addresses/{target}")
                if resp.status_code == 200:
                    attrs = resp.json().get("data", {}).get("attributes", {})
                    result["data"] = _extract_stats(attrs)
                    result["data"]["type"] = "ip"
                else:
                    result["error"] = f"VT API status {resp.status_code}"
            except Exception as exc:
                result["error"] = str(exc)
        else:
            # ---- URL / domain lookup ----
            hostname = extract_hostname(target)

            # Domain report
            try:
                resp = await client.get(f"{VT_BASE}/domains/{hostname}")
                if resp.status_code == 200:
                    attrs = resp.json().get("data", {}).get("attributes", {})
                    result["data"]["domain"] = _extract_stats(attrs)
                    result["data"]["domain"]["type"] = "domain"
                else:
                    result["data"]["domain"] = {"status": resp.status_code}
            except Exception as exc:
                result["data"]["domain"] = {"error": str(exc)}

            # URL report
            url_for_vt = target if target.startswith("http") else f"https://{target}"
            try:
                resp = await client.get(f"{VT_BASE}/urls/{_url_id(url_for_vt)}")
                if resp.status_code == 200:
                    attrs = resp.json().get("data", {}).get("attributes", {})
                    result["data"]["url"] = _extract_stats(attrs)
                    result["data"]["url"]["type"] = "url"
                else:
                    result["data"]["url"] = {"status": resp.status_code}
            except Exception as exc:
                result["data"]["url"] = {"error": str(exc)}

    return result
