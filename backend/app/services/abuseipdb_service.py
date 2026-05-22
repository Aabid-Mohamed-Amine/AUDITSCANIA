"""
AbuseIPDB passive recon service.

Checks an IP address against the AbuseIPDB database.
For domain targets, DNS resolves asynchronously first then queries the resulting IP.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

import httpx

from app.config import settings
from app.utils.net import resolve_hostname

logger = logging.getLogger(__name__)

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


async def query_abuseipdb(target: str) -> Dict[str, Any]:
    """Query AbuseIPDB for abuse reports on the given IP / domain."""
    result: Dict[str, Any] = {"target": target, "error": None, "data": {}}

    if not settings.ABUSEIPDB_API_KEY:
        result["error"] = "ABUSEIPDB_API_KEY not configured"
        return result

    try:
        ip = await resolve_hostname(target)
        result["resolved_ip"] = ip
    except Exception as exc:
        result["error"] = f"DNS resolution failed: {exc}"
        return result

    headers = {
        "Key": settings.ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(timeout=15, headers=headers) as client:
        try:
            resp = await client.get(
                f"{ABUSEIPDB_BASE}/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            )
            if resp.status_code == 200:
                raw = resp.json().get("data", {})
                result["data"] = {
                    "ip_address": raw.get("ipAddress"),
                    "is_public": raw.get("isPublic"),
                    "ip_version": raw.get("ipVersion"),
                    "is_whitelisted": raw.get("isWhitelisted"),
                    "abuse_confidence_score": raw.get("abuseConfidenceScore"),
                    "country_code": raw.get("countryCode"),
                    "usage_type": raw.get("usageType"),
                    "isp": raw.get("isp"),
                    "domain": raw.get("domain"),
                    "hostnames": raw.get("hostnames", []),
                    "total_reports": raw.get("totalReports"),
                    "num_distinct_users": raw.get("numDistinctUsers"),
                    "last_reported_at": raw.get("lastReportedAt"),
                    "recent_reports": raw.get("reports", [])[:5],
                }
            else:
                result["error"] = f"AbuseIPDB API status {resp.status_code}: {resp.text}"
        except Exception as exc:
            result["error"] = str(exc)

    return result
