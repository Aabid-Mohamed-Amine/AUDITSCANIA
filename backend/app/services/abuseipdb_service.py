"""
AbuseIPDB passive recon service.

Checks an IP address against the AbuseIPDB database.
For domain targets, DNS resolves asynchronously first then queries the resulting IP.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any, Dict

import httpx

from app.config import settings
from app.utils.net import resolve_hostname

logger = logging.getLogger(__name__)

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"

_INTERNAL_HOST_RE = re.compile(
    r"^(localhost|.*\.local|.*\.internal|.*\.docker|.*\.test)$", re.IGNORECASE
)


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _is_internal_hostname(host: str) -> bool:
    # Single-label hostnames (e.g. "juiceshop") are Docker/internal names
    if "." not in host:
        return True
    return bool(_INTERNAL_HOST_RE.match(host))


async def query_abuseipdb(target: str) -> Dict[str, Any]:
    """Query AbuseIPDB for abuse reports on the given IP / domain."""
    result: Dict[str, Any] = {"target": target, "error": None, "data": {}}

    if not settings.ABUSEIPDB_API_KEY:
        result["error"] = "ABUSEIPDB_API_KEY not configured"
        return result

    # Extract bare hostname from target (strip scheme/port/path)
    bare = target
    for scheme in ("https://", "http://"):
        if bare.lower().startswith(scheme):
            bare = bare[len(scheme):]
            break
    bare = bare.split("/")[0].split(":")[0]

    if _is_internal_hostname(bare):
        result["error"] = f"Skipped: internal hostname '{bare}' not in AbuseIPDB"
        return result

    try:
        ip = await resolve_hostname(target)
        result["resolved_ip"] = ip
    except Exception as exc:
        result["error"] = f"DNS resolution failed: {exc}"
        return result

    if _is_private_ip(ip):
        result["error"] = f"Skipped: private IP {ip} not in AbuseIPDB"
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
