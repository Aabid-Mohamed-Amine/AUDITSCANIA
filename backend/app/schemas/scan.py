from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Target validation helpers
# ---------------------------------------------------------------------------

# One DNS label: starts/ends with alnum, can contain hyphens in the middle.
# Max 63 chars per label (RFC 1035). Accepts single-word Docker hostnames.
_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$")


def _is_valid_target(v: str) -> bool:
    """
    Accept:
      - IPv4                    192.168.1.1
      - IPv4:port               192.168.1.1:8080
      - domain                  example.com
      - domain:port             example.com:3000
      - http(s)://...           http://example.com/path?q=1
      - Docker DNS hostname     myapp  internal-svc  backend
      - localhost[:port]        localhost:3000
    Reject: empty, non-http schemes, invalid ports, malformed hosts.
    """
    if not v:
        return False

    rest = v

    # ── Scheme ────────────────────────────────────────────────────────────────
    if "://" in rest:
        scheme, rest = rest.split("://", 1)
        if scheme.lower() not in ("http", "https"):
            return False

    # ── Strip path + query ────────────────────────────────────────────────────
    rest = rest.split("/")[0].split("?")[0].split("#")[0]

    # ── Port ─────────────────────────────────────────────────────────────────
    # Split on last colon only (IPv6 not in scope; IPv4 can have one colon)
    host = rest
    if rest.count(":") == 1:
        host, port_str = rest.rsplit(":", 1)
        if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
            return False

    if not host:
        return False

    # ── IPv4 ─────────────────────────────────────────────────────────────────
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        parts = host.split(".")
        try:
            return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    # ── Hostname / domain / Docker DNS ───────────────────────────────────────
    # Split on dots; each label must match _LABEL_RE.
    # Single-word hostnames (no dots) are valid Docker service names.
    labels = host.split(".")
    return bool(labels) and all(_LABEL_RE.match(lbl) for lbl in labels if lbl)


def _normalize_target(v: str) -> str:
    """
    Normalize a raw target string:
      - strip whitespace
      - add http:// if no scheme and target is not a bare IPv4
    Bare IPv4 addresses (8.8.8.8 or 8.8.8.8:80) keep no scheme so Nmap and
    other network tools can use them directly.
    """
    v = v.strip()
    if not v:
        return v

    # Already has a scheme → return as-is
    if v.lower().startswith(("http://", "https://")):
        return v

    # Bare IPv4 (with or without port) → no scheme added
    bare_host = v.split(":")[0]
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", bare_host):
        try:
            if all(0 <= int(p) <= 255 for p in bare_host.split(".")):
                return v
        except ValueError:
            pass

    # Domain / Docker hostname / URL without scheme → add http://
    return f"http://{v}"


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------


class AuthCredentialsSchema(BaseModel):
    """
    Credentials optionnels pour l'authentification automatique.
    Priorité : token > cookie > username+password.
    Non stockés en DB — passés uniquement au worker Celery.
    """
    username:      Optional[str] = Field(None, description="Login username or email")
    password:      Optional[str] = Field(None, description="Login password")
    token:         Optional[str] = Field(None, description="Pre-obtained JWT or API key")
    cookie:        Optional[str] = Field(None, description="Raw cookie string (name=value; ...)")
    login_url:     Optional[str] = Field(None, description="Override auto-detected login URL")
    header_name:   str           = Field("Authorization", description="Header name for token injection")
    header_prefix: str           = Field("Bearer", description="Token prefix (Bearer, Token, etc.)")


class ScanCreate(BaseModel):
    target:      str                              = Field(..., min_length=1, max_length=255, description="IP, domain, URL, or Docker hostname to scan")
    credentials: Optional[AuthCredentialsSchema] = Field(None, description="Optional auth credentials for authenticated scanning")
    lab_mode:    bool                             = Field(True, description="Use Lab Challenge API hints (true=current behaviour). Set false for pure active detection.")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        normalized = _normalize_target(v)
        if not _is_valid_target(normalized):
            raise ValueError(
                "Invalid target. Accepted: IPv4, IPv4:port, domain, domain:port, "
                "http(s)://..., Docker hostname (myapp, internal-svc, localhost:3000)"
            )
        return normalized


# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------


class ScanLogEntry(BaseModel):
    id: uuid.UUID
    level: str
    message: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    id: uuid.UUID
    target: str
    status: str
    progress: int
    risk_score: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    # Raw scanner outputs
    shodan_data: Optional[Dict[str, Any]] = None
    virustotal_data: Optional[Dict[str, Any]] = None
    abuseipdb_data: Optional[Dict[str, Any]] = None
    nmap_data: Optional[Dict[str, Any]] = None
    nuclei_data: Optional[Dict[str, Any]] = None
    zap_data: Optional[Dict[str, Any]] = None
    ai_analysis: Optional[str] = None
    error_message: Optional[str] = None
    # Correlation Engine + SOC output
    correlated_data: Optional[Dict[str, Any]] = None
    soc_report: Optional[Dict[str, Any]] = None
    current_phase: Optional[str] = None
    # v2 enhanced scanner outputs
    subfinder_data: Optional[Dict[str, Any]] = None
    dalfox_data: Optional[Dict[str, Any]] = None
    fp_reduction_data: Optional[Dict[str, Any]] = None
    # v3 new scanners (Phase 3)
    ffuf_data: Optional[Dict[str, Any]] = None
    sqlmap_data: Optional[Dict[str, Any]] = None
    gitleaks_data: Optional[Dict[str, Any]] = None
    katana_data: Optional[Dict[str, Any]] = None
    ai_analysis_data: Optional[Dict[str, Any]] = None
    # Auth detection result (Phase 1.5)
    auth_config: Optional[Dict[str, Any]] = None
    # Detection mode
    lab_mode: bool = True

    model_config = {"from_attributes": True}


class ScanDetailResponse(ScanResponse):
    logs: List[ScanLogEntry] = []


class ScanSummary(BaseModel):
    """
    Vue allégée pour la LISTE des scans — sans les gros blobs JSON
    (nmap_data, zap_data, soc_report…). Évite de renvoyer des centaines de Mo
    quand on liste 50-100 scans. Le détail complet reste sur GET /scans/{id}.
    """
    id: uuid.UUID
    target: str
    status: str
    progress: int
    risk_score: Optional[int] = None
    current_phase: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    total: int
    items: List[ScanSummary]


# ---------------------------------------------------------------------------
# WebSocket payload
# ---------------------------------------------------------------------------


class ScanProgress(BaseModel):
    scan_id: str
    status: str
    progress: int
    message: str
    data: Optional[Dict[str, Any]] = None
