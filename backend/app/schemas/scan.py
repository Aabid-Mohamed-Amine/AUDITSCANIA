from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator
import re


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

URL_PATTERN = re.compile(
    r"^(?:https?://)?"
    r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"
    r"localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?::\d+)?(?:/?|[/?]\S+)$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------


class ScanCreate(BaseModel):
    target: str = Field(..., min_length=1, max_length=255, description="IP address or URL to scan")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        # Accept bare IPs or URLs (with or without scheme)
        if IP_PATTERN.match(v) or URL_PATTERN.match(v):
            return v
        raise ValueError(
            "Target must be a valid IPv4 address or a valid URL / domain name"
        )


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
    shodan_data: Optional[Dict[str, Any]] = None
    virustotal_data: Optional[Dict[str, Any]] = None
    abuseipdb_data: Optional[Dict[str, Any]] = None
    nmap_data: Optional[Dict[str, Any]] = None
    nuclei_data: Optional[Dict[str, Any]] = None
    zap_data: Optional[Dict[str, Any]] = None
    ai_analysis: Optional[str] = None
    error_message: Optional[str] = None

    model_config = {"from_attributes": True}


class ScanDetailResponse(ScanResponse):
    logs: List[ScanLogEntry] = []


class ScanListResponse(BaseModel):
    total: int
    items: List[ScanResponse]


# ---------------------------------------------------------------------------
# WebSocket payload
# ---------------------------------------------------------------------------


class ScanProgress(BaseModel):
    scan_id: str
    status: str
    progress: int
    message: str
    data: Optional[Dict[str, Any]] = None
