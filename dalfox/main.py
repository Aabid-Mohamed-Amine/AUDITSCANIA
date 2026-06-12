from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="AuditScan Dalfox XSS Scanner", version="1.0.0")

_URL_PATTERN = re.compile(
    r"^https?://[a-zA-Z0-9._\-]+(:\d+)?(/[^\s]*)?$"
)


class ScanRequest(BaseModel):
    target: str
    timeout: int = 120
    deep_mode: bool = False
    urls: Optional[List[str]] = None
    auth_headers: Optional[Dict[str, str]] = None

    @field_validator("target")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not _URL_PATTERN.match(v):
            raise ValueError("target must be a valid HTTP/HTTPS URL")
        return v


async def _run_dalfox(url: str, timeout: int, deep_mode: bool, auth_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Exécute dalfox en mode assessment défensif."""
    cmd = [
        "dalfox",
        "url", url,
        "--format", "json",
        "--silence",
        "--timeout", str(min(timeout, 300)),
        "--no-spinner",
    ]

    if not deep_mode:
        # Mode léger : uniquement détection de réflexion, pas d'exploitation
        cmd.extend(["--only-discovery"])

    if auth_headers:
        for hname, hval in auth_headers.items():
            cmd.extend(["--header", f"{hname}: {hval}"])

    findings: List[Dict[str, Any]] = []
    raw_output = ""

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 15)
        raw_output = stdout.decode(errors="ignore")

        # Dalfox peut sortir du JSON line-by-line ou en array
        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if isinstance(data, list):
                    findings.extend(data)
                elif isinstance(data, dict):
                    findings.append(data)
            except json.JSONDecodeError:
                # Ligne non-JSON → on ignore (messages de statut)
                pass

    except asyncio.TimeoutError:
        return {"error": "dalfox_timeout", "findings": [], "raw": ""}
    except FileNotFoundError:
        return {"error": "dalfox_not_found", "findings": [], "raw": ""}
    except Exception as exc:
        return {"error": str(exc), "findings": [], "raw": ""}

    return {"error": None, "findings": findings, "raw": raw_output[:2000]}


def _normalize_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise un finding dalfox vers notre format interne."""
    severity_map = {
        "G": "high",     # PoC XSS confirmed
        "R": "medium",   # Reflected parameter
        "V": "medium",   # Verified
    }
    poc_type = raw.get("type", raw.get("class", ""))
    severity = severity_map.get(poc_type, "low")

    return {
        "type":        "xss",
        "title":       f"XSS: {raw.get('param', raw.get('parameter', 'unknown parameter'))}",
        "severity":    severity,
        "url":         raw.get("url", ""),
        "parameter":   raw.get("param", raw.get("parameter", "")),
        "payload":     raw.get("payload", ""),
        "poc_type":    poc_type,
        "evidence":    raw.get("evidence", ""),
        "cwe_ids":     ["CWE-79"],
        "cve_ids":     [],
        "source":      "dalfox",
    }


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "dalfox"})


@app.post("/scan")
async def scan(req: ScanRequest) -> JSONResponse:
    start       = time.time()
    targets     = req.urls if req.urls else [req.target]
    per_timeout = max(10, req.timeout // len(targets))
    logger.info("Dalfox scan: %d URL(s) (deep=%s)", len(targets), req.deep_mode)

    all_raw:    List[Dict[str, Any]] = []
    last_error: Optional[str]        = None
    for url in targets:
        res = await _run_dalfox(url, per_timeout, req.deep_mode, req.auth_headers)
        if res.get("error"):
            last_error = res["error"]
        all_raw.extend(res.get("findings") or [])

    elapsed    = round(time.time() - start, 2)
    normalized = [_normalize_finding(f) for f in all_raw]

    by_severity: Dict[str, int] = {}
    for f in normalized:
        sev = f.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return JSONResponse({
        "target":          req.target,
        "findings":        normalized,
        "total":           len(normalized),
        "by_severity":     by_severity,
        "elapsed_seconds": elapsed,
        "error":           last_error,
    })


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=9004, log_level="info")
