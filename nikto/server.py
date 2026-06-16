"""
Nikto web server scanner microservice.

POST /scan   → scan the target with Nikto (JSON output)
GET  /health → liveness check

Command:
  nikto -h {host} -Format json -maxtime {timeout} -nointeractive -ask no [-ssl]

Parsing:
  Supports both single-object and JSON-Lines output formats from Nikto.
  Severity is inferred from message keywords and OSVDB presence.
"""
from __future__ import annotations

import asyncio
import json
import os
import logging
import re
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="AuditScan Nikto Scanner", version="1.0.0")


# ── DNS resolution ────────────────────────────────────────────────────────────


def _resolve_target(target_url: str):
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if target_url.startswith("https://") else 80)
    try:
        ip = socket.getaddrinfo(hostname, port)[0][4][0]
        logger.info("[DNS] %s → %s", hostname, ip)
        return target_url.replace(hostname, ip), hostname, ip, port
    except Exception as e:
        logger.warning("[DNS] échec: %s", e)
        return target_url, hostname, hostname, port


# ── Severity inference from Nikto message text ────────────────────────────────

_SEV_CRITICAL = [
    "backdoor", "shell", "remote code execution", "rce",
    "command injection", "arbitrary command",
]
_SEV_HIGH = [
    "vulnerable", "outdated version", "bypass", "xss", "cross-site scripting",
    "sql injection", "sqli", "csrf", "directory traversal", "path traversal",
    "file inclusion", "local file inclusion", "remote file inclusion",
    "authentication bypass", "privilege escalation",
]
_SEV_MEDIUM = [
    "disclosure", "exposed", "sensitive", "leak", "default password",
    "default credential", "misconfigured", "config file", "debug",
    "admin interface", "backup file", "information disclosure",
    "server version", "internal ip",
]


def _infer_severity(msg: str, osvdb: str) -> str:
    lower = msg.lower()
    if any(k in lower for k in _SEV_CRITICAL):
        return "critical"
    if any(k in lower for k in _SEV_HIGH):
        return "high"
    if any(k in lower for k in _SEV_MEDIUM):
        return "medium"
    if osvdb and osvdb not in ("0", "", "None"):
        return "medium"
    return "low"


# ── Nikto JSON output parser ──────────────────────────────────────────────────


def _vuln_to_finding(v: Dict[str, Any], target: str) -> Dict[str, Any]:
    msg  = v.get("msg") or v.get("message") or v.get("description") or ""
    osvdb = str(v.get("OSVDB") or v.get("osvdb") or "")
    return {
        "title":       msg[:200] or "Nikto finding",
        "severity":    _infer_severity(msg, osvdb),
        "url":         v.get("url") or v.get("uri") or target,
        "method":      (v.get("method") or "GET").upper(),
        "osvdb":       osvdb,
        "nikto_id":    str(v.get("id") or ""),
        "description": msg,
        "source":      "nikto",
    }


def _parse_output(raw: str, target: str) -> List[Dict[str, Any]]:
    """
    Handles three Nikto JSON formats:
      1. Single JSON object with 'vulnerabilities' or 'findings' key
      2. JSON array of vulnerability objects
      3. JSON Lines (one JSON object per line)
    """
    findings: List[Dict[str, Any]] = []
    raw = raw.strip()
    if not raw:
        return findings

    # ── Try single JSON object / array ───────────────────────────────────────
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            vulns = (
                data.get("vulnerabilities")
                or data.get("findings")
                or data.get("results")
                or []
            )
            for v in vulns:
                if isinstance(v, dict):
                    findings.append(_vuln_to_finding(v, target))
        elif isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                if item.get("msg") or item.get("message"):
                    findings.append(_vuln_to_finding(item, target))
                    continue
                # Nikto -output writes a list with one wrapper object per host (containing
                # vulnerabilities/findings/results), not a flat list of findings. Unwrap it.
                wrapped_vulns = (
                    item.get("vulnerabilities")
                    or item.get("findings")
                    or item.get("results")
                    or []
                )
                for v in wrapped_vulns:
                    if isinstance(v, dict):
                        findings.append(_vuln_to_finding(v, target))
        return findings
    except (json.JSONDecodeError, ValueError):
        pass

    # ── Try JSON Lines ────────────────────────────────────────────────────────
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict) and (item.get("msg") or item.get("message")):
                findings.append(_vuln_to_finding(item, target))
        except (json.JSONDecodeError, ValueError):
            continue

    return findings


# ── Pydantic models ───────────────────────────────────────────────────────────


class ScanRequest(BaseModel):
    target:  str
    timeout: int = 120


# ── Routes ────────────────────────────────────────────────────────────────────


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "nikto"}


@app.post("/scan")
async def scan(req: ScanRequest) -> Dict[str, Any]:
    target  = req.target.strip()
    timeout = max(30, min(req.timeout, 300))

    ssl_flag: List[str] = ["-ssl"] if target.startswith("https://") else []

    _, hostname, ip, port = _resolve_target(target)

    import uuid as _uuid
    _output_path = f"/tmp/nikto_{_uuid.uuid4().hex[:10]}.json"
    cmd: List[str] = [
        "nikto",
        "-h", ip,
        "-p", str(port),
        "-Format", "json",
        "-output", _output_path,
        "-maxtime", str(timeout),
        "-C", "all",
        "-nointeractive",
        "-ask", "no",
        *ssl_flag,
    ]

    logger.info("[Nikto] scan start: %s → %s:%d (timeout=%ds)", hostname, ip, port, timeout)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=float(timeout + 30)
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.warning("[Nikto] timeout for %s", hostname)
            return {
                "target": target,
                "error":  f"Nikto timed out after {timeout}s",
                "findings": [], "total": 0, "by_severity": {},
            }

        raw        = stdout.decode(errors="ignore").strip()
        stderr_txt = stderr.decode(errors="ignore").strip()

        # -Format json without -output prints human-readable text to stdout,
        # not JSON. The real structured JSON is only written to -output's file.
        try:
            if os.path.exists(_output_path):
                _file_content = open(_output_path, errors="ignore").read().strip()
                if _file_content:
                    raw = _file_content
        except Exception:
            pass
        finally:
            try:
                os.remove(_output_path)
            except Exception:
                pass

        # Nikto returns exit code 0 on success and may return non-zero on error
        if proc.returncode not in (0, 1) and not raw:
            err = f"Nikto exited {proc.returncode}: {stderr_txt[:300]}"
            logger.warning("[Nikto] %s", err)
            return {
                "target": target, "error": err,
                "findings": [], "total": 0, "by_severity": {},
            }

        findings = _parse_output(raw, target)

        by_severity: Dict[str, int] = {}
        for f in findings:
            sev = f["severity"]
            by_severity[sev] = by_severity.get(sev, 0) + 1

        logger.info("[Nikto] scan complete: %s — %d finding(s)", hostname, len(findings))
        return {
            "target":      target,
            "error":       None,
            "findings":    findings,
            "total":       len(findings),
            "by_severity": by_severity,
        }

    except FileNotFoundError:
        logger.error("[Nikto] binary not found in PATH")
        return {
            "target": target,
            "error":  "nikto binary not found — is nikto installed in the container?",
            "findings": [], "total": 0, "by_severity": {},
        }
    except Exception as exc:
        logger.exception("[Nikto] unexpected error for %s", target)
        return {
            "target": target, "error": str(exc),
            "findings": [], "total": 0, "by_severity": {},
        }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9010)
