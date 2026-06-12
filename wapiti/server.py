"""
Wapiti web application auditor microservice — v2.0.0
=====================================================
Fix v2 :
  - --max-depth → -d  (Wapiti 3.x)
  - --max-links-per-page → --max-links-per-page (OK)
  - --timeout → -t  (Wapiti 3.x)
  - --max-scan-time ajouté pour borner le scan global
  - stderr loggué pour détecter les erreurs silencieuses
  - Wapiti 3.3.0 compatible
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="AuditScan Wapiti Auditor", version="2.0.0")


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

# ── Severity helpers ──────────────────────────────────────────────────────────

_CAT_CRITICAL = {
    "SQL Injection", "Blind SQL Injection", "Command Execution",
    "XXE", "XML External Entity",
}
_CAT_HIGH = {
    "Cross Site Scripting", "Reflected Cross Site Scripting",
    "Stored Cross Site Scripting", "Path Traversal", "File Handling",
    "Server Side Request Forgery", "SSRF", "LDAP Injection",
    "XPath Injection", "Shellshock", "Log4Shell",
}
_CAT_MEDIUM = {
    "CRLF Injection", "Open Redirect", "Htaccess Bypass",
    "Backup file", "Potentially dangerous file", "HTTP Response Splitting",
    "Cross Site Request Forgery", "CSRF", "Wapp",
    "Nikto", "Content Security Policy Configuration",
}

_LEVEL_TO_SEV = {1: "critical", 2: "high", 3: "medium"}


def _severity(category: str, level: Any) -> str:
    cat = category.strip()
    if cat in _CAT_CRITICAL:
        return "critical"
    if cat in _CAT_HIGH:
        return "high"
    if cat in _CAT_MEDIUM:
        return "medium"
    try:
        return _LEVEL_TO_SEV.get(int(level), "low")
    except (TypeError, ValueError):
        return "low"


# ── JSON report parser ────────────────────────────────────────────────────────


def _parse_report(report_path: str, target: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    try:
        with open(report_path, encoding="utf-8", errors="ignore") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("[Wapiti] cannot read report %s: %s", report_path, exc)
        return findings

    def _normalise_base(base_url: str) -> str:
        return base_url.rstrip("/")

    base = _normalise_base(target)

    for section in ("vulnerabilities", "anomalies"):
        section_data = data.get(section, {})
        if not isinstance(section_data, dict):
            continue
        for category, items in section_data.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                path      = item.get("path") or item.get("url") or ""
                method    = (item.get("method") or "GET").upper()
                info      = item.get("info") or item.get("description") or ""
                level     = item.get("level", 0)
                parameter = item.get("parameter") or ""
                module    = item.get("module") or category

                if path.startswith(("http://", "https://")):
                    full_url = path
                else:
                    full_url = f"{base}{path}" if path.startswith("/") else f"{base}/{path}"

                title = f"{category}: {info[:120]}" if info else category

                findings.append({
                    "title":       title,
                    "severity":    _severity(category, level),
                    "category":    category,
                    "url":         full_url,
                    "method":      method,
                    "parameter":   parameter,
                    "description": info,
                    "module":      module,
                    "level":       level,
                    "source":      "wapiti",
                })

    return findings


# ── Pydantic model ────────────────────────────────────────────────────────────


class ScanRequest(BaseModel):
    target:  str
    timeout: int = 120


# ── Routes ────────────────────────────────────────────────────────────────────


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "wapiti", "version": "2.0.0"}


@app.post("/scan")
async def scan(req: ScanRequest) -> Dict[str, Any]:
    target  = req.target.strip()
    timeout = max(30, min(req.timeout, 300))

    report_path  = f"/tmp/wapiti_{uuid.uuid4().hex}.json"

    resolved_url, original_hostname, ip, port = _resolve_target(target)

    # ── Wapiti 3.3.0 — options correctes ─────────────────────────────────────
    # --max-depth    → -d
    # --timeout      → -t
    # --max-scan-time → borne le scan global
    cmd: List[str] = [
        "wapiti",
        "-u",    resolved_url,
        "--header", f"Host: {original_hostname}",
        "-d",    "2",
        "-t",    "15",
        "--max-links-per-page", "30",
        "--max-scan-time", str(timeout),
        "--no-bugreport",
        "--flush-session",
        "-f",    "json",
        "-o",    report_path,
    ]

    logger.info(
        "[Wapiti] scan start: %s → %s (host=%s, timeout=%ds, report=%s)",
        target, resolved_url, original_hostname, timeout, report_path,
    )
    logger.info("[Wapiti] cmd: %s", " ".join(cmd))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=float(timeout + 60)
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.warning("[Wapiti] timeout for %s", target)
            findings    = _parse_report(report_path, target) if os.path.exists(report_path) else []
            by_severity = _count_by_sev(findings)
            _cleanup(report_path)
            return {
                "target":      target,
                "error":       f"Wapiti timed out after {timeout}s (partial: {len(findings)} findings)",
                "findings":    findings,
                "total":       len(findings),
                "by_severity": by_severity,
            }

        # Logger stderr pour debug
        stderr_txt = stderr.decode(errors="ignore").strip()
        stdout_txt = stdout.decode(errors="ignore").strip()
        if stderr_txt:
            logger.info("[Wapiti] stderr: %s", stderr_txt[:500])
        if stdout_txt:
            logger.info("[Wapiti] stdout: %s", stdout_txt[:200])

        logger.info("[Wapiti] exit code: %d", proc.returncode or 0)

        # Wapiti 3.x retourne 0 ou 2 selon les findings
        if proc.returncode not in (0, 1, 2) and not os.path.exists(report_path):
            err = f"Wapiti exited {proc.returncode}: {stderr_txt[:300]}"
            logger.warning("[Wapiti] %s", err)
            return {
                "target": target, "error": err,
                "findings": [], "total": 0, "by_severity": {},
            }

        findings    = _parse_report(report_path, target)
        by_severity = _count_by_sev(findings)
        _cleanup(report_path)

        logger.info(
            "[Wapiti] scan complete: %s — %d finding(s) %s",
            target, len(findings), by_severity,
        )
        return {
            "target":      target,
            "error":       None,
            "findings":    findings,
            "total":       len(findings),
            "by_severity": by_severity,
        }

    except FileNotFoundError:
        logger.error("[Wapiti] binary not found in PATH")
        return {
            "target": target,
            "error":  "wapiti binary not found — is wapiti installed?",
            "findings": [], "total": 0, "by_severity": {},
        }
    except Exception as exc:
        logger.exception("[Wapiti] unexpected error for %s", target)
        _cleanup(report_path)
        return {
            "target": target, "error": str(exc),
            "findings": [], "total": 0, "by_severity": {},
        }


# ── Helpers ───────────────────────────────────────────────────────────────────


def _count_by_sev(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        sev = f["severity"]
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _cleanup(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9011)