"""
Nuclei vulnerability scanner microservice.

Accepts optional template IDs and tags derived from Nmap service discovery
to run targeted CVE checks in addition to the general scan.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel

logger = logging.getLogger("nuclei-service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="Nuclei Scanner Microservice", version="1.0.0")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target: str
    severity: str = "low,medium,high,critical"
    timeout: int = 600
    templates: Optional[List[str]] = None   # specific template / CVE IDs
    tags: Optional[List[str]] = None        # filter by nuclei tags


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _aggregate_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _slim_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    info = raw.get("info", {})
    classification = info.get("classification", {})
    return {
        "template_id": raw.get("template-id", ""),
        "name": info.get("name", ""),
        "severity": info.get("severity", "unknown"),
        "description": info.get("description", ""),
        "tags": info.get("tags", []),
        "cve_ids": classification.get("cve-id", []),
        "cwe_ids": classification.get("cwe-id", []),
        "cvss_score": classification.get("cvss-score"),        # float | None
        "cvss_metrics": classification.get("cvss-metrics", ""),
        "epss_score": classification.get("epss-score"),        # float | None
        "epss_percentile": classification.get("epss-percentile"),
        "reference": info.get("reference", []),
        "matched_at": raw.get("matched-at", ""),
        "host": raw.get("host", ""),
        "ip": raw.get("ip", ""),
        "type": raw.get("type", ""),
        "matcher_name": raw.get("matcher-name", ""),
        "timestamp": raw.get("timestamp", ""),
    }


def _build_cmd(req: ScanRequest, output_path: str) -> List[str]:
    cmd: List[str] = [
        "nuclei",
        "-u", req.target,
        "-o", output_path,
        "-json",
        "-severity", req.severity,
        "-silent",
        "-no-color",
        "-timeout", "10",
        "-rate-limit", "100",
        "-bulk-size", "25",
        "-c", "25",
        "-retries", "1",
    ]
    if req.templates:
        # Run specific CVE/template IDs first (targeted scan)
        cmd.extend(["-id", ",".join(req.templates)])
    elif req.tags:
        # Filter by service tags when no explicit IDs provided
        cmd.extend(["-tags", ",".join(req.tags)])
    return cmd


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "nuclei"}


@app.post("/scan")
async def scan(req: ScanRequest) -> Dict[str, Any]:
    logger.info(
        "Scan started — target=%s severity=%s templates=%s tags=%s",
        req.target, req.severity, req.templates, req.tags,
    )

    result: Dict[str, Any] = {
        "target": req.target,
        "findings": [],
        "total": 0,
        "by_severity": {},
        "templates_used": req.templates or [],
        "tags_used": req.tags or [],
        "error": None,
    }

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        output_path = tmp.name

    cmd = _build_cmd(req, output_path)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=req.timeout)

        if proc.returncode not in (0, 1):
            result["error"] = stderr_bytes.decode(errors="replace").strip()[:500]

    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        result["error"] = f"Nuclei scan timed out after {req.timeout}s"
        logger.warning("Scan timed out for %s", req.target)
        return result

    except Exception as exc:
        result["error"] = str(exc)
        logger.exception("Nuclei scan failed for %s", req.target)
        return result

    findings: List[Dict[str, Any]] = []
    try:
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            with open(output_path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(_slim_finding(json.loads(line)))
                        except (json.JSONDecodeError, KeyError):
                            pass
    finally:
        try:
            os.unlink(output_path)
        except Exception:
            pass

    # Sort: critical → high → medium → low
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    findings.sort(key=lambda f: _sev_order.get(f.get("severity", "unknown"), 5))

    result["findings"] = findings
    result["total"] = len(findings)
    result["by_severity"] = _aggregate_by_severity(findings)

    # Compute max CVSS for quick scoring
    cvss_scores = [f["cvss_score"] for f in findings if f.get("cvss_score")]
    result["max_cvss"] = max(cvss_scores, default=None)

    logger.info("Scan complete — target=%s findings=%d", req.target, len(findings))
    return result
