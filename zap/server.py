"""
OWASP ZAP web application scanner microservice.

Uses zap-baseline.py (bundled in the official ZAP Docker image) to run a
passive + light-active web scan.  Exposes a simple HTTP API consumed by the
AuditScan backend worker.

ZAP baseline exit codes:
  0 = no alerts found
  1 = only Warning-level alerts  (not a failure)
  2 = Fail-level alerts found    (not a failure — findings reported)
  3 = ERROR (scan could not run)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI
from pydantic import BaseModel

logger = logging.getLogger("zap-service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="OWASP ZAP Scanner Microservice", version="1.0.0")

ZAP_BASELINE = "/zap/zap-baseline.py"

RISK_LABELS = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Informational"}

# Security headers whose absence is flagged as an abnormal finding
_SECURITY_HEADER_KEYWORDS = {
    "x-frame-options",
    "x-content-type-options",
    "content security policy",
    "strict-transport-security",
    "permissions policy",
    "referrer policy",
    "x-powered-by",
    "server leaks",
    "server header",
    "x-debug-token",
    "cross-domain",
    "access-control",
}


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target: str
    spider_minutes: int = 2
    timeout: int = 900  # 15 minutes max


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"http://{target}"
    return target


def _extract_alerts(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten the ZAP JSON report into a list of alert dicts."""
    alerts: List[Dict[str, Any]] = []
    for site in report.get("site", []):
        for raw in site.get("alerts", []):
            risk_code = int(raw.get("riskcode", 0))
            instances_raw = raw.get("instances", [])
            alerts.append({
                "name": raw.get("name", raw.get("alert", "")),
                "risk": RISK_LABELS.get(risk_code, "Unknown"),
                "risk_code": risk_code,
                "confidence": raw.get("confidence", ""),
                "description": (raw.get("desc", "") or "").strip(),
                "solution": (raw.get("solution", "") or "").strip(),
                "reference": (raw.get("reference", "") or "").strip(),
                "cwe_id": raw.get("cweid", ""),
                "wasc_id": raw.get("wascid", ""),
                "plugin_id": raw.get("pluginid", ""),
                "count": int(raw.get("count", len(instances_raw))),
                "instances": [
                    {
                        "uri": i.get("uri", ""),
                        "method": i.get("method", "GET"),
                        "param": i.get("param", ""),
                        "evidence": (i.get("evidence", "") or "")[:200],
                    }
                    for i in instances_raw[:5]
                ],
            })
    return sorted(alerts, key=lambda a: a["risk_code"], reverse=True)


def _aggregate_by_risk(alerts: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for a in alerts:
        counts[a["risk"]] = counts.get(a["risk"], 0) + 1
    return counts


def _extract_endpoints(alerts: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Collect unique URLs discovered from alert instances."""
    seen: set = set()
    endpoints: List[Dict[str, str]] = []
    for alert in alerts:
        for inst in alert.get("instances", []):
            uri = inst.get("uri", "").strip()
            if uri and uri not in seen:
                seen.add(uri)
                parsed = urlparse(uri)
                endpoints.append({
                    "url": uri,
                    "method": inst.get("method", "GET"),
                    "path": parsed.path,
                    "port": str(parsed.port or ""),
                })
                if len(endpoints) >= 300:
                    return endpoints
    return endpoints


def _extract_form_params(alerts: List[Dict[str, Any]]) -> List[str]:
    """Collect unique form/query parameter names from alert instances."""
    params: set = set()
    for alert in alerts:
        for inst in alert.get("instances", []):
            param = inst.get("param", "").strip()
            if param:
                params.add(param)
    return sorted(params)


def _extract_abnormal_headers(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flag missing security headers or leaking server-version headers."""
    issues: List[Dict[str, Any]] = []
    seen: set = set()
    for alert in alerts:
        name: str = alert.get("name", "").lower()
        for kw in _SECURITY_HEADER_KEYWORDS:
            if kw in name and name not in seen:
                seen.add(name)
                issues.append({
                    "header_issue": alert.get("name", ""),
                    "risk": alert.get("risk", "Informational"),
                    "count": alert.get("count", 0),
                    "cwe_id": alert.get("cwe_id", ""),
                })
                break
    return issues


def _extract_ports_from_endpoints(endpoints: List[Dict[str, str]]) -> List[int]:
    """Return non-standard TCP ports found in discovered endpoint URLs."""
    ports: set = set()
    standard = {80, 443, 8080, 8443}
    for ep in endpoints:
        port_str = ep.get("port", "")
        if port_str:
            try:
                p = int(port_str)
                if p not in standard and 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass
    return sorted(ports)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "zap"}


@app.post("/scan")
async def scan(req: ScanRequest) -> Dict[str, Any]:
    target_url = _normalize_url(req.target)
    logger.info("ZAP baseline scan started — target=%s", target_url)

    result: Dict[str, Any] = {
        "target": target_url,
        "alerts": [],
        "total": 0,
        "by_risk": {},
        "endpoints": [],
        "form_params": [],
        "abnormal_headers": [],
        "implicit_ports": [],
        "error": None,
    }

    report_filename = f"zap_{uuid.uuid4().hex[:12]}.json"
    report_path = f"/zap/wrk/{report_filename}"

    cmd: List[str] = [
        "python", ZAP_BASELINE,
        "-t", target_url,
        "-J", report_filename,
        "-m", str(req.spider_minutes),
        "-I",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd="/zap",
        )
        _, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=req.timeout)

        if proc.returncode == 3:
            result["error"] = stderr_bytes.decode(errors="replace").strip()[:500]
            logger.error("ZAP returned exit 3 for %s: %s", target_url, result["error"])

    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        result["error"] = f"ZAP scan timed out after {req.timeout}s"
        logger.warning("ZAP scan timed out for %s", target_url)
        return result

    except Exception as exc:
        result["error"] = str(exc)
        logger.exception("ZAP scan failed for %s", target_url)
        return result

    try:
        if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
            with open(report_path, encoding="utf-8") as fh:
                report = json.load(fh)
            alerts = _extract_alerts(report)
            endpoints = _extract_endpoints(alerts)
            result["alerts"] = alerts
            result["total"] = len(alerts)
            result["by_risk"] = _aggregate_by_risk(alerts)
            result["endpoints"] = endpoints
            result["form_params"] = _extract_form_params(alerts)
            result["abnormal_headers"] = _extract_abnormal_headers(alerts)
            result["implicit_ports"] = _extract_ports_from_endpoints(endpoints)
    except Exception as exc:
        logger.error("Failed to parse ZAP report for %s: %s", target_url, exc)
        if not result["error"]:
            result["error"] = f"Report parse error: {exc}"
    finally:
        try:
            os.unlink(report_path)
        except Exception:
            pass

    logger.info(
        "ZAP scan complete — target=%s alerts=%d endpoints=%d",
        target_url, result["total"], len(result["endpoints"]),
    )
    return result
