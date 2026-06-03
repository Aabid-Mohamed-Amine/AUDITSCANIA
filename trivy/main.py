"""
Trivy microservice — Supply Chain & Container Vulnerability Scanner.

POST /scan/fs     → scan filesystem ou repo git (dependencies)
POST /scan/image  → scan image Docker
GET  /health      → liveness

Usage défensif : analyse les dépendances et images pour détecter
des CVEs connues dans les librairies utilisées (supply chain security).
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="AuditScan Trivy", version="1.0.0")


class FsScanRequest(BaseModel):
    path: str = "."
    timeout: int = 180


class ImageScanRequest(BaseModel):
    image: str
    timeout: int = 180


_SEVERITY_MAP: Dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "UNKNOWN":  "info",
}


async def _run_trivy(cmd: List[str], timeout: int) -> Dict[str, Any]:
    """Exécute Trivy et parse la sortie JSON."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 15)
        raw = stdout.decode(errors="ignore").strip()
        if not raw:
            return {"Results": [], "error": stderr.decode(errors="ignore")[:500]}
        data = json.loads(raw)
        return data
    except asyncio.TimeoutError:
        return {"Results": [], "error": "trivy_timeout"}
    except json.JSONDecodeError as e:
        return {"Results": [], "error": f"json_parse_error: {e}"}
    except FileNotFoundError:
        return {"Results": [], "error": "trivy_not_found"}
    except Exception as exc:
        return {"Results": [], "error": str(exc)}


def _extract_findings(trivy_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extrait et normalise les vulnérabilités du rapport Trivy."""
    findings: List[Dict[str, Any]] = []
    results = trivy_data.get("Results") or []

    for result in results:
        target = result.get("Target", "")
        pkg_type = result.get("Type", "")
        vulns = result.get("Vulnerabilities") or []

        for vuln in vulns:
            sev = vuln.get("Severity", "UNKNOWN")
            findings.append({
                "type":              "supply_chain",
                "title":             f"{vuln.get('PkgName', 'unknown')} {vuln.get('VulnerabilityID', '')}",
                "severity":          _SEVERITY_MAP.get(sev, "info"),
                "cve_ids":           [vuln.get("VulnerabilityID", "")] if vuln.get("VulnerabilityID") else [],
                "cwe_ids":           [],
                "cvss_score":        _extract_cvss(vuln),
                "package_name":      vuln.get("PkgName", ""),
                "installed_version": vuln.get("InstalledVersion", ""),
                "fixed_version":     vuln.get("FixedVersion", ""),
                "target":            target,
                "pkg_type":          pkg_type,
                "description":       vuln.get("Description", "")[:300],
                "source":            "trivy",
                "version_end_including": vuln.get("InstalledVersion"),
            })

    return findings


def _extract_cvss(vuln: Dict[str, Any]) -> Optional[float]:
    for source_name in ["nvd", "ghsa", "redhat"]:
        cvss = vuln.get("CVSS", {}).get(source_name, {})
        score = cvss.get("V3Score") or cvss.get("V2Score")
        if score:
            return float(score)
    return None


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "trivy"})


@app.post("/scan/fs")
async def scan_fs(req: FsScanRequest) -> JSONResponse:
    start = time.time()
    cmd = [
        "trivy", "fs",
        "--format", "json",
        "--quiet",
        "--timeout", f"{req.timeout}s",
        req.path,
    ]
    data = await _run_trivy(cmd, req.timeout)
    findings = _extract_findings(data)
    elapsed = round(time.time() - start, 2)

    by_severity: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return JSONResponse({
        "scan_type":       "filesystem",
        "path":            req.path,
        "findings":        findings,
        "total":           len(findings),
        "by_severity":     by_severity,
        "elapsed_seconds": elapsed,
        "error":           data.get("error"),
    })


@app.post("/scan/image")
async def scan_image(req: ImageScanRequest) -> JSONResponse:
    start = time.time()
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--quiet",
        "--timeout", f"{req.timeout}s",
        req.image,
    ]
    data = await _run_trivy(cmd, req.timeout)
    findings = _extract_findings(data)
    elapsed = round(time.time() - start, 2)

    by_severity: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return JSONResponse({
        "scan_type":       "image",
        "image":           req.image,
        "findings":        findings,
        "total":           len(findings),
        "by_severity":     by_severity,
        "elapsed_seconds": elapsed,
        "error":           data.get("error"),
    })


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=9005, log_level="info")
