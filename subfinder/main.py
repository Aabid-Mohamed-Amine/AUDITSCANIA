"""
Subfinder + httpx microservice — Asset Discovery.

POST /discover  → subdomain enumeration + HTTP probing
GET  /health    → liveness check

Défensif uniquement : passive subdomain enumeration (sources publiques),
puis httpx pour vérifier quels sous-domaines répondent.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import subprocess
import time
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="AuditScan Subfinder+httpx", version="1.0.0")


class DiscoverRequest(BaseModel):
    target: str
    timeout: int = 120
    passive_only: bool = True

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip().lower()
        # Accepte domaines seulement (pas d'IPs — subfinder n'a de sens que pour des domaines)
        pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        # Si IP → on skip subfinder, on fait juste httpx
        return v


async def _run_subfinder(domain: str, timeout: int) -> List[str]:
    """Enumère les sous-domaines passivamente via sources publiques."""
    cmd = [
        "subfinder",
        "-d", domain,
        "-silent",
        "-json",
        "-timeout", str(min(timeout, 90)),
        "-sources", "crtsh,hackertarget,urlscan,certspotter",  # sources passives légales
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 10)
        subdomains: List[str] = []
        for line in stdout.decode(errors="ignore").strip().splitlines():
            try:
                data = json.loads(line)
                host = data.get("host") or data.get("subdomain", "")
                if host:
                    subdomains.append(host)
            except json.JSONDecodeError:
                if line.strip():
                    subdomains.append(line.strip())
        return list(set(subdomains))
    except asyncio.TimeoutError:
        logger.warning("Subfinder timeout for %s", domain)
        return []
    except FileNotFoundError:
        logger.error("subfinder binary not found")
        return []
    except Exception as exc:
        logger.error("Subfinder error: %s", exc)
        return []


async def _run_httpx(targets: List[str], timeout: int) -> List[Dict[str, Any]]:
    """Probe les cibles avec httpx pour vérifier lesquelles répondent."""
    if not targets:
        return []

    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        tmpfile = f.name

    cmd = [
        "httpx",
        "-l", tmpfile,
        "-json",
        "-silent",
        "-follow-redirects",
        "-timeout", str(min(timeout, 30)),
        "-status-code",
        "-title",
        "-tech-detect",
        "-server",
        "-content-length",
        "-no-color",
    ]

    results: List[Dict[str, Any]] = []
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 10)
        for line in stdout.decode(errors="ignore").strip().splitlines():
            try:
                data = json.loads(line)
                results.append({
                    "url":            data.get("url", ""),
                    "host":           data.get("host", ""),
                    "status_code":    data.get("status-code") or data.get("status_code"),
                    "title":          data.get("title", ""),
                    "server":         data.get("server", ""),
                    "technologies":   data.get("tech") or data.get("technologies") or [],
                    "content_length": data.get("content-length") or data.get("content_length"),
                    "scheme":         data.get("scheme", "https"),
                })
            except json.JSONDecodeError:
                pass
    except asyncio.TimeoutError:
        logger.warning("httpx timeout")
    except FileNotFoundError:
        logger.error("httpx binary not found")
    except Exception as exc:
        logger.error("httpx error: %s", exc)
    finally:
        try:
            os.unlink(tmpfile)
        except Exception:
            pass

    return results


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "subfinder-httpx"})


@app.post("/discover")
async def discover(req: DiscoverRequest) -> JSONResponse:
    start = time.time()
    target = req.target

    # Détection IP vs domaine
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))

    subdomains: List[str] = []
    if not is_ip:
        logger.info("Running subfinder on %s", target)
        subdomains = await _run_subfinder(target, timeout=req.timeout // 2)
        logger.info("Subfinder found %d subdomains for %s", len(subdomains), target)

    # httpx probe : cible principale + sous-domaines
    probe_targets = [target] + subdomains
    logger.info("Running httpx on %d targets", len(probe_targets))
    http_results = await _run_httpx(probe_targets, timeout=req.timeout // 2)

    elapsed = round(time.time() - start, 2)

    # Extraire les technologies uniques
    all_techs: List[str] = []
    for r in http_results:
        techs = r.get("technologies") or []
        if isinstance(techs, list):
            all_techs.extend(techs)
        elif isinstance(techs, str):
            all_techs.append(techs)

    live_hosts = [r["url"] for r in http_results if r.get("status_code")]

    return JSONResponse({
        "target":         target,
        "is_ip":          is_ip,
        "subdomains":     subdomains,
        "subdomains_count": len(subdomains),
        "http_probes":    http_results,
        "live_hosts":     live_hosts,
        "live_count":     len(live_hosts),
        "technologies":   list(set(all_techs)),
        "elapsed_seconds": elapsed,
        "error":          None,
    })


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=9003, log_level="info")
