"""GitLeaks â€” secrets & credential detection microservice."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
import uuid
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

logger = logging.getLogger("gitleaks-service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="GitLeaks Secrets Detection Microservice", version="1.0.0")

# Mask secret values for safe reporting
def _mask(value: str) -> str:
    if not value or len(value) < 8:
        return "***"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _severity_from_rule(rule_id: str) -> str:
    critical_rules = {"aws-access-token", "private-key", "rsa-private-key", "github-pat",
                      "stripe-secret-key", "google-api-key", "slack-webhook", "jwt"}
    high_rules = {"generic-api-key", "password-in-url", "sendgrid-api-token", "twilio-api-key"}
    rule_lower = rule_id.lower()
    if any(r in rule_lower for r in critical_rules):
        return "critical"
    if any(r in rule_lower for r in high_rules):
        return "high"
    return "medium"


class ScanRequest(BaseModel):
    target: str          # git repo URL or web URL
    timeout: int = 120


async def _scan_git_repo(target: str, work_dir: str, timeout: int) -> List[Dict]:
    """Clone and scan a git repository."""
    repo_dir = os.path.join(work_dir, "repo")
    report_file = os.path.join(work_dir, "report.json")

    # Shallow clone (faster, no history needed for surface scan)
    clone_cmd = ["git", "clone", "--depth=1", "--quiet", target, repo_dir]
    try:
        proc = await asyncio.create_subprocess_exec(
            *clone_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        await asyncio.wait_for(proc.communicate(), timeout=60)
    except Exception as exc:
        logger.warning("Git clone failed: %s", exc)
        return []

    cmd = ["gitleaks", "detect", "--source", repo_dir,
           "--report-format", "json", "--report-path", report_file,
           "--no-git", "--exit-code", "0"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout - 70)
    except Exception:
        return []

    return _load_report(report_file)


async def _scan_web_target(target: str, work_dir: str, timeout: int) -> List[Dict]:
    """Probe web target for exposed secrets (common files + .git exposure + SPA/Juice Shop)."""
    findings: List[Dict] = []

    secret_pattern = re.compile(
        r'(?i)(?:api[_-]?key|secret|password|token|bearer|private[_-]?key|access[_-]?key)'
        r'\s*[=:]\s*["\']?([A-Za-z0-9+/\-_]{16,})["\']?'
    )
    jwt_pattern = re.compile(
        r'eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}'
    )
    bcrypt_pattern = re.compile(
        r'\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}'
    )

    probe_paths = [
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/config.php", "/configuration.php", "/config.js", "/config.json",
        "/wp-config.php", "/settings.py", "/local_settings.py",
        "/.git/config", "/.git/HEAD",
        "/docker-compose.yml", "/docker-compose.yaml",
        "/Makefile", "/.travis.yml", "/.circleci/config.yml",
        "/credentials.json", "/secrets.json", "/keys.json",
        "/main.js.map", "/polyfills.js.map", "/runtime.js.map",
        "/package.json", "/package-lock.json", "/yarn.lock",
        "/.npmrc", "/.yarnrc",
        "/angular.json", "/ngsw.json",
        "/server/.env", "/api/.env", "/.env.development",
        # Juice Shop / OWASP vulnerable app specific paths
        "/encryptionkeys/",
        "/encryptionkeys/premium.key",
        "/encryptionkeys/jwt.pub",
        "/encryptionkeys/acc2020.md",
        "/encryptionkeys/coupons_2013.md.bak",
        "/api/Users",
        "/rest/admin/application-configuration",
        "/metrics",
        "/b2b/v2",
    ]

    # These paths contain cryptographic material by nature — report the file itself if accessible
    _crypto_paths = frozenset([
        "/encryptionkeys/", "/encryptionkeys/premium.key",
        "/encryptionkeys/jwt.pub", "/encryptionkeys/acc2020.md",
        "/encryptionkeys/coupons_2013.md.bak",
    ])
    _pem_markers = ("BEGIN RSA", "BEGIN PRIVATE", "BEGIN PUBLIC",
                    "BEGIN CERTIFICATE", "ssh-rsa", "-----")

    seen: set = set()

    def _dedup_add(f: dict) -> bool:
        key = (f["rule_id"], f["file"], f.get("match", "")[:40])
        if key in seen:
            return False
        seen.add(key)
        return True

    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as client:
        for path in probe_paths:
            try:
                resp = await client.get(base + path)
                if resp.status_code != 200:
                    continue
                body = resp.text
                if len(body) > 2_000_000:
                    continue

                # Crypto key files: report exposure even without a regex match
                if path in _crypto_paths and body.strip():
                    is_key = any(m in body[:512] for m in _pem_markers)
                    rule = "exposed-cryptographic-key" if is_key else "exposed-sensitive-file"
                    sev  = "critical" if is_key else "high"
                    f = {
                        "rule_id":     rule,
                        "description": f"Cryptographic material exposed at {path}",
                        "file":        base + path,
                        "secret":      _mask(body.strip()[:32]),
                        "match":       body.strip()[:100],
                        "severity":    sev,
                        "line":        0,
                    }
                    if _dedup_add(f):
                        findings.append(f)

                # Generic secret key=value pattern
                for match in secret_pattern.finditer(body):
                    raw_val = match.group(1)
                    f = {
                        "rule_id":     "exposed-secret-file",
                        "description": f"Potential secret found in {path}",
                        "file":        base + path,
                        "secret":      _mask(raw_val),
                        "match":       match.group(0)[:100],
                        "severity":    "high",
                        "line":        0,
                    }
                    if _dedup_add(f):
                        findings.append(f)

                # JWT tokens in responses
                for match in jwt_pattern.finditer(body):
                    token = match.group(0)
                    f = {
                        "rule_id":     "jwt-token-exposed",
                        "description": f"JWT token found in response from {path}",
                        "file":        base + path,
                        "secret":      _mask(token),
                        "match":       token[:100],
                        "severity":    "high",
                        "line":        0,
                    }
                    if _dedup_add(f):
                        findings.append(f)

                # Bcrypt password hashes (user database exposure)
                for match in bcrypt_pattern.finditer(body):
                    f = {
                        "rule_id":     "bcrypt-hash-exposed",
                        "description": f"Bcrypt password hash found in response from {path} — possible user DB exposure",
                        "file":        base + path,
                        "secret":      match.group(0)[:20] + "...",
                        "match":       match.group(0)[:60],
                        "severity":    "critical",
                        "line":        0,
                    }
                    if _dedup_add(f):
                        findings.append(f)

            except Exception:
                pass

    return findings


def _load_report(report_file: str) -> List[Dict]:
    if not os.path.exists(report_file) or os.path.getsize(report_file) == 0:
        return []
    try:
        with open(report_file) as fh:
            data = json.load(fh)
        findings = []
        for leak in (data if isinstance(data, list) else []):
            rule_id = leak.get("RuleID", "unknown")
            findings.append({
                "rule_id": rule_id,
                "description": leak.get("Description", ""),
                "file": leak.get("File", ""),
                "secret": _mask(leak.get("Secret", "")),
                "match": leak.get("Match", "")[:100],
                "severity": _severity_from_rule(rule_id),
                "line": leak.get("StartLine", 0),
                "author": leak.get("Author", ""),
                "commit": (leak.get("Commit", "") or "")[:12],
            })
        return findings
    except Exception:
        return []


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "gitleaks"}


@app.post("/scan")
async def scan(req: ScanRequest) -> Dict[str, Any]:
    target = req.target.strip()
    logger.info("GitLeaks scan started â€” target=%s", target)

    result: Dict[str, Any] = {
        "target": target,
        "findings": [],
        "total": 0,
        "by_severity": {},
        "scan_type": "",
        "error": None,
    }

    work_dir = f"/tmp/gitleaks_{uuid.uuid4().hex[:12]}"
    os.makedirs(work_dir, exist_ok=True)

    try:
        is_git = target.endswith(".git") or "github.com" in target or "gitlab.com" in target or "bitbucket.org" in target
        if is_git:
            result["scan_type"] = "git_repository"
            findings = await _scan_git_repo(target, work_dir, req.timeout)
        else:
            result["scan_type"] = "web_probe"
            findings = await _scan_web_target(target, work_dir, req.timeout)

        by_sev: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "medium")
            by_sev[sev] = by_sev.get(sev, 0) + 1

        result["findings"] = findings
        result["total"] = len(findings)
        result["by_severity"] = by_sev

    except asyncio.TimeoutError:
        result["error"] = f"GitLeaks scan timed out after {req.timeout}s"
    except Exception as exc:
        result["error"] = str(exc)
        logger.exception("GitLeaks failed for %s", target)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    logger.info("GitLeaks done â€” target=%s findings=%d", target, result["total"])
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9008)
