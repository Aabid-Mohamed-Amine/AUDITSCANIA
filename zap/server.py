from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI
from pydantic import BaseModel

logger = logging.getLogger("zap-service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="OWASP ZAP Scanner Microservice", version="3.0.0")

# ── Config ────────────────────────────────────────────────────────────────────
ZAP_DAEMON_PORT = int(os.getenv("ZAP_PORT", "8090"))
ZAP_API_KEY     = os.getenv("ZAP_API_KEY", "")

# Timeouts (secondes)
SPIDER_TIMEOUT_S       = int(os.getenv("ZAP_SPIDER_TIMEOUT",      "180"))   # 3 min
AJAX_SPIDER_TIMEOUT_S  = int(os.getenv("ZAP_AJAX_TIMEOUT",        "60"))    # 1 min max
PASSIVE_WAIT_S         = int(os.getenv("ZAP_PASSIVE_WAIT",        "30"))    # 30 s
ACTIVE_SCAN_TIMEOUT_S  = int(os.getenv("ZAP_ACTIVE_TIMEOUT",      "480"))   # 8 min

RISK_LABELS = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Informational"}

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

# Indicateurs de SPA (Angular / React / Vue)
_SPA_INDICATORS = {
    "angular", "react", "vue", "next.js", "nuxt",
    "ng-version", "__ngContext__", "_reactFiber",
    "webpack", "chunk.js", "main.js", "polyfills.js",
}


# ── Schema ────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target:         str
    spider_minutes: int                     = 3
    timeout:        int                     = 900
    ajax_spider:    bool                    = True    # activé par défaut maintenant
    active_scan:    bool                    = True    # active scan activé par défaut
    max_depth:      int                     = 10
    max_children:   int                     = 0
    headers:        Optional[Dict[str, str]] = None
    cookies:        Optional[Dict[str, str]] = None
    is_spa:         Optional[bool]          = None    # None = auto-détection


# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"http://{target}"
    return target


def _detect_spa_from_target(target: str) -> bool:
    """Heuristique légère : port 3000/4200/5173 → probablement SPA."""
    parsed = urlparse(target)
    spa_ports = {3000, 4200, 5173, 8080, 8100}
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return port in spa_ports
    except Exception:
        return False


def _extract_alerts_from_api(alerts_raw: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalise les alertes ZAP en format groupé par plugin_id."""
    _CONF_MAP = {"Low": 1, "Medium": 2, "High": 3, "Confirmed": 4}
    _RISK_MAP = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

    grouped: Dict[str, Dict[str, Any]] = {}
    for raw in alerts_raw:
        plugin_id = raw.get("pluginId", raw.get("pluginid", ""))
        name      = raw.get("name", raw.get("alert", ""))
        key       = f"{plugin_id}_{name}"

        if key not in grouped:
            _r = raw.get("riskcode", raw.get("risk", 0))
            risk_code  = _RISK_MAP.get(str(_r), 0) if isinstance(_r, str) else int(_r or 0)
            _c = raw.get("confidence", "0")
            confidence = _CONF_MAP.get(str(_c), int(_c) if str(_c).isdigit() else 2)

            grouped[key] = {
                "name":        name,
                "risk":        RISK_LABELS.get(risk_code, "Unknown"),
                "risk_code":   risk_code,
                "confidence":  confidence,
                "description": (raw.get("description", raw.get("desc", "")) or "").strip(),
                "solution":    (raw.get("solution", "") or "").strip(),
                "reference":   (raw.get("reference", "") or "").strip(),
                "cwe_id":      raw.get("cweid", ""),
                "wasc_id":     raw.get("wascid", ""),
                "plugin_id":   plugin_id,
                "count":       0,
                "instances":   [],
            }

        entry = grouped[key]
        entry["count"] += 1
        if len(entry["instances"]) < 10:
            entry["instances"].append({
                "uri":      raw.get("url", raw.get("uri", "")),
                "method":   raw.get("method", "GET"),
                "param":    raw.get("param", ""),
                "evidence": (raw.get("evidence", "") or "")[:300],
                "attack":   (raw.get("attack",   "") or "")[:200],
            })

    return sorted(grouped.values(), key=lambda a: a["risk_code"], reverse=True)


def _aggregate_by_risk(alerts: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for a in alerts:
        counts[a["risk"]] = counts.get(a["risk"], 0) + 1
    return counts


def _extract_endpoints(alerts: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    seen: set       = set()
    endpoints: list = []
    for alert in alerts:
        for inst in alert.get("instances", []):
            uri = inst.get("uri", "").strip()
            if uri and uri not in seen:
                seen.add(uri)
                parsed = urlparse(uri)
                endpoints.append({
                    "url":    uri,
                    "method": inst.get("method", "GET"),
                    "path":   parsed.path,
                    "port":   str(parsed.port or ""),
                    "param":  inst.get("param", ""),
                })
                if len(endpoints) >= 500:
                    return endpoints
    return endpoints


def _extract_form_params(alerts: List[Dict[str, Any]]) -> List[str]:
    params: set = set()
    for alert in alerts:
        for inst in alert.get("instances", []):
            param = inst.get("param", "").strip()
            if param:
                params.add(param)
    return sorted(params)


def _extract_abnormal_headers(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    issues: list = []
    seen:   set  = set()
    for alert in alerts:
        name: str = alert.get("name", "").lower()
        for kw in _SECURITY_HEADER_KEYWORDS:
            if kw in name and name not in seen:
                seen.add(name)
                issues.append({
                    "header_issue": alert.get("name", ""),
                    "risk":         alert.get("risk", "Informational"),
                    "count":        alert.get("count", 0),
                    "cwe_id":       alert.get("cwe_id", ""),
                })
                break
    return issues


def _extract_ports_from_endpoints(endpoints: List[Dict[str, str]]) -> List[int]:
    ports:    set = set()
    standard: set = {80, 443, 8080, 8443}
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


def _inject_auth(
    zap: Any,
    headers:  Optional[Dict[str, str]],
    cookies:  Optional[Dict[str, str]],
) -> tuple[Optional[str], Optional[str], list[str]]:
    """Injecte l'auth via le replacer ZAP. Retourne (header_name, header_value, rules_added)."""
    auth_header_name:  Optional[str] = None
    auth_header_value: Optional[str] = None
    replacer_rules: list[str]        = []

    if headers:
        for k, v in headers.items():
            if k.lower() == "authorization":
                auth_header_name, auth_header_value = k, v
                break
        if auth_header_name is None:
            auth_header_name, auth_header_value = next(iter(headers.items()))

    if auth_header_name is None and cookies:
        auth_header_name  = "Cookie"
        auth_header_value = "; ".join(f"{k}={v}" for k, v in cookies.items())

    if auth_header_name and auth_header_value:
        desc = "auditscania_auth_header"
        try:
            zap.replacer.add_rule(
                description=desc,
                enabled=True,
                matchtype="REQ_HEADER",
                matchregex=False,
                matchstring=auth_header_name,
                replacement=auth_header_value,
            )
            replacer_rules.append(desc)
            logger.info("ZAP replacer: injecting header '%s'", auth_header_name)
        except Exception as exc:
            logger.warning("Could not add replacer rule: %s", exc)

    return auth_header_name, auth_header_value, replacer_rules


async def _wait_for_passive_scan(zap: Any, timeout: int = 60) -> None:
    """Attend que le scan passif ZAP vide sa file."""
    start = time.time()
    while True:
        try:
            records = int(zap.pscan.records_to_scan)
            if records == 0:
                break
        except Exception:
            break
        if time.time() - start > timeout:
            logger.warning("Passive scan wait timed out after %ds", timeout)
            break
        await asyncio.sleep(3)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "zap", "version": "3.0.0"}


@app.post("/scan")
async def scan(req: ScanRequest) -> Dict[str, Any]:
    target_url = _normalize_url(req.target)
    logger.info("ZAP v3 scan started — target=%s ajax=%s active=%s",
                target_url, req.ajax_spider, req.active_scan)

    result: Dict[str, Any] = {
        "target":           target_url,
        "alerts":           [],
        "total":            0,
        "by_risk":          {},
        "endpoints":        [],
        "form_params":      [],
        "abnormal_headers": [],
        "implicit_ports":   [],
        "scan_phases":      [],   # trace des phases exécutées
        "error":            None,
    }

    try:
        from zapv2 import ZAPv2
    except ImportError:
        result["error"] = "python-owasp-zap-v2.4 not installed in container"
        logger.error(result["error"])
        return result

    zap = ZAPv2(
        apikey=ZAP_API_KEY,
        proxies={
            "http":  f"http://127.0.0.1:{ZAP_DAEMON_PORT}",
            "https": f"http://127.0.0.1:{ZAP_DAEMON_PORT}",
        },
    )

    use_ajax = req.ajax_spider
    if req.is_spa is not None:
        use_ajax = req.is_spa

    replacer_rules: list[str] = []
    context_id:     Optional[str] = None
    spider_id:      Optional[str] = None
    ascan_id:       Optional[str] = None

    try:
        try:
            zap.core.new_session(name="auditscania", overwrite=True)
        except Exception as e:
            logger.warning("ZAP session reset warning: %s", e)

        # ── 1. Injecter l'auth via replacer ──────────────────────────────────
        _, _, replacer_rules = _inject_auth(zap, req.headers, req.cookies)

        # ── 2. Créer un context ZAP scopé ────────────────────────────────────
        try:
            context_id = zap.context.new_context("auditscania_ctx")
            parsed = urlparse(target_url)
            scope_pattern = f"{parsed.scheme}://{parsed.netloc}.*"
            zap.context.include_in_context("auditscania_ctx", scope_pattern)
            logger.info("ZAP context créé — scope: %s", scope_pattern)
        except Exception as e:
            logger.warning("ZAP context creation warning: %s", e)
            context_id = None

        # ── 3. Accéder à l'URL cible (seed) ──────────────────────────────────
        try:
            zap.core.access_url(target_url, followredirects=True)
            await asyncio.sleep(2)
        except Exception as e:
            logger.warning("ZAP access_url warning: %s", e)

        result["scan_phases"].append("seed")

        # ── 4. Ajax Spider en premier (SPA Angular/React/Vue) ───────────────────
        if use_ajax:
            logger.info("ZAP Phase 1/4 — Ajax Spider (SPA mode, timeout %ds)", AJAX_SPIDER_TIMEOUT_S)
            try:
                ajax_kwargs: Dict[str, Any] = {"url": target_url, "inscope": True}
                if context_id:
                    ajax_kwargs["contextname"] = "auditscania_ctx"

                zap.ajaxSpider.scan(**ajax_kwargs)
                start = time.time()

                while True:
                    try:
                        status = zap.ajaxSpider.status
                        if hasattr(status, "__call__"):
                            status = status()
                        if str(status).lower() not in ("running",):
                            break
                    except Exception:
                        break

                    elapsed = time.time() - start
                    if elapsed > AJAX_SPIDER_TIMEOUT_S:
                        logger.warning("Ajax Spider timeout (%ds) — arrêt, on continue", AJAX_SPIDER_TIMEOUT_S)
                        try:
                            zap.ajaxSpider.stop()
                        except Exception:
                            pass
                        break

                    logger.info("  Ajax Spider: running... (%ds)", int(elapsed))
                    await asyncio.sleep(5)

                try:
                    ajax_results = zap.ajaxSpider.results(start=0, count=500)
                    logger.info("Ajax Spider terminé — %d resources", len(ajax_results))
                    result["scan_phases"].append(f"ajax_spider:{len(ajax_results)}resources")
                except Exception:
                    result["scan_phases"].append("ajax_spider:done")

            except Exception as e:
                logger.warning("Ajax Spider failed: %s — on continue", e)
                result["scan_phases"].append("ajax_spider:failed")
        else:
            result["scan_phases"].append("ajax_spider:skipped")

        # ── 5. Spider classique (complément) ─────────────────────────────────
        logger.info("ZAP Phase 2/4 — Spider classique")
        try:
            spider_kwargs: Dict[str, Any] = {
                "url":         target_url,
                "maxchildren": req.max_children,
                "recurse":     True,
            }
            if context_id:
                spider_kwargs["contextid"] = context_id

            spider_id = zap.spider.scan(**spider_kwargs)
            start     = time.time()

            while True:
                try:
                    progress = int(zap.spider.status(spider_id))
                except Exception:
                    break
                if progress >= 100:
                    break
                elapsed = time.time() - start
                if elapsed > SPIDER_TIMEOUT_S:
                    logger.warning("ZAP spider timeout (%ds) — arrêt forcé", SPIDER_TIMEOUT_S)
                    zap.spider.stop(spider_id)
                    break
                logger.info("  Spider: %d%% (%ds)", progress, int(elapsed))
                await asyncio.sleep(5)

            urls_found = len(zap.spider.results(spider_id))
            logger.info("Spider terminé — %d URLs trouvées", urls_found)
            result["scan_phases"].append(f"spider:{urls_found}urls")
        except Exception as e:
            logger.warning("ZAP spider failed: %s", e)

        # ── 6. Attendre scan passif ───────────────────────────────────────────
        logger.info("ZAP Phase 3/4 — Scan passif")
        await _wait_for_passive_scan(zap, timeout=PASSIVE_WAIT_S)
        result["scan_phases"].append("passive_scan:done")

        # ── 7. Active Scan ────────────────────────────────────────────────────
        if req.active_scan:
            logger.info("ZAP Phase 4/4 — Active Scan")
            try:
                ascan_kwargs: Dict[str, Any] = {
                    "url":      target_url,
                    "recurse":  True,
                    "inscope":  True,
                }
                if context_id:
                    ascan_kwargs["contextid"] = context_id

                ascan_id = zap.ascan.scan(**ascan_kwargs)
                start    = time.time()

                while True:
                    try:
                        progress = int(zap.ascan.status(ascan_id))
                    except Exception:
                        break
                    if progress >= 100:
                        break
                    elapsed = time.time() - start
                    if elapsed > ACTIVE_SCAN_TIMEOUT_S:
                        logger.warning("Active scan timeout (%ds) — arrêt", ACTIVE_SCAN_TIMEOUT_S)
                        try:
                            zap.ascan.stop(ascan_id)
                        except Exception:
                            pass
                        break
                    logger.info("  Active scan: %d%% (%ds)", progress, int(elapsed))
                    await asyncio.sleep(8)

                result["scan_phases"].append("active_scan:done")
                logger.info("Active Scan terminé")

            except Exception as e:
                logger.warning("Active scan failed: %s", e)
                result["scan_phases"].append("active_scan:failed")
        else:
            result["scan_phases"].append("active_scan:skipped")

        # ── 8. Collecter toutes les alertes ───────────────────────────────────
        logger.info("Collecte des alertes ZAP")
        try:
            alerts_raw = zap.core.alerts(baseurl=target_url)
            alerts     = _extract_alerts_from_api(alerts_raw)
            endpoints  = _extract_endpoints(alerts)

            result["alerts"]           = alerts
            result["total"]            = len(alerts)
            result["by_risk"]          = _aggregate_by_risk(alerts)
            result["endpoints"]        = endpoints
            result["form_params"]      = _extract_form_params(alerts)
            result["abnormal_headers"] = _extract_abnormal_headers(alerts)
            result["implicit_ports"]   = _extract_ports_from_endpoints(endpoints)

        except Exception as e:
            result["error"] = f"Alert collection failed: {e}"
            logger.exception("ZAP alert collection failed")

    except Exception as exc:
        result["error"] = str(exc)
        logger.exception("ZAP scan failed for %s", target_url)

    finally:
        # ── Cleanup complet ───────────────────────────────────────────────────
        for desc in replacer_rules:
            try:
                zap.replacer.remove_rule(description=desc)
            except Exception:
                pass
        if spider_id is not None:
            try:
                zap.spider.remove_scan(spider_id)
            except Exception:
                pass
        if ascan_id is not None:
            try:
                zap.ascan.remove_scan(ascan_id)
            except Exception:
                pass
        try:
            zap.ajaxSpider.stop()
        except Exception:
            pass

    logger.info(
        "ZAP v3 scan complet — target=%s phases=%s alerts=%d endpoints=%d",
        target_url,
        result["scan_phases"],
        result["total"],
        len(result["endpoints"]),
    )
    return result