"""
Nmap active scanner microservice v3.

Fixes pour tcpwrapped + environnements cloud/CDN :
  1. Service detection avancée (--version-intensity 9 + scripts NSE étendus)
  2. Fallback HTTP probing via httpx sur ports tcpwrapped/unknown
  3. Détection CDN/cloud (Cloudflare, AWS, Azure, Fastly, Akamai...)
  4. Inférence de service par numéro de port quand Nmap échoue
  5. Corrélation Nmap + httpx dans le résumé final
  6. Pré-résolution DNS pour contourner les problèmes Docker
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

logger = logging.getLogger("nmap-service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="Nmap Scanner Microservice", version="3.0.0")

# Standard high-value ports scanned alongside 1-1024
_BASE_PORTS = (
    "1-1024,"
    "1433,1521,1723,1900,2000,2049,2121,2375,2376,3000,3128,3306,3389,"
    "4848,5000,5432,5601,5900,6000,6379,7001,7474,8000,8008,8009,8080,"
    "8081,8443,8888,9000,9090,9200,9300,9418,10250,27017,49152-49157"
)

# Scripts that provide real fingerprinting value without being intrusive
_NSE_SCRIPTS = (
    "banner,http-title,http-server-header,http-methods,"
    "ssl-cert,ssl-enum-ciphers,ssh-hostkey,http-auth-finder,"
    "http-robots.txt,ftp-anon,smtp-commands"
)

# Infer service name from port when Nmap returns tcpwrapped/unknown
_PORT_SERVICE_MAP: Dict[int, tuple] = {
    21:    ("ftp",           "FTP"),
    22:    ("ssh",           "SSH"),
    23:    ("telnet",        "Telnet"),
    25:    ("smtp",          "SMTP"),
    53:    ("dns",           "DNS"),
    80:    ("http",          "HTTP"),
    110:   ("pop3",          "POP3"),
    143:   ("imap",          "IMAP"),
    389:   ("ldap",          "LDAP"),
    443:   ("https",         "HTTPS"),
    445:   ("microsoft-ds",  "SMB"),
    465:   ("smtps",         "SMTP/SSL"),
    587:   ("submission",    "SMTP/TLS"),
    636:   ("ldaps",         "LDAPS"),
    993:   ("imaps",         "IMAP/SSL"),
    995:   ("pop3s",         "POP3/SSL"),
    1433:  ("ms-sql-s",      "MSSQL"),
    1521:  ("oracle",        "Oracle DB"),
    3306:  ("mysql",         "MySQL"),
    3389:  ("ms-wbt-server", "RDP"),
    5432:  ("postgresql",    "PostgreSQL"),
    5900:  ("vnc",           "VNC"),
    6379:  ("redis",         "Redis"),
    8080:  ("http-proxy",    "HTTP-Alt"),
    8443:  ("https-alt",     "HTTPS-Alt"),
    8888:  ("http",          "HTTP"),
    9090:  ("zeus-admin",    "HTTP"),
    9200:  ("wap-wsp",       "Elasticsearch"),
    9300:  ("vrace",         "Elasticsearch-Transport"),
    27017: ("mongod",        "MongoDB"),
}

# CDN/cloud detection via response headers
_CDN_HEADER_MAP: Dict[str, str] = {
    "cf-ray":               "Cloudflare",
    "cf-cache-status":      "Cloudflare",
    "cf-connecting-ip":     "Cloudflare",
    "x-amz-cf-id":          "AWS CloudFront",
    "x-amz-request-id":     "AWS",
    "x-azure-ref":          "Azure CDN",
    "x-ms-request-id":      "Azure",
    "x-fastly-request-id":  "Fastly",
    "x-served-by":          "Fastly",
    "x-varnish":            "Varnish",
    "x-cache-hits":         "CDN Cache",
    "x-akamai-transformed": "Akamai",
    "x-check-cacheable":    "Akamai",
    "x-sucuri-id":          "Sucuri WAF",
    "x-fw-hash":            "Imperva/Incapsula",
}

_SERVER_TECH_MAP: Dict[str, str] = {
    "nginx":       "Nginx",
    "apache":      "Apache",
    "microsoft-iis": "IIS",
    "iis":         "IIS",
    "litespeed":   "LiteSpeed",
    "openresty":   "OpenResty",
    "caddy":       "Caddy",
    "cloudflare":  "Cloudflare",
    "gunicorn":    "Gunicorn",
    "uvicorn":     "Uvicorn",
    "node":        "Node.js",
    "express":     "Express",
    "tomcat":      "Tomcat",
    "jetty":       "Jetty",
    "werkzeug":    "Flask/Werkzeug",
    "next.js":     "Next.js",
}


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target:           str
    additional_ports: Optional[List[int]] = None
    timeout:          int = 300


# ---------------------------------------------------------------------------
# DNS pre-resolution
# ---------------------------------------------------------------------------


def _is_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def _strip_to_host(target: str) -> str:
    return re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]


def _resolve_target(target: str) -> str:
    host = _strip_to_host(target)
    if _is_ip(host):
        return target
    try:
        ip = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
        logger.info("DNS pre-resolve: %s → %s", host, ip)
        return ip
    except Exception as exc:
        logger.warning("DNS pre-resolve failed for %s (%s), using original", host, exc)
        return target


# ---------------------------------------------------------------------------
# HTTP probing fallback
# ---------------------------------------------------------------------------


async def _http_probe(ip: str, port: int, timeout: float = 8.0) -> Dict[str, Any]:
    """
    Probe a port with HTTP/HTTPS to resolve tcpwrapped and detect technologies.
    Returns enriched service info extracted from response headers + body.
    """
    probe: Dict[str, Any] = {
        "probed":    False,
        "scheme":    None,
        "status":    None,
        "server":    "",
        "title":     "",
        "powered_by": "",
        "technologies": [],
        "cdn":       None,
        "cloud":     None,
        "waf":       None,
        "headers":   {},
    }

    schemes = ["https", "http"] if port in {443, 8443} else ["http", "https"]
    if port in {443, 8443, 8080, 8888, 9090, 3000, 5000}:
        schemes = ["https", "http"] if port in {443, 8443} else ["http", "https"]

    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}"
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            ) as client:
                resp = await client.get(url)

            probe["probed"]     = True
            probe["scheme"]     = scheme
            probe["status"]     = resp.status_code
            probe["server"]     = resp.headers.get("server", "")
            probe["powered_by"] = resp.headers.get("x-powered-by", "")
            probe["headers"]    = dict(resp.headers)

            # CDN / cloud / WAF detection
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            for hdr, provider in _CDN_HEADER_MAP.items():
                if hdr in resp_headers_lower:
                    if "waf" in provider.lower() or "imperva" in provider.lower() or "sucuri" in provider.lower():
                        probe["waf"]   = provider
                    elif provider in {"Cloudflare", "AWS CloudFront", "Azure CDN", "Fastly", "Akamai"}:
                        probe["cloud"] = provider
                    else:
                        probe["cdn"]   = provider
                    break

            # Server-header technology
            techs: List[str] = []
            server_lower  = probe["server"].lower()
            powered_lower = probe["powered_by"].lower()
            for kw, name in _SERVER_TECH_MAP.items():
                if kw in server_lower or kw in powered_lower:
                    techs.append(name)

            # Body-based tech detection (first 3000 chars)
            body = ""
            try:
                body = resp.text[:3000]
            except Exception:
                pass

            if body:
                if re.search(r'<meta[^>]+generator[^>]+WordPress', body, re.I):
                    techs.append("WordPress")
                if re.search(r'<meta[^>]+generator[^>]+Drupal', body, re.I):
                    techs.append("Drupal")
                if re.search(r'<meta[^>]+generator[^>]+Joomla', body, re.I):
                    techs.append("Joomla")
                if "wp-content" in body or "wp-includes" in body:
                    techs.append("WordPress")
                if "React" in body or "__NEXT_DATA__" in body:
                    techs.append("React/Next.js")
                if "angular" in body.lower():
                    techs.append("Angular")
                if "vue" in body.lower() and ("app.vue" in body.lower() or "v-bind" in body.lower()):
                    techs.append("Vue.js")
                if "PHPSESSID" in body:
                    techs.append("PHP")
                if "ASP.NET_SessionId" in body or "asp.net" in powered_lower:
                    techs.append("ASP.NET")
                if "laravel_session" in body:
                    techs.append("Laravel")
                if "csrfmiddlewaretoken" in body:
                    techs.append("Django")

            probe["technologies"] = sorted(set(techs))

            # Page title
            m = re.search(r"<title[^>]*>([^<]{1,200})</title>", body, re.I)
            if m:
                probe["title"] = m.group(1).strip()

            return probe  # success — return on first working scheme

        except (httpx.ConnectError, httpx.ConnectTimeout):
            continue
        except Exception:
            continue

    return probe


async def _enrich_tcpwrapped(
    hosts: List[Dict[str, Any]],
    original_target: str,
    probe_timeout: float = 8.0,
) -> None:
    """
    For every port that is open but has service=tcpwrapped or service='',
    run an HTTP probe and merge results back into the port dict in-place.
    """
    probe_tasks: List[tuple] = []  # (host_idx, port_idx, ip, port_num)

    for h_idx, host in enumerate(hosts):
        # Best IP to probe
        ip = original_target
        for addr in host.get("addresses", []):
            if addr.get("addrtype") == "ipv4":
                ip = addr["addr"]
                break

        for p_idx, port in enumerate(host.get("ports", [])):
            if port.get("state") != "open":
                continue
            svc = port.get("service", "").lower()
            # Probe if: tcpwrapped, empty, or web-likely port with no product
            if svc in ("tcpwrapped", "", "unknown") or (
                port.get("port") in {80, 443, 8080, 8443, 8888, 3000, 5000, 9090}
                and not port.get("product")
            ):
                probe_tasks.append((h_idx, p_idx, ip, port["port"]))

    if not probe_tasks:
        return

    logger.info("HTTP probing %d ports on %s", len(probe_tasks), original_target)

    results = await asyncio.gather(
        *[_http_probe(ip, port_num, probe_timeout) for _, _, ip, port_num in probe_tasks],
        return_exceptions=True,
    )

    for (h_idx, p_idx, ip, port_num), probe_result in zip(probe_tasks, results):
        if isinstance(probe_result, Exception) or not isinstance(probe_result, dict):
            continue
        if not probe_result.get("probed"):
            continue

        port = hosts[h_idx]["ports"][p_idx]
        scheme = probe_result["scheme"]

        # Override service name
        if port.get("service") in ("tcpwrapped", "", "unknown", None):
            port["service"] = scheme  # "http" or "https"
        if not port.get("product") and probe_result.get("server"):
            port["product"] = probe_result["server"][:60]

        # Inject probing data
        port["http_probe"]     = {
            "status":     probe_result["status"],
            "scheme":     scheme,
            "server":     probe_result["server"],
            "powered_by": probe_result["powered_by"],
            "title":      probe_result["title"],
            "cdn":        probe_result["cdn"],
            "cloud":      probe_result["cloud"],
            "waf":        probe_result["waf"],
            "techs":      probe_result["technologies"],
        }
        port["http_title"]     = probe_result["title"]
        port["server_header"]  = probe_result["server"]
        port["technologies"]   = probe_result["technologies"]

        logger.info(
            "HTTP probe port %d → %s %s | server=%s | cdn=%s | techs=%s",
            port_num, scheme, probe_result["status"],
            probe_result["server"][:40],
            probe_result["cloud"] or probe_result["cdn"],
            probe_result["technologies"],
        )


def _infer_service_from_port(port_num: int, current_service: str) -> str:
    """Return a better service name if Nmap returned tcpwrapped/unknown."""
    if current_service not in ("tcpwrapped", "", "unknown"):
        return current_service
    svc, _ = _PORT_SERVICE_MAP.get(port_num, ("unknown", "Unknown"))
    return svc


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------


def _extract_script_output(scripts: List[Dict], script_id: str) -> str:
    for s in scripts:
        if s.get("id") == script_id:
            return (s.get("output") or "").strip()[:300]
    return ""


def _extract_ssl_subject(scripts: List[Dict]) -> str:
    for s in scripts:
        if s.get("id") == "ssl-cert":
            m = re.search(r"Subject:([^\n]+)", s.get("output", ""))
            if m:
                return m.group(1).strip()[:200]
    return ""


def _parse_nmap_xml(xml_str: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"hosts": [], "raw_summary": "", "hosts_down": 0}
    try:
        root = ET.fromstring(xml_str)
        result["raw_summary"] = root.attrib.get("summary", "")

        for host_el in root.findall("host"):
            status_el = host_el.find("status")
            status = status_el.attrib.get("state", "") if status_el is not None else ""

            if status == "down":
                result["hosts_down"] += 1
                continue

            host: Dict[str, Any] = {
                "status": status, "addresses": [],
                "hostnames": [], "ports": [],
                "os": [], "scripts": [],
            }

            for addr in host_el.findall("address"):
                host["addresses"].append({
                    "addr":     addr.attrib.get("addr"),
                    "addrtype": addr.attrib.get("addrtype"),
                })
            for hn in host_el.findall(".//hostname"):
                if hn.attrib.get("name"):
                    host["hostnames"].append(hn.attrib["name"])

            for port_el in host_el.findall(".//port"):
                state_el   = port_el.find("state")
                service_el = port_el.find("service")
                port_state = state_el.attrib.get("state", "") if state_el is not None else ""
                cpes       = [c.text for c in (service_el.findall("cpe") if service_el else []) if c.text]
                scripts    = [
                    {"id": s.attrib.get("id", ""), "output": s.attrib.get("output", "")}
                    for s in port_el.findall("script")
                ]
                raw_svc = service_el.attrib.get("name", "") if service_el is not None else ""
                port_num = int(port_el.attrib.get("portid", 0))
                inferred_svc = _infer_service_from_port(port_num, raw_svc)

                host["ports"].append({
                    "port":          port_num,
                    "protocol":      port_el.attrib.get("protocol", "tcp"),
                    "state":         port_state,
                    "service":       inferred_svc,
                    "service_raw":   raw_svc,   # preserve original
                    "product":       service_el.attrib.get("product", "") if service_el else "",
                    "version":       service_el.attrib.get("version", "") if service_el else "",
                    "extrainfo":     service_el.attrib.get("extrainfo", "") if service_el else "",
                    "tunnel":        service_el.attrib.get("tunnel", "") if service_el else "",
                    "cpes":          cpes,
                    "scripts":       scripts,
                    "http_title":    _extract_script_output(scripts, "http-title"),
                    "server_header": _extract_script_output(scripts, "http-server-header"),
                    "ssl_subject":   _extract_ssl_subject(scripts),
                    "banner":        _extract_script_output(scripts, "banner"),
                    "technologies":  [],
                    "http_probe":    None,
                })

            for os_match in host_el.findall(".//osmatch"):
                host["os"].append({
                    "name":     os_match.attrib.get("name"),
                    "accuracy": os_match.attrib.get("accuracy"),
                })
            for script_el in host_el.findall(".//hostscript/script"):
                host["scripts"].append({
                    "id":     script_el.attrib.get("id", ""),
                    "output": script_el.attrib.get("output", ""),
                })

            result["hosts"].append(host)
    except ET.ParseError as exc:
        result["parse_error"] = str(exc)

    return result


def _build_summary(nmap_data: Dict[str, Any], original_target: str) -> Dict[str, Any]:
    ports:    set = set()
    services: Dict[str, Any] = {}
    ips:      set = set()
    cpes:     set = set()
    all_techs: set = set()
    cdns:      set = set()

    for host in nmap_data.get("hosts", []):
        for addr in host.get("addresses", []):
            if addr.get("addrtype") == "ipv4" and addr.get("addr"):
                ips.add(addr["addr"])

        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            port_num = port.get("port")
            if port_num is None:
                continue
            ports.add(port_num)

            # Merge HTTP probe data into service info
            probe = port.get("http_probe") or {}
            techs = port.get("technologies", [])
            if probe.get("techs"):
                techs = list(set(techs + probe["techs"]))
            all_techs.update(techs)

            cdn_info = probe.get("cloud") or probe.get("cdn") or ""
            if cdn_info:
                cdns.add(cdn_info)

            services[str(port_num)] = {
                "name":          port.get("service", ""),
                "service_raw":   port.get("service_raw", ""),
                "product":       port.get("product", ""),
                "version":       port.get("version", ""),
                "protocol":      port.get("protocol", "tcp"),
                "http_title":    port.get("http_title", "") or probe.get("title", ""),
                "server_header": port.get("server_header", "") or probe.get("server", ""),
                "ssl_subject":   port.get("ssl_subject", ""),
                "banner":        port.get("banner", ""),
                "technologies":  techs,
                "cdn":           cdn_info,
                "http_status":   probe.get("status"),
            }
            for cpe in port.get("cpes", []):
                cpes.add(cpe)

    hosts_down = nmap_data.get("hosts_down", 0)
    summary: Dict[str, Any] = {
        "ports":             sorted(ports),
        "services":          services,
        "ips":               sorted(ips),
        "cpes":              sorted(cpes),
        "technologies":      sorted(all_techs),
        "cdn_providers":     sorted(cdns),
        "open_port_count":   len(ports),
        "host_count":        len(nmap_data.get("hosts", [])),
        "hosts_down":        hosts_down,
    }
    if hosts_down:
        summary["host_down_message"] = (
            f"{hosts_down} host(s) did not respond. "
            "They may be offline, behind a firewall, or blocking ICMP probes."
        )
    if cdns:
        summary["cloud_note"] = (
            f"Target is behind {', '.join(cdns)}. "
            "Real server IP and services may be hidden. "
            "Nmap results reflect the CDN edge, not the origin."
        )
    return summary


def _build_port_arg(additional_ports: Optional[List[int]]) -> List[str]:
    if not additional_ports:
        return ["--top-ports", "1000"]
    extra = ",".join(str(p) for p in sorted(set(additional_ports)))
    return ["-p", f"{_BASE_PORTS},{extra}"]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "nmap"}


@app.post("/scan")
async def scan(req: ScanRequest) -> Dict[str, Any]:
    logger.info("Scan started — target=%s ports=%s", req.target, req.additional_ports)

    resolved = _resolve_target(req.target)

    result: Dict[str, Any] = {
        "target":                    req.target,
        "resolved_target":           resolved,
        "scan_method":               "nmap+http_probe",
        "error":                     None,
        "data":                      {},
        "summary":                   {},
        "additional_ports_from_zap": req.additional_ports or [],
    }

    # ── 1. Nmap scan with enhanced service detection ─────────────────────────
    cmd = (
        ["nmap", "-sV", "-Pn", "--open"]
        + _build_port_arg(req.additional_ports)
        + [
            "-T3",
            "--version-intensity", "9",       # max service detection depth
            "--host-timeout",      "120s",
            "--dns-servers",       "8.8.8.8,8.8.4.4",
            "--min-rate",          "200",
            "--script",            _NSE_SCRIPTS,
            "-oX", "-",
            resolved,
        ]
    )

    xml_output = ""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=req.timeout)
        xml_output = proc.stdout
        if proc.stderr:
            logger.debug("Nmap stderr: %s", proc.stderr[:500])
    except FileNotFoundError:
        result["error"] = "nmap binary not found"
        return result
    except subprocess.TimeoutExpired:
        result["error"] = f"nmap timed out after {req.timeout}s"
        logger.warning("Scan timed out for %s", req.target)
        return result
    except Exception as exc:
        result["error"] = str(exc)
        logger.exception("Unexpected error running nmap for %s", req.target)
        return result

    if not xml_output.strip():
        stderr_hint = (proc.stderr or "").strip()[:300]
        result["error"] = f"nmap produced no XML output. stderr: {stderr_hint}"
        return result

    nmap_data = _parse_nmap_xml(xml_output)

    # ── 2. HTTP probing on tcpwrapped / unknown ports ────────────────────────
    if nmap_data.get("hosts"):
        try:
            probe_timeout = min(8.0, (req.timeout - 60) / 4)
            await _enrich_tcpwrapped(nmap_data["hosts"], req.target, probe_timeout)
        except Exception as exc:
            logger.warning("HTTP probing step failed: %s", exc)

    result["data"]    = nmap_data
    result["summary"] = _build_summary(nmap_data, req.target)

    open_count = result["summary"].get("open_port_count", 0)
    cdn_note   = result["summary"].get("cloud_note", "")
    logger.info(
        "Scan complete — target=%s resolved=%s open_ports=%d%s",
        req.target, resolved, open_count,
        f" [{cdn_note[:60]}]" if cdn_note else "",
    )
    return result
