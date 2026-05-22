"""
Nmap active scanner microservice.

Accepts optional additional_ports (extracted from ZAP endpoints) to extend
the standard top-1000 port scan with non-standard ports discovered by ZAP.
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel

logger = logging.getLogger("nmap-service")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="Nmap Scanner Microservice", version="1.0.0")

# Standard high ports always included alongside the privileged range (1-1024)
# when ZAP supplies additional ports — mirrors what --top-ports 1000 covers.
_BASE_PORTS = (
    "1-1024,"
    "1433,1521,1723,1900,2000,2049,2121,2375,2376,3000,3128,3306,3389,"
    "4848,5000,5432,5601,5900,6000,6379,7001,7474,8000,8008,8009,8080,"
    "8081,8443,8888,9000,9090,9200,9300,9418,10250,27017,49152-49157"
)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target: str
    additional_ports: Optional[List[int]] = None
    timeout: int = 300


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------


def _parse_nmap_xml(xml_str: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"hosts": [], "raw_summary": "", "hosts_down": 0}
    try:
        root = ET.fromstring(xml_str)
        result["raw_summary"] = root.attrib.get("summary", "")

        for host_el in root.findall("host"):
            status_el = host_el.find("status")
            status = status_el.attrib.get("state", "") if status_el is not None else ""

            # Count down hosts and skip them — no ports to report
            if status == "down":
                result["hosts_down"] += 1
                continue

            host: Dict[str, Any] = {
                "status": status,
                "addresses": [],
                "hostnames": [],
                "ports": [],
                "os": [],
                "scripts": [],
            }

            for addr in host_el.findall("address"):
                host["addresses"].append({
                    "addr": addr.attrib.get("addr"),
                    "addrtype": addr.attrib.get("addrtype"),
                })

            for hn in host_el.findall(".//hostname"):
                host["hostnames"].append(hn.attrib.get("name"))

            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")

                # CPE strings from <cpe> children of <service>
                cpes = [
                    cpe.text for cpe in (service_el.findall("cpe") if service_el is not None else [])
                    if cpe.text
                ]

                # NSE scripts at port level: <script id="..." output="..."/>
                scripts = [
                    {"id": s.attrib.get("id", ""), "output": s.attrib.get("output", "")}
                    for s in port_el.findall("script")
                ]

                host["ports"].append({
                    "port": int(port_el.attrib.get("portid", 0)),
                    "protocol": port_el.attrib.get("protocol", "tcp"),
                    "state": state_el.attrib.get("state", "") if state_el is not None else "",
                    "service": service_el.attrib.get("name", "") if service_el is not None else "",
                    "product": service_el.attrib.get("product", "") if service_el is not None else "",
                    "version": service_el.attrib.get("version", "") if service_el is not None else "",
                    "cpes": cpes,
                    "scripts": scripts,
                })

            for os_match in host_el.findall(".//osmatch"):
                host["os"].append({
                    "name": os_match.attrib.get("name"),
                    "accuracy": os_match.attrib.get("accuracy"),
                })

            # NSE scripts at host level: <hostscript><script .../></hostscript>
            for script_el in host_el.findall(".//hostscript/script"):
                host["scripts"].append({
                    "id": script_el.attrib.get("id", ""),
                    "output": script_el.attrib.get("output", ""),
                })

            result["hosts"].append(host)
    except ET.ParseError as exc:
        result["parse_error"] = str(exc)

    return result


def _build_summary(nmap_data: Dict[str, Any]) -> Dict[str, Any]:
    ports: set = set()
    services: Dict[str, Any] = {}
    ips: set = set()
    cpes: set = set()

    for host in nmap_data.get("hosts", []):
        for addr in host.get("addresses", []):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                if ip:
                    ips.add(ip)

        for port in host.get("ports", []):
            if port.get("state") == "open":
                port_num = port.get("port")
                if port_num is not None:
                    ports.add(port_num)
                    services[str(port_num)] = {
                        "name": port.get("service", ""),
                        "product": port.get("product", ""),
                        "version": port.get("version", ""),
                        "protocol": port.get("protocol", "tcp"),
                    }
                for cpe in port.get("cpes", []):
                    cpes.add(cpe)

    hosts_down: int = nmap_data.get("hosts_down", 0)
    summary: Dict[str, Any] = {
        "ports": sorted(ports),
        "services": services,
        "ips": sorted(ips),
        "cpes": sorted(cpes),
        "open_port_count": len(ports),
        "host_count": len(nmap_data.get("hosts", [])),
        "hosts_down": hosts_down,
    }
    if hosts_down:
        summary["host_down_message"] = (
            f"{hosts_down} host(s) did not respond — they may be offline or blocking ICMP/probes."
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
    logger.info(
        "Scan started — target=%s additional_ports=%s",
        req.target, req.additional_ports,
    )

    result: Dict[str, Any] = {
        "target": req.target,
        "scan_method": "local",
        "error": None,
        "data": {},
        "summary": {},
        "additional_ports_from_zap": req.additional_ports or [],
    }

    cmd = (
        ["nmap", "-sV", "-O"]
        + _build_port_arg(req.additional_ports)
        + ["-T4", "-oX", "-", req.target]
    )

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=req.timeout)
        xml_output = proc.stdout

        if not xml_output.strip():
            result["error"] = "nmap produced no output"
            return result

        nmap_data = _parse_nmap_xml(xml_output)
        result["data"] = nmap_data
        result["summary"] = _build_summary(nmap_data)

    except FileNotFoundError:
        result["error"] = "nmap binary not found"
        logger.error("nmap binary not found in PATH")
    except subprocess.TimeoutExpired:
        result["error"] = f"nmap scan timed out after {req.timeout}s"
        logger.warning("Scan timed out for %s", req.target)
    except Exception as exc:
        result["error"] = str(exc)
        logger.exception("Unexpected error running nmap for %s", req.target)

    logger.info(
        "Scan complete — target=%s open_ports=%d",
        req.target, result["summary"].get("open_port_count", 0),
    )
    return result
