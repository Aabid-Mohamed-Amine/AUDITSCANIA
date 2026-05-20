"""
Nmap active scan service.

Runs nmap inside the dedicated nmap Docker container via the Docker SDK.
Falls back to a local subprocess call if the Docker socket is unavailable.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# XML → dict parser
# ---------------------------------------------------------------------------


def _parse_nmap_xml(xml_str: str) -> Dict[str, Any]:
    """Parse nmap XML output into a structured dict."""
    result: Dict[str, Any] = {"hosts": [], "raw_summary": ""}
    try:
        root = ET.fromstring(xml_str)
        result["raw_summary"] = root.attrib.get("summary", "")

        for host_el in root.findall("host"):
            host: Dict[str, Any] = {
                "status": "",
                "addresses": [],
                "hostnames": [],
                "ports": [],
                "os": [],
            }

            # Status
            status_el = host_el.find("status")
            if status_el is not None:
                host["status"] = status_el.attrib.get("state", "")

            # Addresses
            for addr in host_el.findall("address"):
                host["addresses"].append({
                    "addr": addr.attrib.get("addr"),
                    "addrtype": addr.attrib.get("addrtype"),
                })

            # Hostnames
            for hn in host_el.findall(".//hostname"):
                host["hostnames"].append(hn.attrib.get("name"))

            # Ports
            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                port_info: Dict[str, Any] = {
                    "port": int(port_el.attrib.get("portid", 0)),
                    "protocol": port_el.attrib.get("protocol", "tcp"),
                    "state": state_el.attrib.get("state", "") if state_el is not None else "",
                    "service": service_el.attrib.get("name", "") if service_el is not None else "",
                    "product": service_el.attrib.get("product", "") if service_el is not None else "",
                    "version": service_el.attrib.get("version", "") if service_el is not None else "",
                }
                host["ports"].append(port_info)

            # OS detection
            for os_match in host_el.findall(".//osmatch"):
                host["os"].append({
                    "name": os_match.attrib.get("name"),
                    "accuracy": os_match.attrib.get("accuracy"),
                })

            result["hosts"].append(host)
    except ET.ParseError as exc:
        result["parse_error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Run nmap
# ---------------------------------------------------------------------------


def _run_local_nmap(target: str) -> str:
    """Run nmap locally (fallback) and return XML output."""
    cmd = [
        "nmap",
        "-sV",           # service/version detection
        "-O",            # OS detection
        "--top-ports", "1000",
        "-T4",           # aggressive timing
        "-oX", "-",      # XML to stdout
        target,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return proc.stdout


async def run_nmap_scan(target: str) -> Dict[str, Any]:
    """
    Execute an nmap scan against *target*.

    Returns a structured dict with parsed port/service/OS data.
    """
    result: Dict[str, Any] = {"target": target, "error": None, "data": {}}

    try:
        xml_output = _run_local_nmap(target)
        result["scan_method"] = "local"

        if not xml_output.strip():
            result["error"] = "nmap produced no output"
            return result

        result["data"] = _parse_nmap_xml(xml_output)
        result["data"]["raw_xml"] = xml_output

    except FileNotFoundError:
        result["error"] = "nmap binary not found – install nmap or ensure the nmap container is running"
    except subprocess.TimeoutExpired:
        result["error"] = "nmap scan timed out after 300 seconds"
    except Exception as exc:
        result["error"] = str(exc)
        logger.exception("Unexpected error running nmap for target %s", target)

    return result
