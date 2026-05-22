from __future__ import annotations

import asyncio
import re
import socket

IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def is_ip(value: str) -> bool:
    return bool(IP_RE.match(value))


def extract_hostname(target: str) -> str:
    """Extract bare hostname from a URL-like string or return target as-is."""
    return target.split("//")[-1].split("/")[0].split(":")[0]


async def resolve_hostname(target: str, timeout: float = 10.0) -> str:
    """Resolve target (IP or hostname/URL) to an IPv4 address asynchronously."""
    if is_ip(target):
        return target
    loop = asyncio.get_running_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(None, socket.gethostbyname, extract_hostname(target)),
        timeout=timeout,
    )
