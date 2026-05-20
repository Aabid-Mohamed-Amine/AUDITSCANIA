from __future__ import annotations

import re

IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def is_ip(value: str) -> bool:
    return bool(IP_RE.match(value))


def extract_hostname(target: str) -> str:
    """Extract bare hostname from a URL-like string or return target as-is."""
    return target.split("//")[-1].split("/")[0].split(":")[0]
