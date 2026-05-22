import os

from slowapi import Limiter
from slowapi.util import get_remote_address

# Set RATE_LIMIT_ENABLED=false in test environments to skip limits
_enabled = os.getenv("RATE_LIMIT_ENABLED", "true").lower() != "false"

limiter = Limiter(key_func=get_remote_address, enabled=_enabled)
