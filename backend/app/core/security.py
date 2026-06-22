from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import redis as sync_redis
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=10)


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(tz=timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": subject,
        "exp": expire,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "type": "access",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(tz=timezone.utc)
    expire = now + (expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
    payload = {
        "sub": subject,
        "exp": expire,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "type": "refresh",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    """Return the full decoded payload, or None if invalid / expired."""
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None


# ---------------------------------------------------------------------------
# Token blacklist — stored in Redis with TTL matching the token's remaining life
# ---------------------------------------------------------------------------

_BLACKLIST_PREFIX = "blacklisted_jti:"


def _redis() -> sync_redis.Redis:
    return sync_redis.from_url(settings.REDIS_URL, decode_responses=True)


def blacklist_token(jti: str, exp: datetime) -> None:
    """Invalidate a token by adding its jti to Redis until it would have expired."""
    # Ensure exp is offset-aware for arithmetic
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    ttl = max(int((exp - datetime.now(tz=timezone.utc)).total_seconds()), 1)
    r = _redis()
    try:
        r.setex(f"{_BLACKLIST_PREFIX}{jti}", ttl, "1")
    finally:
        r.close()


def is_token_blacklisted(jti: str) -> bool:
    r = _redis()
    try:
        return bool(r.exists(f"{_BLACKLIST_PREFIX}{jti}"))
    finally:
        r.close()
