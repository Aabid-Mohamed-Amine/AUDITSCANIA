import uuid
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.schemas.user import (
    UserCreate, UserResponse, TokenResponse, LoginResponse,
    LoginRequest, RefreshRequest, LogoutRequest,
)
from app.core.security import (
    get_password_hash, verify_password,
    create_access_token, create_refresh_token,
    decode_access_token, blacklist_token,
)
from app.core.deps import get_current_user
from app.core.limiter import limiter

logger = logging.getLogger(__name__)
router = APIRouter()

bearer_scheme = HTTPBearer(auto_error=False)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
def register(request: Request, payload: UserCreate, db: Session = Depends(get_db)) -> UserResponse:
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        id=uuid.uuid4(),
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("New user registered: %s", user.email)
    return UserResponse.model_validate(user)


@router.post("/login", response_model=LoginResponse)
@limiter.limit("5/minute")
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    return LoginResponse(
        access_token=create_access_token(subject=user.email),
        refresh_token=create_refresh_token(subject=user.email),
        user=UserResponse.model_validate(user),
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)) -> TokenResponse:
    token_data = decode_access_token(payload.refresh_token)
    if not token_data or token_data.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    jti = token_data.get("jti")
    exp_ts = token_data.get("exp")

    # Check if this refresh token was already revoked
    from app.core.security import is_token_blacklisted
    if jti and is_token_blacklisted(jti):
        raise HTTPException(status_code=401, detail="Refresh token has been revoked")

    email: str | None = token_data.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    # Rotate: blacklist the consumed refresh token
    if jti and exp_ts:
        exp_dt = datetime.fromtimestamp(exp_ts, tz=timezone.utc)
        blacklist_token(jti, exp_dt)

    logger.info("Token refreshed for user %s", email)
    return TokenResponse(
        access_token=create_access_token(subject=email),
        refresh_token=create_refresh_token(subject=email),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    body: LogoutRequest | None = None,
) -> None:
    # Blacklist access token
    if credentials:
        payload = decode_access_token(credentials.credentials)
        if payload:
            jti = payload.get("jti")
            exp_ts = payload.get("exp")
            if jti and exp_ts:
                exp_dt = datetime.fromtimestamp(exp_ts, tz=timezone.utc)
                blacklist_token(jti, exp_dt)
                logger.info("Access token revoked (jti=%s, user=%s)", jti, payload.get("sub"))

    # Also blacklist refresh token if provided
    if body and body.refresh_token:
        rt_data = decode_access_token(body.refresh_token)
        if rt_data and rt_data.get("type") == "refresh":
            rt_jti = rt_data.get("jti")
            rt_exp_ts = rt_data.get("exp")
            if rt_jti and rt_exp_ts:
                rt_exp_dt = datetime.fromtimestamp(rt_exp_ts, tz=timezone.utc)
                blacklist_token(rt_jti, rt_exp_dt)
                logger.info("Refresh token revoked (jti=%s)", rt_jti)


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)) -> UserResponse:
    return UserResponse.model_validate(current_user)
