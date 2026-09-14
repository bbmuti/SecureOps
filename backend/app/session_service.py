import hmac
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Response
from sqlalchemy.orm import Session

from .auth import create_access_token, create_refresh_token
from .config import get_settings
from .models import AnalystUser, RefreshSession
from .schemas import TokenResponse

REFRESH_COOKIE = "sentinelscope_refresh"
CSRF_COOKIE = "sentinelscope_csrf"

settings = get_settings()


def issue_token_pair(
    user: AnalystUser,
    db: Session,
    *,
    family_id: str | None = None,
    parent_jti: str | None = None,
) -> tuple[TokenResponse, str]:
    jti = uuid.uuid4().hex
    family = family_id or uuid.uuid4().hex
    expires = datetime.now(UTC) + timedelta(days=settings.refresh_token_days)
    db.add(
        RefreshSession(
            jti=jti,
            family_id=family,
            parent_jti=parent_jti,
            user_id=user.id,
            expires_at=expires,
        )
    )
    return (
        TokenResponse(
            access_token=create_access_token(user.username, user.role),
            expires_in=settings.access_token_minutes * 60,
        ),
        create_refresh_token(user.username, user.role, jti),
    )


def set_session_cookies(response: Response, refresh_token: str) -> None:
    secure = settings.environment.lower() == "production"
    max_age = settings.refresh_token_days * 24 * 60 * 60
    response.set_cookie(
        REFRESH_COOKIE,
        refresh_token,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/api/v1/auth",
    )
    response.set_cookie(
        CSRF_COOKIE,
        uuid.uuid4().hex,
        max_age=max_age,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/",
    )


def require_csrf(csrf_cookie: str | None, csrf_header: str | None) -> None:
    if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
