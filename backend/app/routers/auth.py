from datetime import UTC, datetime

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..auth import PASSWORD_ITERATIONS, decode_token, hash_password, verify_password
from ..config import get_settings
from ..database import get_db
from ..models import AnalystUser, RefreshSession
from ..rate_limit import SlidingWindowRateLimiter
from ..schemas import TokenRequest, TokenResponse
from ..session_service import (
    CSRF_COOKIE,
    REFRESH_COOKIE,
    issue_token_pair,
    require_csrf,
    set_session_cookies,
)

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
settings = get_settings()
login_pair_limiter = SlidingWindowRateLimiter(limit=5, window_seconds=300)
login_ip_limiter = SlidingWindowRateLimiter(limit=25, window_seconds=300)


@router.post("/login", response_model=TokenResponse)
def login(
    payload: TokenRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    client = request.client.host if request.client else "unknown"
    limiter_key = f"{client}:{payload.username.lower()}"
    if not login_ip_limiter.allow(client) or not login_pair_limiter.allow(limiter_key):
        raise HTTPException(status_code=429, detail="Too many login attempts; retry in five minutes")

    user = db.scalar(select(AnalystUser).where(AnalystUser.username == payload.username))
    if not user or not user.is_active or not verify_password(
        payload.password,
        user.password_hash,
        user.password_salt,
        user.password_iterations,
    ):
        write_audit(db, payload.username, "login_failed", "session", client)
        db.commit()
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    login_pair_limiter.reset(limiter_key)
    login_ip_limiter.reset(client)
    if user.password_iterations < PASSWORD_ITERATIONS:
        user.password_hash, user.password_salt = hash_password(payload.password)
        user.password_iterations = PASSWORD_ITERATIONS
    write_audit(db, user.username, "login_succeeded", "session", client)
    tokens, refresh_token = issue_token_pair(user, db)
    db.commit()
    set_session_cookies(response, refresh_token)
    return tokens


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    response: Response,
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE),
    x_csrf_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> TokenResponse:
    require_csrf(csrf_cookie, x_csrf_token)
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh session is unavailable")
    claims = decode_token(refresh_token, "refresh")
    jti = claims.get("jti")
    now = datetime.now(UTC)
    session = db.scalar(
        update(RefreshSession)
        .where(
            RefreshSession.jti == jti,
            RefreshSession.revoked_at.is_(None),
            RefreshSession.expires_at > now,
        )
        .values(revoked_at=now)
        .returning(RefreshSession)
    )
    if not session:
        replayed = db.scalar(select(RefreshSession).where(RefreshSession.jti == jti))
        if replayed:
            db.execute(
                update(RefreshSession)
                .where(
                    RefreshSession.family_id == replayed.family_id,
                    RefreshSession.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            write_audit(
                db,
                claims.get("sub", "unknown"),
                "refresh_token_reuse_detected",
                "session_family",
                replayed.family_id,
                {"replayed_jti": jti},
            )
            db.commit()
        raise HTTPException(status_code=401, detail="Refresh token is revoked or expired")
    user = db.get(AnalystUser, session.user_id)
    if not user or not user.is_active:
        db.execute(
            update(RefreshSession)
            .where(
                RefreshSession.family_id == session.family_id,
                RefreshSession.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        write_audit(
            db,
            claims.get("sub", "unknown"),
            "inactive_user_refresh_rejected",
            "session_family",
            session.family_id,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="User is inactive or unavailable")
    write_audit(db, user.username, "token_rotated", "session", session.jti)
    tokens, new_refresh_token = issue_token_pair(
        user,
        db,
        family_id=session.family_id,
        parent_jti=session.jti,
    )
    db.commit()
    set_session_cookies(response, new_refresh_token)
    return tokens


@router.post("/logout", status_code=204)
def logout(
    response: Response,
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE),
    x_csrf_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> None:
    require_csrf(csrf_cookie, x_csrf_token)
    if not refresh_token:
        response.delete_cookie(CSRF_COOKIE, path="/")
        return
    claims = decode_token(refresh_token, "refresh")
    session = db.scalar(select(RefreshSession).where(RefreshSession.jti == claims.get("jti")))
    if session:
        db.execute(
            update(RefreshSession)
            .where(
                RefreshSession.family_id == session.family_id,
                RefreshSession.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(UTC))
        )
        write_audit(db, claims.get("sub", "unknown"), "logout", "session_family", session.family_id)
        db.commit()
    response.delete_cookie(REFRESH_COOKIE, path="/api/v1/auth")
    response.delete_cookie(CSRF_COOKIE, path="/")
