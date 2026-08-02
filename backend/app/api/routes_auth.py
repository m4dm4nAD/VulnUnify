"""Login / logout / current-user + optional OIDC SSO. Open router (not behind
require_user). Local password login is the default; SSO is inert unless
configured."""
from __future__ import annotations

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from backend.app.api.deps import get_current_user, require_user
from backend.app.config import settings
from backend.app.db import get_db
from backend.app.models.user import User
from backend.app.schemas.user import LoginIn, UserOut
from backend.app.services import audit, auth, oidc

router = APIRouter(prefix="/api/auth", tags=["auth"])

_OIDC_TXN_COOKIE = "vu_oidc_txn"
_OIDC_CALLBACK_PATH = "/api/auth/oidc/callback"


def _safe_next(raw: str | None) -> str:
    """Only allow same-origin relative paths as the post-login destination —
    never a scheme/host — so the login flow can't be an open redirect."""
    if raw and raw.startswith("/") and not raw.startswith(("//", "/\\")):
        return raw
    return "/"


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=settings.session_ttl_hours * 3600,
        path="/",
    )


def _redirect_uri(request: Request) -> str:
    return settings.oidc_redirect_url or (
        str(request.base_url).rstrip("/") + _OIDC_CALLBACK_PATH
    )


@router.post("/login", response_model=UserOut)
def login(body: LoginIn, request: Request, response: Response, db: DbSession = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == body.username))
    if user is None or not user.is_active or not auth.verify_password(
        body.password, user.password_hash
    ):
        # The client gets one indistinguishable 401; the trail keeps the detail.
        # Only echo the attempted name when it's a REAL user: an unknown name is
        # attacker-controlled (a fumbled password lands here) and must not be
        # persisted verbatim or used to forge arbitrary actor names in the trail.
        known = user is not None
        audit.record(db, "auth.login_failed",
                     f"failed login for {user.username!r}" if known
                     else "failed login for an unknown username",
                     actor_username=user.username if known else None,
                     request=request,
                     details={"known_user": known, "inactive": bool(user and not user.is_active)})
        raise HTTPException(status_code=401, detail="invalid username or password")
    token = auth.create_session(db, user)
    audit.record(db, "auth.login", f"{user.username} logged in",
                 actor=user, request=request, details={"method": "local"})
    _set_session_cookie(response, token)
    return user


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: DbSession = Depends(get_db),
    user: User | None = Depends(get_current_user),
):
    auth.delete_session(db, request.cookies.get(settings.session_cookie_name))
    response.delete_cookie(settings.session_cookie_name, path="/")
    if user is not None:
        audit.record(db, "auth.logout", f"{user.username} logged out",
                     actor=user, request=request)
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(require_user)):
    return user


# --- OIDC / SSO (present but inert unless configured) ---

@router.get("/providers")
def providers():
    """Which login methods the UI should offer. Local is always available."""
    return {
        "local": True,
        "oidc": {"enabled": oidc.is_configured(), "label": settings.oidc_button_label},
    }


@router.get("/oidc/login")
def oidc_login(request: Request, next: str | None = Query(None)):
    """Kick off SSO: redirect to the IdP with a short-lived transaction cookie."""
    if not oidc.is_configured():
        raise HTTPException(404, "SSO is not configured")
    try:
        auth_url, txn = oidc.begin_login(_redirect_uri(request), _safe_next(next))
    except (oidc.OidcError, httpx.HTTPError) as exc:
        # Provider unreachable / misconfigured — don't start a broken flow.
        raise HTTPException(502, "SSO provider is unavailable") from exc
    resp = RedirectResponse(auth_url, status_code=303)
    resp.set_cookie(
        key=_OIDC_TXN_COOKIE, value=txn,
        httponly=True,
        samesite="lax",    # must survive the top-level redirect back from the IdP
        secure=settings.cookie_secure,
        max_age=600,
        path=_OIDC_CALLBACK_PATH,   # only sent to the callback
    )
    return resp


@router.get("/oidc/callback")
def oidc_callback(
    request: Request,
    db: DbSession = Depends(get_db),
    code: str | None = Query(None),
    state: str | None = Query(None),
    error: str | None = Query(None),
):
    """Handle the IdP redirect: validate, open a local session, land on the app."""
    txn_cookie = request.cookies.get(_OIDC_TXN_COOKIE)

    def _fail(reason: str, detail: str | None = None) -> RedirectResponse:
        audit.record(db, "auth.login_failed", f"SSO login failed: {reason}",
                     request=request, details={"method": "oidc", "reason": reason})
        r = RedirectResponse("/login.html?sso_error=1", status_code=303)
        r.delete_cookie(_OIDC_TXN_COOKIE, path=_OIDC_CALLBACK_PATH)
        return r

    if error or not code or not state or not txn_cookie:
        return _fail(error or "missing code/state")
    try:
        user, next_path = oidc.complete_login(code, state, txn_cookie,
                                              _redirect_uri(request), db)
    except (oidc.OidcError, httpx.HTTPError, jwt.PyJWTError) as exc:
        # Any validation/provider failure lands the user back on login, never a 500.
        return _fail(str(exc))

    token = auth.create_session(db, user)
    audit.record(db, "auth.login", f"{user.username} logged in via SSO",
                 actor=user, request=request, details={"method": "oidc"})
    resp = RedirectResponse(_safe_next(next_path), status_code=303)
    _set_session_cookie(resp, token)
    resp.delete_cookie(_OIDC_TXN_COOKIE, path=_OIDC_CALLBACK_PATH)
    return resp
