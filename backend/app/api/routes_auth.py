"""Login / logout / current-user. Open router (not behind require_user)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from backend.app.api.deps import get_current_user, require_user
from backend.app.config import settings
from backend.app.db import get_db
from backend.app.models.user import User
from backend.app.schemas.user import LoginIn, UserOut
from backend.app.services import audit, auth

router = APIRouter(prefix="/api/auth", tags=["auth"])


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
                 actor=user, request=request)
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=settings.session_ttl_hours * 3600,
        path="/",
    )
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
