"""Login / logout / current-user. Open router (not behind require_user)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from backend.app.api.deps import require_user
from backend.app.config import settings
from backend.app.db import get_db
from backend.app.models.user import User
from backend.app.schemas.user import LoginIn, UserOut
from backend.app.services import auth

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=UserOut)
def login(body: LoginIn, response: Response, db: DbSession = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == body.username))
    if user is None or not user.is_active or not auth.verify_password(
        body.password, user.password_hash
    ):
        raise HTTPException(status_code=401, detail="invalid username or password")
    token = auth.create_session(db, user)
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.session_cookie_secure,
        max_age=settings.session_ttl_hours * 3600,
        path="/",
    )
    return user


@router.post("/logout")
def logout(request: Request, response: Response, db: DbSession = Depends(get_db)):
    auth.delete_session(db, request.cookies.get(settings.session_cookie_name))
    response.delete_cookie(settings.session_cookie_name, path="/")
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(require_user)):
    return user
