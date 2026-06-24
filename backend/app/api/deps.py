"""Shared FastAPI dependencies for authentication/authorization."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session as DbSession

from backend.app.config import settings
from backend.app.db import get_db
from backend.app.models.user import User
from backend.app.services import auth


def get_current_user(request: Request, db: DbSession = Depends(get_db)) -> User | None:
    """The user behind the session cookie, or None if not authenticated."""
    token = request.cookies.get(settings.session_cookie_name)
    return auth.resolve_session(db, token)


def require_user(user: User | None = Depends(get_current_user)) -> User:
    """Gate a route on being logged in."""
    if user is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    """Gate a route on the admin role (used by the roles phase)."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return user
