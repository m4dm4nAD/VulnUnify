"""Shared FastAPI dependencies for authentication/authorization."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session as DbSession

from backend.app.config import settings
from backend.app.db import get_db
from backend.app.models.user import User, UserRole
from backend.app.services import auth

# Single source of truth for "is this the security team?" — the two security
# roles. Imported wherever a role check is needed so the set can't drift.
SECURITY_ROLES = {UserRole.SECURITY_ADMIN.value, UserRole.SECURITY_USER.value}


def get_current_user(request: Request, db: DbSession = Depends(get_db)) -> User | None:
    """The user behind the session cookie, or None if not authenticated."""
    token = request.cookies.get(settings.session_cookie_name)
    return auth.resolve_session(db, token)


def require_user(user: User | None = Depends(get_current_user)) -> User:
    """Gate a route on being logged in (any role)."""
    if user is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


def require_security(user: User = Depends(require_user)) -> User:
    """Security team: sees all findings/connectors, assigns work. Excludes devs."""
    if user.role not in SECURITY_ROLES:
        raise HTTPException(status_code=403, detail="security role required")
    return user


def require_security_admin(user: User = Depends(require_user)) -> User:
    """Full access: user management + connector credentials."""
    if user.role != UserRole.SECURITY_ADMIN.value:
        raise HTTPException(status_code=403, detail="security_admin role required")
    return user

