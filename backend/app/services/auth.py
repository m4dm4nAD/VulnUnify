"""Password hashing (bcrypt) and server-side session management."""
from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

import bcrypt
import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from backend.app.config import settings
from backend.app.models.base import utcnow
from backend.app.models.session import Session
from backend.app.models.user import User

log = structlog.get_logger()


# --- passwords ---

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str | None) -> bool:
    if not hashed:
        return False
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ValueError:
        return False


# --- sessions ---

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: DbSession, user: User) -> str:
    """Create a session and return the raw cookie token (only its hash is stored)."""
    token = secrets.token_urlsafe(32)
    now = utcnow()
    db.add(
        Session(
            token_hash=_hash_token(token),
            user_id=user.id,
            created_at=now,
            expires_at=now + timedelta(hours=settings.session_ttl_hours),
            last_seen=now,
        )
    )
    db.commit()
    return token


def resolve_session(db: DbSession, token: str | None) -> User | None:
    """Return the active user for a cookie token, or None. Prunes if expired."""
    if not token:
        return None
    sess = db.get(Session, _hash_token(token))
    if sess is None:
        return None
    now = utcnow()
    if sess.expires_at < now:
        db.delete(sess)
        db.commit()
        return None
    # Avoid a write on every request — only refresh last_seen when it's stale.
    if (now - sess.last_seen).total_seconds() > 60:
        sess.last_seen = now
        db.commit()
    user = db.get(User, sess.user_id)
    return user if user and user.is_active else None


def delete_session(db: DbSession, token: str | None) -> None:
    if not token:
        return
    sess = db.get(Session, _hash_token(token))
    if sess is not None:
        db.delete(sess)
        db.commit()


def seed_initial_admin(db: DbSession) -> None:
    """Create the bootstrap admin when there are no users yet."""
    if db.scalar(select(User).limit(1)) is not None:
        return
    generated = not settings.initial_admin_password
    password = settings.initial_admin_password or secrets.token_urlsafe(12)
    db.add(
        User(
            username=settings.initial_admin_username,
            role="security_admin",
            is_active=True,
            password_hash=hash_password(password),
        )
    )
    db.commit()
    log.warning(
        "auth.seeded_admin",
        username=settings.initial_admin_username,
        password=password if generated else "<from INITIAL_ADMIN_PASSWORD>",
        note="change this password" if generated else "",
    )
