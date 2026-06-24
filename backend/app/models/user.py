"""User + role.

`password_hash` is nullable on purpose: local accounts have a bcrypt hash, while
future OIDC/SSO accounts authenticate externally and carry none. Roles are stored
now so the roles phase builds on top without a model change.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.models.base import Base


class UserRole(str, Enum):
    ADMIN = "admin"   # sees and manages everything
    USER = "user"     # (roles phase) sees only findings assigned to them


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str | None] = mapped_column(String(255))  # null for SSO users
    role: Mapped[str] = mapped_column(String(16), default=UserRole.USER.value)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
