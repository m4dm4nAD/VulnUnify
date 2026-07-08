"""Auth/user API schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from backend.app.models.user import UserRole

# New-password policy. bcrypt only uses the first 72 bytes, so cap there.
_PASSWORD = Field(min_length=8, max_length=72)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str | None
    role: str
    is_active: bool
    created_at: datetime | None = None


class LoginIn(BaseModel):
    # No length policy here: existing credentials must still authenticate, and
    # we don't want validation to leak the policy on the login path.
    username: str
    password: str


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = _PASSWORD
    email: EmailStr | None = None
    role: UserRole = UserRole.DEV


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    role: UserRole | None = None
    is_active: bool | None = None


class PasswordIn(BaseModel):
    password: str = _PASSWORD


class AssignIn(BaseModel):
    user_id: int | None  # null unassigns
