"""Auth/user API schemas."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from backend.app.models.user import UserRole


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str | None
    role: str
    is_active: bool


class LoginIn(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str
    password: str
    email: str | None = None
    role: UserRole = UserRole.DEV


class UserUpdate(BaseModel):
    email: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None


class PasswordIn(BaseModel):
    password: str


class AssignIn(BaseModel):
    user_id: int | None  # null unassigns
