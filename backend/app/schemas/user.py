"""Auth/user API schemas."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


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
