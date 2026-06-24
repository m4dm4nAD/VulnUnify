"""User management. Listing is for the security team (to assign work);
mutations are security_admin only."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.api.deps import require_security, require_security_admin
from backend.app.db import get_db
from backend.app.models.user import User
from backend.app.schemas.user import PasswordIn, UserCreate, UserOut, UserUpdate
from backend.app.services import auth

router = APIRouter(prefix="/api/users", tags=["users"])


def _active_admins(db: Session) -> int:
    return db.scalar(
        select(func.count())
        .select_from(User)
        .where(User.role == "security_admin", User.is_active.is_(True))
    ) or 0


@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_security)):
    return db.scalars(select(User).order_by(User.username)).all()


@router.post("", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreate, db: Session = Depends(get_db), _: User = Depends(require_security_admin)
):
    if db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(409, "username already exists")
    user = User(
        username=body.username,
        email=body.email,
        role=body.role.value,
        password_hash=auth.hash_password(body.password),
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    body: UserUpdate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_security_admin),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    # Don't let the last admin demote or deactivate themselves into lockout.
    demoting = (body.role is not None and body.role.value != "security_admin") or (
        body.is_active is False
    )
    if user.role == "security_admin" and demoting and _active_admins(db) <= 1:
        raise HTTPException(400, "cannot remove the last active security_admin")

    if body.email is not None:
        user.email = body.email
    if body.role is not None:
        user.role = body.role.value
    if body.is_active is not None:
        user.is_active = body.is_active
    db.commit()
    db.refresh(user)
    return user


@router.post("/{user_id}/password", status_code=204)
def set_password(
    user_id: int,
    body: PasswordIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_security_admin),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    user.password_hash = auth.hash_password(body.password)
    db.commit()


@router.delete("/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    actor: User = Depends(require_security_admin),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    if user.id == actor.id:
        raise HTTPException(400, "cannot delete yourself")
    if user.role == "security_admin" and _active_admins(db) <= 1:
        raise HTTPException(400, "cannot delete the last active security_admin")
    db.delete(user)  # findings.assigned_user_id is set null via FK
    db.commit()
