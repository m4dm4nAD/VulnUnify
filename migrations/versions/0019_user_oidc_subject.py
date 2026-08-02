"""users.oidc_subject: link a local account to a stable OIDC identity

Stamped on first SSO login so an IdP identity ("sub" claim) maps to exactly one
account across email changes. Null for local-only users; password_hash was
already nullable for SSO-only accounts.

Revision ID: 0019_user_oidc_subject
Revises: 0018_package_scan_username
Create Date: 2026-08-02
"""
from alembic import op
import sqlalchemy as sa

revision = "0019_user_oidc_subject"
down_revision = "0018_package_scan_username"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("oidc_subject", sa.String(255), nullable=True))
    op.create_index("ix_users_oidc_subject", "users", ["oidc_subject"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_oidc_subject", table_name="users")
    op.drop_column("users", "oidc_subject")
