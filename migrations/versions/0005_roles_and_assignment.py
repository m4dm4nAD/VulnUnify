"""three roles (security_admin/security_user/dev) + finding assignment

Revision ID: 0005_roles_and_assignment
Revises: 0004_users_sessions
Create Date: 2026-06-23
"""
from alembic import op
import sqlalchemy as sa

revision = "0005_roles_and_assignment"
down_revision = "0004_users_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Migrate the old two-role vocabulary to the new three-role one.
    op.execute("UPDATE users SET role='security_admin' WHERE role='admin'")
    op.execute("UPDATE users SET role='security_user' WHERE role='user'")
    op.alter_column("users", "role", server_default="dev")

    op.add_column(
        "findings",
        sa.Column(
            "assigned_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_findings_assigned_user_id", "findings", ["assigned_user_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_assigned_user_id", table_name="findings")
    op.drop_column("findings", "assigned_user_id")
    op.alter_column("users", "role", server_default="user")
    op.execute("UPDATE users SET role='admin' WHERE role='security_admin'")
    op.execute("UPDATE users SET role='user' WHERE role='security_user'")
