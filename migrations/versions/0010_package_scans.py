"""package_scans (self-service scan history)

Revision ID: 0010_package_scans
Revises: 0009_index_triage_state
Create Date: 2026-07-02
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0010_package_scans"
down_revision = "0009_index_triage_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "package_scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("filename", sa.String(512), nullable=False),
        sa.Column("checked", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("vulnerable", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_vulns", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ecosystems", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("packages", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_package_scans_user_id", "package_scans", ["user_id"])
    op.create_index("ix_package_scans_created_at", "package_scans", ["created_at"])


def downgrade() -> None:
    op.drop_table("package_scans")
