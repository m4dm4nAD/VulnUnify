"""clearwing_scans (experimental source-code scan jobs)

Revision ID: 0011_clearwing_scans
Revises: 0010_package_scans
Create Date: 2026-07-08
"""
from alembic import op
import sqlalchemy as sa

revision = "0011_clearwing_scans"
down_revision = "0010_package_scans"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "clearwing_scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("repo_url", sa.String(1024), nullable=False),
        sa.Column("branch", sa.String(256), nullable=False, server_default="main"),
        sa.Column("depth", sa.String(16), nullable=False, server_default="standard"),
        sa.Column("budget_usd", sa.Float(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("stage", sa.String(32), nullable=True),
        sa.Column("session_id", sa.String(128), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cost_usd", sa.Float(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_clearwing_scans_status", "clearwing_scans", ["status"])
    op.create_index("ix_clearwing_scans_created_by", "clearwing_scans", ["created_by"])
    op.create_index("ix_clearwing_scans_created_at", "clearwing_scans", ["created_at"])


def downgrade() -> None:
    op.drop_table("clearwing_scans")
