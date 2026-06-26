"""error_logs (persisted failures)

Revision ID: 0008_error_logs
Revises: 0007_app_settings
Create Date: 2026-06-26
"""
from alembic import op
import sqlalchemy as sa

revision = "0008_error_logs"
down_revision = "0007_app_settings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "error_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("message", sa.String(512), nullable=False),
        sa.Column("detail", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_error_logs_source", "error_logs", ["source"])
    op.create_index("ix_error_logs_created_at", "error_logs", ["created_at"])


def downgrade() -> None:
    op.drop_table("error_logs")
