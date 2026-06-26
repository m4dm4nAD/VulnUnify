"""app_settings (runtime-editable SLA windows + sync interval)

Revision ID: 0007_app_settings
Revises: 0006_watched_packages
Create Date: 2026-06-26
"""
from alembic import op
import sqlalchemy as sa

revision = "0007_app_settings"
down_revision = "0006_watched_packages"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.String(256), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("app_settings")
