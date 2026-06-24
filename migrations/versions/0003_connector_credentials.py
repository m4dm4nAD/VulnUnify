"""connector_credentials: encrypted UI-managed credential overrides

Revision ID: 0003_connector_credentials
Revises: 0002_finding_lifecycle
Create Date: 2026-06-23
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_connector_credentials"
down_revision = "0002_finding_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "connector_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("connector", sa.String(64), nullable=False),
        sa.Column("key", sa.String(128), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("connector", "key", name="uq_connector_key"),
    )
    op.create_index("ix_connector_credentials_connector", "connector_credentials", ["connector"])


def downgrade() -> None:
    op.drop_table("connector_credentials")
